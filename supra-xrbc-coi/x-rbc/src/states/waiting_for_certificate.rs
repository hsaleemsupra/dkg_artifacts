use crate::states::done::{Done, DoneCommitteeFSM};
use crate::states::handlers::{
    CommitteeMessageHandler, CommitteeMessageReceiver, FSMErrorHandler, InputVerifier,
};
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::LoggingName;
use crate::types::context::committee::{CommitteeFSMContext, CommitteeFSMContextSchema};
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::helpers::assignment_extractor::AssignmentExtractor;
use crate::types::helpers::message_factory::{MessageFactoryTrait, MessageFrom};
use crate::types::helpers::sender_extractor::SenderExtractor;
use crate::types::helpers::Visitor;
use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    CommitteeFSMResponseMessage, EchoReadyData, EchoValueData, QuorumCertificateData,
    RBCCommitteeMessage, RBCNetworkMessage, ReadyData, ResponseTypeIfc, ShareData, ValueData,
    VoteData,
};
use crate::types::payload_state::committee::{CommitteePayloadFlags, CommitteePayloadTag};
use crate::types::payload_state::PayloadFlags;
use log::info;
use metrics::{
    impl_timestamp, nanoseconds_since_unix_epoch, report, MetricValue, TimeStampTrait, Timestamp,
};
use primitives::types::HeaderIfc;
use primitives::{Origin, Protocol};
use sfsm::{ReceiveMessage, ReturnMessage, State, TransitGuard, Transition};

pub(crate) struct WaitingForCertificate<C: SupraDeliveryErasureCodecSchema> {
    context: CommitteeFSMContext<C>,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(
    timestamp,
    WaitingForCertificate<Schema: SupraDeliveryErasureCodecSchema>
);

impl<C: SupraDeliveryErasureCodecSchema> FSMContextOwner for WaitingForCertificate<C> {
    type Schema = CommitteeFSMContextSchema<C>;

    fn context(&self) -> &CommitteeFSMContext<C> {
        &self.context
    }

    fn context_mut(&mut self) -> &mut CommitteeFSMContext<C> {
        &mut self.context
    }
}

impl<C: SupraDeliveryErasureCodecSchema> LoggingName for WaitingForCertificate<C> {
    fn name<'a>() -> &'a str {
        "WaitingForCertificate"
    }
}

impl<C: SupraDeliveryErasureCodecSchema> WaitingForCertificate<C> {
    pub(crate) fn new(context: CommitteeFSMContext<C>) -> Self {
        Self {
            context,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    fn consume_value_data(&mut self, value_data: &ValueData<C>) {
        let state = self.payload_state_mut();

        // store chunk index
        state.store_chunk_index(value_data.get_chunk_index());
    }

    fn consume_ready_data(&mut self, ready_data: &ReadyData<C>) {
        let sender = SenderExtractor::new(self.topology())
            .visit_ready(ready_data)
            .unwrap()
            .position();

        // Handle value data
        self.consume_value_data(ready_data.value());

        let state = self.payload_state_mut();

        // Save sender as all chunks owner
        state.store_peer_with_all_chunks(sender);
    }

    pub(crate) fn resend_vote(&mut self) {
        let index = self.topology().get_position();
        let vote = self.payload_state().get_vote(index as u32).unwrap();
        let vote_data = VoteData::new(self.payload_state().get_header(), vote);

        // Broadcast
        let addresses = <AssignmentExtractor as Visitor<C>>::visit_vote(
            &self.assignment_extractor(),
            &vote_data,
        )
        .unwrap();
        let msg = (RBCCommitteeMessage::from(vote_data), addresses);
        info!("{}: {} => {:?}", Self::name(), msg.0, msg.1);
        self.response_mut().add_message(msg);
    }

    ///
    /// As current node is committee hence it will send network piece in share data message
    ///
    fn get_share_data(&mut self, nt_index: usize) -> ShareData<C> {
        let network_chunks = self.payload_state().network_chunks().unwrap();
        let header = self.payload_state().get_header();
        let position = self.topology().get_position();
        let sender = self.topology().origin();
        let (meta, pieces) = network_chunks[nt_index].split_ref();
        let value_data = ValueData::new(header, pieces.get(position).unwrap().clone());
        ShareData::new(*sender, value_data, meta.clone())
    }

    ///
    /// send share message to the requester
    ///
    pub fn send_share_msg_to_requester(&mut self, requester: Origin) {
        // define network-chunk-commitment index for requester
        let network_chunk_commitment_index = self
            .assignment_extractor()
            .target_chunk_index(self.payload_state().origin(), &requester);

        let network_chunk_index =
            network_chunk_commitment_index - self.topology().get_committee_size();
        let share_data = self.get_share_data(network_chunk_index);

        let address = self
            .assignment_extractor()
            .visit_share(&share_data)
            .unwrap();
        let msg = (RBCNetworkMessage::Share(share_data), address);
        info!("{}: {} => {:?}", Self::name(), msg.0, msg.1);
        self.response_mut().add_aux_message(msg);
    }

    pub fn echo_value_msg(&mut self, value_data: ValueData<C>) {
        let echo = EchoValueData::new(value_data);
        let addresses = self.assignment_extractor().visit_echo_value(&echo).unwrap();

        let msg = (RBCCommitteeMessage::EchoValue(echo), addresses);
        info!("{}: {} => {:?}", Self::name(), msg.0, msg.1);
        self.response_mut().add_message(msg);
    }

    pub fn echo_ready_msg(&mut self, ready_data: ReadyData<C>) {
        let echo = self.message_factory().message_from(ready_data);
        let addresses = self.assignment_extractor().visit_echo_ready(&echo).unwrap();
        let msg = (RBCCommitteeMessage::EchoReady(echo), addresses);
        info!("{}: {} => {:?}", Self::name(), msg.0, msg.1);
        self.response_mut().add_message(msg);
    }

    pub fn send_ready_msg(&mut self, ready_data: ReadyData<C>) {
        let topology = self.topology();

        let address = topology
            .get_address_by_position(Protocol::XRBC, ready_data.value().get_chunk_index())
            .unwrap();
        let msg = (RBCCommitteeMessage::Ready(ready_data), vec![address]);
        info!("{}: {} => {:?}", Self::name(), msg.0, msg.1);
        self.response_mut().add_message(msg);
    }

    ///
    /// Adds ready messages for the committee/clan(excluding broadcaster) members from which no
    /// chunk info received so far as response message
    ///
    fn broadcast_ready_messages(&mut self) {
        let committee_data = self.payload_state_mut().take_committee_chunks().unwrap();
        if self.is_data_broadcaster() {
            return;
        }
        let this_index = self.topology().get_position();
        let this_origin = *self.topology().origin();
        let broadcaster_index = self
            .topology()
            .info_by_origin(self.payload_state().origin())
            .unwrap()
            .position();
        let header = self.payload_state().header();
        committee_data
            .into_iter()
            .filter(|c| self.should_be_sent(c.data().get_commitment_index(), broadcaster_index))
            .map(|c| ValueData::new(header.clone(), c))
            .map(|c| ReadyData::new(this_origin, c))
            .collect::<Vec<_>>()
            .into_iter()
            .for_each(|ready_data| {
                if ready_data.value().get_chunk_index() != this_index {
                    self.send_ready_msg(ready_data)
                } else {
                    self.echo_ready_msg(ready_data)
                }
            });
    }

    ///
    /// Returns true if the chunk corresponding to the input index should be sent by the node as
    /// ready or echo ready message
    /// Chunk should be sent if:
    ///     - it is not broadcaster chunk
    ///     - no chunk with the corresponding index is received so far
    ///     - the node corresponding to chunk index did not vote for data
    ///     - it is the current node chunk
    ///
    fn should_be_sent(&self, chunk_idx: usize, broadcaster_index: usize) -> bool {
        if chunk_idx == broadcaster_index {
            return false;
        }
        if chunk_idx == self.topology().get_position() {
            return true;
        }
        let state = self.payload_state();
        !state
            .certificate()
            .as_ref()
            .unwrap()
            .participants()
            .contains(&(chunk_idx as u32))
            && !state.has_chunk(chunk_idx)
    }

    pub(crate) fn is_data_broadcaster(&self) -> bool {
        self.topology().origin() == self.payload_state().origin()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> State for WaitingForCertificate<C> {
    fn entry(&mut self) {
        if !self.payload_state().has_payload_data() {
            panic!("Internal implementation error, entered WFC state without reconstructed data")
        } else if !self.is_data_broadcaster()
            && !self.payload_state().is_certified()
            && self
                .payload_state()
                .get_vote(self.topology().get_position() as u32)
                .is_none()
        {
            self.register_internal_error(
                "Invalid internal state when entering WFC. No vote details on deliverable."
                    .to_string(),
            )
        }
    }

    fn exit(&mut self) {
        if !self.payload_state().is_certified() {
            return;
        }
        if !self.is_data_broadcaster() {
            report(
                &[
                    &CommitteePayloadTag::QC,
                    self.payload_state().header(),
                    &CommitteePayloadTag::TagName,
                ],
                MetricValue::AsSeconds(self.elapsed_time()),
            );
        }

        // Disbale sending Ready and EchoReady messages as long as nodes which are late can always
        // fetch missing data via synchronization path
        // self.broadcast_ready_messages();
    }
}

/// State Transition from WaitingForCertificate -> DoneCommitteeFSM
impl<C: SupraDeliveryErasureCodecSchema> Into<DoneCommitteeFSM<C>> for WaitingForCertificate<C> {
    fn into(self) -> DoneCommitteeFSM<C> {
        Done::new(self.context)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Transition<DoneCommitteeFSM<C>>
    for WaitingForCertificate<C>
{
    fn guard(&self) -> TransitGuard {
        (self.payload_state().has_payload_data() && self.payload_state().is_certified()).into()
    }
}

/// Message handling and Response Query interfaces for WaitingForCertificate state of CommitteeStateMachine

impl<C: SupraDeliveryErasureCodecSchema> ReturnMessage<CommitteeFSMResponseMessage<C>>
    for WaitingForCertificate<C>
{
    fn return_message(&mut self) -> Option<CommitteeFSMResponseMessage<C>> {
        self.take_response()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> ReceiveMessage<RBCCommitteeMessage<C>>
    for WaitingForCertificate<C>
{
    fn receive_message(&mut self, message: RBCCommitteeMessage<C>) {
        self.handle_message(message)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> InputVerifier<C, RBCCommitteeMessage<C>>
    for WaitingForCertificate<C>
{
}

impl<C: SupraDeliveryErasureCodecSchema> CommitteeMessageReceiver<C> for WaitingForCertificate<C> {}

impl<C: SupraDeliveryErasureCodecSchema> CommitteeMessageHandler for WaitingForCertificate<C> {
    type Value = ValueData<C>;
    type EchoValue = EchoValueData<C>;
    type Ready = ReadyData<C>;
    type EchoReady = EchoReadyData<C>;

    ///
    /// Updates payload state based on the input message and echoes input message to all peers
    /// and peer vote on data is resent to broadcaster one more time, as value message has received
    /// at this stage may be the cause of missing votes to form QC on deliverable.
    ///
    /// At this state the deliverable message has been successfully reconstructed and there is not
    /// need to store actual chunk information.
    /// The current state is only update with sender meta-information in order to prevent later
    /// redundant echo|ready|echo-ready data dissemination.
    ///
    /// This is true for all messages.
    /// Note: All messages before reaching this step are verified according to verification rules.
    /// It is expected that no unexpected messages will be handled, i.e.
    ///     - duplicates won't reach this stage (except Value messages)
    ///     - votes sent to non-broadcaster won't reach this stage, etc.
    ///     - 'value' messages not expected as input for broadcaster won't reach this stage, etc.
    ///
    /// For more details on verification rules please see VerifierVisitor implementation
    ///
    ///
    fn handle_value(&mut self, msg: Self::Value) {
        self.consume_value_data(&msg);
        self.echo_value_msg(msg);
        self.resend_vote()
    }

    ///
    /// Stores chunk index to mark the chunk as received
    ///
    fn handle_echo_value(&mut self, msg: Self::EchoValue) {
        self.payload_state_mut()
            .store_chunk_index(msg.get_chunk_index())
    }

    ///
    /// Stores input voter index and sender as peer having all chunks
    ///
    fn handle_vote(&mut self, msg: VoteData) {
        let (_, vote) = msg.split();
        self.payload_state_mut().add_vote(vote);
    }

    ///
    /// Updates payload state with input message meta-information and echoes input message to all
    /// peers except broadcaster and sender.
    ///
    fn handle_ready(&mut self, msg: Self::Ready) {
        self.consume_ready_data(&msg);
        self.echo_ready_msg(msg);
    }

    ///
    /// Stores chunk index to mark the chunk as received and also stores underlying ready message
    /// sender as peer with all chunks
    ///
    fn handle_echo_ready(&mut self, msg: Self::EchoReady) {
        self.consume_ready_data(msg.ready_data());
    }

    fn handle_certificate(&mut self, msg: QuorumCertificateData) {
        let (_, _, qc) = msg.split();
        self.payload_state_mut().set_certificate(qc);
    }

    ///
    /// Nothing should be sent if requester is from current clan.
    ///
    fn handle_pull_request(&mut self, msg: PullRequest) {
        let (sync, requester) = msg.split();
        self.handle_sync_request(sync);
        if let Some(clan_member) = self.topology().is_clan_member(&requester) {
            if !clan_member {
                self.send_share_msg_to_requester(requester);
            }
        }
    }

    fn handle_sync_request(&mut self, msg: SyncRequest) {
        let (_, qc) = msg.split();
        if !self.payload_state().is_certified() {
            self.payload_state_mut().set_certificate(qc);
        }
    }

    fn handle_payload(&mut self, _msg: PayloadData) {}
}
