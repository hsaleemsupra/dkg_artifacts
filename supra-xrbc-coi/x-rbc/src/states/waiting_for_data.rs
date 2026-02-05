use crate::states::done::{Done, DoneCommitteeFSM};
use crate::states::handlers::{
    CommitteeMessageHandler, CommitteeMessageReceiver, FSMErrorHandler, GenericAssembler,
    InputVerifier, NetworkShareBroadcaster, PayloadAssembler, PullRequestBroadcaster,
    PullRequestBroadcasterCommittee, ReconstructedDataAssembler,
};
use crate::states::waiting_for_vote::WaitingForVote;
use crate::states::WaitingForCertificate;
use crate::tasks::codec::{
    EncodeResultIfc, SupraDeliveryErasureCodec, SupraDeliveryErasureCodecSchema,
};
use crate::tasks::config::DisseminationRule;
use crate::tasks::errors::RBCError;
use crate::tasks::LoggingName;
use crate::types::context::committee::{CommitteeFSMContext, CommitteeFSMContextSchema};
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::helpers::message_factory::{MessageFactoryTrait, MessageFrom};
use crate::types::helpers::sender_extractor::SenderExtractor;
use crate::types::helpers::Visitor;
use crate::types::messages::chunk::ChunkData;
use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    CommitteeFSMResponseMessage, EchoReadyData, EchoValueData, QuorumCertificateData,
    RBCCommitteeMessage, ReadyData, ResponseTypeIfc, ValueData, VoteData,
};
use crate::types::payload_state::committee::{
    CommitteePayloadFlags, CommitteePayloadTag, ReconstructedData,
};
use crate::types::payload_state::PayloadFlags;
use crate::FeedbackMessage;
use log::info;
use metrics::{
    impl_timestamp, nanoseconds_since_unix_epoch, report, MetricValue, TimeStampTrait, Timestamp,
};
use primitives::types::header::HeaderIfc;
use primitives::{Origin, Protocol};
use sfsm::{ReceiveMessage, ReturnMessage, State, TransitGuard, Transition};

///
/// Committee message handler FSM state transitioned from not-started state when FSM has been
/// started upon a new deliverable message arrival for the current node committee peer.
///
/// According to protocol definition this state will never be accessed by the FSM created for the
/// payload produced by current node(which means that the node is proposer/broadcaster itself)
///
/// The state machine remains in this state until the deliverable is successfully reconstructed.
/// Possible transitions are:
///     - WFV state if data reconstructed but not yet certified
///     - WFC state id data reconstructed and  valid integrity certificate information is available
///     - Done in case of any error
///
/// For more details see the message handling and state execution implementation
///
///
pub(crate) struct WaitingForData<C: SupraDeliveryErasureCodecSchema> {
    context: CommitteeFSMContext<C>,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(
    timestamp,
    WaitingForData<Schema: SupraDeliveryErasureCodecSchema>
);

impl<C: SupraDeliveryErasureCodecSchema> FSMContextOwner for WaitingForData<C> {
    type Schema = CommitteeFSMContextSchema<C>;
    fn context(&self) -> &CommitteeFSMContext<C> {
        &self.context
    }

    fn context_mut(&mut self) -> &mut CommitteeFSMContext<C> {
        &mut self.context
    }
}

impl<C: SupraDeliveryErasureCodecSchema> LoggingName for WaitingForData<C> {
    fn name<'a>() -> &'a str {
        "WaitingForData"
    }
}

impl<C: SupraDeliveryErasureCodecSchema> WaitingForData<C> {
    pub fn new(context: CommitteeFSMContext<C>) -> Self {
        Self {
            context,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    ///
    /// Consumes value data and returns broadcaster index
    /// Updates payload state based on value-data message
    ///     - store header if required
    ///     - adds the chunk
    ///     - marks broadcaster of the original message as peer having all data
    ///
    fn consume_value_data(&mut self, value_data: ValueData<C>) {
        let broadcaster = SenderExtractor::new(self.topology())
            .visit_value(&value_data)
            .unwrap()
            .position();
        // store payload header
        let (_header, chunk) = value_data.split();

        let current_node_index = self.topology().get_position();
        let state = self.payload_state_mut();

        // add chunk data
        let chunk_index = chunk.data().get_chunk_index();
        state
            .add_chunk(chunk, current_node_index == chunk_index)
            .unwrap();

        // Save sender as all chunks owner
        state.store_peer_with_all_chunks(broadcaster);
    }

    ///
    /// Consumes ready message and returns data sender information
    /// Updates payload state based on ready message
    ///     - store header if required
    ///     - adds the chunk
    ///     - marks ready message sender as peer having all data
    ///     - marks broadcaster of the original message as peer having all data
    ///
    fn consume_ready_data(&mut self, ready_data: ReadyData<C>) {
        let sender = SenderExtractor::new(self.topology())
            .visit_ready(&ready_data)
            .unwrap()
            .position();
        let (_, value_data) = ready_data.split();
        self.consume_value_data(value_data);

        let state = self.payload_state_mut();

        // Save sender as all chunks owner
        state.store_peer_with_all_chunks(sender);
    }

    pub fn echo_value_msg(&mut self, value_data: ValueData<C>) {
        let echo = self.message_factory().message_from(value_data);
        let addresses = self.assignment_extractor().visit_echo_value(&echo).unwrap();

        let msg = (RBCCommitteeMessage::EchoValue(echo), addresses);
        info!("{}: {} => {:?}", Self::name(), msg.0, msg.1);
        self.response_mut().add_message(msg);
    }

    ///
    /// send echo value message to the requester
    ///
    pub fn send_value_msg_to_requester(&mut self, owned_chunk: ChunkData<C>, requester: &Origin) {
        let value_data = ValueData::new(self.payload_state().get_header(), owned_chunk);
        let echo = self.message_factory().message_from(value_data);
        let address = self
            .topology()
            .get_address_by_origin(Protocol::XRBC, requester)
            .unwrap();
        let msg = (RBCCommitteeMessage::EchoValue(echo), vec![address]);
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

    fn echo_own_chunk_if_not_received(&mut self) {
        if !self.payload_state().is_reconstructed()
            || self.payload_state().failed()
            || self.resources().dissemination_rule() == DisseminationRule::Full
        {
            return;
        }
        let this_index = self.topology().get_position();
        if self.payload_state().has_chunk(this_index) {
            return;
        }
        let this_chunk = self
            .payload_state()
            .committee_chunks()
            .unwrap()
            .get(this_index)
            .unwrap()
            .clone();
        let header = self.payload_state().get_header();
        let value_data = ValueData::new(header, this_chunk);
        self.echo_value_msg(value_data);
    }
}

impl<C: SupraDeliveryErasureCodecSchema> State for WaitingForData<C> {
    fn entry(&mut self) {
        if self.payload_state().has_payload_data() {
            self.register_internal_error(
                "Invalid payload state with reconstructed data while entering WFD state"
                    .to_string(),
            );
        }
    }

    ///
    /// Tries to reconstruct the data based on the chunks received so far.
    /// Upon successful reconstruction and verification, the reconstructed payload along with full
    /// chunk info (committee and network) is stored. This will also lead to move to next state.
    /// If reconstruction fails due to not enough data availability then the execution ends with success
    /// If reconstruction fails due to any other error or
    /// If reconstruction is success but commitment verification fails then an internal error is
    /// reported as feedback and error is registered.
    ///
    fn execute(&mut self) {
        let result = {
            match self.resources().dissemination_rule() {
                DisseminationRule::Full => {
                    info!("Full reconstruction");
                    ReconstructedDataAssembler(&mut self.context).try_assemble()
                }
                DisseminationRule::Partial(_) => PayloadAssembler(&mut self.context).try_assemble(),
            }
        };
        match result {
            Ok(None) => {}
            Ok(Some((payload, mut encoded_data))) => {
                report(
                    &[
                        &CommitteePayloadTag::Delivery,
                        self.payload_state().header(),
                        &CommitteePayloadTag::TagName,
                    ],
                    MetricValue::AsSeconds(self.payload_state().elapsed_time()),
                );
                let state = self.payload_state_mut();
                let reconstructed_data = ReconstructedData::new(
                    payload,
                    encoded_data.take_committee_chunks(),
                    encoded_data.take_network_chunks(),
                );
                state.set_reconstructed_data(reconstructed_data);
            }
            Err(RBCError::InvalidDeliverable(origin)) => self.register_error_feedback(
                FeedbackMessage::Error(self.payload_state().get_meta(), origin),
            ),
            Err(e) => self.register_internal_error(format!("Failed to reconstruct data: {:?}", e)),
        }
    }

    ///
    /// Clears temporary data such as codec to drop the chunk data received so far.
    /// Exit happens if the data was successfully reconstructed or any error happened.
    /// In both cases intermediate chunk data is not required anymore.
    ///
    fn exit(&mut self) {
        self.payload_state_mut().codec_mut().reset_decoder();
        self.echo_own_chunk_if_not_received();
        self.broadcast_network_shares();
    }
}

/// Transition Interface definition from WaitingForData for CommitteeStateMachine

/// ------------------------------------------------------------------------------------------------
/// WaitingForData -> WaitingForVote
///
impl<C: SupraDeliveryErasureCodecSchema> Into<WaitingForVote<C>> for WaitingForData<C> {
    fn into(self) -> WaitingForVote<C> {
        WaitingForVote::new(self.context)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Transition<WaitingForVote<C>> for WaitingForData<C> {
    ///
    /// Transition to WFD state if
    ///     - no failure is registered
    ///     - and payload data is available
    ///     - and no certificate is available
    ///
    fn guard(&self) -> TransitGuard {
        (!self.payload_state().failed()
            && self.payload_state().has_payload_data()
            && !self.payload_state().is_certified())
        .into()
    }
}

/// ------------------------------------------------------------------------------------------------
/// WaitingForData -> WaitingForCertificate
///
impl<C: SupraDeliveryErasureCodecSchema> Into<WaitingForCertificate<C>> for WaitingForData<C> {
    fn into(self) -> WaitingForCertificate<C> {
        WaitingForCertificate::new(self.context)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Transition<WaitingForCertificate<C>>
    for WaitingForData<C>
{
    ///
    /// Transition to WFC state if
    ///     - no failure is registered
    ///     - and data is reconstructed
    ///     - and certificate is available
    ///
    fn guard(&self) -> TransitGuard {
        (!self.payload_state().failed()
            && self.payload_state().has_payload_data()
            && self.payload_state().is_certified())
        .into()
    }
}

/// ------------------------------------------------------------------------------------------------
/// WaitingForData -> DoneCommitteeFSM
///
impl<C: SupraDeliveryErasureCodecSchema> Into<DoneCommitteeFSM<C>> for WaitingForData<C> {
    fn into(self) -> DoneCommitteeFSM<C> {
        Done::new(self.context)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Transition<DoneCommitteeFSM<C>> for WaitingForData<C> {
    ///
    /// Transition to Done state if
    ///     - failure is registered
    ///
    fn guard(&self) -> TransitGuard {
        self.payload_state().failed().into()
    }
}

/// Message handling and Response Query interfaces for WaitingForData state of CommitteeStateMachine

impl<C: SupraDeliveryErasureCodecSchema> NetworkShareBroadcaster<C> for WaitingForData<C> {}

impl<C: SupraDeliveryErasureCodecSchema> ReturnMessage<CommitteeFSMResponseMessage<C>>
    for WaitingForData<C>
{
    fn return_message(&mut self) -> Option<CommitteeFSMResponseMessage<C>> {
        self.take_response()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> ReceiveMessage<RBCCommitteeMessage<C>>
    for WaitingForData<C>
{
    fn receive_message(&mut self, message: RBCCommitteeMessage<C>) {
        self.handle_message(message)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> InputVerifier<C, RBCCommitteeMessage<C>>
    for WaitingForData<C>
{
}

impl<C: SupraDeliveryErasureCodecSchema> CommitteeMessageReceiver<C> for WaitingForData<C> {}

impl<C: SupraDeliveryErasureCodecSchema> CommitteeMessageHandler for WaitingForData<C> {
    type Value = ValueData<C>;
    type EchoValue = EchoValueData<C>;
    type Ready = ReadyData<C>;
    type EchoReady = EchoReadyData<C>;

    ///
    /// Processes input value message.
    /// If the value message reached this stage, then it was verified successfully, i.e.
    ///     - its header is valid header constructed by broadcaster
    ///       (there is not any equal ID created based on the commitment produced by the broadcaster)
    ///     - chunk is valid one corresponding to commitment and index does not exceed committee size
    ///     - sender is from current committee and corresponding info is available
    ///     - and the data is not duplicate
    /// Note: This assumption is also true for any other message reaching this processing stage
    ///
    /// Processing of value message includes:
    ///     - header is stored if there is none stored yet
    ///     - chunk is added to the state and no error should be expected
    ///     - sender of the message is stored as peer having all chunks
    ///     - echo input value message to all peers that are not registered having all chunks
    /// Note: No error is expected to be reported when handling value message
    ///
    fn handle_value(&mut self, msg: Self::Value) {
        if !self.payload_state().has_chunk(msg.get_chunk_index()) {
            self.consume_value_data(msg.duplicate());
        }
        self.echo_value_msg(msg);
    }

    ///
    /// Processes input echo value message:
    ///     - header is stored if there is none stored yet
    ///     - chunk is added to the state and no error should be expected
    /// Note:
    ///     - No error is expected to be reported when handling echo value message
    ///     - as data and header is already successfully verified
    ///
    fn handle_echo_value(&mut self, msg: Self::EchoValue) {
        let value_data = msg.split();
        self.consume_value_data(value_data);
    }

    ///
    /// According to protocol non-broadcaster will not receive any vote messages, and
    /// FSM for the deliverable created for own message will not enter WFD state.
    /// Based on the above statements any vote message that receives this stage is indication of
    /// an internal error
    ///
    fn handle_vote(&mut self, msg: VoteData) {
        self.register_internal_error(format!(
            "Unexpected vote message in WFD state. Verification error: {:?}",
            msg
        ));
    }

    ///
    /// Processes input ready message:
    ///     - header is stored if there is none stored yet
    ///     - chunk is added to the state and no error should be expected
    ///     - sender of the message is stored as peer having all chunks
    ///     - store certificate data
    ///     - echo input ready message to all peers that are not registered having all chunks
    /// Note: No error is expected to be reported when handling value message
    ///
    fn handle_ready(&mut self, msg: Self::Ready) {
        self.consume_ready_data(msg.duplicate());
        self.echo_ready_msg(msg);
    }

    ///
    /// Processes input echo ready message:
    ///     - header is stored if there is none stored yet
    ///     - chunk is added to the state and no error should be expected
    ///     - sender of the ready message is stored as peer having all chunks
    ///     - store certificate data
    /// Note: No error is expected to be reported when handling value message
    ///
    fn handle_echo_ready(&mut self, msg: Self::EchoReady) {
        let ready_data = msg.split();
        self.consume_ready_data(ready_data);
    }

    ///
    /// Processes input value message:
    ///     - header is stored if there is none stored yet
    ///     - store certificate data
    /// Note: No error is expected to be reported when handling value message
    ///
    fn handle_certificate(&mut self, msg: QuorumCertificateData) {
        let (_header, _, qc) = msg.split();
        self.payload_state_mut().set_certificate(qc)
    }

    fn handle_pull_request(&mut self, msg: PullRequest) {
        if !self.payload_state().is_certified() {
            self.payload_state_mut().set_certificate(msg.get_qc());
        }
        if let Some(clan_member) = self.topology().is_clan_member(msg.sender()) {
            if clan_member {
                if let Some(owned_chunk) = self.payload_state().get_owned_chunk() {
                    self.send_value_msg_to_requester(owned_chunk, msg.sender());
                }
            }
        }
    }

    fn handle_sync_request(&mut self, msg: SyncRequest) {
        if !self.payload_state().is_certified() {
            self.payload_state_mut().set_certificate(msg.get_qc());
        }
    }

    fn handle_payload(&mut self, msg: PayloadData) {
        let (_, payload) = msg.split();
        let reconstructed_data = ReconstructedData::from_payload(payload);
        self.payload_state_mut()
            .set_reconstructed_data(reconstructed_data);
    }
}
