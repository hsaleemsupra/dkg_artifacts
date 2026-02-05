use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::config::DisseminationRule;
use crate::tasks::LoggingName;
use crate::types::context::committee::CommitteeFSMContextSchema;
use crate::types::context::{FSMContext, FSMContextOwner, FSMContextSchema, ResourcesApi};
use crate::types::helpers::assignment_extractor::AssignmentExtractor;
use crate::types::helpers::message_factory::{MessageFactoryTrait, MessageFrom};
use crate::types::helpers::Visitor;
use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    EchoValueData, RBCCommitteeMessage, RBCNetworkMessage, ResponseTypeIfc, ShareData, ValueData,
};
use crate::types::payload_state::committee::CommitteePayloadFlags;
use crate::types::payload_state::{NetworkChunkDataSettings, PayloadDataSettings, PayloadFlags};
use crate::QuorumCertificateData;
use log::info;
use network::topology::PeerFilterPredicate;
use primitives::types::{HeaderIfc, QuorumCertificate};
use primitives::{Addresses, HASH64};
use std::collections::HashSet;

///
/// Broadcast network share pieces upon request if any.
/// Request will be ignored if current payload state error or not reconstructed
///
pub(crate) trait NetworkShareBroadcaster<C: SupraDeliveryErasureCodecSchema>
where
    Self: FSMContextOwner<Schema = CommitteeFSMContextSchema<C>> + LoggingName,
{
    ///
    /// List of ShareData for the rest of the network peers containing network chunk piece
    /// which has index equal to current node position
    ///
    fn get_share_data(&mut self) -> Vec<ShareData<C>> {
        let network_chunks = self.payload_state().network_chunks().unwrap();
        let header = self.payload_state().get_header();
        let position = self.topology().get_position();
        let sender = self.topology().origin();
        network_chunks
            .iter()
            .map(|chunk| chunk.split_ref())
            .map(|(meta, pieces)| (meta, pieces.get(position).unwrap()))
            .map(|(meta, piece)| (meta, ValueData::new(header.clone(), piece.clone())))
            .map(|(meta, piece_value)| ShareData::new(*sender, piece_value, meta.clone()))
            .collect()
    }

    ///
    /// Adds share messages as response for the rest of the network members
    /// The shared data target has global index equal to chunk commitment index
    /// relative to current peer clan
    ///
    fn broadcast_network_shares(&mut self) {
        if self.payload_state().network_chunks_len() == 0 || self.payload_state().failed() {
            return;
        }
        for share in self.get_share_data().into_iter() {
            let addresses = self.assignment_extractor().visit_share(&share).unwrap();
            // info!("{}: {} => {:?}", Self::name(), share, addresses);
            self.response_mut()
                .add_aux_message((RBCNetworkMessage::Share(share), addresses));
        }
    }
}

///
/// Broadcast committee chunk upon broadcaster node request .
/// Request will be ignored if current node is not broadcaster
///
pub(crate) trait CommitteeChunkBroadcaster<C: SupraDeliveryErasureCodecSchema>
where
    Self:
        FSMContextOwner<Schema = CommitteeFSMContextSchema<C>> + LoggingName + MessageFactoryTrait,
{
    fn is_data_broadcaster(&self) -> bool {
        self.topology().origin() == self.payload_state().origin()
    }

    fn get_committee_value_data(&mut self) -> Vec<ValueData<C>> {
        let committee_chunks = self.payload_state().committee_chunks().unwrap();
        let header = self.payload_state().header();
        committee_chunks
            .iter()
            .map(|chunk| ValueData::new(header.clone(), chunk.clone()))
            .collect()
    }

    fn prepare_value_message(
        &self,
        value_data: ValueData<C>,
    ) -> (RBCCommitteeMessage<C>, Addresses) {
        let addresses = self
            .assignment_extractor()
            .visit_value(&value_data)
            .unwrap();
        (RBCCommitteeMessage::Value(value_data), addresses)
    }

    fn prepare_echo_message(
        &self,
        value_data: ValueData<C>,
    ) -> (RBCCommitteeMessage<C>, Addresses) {
        let echo_data: EchoValueData<C> = self.message_factory().message_from(value_data);
        let addresses = self
            .assignment_extractor()
            .visit_echo_value(&echo_data)
            .unwrap();
        (RBCCommitteeMessage::EchoValue(echo_data), addresses)
    }

    fn broadcast_committee_data(&mut self) {
        if !self.is_data_broadcaster() {
            return;
        }
        match self.resources().dissemination_rule() {
            DisseminationRule::Full => self.broadcast_payload(),
            DisseminationRule::Partial(_) => self.broadcast_committee_chunks(),
        }
    }

    fn broadcast_committee_chunks(&mut self) {
        let current_node_index = self.topology().get_position();
        for data in self.get_committee_value_data() {
            let message = if data.get_chunk_index() == current_node_index {
                self.prepare_echo_message(data)
            } else {
                self.prepare_value_message(data)
            };
            // info!("{}: {} => {:?}", Self::name(), message.0, message.1);
            self.response_mut().add_message(message);
        }
    }

    fn broadcast_payload(&mut self) {
        let payload = self
            .payload_state()
            .reconstructed_payload()
            .unwrap()
            .clone();
        let header = self.payload_state().header().clone();
        let payload_data = PayloadData::new(header, payload);
        let targets = <AssignmentExtractor as Visitor<C>>::visit_payload(
            &self.resources().assignment_extractor(),
            &payload_data,
        )
        .unwrap();
        self.response_mut()
            .add_message((RBCCommitteeMessage::Payload(payload_data), targets));
    }

    /// # STD
    /// broadcast QuorumCertificateData to all peers.
    ///
    /// # Panic
    /// * if payload header is not already assigned
    /// * task is unchecked during transition to WFV state
    /// * IllFormatted QuorumCertificate
    fn broadcast_quorum_certificate_data(&mut self, qc_signature: HASH64, qc: QuorumCertificate) {
        if !self.is_data_broadcaster() {
            return;
        }
        if !self.payload_state().is_certified() {
            return;
        }
        let header = self.payload_state().get_header();
        let qc_data = QuorumCertificateData::new(header, qc_signature, qc);
        let addresses = <AssignmentExtractor as Visitor<C>>::visit_certificate(
            &self.assignment_extractor(),
            &qc_data,
        )
        .unwrap();
        let message = (RBCCommitteeMessage::<C>::Certificate(qc_data), addresses);
        info!("{}: {} => {:?}", Self::name(), message.0, message.1);
        self.response_mut().add_message(message);
    }
}

///
/// Broadcast pull request to the peers in the chain/network
///
pub(crate) trait PullRequestBroadcaster<ContextSchema, OutputMessageType>
where
    Self: FSMContextOwner<Schema = ContextSchema>,
    ContextSchema: FSMContextSchema,
    ContextSchema::ResponseType: ResponseTypeIfc<MessageType = OutputMessageType>,
    OutputMessageType: From<PullRequest>,
{
    ///
    /// Send pull request to all the peers in clan or in network depending on data origin and
    /// node origin relation
    ///
    fn broadcast_pull_request(&mut self, sync: SyncRequest) {
        let pull = self.message_factory().message_from(sync);
        let broadcaster = pull.header().origin();
        let mut assignment_extractor = self.assignment_extractor();
        let exclude = self
            .get_received_chunks_owners_indexes()
            .into_iter()
            .map(|idx| {
                assignment_extractor.assigned_target_index_by_commitment_index(broadcaster, idx)
            })
            .collect::<Vec<_>>();

        let pleft = PeerFilterPredicate::NotWithFlattenedIndex(
            &exclude,
            self.topology().get_tribe_size(),
            self.topology().get_committee_size(),
        );
        assignment_extractor.add_custom_filter(pleft);
        let addresses =
            <AssignmentExtractor as Visitor<ContextSchema::CodecSchema>>::visit_pull_request(
                &assignment_extractor,
                &pull,
            )
            .unwrap();
        let msg = (pull, addresses);
        info!("{} => {:?}", msg.0, msg.1);
        self.response_mut().add_message_data(msg);
    }

    ///
    /// Should return received chunks owners flattened indexes with respect to the "transformed"
    /// chain topology, where message broadcaster clan is the very first clan(0, 0) in the chain
    ///
    fn get_received_chunks_owners_indexes(&self) -> HashSet<usize>;
}

///
/// Wrapper to handle pull request broadcast to committee members taking into account already
/// received data from committee
///
pub(crate) struct PullRequestBroadcasterCommittee<'a, ContextSchema: FSMContextSchema>(
    pub(crate) &'a mut FSMContext<ContextSchema>,
);

impl<'a, ContextSchema> FSMContextOwner for PullRequestBroadcasterCommittee<'a, ContextSchema>
where
    ContextSchema: FSMContextSchema,
{
    type Schema = ContextSchema;

    fn context(&self) -> &FSMContext<Self::Schema> {
        self.0
    }

    fn context_mut(&mut self) -> &mut FSMContext<Self::Schema> {
        self.0
    }
}

impl<'a, ContextSchema, OutputMessageType> PullRequestBroadcaster<ContextSchema, OutputMessageType>
    for PullRequestBroadcasterCommittee<'a, ContextSchema>
where
    ContextSchema: FSMContextSchema,
    ContextSchema::ResponseType: ResponseTypeIfc<MessageType = OutputMessageType>,
    ContextSchema::PayloadStateType: PayloadDataSettings<ContextSchema::CodecSchema>,
    OutputMessageType: From<PullRequest>,
{
    ///
    /// Returns indexes of the chunks as flattened indexes of broadcaster-clan-peers(wrt to topology
    /// system where broadcaster clan is at position (0,0))
    ///
    fn get_received_chunks_owners_indexes(&self) -> HashSet<usize> {
        self.payload_state().get_received_chunks()
    }
}

///
/// Wrapper to handle pull request broadcast to network members taking into account already
/// received data from network
///
pub(crate) struct PullRequestBroadcasterNetwork<'a, ContextSchema: FSMContextSchema>(
    pub(crate) &'a mut FSMContext<ContextSchema>,
);

impl<'a, ContextSchema> FSMContextOwner for PullRequestBroadcasterNetwork<'a, ContextSchema>
where
    ContextSchema: FSMContextSchema,
{
    type Schema = ContextSchema;

    fn context(&self) -> &FSMContext<Self::Schema> {
        self.0
    }

    fn context_mut(&mut self) -> &mut FSMContext<Self::Schema> {
        self.0
    }
}

impl<'a, ContextSchema, OutputMessageType> PullRequestBroadcaster<ContextSchema, OutputMessageType>
    for PullRequestBroadcasterNetwork<'a, ContextSchema>
where
    ContextSchema: FSMContextSchema,
    ContextSchema::ResponseType: ResponseTypeIfc<MessageType = OutputMessageType>,
    ContextSchema::PayloadStateType: NetworkChunkDataSettings<ContextSchema::CodecSchema>
        + PayloadDataSettings<ContextSchema::CodecSchema>,
    OutputMessageType: From<PullRequest>,
{
    ///
    /// Returns flattened indexes of the chain-peers(wrt to topology system where broadcaster clan
    /// is at position (0,0)) from which data has been already received|not expected anymore
    ///
    fn get_received_chunks_owners_indexes(&self) -> HashSet<usize> {
        let clan_size = self.topology().get_committee_size();
        let network_senders = self
            .payload_state()
            .get_received_chunks()
            .into_iter()
            .map(|index| index + clan_size)
            .collect::<HashSet<_>>();
        let owned_chunk_commitment_index = self
            .assignment_extractor()
            .assigned_chunk_index(self.payload_state().origin());
        // if owned chunk is available do not send pull request to broadcaster clan members
        let mut data_senders = if network_senders.contains(&owned_chunk_commitment_index) {
            // all the peers indexes in broadcaster clan(BC) is assumed have sent the data
            (0..self.topology().get_committee_size()).collect()
        } else {
            // otherwise take the piece indexes so far received which match peer position at BC
            self.payload_state().get_received_pieces()
        };
        data_senders.extend(network_senders);
        data_senders
    }
}
