use crate::tasks::codec::{
    EncodeResult, EncodeResultIfc, SupraDeliveryCodec, SupraDeliveryErasureCodec,
    SupraDeliveryErasureCodecSchema,
};
use crate::tasks::config::DisseminationRule;
use crate::types::context::committee::CommitteeFSMContext;
use crate::types::context::network::NetworkFSMContext;
use crate::types::context::sync::SyncFSMContext;
use crate::types::context::{FSMContextOwner, Resources, ResourcesApi};
use crate::types::helpers::assignment_extractor::AssignmentExtractor;
use crate::types::helpers::verifier_visitor::verify_value_data_tests::{
    encoded_chunks, TestResources,
};
use crate::types::messages::ValueData;
use crate::types::payload_state::committee::{CommitteePayloadState, ReconstructedData};
use crate::types::payload_state::network::NetworkPayloadState;
use crate::types::payload_state::sync::{PayloadType, SyncPayloadState};
use crate::{QuorumCertificate, SupraDeliveryErasureRs8Schema};
use erasure::utils::codec_trait::{Codec, Setting};
use network::topology::peer_info::Role;
use primitives::types::{Header, HeaderIfc};
use primitives::{Payload, PeerGlobalIndex, Protocol};
use rand::{thread_rng, RngCore};
use sfsm::TransitGuard;
use vec_commitment::txn_generator::GeneratorType;

mod assemblers_tests;
mod committee_message_receiver_tests;
mod network_message_receiver_tests;
mod network_share_broadcaster;
mod not_started_committee_fsm;
mod not_started_network_fsm;
mod not_started_sync_fsm;
mod pull_request_broadcaster;
mod sync_message_receiver_tests;
mod unit_test_done_fsm;
mod unit_test_sync_ready;
mod unit_test_waiting_for_certificate_committee;
mod unit_test_waiting_for_data;
mod unit_test_waiting_for_share;
mod unit_test_waiting_for_sync_data_committee;
mod unit_test_waiting_for_sync_data_network;
mod waiting_for_vote_tests;

pub fn can_transaction_happen(guard: TransitGuard) -> bool {
    match guard {
        TransitGuard::Transit => true,
        TransitGuard::Remain => false,
    }
}

pub(crate) struct ContextProvider {
    resource_provider: TestResources,
    broadcaster_resources: Resources,
}

impl ContextProvider {
    pub(crate) fn new(broadcaster_index: PeerGlobalIndex) -> Self {
        let mut resource_provider = TestResources::new(Role::Leader, broadcaster_index);
        let broadcaster_resources = resource_provider.get_broadcaster_resources();
        Self {
            resource_provider,
            broadcaster_resources,
        }
    }

    pub fn resource_provider(&mut self) -> &mut TestResources {
        &mut self.resource_provider
    }

    pub(crate) fn committee_context<C: SupraDeliveryErasureCodecSchema>(
        &mut self,
        peer_index: PeerGlobalIndex,
    ) -> CommitteeFSMContext<C> {
        let header = TestResources::generate_header(
            self.broadcaster_resources.authenticator(),
            [thread_rng().next_u64() as u8; 32],
        );

        self.committee_context_with_header::<C>(header, peer_index)
    }

    pub(crate) fn committee_context_with_header<C: SupraDeliveryErasureCodecSchema>(
        &mut self,
        header: Header,
        peer_index: PeerGlobalIndex,
    ) -> CommitteeFSMContext<C> {
        self.committee_context_with_header_dissemination_rule(
            header,
            peer_index,
            DisseminationRule::default(),
        )
    }

    pub(crate) fn committee_context_with_header_dissemination_rule<
        C: SupraDeliveryErasureCodecSchema,
    >(
        &mut self,
        header: Header,
        peer_index: PeerGlobalIndex,
        rule: DisseminationRule,
    ) -> CommitteeFSMContext<C> {
        let resources = self
            .resource_provider
            .get_resources_with_rule(peer_index, rule);
        let payload_state = CommitteePayloadState::new(header, self.codec::<C>());

        let context: CommitteeFSMContext<C> = CommitteeFSMContext::new(payload_state, resources);
        context
    }

    pub(crate) fn network_context<C: SupraDeliveryErasureCodecSchema>(
        &mut self,
        peer_index: PeerGlobalIndex,
    ) -> NetworkFSMContext<C> {
        let header = TestResources::generate_header(
            self.broadcaster_resources.authenticator(),
            [thread_rng().next_u64() as u8; 32],
        );
        self.network_context_with_header(header, peer_index)
    }

    pub(crate) fn network_context_with_header<C: SupraDeliveryErasureCodecSchema>(
        &mut self,
        header: Header,
        peer_index: PeerGlobalIndex,
    ) -> NetworkFSMContext<C> {
        let resources = self.resource_provider.get_resources(peer_index);
        let payload_state = NetworkPayloadState::new(header, self.codec::<C>());

        let context: NetworkFSMContext<C> = NetworkFSMContext::new(payload_state, resources);
        context
    }

    pub(crate) fn committee_context_with_payload<C: SupraDeliveryErasureCodecSchema>(
        &mut self,
        peer_index: PeerGlobalIndex,
    ) -> CommitteeFSMContext<C> {
        self.committee_context_with_payload_dissemination_rule(
            peer_index,
            DisseminationRule::default(),
        )
    }

    pub(crate) fn committee_context_with_payload_dissemination_rule<
        C: SupraDeliveryErasureCodecSchema,
    >(
        &mut self,
        peer_index: PeerGlobalIndex,
        rule: DisseminationRule,
    ) -> CommitteeFSMContext<C> {
        let (result, payload) = self.encoded_data::<C>();
        let (header, committee_chunks, network_chunks) = result.split();
        let mut context =
            self.committee_context_with_header_dissemination_rule::<C>(header, peer_index, rule);
        context
            .payload_state_mut()
            .set_owned_chunk(committee_chunks.get(peer_index.position()).cloned());
        let reconstructed_data = ReconstructedData::new(payload, committee_chunks, network_chunks);
        context
            .payload_state_mut()
            .set_reconstructed_data(reconstructed_data);
        context
            .payload_state_mut()
            .store_peer_with_all_chunks(peer_index.position());
        context
    }

    pub(crate) fn network_context_with_payload<C: SupraDeliveryErasureCodecSchema>(
        &mut self,
        peer_index: PeerGlobalIndex,
    ) -> NetworkFSMContext<C> {
        let (result, payload) = self.encoded_data::<C>();
        let (header, _committee_chunks, _network_chunks) = result.split();
        let mut context = self.network_context_with_header::<C>(header, peer_index);
        context
            .payload_state_mut()
            .set_reconstructed_payload(Some(payload));
        context
    }

    pub(crate) fn codec<C: SupraDeliveryErasureCodecSchema>(&self) -> SupraDeliveryCodec<C> {
        let cmt_settings = self.resource_provider.committee_settings();
        let nt_settings = self.resource_provider.network_settings();
        let codec = SupraDeliveryCodec::<C>::new(
            <<C as SupraDeliveryErasureCodecSchema>::DataCodec as Codec>::Setting::new(
                cmt_settings.0,
                cmt_settings.1,
            ),
            Some(
                <<C as SupraDeliveryErasureCodecSchema>::DataCodec as Codec>::Setting::new(
                    nt_settings.0,
                    nt_settings.1,
                ),
            ),
        );
        codec
    }

    pub(crate) fn encoded_data<C: SupraDeliveryErasureCodecSchema>(
        &self,
    ) -> (EncodeResult<C>, Payload) {
        let codec = self.codec::<C>();

        let payload =
            bincode::serialize(&GeneratorType::Gibberish.spawn_the_generator(1000, 50)).unwrap();

        let result = codec
            .encode(payload.clone(), self.broadcaster_resources.authenticator())
            .unwrap();
        (result, payload)
    }

    pub(crate) fn sync_context<C: SupraDeliveryErasureCodecSchema>(
        &mut self,
        peer_index: PeerGlobalIndex,
        payload_type: PayloadType,
        header: Header,
    ) -> SyncFSMContext<C> {
        let resources = self.resource_provider.get_resources(peer_index);
        let payload_state = match payload_type {
            PayloadType::Committee => SyncPayloadState::for_committee(
                header,
                QuorumCertificate::default(),
                self.codec::<C>(),
            ),
            PayloadType::Network => SyncPayloadState::for_network(
                header,
                QuorumCertificate::default(),
                self.codec::<C>(),
            ),
        };

        let context: SyncFSMContext<C> = SyncFSMContext::new(payload_state, resources);
        context
    }

    pub(crate) fn sync_context_with_payload<C: SupraDeliveryErasureCodecSchema>(
        &mut self,
        peer_index: PeerGlobalIndex,
        payload_type: PayloadType,
    ) -> SyncFSMContext<C> {
        let resources = self.resource_provider.get_resources(peer_index);
        let (result, _payload) = self.encoded_data::<C>();
        let (header, committee_chunks, network_chunks) = result.split();
        let payload_state = match payload_type {
            PayloadType::Committee => SyncPayloadState::ready_for_committee(
                header,
                QuorumCertificate::default(),
                peer_index.position(),
                committee_chunks,
                network_chunks,
                self.codec(),
            ),
            PayloadType::Network => {
                let chunk_commitment_idx = AssignmentExtractor::new(
                    resources.topology(),
                    Protocol::XRBC,
                    &DisseminationRule::default(),
                )
                .target_chunk_index(header.origin(), resources.topology().origin());
                let owned_chunk_index =
                    chunk_commitment_idx - resources.topology().get_committee_size();
                SyncPayloadState::ready_for_network(
                    header,
                    QuorumCertificate::default(),
                    network_chunks
                        .get(owned_chunk_index)
                        .cloned()
                        .unwrap()
                        .decode(self.codec())
                        .unwrap(),
                    self.codec(),
                )
            }
        };

        let context: SyncFSMContext<C> = SyncFSMContext::new(payload_state, resources);
        context
    }
}

pub(crate) fn create_committee_value(
    seed: u8,
    resource: &Resources,
) -> Vec<ValueData<SupraDeliveryErasureRs8Schema>> {
    let mut encode_result = encoded_chunks(seed, resource.authenticator());
    let committee_chunks = encode_result.take_committee_chunks();
    committee_chunks
        .into_iter()
        .map(|chunk| ValueData::new(encode_result.header().clone(), chunk))
        .collect::<Vec<ValueData<SupraDeliveryErasureRs8Schema>>>()
}
