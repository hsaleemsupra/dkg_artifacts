use crate::types::context::committee::CommitteeFSMContextSchema;
use crate::types::context::network::NetworkFSMContextSchema;
use crate::types::context::{FSMContext, FSMContextOwner, ResourcesApi};
use crate::types::helpers::verifier_visitor::verify_value_data_tests::{rs8_codec, TestResources};
use crate::types::payload_state::committee::CommitteePayloadState;
use crate::types::payload_state::network::NetworkPayloadState;
use crate::types::tests::header_with_origin;
use network::topology::peer_info::Role;
use primitives::PeerGlobalIndex;

#[tokio::test]
async fn test_owned_data_chunk_index() {
    let leader_index = PeerGlobalIndex::new(0, 2, 1);
    let mut resource_provider = TestResources::new(Role::Leader, leader_index);
    let resources_000 = resource_provider.get_resources(PeerGlobalIndex::new(0, 0, 0));
    let resources_012 = resource_provider.get_resources(PeerGlobalIndex::new(0, 1, 2));
    let resources_020 = resource_provider.get_resources(PeerGlobalIndex::new(0, 2, 0));
    let resources_021 = resource_provider.get_resources(leader_index);
    let header = header_with_origin(resource_provider.get_origin(&leader_index));

    let context_021 = FSMContext::<CommitteeFSMContextSchema<_>>::new(
        CommitteePayloadState::new(header.clone(), rs8_codec()),
        resources_021,
    );
    let result = context_021.owned_chunk_data_index();
    assert_eq!(result, context_021.topology().get_position());

    let context_020 = FSMContext::<CommitteeFSMContextSchema<_>>::new(
        CommitteePayloadState::new(header.clone(), rs8_codec()),
        resources_020,
    );

    let result = context_020.owned_chunk_data_index();
    assert_eq!(result, context_020.topology().get_position());

    // Network with 1 tribe, 3 clans with 5 nodes
    let context_000 = FSMContext::<NetworkFSMContextSchema<_>>::new(
        NetworkPayloadState::new(header.clone(), rs8_codec()),
        resources_000,
    );
    let result = context_000.owned_chunk_data_index();
    assert_eq!(result, 0);

    // Network with 1 tribe, 3 clans with 5 nodes
    let context_012 = FSMContext::<NetworkFSMContextSchema<_>>::new(
        NetworkPayloadState::new(header.clone(), rs8_codec()),
        resources_012,
    );
    let result = context_012.owned_chunk_data_index();
    assert_eq!(result, 7);
}
