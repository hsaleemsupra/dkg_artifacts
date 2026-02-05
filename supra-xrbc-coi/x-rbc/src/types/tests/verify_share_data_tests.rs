use crate::tasks::codec::EncodeResultIfc;
use crate::types::context::ResourcesApi;
use crate::types::helpers::verifier_visitor::verify_value_data_tests::{
    encoded_chunks, TestResources,
};
use crate::types::helpers::verifier_visitor::VerifierVisitor;
use crate::types::helpers::Visitor;
use crate::types::messages::chunk::ChunkData;
use crate::types::messages::{ShareData, ValueData};
use crate::types::tests::{header_with_origin, share_data, value_data_with_header_idx};
use crate::SupraDeliveryErasureRs8Schema;
use metrics::TimeStampTrait;
use network::topology::peer_info::Role;
use primitives::types::Header;
use primitives::{Origin, PeerGlobalIndex};
use std::time::Duration;
use vec_commitment::committed_chunk::CommitmentMeta;

#[tokio::test]
async fn verify_share_data_with_invalid_origins() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);

    let current_global_index = PeerGlobalIndex::new(0, 2, 3);
    let current_node_resources = resource_provider.get_resources(current_global_index);
    let verifier = VerifierVisitor::new(&current_node_resources);

    // Non-Existent origin as broadcaster
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header_with_origin([0; 32]), 1);
    let share_msg = share_data([2; 32], value_data);
    let result = verifier.visit_share(&share_msg);
    assert!(result.is_err());

    // Existent origin as broadcaster but non-existent sender
    let origin = resource_provider.get_origin(&PeerGlobalIndex::new(0, 1, 2));
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header_with_origin(origin), 1);
    let share_msg = share_data([2; 32], value_data);
    let result = verifier.visit_share(&share_msg);
    assert!(result.is_err());

    // Expected-owner failed to deduced
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header_with_origin(origin), 1);
    let share_msg = ShareData::new(
        origin,
        value_data,
        CommitmentMeta::new(10000, vec![], [0; 32]),
    );
    let result = verifier.visit_share(&share_msg);
    assert!(result.is_err());
}

#[tokio::test]
async fn verify_share_data_with_incorrect_origins() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);

    // global index (0, 2, 2) = 2 * 5 + 2
    let commitment_meta = CommitmentMeta::new(12, vec![], [0; 32]);

    let current_global_index = PeerGlobalIndex::new(0, 2, 3);
    let current_node_resources = resource_provider.get_resources(current_global_index);
    let verifier = VerifierVisitor::new(&current_node_resources);

    // origin and current node are from the same clan
    let origin = resource_provider.get_origin(&PeerGlobalIndex::new(0, 2, 2));
    let sender = resource_provider.get_origin(&PeerGlobalIndex::new(0, 2, 1));
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header_with_origin(origin), 1);
    let share_msg = ShareData::new(sender, value_data, commitment_meta.clone());
    let result = verifier.visit_share(&share_msg);
    assert!(result.is_err());

    // origin and sender are not from the same clan
    let leader_origin = resource_provider.get_origin(&global_index);
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(
        header_with_origin(leader_origin),
        1,
    );
    let share_data = ShareData::new(sender, value_data, commitment_meta.clone());
    let result = verifier.visit_share(&share_data);
    assert!(result.is_err());

    // Expected-owner and current node are not the same
    let sender = resource_provider.get_origin(&PeerGlobalIndex::new(0, 0, 1));
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(
        header_with_origin(leader_origin),
        1,
    );
    let share_data = ShareData::new(sender, value_data, commitment_meta);
    let result = verifier.visit_share(&share_data);
    assert!(result.is_err());

    // Sender node and chunk piece have different positions
    let sender = resource_provider.get_origin(&PeerGlobalIndex::new(0, 0, 1));
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(
        header_with_origin(leader_origin),
        3,
    );
    let commitment_meta = CommitmentMeta::new(13, vec![], [0; 32]);
    let share_msg = ShareData::new(sender, value_data, commitment_meta);
    let result = verifier.visit_share(&share_msg);
    assert!(result.is_err());
}

#[tokio::test]
async fn verify_share_data() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let resources = resource_provider.get_resources(global_index);
    let encoded_data = encoded_chunks(1, resources.authenticator());

    // global index (0, 2, 3) = 2 * 5 + 3
    let commitment_meta = CommitmentMeta::new(13, vec![], [0; 32]);

    let current_global_index = PeerGlobalIndex::new(0, 2, 3);
    let current_node_resources = resource_provider.get_resources(current_global_index);
    let verifier = VerifierVisitor::new(&current_node_resources);

    // Invalid header
    let leader_origin = resource_provider.get_origin(&global_index);
    let sender = resource_provider.get_origin(&PeerGlobalIndex::new(0, 0, 1));
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(
        header_with_origin(leader_origin),
        1,
    );
    let share_msg = ShareData::new(sender, value_data, commitment_meta.clone());
    let result = verifier.visit_share(&share_msg);
    assert!(result.is_err());

    // invalid chunk-data
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(
        encoded_data.header().clone(),
        1,
    );
    let share_msg = ShareData::new(sender, value_data, commitment_meta);
    let result = verifier.visit_share(&share_msg);
    assert!(result.is_err());

    let (meta, pieces) = encoded_data.network_chunks()[8].clone().split();
    // Not owned chunk
    assert_eq!(meta.index(), 13);
    let value_data = ValueData::new(encoded_data.header().clone(), pieces[2].clone());
    let share_msg = ShareData::new(sender, value_data, meta.clone());
    let result = verifier.visit_share(&share_msg);
    assert!(result.is_err());

    // valid share data but invalid commitment_meta
    let value_data = ValueData::new(encoded_data.header().clone(), pieces[1].clone());
    let invalid_meta = CommitmentMeta::new(meta.index(), meta.proof().clone(), [0; 32]);
    let share_msg = ShareData::new(sender, value_data, invalid_meta);
    let result = verifier.visit_share(&share_msg);
    assert!(result.is_err());

    // valid share data
    let value_data = ValueData::new(encoded_data.header().clone(), pieces[1].clone());
    let share_msg = ShareData::new(sender, value_data, meta);
    let result = verifier.visit_share(&share_msg);
    assert!(result.is_ok());
}

#[test]
fn share_data_timestamp_works() {
    let value =
        ValueData::<SupraDeliveryErasureRs8Schema>::new(Header::default(), ChunkData::default());
    let test_struct = ShareData::new(Origin::default(), value, CommitmentMeta::default());

    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}
