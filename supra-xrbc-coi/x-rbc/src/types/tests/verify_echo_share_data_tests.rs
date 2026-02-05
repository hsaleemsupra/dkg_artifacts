use crate::tasks::codec::EncodeResultIfc;
use crate::types::context::ResourcesApi;
use crate::types::helpers::verifier_visitor::verify_value_data_tests::{
    encoded_chunks, rs8_codec, TestResources,
};
use crate::types::helpers::verifier_visitor::VerifierVisitor;
use crate::types::helpers::Visitor;
use crate::types::messages::chunk::ChunkData;
use crate::types::messages::{EchoShareData, ValueData};
use crate::types::tests::{header_with_origin, value_data_with_header_idx};
use crate::SupraDeliveryErasureRs8Schema;
use metrics::TimeStampTrait;
use network::topology::peer_info::Role;
use primitives::types::Header;
use primitives::{Origin, PeerGlobalIndex};
use std::time::Duration;

#[tokio::test]
async fn verify_echo_share_data_with_invalid_origins() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);

    let current_global_index = PeerGlobalIndex::new(0, 2, 3);
    let current_node_resources = resource_provider.get_resources(current_global_index);
    let verifier = VerifierVisitor::new(&current_node_resources);

    // Non-Existent origin as broadcaster
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header_with_origin([0; 32]), 1);
    let share_msg = EchoShareData::new([2; 32], value_data);
    let result = verifier.visit_echo_share(&share_msg);
    assert!(result.is_err());

    // Existent origin as broadcaster but non-existent sender
    let origin = resource_provider.get_origin(&PeerGlobalIndex::new(0, 1, 2));
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header_with_origin(origin), 1);
    let share_msg = EchoShareData::new([2; 32], value_data);
    let result = verifier.visit_echo_share(&share_msg);
    assert!(result.is_err());

    // Expected-owner failed to deduced
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(
        header_with_origin(origin),
        1000,
    );
    let share_msg = EchoShareData::new(origin, value_data);
    let result = verifier.visit_echo_share(&share_msg);
    assert!(result.is_err());
}

#[tokio::test]
async fn verify_echo_share_data_with_incorrect_origins() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);

    let current_global_index = PeerGlobalIndex::new(0, 2, 3);
    let current_node_resources = resource_provider.get_resources(current_global_index);
    let verifier = VerifierVisitor::new(&current_node_resources);

    // origin and current node are from the same clan
    let origin = resource_provider.get_origin(&PeerGlobalIndex::new(0, 2, 2));
    let sender = resource_provider.get_origin(&PeerGlobalIndex::new(0, 2, 1));
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header_with_origin(origin), 1);
    let share_msg = EchoShareData::new(sender, value_data);
    let result = verifier.visit_echo_share(&share_msg);
    assert!(result.is_err());

    // origin and sender are from the same clan
    let leader_origin = resource_provider.get_origin(&global_index);
    let sender = resource_provider.get_origin(&PeerGlobalIndex::new(0, 0, 1));
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(
        header_with_origin(leader_origin),
        1,
    );
    let share_data = EchoShareData::new(sender, value_data);
    let result = verifier.visit_echo_share(&share_data);
    assert!(result.is_err());

    // Expected-owner and sender node are not the same
    let sender = resource_provider.get_origin(&PeerGlobalIndex::new(0, 2, 1));
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(
        header_with_origin(leader_origin),
        1,
    );
    let share_data = EchoShareData::new(sender, value_data);
    let result = verifier.visit_echo_share(&share_data);
    assert!(result.is_err());
}

#[tokio::test]
async fn verify_echo_share_data() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let resources = resource_provider.get_resources(global_index);
    let encoded_data = encoded_chunks(1, resources.authenticator());

    let current_global_index = PeerGlobalIndex::new(0, 2, 3);
    let current_node_resources = resource_provider.get_resources(current_global_index);
    let verifier = VerifierVisitor::new(&current_node_resources);

    let leader_origin = resource_provider.get_origin(&global_index);
    // network-chunk-commitment-index - 11, chunk-index - 6
    let sender = resource_provider.get_origin(&PeerGlobalIndex::new(0, 2, 1));

    // Invalid header
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(
        header_with_origin(leader_origin),
        11,
    );
    let share_msg = EchoShareData::new(sender, value_data);
    let result = verifier.visit_echo_share(&share_msg);
    assert!(result.is_err());

    // invalid chunk-data
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(
        encoded_data.header().clone(),
        11,
    );
    let share_msg = EchoShareData::new(sender, value_data);
    let result = verifier.visit_echo_share(&share_msg);
    assert!(result.is_err());

    let chunk_data = encoded_data.network_chunks()[7]
        .clone()
        .decode(rs8_codec())
        .unwrap();
    // Not owned chunk
    assert_eq!(chunk_data.data().get_commitment_index(), 12);
    let value_data = ValueData::new(encoded_data.header().clone(), chunk_data);
    let share_msg = EchoShareData::new(sender, value_data);
    let result = verifier.visit_echo_share(&share_msg);
    assert!(result.is_err());

    // valid echo share data
    let chunk_data = encoded_data.network_chunks()[6]
        .clone()
        .decode(rs8_codec())
        .unwrap();
    // Not owned chunk
    assert_eq!(chunk_data.data().get_commitment_index(), 11);
    let value_data = ValueData::new(encoded_data.header().clone(), chunk_data);
    let share_msg = EchoShareData::new(sender, value_data);
    let result = verifier.visit_echo_share(&share_msg);
    assert!(result.is_ok());
}

#[test]
fn echo_share_data_timestamp_works() {
    let value =
        ValueData::<SupraDeliveryErasureRs8Schema>::new(Header::default(), ChunkData::default());
    let test_struct = EchoShareData::new(Origin::default(), value);

    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}
