use crate::tasks::codec::EncodeResultIfc;
use metrics::TimeStampTrait;
use std::time::Duration;

use crate::types::context::ResourcesApi;
use crate::types::helpers::verifier_visitor::verify_value_data_tests::{
    encoded_chunks, TestResources,
};
use crate::types::helpers::verifier_visitor::VerifierVisitor;
use crate::types::helpers::Visitor;
use crate::types::messages::chunk::ChunkData;
use crate::types::messages::{EchoValueData, ValueData};
use crate::types::tests::{header_with_origin, value_data_with_header_idx};
use crate::SupraDeliveryErasureRs8Schema;
use network::topology::peer_info::Role;
use primitives::types::{Header, HeaderIfc};
use primitives::PeerGlobalIndex;

#[tokio::test]
async fn verify_echo_value_data_with_invalid_owner_data() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let resources = resource_provider.get_resources(global_index);
    let encoded_data = encoded_chunks(1, resources.authenticator());
    let echo_data = EchoValueData::new(ValueData::new(
        encoded_data.header().clone(),
        encoded_data.committee_chunks()[0].clone(),
    ));

    // Resources for peer (0, 0, 0) and echo_value data for node 0
    let verifier = VerifierVisitor::new(&resources);
    let result = verifier.visit_echo_value(&echo_data);
    assert!(result.is_err());

    // Resources for peer (0, 1, 0) and echo value data for node from clan (0, 0)
    let resources = resource_provider.get_resources(PeerGlobalIndex::new(0, 1, 0));
    let verifier = VerifierVisitor::new(&resources);
    let result = verifier.visit_echo_value(&echo_data);
    assert!(result.is_err());
}

#[tokio::test]
async fn verify_echo_value_data_with_invalid_header() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let resources = resource_provider.get_resources(global_index);
    let encoded_data = encoded_chunks(1, resources.authenticator());
    let header = header_with_origin(*encoded_data.header().origin());
    let echo_data = EchoValueData::new(ValueData::new(
        header,
        encoded_data.committee_chunks()[0].clone(),
    ));

    let resources_001 = resource_provider.get_resources(PeerGlobalIndex::new(0, 0, 1));
    assert!(!resources_001.topology().current_node().is_proposer());

    // Resources for peer (0, 0, 1) and value data for node 1
    let verifier = VerifierVisitor::new(&resources_001);
    let result = verifier.visit_echo_value(&echo_data);
    assert!(result.is_err());

    // Valid chunk header but not from proposer
    let header = TestResources::generate_header(
        resources_001.authenticator(),
        *encoded_data.header().commitment(),
    );
    let echo_data = EchoValueData::new(ValueData::new(
        header,
        encoded_data.committee_chunks()[0].clone(),
    ));

    let result = verifier.visit_echo_value(&echo_data);
    assert!(result.is_err());
}

#[tokio::test]
async fn verify_echo_value_data() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let resources = resource_provider.get_resources(global_index);
    let encoded_data = encoded_chunks(1, resources.authenticator());
    let echo_data =
        EchoValueData::new(value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(
            encoded_data.header().clone(),
            0,
        ));

    let resources_001 = resource_provider.get_resources(PeerGlobalIndex::new(0, 0, 1));
    assert!(!resources_001.topology().current_node().is_proposer());

    // Resources for peer (0, 0, 1) and value data for node 1 and invalid chunk data
    let verifier = VerifierVisitor::new(&resources_001);
    let result = verifier.visit_echo_value(&echo_data);
    assert!(result.is_err());

    let echo_data = EchoValueData::new(ValueData::new(
        encoded_data.header().clone(),
        encoded_data.committee_chunks()[0].clone(),
    ));

    let result = verifier.visit_echo_value(&echo_data);
    assert!(result.is_ok());
}

#[test]
fn echo_value_data_timestamp_works() {
    let value =
        ValueData::<SupraDeliveryErasureRs8Schema>::new(Header::default(), ChunkData::default());
    let test_struct = EchoValueData::new(value);
    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}
