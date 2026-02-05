use crate::tasks::codec::EncodeResultIfc;
use metrics::TimeStampTrait;
use std::time::Duration;

use crate::types::helpers::verifier_visitor::verify_value_data_tests::{
    encoded_chunks, TestResources,
};
use crate::types::helpers::verifier_visitor::VerifierVisitor;
use crate::types::helpers::Visitor;
use crate::types::messages::{EchoReadyData, ReadyData, ValueData};
use crate::types::tests::{
    header_with_origin, ready_data, value_data_with_header, value_data_with_header_idx,
    TestSupraCodec,
};
use crate::SupraDeliveryErasureRs8Schema;
use primitives::types::{Header, HeaderIfc};

use network::topology::peer_info::Role;

use crate::types::context::ResourcesApi;
use crate::types::messages::chunk::ChunkData;
use primitives::{Origin, PeerGlobalIndex};

#[tokio::test]
async fn verify_echo_ready_data_with_invalid_header() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let resources = resource_provider.get_resources(global_index);
    let encoded_data = encoded_chunks(1, resources.authenticator());
    let sender = resource_provider.get_origin(&PeerGlobalIndex::new(0, 0, 2));

    let resources_001 = resource_provider.get_resources(PeerGlobalIndex::new(0, 0, 1));
    assert!(!resources_001.topology().current_node().is_proposer());

    // Resources for peer (0, 0, 1) and invalid header
    let header = header_with_origin(*encoded_data.header().origin());
    let ready = EchoReadyData::new(ready_data(
        sender,
        value_data_with_header::<TestSupraCodec>(header),
    ));

    let verifier = VerifierVisitor::new(&resources_001);
    let result = verifier.visit_echo_ready(&ready);
    assert!(result.is_err());

    // Valid chunk header but not from proposer
    let header = TestResources::generate_header(
        resources_001.authenticator(),
        *encoded_data.header().commitment(),
    );
    let value_data = ValueData::new(header, encoded_data.committee_chunks()[1].clone());
    let ready = EchoReadyData::new(ready_data(sender, value_data));

    let result = verifier.visit_echo_ready(&ready);
    assert!(result.is_err());
}

#[tokio::test]
async fn verify_echo_ready_data() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let resources = resource_provider.get_resources(global_index);
    let encoded_data = encoded_chunks(1, resources.authenticator());
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(
        encoded_data.header().clone(),
        1,
    );

    let sender = resource_provider.get_origin(&PeerGlobalIndex::new(0, 0, 2));

    let resources_001 = resource_provider.get_resources(PeerGlobalIndex::new(0, 0, 1));
    assert!(!resources_001.topology().current_node().is_proposer());

    // Resources for peer (0, 0, 1) and ready data for node 1 and invalid chunk data
    let ready = EchoReadyData::new(ready_data(sender, value_data));
    let verifier = VerifierVisitor::new(&resources_001);
    let result = verifier.visit_echo_ready(&ready);
    assert!(result.is_err());

    // Valid data
    let value_data = ValueData::new(
        encoded_data.header().clone(),
        encoded_data.committee_chunks()[1].clone(),
    );

    let ready = ReadyData::new(sender, value_data);
    let result = verifier.visit_echo_ready(&EchoReadyData::new(ready));
    assert!(result.is_ok());
}

#[test]
fn echo_ready_data_timestamp_works() {
    let value =
        ValueData::<SupraDeliveryErasureRs8Schema>::new(Header::default(), ChunkData::default());
    let echo = ReadyData::new(Origin::default(), value);
    let test_struct = EchoReadyData::new(echo);

    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}
