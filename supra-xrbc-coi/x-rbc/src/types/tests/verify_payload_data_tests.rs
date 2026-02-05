use crate::tasks::codec::EncodeResultIfc;
use metrics::TimeStampTrait;
use std::time::Duration;

use crate::types::context::ResourcesApi;
use crate::types::helpers::verifier_visitor::verify_value_data_tests::{
    encoded_chunks, payload, TestResources,
};
use crate::types::helpers::verifier_visitor::VerifierVisitor;
use crate::types::helpers::Visitor;
use crate::types::messages::chunk::ChunkData;
use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::{EchoValueData, ValueData};
use crate::types::tests::{header_with_origin, value_data_with_header_idx};
use crate::SupraDeliveryErasureRs8Schema;
use network::topology::peer_info::Role;
use primitives::types::{Header, HeaderIfc};
use primitives::PeerGlobalIndex;

#[tokio::test]
async fn verify_payload_data_with_valid_header() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let peer_index = PeerGlobalIndex::new(0, 1, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let leader_resources = resource_provider.get_resources(global_index);
    let peer_resources = resource_provider.get_resources(peer_index);
    let payload = payload(1);
    let encoded_data = encoded_chunks(1, leader_resources.authenticator());
    let payload_data = PayloadData::new(encoded_data.header().clone(), payload);

    let verifier = VerifierVisitor::new(&peer_resources);
    let result = <VerifierVisitor as Visitor<SupraDeliveryErasureRs8Schema>>::visit_payload(
        &verifier,
        &payload_data,
    );
    assert!(result.is_ok());
}

#[tokio::test]
async fn verify_payload_data_with_invalid_header() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let peer_index = PeerGlobalIndex::new(0, 1, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let leader_resources = resource_provider.get_resources(global_index);
    let peer_resources = resource_provider.get_resources(peer_index);
    let payload = payload(1);
    let payload_data = PayloadData::new(
        header_with_origin(leader_resources.topology().origin().clone()),
        payload,
    );

    // Leader origin but invalid commitment and id
    let verifier = VerifierVisitor::new(&peer_resources);
    let result = <VerifierVisitor as Visitor<SupraDeliveryErasureRs8Schema>>::visit_payload(
        &verifier,
        &payload_data,
    );
    assert!(result.is_err());
}
