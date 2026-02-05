use crate::tasks::codec::EncodeResultIfc;

use crate::types::context::ResourcesApi;
use crate::types::helpers::verifier_visitor::verify_value_data_tests::{
    encoded_chunks, TestResources,
};
use crate::types::helpers::verifier_visitor::VerifierVisitor;
use crate::types::helpers::Visitor;
use crate::types::messages::{EchoValueData, RBCCommitteeMessage, ValueData};
use crate::types::tests::{header_with_origin, value_data_with_header};
use crate::SupraDeliveryErasureRs8Schema;
use network::topology::peer_info::Role;
use primitives::types::HeaderIfc;
use primitives::PeerGlobalIndex;

#[tokio::test]
async fn verify_composite_data() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let resources = resource_provider.get_resources(global_index);
    let encoded_data = encoded_chunks(1, resources.authenticator());

    let header1 = header_with_origin(*encoded_data.header().origin());
    let header2 = header_with_origin([2; 32]);
    let value_data = value_data_with_header::<SupraDeliveryErasureRs8Schema>(header2);
    let echo_data = EchoValueData::new(ValueData::new(
        header1,
        encoded_data.committee_chunks()[0].clone(),
    ));

    let resources_001 = resource_provider.get_resources(PeerGlobalIndex::new(0, 0, 1));
    assert!(!resources_001.topology().current_node().is_proposer());

    // Different Headers
    let verifier = VerifierVisitor::new(&resources_001);
    let result = verifier.visit_composite(&vec![
        RBCCommitteeMessage::Value(value_data),
        RBCCommitteeMessage::EchoValue(echo_data),
    ]);
    assert!(result.is_err());

    // Valid Header invalid data
    let value_data = ValueData::new(
        encoded_data.header().clone(),
        encoded_data.committee_chunks()[2].clone(),
    );
    let echo_data = EchoValueData::new(ValueData::new(
        encoded_data.header().clone(),
        encoded_data.committee_chunks()[0].clone(),
    ));
    let result = verifier.visit_composite(&vec![
        RBCCommitteeMessage::Value(value_data),
        RBCCommitteeMessage::EchoValue(echo_data),
    ]);
    assert!(result.is_err());

    // Valid data
    let value_data = ValueData::new(
        encoded_data.header().clone(),
        encoded_data.committee_chunks()[1].clone(),
    );
    let echo_data = EchoValueData::new(ValueData::new(
        encoded_data.header().clone(),
        encoded_data.committee_chunks()[0].clone(),
    ));
    let composite = vec![
        RBCCommitteeMessage::Value(value_data),
        RBCCommitteeMessage::EchoValue(echo_data),
    ];
    let result = verifier.visit_composite(&composite);
    assert!(result.is_ok());

    let result = verifier.visit_committee_message(&RBCCommitteeMessage::<
        SupraDeliveryErasureRs8Schema,
    >::Composite(composite));
    assert!(result.is_ok());
}
