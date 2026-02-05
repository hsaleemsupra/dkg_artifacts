use crate::types::context::ResourcesApi;
use crate::types::helpers::verifier_visitor::verify_value_data_tests::TestResources;
use crate::types::helpers::verifier_visitor::VerifierVisitor;
use crate::types::helpers::Visitor;
use crate::types::messages::certificate_data::QuorumCertificateData;
use crate::types::tests::{certificate_data, header_with_origin, TestSupraCodec};
use metrics::TimeStampTrait;
use network::topology::peer_info::Role;
use primitives::types::QuorumCertificate;
use primitives::types::{Header, HeaderIfc};
use primitives::PeerGlobalIndex;
use std::collections::BTreeSet;
use std::time::Duration;

///
/// Verify Header, QC, and Integrity Data
///
#[tokio::test]
async fn verify_certificate() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let resources = resource_provider.get_resources(global_index);
    let resources_001 = resource_provider.get_resources(PeerGlobalIndex::new(0, 0, 1));
    let mocked_commitment = [5; 32];
    let verifier = VerifierVisitor::new(&resources);

    // Invalid header
    let header = header_with_origin(*resources.topology().origin());
    let certificate = certificate_data(header);
    let result =
        <VerifierVisitor as Visitor<TestSupraCodec>>::visit_certificate(&verifier, &certificate);
    assert!(result.is_err());

    // Header creator is not proposer
    let header = TestResources::generate_header(resources_001.authenticator(), mocked_commitment);
    let certificate = certificate_data(header);
    let result =
        <VerifierVisitor as Visitor<TestSupraCodec>>::visit_certificate(&verifier, &certificate);
    assert!(result.is_err());

    // Invalid qc
    let header = TestResources::generate_header(resources.authenticator(), mocked_commitment);
    let certificate = certificate_data(header.clone());
    let result =
        <VerifierVisitor as Visitor<TestSupraCodec>>::visit_certificate(&verifier, &certificate);
    assert!(result.is_err());

    // Valid QC
    let qc = resource_provider.generate_qc(global_index.clan_identifier(), header.commitment());
    let qc_bytes = bincode::serialize(&qc).unwrap();
    let qc_signature = resources.authenticator().sign(&qc_bytes).unwrap();
    let certificate = QuorumCertificateData::new(header, qc_signature, qc);
    let result =
        <VerifierVisitor as Visitor<TestSupraCodec>>::visit_certificate(&verifier, &certificate);
    assert!(result.is_ok());
}

///
/// Verify Header, QC, and Integrity Data
///
#[tokio::test]
async fn verify_qc() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let resources = resource_provider.get_resources(global_index);
    let mocked_commitment = [5; 32];
    let verifier = VerifierVisitor::new(&resources);

    // Valid QC
    let header = TestResources::generate_header(resources.authenticator(), mocked_commitment);
    let qc = resource_provider.generate_qc(global_index.clan_identifier(), header.commitment());
    let result = verifier.verify_qc(&header, &qc);
    assert!(result.is_ok());

    // Invalid QC with less participants
    let invalid_qc = QuorumCertificate::new(qc.data().clone(), BTreeSet::new());
    let result = verifier.verify_qc(&header, &invalid_qc);
    assert!(result.is_err());

    // Invalid qc with invalid signature
    let invalid_qc = QuorumCertificate::new([5; 96], qc.participants().clone());
    let result = verifier.verify_qc(&header, &invalid_qc);
    assert!(result.is_err());
}

#[test]
fn certificate_data_timestamp_works() {
    let test_struct =
        QuorumCertificateData::new(Header::default(), [0; 64], QuorumCertificate::default());
    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}
