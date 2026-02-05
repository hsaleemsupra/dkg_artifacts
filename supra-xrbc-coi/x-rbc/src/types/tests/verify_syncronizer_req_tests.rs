use crate::types::context::ResourcesApi;
use crate::types::helpers::verifier_visitor::verify_value_data_tests::TestResources;
use crate::types::helpers::verifier_visitor::VerifierVisitor;
use crate::types::helpers::Visitor;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::tests::TestSupraCodec;
use crate::QuorumCertificate;
use metrics::TimeStampTrait;
use network::topology::peer_info::Role;
use primitives::types::{Header, HeaderIfc};
use primitives::{Origin, PeerGlobalIndex};
use std::collections::BTreeSet;
use std::time::Duration;

#[tokio::test]
async fn verify_sync() {
    let role = Role::Leader;
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, broadcaster_index);

    let broadcaster_resource = resource_provider.get_resources(broadcaster_index);
    let committee_resource = resource_provider.get_resources(PeerGlobalIndex::new(0, 0, 1));
    let network_resource = resource_provider.get_resources(PeerGlobalIndex::new(0, 1, 2));

    let commitment = [5; 32];
    let broadcaster_header =
        TestResources::generate_header(broadcaster_resource.authenticator(), commitment);
    let broadcaster_qc = resource_provider.generate_qc(
        broadcaster_index.clan_identifier(),
        broadcaster_header.commitment(),
    );

    let bad_header = Header::default();
    let bad_qc = QuorumCertificate::new(broadcaster_qc.data().clone(), BTreeSet::new());

    let good_sync = SyncRequest::new(broadcaster_header.clone(), broadcaster_qc.clone());
    let bad_sync = SyncRequest::new(bad_header.clone(), bad_qc.clone());

    // committee resource , good sync request
    let verifier = VerifierVisitor::new(&committee_resource);
    let result =
        <VerifierVisitor as Visitor<TestSupraCodec>>::visit_sync_request(&verifier, &good_sync);
    assert!(result.is_ok());

    // committee resource , bad sync request
    let verifier = VerifierVisitor::new(&committee_resource);
    let result =
        <VerifierVisitor as Visitor<TestSupraCodec>>::visit_sync_request(&verifier, &bad_sync);
    assert!(result.is_err());

    // network resource , good sync request
    let verifier = VerifierVisitor::new(&network_resource);
    let result =
        <VerifierVisitor as Visitor<TestSupraCodec>>::visit_sync_request(&verifier, &good_sync);
    assert!(result.is_ok());

    // network resource , bad sync request
    let verifier = VerifierVisitor::new(&network_resource);
    let result =
        <VerifierVisitor as Visitor<TestSupraCodec>>::visit_sync_request(&verifier, &bad_sync);
    assert!(result.is_err());
}

#[tokio::test]
async fn verify_pull() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let broadcaster = resource_provider.get_resources(global_index);

    let commitment = [5; 32];
    let good_header = TestResources::generate_header(broadcaster.authenticator(), commitment);
    let good_committee = resource_provider.get_resources(PeerGlobalIndex::new(0, 0, 1));
    let good_qc =
        resource_provider.generate_qc(global_index.clan_identifier(), good_header.commitment());

    // good header, good qc, good committee
    let sync = SyncRequest::new(good_header.clone(), good_qc.clone());
    let pull = PullRequest::new(good_committee.authenticator().origin(), sync);
    let receiver = VerifierVisitor::new(&good_committee);
    let result = <VerifierVisitor as Visitor<TestSupraCodec>>::visit_pull_request(&receiver, &pull);
    assert!(result.is_ok());

    // good header, good qc, broadcaster
    let sync = SyncRequest::new(good_header.clone(), good_qc.clone());
    let pull = PullRequest::new(broadcaster.authenticator().origin(), sync);
    let receiver = VerifierVisitor::new(&broadcaster);
    let result = <VerifierVisitor as Visitor<TestSupraCodec>>::visit_pull_request(&receiver, &pull);
    assert!(result.is_err());
}

#[test]
fn sync_data_timestamp_works() {
    let test_struct = SyncRequest::new(Header::default(), QuorumCertificate::default());
    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}

#[test]
fn pull_data_timestamp_works() {
    let sync = SyncRequest::new(Header::default(), QuorumCertificate::default());
    let test_struct = PullRequest::new(Origin::default(), sync);
    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}
