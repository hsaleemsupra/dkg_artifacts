use crate::types::context::ResourcesApi;
use crate::types::helpers::verifier_visitor::verify_value_data_tests::TestResources;
use crate::types::helpers::verifier_visitor::VerifierVisitor;
use crate::types::helpers::Visitor;
use crate::types::messages::VoteData;
use crate::types::tests::{header_with_origin, partial_share, TestSupraCodec};
use crypto::PartialShare;
use metrics::TimeStampTrait;
use network::topology::peer_info::Role;
use primitives::types::{Header, HeaderIfc};
use primitives::PeerGlobalIndex;
use std::time::Duration;

///
/// Verify(vote_data: VoteData, Res: Resources)
/// Res.CurrentPeerInfo().id == vote_data.origin
/// sender_info = Res.GetPeerInfo(vote_data.sender())
/// Res.CurrentPeerInfo().isFromSameClan(sender_info)
/// Res.VerifyVote(commitment, signature, vote_origin)
/// Res.IsBroadcaster(vote_data.origin)
///
#[tokio::test]
async fn verify_vote_data() {
    let role = Role::Leader;
    let global_index = PeerGlobalIndex::new(0, 0, 0);
    let mut resource_provider = TestResources::new(role, global_index);
    let resources = resource_provider.get_resources(global_index);
    let resources_001 = resource_provider.get_resources(PeerGlobalIndex::new(0, 0, 1));
    let mocked_commitment = [5; 32];
    let verifier = VerifierVisitor::new(&resources);
    let verifier_001 = VerifierVisitor::new(&resources_001);

    // Current peer is not the header-creator
    let header = TestResources::generate_header(resources_001.authenticator(), mocked_commitment);
    let vote_data = VoteData::new(header, partial_share(2));
    let result = <VerifierVisitor as Visitor<TestSupraCodec>>::visit_vote(&verifier, &vote_data);
    assert!(result.is_err());

    // Correct header but Current node is not proposer
    let result =
        <VerifierVisitor as Visitor<TestSupraCodec>>::visit_vote(&verifier_001, &vote_data);
    assert!(result.is_err());

    // current peer have data origin, but header is invalid
    let header = header_with_origin(*resources.topology().origin());
    let vote_data = VoteData::new(header, partial_share(2));
    let result = <VerifierVisitor as Visitor<TestSupraCodec>>::visit_vote(&verifier, &vote_data);
    assert!(result.is_err());

    // Could not deduce sender info
    let header = TestResources::generate_header(resources.authenticator(), mocked_commitment);
    let vote_data = VoteData::new(header.clone(), partial_share(7));
    let result = <VerifierVisitor as Visitor<TestSupraCodec>>::visit_vote(&verifier, &vote_data);
    assert!(result.is_err());

    // Invalid partial share
    let vote_data = VoteData::new(header.clone(), partial_share(1));
    let result = <VerifierVisitor as Visitor<TestSupraCodec>>::visit_vote(&verifier, &vote_data);
    assert!(result.is_err());

    // Own votes should be rejected as input
    let vote_data = VoteData::new(header.clone(), partial_share(0));
    let result = <VerifierVisitor as Visitor<TestSupraCodec>>::visit_vote(&verifier, &vote_data);
    assert!(result.is_err());

    // Own votes should be rejected as input
    let partial_share = resources_001
        .authenticator()
        .partial_signature(header.commitment())
        .expect("Valid share");
    let vote_data = VoteData::new(header.clone(), partial_share);
    let result = <VerifierVisitor as Visitor<TestSupraCodec>>::visit_vote(&verifier, &vote_data);
    assert!(result.is_ok());
}

#[test]
fn value_data_timestamp_works() {
    let test_struct = VoteData::new(Header::default(), PartialShare::new(1, [0; 96]));
    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}
