use crate::states::handlers::{CommitteeChunkBroadcaster, CommitteeMessageHandler};
use crate::states::tests::can_transaction_happen;
use crate::states::tests::{create_committee_value, ContextProvider};
use crate::states::{DoneCommitteeFSM, WaitingForCertificate, WaitingForVote};
use crate::tasks::codec::{SupraDeliveryErasureCodec, SupraDeliveryErasureCodecSchema};
use crate::types::messages::{
    EchoReadyData, EchoValueData, RBCCommitteeMessage, RBCNetworkMessage, ReadyData,
    ResponseTypeIfc, VoteData,
};
use crate::types::tests::{certificate_data, value_data_with_header_idx};
use crate::{FeedbackMessage, QuorumCertificateData, SupraDeliveryErasureRs8Schema};
use std::collections::BTreeSet;

use crate::types::context::{FSMContextOwner, Resources, ResourcesApi};
use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::payload_state::committee::CommitteePayloadFlags;
use crate::types::payload_state::{PayloadDataSettings, PayloadFlags};
use crypto::PartialShare;
use primitives::types::header::HeaderIfc;
use primitives::types::QuorumCertificate;
use primitives::{ClanIdentifier, PeerGlobalIndex};
use sfsm::{ReceiveMessage, ReturnMessage, State, Transition};

fn add_vote<C: SupraDeliveryErasureCodecSchema>(wfc: &mut WaitingForCertificate<C>) {
    let position = wfc.topology().get_position();
    let vote = PartialShare::new(position as u32, [2; 96]);
    wfc.payload_state_mut().add_vote(vote);
}

fn prepare_valid_state(
    seed: u8,
    resources: &Resources,
    wfc: &mut WaitingForCertificate<SupraDeliveryErasureRs8Schema>,
) {
    let leader_position = resources.topology().get_position();
    let position = wfc.topology().get_position();
    if leader_position != position {
        // add vote only for non broadcaster peer
        let vote = PartialShare::new(position as u32, [seed; 96]);
        wfc.payload_state_mut().add_vote(vote);
    }
}

#[tokio::test]
async fn test_state_transition_to_done_state() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfc_001 = WaitingForCertificate::new(context);
    prepare_valid_state(1, &context_provider.broadcaster_resources, &mut wfc_001);
    wfc_001
        .payload_state_mut()
        .set_certificate(QuorumCertificate::new([2; 96], BTreeSet::new()));
    wfc_001.execute();
    assert!(wfc_001.response().is_none());
    let transaction =
        Transition::<DoneCommitteeFSM<SupraDeliveryErasureRs8Schema>>::guard(&wfc_001);
    assert!(can_transaction_happen(transaction));
    assert!(wfc_001.response().is_none());
    wfc_001.exit();
    // No response upon exiting WFC state if ready-echo-ready broadcasting is disabled
    // assert!(wfc_001.response().is_some());
    assert!(wfc_001.response().is_none());
    let done: DoneCommitteeFSM<SupraDeliveryErasureRs8Schema> = wfc_001.into();
    assert!(done.response().is_none());
    assert!(done.payload_state().codec().feed_len().eq(&0))
}

#[tokio::test]
async fn test_wfc_handle_value() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfc_001 = WaitingForCertificate::new(context);
    prepare_valid_state(1, &context_provider.broadcaster_resources, &mut wfc_001);

    assert!(!wfc_001.payload_state().failed());
    let mut committee_value = create_committee_value(2, &context_provider.broadcaster_resources);
    assert_eq!(wfc_001.payload_state().get_received_chunks().len(), 0);
    wfc_001.handle_value(committee_value.pop().unwrap());
    assert_eq!(wfc_001.payload_state().get_received_chunks().len(), 1);
    let response = wfc_001.take_response().unwrap();
    assert_eq!(response.messages().len(), 2);
    assert!(response.aux_messages().is_empty());
    assert!(response.feedback().is_empty());
    let has_echo_value = response.messages().data().iter().find(|(msg, targets)| {
        if let RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::EchoValue(_) = msg {
            assert_eq!(targets.len(), wfc_001.topology().get_committee_size() - 2);
            true
        } else {
            false
        }
    });
    assert!(has_echo_value.is_some());

    let has_vote_data = response.messages().data().iter().find(|(msg, targets)| {
        if let RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::Vote(_) = msg {
            assert_eq!(targets.len(), 1);
            true
        } else {
            false
        }
    });
    assert!(has_vote_data.is_some());
}

#[tokio::test]
async fn test_wfc_handle_echo_value() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfc_001 = WaitingForCertificate::new(context);

    assert!(!wfc_001.payload_state().failed());
    let mut committee_value = create_committee_value(2, &context_provider.broadcaster_resources);
    assert_eq!(wfc_001.payload_state().get_received_chunks().len(), 0);
    assert_eq!(wfc_001.payload_state().peers_with_all_chunks().len(), 0);
    let echo = EchoValueData::new(committee_value.pop().unwrap());
    wfc_001.handle_echo_value(echo);
    assert_eq!(wfc_001.payload_state().get_received_chunks().len(), 1);
    assert_eq!(wfc_001.payload_state().peers_with_all_chunks().len(), 0);
    assert!(wfc_001.response().is_none());
}

#[tokio::test]
async fn test_wfc_handle_vote() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(leader_index);
    let mut wfc_000 = WaitingForCertificate::new(context);
    assert!(!wfc_000.payload_state().failed());

    let vote = VoteData::new(
        wfc_000.payload_state().get_header(),
        PartialShare::new(2, [2; 96]),
    );

    assert_eq!(wfc_000.payload_state().peers_with_all_chunks().len(), 0);
    assert!(!wfc_000.payload_state().has_vote(2));
    wfc_000.handle_vote(vote);
    assert_eq!(wfc_000.payload_state().peers_with_all_chunks().len(), 1);
    assert!(wfc_000.payload_state().has_vote(2));
}

#[tokio::test]
async fn test_entry_for_wfc_data_is_reconstructed() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfc_001 = WaitingForCertificate::new(context);
    prepare_valid_state(1, &context_provider.broadcaster_resources, &mut wfc_001);
    wfc_001.entry();
    assert!(!wfc_001.payload_state().failed());
}

#[test]
#[should_panic]
fn test_entry_for_wfc_data_no_payload_data() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfc_001 = WaitingForCertificate::new(context);
    wfc_001.entry();
}

#[tokio::test]
async fn test_execute_for_wfc_is_broadcaster_committee_peer() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index);
    let mut wfc_000 = WaitingForCertificate::new(context);
    prepare_valid_state(1, &context_provider.broadcaster_resources, &mut wfc_000);
    wfc_000.entry();
    let expected_committee_chunk = wfc_000.payload_state().codec().total_committee_chunks();
    let expected_network_chunks = wfc_000.payload_state().codec().total_network_chunks();
    assert!(wfc_000.response().is_none());
    assert!(!wfc_000.payload_state().failed());
    assert!(wfc_000.payload_state().is_reconstructed());
    assert!(wfc_000
        .payload_state()
        .committee_chunks()
        .unwrap()
        .len()
        .eq(&expected_committee_chunk));
    assert!(wfc_000
        .payload_state()
        .network_chunks()
        .unwrap()
        .len()
        .eq(&expected_network_chunks));

    wfc_000.execute();

    assert!(wfc_000.response().is_none());
    assert!(!wfc_000.payload_state().failed());
    assert!(wfc_000.payload_state().is_reconstructed());
    assert!(wfc_000
        .payload_state()
        .committee_chunks()
        .unwrap()
        .len()
        .eq(&expected_committee_chunk));
    assert!(wfc_000
        .payload_state()
        .network_chunks()
        .unwrap()
        .len()
        .eq(&expected_network_chunks));
}

#[tokio::test]
async fn test_exit_for_wfc_is_broadcaster_committee_peer() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index);
    let mut wfc_000 = WaitingForCertificate::new(context);
    prepare_valid_state(1, &context_provider.broadcaster_resources, &mut wfc_000);
    wfc_000.entry();

    assert!(wfc_000.response().is_none());
    wfc_000.execute();
    assert!(wfc_000.response().is_none());
    assert!(!wfc_000.payload_state().failed());

    wfc_000
        .payload_state_mut()
        .set_certificate(QuorumCertificate::new([2; 96], BTreeSet::new()));
    wfc_000.execute();
    wfc_000.exit();
    assert!(wfc_000.response().is_none());
    assert!(!wfc_000.payload_state().failed());
}

#[tokio::test]
async fn test_exit_for_wfc_another_peer_committee_msg() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfc_001 = WaitingForCertificate::new(context);
    prepare_valid_state(1, &context_provider.broadcaster_resources, &mut wfc_001);
    wfc_001.entry();

    assert!(wfc_001.response().is_none());
    wfc_001.execute();
    assert!(wfc_001.response().is_none());
    assert!(!wfc_001.payload_state().failed());

    wfc_001
        .payload_state_mut()
        .set_certificate(QuorumCertificate::new(
            [2; 96],
            BTreeSet::from([0, 1, 2, 3]),
        ));
    wfc_001.execute();
    assert!(wfc_001.response().is_none());
    wfc_001.exit();
    assert!(wfc_001.response().is_none());
    // No ready-echo-ready is sent when broadcasting is disabled
    // assert!(wfc_001.response().is_some());
    // assert!(!wfc_001.payload_state().failed());
    // let resp = wfc_001.response().as_ref().unwrap();
    // let msg = resp.messages().data();
    // // 1 Ready message to peer number 4 except broadcaster and self, 1 echo_ready for owned chunk
    // assert_eq!(msg.len(), 2, "{:?}", msg);

    // // No Network-Chunk has been delivered upon exiting
    // assert!(resp.aux_messages().is_empty());

    // assert!(wfc_001.payload_state().committee_chunks().is_none());
    // assert!(!wfc_001.payload_state().is_reconstructed());
    // assert!(wfc_001.payload_state().has_payload_data());
}

#[tokio::test]
async fn test_wfc_handle_ready() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfc_001 = WaitingForCertificate::new(context);
    prepare_valid_state(1, &context_provider.broadcaster_resources, &mut wfc_001);
    let header = wfc_001.payload_state().get_header();
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header, 1);

    let ready_data = ReadyData::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 0, 2)),
        value_data,
    );

    assert!(!wfc_001.payload_state().has_chunk(1));
    assert!(wfc_001.payload_state().peers_with_all_chunks().len().eq(&1));
    assert!(wfc_001.response().is_none());

    wfc_001.handle_ready(ready_data);
    assert!(wfc_001.payload_state().has_chunk(1));
    assert!(wfc_001.payload_state().peers_with_all_chunks().len().eq(&2));
    let response = wfc_001.take_response().unwrap();
    assert_eq!(response.messages().len(), 1);
    assert!(response.aux_messages().is_empty());
    assert!(response.feedback().is_empty());
    let (_, targets) = &response.messages().data()[0];
    // excluding broadcaster and current node, and message sender
    assert_eq!(targets.len(), wfc_001.topology().get_committee_size() - 3);
}

#[tokio::test]
async fn test_wfc_handle_echo_ready() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfc_001 = WaitingForCertificate::new(context);
    prepare_valid_state(1, &context_provider.broadcaster_resources, &mut wfc_001);
    let header = wfc_001.payload_state().get_header();
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header, 1);

    let ready_data = ReadyData::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 0, 2)),
        value_data,
    );

    let echo_ready = EchoReadyData::new(ready_data);

    assert!(!wfc_001.payload_state().has_chunk(1));
    assert!(wfc_001.payload_state().peers_with_all_chunks().len().eq(&1));
    assert!(wfc_001.response().is_none());
    wfc_001.handle_echo_ready(echo_ready);
    assert!(wfc_001.payload_state().has_chunk(1));
    assert!(wfc_001.payload_state().peers_with_all_chunks().len().eq(&2));
    assert!(wfc_001.response().is_none());
}

#[tokio::test]
async fn test_wfc_handle_certificate() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfc_001 = WaitingForCertificate::new(context);
    prepare_valid_state(1, &context_provider.broadcaster_resources, &mut wfc_001);
    let header = wfc_001.payload_state().get_header();

    let certificate_data = certificate_data(header);
    assert!(wfc_001.payload_state().certificate().is_none());
    assert!(wfc_001.response().is_none());
    wfc_001.handle_certificate(certificate_data);
    assert!(wfc_001.payload_state().certificate().is_some());
    assert!(wfc_001.response().is_none());
}

#[tokio::test]
async fn test_handle_certificate() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(broadcaster_index);

    let peer_1 = PeerGlobalIndex::new(0, 0, 1);
    let peer_2 = PeerGlobalIndex::new(0, 0, 2);
    let peer_3 = PeerGlobalIndex::new(0, 0, 3);
    let peer_4 = PeerGlobalIndex::new(0, 0, 4);

    let wfv_000 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(broadcaster_index),
    );
    let wfv_001 = WaitingForVote::new(
        context_provider.committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_1),
    );
    let mut wfc_002 = WaitingForCertificate::new(
        context_provider.committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_2),
    );
    let mut wfc_003 = WaitingForCertificate::new(
        context_provider.committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_3),
    );
    let mut wfc_004 = WaitingForCertificate::new(
        context_provider.committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_4),
    );

    assert!(wfv_000.is_data_broadcaster());
    assert!(!wfv_001.is_data_broadcaster());

    // good certificate signed by broadcaster
    let header = wfv_000.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(ClanIdentifier::new(0, 0), header.commitment());
    let qc_bytes = bincode::serialize(&qc).unwrap();
    let qc_signature = wfv_000.authenticator().sign(&qc_bytes).unwrap();
    let certificate_data = QuorumCertificateData::new(header, qc_signature, qc);
    assert!(!wfc_002.payload_state().is_certified());
    wfc_002.receive_message(RBCCommitteeMessage::Certificate(certificate_data));
    let response = wfc_002.return_message();
    assert!(response.is_none());
    assert!(wfc_002.payload_state().is_certified());

    // good certificate signed by non broadcaster
    let header = wfc_003.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(ClanIdentifier::new(0, 0), header.commitment());
    let qc_bytes = bincode::serialize(&qc).unwrap();
    let qc_signature = wfv_001.authenticator().sign(&qc_bytes).unwrap();
    let certificate_data = QuorumCertificateData::new(header, qc_signature, qc);
    assert!(!wfc_003.payload_state().is_certified());
    wfc_003.receive_message(RBCCommitteeMessage::Certificate(certificate_data));
    let response = wfc_003.return_message();
    assert!(response.is_some());
    if let Some(FeedbackMessage::Error(meta, _origin)) = response.unwrap().feedback().get(0) {
        let msg_meta = wfc_003.payload_state().header().meta();
        assert_eq!(meta, msg_meta);
    } else {
        panic!("Internal error expected")
    }
    assert!(!wfc_003.payload_state().is_certified());

    // bad certificate signed by broadcaster
    let header = wfc_004.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(ClanIdentifier::new(0, 0), header.commitment());
    let certificate_data = QuorumCertificateData::new(header, [0; 64], qc);
    assert!(!wfc_004.payload_state().is_certified());
    wfc_004.receive_message(RBCCommitteeMessage::Certificate(certificate_data));
    let response = wfc_004.return_message();
    assert!(response.is_some());
    if let Some(FeedbackMessage::Error(meta, _origin)) = response.unwrap().feedback().get(0) {
        let msg_meta = wfc_004.payload_state().header().meta();
        assert_eq!(meta, msg_meta);
    } else {
        panic!("Internal error expected")
    }
    assert!(!wfc_004.payload_state().is_certified());
}

#[tokio::test]
async fn test_committee_handle_pull_sync_request() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let peer_index2 = PeerGlobalIndex::new(0, 0, 2);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfc_001 = WaitingForCertificate::new(context);
    prepare_valid_state(1, &context_provider.broadcaster_resources, &mut wfc_001);

    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index2);
    let mut wfc_002 = WaitingForCertificate::new(context);
    prepare_valid_state(1, &context_provider.broadcaster_resources, &mut wfc_002);
    assert!(!wfc_001.payload_state().failed());
    assert!(!wfc_002.payload_state().failed());

    assert!(wfc_001.payload_state().is_reconstructed());
    assert!(wfc_002.payload_state().is_reconstructed());

    assert!(!wfc_001.payload_state().is_certified());
    assert!(!wfc_002.payload_state().is_certified());

    let header_001 = wfc_001.payload_state().get_header();
    let qc_001 = context_provider
        .resource_provider
        .generate_qc(ClanIdentifier::new(0, 0), header_001.commitment());
    let sync_001 = SyncRequest::new(header_001, qc_001);
    let pull_from_002 = PullRequest::new(*wfc_002.topology().origin(), sync_001);

    wfc_001.receive_message(RBCCommitteeMessage::Pull(pull_from_002));
    let response = wfc_001.return_message();
    assert!(response.is_none()); // nothing should be sent , as ready and echo-ready message will be sent upon exiting WFC state.
    assert!(wfc_001.payload_state().is_certified());

    assert!(!wfc_002.payload_state().is_certified());
    let header_002 = wfc_002.payload_state().get_header();
    let qc_002 = context_provider
        .resource_provider
        .generate_qc(ClanIdentifier::new(0, 0), header_002.commitment());
    let sync_002 = SyncRequest::new(header_002, qc_002);
    wfc_002.receive_message(RBCCommitteeMessage::Sync(sync_002));
    assert!(wfc_002.payload_state().is_certified());
}

#[tokio::test]
async fn test_network_handle_pull_sync_request() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfc_001 = WaitingForCertificate::new(context);
    prepare_valid_state(1, &context_provider.broadcaster_resources, &mut wfc_001);

    let network_011 = *context_provider
        .resource_provider
        .get_resources(PeerGlobalIndex::new(0, 1, 1))
        .topology()
        .origin();

    assert!(!wfc_001.payload_state().failed());

    assert!(wfc_001.payload_state().is_reconstructed());
    assert!(!wfc_001.payload_state().is_certified());

    let header_001 = wfc_001.payload_state().get_header();
    let qc_001 = context_provider
        .resource_provider
        .generate_qc(ClanIdentifier::new(0, 0), header_001.commitment());
    let sync_001 = SyncRequest::new(header_001, qc_001);
    let pull_011 = PullRequest::new(network_011, sync_001);

    wfc_001.receive_message(RBCCommitteeMessage::Pull(pull_011));
    let response = wfc_001.return_message();
    assert!(response.is_some()); //  should send the share value to origin

    let output = response.as_ref().unwrap().aux_messages();
    let net_msg = output.data();
    assert_eq!(net_msg.len(), 1);
    let share = net_msg.get(0).unwrap();
    assert!(matches!(share, (RBCNetworkMessage::Share(_), _)));
    assert!(wfc_001.payload_state().is_certified());
}

#[tokio::test]
async fn test_handle_payload() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfc_001 = WaitingForCertificate::new(context);
    prepare_valid_state(1, &context_provider.broadcaster_resources, &mut wfc_001);

    assert!(!wfc_001.payload_state().failed());

    assert!(wfc_001.payload_state().is_reconstructed());
    assert!(!wfc_001.payload_state().is_certified());

    let payload_data = PayloadData::new(wfc_001.payload_state().header().clone(), vec![10; 25]);
    wfc_001.receive_message(RBCCommitteeMessage::Payload(payload_data));

    assert!(!wfc_001.payload_state().failed());
    assert!(wfc_001.payload_state().is_reconstructed());
    assert!(!wfc_001.payload_state().is_certified());
    assert!(wfc_001.return_message().is_none());
}
