use crate::states::handlers::{
    CommitteeChunkBroadcaster, CommitteeMessageHandler, TimeoutMessageHandler,
};
use crate::states::tests::{can_transaction_happen, ContextProvider};
use crate::states::{DoneCommitteeFSM, WaitingForCertificate, WaitingForVote};
use crate::tasks::messages::TimeoutMessage;
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::messages::{
    EchoReadyData, EchoValueData, RBCCommitteeMessage, ReadyData, ResponseTypeIfc, ValueData,
};
use crate::types::payload_state::{PayloadDataSettings, PayloadFlags};
use crate::types::tests::{certificate_data, partial_share, value_data_with_header_idx};
use crate::{FeedbackMessage, QuorumCertificateData, SupraDeliveryErasureRs8Schema};
use primitives::types::HeaderIfc;

use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::payload_state::committee::CommitteePayloadFlags;
use primitives::types::QuorumCertificate;
use primitives::{ClanIdentifier, Origin, PeerGlobalIndex, Protocol};
use rand::prelude::SliceRandom;
use rand::thread_rng;
use sfsm::{ReceiveMessage, ReturnMessage, State, Transition};
use std::collections::BTreeSet;

#[tokio::test]
async fn test_wfv_conditional_apis() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut wfv_000 = WaitingForVote::new(
        context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(leader_index),
    );
    assert!(wfv_000.is_data_broadcaster());

    let wfv_001 = WaitingForVote::new(
        context_provider
            .committee_context::<SupraDeliveryErasureRs8Schema>(PeerGlobalIndex::new(0, 0, 1)),
    );
    assert!(!wfv_001.is_data_broadcaster());

    let mut votes = context_provider
        .resource_provider
        .generate_shares(ClanIdentifier::new(0, 0), wfv_000.payload_state().header());

    votes.shuffle(&mut thread_rng());
    let threshold = wfv_000.authenticator().threshold();
    for i in 0..threshold - 1 {
        wfv_000.payload_state_mut().add_vote(votes.remove(i));
        assert!(!wfv_000.has_quorum_reached())
    }
    wfv_000
        .payload_state_mut()
        .add_vote(votes.remove(threshold - 1));
    assert!(wfv_000.has_quorum_reached())
}

#[tokio::test]
async fn test_wfv_entry() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut wfv_000 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index),
    );
    assert!(wfv_000.is_data_broadcaster());
    assert!(wfv_000.response().is_none());
    assert_eq!(wfv_000.payload_state().votes_len(), 0);

    // Entry for the broadcaster
    wfv_000.entry();
    assert!(wfv_000.response().is_none());
    assert_eq!(wfv_000.payload_state().votes_len(), 0);

    // Entry for the non-broadcaster
    let mut wfv_001 = WaitingForVote::new(
        context_provider.committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(
            PeerGlobalIndex::new(0, 0, 1),
        ),
    );

    assert!(!wfv_001.is_data_broadcaster());

    assert!(wfv_001.response().is_none());
    assert_eq!(wfv_001.payload_state().votes_len(), 0);

    // Entry, creates vote message to be sent to data-origin
    wfv_001.entry();
    assert!(wfv_001.response().is_some());
    // the vote is stored also locally to rebroadcast it if required
    assert_eq!(wfv_001.payload_state().votes_len(), 1);
    assert!(wfv_001
        .payload_state()
        .get_vote(wfv_001.topology().get_position() as u32)
        .is_some());
    let response = wfv_001.response().as_ref().unwrap();
    assert!(response.feedback().is_empty());
    assert_eq!(response.messages().len(), 1);
    assert!(response.aux_messages().is_empty());
    let (msg, address) = &response.messages().data()[0];
    assert!(matches!(
        msg,
        RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::Vote(_)
    ));
    assert_eq!(address.len(), 1);
    let expected_address = wfv_001
        .topology()
        .get_address_by_origin(Protocol::XRBC, msg.origin())
        .unwrap();
    assert_eq!(&expected_address, &address[0])
}

#[test]
#[should_panic]
fn test_wfv_entry_negative_case() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut wfv_000 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index),
    );

    // No reconstructed payload information
    wfv_000.entry();
}

#[tokio::test]
async fn test_wfv_exit() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut wfv_000 = WaitingForVote::new(
        context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(leader_index),
    );
    assert!(wfv_000.is_data_broadcaster());

    let threshold = wfv_000.authenticator().threshold();
    for i in 0..threshold - 1 {
        wfv_000
            .payload_state_mut()
            .add_vote(partial_share(i as u32));
        assert!(!wfv_000.has_quorum_reached())
    }

    assert_eq!(wfv_000.payload_state().votes_len(), threshold - 1);
    wfv_000.exit();
    assert_eq!(wfv_000.payload_state().votes_len(), threshold - 1);
}

#[tokio::test]
async fn test_wfv_execute_success() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut wfv_000 = WaitingForVote::new(
        context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(leader_index),
    );
    assert!(wfv_000.is_data_broadcaster());

    let mut votes = context_provider
        .resource_provider
        .generate_shares(ClanIdentifier::new(0, 0), wfv_000.payload_state().header());

    votes.shuffle(&mut thread_rng());
    let threshold = wfv_000.authenticator().threshold();
    for i in 0..threshold - 1 {
        wfv_000.payload_state_mut().add_vote(votes.remove(i));
        wfv_000.execute();
        assert!(wfv_000.response().is_none());
        assert!(!wfv_000.payload_state().failed());
        assert!(!wfv_000.payload_state().is_certified());
    }
    wfv_000
        .payload_state_mut()
        .add_vote(votes.remove(threshold - 1));
    wfv_000.execute();
    assert!(wfv_000.response().is_some());
    assert!(!wfv_000.payload_state().failed());
    assert!(wfv_000.payload_state().is_certified());
    let response = wfv_000.response().as_ref().unwrap();
    assert!(!response.messages().is_empty()); // broadcast QuorumCertificateData to all committee peers
    let committee_resp = response.messages().data();
    assert_eq!(committee_resp.len(), 1);
    let rbc_message = committee_resp.first().unwrap();
    assert_eq!(rbc_message.1.len(), 4);
    if let RBCCommitteeMessage::Certificate(cert) = &rbc_message.0 {
        assert_eq!(
            cert.qc().participants().len(),
            wfv_000.authenticator().threshold()
        );
    } else {
        panic!("Expected QuorumCertificateData, got: {:?}", &rbc_message.0);
    }

    assert!(response.aux_messages().is_empty());
    assert!(!response.feedback().is_empty());
    let available = response.feedback().get(0).unwrap();
    if let FeedbackMessage::Available(data) = available {
        assert_eq!(
            data.qc().participants().len(),
            wfv_000.authenticator().threshold()
        );
    } else {
        panic!(
            "Expected Available message as feedback got: {:?}",
            available
        );
    }
}

#[tokio::test]
async fn test_wfv_execute_failure() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut wfv_000 = WaitingForVote::new(
        context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(leader_index),
    );
    assert!(wfv_000.is_data_broadcaster());

    let threshold = wfv_000.authenticator().threshold();
    for i in 0..threshold - 1 {
        wfv_000
            .payload_state_mut()
            .add_vote(partial_share(i as u32));
        wfv_000.execute();
        assert!(wfv_000.response().is_none());
        assert!(!wfv_000.payload_state().failed());
        assert!(!wfv_000.payload_state().is_certified());
    }
    wfv_000
        .payload_state_mut()
        .add_vote(partial_share((threshold - 1) as u32));
    wfv_000.execute();
    assert!(wfv_000.response().is_some());
    assert!(wfv_000.payload_state().failed());
    assert!(!wfv_000.payload_state().is_certified());
    let response = wfv_000.response().as_ref().unwrap();
    assert!(response.messages().is_empty());
    assert!(response.aux_messages().is_empty());
    assert!(!response.feedback().is_empty());
    let id = wfv_000.payload_state().id();
    if let FeedbackMessage::InternalError(meta, _) = response.feedback().get(0).unwrap() {
        assert_eq!(id, meta.id())
    } else {
        panic!("Expected InternalError, got: {:?}", response.feedback())
    }
}

fn transaction_wfc_ok(state: &WaitingForVote<SupraDeliveryErasureRs8Schema>) {
    let transaction =
        Transition::<WaitingForCertificate<SupraDeliveryErasureRs8Schema>>::guard(state);
    assert!(can_transaction_happen(transaction));
}

fn transaction_wfc_nok(state: &WaitingForVote<SupraDeliveryErasureRs8Schema>) {
    let transaction =
        Transition::<WaitingForCertificate<SupraDeliveryErasureRs8Schema>>::guard(state);
    assert!(!can_transaction_happen(transaction));
}

fn transaction_done_ok(state: &WaitingForVote<SupraDeliveryErasureRs8Schema>) {
    let transaction = Transition::<DoneCommitteeFSM<SupraDeliveryErasureRs8Schema>>::guard(state);
    assert!(can_transaction_happen(transaction));
}
fn transaction_done_nok(state: &WaitingForVote<SupraDeliveryErasureRs8Schema>) {
    let transaction = Transition::<DoneCommitteeFSM<SupraDeliveryErasureRs8Schema>>::guard(state);
    assert!(!can_transaction_happen(transaction));
}

#[tokio::test]
async fn test_wfv_transitions_is_broadcaster() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut wfv = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index),
    );
    assert!(wfv.is_data_broadcaster());

    // No Qc No Certificate -> No transition
    transaction_wfc_nok(&wfv);
    transaction_done_nok(&wfv);

    //  Certificate -> Transition to WFC
    wfv.payload_state_mut()
        .set_certificate(QuorumCertificate::new([3; 96], BTreeSet::new()));

    transaction_wfc_ok(&wfv);
    transaction_done_nok(&wfv);

    // no committee-chunks , WFC transition is okay
    wfv.payload_state_mut().take_committee_chunks();
    transaction_wfc_ok(&wfv);
    transaction_done_nok(&wfv);

    // no network-chunks , WFC transition is okay
    wfv.payload_state_mut().take_network_chunks();
    transaction_wfc_ok(&wfv);
    transaction_done_nok(&wfv);

    // Error -> Transition to Done
    let mut wfv2 = WaitingForVote::new(
        context_provider
            .committee_context::<SupraDeliveryErasureRs8Schema>(PeerGlobalIndex::new(0, 0, 2)),
    );

    wfv2.payload_state_mut().set_error();
    transaction_wfc_nok(&wfv2);
    transaction_done_ok(&wfv2);
}

#[tokio::test]
async fn test_wfv_transitions_is_not_broadcaster() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut wfv = WaitingForVote::new(
        context_provider.committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(
            PeerGlobalIndex::new(0, 0, 1),
        ),
    );
    // No Certificate -> WFC, non-broadcaster does not stay in WFV state
    transaction_wfc_ok(&wfv);
    transaction_done_nok(&wfv);

    // Qc,  Certificate -> Transition to WFC
    wfv.payload_state_mut()
        .set_certificate(QuorumCertificate::new([3; 96], BTreeSet::new()));

    transaction_wfc_ok(&wfv);
    transaction_done_nok(&wfv);

    // no committee-chunks , WFC transition is okay
    wfv.payload_state_mut().take_committee_chunks();
    transaction_wfc_ok(&wfv);
    transaction_done_nok(&wfv);

    // no network-chunks , WFC transition is okay
    wfv.payload_state_mut().take_network_chunks();
    transaction_wfc_ok(&wfv);
    transaction_done_nok(&wfv);

    // Error -> Transition to Done
    let mut wfv2 = WaitingForVote::new(
        context_provider
            .committee_context::<SupraDeliveryErasureRs8Schema>(PeerGlobalIndex::new(0, 0, 2)),
    );

    wfv2.payload_state_mut().set_error();
    transaction_wfc_nok(&wfv2);
    transaction_done_ok(&wfv2);
}

#[tokio::test]
async fn test_wfv_handle_value() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut wfv_000 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index),
    );
    let header = wfv_000.payload_state().get_header();

    assert_eq!(wfv_000.payload_state().get_received_chunks().len(), 0);
    assert_eq!(wfv_000.payload_state().peers_with_all_chunks().len(), 1);
    assert!(wfv_000
        .payload_state()
        .peers_with_all_chunks()
        .contains(&leader_index.position()));
    assert!(wfv_000.response().is_none());

    // consuming value with index 1
    let expected_value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), 1);
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header, 1);

    wfv_000.handle_value(value_data);
    assert!(!wfv_000
        .payload_state()
        .get_received_chunks()
        .contains(&expected_value_data.get_chunk_index()));
    let expected_peers_with_all_chunks = 1;
    assert_eq!(
        wfv_000.payload_state().peers_with_all_chunks().len(),
        expected_peers_with_all_chunks
    );
    assert!(!wfv_000
        .payload_state()
        .peers_with_all_chunks()
        .contains(&expected_value_data.get_chunk_index()));
    let response = wfv_000.take_response().expect("Value Message is echoed");
    assert!(response.messages().is_empty());
    assert!(response.aux_messages().is_empty());
    assert!(!response.feedback().is_empty());
    assert!(matches!(
        response.feedback().get(0).unwrap(),
        FeedbackMessage::InternalError(_, _)
    ));
}

#[tokio::test]
async fn test_wfv_handle_payload() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut wfv_000 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index),
    );
    let header = wfv_000.payload_state().get_header();
    let payload_data = PayloadData::new(header, vec![10; 25]);
    wfv_000.handle_payload(payload_data);
    let response = wfv_000.take_response().expect("Value Message is echoed");
    assert!(response.messages().is_empty());
    assert!(response.aux_messages().is_empty());
    assert!(!response.feedback().is_empty());
    assert!(matches!(
        response.feedback().get(0).unwrap(),
        FeedbackMessage::InternalError(_, _)
    ));
}

#[tokio::test]
async fn test_wfv_handle_echo_value() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut wfv_000 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index),
    );
    let header = wfv_000.payload_state().get_header();

    assert_eq!(wfv_000.payload_state().get_received_chunks().len(), 0);
    assert_eq!(wfv_000.payload_state().peers_with_all_chunks().len(), 1);
    assert!(wfv_000
        .payload_state()
        .peers_with_all_chunks()
        .contains(&leader_index.position()));
    assert!(wfv_000.response().is_none());

    // consuming echo value with index 2
    let expected_value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), 2);
    let value_data = EchoValueData::new(
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header, 2),
    );

    wfv_000.handle_echo_value(value_data);
    assert!(!wfv_000
        .payload_state()
        .get_received_chunks()
        .contains(&expected_value_data.get_chunk_index()));
    let expected_peers_with_all_chunks = 1;
    assert_eq!(
        wfv_000.payload_state().peers_with_all_chunks().len(),
        expected_peers_with_all_chunks
    );
    assert!(!wfv_000
        .payload_state()
        .peers_with_all_chunks()
        .contains(&expected_value_data.get_chunk_index()));
    let response = wfv_000.take_response().unwrap();
    assert!(response.messages().is_empty());
    assert!(response.aux_messages().is_empty());
    assert!(!response.feedback().is_empty());
    assert!(matches!(
        response.feedback().get(0).unwrap(),
        FeedbackMessage::InternalError(_, _)
    ));
}

#[tokio::test]
async fn test_wfv_handle_ready_value() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut wfv_000 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index),
    );
    let header = wfv_000.payload_state().get_header();

    assert_eq!(wfv_000.payload_state().get_received_chunks().len(), 0);
    assert_eq!(wfv_000.payload_state().peers_with_all_chunks().len(), 1);
    assert!(wfv_000
        .payload_state()
        .peers_with_all_chunks()
        .contains(&leader_index.position()));
    assert!(wfv_000.response().is_none());

    // consuming value with index 1
    let expected_value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), 1);
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header, 1);
    let sender_global_index = PeerGlobalIndex::new(0, 0, 2);
    let ready_sender = context_provider
        .resource_provider
        .get_origin(&sender_global_index);
    let ready_data = ReadyData::new(ready_sender, value_data);
    wfv_000.handle_ready(ready_data);
    assert!(!wfv_000
        .payload_state()
        .get_received_chunks()
        .contains(&expected_value_data.get_chunk_index()));
    let expected_peers_with_all_chunks = 1;
    assert_eq!(
        wfv_000.payload_state().peers_with_all_chunks().len(),
        expected_peers_with_all_chunks
    );
    assert!(!wfv_000
        .payload_state()
        .peers_with_all_chunks()
        .contains(&sender_global_index.position()));
    assert!(!wfv_000.payload_state().is_certified());

    let response = wfv_000.take_response().expect("Error Message as response");
    assert!(response.messages().is_empty());
    assert!(response.aux_messages().is_empty());
    assert!(!response.feedback().is_empty());
    assert!(matches!(
        response.feedback().get(0).unwrap(),
        FeedbackMessage::InternalError(_, _)
    ));
}

#[tokio::test]
async fn test_wfv_handle_echo_ready_value() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut wfv_000 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index),
    );
    let header = wfv_000.payload_state().get_header();

    assert_eq!(wfv_000.payload_state().get_received_chunks().len(), 0);
    assert_eq!(wfv_000.payload_state().peers_with_all_chunks().len(), 1);
    assert!(wfv_000
        .payload_state()
        .peers_with_all_chunks()
        .contains(&leader_index.position()));
    assert!(wfv_000.response().is_none());

    // consuming value with index 1
    let expected_value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), 1);
    let value_data = value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header, 1);
    let sender_global_index = PeerGlobalIndex::new(0, 0, 2);
    let ready_sender = context_provider
        .resource_provider
        .get_origin(&sender_global_index);
    let ready_data = EchoReadyData::new(ReadyData::new(ready_sender, value_data));
    wfv_000.handle_echo_ready(ready_data);
    assert!(!wfv_000
        .payload_state()
        .get_received_chunks()
        .contains(&expected_value_data.get_chunk_index()));
    let expected_peers_with_all_chunks = 1;
    assert_eq!(
        wfv_000.payload_state().peers_with_all_chunks().len(),
        expected_peers_with_all_chunks
    );
    assert!(!wfv_000
        .payload_state()
        .peers_with_all_chunks()
        .contains(&sender_global_index.position()));
    assert!(!wfv_000.payload_state().is_certified());

    let response = wfv_000.take_response().expect("Error Message as response");
    assert!(response.messages().is_empty());
    assert!(response.aux_messages().is_empty());
    assert!(!response.feedback().is_empty());
    assert!(matches!(
        response.feedback().get(0).unwrap(),
        FeedbackMessage::InternalError(_, _)
    ));
}

#[tokio::test]
async fn test_wfv_handle_certificate() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    // Non-broadcaster
    let current_peer_index = PeerGlobalIndex::new(0, 0, 1);
    let mut wfv_001 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(current_peer_index),
    );

    check_wfv_handle_certificate(&mut wfv_001);

    // broadcaster
    let mut wfv_000 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index),
    );
    check_wfv_handle_certificate(&mut wfv_000);
}

fn check_wfv_handle_certificate(wfv: &mut WaitingForVote<SupraDeliveryErasureRs8Schema>) {
    let header = wfv.payload_state().get_header();

    assert_eq!(wfv.payload_state().get_received_chunks().len(), 0);
    assert_eq!(wfv.payload_state().peers_with_all_chunks().len(), 1);
    assert!(wfv.response().is_none());

    // consuming certificate
    let certificate_data = certificate_data(header);
    wfv.handle_certificate(certificate_data);
    assert!(!wfv.payload_state().is_certified());
    assert_eq!(wfv.payload_state().get_received_chunks().len(), 0);
    assert_eq!(wfv.payload_state().peers_with_all_chunks().len(), 1);

    let mut response = wfv.take_response().unwrap();
    assert!(matches!(
        response.take_feedback().remove(0),
        FeedbackMessage::InternalError(_, _)
    ));
    assert!(response.messages().is_empty());
    assert!(response.aux_messages().is_empty());
}

fn broadcaster_consume_message_and_check_response_and_state(
    wfv_000: &mut WaitingForVote<SupraDeliveryErasureRs8Schema>,
    msg: RBCCommitteeMessage<SupraDeliveryErasureRs8Schema>,
    sender: &Origin,
) {
    wfv_000.receive_message(msg);
    assert!(wfv_000.payload_state().get_received_chunks().is_empty());
    assert_eq!(wfv_000.payload_state().peers_with_all_chunks().len(), 1);
    let response = wfv_000
        .return_message()
        .expect("Response is expected for value input of Broadcaster: WFV");
    assert!(response.messages().is_empty());
    assert!(response.aux_messages().is_empty());
    assert!(!response.feedback().is_empty());
    let msg_meta = wfv_000.payload_state().header().meta();

    match response.feedback().get(0) {
        Some(FeedbackMessage::Error(meta, origin)) => {
            assert_eq!(meta, msg_meta);
            assert_eq!(origin, sender);
        }
        _ => {
            panic!("expected error message")
        }
    }
}

#[tokio::test]
async fn test_wfv_broadcaster_flow_via_receive_interface() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut wfv_000 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index),
    );

    assert!(wfv_000.is_data_broadcaster());
    assert_eq!(wfv_000.payload_state().peers_with_all_chunks().len(), 1);
    assert!(wfv_000.payload_state().get_received_chunks().is_empty());
    let header = wfv_000.payload_state().get_header();

    let committee_chunk = wfv_000.payload_state().committee_chunks().unwrap().clone();

    // any input except valid vote and certificate data will be rejected by the state

    // Value message should be rejected and the sender should be sent as error
    let value_data = ValueData::new(header.clone(), committee_chunk[0].clone());
    broadcaster_consume_message_and_check_response_and_state(
        &mut wfv_000,
        RBCCommitteeMessage::Value(value_data),
        header.origin(),
    );

    // Echo Value message should be rejected and the sender should be sent as error
    let value_data = EchoValueData::new(ValueData::new(header.clone(), committee_chunk[1].clone()));
    let echo_sender = context_provider
        .resource_provider
        .get_origin(&PeerGlobalIndex::new(0, 0, 1));
    broadcaster_consume_message_and_check_response_and_state(
        &mut wfv_000,
        RBCCommitteeMessage::EchoValue(value_data),
        &echo_sender,
    );

    // Ready Value message should be rejected and the sender should be sent as error
    let ready_sender = context_provider
        .resource_provider
        .get_origin(&PeerGlobalIndex::new(0, 0, 2));
    let value_data = ReadyData::new(
        ready_sender,
        ValueData::new(header.clone(), committee_chunk[0].clone()),
    );
    broadcaster_consume_message_and_check_response_and_state(
        &mut wfv_000,
        RBCCommitteeMessage::Ready(value_data),
        &ready_sender,
    );

    // Echo Ready Value message should be rejected and the sender should be sent as error
    let ready_sender = context_provider
        .resource_provider
        .get_origin(&PeerGlobalIndex::new(0, 0, 3));
    let value_data = EchoReadyData::new(ReadyData::new(
        ready_sender,
        ValueData::new(header.clone(), committee_chunk[2].clone()),
    ));
    let echo_sender = context_provider
        .resource_provider
        .get_origin(&PeerGlobalIndex::new(0, 0, 2));
    broadcaster_consume_message_and_check_response_and_state(
        &mut wfv_000,
        RBCCommitteeMessage::EchoReady(value_data),
        &echo_sender,
    );

    // Sent Certificate data to broadcaster
    let qc = context_provider
        .resource_provider
        .generate_qc(ClanIdentifier::new(0, 0), header.commitment());
    let qc_bytes = bincode::serialize(&qc).unwrap();
    let qc_signature = wfv_000.authenticator().sign(&qc_bytes).unwrap();
    let certificate_data = QuorumCertificateData::new(header.clone(), qc_signature, qc);
    wfv_000.receive_message(RBCCommitteeMessage::Certificate(certificate_data));
    // broadcaster is not expecting certificate
    assert!(wfv_000.return_message().is_some());

    // Check vote message consumption
    let mut votes = context_provider
        .resource_provider
        .generate_votes(ClanIdentifier::new(0, 0), &header);
    votes.remove(0);
    for vote in votes {
        wfv_000.receive_message(RBCCommitteeMessage::Vote(vote));
        assert!(wfv_000.return_message().is_none());
    }
    assert_eq!(
        wfv_000.payload_state().peers_with_all_chunks().len(),
        wfv_000.topology().get_committee_size()
    );
}

fn non_broadcaster_consume_message_and_check_response_and_state(
    wfv_000: &mut WaitingForVote<SupraDeliveryErasureRs8Schema>,
    msg: RBCCommitteeMessage<SupraDeliveryErasureRs8Schema>,
    sender: &Origin,
    is_internal_error: bool,
) {
    wfv_000.receive_message(msg);
    let response = wfv_000
        .return_message()
        .expect("Response is expected for value input of Broadcaster: WFV");
    assert!(response.messages().is_empty());
    assert!(response.aux_messages().is_empty());
    assert!(!response.feedback().is_empty());
    let msg_meta = wfv_000.payload_state().header().meta();

    match response.feedback().get(0) {
        Some(FeedbackMessage::Error(meta, origin)) => {
            assert_eq!(meta, msg_meta);
            assert_eq!(origin, sender);
            assert!(!is_internal_error);
        }
        Some(FeedbackMessage::InternalError(meta, _)) => {
            assert_eq!(meta, msg_meta);
            assert!(is_internal_error);
        }
        _ => {
            panic!("expected error message")
        }
    }
}

#[tokio::test]
async fn test_wfv_non_broadcaster_flow_via_receive_interface() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let current_peer_index = PeerGlobalIndex::new(0, 0, 1);
    let mut wfv_001 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(current_peer_index),
    );

    assert!(!wfv_001.is_data_broadcaster());
    let header = wfv_001.payload_state().get_header();
    let committee_chunk = wfv_001.payload_state().committee_chunks().unwrap().clone();

    // any input except certificate data will be rejected by the state by reporting internal error

    let INTERNAL_ERROR = true;
    // Value message should be rejected and internal error should be reported
    let origin = header.origin().clone();
    let value_data = ValueData::new(header.clone(), committee_chunk[1].clone());
    non_broadcaster_consume_message_and_check_response_and_state(
        &mut wfv_001,
        RBCCommitteeMessage::Value(value_data),
        &origin,
        INTERNAL_ERROR,
    );

    // Echo Value message should be rejected and internal error should be reported
    let echo_data = EchoValueData::new(ValueData::new(header.clone(), committee_chunk[0].clone()));
    non_broadcaster_consume_message_and_check_response_and_state(
        &mut wfv_001,
        RBCCommitteeMessage::EchoValue(echo_data),
        &origin,
        INTERNAL_ERROR,
    );

    // Ready Value message should be rejected and internal error should be reported
    let ready_sender = context_provider
        .resource_provider
        .get_origin(&PeerGlobalIndex::new(0, 0, 2));
    let ready_data = ReadyData::new(
        ready_sender,
        ValueData::new(header.clone(), committee_chunk[1].clone()),
    );
    non_broadcaster_consume_message_and_check_response_and_state(
        &mut wfv_001,
        RBCCommitteeMessage::Ready(ready_data),
        &origin,
        INTERNAL_ERROR,
    );

    // Echo Ready Value message should be rejected and the sender should be sent as error
    let ready_sender = context_provider
        .resource_provider
        .get_origin(&PeerGlobalIndex::new(0, 0, 2));
    let echo_ready_data = EchoReadyData::new(ReadyData::new(
        ready_sender,
        ValueData::new(header.clone(), committee_chunk[3].clone()),
    ));
    non_broadcaster_consume_message_and_check_response_and_state(
        &mut wfv_001,
        RBCCommitteeMessage::EchoReady(echo_ready_data),
        &origin,
        INTERNAL_ERROR,
    );

    // Sent Certificate data
    let qc = context_provider
        .resource_provider
        .generate_qc(ClanIdentifier::new(0, 0), header.commitment());
    let qc_bytes = bincode::serialize(&qc).unwrap();
    let qc_signature = wfv_001.authenticator().sign(&qc_bytes).unwrap();
    let certificate_data = QuorumCertificateData::new(header.clone(), qc_signature, qc);
    non_broadcaster_consume_message_and_check_response_and_state(
        &mut wfv_001,
        RBCCommitteeMessage::Certificate(certificate_data),
        &origin,
        !INTERNAL_ERROR,
    );
    assert!(!wfv_001.payload_state().is_certified());
    assert!(!wfv_001.payload_state().is_certified());

    // Check vote message  are not consumed and error is reported
    let votes = context_provider
        .resource_provider
        .generate_votes(ClanIdentifier::new(0, 0), &header);
    for vote in votes {
        let origin = context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 0, vote.index() as usize));
        non_broadcaster_consume_message_and_check_response_and_state(
            &mut wfv_001,
            RBCCommitteeMessage::Vote(vote),
            &origin,
            !INTERNAL_ERROR,
        )
    }
    assert_eq!(wfv_001.payload_state().votes_len(), 0);
}

#[tokio::test]
async fn test_timeout_messages_for_non_broadcaster() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let current_peer_index = PeerGlobalIndex::new(0, 0, 1);
    let mut wfv_001 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(current_peer_index),
    );

    wfv_001.receive_message(TimeoutMessage::Retry);
    assert!(!wfv_001.payload_state().failed());
    assert!(wfv_001.take_response().is_none());

    // Check that direct handling of retry is does not produce any message
    wfv_001.handle_retry();
    assert!(!wfv_001.payload_state().failed());
    assert!(wfv_001.take_response().is_none());
}

#[tokio::test]
async fn test_timeout_messages_for_broadcaster() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut wfv_000 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index),
    );

    let committee_size = wfv_000.topology().get_committee_size();

    wfv_000.receive_message(TimeoutMessage::Retry);
    assert!(!wfv_000.payload_state().failed());
    let response = wfv_000.take_response().unwrap();
    assert!(response.feedback().is_empty());
    assert!(response.aux_messages().is_empty());
    assert_eq!(response.messages().len(), committee_size);

    assert!(wfv_000.take_response().is_none());
    wfv_000.handle_retry();
    assert!(!wfv_000.payload_state().failed());
    let response = wfv_000.take_response().unwrap();
    assert!(response.feedback().is_empty());
    assert!(response.aux_messages().is_empty());
    assert_eq!(response.messages().len(), committee_size);
}

#[tokio::test]
async fn test_handle_sync_req_to_broadcaster() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut broadcaster_000 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index),
    );
    let header = broadcaster_000.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(leader_index.clan_identifier(), header.commitment());
    let sync = SyncRequest::new(header.clone(), qc);

    // broadcaster_000 <=[sync]=
    assert!(!broadcaster_000.payload_state().is_certified());
    assert!(!broadcaster_000.payload_state().failed());
    broadcaster_000.receive_message(RBCCommitteeMessage::Sync(sync));
    let response_000 = broadcaster_000.return_message();
    println!("{:?}", response_000);
    if let Some(FeedbackMessage::Error(meta, origin)) = response_000.unwrap().feedback().get(0) {
        let msg_meta = broadcaster_000.payload_state().header().meta();
        assert_eq!(meta, msg_meta);
        assert_eq!(origin, header.origin())
    } else {
        panic!("error expected")
    }
    assert!(!broadcaster_000.payload_state().is_certified());
    assert!(!broadcaster_000.payload_state().failed());
}

#[tokio::test]
async fn test_handle_sync_req_to_committee() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let current_peer_index = PeerGlobalIndex::new(0, 0, 1);
    let mut committee_001 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(current_peer_index),
    );

    let header = committee_001.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(leader_index.clan_identifier(), header.commitment());
    let sync = SyncRequest::new(header, qc);

    // committee_001 <=[sync]=
    assert!(!committee_001.payload_state().is_certified());
    assert!(!committee_001.payload_state().failed());
    committee_001.receive_message(RBCCommitteeMessage::Sync(sync));
    let response_001 = committee_001.return_message();
    if let Some(FeedbackMessage::InternalError(meta, _origin)) =
        response_001.unwrap().feedback().get(0)
    {
        let msg_meta = committee_001.payload_state().header().meta();
        assert_eq!(meta, msg_meta);
    } else {
        panic!("internal error expected")
    }
    assert!(!committee_001.payload_state().is_certified());
    assert!(committee_001.payload_state().failed());
}

#[tokio::test]
async fn test_handle_committee_pull_request_to_broadcaster() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut broadcaster_000 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index),
    );
    let header = broadcaster_000.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(leader_index.clan_identifier(), header.commitment());
    let sync = SyncRequest::new(header, qc);
    let pull_001 = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 0, 1)),
        sync,
    );

    // broadcaster_000 <=[pull_001]= resource_001
    assert!(!broadcaster_000.payload_state().is_certified());
    assert!(!broadcaster_000.payload_state().failed());
    broadcaster_000.receive_message(RBCCommitteeMessage::Pull(pull_001));
    let response_000 = broadcaster_000.return_message();
    if let Some(FeedbackMessage::Error(meta, _origin)) = response_000.unwrap().feedback().get(0) {
        let msg_meta = broadcaster_000.payload_state().header().meta();
        assert_eq!(meta, msg_meta);
    } else {
        panic!("error expected")
    }
    assert!(!broadcaster_000.payload_state().is_certified());
    assert!(!broadcaster_000.payload_state().failed());
}

#[tokio::test]
async fn test_handle_committee_pull_request_to_committee() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let current_peer_index = PeerGlobalIndex::new(0, 0, 1);
    let mut committee_001 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(current_peer_index),
    );

    let origin_002 = context_provider
        .resource_provider
        .get_origin(&PeerGlobalIndex::new(0, 0, 2));

    let header = committee_001.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(leader_index.clan_identifier(), header.commitment());
    let sync = SyncRequest::new(header, qc);

    let pull_002 = PullRequest::new(origin_002, sync);

    // committee_001 <=[pull_002]= committee_002
    assert!(!committee_001.payload_state().is_certified());
    assert!(!committee_001.payload_state().failed());
    committee_001.receive_message(RBCCommitteeMessage::Pull(pull_002));
    let response_001 = committee_001.return_message();
    if let Some(FeedbackMessage::InternalError(meta, _origin)) =
        response_001.unwrap().feedback().get(0)
    {
        let msg_meta = committee_001.payload_state().header().meta();
        assert_eq!(meta, msg_meta);
    } else {
        panic!("internal error expected")
    }
    assert!(!committee_001.payload_state().is_certified());
    assert!(committee_001.payload_state().failed());
}

#[tokio::test]
async fn test_handle_network_pull_request_to_broadcaster() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let mut broadcaster_000 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index),
    );
    let network_011 = context_provider
        .resource_provider
        .get_origin(&PeerGlobalIndex::new(0, 1, 1));

    let header = broadcaster_000.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(leader_index.clan_identifier(), header.commitment());
    let sync = SyncRequest::new(header, qc);
    let pull_011 = PullRequest::new(network_011, sync);

    // broadcaster_000 <=[pull_011]= network_011
    assert!(!broadcaster_000.payload_state().is_certified());
    assert!(!broadcaster_000.payload_state().failed());
    broadcaster_000.receive_message(RBCCommitteeMessage::Pull(pull_011));
    let response_000 = broadcaster_000.return_message();
    if let Some(FeedbackMessage::Error(meta, _origin)) = response_000.unwrap().feedback().get(0) {
        let msg_meta = broadcaster_000.payload_state().header().meta();
        assert_eq!(meta, msg_meta);
    } else {
        panic!("error expected")
    }
    assert!(!broadcaster_000.payload_state().is_certified());
    assert!(!broadcaster_000.payload_state().failed());
}

#[tokio::test]
async fn test_handle_network_pull_request_to_committee() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let current_peer_index = PeerGlobalIndex::new(0, 0, 1);
    let mut committee_001 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(current_peer_index),
    );
    let network_011 = context_provider
        .resource_provider
        .get_origin(&PeerGlobalIndex::new(0, 1, 1));

    let header = committee_001.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(leader_index.clan_identifier(), header.commitment());
    let sync = SyncRequest::new(header, qc);

    let pull_011 = PullRequest::new(network_011, sync);

    // committee_001 <=[pull_011]= network_011
    assert!(!committee_001.payload_state().is_certified());
    assert!(!committee_001.payload_state().failed());
    committee_001.receive_message(RBCCommitteeMessage::Pull(pull_011));
    let response_001 = committee_001.return_message();
    if let Some(FeedbackMessage::InternalError(meta, _origin)) =
        response_001.unwrap().feedback().get(0)
    {
        let msg_meta = committee_001.payload_state().header().meta();
        assert_eq!(meta, msg_meta);
    } else {
        panic!("internal error expected")
    }
    assert!(!committee_001.payload_state().is_certified());
    assert!(committee_001.payload_state().failed());
}
