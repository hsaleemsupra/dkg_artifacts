use crate::states::handlers::CommitteeMessageHandler;

use primitives::types::header::HeaderIfc;

use crate::states::tests::{can_transaction_happen, ContextProvider};
use crate::states::{DoneCommitteeFSM, WaitingForCertificate, WaitingForData, WaitingForVote};
use crate::tasks::codec::{EncodeResultIfc, SupraDeliveryErasureCodec};
use crate::tasks::config::DisseminationRule;
use crate::tasks::supra_delivery::SupraDeliverySchema;
use crate::types::context::committee::CommitteeFSMContext;
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::helpers::message_factory::{MessageFactory, MessageFrom};
use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    EchoValueData, RBCCommitteeMessage, ReadyData, ResponseTypeIfc, ValueData, VoteData,
};
use crate::types::payload_state::committee::CommitteePayloadFlags;
use crate::types::payload_state::{PayloadDataSettings, PayloadFlags};
use crate::types::tests::certificate_data;
use crate::{
    FeedbackMessage, SupraDeliveryErasureRs16Schema, SupraDeliveryErasureRs8Schema,
    SupraDeliveryRs16Schema,
};
use erasure::utils::codec_trait::Setting;
use primitives::{ClanIdentifier, Payload, PeerGlobalIndex};
use sfsm::{ReceiveMessage, ReturnMessage, State, Transition};

fn get_test_wfd_state<C: SupraDeliverySchema>(
    node: PeerGlobalIndex,
    broadcaster: PeerGlobalIndex,
) -> (
    WaitingForData<<C as SupraDeliverySchema>::CodecSchema>,
    Vec<ValueData<<C as SupraDeliverySchema>::CodecSchema>>,
) {
    let (st, msg, pld) =
        get_test_wfd_state_with_dissemination::<C>(node, broadcaster, DisseminationRule::default());
    (st, msg)
}

fn get_test_wfd_state_with_dissemination<C: SupraDeliverySchema>(
    node: PeerGlobalIndex,
    broadcaster: PeerGlobalIndex,
    rule: DisseminationRule,
) -> (
    WaitingForData<<C as SupraDeliverySchema>::CodecSchema>,
    Vec<ValueData<<C as SupraDeliverySchema>::CodecSchema>>,
    Payload,
) {
    let mut context_provider = ContextProvider::new(broadcaster);

    let (result, payload) = context_provider.encoded_data::<C::CodecSchema>();
    let (header, committee_chunks, _network_chunks) = result.split();
    let value_msg = committee_chunks
        .into_iter()
        .map(|date| ValueData::new(header.clone(), date))
        .collect::<Vec<ValueData<<C as SupraDeliverySchema>::CodecSchema>>>();

    let context: CommitteeFSMContext<C::CodecSchema> = context_provider
        .committee_context_with_header_dissemination_rule::<C::CodecSchema>(header, node, rule);
    let wfd = WaitingForData::new(context);
    (wfd, value_msg, payload)
}

#[tokio::test]
async fn test_waiting_for_data_state_transition_in_case_of_failure() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);

    let (mut wfd_0, _value_data_0) =
        get_test_wfd_state::<SupraDeliveryRs16Schema>(node_index, broadcaster_index);

    assert!(!wfd_0.payload_state().is_reconstructed());
    assert!(!wfd_0.payload_state().failed());

    let transaction = Transition::<DoneCommitteeFSM<SupraDeliveryErasureRs16Schema>>::guard(&wfd_0);
    assert!(!can_transaction_happen(transaction));

    wfd_0.payload_state_mut().set_error();

    let transaction = Transition::<DoneCommitteeFSM<SupraDeliveryErasureRs16Schema>>::guard(&wfd_0);
    assert!(can_transaction_happen(transaction));
}

#[tokio::test]
async fn test_waiting_for_data_state_transition_handle_value() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);

    let (mut wfd_0, value_data_0) =
        get_test_wfd_state::<SupraDeliveryRs16Schema>(node_index, broadcaster_index);

    assert!(!wfd_0.payload_state().is_reconstructed());
    assert!(!wfd_0.payload_state().failed());

    let mut guard = false;
    for data in value_data_0 {
        wfd_0.handle_value(data);
        wfd_0.execute();
        if wfd_0.payload_state().is_reconstructed() {
            guard = true;
            break;
        }
    }
    assert!(guard);
    assert!(!wfd_0.payload_state().failed());
    assert!(wfd_0.payload_state().is_reconstructed());

    let transaction = Transition::<WaitingForVote<SupraDeliveryErasureRs16Schema>>::guard(&wfd_0);
    assert!(can_transaction_happen(transaction));
}

#[tokio::test]
async fn test_waiting_for_data_state_transition_handle_echo_value() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);

    let (mut wfd_0, value_data_0) =
        get_test_wfd_state::<SupraDeliveryRs16Schema>(node_index, broadcaster_index);

    let auth = wfd_0.authenticator().clone();
    let message_factory = MessageFactory::new(&auth);

    assert!(!wfd_0.payload_state().is_reconstructed());
    assert!(!wfd_0.payload_state().failed());

    let mut guard = false;
    let mut is_header_set = false;
    for data in value_data_0 {
        if !is_header_set {
            wfd_0.handle_value(data);
            is_header_set = true;
        } else {
            let data = message_factory.message_from(data);
            wfd_0.handle_echo_value(data);
        }
        wfd_0.execute();
        if wfd_0.payload_state().is_reconstructed() {
            guard = true;
            break;
        }
    }

    assert!(guard);
    assert!(!wfd_0.payload_state().failed());
    assert!(wfd_0.payload_state().is_reconstructed());

    let transaction = Transition::<WaitingForVote<SupraDeliveryErasureRs16Schema>>::guard(&wfd_0);
    assert!(can_transaction_happen(transaction));
}

#[tokio::test]
async fn test_waiting_for_data_state_transition_handle_ready() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);

    let (mut wfd_0, value_data_0) =
        get_test_wfd_state::<SupraDeliveryRs16Schema>(node_index, broadcaster_index);

    let auth = wfd_0.authenticator().clone();
    let ori = auth.origin();

    assert!(!wfd_0.payload_state().is_reconstructed());
    assert!(!wfd_0.payload_state().failed());
    assert!(!wfd_0.payload_state().is_certified());

    let mut guard = false;
    let mut is_header_set = false;
    for data in value_data_0 {
        if !is_header_set {
            wfd_0.handle_value(data);
            is_header_set = true;
        } else {
            let data = ReadyData::new(ori, data);
            wfd_0.handle_ready(data);
        }
        wfd_0.execute();
        if wfd_0.payload_state().is_reconstructed() {
            guard = true;
            break;
        }
    }

    assert!(guard);
    assert!(!wfd_0.payload_state().failed());
    assert!(wfd_0.payload_state().is_reconstructed());
    assert!(!wfd_0.payload_state().is_certified());

    let transaction =
        Transition::<WaitingForCertificate<SupraDeliveryErasureRs16Schema>>::guard(&wfd_0);
    assert!(!can_transaction_happen(transaction));

    let transaction = Transition::<WaitingForVote<SupraDeliveryErasureRs16Schema>>::guard(&wfd_0);
    assert!(can_transaction_happen(transaction));
}

#[tokio::test]
async fn test_waiting_for_data_state_transition_handle_echo_ready() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);

    let (mut wfd_0, value_data_0) =
        get_test_wfd_state::<SupraDeliveryRs16Schema>(node_index, broadcaster_index);

    let auth = wfd_0.authenticator().clone();
    let ori = auth.origin();
    let message_factory = MessageFactory::new(&auth);
    assert!(!wfd_0.payload_state().is_reconstructed());
    assert!(!wfd_0.payload_state().failed());

    let mut guard = false;
    let mut is_header_set = false;
    for data in value_data_0 {
        if !is_header_set {
            wfd_0.handle_value(data);
            is_header_set = true;
        } else {
            let data = ReadyData::new(ori, data);
            let data = message_factory.message_from(data);
            wfd_0.handle_echo_ready(data);
        }
        wfd_0.execute();
        if wfd_0.payload_state().is_reconstructed() {
            guard = true;
            break;
        }
    }

    assert!(guard);
    assert!(!wfd_0.payload_state().failed());

    let transaction =
        Transition::<WaitingForCertificate<SupraDeliveryErasureRs16Schema>>::guard(&wfd_0);
    assert!(!can_transaction_happen(transaction));

    let transaction = Transition::<WaitingForVote<SupraDeliveryErasureRs16Schema>>::guard(&wfd_0);
    assert!(can_transaction_happen(transaction));
}

#[tokio::test]
async fn test_waiting_for_data_state_transition_handle_vote() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);

    let (mut wfd_0, mut value_data_0) =
        get_test_wfd_state::<SupraDeliveryRs16Schema>(node_index, broadcaster_index);

    assert!(!wfd_0.payload_state().is_reconstructed());
    assert!(!wfd_0.payload_state().failed());

    let first_value = value_data_0.pop().unwrap();
    let header = first_value.header().clone();
    wfd_0.handle_value(first_value);

    let auth = wfd_0.authenticator();
    let vote = auth.partial_signature(header.commitment()).unwrap();
    let vote_data = VoteData::new(header, vote);

    wfd_0.handle_vote(vote_data);
    assert!(wfd_0.payload_state().failed());
    let mut response = wfd_0.take_response().expect("Expected response");
    let feedback = response.take_feedback().remove(0);
    assert!(matches!(feedback, FeedbackMessage::InternalError(_, _)));

    assert!(!wfd_0.payload_state().has_vote(1));
}

#[tokio::test]
async fn test_waiting_for_data_state_transition_handle_certificate() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);

    let (mut wfd_0, mut value_data_0) =
        get_test_wfd_state::<SupraDeliveryRs16Schema>(node_index, broadcaster_index);

    assert!(!wfd_0.payload_state().is_reconstructed());
    assert!(!wfd_0.payload_state().failed());

    let first_value = value_data_0.pop().unwrap();
    let header = first_value.header().clone();
    wfd_0.handle_value(first_value);

    let cert_data = certificate_data(header);
    assert!(!wfd_0.payload_state().is_certified());

    wfd_0.handle_certificate(cert_data);

    assert!(wfd_0.payload_state().is_certified());
    let transaction = Transition::<WaitingForVote<SupraDeliveryErasureRs16Schema>>::guard(&wfd_0);
    assert!(!can_transaction_happen(transaction));

    let transaction =
        Transition::<WaitingForCertificate<SupraDeliveryErasureRs16Schema>>::guard(&wfd_0);
    assert!(!can_transaction_happen(transaction));
}

#[tokio::test]
async fn test_waiting_for_data_execute_good_case() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);

    let (mut wfd_0, value_data_0) =
        get_test_wfd_state::<SupraDeliveryRs16Schema>(node_index, broadcaster_index);

    assert!(!wfd_0.payload_state().is_reconstructed());
    assert!(!wfd_0.payload_state().failed());

    let mut guard = false;
    for data in value_data_0 {
        wfd_0.handle_value(data);
        wfd_0.execute();
        if wfd_0.payload_state().is_reconstructed() {
            guard = true;
            break;
        }
    }
    assert!(guard);
    assert!(!wfd_0.payload_state().failed());
    assert!(wfd_0.payload_state().is_reconstructed());

    assert_eq!(
        wfd_0.payload_state().codec().feed_len(),
        wfd_0
            .payload_state()
            .codec()
            .committee_settings()
            .data_shards()
    )
}

#[tokio::test]
async fn test_waiting_for_data_execute_bad_case_false_commitment() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);

    let mut context_provider = ContextProvider::new(broadcaster_index);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(node_index);

    let mut wfd_001 = WaitingForData::new(context);

    let (result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, chunks, _) = result.split();
    let value_data = chunks
        .into_iter()
        .map(|c| ValueData::new(header.clone(), c))
        .collect::<Vec<_>>();

    assert!(!wfd_001.payload_state().is_reconstructed());
    assert!(!wfd_001.payload_state().failed());

    let mut guard = false;

    for data in value_data {
        wfd_001.handle_value(data);
        wfd_001.execute();
        if wfd_001.payload_state().is_reconstructed() {
            guard = true;
            break;
        }
    }

    assert!(!guard);
    assert!(wfd_001.payload_state().failed());
    assert!(wfd_001.response().is_some());
    let feedback = wfd_001.take_response().unwrap().take_feedback().remove(0);
    assert!(matches!(feedback, FeedbackMessage::Error(_, _)))
}

#[tokio::test]
async fn test_waiting_for_data_handle_value_good_case() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);

    let (mut wfd_0, mut value_data_0) =
        get_test_wfd_state::<SupraDeliveryRs16Schema>(node_index, broadcaster_index);
    let good_value_data_0 = value_data_0.pop().unwrap();
    let value_data_duplicate = good_value_data_0.duplicate();

    let chunk_index_0 = good_value_data_0.get_chunk_index();

    assert!(!wfd_0.payload_state().has_chunk(chunk_index_0));
    assert!(wfd_0.response().is_none());
    assert_eq!(wfd_0.payload_state().codec().feed_len(), 0);
    assert!(!wfd_0.payload_state().failed());

    wfd_0.handle_value(good_value_data_0);

    assert_eq!(wfd_0.payload_state().codec().feed_len(), 1);
    assert!(wfd_0.payload_state().has_chunk(chunk_index_0));
    assert!(!wfd_0.payload_state().failed());
    assert!(wfd_0.response().is_some());
    let response = wfd_0.take_response().unwrap();
    assert_eq!(response.messages().len(), 1);
    let mut msg_type = false;
    if let (RBCCommitteeMessage::<SupraDeliveryErasureRs16Schema>::EchoValue(_m), _a) =
        response.messages().data().get(0).as_ref().unwrap()
    {
        msg_type = true;
    };
    assert!(msg_type);

    // duplicate value message is echoed but is not added to codec
    wfd_0.handle_value(value_data_duplicate);
    assert_eq!(wfd_0.take_response().unwrap().messages().len(), 1);
    assert_eq!(wfd_0.payload_state().codec().feed_len(), 1);
}

#[tokio::test]
async fn test_waiting_for_data_handle_echo_value_good_case() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);

    let (mut wfd_0, mut value_data_0) =
        get_test_wfd_state::<SupraDeliveryRs16Schema>(node_index, broadcaster_index);

    let good_value_data_0 = value_data_0.pop().unwrap();

    wfd_0.handle_value(good_value_data_0);

    let good_value_data_1 = value_data_0.pop().unwrap();
    let chunk_index_1 = good_value_data_1.get_chunk_index();
    let echo_val = EchoValueData::new(good_value_data_1);

    assert_eq!(wfd_0.payload_state().codec().feed_len(), 1);
    assert!(!wfd_0.payload_state().has_chunk(chunk_index_1));
    assert!(!wfd_0.payload_state().failed());

    wfd_0.handle_echo_value(echo_val);
    assert_eq!(wfd_0.payload_state().codec().feed_len(), 2);
    assert!(wfd_0.payload_state().has_chunk(chunk_index_1));
    assert!(!wfd_0.payload_state().failed());
}

#[tokio::test]
async fn check_wfd_entry() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(peer_index);

    let mut wfd_001 = WaitingForData::new(context);

    // No reconstructed payload information
    wfd_001.entry();
    assert!(wfd_001.take_response().is_none());
    assert!(!wfd_001.payload_state().failed());

    // reconstructed payload information
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);

    let mut wfd_001 = WaitingForData::new(context);
    wfd_001.entry();
    assert!(wfd_001.payload_state().failed());
    let mut response = wfd_001.take_response().expect("Expected response");
    let feedback = response.take_feedback().remove(0);
    assert!(matches!(feedback, FeedbackMessage::InternalError(_, _)));
}

#[tokio::test]
async fn late_echo_value_data_after_reconstruction_is_not_broadcaster() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let this_index = PeerGlobalIndex::new(0, 0, 1);

    let (mut wfd_0, value_data_0) =
        get_test_wfd_state::<SupraDeliveryRs16Schema>(this_index, broadcaster_index);

    let value_data_0 = value_data_0
        .into_iter()
        .filter(|data| data.get_chunk_index() != this_index.position())
        .collect::<Vec<ValueData<_>>>();

    let mut guard = false;
    for data in value_data_0 {
        let data = EchoValueData::new(data);
        wfd_0.handle_echo_value(data);
        wfd_0.execute();
        if wfd_0.payload_state().is_reconstructed() {
            guard = true;
            assert!(!wfd_0.payload_state().failed());
            assert!(wfd_0.payload_state().is_reconstructed());
            assert!(wfd_0.response().is_none());
            break;
        }
    }
    assert!(guard);
    wfd_0.exit();
    assert!(!wfd_0.payload_state().failed());
    assert!(wfd_0.payload_state().has_payload_data());
    let response = wfd_0.response().as_ref().unwrap();
    let committee = response.messages().data();
    // 1 echo value message
    assert_eq!(committee.len(), 1);
    let nt_messages = response.aux_messages().data();
    // for all network peer there should be a message
    assert_eq!(
        nt_messages.len(),
        wfd_0
            .payload_state()
            .codec()
            .network_settings()
            .as_ref()
            .unwrap()
            .total_shards()
    );
}

#[tokio::test]
async fn late_echo_value_data_after_reconstruction_is_broadcaster() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let this_index = PeerGlobalIndex::new(0, 0, 0);

    let (mut wfd_0, value_data_0) =
        get_test_wfd_state::<SupraDeliveryRs16Schema>(this_index, broadcaster_index);

    let value_data_0 = value_data_0
        .into_iter()
        .filter(|data| data.get_chunk_index() != this_index.position())
        .collect::<Vec<ValueData<_>>>();

    let mut guard = false;
    for data in value_data_0 {
        let data = EchoValueData::new(data);
        wfd_0.handle_echo_value(data);
        wfd_0.execute();
        if wfd_0.payload_state().is_reconstructed() {
            guard = true;
            assert!(!wfd_0.payload_state().failed());
            assert!(wfd_0.payload_state().is_reconstructed());
            assert!(wfd_0.response().is_none());
            break;
        }
    }
    assert!(guard);
    wfd_0.exit();
    assert!(!wfd_0.payload_state().failed());
    assert!(wfd_0.payload_state().has_payload_data());
    let resp = wfd_0.response();
    assert!(resp.is_some());
    let committee_msg = resp.as_ref().unwrap().messages().data();
    // 1 echo value for own chunk
    assert_eq!(committee_msg.len(), 1);
    let nt_messages = resp.as_ref().unwrap().aux_messages().data();
    // for all network peer there should be a message
    assert_eq!(
        nt_messages.len(),
        wfd_0
            .payload_state()
            .codec()
            .network_settings()
            .as_ref()
            .unwrap()
            .total_shards()
    );
}

#[tokio::test]
async fn test_wfd_receive_return_message() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);

    let (mut wfd_0, mut values) =
        get_test_wfd_state::<SupraDeliveryRs16Schema>(node_index, broadcaster_index);
    let value_data = values.remove(1);

    wfd_0.receive_message(RBCCommitteeMessage::Value(value_data));

    assert_eq!(wfd_0.payload_state().codec().feed_len(), 1);
    assert!(wfd_0.payload_state().has_chunk(1));
    assert!(!wfd_0.payload_state().failed());
    assert!(wfd_0.response().is_some());
    let response = wfd_0.return_message();
    assert!(response.is_some());
    assert!(wfd_0.response().is_none());
}

#[tokio::test]
async fn test_sync_request_to_any_committee_peer() {
    let broadcaster_000 = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(broadcaster_000);
    let committee_001 = PeerGlobalIndex::new(0, 0, 1);

    // committee_001 state
    let mut committee_001 = WaitingForData::new(
        context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(committee_001),
    );
    let header = committee_001.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(broadcaster_000.clan_identifier(), header.commitment());
    let sync = SyncRequest::new(header.clone(), qc);

    // committee_001 <=[sync]=
    assert!(!committee_001.payload_state().failed());
    assert!(!committee_001.payload_state().is_certified());
    committee_001.receive_message(RBCCommitteeMessage::Sync(sync));
    assert!(!committee_001.payload_state().failed());
    assert!(committee_001.payload_state().is_certified());
    let response_001 = committee_001.return_message();
    // Ongoing xRBC task does not respond to internal sync request
    assert!(response_001.is_none());
}

#[tokio::test]
async fn test_pull_request_to_owned_chunk_broadcaster_from_committee_peer() {
    let broadcaster_idx_000 = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(broadcaster_idx_000);

    let committee_001 = PeerGlobalIndex::new(0, 0, 1);
    // broadcaster_000 state
    let mut broadcaster_000 = WaitingForVote::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(broadcaster_idx_000),
    );
    let header = broadcaster_000.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(broadcaster_idx_000.clan_identifier(), header.commitment());
    let sync = SyncRequest::new(header.clone(), qc);

    // broadcaster_000 <=[pull_001]= committee_001
    let pull_001 = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&committee_001),
        sync,
    );
    assert!(!broadcaster_000.payload_state().is_certified());
    broadcaster_000.receive_message(RBCCommitteeMessage::Pull(pull_001));
    assert!(!broadcaster_000.payload_state().failed());
    assert!(!broadcaster_000.payload_state().is_certified());
    let response_000 = broadcaster_000.return_message();
    assert!(response_000.is_some());
    let feedback = response_000.as_ref().unwrap().feedback().get(0).unwrap();
    if let FeedbackMessage::Error(_, _) = feedback {
        assert!(true)
    } else {
        panic!("error expected")
    }
}

#[tokio::test]
async fn test_pull_request_to_owned_chunk_peer_from_committee_peer() {
    let broadcaster_000 = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(broadcaster_000);

    let committee_001 = PeerGlobalIndex::new(0, 0, 1);
    let committee_002 = PeerGlobalIndex::new(0, 0, 2);

    // committee_001 state
    let mut committee_001 = WaitingForData::new(
        context_provider
            .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(committee_001),
    );

    let header = committee_001.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(broadcaster_000.clan_identifier(), header.commitment());
    let sync = SyncRequest::new(header.clone(), qc);

    // committee_001 <=[pull_002]= committee_002
    let pull_002 = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&committee_002),
        sync,
    );
    assert!(!committee_001.payload_state().is_certified());
    committee_001.receive_message(RBCCommitteeMessage::Pull(pull_002));
    assert!(!committee_001.payload_state().failed());
    assert!(committee_001.payload_state().is_certified());
    let response_001 = committee_001.return_message();
    let committee_msg_001 = response_001.as_ref().unwrap().messages().data();
    assert_eq!(committee_msg_001.len(), 1);
    let msg = committee_msg_001.first().unwrap();
    if let (RBCCommitteeMessage::EchoValue(_req), address) = msg {
        assert_eq!(address.len(), 1);
    } else {
        panic!("echo message expected");
    }
}

#[tokio::test]
async fn test_pull_request_to_not_owned_chunk_peer_from_committee_peer() {
    let broadcaster_000 = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(broadcaster_000);

    let committee_001 = PeerGlobalIndex::new(0, 0, 1);
    let committee_002 = PeerGlobalIndex::new(0, 0, 2);

    // committee_001 state
    let mut committee_001 = WaitingForData::new(
        context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(committee_001),
    );

    let header = committee_001.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(broadcaster_000.clan_identifier(), header.commitment());
    let sync = SyncRequest::new(header.clone(), qc);

    // committee_001 <=[pull_002]= committee_002
    let pull_002 = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&committee_002),
        sync,
    );
    assert!(!committee_001.payload_state().is_certified());
    committee_001.receive_message(RBCCommitteeMessage::Pull(pull_002));
    assert!(!committee_001.payload_state().failed());
    assert!(committee_001.payload_state().is_certified());
    let response_001 = committee_001.return_message();
    assert!(response_001.is_none())
}

// remove ignore when check that broadcaster node can not receive Pull | Sync request is in master
#[tokio::test]
async fn test_pull_request_from_network() {
    let committee_clan = ClanIdentifier::new(0, 0);
    let broadcaster_000 = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(broadcaster_000);

    let network_010 = PeerGlobalIndex::new(0, 1, 0);
    let committee_001 = PeerGlobalIndex::new(0, 0, 1);
    let network_011 = PeerGlobalIndex::new(0, 1, 1);

    // broadcaster_000 state
    let mut broadcaster_000 = WaitingForData::new(
        context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(broadcaster_000),
    );

    // committee_001 state
    let mut committee_001 = WaitingForData::new(
        context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(committee_001),
    );

    let header = broadcaster_000.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(committee_clan, header.commitment());
    let sync = SyncRequest::new(header.clone(), qc);

    // broadcaster_000 <=[pull_010]= network_010
    let pull_010 = PullRequest::new(
        context_provider.resource_provider.get_origin(&network_010),
        sync.clone(),
    );
    assert!(!broadcaster_000.payload_state().is_certified());
    broadcaster_000.receive_message(RBCCommitteeMessage::Pull(pull_010));
    assert!(!broadcaster_000.payload_state().failed());
    assert!(!broadcaster_000.payload_state().is_certified());
    let response_000 = broadcaster_000.return_message();
    assert!(response_000.is_some());
    let feedback = response_000.as_ref().unwrap().feedback().get(0).unwrap();
    if let FeedbackMessage::Error(_, _) = feedback {
        assert!(true)
    } else {
        panic!("error expected")
    }

    // committee_001 <=[pull_011]= network_011
    let header = committee_001.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(committee_clan, header.commitment());
    let sync = SyncRequest::new(header.clone(), qc);
    let pull_011 = PullRequest::new(
        context_provider.resource_provider.get_origin(&network_011),
        sync,
    );
    assert!(!committee_001.payload_state().is_certified());
    committee_001.receive_message(RBCCommitteeMessage::Pull(pull_011));
    assert!(!committee_001.payload_state().failed());
    assert!(committee_001.payload_state().is_certified());
    let response_001 = committee_001.return_message();
    assert!(response_001.is_none())
}

#[tokio::test]
async fn test_sync_with_received_chunk_state() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let context_provider = ContextProvider::new(broadcaster_index.clone());

    let node_index = PeerGlobalIndex::new(0, 0, 1);

    let (mut wfd_0, mut value_data_0) =
        get_test_wfd_state::<SupraDeliveryRs16Schema>(node_index, broadcaster_index);

    assert!(!wfd_0.payload_state().is_reconstructed());
    assert!(!wfd_0.payload_state().failed());

    assert_eq!(wfd_0.payload_state().get_received_chunks().len(), 0);

    let value1 = value_data_0.remove(1);
    let value3 = value_data_0.remove(3);
    wfd_0.receive_message(RBCCommitteeMessage::Value(value1));
    wfd_0.receive_message(RBCCommitteeMessage::EchoValue(EchoValueData::new(value3)));
    assert_eq!(wfd_0.payload_state().get_received_chunks().len(), 2); // exclude filter [1, 4]
    let response_001 = wfd_0.return_message();
    assert!(response_001.is_some());

    let header = wfd_0.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(broadcaster_index.clan_identifier(), header.commitment());
    let sync = SyncRequest::new(header.clone(), qc);
    wfd_0.receive_message(RBCCommitteeMessage::Sync(sync));

    let response_001 = wfd_0.return_message();
    // Ongoing xRBC task does not respond to internal sync request
    assert!(response_001.is_none());
}

#[tokio::test]
async fn test_waiting_for_data_with_full_dissemination() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);

    let (mut wfd_0, _value_data_0, payload) =
        get_test_wfd_state_with_dissemination::<SupraDeliveryRs16Schema>(
            node_index,
            broadcaster_index,
            DisseminationRule::Full,
        );

    assert!(!wfd_0.payload_state().is_reconstructed());
    assert!(!wfd_0.payload_state().failed());

    // Dummy state after execute no response no state change
    wfd_0.execute();
    assert!(!wfd_0.payload_state().is_reconstructed());
    assert!(!wfd_0.payload_state().failed());

    // consume payload data, no state change
    let pld_data = PayloadData::new(wfd_0.payload_state().get_header(), payload);
    wfd_0.handle_payload(pld_data);
    assert!(!wfd_0.payload_state().is_reconstructed());
    assert!(!wfd_0.payload_state().failed());

    // with  payload data, after execute state is changed
    wfd_0.execute();
    assert!(wfd_0.payload_state().is_reconstructed());
    assert!(!wfd_0.payload_state().failed());
    // on exit network pieces are disseminated
    wfd_0.exit();
    let response = wfd_0.take_response().unwrap();
    // shares are sent to committee
    assert!(!response.aux_messages().is_empty());
    // No message is sent to committee
    assert!(response.messages().is_empty());

    // Transition to WFV state is possible
    let transaction = Transition::<WaitingForVote<SupraDeliveryErasureRs16Schema>>::guard(&wfd_0);
    assert!(can_transaction_happen(transaction));
}
