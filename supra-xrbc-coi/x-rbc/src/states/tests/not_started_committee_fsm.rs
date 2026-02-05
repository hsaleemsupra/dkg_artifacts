use crate::states::{NotStartedCommitteeFSM, WaitingForData, WaitingForVote};
use crate::types::payload_state::PayloadFlags;
use crate::{SupraDeliveryErasureRs16Schema, SupraDeliveryErasureRs8Schema};
use sfsm::{State, Transition};
use std::ops::Not;

use crate::states::handlers::CommitteeChunkBroadcaster;
use crate::states::tests::{can_transaction_happen, ContextProvider};
use crate::tasks::config::DisseminationRule;
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::messages::RBCCommitteeMessage;
use crate::types::messages::ResponseTypeIfc;
use primitives::PeerGlobalIndex;

#[tokio::test]
async fn test_not_started_committee_fsm_context_with_payload() {
    let _ = env_logger::try_init();
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(leader_index);

    let mut start_state = NotStartedCommitteeFSM::new(context);
    let committee_size = start_state.topology().get_committee_size();
    let network_peer_size = start_state.topology().get_chain_size() - committee_size;
    start_state.entry();
    assert!(start_state.response().is_none());
    assert!(
        start_state.payload_state().is_reconstructed(),
        "{}",
        start_state.payload_state()
    );
    start_state.execute();
    let response = start_state.take_response().unwrap();
    assert!(response.messages().len().eq(&committee_size));
    assert!(response.aux_messages().len().eq(&network_peer_size));
    assert!(start_state.payload_state().is_reconstructed()); // not cleaning the payload state
    assert_eq!(
        start_state.payload_state().committee_chunks_len(),
        committee_size
    );
    assert!(start_state.payload_state().has_payload_data());

    start_state.exit();
    assert!(start_state.response().is_none());
    assert!(start_state.payload_state().is_reconstructed()); // not cleaning the chunks
    assert_eq!(
        start_state.payload_state().committee_chunks_len(),
        committee_size
    );
    assert!(start_state.payload_state().has_payload_data());
}

#[tokio::test]
async fn test_not_started_committee_fsm_context_with_payload_full_dissemination() {
    let _ = env_logger::try_init();
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload_dissemination_rule::<SupraDeliveryErasureRs8Schema>(
            leader_index,
            DisseminationRule::Full,
        );

    let mut start_state = NotStartedCommitteeFSM::new(context);
    let committee_size = start_state.topology().get_committee_size();
    let network_peer_size = start_state.topology().get_chain_size() - committee_size;
    start_state.entry();
    assert!(start_state.response().is_none());
    assert!(
        start_state.payload_state().is_reconstructed(),
        "{}",
        start_state.payload_state()
    );
    start_state.execute();
    let response = start_state.take_response().unwrap();
    assert!(response.messages().len().eq(&1));
    match &response.messages().data()[0] {
        (RBCCommitteeMessage::Payload(data), addresses) => {
            assert_eq!(addresses.len(), committee_size - 1);
        }
        _ => {
            assert!(
                false,
                "Expected payload data dissemination, got: {:?}",
                response
            )
        }
    }
    assert!(response.aux_messages().len().eq(&network_peer_size));
    assert!(start_state.payload_state().is_reconstructed()); // not cleaning the payload state
    assert_eq!(
        start_state.payload_state().committee_chunks_len(),
        committee_size
    );
    assert!(start_state.payload_state().has_payload_data());

    start_state.exit();
    assert!(start_state.response().is_none());
    assert!(start_state.payload_state().is_reconstructed()); // not cleaning the chunks
    assert_eq!(
        start_state.payload_state().committee_chunks_len(),
        committee_size
    );
    assert!(start_state.payload_state().has_payload_data());
}

#[tokio::test]
async fn test_not_started_committee_fsm_context_without_payload() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(peer_index);

    let mut start_state = NotStartedCommitteeFSM::new(context);
    assert!(start_state.payload_state().is_reconstructed().not());
    start_state.entry();
    assert!(start_state.response().is_none());
    start_state.execute();
    assert!(start_state.response().is_none());
    start_state.exit();
    assert!(start_state.response().is_none());
}

#[tokio::test]
async fn test_not_started_committee_fsm_transition_to_waiting_for_data() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs16Schema>(peer_index);

    let start_state = NotStartedCommitteeFSM::new(context);
    assert!(start_state.response().is_none());
    assert!(start_state.payload_state().is_reconstructed().not());
    assert!(!start_state.payload_state().failed());
    assert!(start_state.payload_state().all_chunks_len().eq(&0));

    let transaction =
        Transition::<WaitingForData<SupraDeliveryErasureRs16Schema>>::guard(&start_state);
    assert!(can_transaction_happen(transaction));

    let waiting_for_data: WaitingForData<SupraDeliveryErasureRs16Schema> = start_state.into();
    assert!(waiting_for_data.response().is_none());
    assert!(waiting_for_data.payload_state().is_reconstructed().not());
    assert!(!waiting_for_data.payload_state().failed());
    assert!(waiting_for_data.payload_state().all_chunks_len().eq(&0));
}

#[tokio::test]
async fn test_not_started_committee_fsm_transition_to_waiting_for_vote() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs16Schema>(leader_index);

    let transaction_wfv_ok = |state: &NotStartedCommitteeFSM<SupraDeliveryErasureRs16Schema>| {
        let transaction =
            Transition::<WaitingForVote<SupraDeliveryErasureRs16Schema>>::guard(state);
        assert!(can_transaction_happen(transaction));
    };

    let transaction_wfd_err = |state: &NotStartedCommitteeFSM<SupraDeliveryErasureRs16Schema>| {
        let transaction =
            Transition::<WaitingForData<SupraDeliveryErasureRs16Schema>>::guard(state);
        assert!(!can_transaction_happen(transaction));
    };
    let mut start_state = NotStartedCommitteeFSM::new(context);
    assert!(start_state.response().is_none());
    assert!(start_state.payload_state().is_reconstructed());
    assert!(!start_state.payload_state().failed());

    transaction_wfv_ok(&start_state);
    transaction_wfd_err(&start_state);

    start_state.payload_state_mut().take_committee_chunks();

    transaction_wfv_ok(&start_state);
    transaction_wfd_err(&start_state);

    start_state.payload_state_mut().take_network_chunks();

    transaction_wfv_ok(&start_state);
    transaction_wfd_err(&start_state);

    let waiting_for_vote: WaitingForVote<SupraDeliveryErasureRs16Schema> = start_state.into();
    assert!(waiting_for_vote.response().is_none());
    assert!(waiting_for_vote.payload_state().has_payload_data());
    assert!(!waiting_for_vote.payload_state().failed());
}

#[tokio::test]
async fn test_not_started_committee_fsm_prepare_value_message() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs16Schema>(leader_index);

    let mut start_state = NotStartedCommitteeFSM::new(context);

    let mut value_data = start_state.get_committee_value_data();
    let committee_size = start_state.topology().get_committee_size();
    assert!(value_data.len().eq(&committee_size));
    let data = value_data.pop().unwrap();
    let (msg, address) = start_state.prepare_value_message(data);
    assert_eq!(address.len(), 1);
    assert!(matches!(msg, RBCCommitteeMessage::Value(_)))
}

#[tokio::test]
async fn test_not_started_committee_fsm_prepare_echo_message() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs16Schema>(leader_index);

    let mut start_state = NotStartedCommitteeFSM::new(context);

    let mut value_data = start_state.get_committee_value_data();
    assert!(!value_data.is_empty());
    let data = value_data.remove(0);
    let (msg, addresses) = start_state.prepare_echo_message(data);

    assert_eq!(
        addresses.len(),
        start_state.topology().get_committee_size() - 1
    );
    assert!(matches!(msg, RBCCommitteeMessage::EchoValue(_)))
}
