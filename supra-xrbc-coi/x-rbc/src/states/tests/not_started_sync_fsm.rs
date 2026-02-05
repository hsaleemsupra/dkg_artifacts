use crate::states::{NotStartedSyncFSM, SyncReady, WaitingForSyncData};
use crate::types::payload_state::PayloadFlags;
use crate::SupraDeliveryErasureRs8Schema;
use sfsm::{State, Transition};
use std::ops::Not;

use crate::states::tests::{can_transaction_happen, ContextProvider};
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::messages::RBCSyncMessage;
use crate::types::messages::ResponseTypeIfc;
use crate::types::payload_state::sync::PayloadType;
use crate::types::tests::header_with_origin;
use primitives::types::HeaderIfc;
use primitives::PeerGlobalIndex;

#[tokio::test]
async fn test_not_started_sync_fsm_context_with_payload() {
    let _ = env_logger::try_init();
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let check_entry_execute_exit =
        |start_state: &mut NotStartedSyncFSM<SupraDeliveryErasureRs8Schema>| {
            start_state.entry();
            assert!(start_state.response().is_none());
            assert!(
                start_state.payload_state().is_reconstructed(),
                "{}",
                start_state.payload_state()
            );
            start_state.execute();
            assert!(start_state.response().is_none());
            assert!(
                start_state.payload_state().is_reconstructed(),
                "{}",
                start_state.payload_state()
            );

            start_state.exit();
            assert!(start_state.response().is_none());
            assert!(
                start_state.payload_state().is_reconstructed(),
                "{}",
                start_state.payload_state()
            );
        };

    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let context = context_provider.sync_context_with_payload::<SupraDeliveryErasureRs8Schema>(
        peer_index,
        PayloadType::Committee,
    );
    let mut committee_start_state = NotStartedSyncFSM::new(context);
    check_entry_execute_exit(&mut committee_start_state);

    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let context = context_provider.sync_context_with_payload::<SupraDeliveryErasureRs8Schema>(
        peer_index,
        PayloadType::Network,
    );
    let mut network_start_state = NotStartedSyncFSM::new(context);
    check_entry_execute_exit(&mut network_start_state);
}

#[tokio::test]
async fn test_not_started_sync_fsm_context_without_payload() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        peer_index,
        PayloadType::Committee,
        header_with_origin(*context_provider.broadcaster_resources.topology().origin()),
    );

    let mut start_state = NotStartedSyncFSM::new(context);
    assert!(start_state.payload_state().is_reconstructed().not());
    start_state.entry();
    assert!(start_state.response().is_none());

    start_state.execute();
    let mut response = start_state.take_response().expect("Response expected");
    assert!(start_state.payload_state().is_reconstructed().not());
    assert!(start_state.payload_state().failed().not());
    let mut output = response.take_messages().take();
    assert_eq!(output.len(), 1);
    // Pull request sent to all committee peers
    let (message, addresses) = output.remove(0);
    match message {
        RBCSyncMessage::Pull(request) => {
            let (sync, sender) = request.split();
            let (header, qc) = sync.split();
            assert_eq!(&sender, start_state.topology().origin());
            assert_eq!(&header, start_state.payload_state().header());
            assert_eq!(&qc, start_state.payload_state().qc());
        }
        _ => assert!(false, "Expected pull reqeust as output"),
    }
    assert_eq!(
        addresses.len(),
        start_state.topology().get_committee_size() - 1
    );

    start_state.exit();
    assert!(start_state.response().is_none());
}

#[tokio::test]
async fn test_not_started_sync_fsm_context_without_payload_network() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        peer_index,
        PayloadType::Network,
        header_with_origin(*context_provider.broadcaster_resources.topology().origin()),
    );

    let mut start_state = NotStartedSyncFSM::new(context);
    assert!(start_state.payload_state().is_reconstructed().not());
    start_state.entry();
    assert!(start_state.response().is_none());

    start_state.execute();
    let mut response = start_state.take_response().expect("Response expected");
    assert!(start_state.payload_state().is_reconstructed().not());
    assert!(start_state.payload_state().failed().not());
    let mut output = response.take_messages().take();
    assert_eq!(output.len(), 1);
    // Pull request sent to all peers in network
    let (message, addresses) = output.remove(0);
    match message {
        RBCSyncMessage::Pull(request) => {
            let (sync, sender) = request.split();
            let (header, qc) = sync.split();
            assert_eq!(&sender, start_state.topology().origin());
            assert_eq!(&header, start_state.payload_state().header());
            assert_eq!(&qc, start_state.payload_state().qc());
        }
        _ => assert!(false, "Expected pull reqeust as output"),
    }
    assert_eq!(addresses.len(), start_state.topology().get_chain_size() - 1);

    start_state.exit();
    assert!(start_state.response().is_none());
}

#[tokio::test]
async fn test_not_started_sync_fsm_transition_to_waiting_for_sync_data() {
    let committee_peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        committee_peer_index,
        PayloadType::Committee,
        header_with_origin(*context_provider.broadcaster_resources.topology().origin()),
    );

    let committee_start_state = NotStartedSyncFSM::new(context);
    assert!(committee_start_state.response().is_none());
    assert!(committee_start_state
        .payload_state()
        .is_reconstructed()
        .not());
    assert!(!committee_start_state.payload_state().failed());

    // No transition to Ready is possible
    let transaction =
        Transition::<SyncReady<SupraDeliveryErasureRs8Schema>>::guard(&committee_start_state);
    assert!(!can_transaction_happen(transaction));

    // Transition to WFSD is possible
    let transaction = Transition::<WaitingForSyncData<SupraDeliveryErasureRs8Schema>>::guard(
        &committee_start_state,
    );
    assert!(can_transaction_happen(transaction));

    let waiting_for_data: WaitingForSyncData<SupraDeliveryErasureRs8Schema> =
        committee_start_state.into();
    assert!(waiting_for_data.response().is_none());
    assert!(waiting_for_data.payload_state().is_reconstructed().not());
    assert!(!waiting_for_data.payload_state().failed());

    let network_peer_index = PeerGlobalIndex::new(0, 1, 1);
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        network_peer_index,
        PayloadType::Network,
        header_with_origin(*context_provider.broadcaster_resources.topology().origin()),
    );

    let network_start_state = NotStartedSyncFSM::new(context);
    assert!(network_start_state.response().is_none());
    assert!(network_start_state.payload_state().is_reconstructed().not());
    assert!(!network_start_state.payload_state().failed());

    // No transition to Ready is possible
    let transaction =
        Transition::<SyncReady<SupraDeliveryErasureRs8Schema>>::guard(&network_start_state);
    assert!(!can_transaction_happen(transaction));

    // Transition to WFSD is possible
    let transaction = Transition::<WaitingForSyncData<SupraDeliveryErasureRs8Schema>>::guard(
        &network_start_state,
    );
    assert!(can_transaction_happen(transaction));

    let waiting_for_data: WaitingForSyncData<SupraDeliveryErasureRs8Schema> =
        network_start_state.into();
    assert!(waiting_for_data.response().is_none());
    assert!(waiting_for_data.payload_state().is_reconstructed().not());
    assert!(!waiting_for_data.payload_state().failed());
}

#[tokio::test]
async fn test_not_started_sync_fsm_transition_to_ready() {
    let committee_peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.sync_context_with_payload::<SupraDeliveryErasureRs8Schema>(
        committee_peer_index,
        PayloadType::Committee,
    );

    let committee_start_state = NotStartedSyncFSM::new(context);
    assert!(committee_start_state.response().is_none());
    assert!(committee_start_state.payload_state().is_reconstructed());
    assert!(!committee_start_state.payload_state().failed());

    // No transition to WFSD is possible
    let transaction = Transition::<WaitingForSyncData<SupraDeliveryErasureRs8Schema>>::guard(
        &committee_start_state,
    );
    assert!(!can_transaction_happen(transaction));

    // Transition to Ready is possible
    let transaction =
        Transition::<SyncReady<SupraDeliveryErasureRs8Schema>>::guard(&committee_start_state);
    assert!(can_transaction_happen(transaction));

    let sync_ready: SyncReady<SupraDeliveryErasureRs8Schema> = committee_start_state.into();
    assert!(sync_ready.response().is_none());
    assert!(sync_ready.payload_state().is_reconstructed());
    assert!(!sync_ready.payload_state().failed());

    let network_peer_index = PeerGlobalIndex::new(0, 1, 1);
    let context = context_provider.sync_context_with_payload::<SupraDeliveryErasureRs8Schema>(
        network_peer_index,
        PayloadType::Network,
    );

    let network_start_state = NotStartedSyncFSM::new(context);
    assert!(network_start_state.response().is_none());
    assert!(network_start_state.payload_state().is_reconstructed());
    assert!(!network_start_state.payload_state().failed());

    // No transition to WFSD is possible
    let transaction = Transition::<WaitingForSyncData<SupraDeliveryErasureRs8Schema>>::guard(
        &network_start_state,
    );
    assert!(!can_transaction_happen(transaction));

    // Transition to Ready is possible
    let transaction =
        Transition::<SyncReady<SupraDeliveryErasureRs8Schema>>::guard(&network_start_state);
    assert!(can_transaction_happen(transaction));

    let sync_ready: SyncReady<SupraDeliveryErasureRs8Schema> = network_start_state.into();
    assert!(sync_ready.response().is_none());
    assert!(sync_ready.payload_state().is_reconstructed());
    assert!(!sync_ready.payload_state().failed());
}
