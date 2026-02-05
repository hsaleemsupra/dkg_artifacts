use crate::states::not_started::NotStarted;
use crate::states::tests::{can_transaction_happen, ContextProvider};
use crate::states::{NotStartedNetworkFSM, WaitingForShare};
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::context::network::NetworkFSMContext;
use crate::types::context::FSMContextOwner;
use crate::types::payload_state::PayloadFlags;
use crate::SupraDeliveryErasureRs16Schema;
use primitives::PeerGlobalIndex;
use sfsm::{State, Transition};

pub(crate) fn network_fsm_state_context_rs16() -> NetworkFSMContext<SupraDeliveryErasureRs16Schema>
{
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    context_provider.network_context::<SupraDeliveryErasureRs16Schema>(peer_index)
}

fn assert_not_started_network_payload_state_struct_items_is_none<
    C: SupraDeliveryErasureCodecSchema,
>(
    start_state: &NotStarted<NetworkFSMContext<C>>,
) {
    assert!(start_state
        .payload_state()
        .reconstructed_payload()
        .is_none());
}

fn assert_waiting_for_share_payload_state_struct_items_is_none<
    C: SupraDeliveryErasureCodecSchema,
>(
    start_state: &WaitingForShare<C>,
) {
    assert!(start_state
        .payload_state()
        .reconstructed_payload()
        .is_none());
    assert!(!start_state.payload_state().failed());
}

#[tokio::test]
async fn test_not_started_network_fsm_context_is_not_modified() {
    let context: NetworkFSMContext<SupraDeliveryErasureRs16Schema> =
        network_fsm_state_context_rs16();
    let mut start_state = NotStartedNetworkFSM::new(context);

    assert_not_started_network_payload_state_struct_items_is_none(&start_state);
    assert!(!start_state.payload_state().failed());
    start_state.entry();
    assert_not_started_network_payload_state_struct_items_is_none(&start_state);
    assert!(!start_state.payload_state().failed());
    start_state.execute();
    assert_not_started_network_payload_state_struct_items_is_none(&start_state);
    assert!(!start_state.payload_state().failed());
    start_state.exit();
    assert_not_started_network_payload_state_struct_items_is_none(&start_state);
    assert!(!start_state.payload_state().failed());
}

#[tokio::test]
async fn test_not_started_network_fsm_transition_to_waiting_for_share() {
    let context: NetworkFSMContext<SupraDeliveryErasureRs16Schema> =
        network_fsm_state_context_rs16();
    let start_state = NotStartedNetworkFSM::new(context);

    assert_not_started_network_payload_state_struct_items_is_none(&start_state);
    assert!(!start_state.payload_state().failed());
    let transaction =
        Transition::<WaitingForShare<SupraDeliveryErasureRs16Schema>>::guard(&start_state);
    assert!(can_transaction_happen(transaction));
    let wfs: WaitingForShare<SupraDeliveryErasureRs16Schema> = start_state.into();
    assert_waiting_for_share_payload_state_struct_items_is_none(&wfs);
}
