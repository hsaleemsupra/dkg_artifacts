use crate::states::handlers::{SyncMessageHandler, SyncMessageReceiver, TimeoutMessageHandler};
use crate::states::tests::{can_transaction_happen, ContextProvider};
use crate::states::{DoneSyncFSM, SyncReady};
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    EchoReadyData, EchoShareData, EchoValueData, RBCSyncMessage, ReadyData, ResponseTypeIfc,
    ShareData,
};
use crate::types::payload_state::sync::PayloadType;
use crate::types::payload_state::{NetworkChunkDataSettings, PayloadFlags};
use crate::types::tests::value_data_with_header_idx;
use crate::SupraDeliveryErasureRs8Schema;
use primitives::types::{HeaderIfc, QuorumCertificate};
use primitives::PeerGlobalIndex;
use sfsm::Transition;
use vec_commitment::committed_chunk::CommitmentMeta;

fn check_message_is_ignored<C: SupraDeliveryErasureCodecSchema>(
    sync_ready: &mut SyncReady<C>,
    message: RBCSyncMessage<C>,
) {
    assert!(sync_ready.payload_state().is_reconstructed());
    assert!(!sync_ready.payload_state().failed());
    assert!(sync_ready.take_response().is_none());
    assert!(sync_ready.payload_state().owned_chunk_meta().is_none());
    sync_ready.process(message);
    assert!(sync_ready.payload_state().is_reconstructed());
    assert!(!sync_ready.payload_state().failed());
    assert!(sync_ready.take_response().is_none());
    assert!(sync_ready.payload_state().owned_chunk_meta().is_none());
}

#[tokio::test]
async fn test_all_message_are_ignored() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let nt_peer_index = PeerGlobalIndex::new(0, 1, 2);
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let nt_context = context_provider.sync_context_with_payload::<SupraDeliveryErasureRs8Schema>(
        nt_peer_index,
        PayloadType::Network,
    );
    let cmt_context = context_provider.sync_context_with_payload::<SupraDeliveryErasureRs8Schema>(
        peer_index,
        PayloadType::Committee,
    );
    let mut committee_sync_state = SyncReady::new(cmt_context);
    let mut network_sync_state = SyncReady::new(nt_context);

    let data_index = 10;
    let header = committee_sync_state.payload_state().get_header();

    let echo_value_data = EchoValueData::new(value_data_with_header_idx::<
        SupraDeliveryErasureRs8Schema,
    >(header.clone(), data_index * 2));
    let echo_value_msg = RBCSyncMessage::EchoValue(echo_value_data);
    check_message_is_ignored(&mut committee_sync_state, echo_value_msg);

    let ready_data = ReadyData::new(
        [4; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index * 3),
    );
    let ready_msg = RBCSyncMessage::Ready(ready_data);
    check_message_is_ignored(&mut committee_sync_state, ready_msg);

    let echo_ready_data = EchoReadyData::new(ReadyData::new(
        [4; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index * 4),
    ));
    let echo_ready_msg = RBCSyncMessage::EchoReady(echo_ready_data);
    check_message_is_ignored(&mut committee_sync_state, echo_ready_msg);

    let header = network_sync_state.payload_state().get_header();
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let share_msg = RBCSyncMessage::Share(ShareData::new(
        [0; 32],
        value_data,
        CommitmentMeta::default(),
    ));
    check_message_is_ignored(&mut network_sync_state, share_msg);

    let data_index = 4;
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let share_msg = RBCSyncMessage::EchoShare(EchoShareData::new([0; 32], value_data));
    check_message_is_ignored(&mut network_sync_state, share_msg);
}

#[tokio::test]
async fn test_sync_ready_handle_pull_request_committee() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let context = context_provider.sync_context_with_payload::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Committee,
    );
    let header = context.payload_state().get_header();
    let mut sync_ready_001 = SyncReady::new(context);
    assert!(sync_ready_001.payload_state().is_reconstructed());
    assert!(!sync_ready_001.payload_state().failed());
    assert!(sync_ready_001
        .payload_state()
        .get_owned_chunk_index()
        .is_some());
    assert!(sync_ready_001.payload_state().get_owned_chunk().is_some());

    let sync_request = SyncRequest::new(header.clone(), QuorumCertificate::default());
    let requester_index = PeerGlobalIndex::new(0, 0, 3);
    let committee_pull_request = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&requester_index),
        sync_request.clone(),
    );
    sync_ready_001.handle_pull_request(committee_pull_request.clone());
    assert!(!sync_ready_001.payload_state().failed());
    let mut response = sync_ready_001.take_response().unwrap();
    assert!(response.take_feedback().is_empty());
    let messages = response.take_messages().take();
    assert_eq!(messages.len(), 2);
    for (message, addresses) in messages {
        match message {
            RBCSyncMessage::Ready(value) => {
                assert_eq!(value.value().get_chunk_index(), requester_index.position());
            }
            RBCSyncMessage::EchoReady(value) => {
                assert_eq!(value.value().get_chunk_index(), node_index.position());
            }
            _ => {
                assert!(false, "expected echo ready or ready, got {}", message)
            }
        }
        assert_eq!(addresses.len(), 1);
    }

    // network chunk piece is sent to requester
    let nt_peer_index = PeerGlobalIndex::new(0, 1, 3);
    let nt_pull_request = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&nt_peer_index),
        sync_request.clone(),
    );

    sync_ready_001.handle_pull_request(nt_pull_request.clone());
    assert!(!sync_ready_001.payload_state().failed());
    let mut response = sync_ready_001.take_response().unwrap();
    assert!(response.take_feedback().is_empty());
    let messages = response.take_messages().take();
    assert_eq!(messages.len(), 1);
    for (message, addresses) in messages {
        match message {
            RBCSyncMessage::Share(value) => {
                assert_eq!(value.value().get_chunk_index(), node_index.position());
                assert_eq!(
                    value.network_chunk_meta().index(),
                    nt_peer_index.position() + sync_ready_001.topology().get_committee_size()
                );
            }
            _ => {
                assert!(false, "expected share , got {}", message)
            }
        }
        assert_eq!(addresses.len(), 1);
    }
}

#[tokio::test]
async fn test_wfsd_handle_pull_request() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 1, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let context = context_provider.sync_context_with_payload::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Network,
    );
    let header = context.payload_state().get_header();
    let mut sync_ready_011 = SyncReady::new(context);
    assert!(sync_ready_011.payload_state().is_reconstructed());
    assert!(!sync_ready_011.payload_state().failed());
    assert!(sync_ready_011.payload_state().get_owned_chunk().is_some());

    let sync_request = SyncRequest::new(header.clone(), QuorumCertificate::default());
    let nt_pull_request = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 1, 3)),
        sync_request.clone(),
    );

    // owned chunk is sent as response
    sync_ready_011.handle_pull_request(nt_pull_request);
    assert!(!sync_ready_011.payload_state().failed());
    let mut response = sync_ready_011.take_response().unwrap();
    assert!(response.take_feedback().is_empty());
    let mut messages = response.take_messages().take();
    assert_eq!(messages.len(), 1);
    let (message, addresses) = messages.remove(0);
    match message {
        RBCSyncMessage::EchoShare(value) => {
            assert_eq!(value.value().get_chunk_index(), node_index.position());
        }
        _ => {
            assert!(false, "expected echo share, got {}", message)
        }
    }
    assert_eq!(addresses.len(), 1);
}

#[tokio::test]
async fn test_handle_timeout() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let nt_peer_index = PeerGlobalIndex::new(0, 1, 2);
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let nt_context = context_provider.sync_context_with_payload::<SupraDeliveryErasureRs8Schema>(
        nt_peer_index,
        PayloadType::Network,
    );
    let cmt_context = context_provider.sync_context_with_payload::<SupraDeliveryErasureRs8Schema>(
        peer_index,
        PayloadType::Committee,
    );
    let mut committee_sync_state = SyncReady::new(cmt_context);

    assert!(!committee_sync_state.payload_state().should_finalize());
    committee_sync_state.handle_retry();
    assert!(committee_sync_state.payload_state().should_finalize());

    let mut network_sync_state = SyncReady::new(nt_context);
    assert!(!network_sync_state.payload_state().should_finalize());
    network_sync_state.handle_retry();
    assert!(network_sync_state.payload_state().should_finalize());
}

#[tokio::test]
async fn test_check_transition() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);

    let nt_peer_index = PeerGlobalIndex::new(0, 1, 2);
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let nt_context = context_provider.sync_context_with_payload::<SupraDeliveryErasureRs8Schema>(
        nt_peer_index,
        PayloadType::Network,
    );
    let cmt_context = context_provider.sync_context_with_payload::<SupraDeliveryErasureRs8Schema>(
        peer_index,
        PayloadType::Committee,
    );
    let mut committee_sync_state = SyncReady::new(cmt_context);

    assert!(!committee_sync_state.payload_state().should_finalize());
    let transition_guard =
        Transition::<DoneSyncFSM<SupraDeliveryErasureRs8Schema>>::guard(&committee_sync_state);
    assert!(!can_transaction_happen(transition_guard));

    committee_sync_state.handle_retry();
    let transition_guard =
        Transition::<DoneSyncFSM<SupraDeliveryErasureRs8Schema>>::guard(&committee_sync_state);
    assert!(can_transaction_happen(transition_guard));

    let mut network_sync_state = SyncReady::new(nt_context);
    assert!(!network_sync_state.payload_state().should_finalize());
    let transition_guard =
        Transition::<DoneSyncFSM<SupraDeliveryErasureRs8Schema>>::guard(&network_sync_state);
    assert!(!can_transaction_happen(transition_guard));
    network_sync_state.handle_retry();
    let transition_guard =
        Transition::<DoneSyncFSM<SupraDeliveryErasureRs8Schema>>::guard(&network_sync_state);
    assert!(can_transaction_happen(transition_guard));
}
