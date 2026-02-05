use crate::states::handlers::{SyncMessageHandler, TimeoutMessageHandler};
use crate::states::tests::{can_transaction_happen, ContextProvider};
use crate::states::{DoneSyncFSM, SyncReady, WaitingForSyncData};
use crate::tasks::codec::{EncodeResultIfc, SupraDeliveryErasureCodec};
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    EchoShareData, RBCSyncMessage, ResponseTypeIfc, ShareData, ValueData,
};
use crate::types::payload_state::sync::PayloadType;
use crate::types::payload_state::{NetworkChunkDataSettings, PayloadFlags};
use crate::types::tests::header_with_origin;
use crate::{FeedbackMessage, SupraDeliveryErasureRs8Schema};
use primitives::types::{HeaderIfc, QuorumCertificate};
use primitives::PeerGlobalIndex;
use sfsm::{State, Transition};
use std::time::Duration;
use storage::StorageReadIfc;
use tokio::time::timeout;

#[tokio::test]
async fn test_wfsd_state_transition_in_case_of_failure() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 1, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Network,
        header_with_origin(
            context_provider
                .resource_provider
                .get_origin(&broadcaster_index),
        ),
    );
    let mut wfsd_011 = WaitingForSyncData::new(context);

    let transaction = Transition::<DoneSyncFSM<SupraDeliveryErasureRs8Schema>>::guard(&wfsd_011);
    assert!(!can_transaction_happen(transaction));

    wfsd_011.payload_state_mut().set_error();

    let transaction = Transition::<DoneSyncFSM<SupraDeliveryErasureRs8Schema>>::guard(&wfsd_011);
    assert!(can_transaction_happen(transaction));
}

#[tokio::test]
async fn test_wfsd_state_transition_with_data_available() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 1, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let context = context_provider.sync_context_with_payload::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Network,
    );
    let wfsd_011 = WaitingForSyncData::new(context);

    let transaction = Transition::<SyncReady<SupraDeliveryErasureRs8Schema>>::guard(&wfsd_011);
    assert!(can_transaction_happen(transaction));
}

#[tokio::test]
async fn test_wfsd_execute_network_chunk_reconstruction() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 1, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, _committee_chunks, mut nt_chunks) = encoded_result.split();
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Network,
        header.clone(),
    );
    let mut wfsd_011 = WaitingForSyncData::new(context);
    assert!(!wfsd_011.payload_state().is_reconstructed());
    assert!(!wfsd_011.payload_state().failed());

    let (meta, nt_pieces) = nt_chunks.remove(wfsd_011.owned_chunk_data_index()).split();
    for data in nt_pieces {
        let sender = context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 0, data.data().get_chunk_index()));
        let value_data = ValueData::new(header.clone(), data);
        let share_data = ShareData::new(sender, value_data, meta.clone());
        wfsd_011.handle_share(share_data);
        wfsd_011.execute();
        if wfsd_011.payload_state().has_chunk(1) {
            break;
        }
    }
    assert!(!wfsd_011.payload_state().failed());
    assert!(wfsd_011.payload_state().get_owned_chunk().is_some());

    let codec = wfsd_011.payload_state_mut().payload_codec().unwrap();
    assert_eq!(codec.feed_len(), 1)
}

#[tokio::test]
async fn test_wfsd_execute_network_chunk_reconstruction_fails() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 1, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, _committee_chunks, mut nt_chunks) = encoded_result.split();
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Network,
        header.clone(),
    );
    let mut wfsd_011 = WaitingForSyncData::new(context);
    assert!(!wfsd_011.payload_state().is_reconstructed());
    assert!(!wfsd_011.payload_state().failed());

    let (_meta, nt_pieces) = nt_chunks.remove(wfsd_011.owned_chunk_data_index()).split();
    // other meta
    let meta = nt_chunks[0].split_ref().0.clone();
    for data in nt_pieces {
        let sender = context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 0, data.data().get_chunk_index()));
        let value_data = ValueData::new(header.clone(), data);
        let share_data = ShareData::new(sender, value_data, meta.clone());
        wfsd_011.handle_share(share_data);
        wfsd_011.execute();
    }
    assert!(!wfsd_011.payload_state().failed());
    assert!(wfsd_011.payload_state().get_owned_chunk().is_none());
    assert!(wfsd_011.payload_state().owned_chunk_meta().is_some());

    let codec = wfsd_011.payload_state_mut().payload_codec().unwrap();
    assert_eq!(codec.feed_len(), 0);
    assert!(wfsd_011.take_response().is_none());
}

#[tokio::test]
async fn test_wfsd_execute_payload_reconstruction() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 1, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, _committee_chunks, nt_chunks) = encoded_result.split();
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Network,
        header.clone(),
    );
    let mut wfsd_011 = WaitingForSyncData::new(context);
    assert!(!wfsd_011.payload_state().is_reconstructed());
    assert!(!wfsd_011.payload_state().failed());
    assert!(wfsd_011.payload_state().get_owned_chunk().is_none());

    let origin = context_provider
        .resource_provider
        .get_origin(&PeerGlobalIndex::new(0, 0, 2));
    for data in nt_chunks {
        let nt_chunk = data
            .decode(wfsd_011.payload_state_mut().chunk_codec().unwrap().clone())
            .unwrap();
        let value_data = ValueData::new(header.clone(), nt_chunk);
        let echo_share = EchoShareData::new(origin, value_data);
        wfsd_011.handle_echo_share(echo_share);
        wfsd_011.execute();
        if wfsd_011.payload_state().is_reconstructed() {
            break;
        }
    }
    assert!(!wfsd_011.payload_state().failed());
    assert!(wfsd_011.payload_state().is_reconstructed());
    assert!(wfsd_011.payload_state().get_owned_chunk().is_some());
    assert_eq!(wfsd_011.payload_state().get_owned_chunk_index().unwrap(), 1);
    let result = timeout(
        Duration::from_secs(1),
        wfsd_011.storage_client().read(header.hash()),
    )
    .await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
}

#[tokio::test]
async fn test_wfsd_execute_reconstruction_fails() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 1, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, _committee_chunks, nt_chunks) = encoded_result.split();
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Network,
        header_with_origin(*header.origin()),
    );
    let mut wfsd_011 = WaitingForSyncData::new(context);
    assert!(!wfsd_011.payload_state().is_reconstructed());
    assert!(!wfsd_011.payload_state().failed());

    let origin = context_provider
        .resource_provider
        .get_origin(&PeerGlobalIndex::new(0, 0, 2));
    for data in nt_chunks {
        let nt_chunk = data
            .decode(wfsd_011.payload_state_mut().chunk_codec().unwrap().clone())
            .unwrap();
        let value_data = ValueData::new(header.clone(), nt_chunk);
        let echo_share = EchoShareData::new(origin, value_data);
        wfsd_011.handle_echo_share(echo_share);
        wfsd_011.execute();
        if wfsd_011.payload_state().failed() {
            break;
        }
    }
    assert!(wfsd_011.payload_state().failed());
    assert!(!wfsd_011.payload_state().is_reconstructed());
    assert!(wfsd_011.payload_state().get_owned_chunk().is_none());
    let result = timeout(
        Duration::from_secs(1),
        wfsd_011.storage_client().has_key(header.hash()),
    )
    .await;
    assert!(result.is_ok());
    assert!(!result.unwrap());

    assert!(wfsd_011.response().is_some());
    let feedback = wfsd_011.take_response().unwrap().take_feedback().remove(0);
    assert!(matches!(feedback, FeedbackMessage::Error(_, _)));
}

#[tokio::test]
async fn test_wfsd_handle_share_data() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 1, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, _committee_chunks, mut nt_chunks) = encoded_result.split();
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Network,
        header.clone(),
    );
    let mut wfsd_011 = WaitingForSyncData::new(context);
    assert!(!wfsd_011.payload_state().is_reconstructed());
    assert!(!wfsd_011.payload_state().failed());
    assert!(!wfsd_011
        .payload_state()
        .has_piece(broadcaster_index.position()));
    assert!(wfsd_011.payload_state().get_owned_chunk_index().is_none());
    assert!(wfsd_011.payload_state().owned_chunk_meta().is_none());
    assert!(wfsd_011.payload_state().get_owned_chunk().is_none());

    let (meta, mut nt_pieces) = nt_chunks.remove(wfsd_011.owned_chunk_data_index()).split();
    let data = nt_pieces.remove(broadcaster_index.position());
    let value_data = ValueData::new(header.clone(), data.clone());
    let share_data = ShareData::new(
        context_provider
            .resource_provider
            .get_origin(&broadcaster_index),
        value_data,
        meta.clone(),
    );
    wfsd_011.handle_share(share_data);
    assert!(!wfsd_011.payload_state().is_reconstructed());
    assert!(!wfsd_011.payload_state().failed());
    assert!(wfsd_011
        .payload_state()
        .has_piece(broadcaster_index.position()));
    assert!(wfsd_011.payload_state().owned_chunk_meta().is_some());
    assert!(wfsd_011.payload_state().get_owned_chunk_index().is_none());
    assert!(wfsd_011.payload_state().get_owned_chunk().is_none());
    assert!(wfsd_011.take_response().is_none());
}

#[tokio::test]
async fn test_wfsd_handle_echo_share() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 1, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, _committee_chunks, mut nt_chunks) = encoded_result.split();
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Network,
        header.clone(),
    );
    let mut wfsd_011 = WaitingForSyncData::new(context);
    assert!(!wfsd_011.payload_state().is_reconstructed());
    assert!(!wfsd_011.payload_state().failed());
    assert!(!wfsd_011.payload_state().has_chunk(0));
    assert!(wfsd_011.payload_state().get_owned_chunk_index().is_none());
    assert!(wfsd_011.payload_state().get_owned_chunk().is_none());

    let nt_chunk = nt_chunks
        .remove(0)
        .decode(wfsd_011.payload_state_mut().chunk_codec().unwrap().clone())
        .unwrap();
    let value_data = ValueData::new(header.clone(), nt_chunk);
    let share_data = EchoShareData::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 1, 0)),
        value_data,
    );
    wfsd_011.handle_echo_share(share_data);
    assert!(!wfsd_011.payload_state().is_reconstructed());
    assert!(!wfsd_011.payload_state().failed());
    assert!(wfsd_011.payload_state().has_chunk(0));
    assert!(wfsd_011.payload_state().get_owned_chunk_index().is_none(),);
    assert!(wfsd_011.payload_state().get_owned_chunk().is_none());
    assert!(wfsd_011.take_response().is_none());
}

#[tokio::test]
async fn test_wfsd_handle_pull_request() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 1, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, _committee_chunks, mut nt_chunks) = encoded_result.split();
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Network,
        header.clone(),
    );
    let mut wfsd_011 = WaitingForSyncData::new(context);
    assert!(!wfsd_011.payload_state().is_reconstructed());
    assert!(!wfsd_011.payload_state().failed());
    assert!(!wfsd_011.payload_state().has_chunk(node_index.position()));
    assert!(wfsd_011.payload_state().get_owned_chunk_index().is_none());
    assert!(wfsd_011.payload_state().get_owned_chunk().is_none());

    let sync_request = SyncRequest::new(header.clone(), QuorumCertificate::default());
    let nt_pull_request = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 1, 3)),
        sync_request.clone(),
    );

    // no owned chunk no response to pull request
    // nothing to send to network-peer
    wfsd_011.handle_pull_request(nt_pull_request.clone());
    assert!(!wfsd_011.payload_state().failed());
    assert!(wfsd_011.take_response().is_none());

    // add owned chunk data and check pull requests
    let nt_chunk = nt_chunks
        .remove(node_index.position())
        .decode(wfsd_011.payload_state_mut().chunk_codec().unwrap().clone())
        .unwrap();
    wfsd_011
        .payload_state_mut()
        .set_owned_chunk(nt_chunk.clone());
    assert!(!wfsd_011.payload_state().is_reconstructed());
    assert!(!wfsd_011.payload_state().failed());
    assert!(wfsd_011.payload_state().get_owned_chunk().is_some());

    // owned chunk is sent as response
    wfsd_011.handle_pull_request(nt_pull_request);
    assert!(!wfsd_011.payload_state().failed());
    let mut response = wfsd_011.take_response().unwrap();
    assert!(response.take_feedback().is_empty());
    let mut messages = response.take_messages().take();
    assert_eq!(messages.len(), 1);
    let (message, addresses) = messages.remove(0);
    match message {
        RBCSyncMessage::EchoShare(value) => {
            assert_eq!(value.value().chunk_data().data(), nt_chunk.data());
        }
        _ => {
            assert!(false, "expected echo share, got {}", message)
        }
    }
    assert_eq!(addresses.len(), 1);
}

#[tokio::test]
async fn test_wfsd_handle_timeout() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 1, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, _committee_chunks, _nt_chunks) = encoded_result.split();
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Network,
        header.clone(),
    );
    let mut wfsd_011 = WaitingForSyncData::new(context);
    wfsd_011.handle_retry();
    let mut response = wfsd_011.take_response().unwrap();
    assert!(response.take_feedback().is_empty());
    let mut messages = response.take_messages().take();
    assert_eq!(messages.len(), 1);
    let (message, addresses) = messages.remove(0);
    match message {
        RBCSyncMessage::Pull(_) => {}
        _ => {
            assert!(false, "Expected pull request, got: {}", message);
        }
    }
    assert_eq!(addresses.len(), wfsd_011.topology().get_chain_size() - 1);
}
