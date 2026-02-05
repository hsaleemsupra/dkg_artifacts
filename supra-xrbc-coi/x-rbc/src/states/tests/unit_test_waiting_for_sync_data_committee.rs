use crate::states::handlers::{SyncMessageHandler, TimeoutMessageHandler};
use crate::states::tests::{can_transaction_happen, ContextProvider};
use crate::states::{DoneSyncFSM, SyncReady, WaitingForSyncData};
use crate::tasks::codec::{EncodeResultIfc, SupraDeliveryErasureCodec};
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    EchoReadyData, EchoValueData, RBCSyncMessage, ReadyData, ResponseTypeIfc, ValueData,
};
use crate::types::payload_state::sync::PayloadType;
use crate::types::payload_state::PayloadFlags;
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
    let node_index = PeerGlobalIndex::new(0, 0, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Committee,
        header_with_origin(
            context_provider
                .resource_provider
                .get_origin(&broadcaster_index),
        ),
    );
    let mut wfsd_001 = WaitingForSyncData::new(context);

    let transaction = Transition::<DoneSyncFSM<SupraDeliveryErasureRs8Schema>>::guard(&wfsd_001);
    assert!(!can_transaction_happen(transaction));

    wfsd_001.payload_state_mut().set_error();

    let transaction = Transition::<DoneSyncFSM<SupraDeliveryErasureRs8Schema>>::guard(&wfsd_001);
    assert!(can_transaction_happen(transaction));
}

#[tokio::test]
async fn test_wfsd_state_transition_with_data_available() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let context = context_provider.sync_context_with_payload::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Committee,
    );
    let wfsd_001 = WaitingForSyncData::new(context);

    let transaction = Transition::<SyncReady<SupraDeliveryErasureRs8Schema>>::guard(&wfsd_001);
    assert!(can_transaction_happen(transaction));
}

#[tokio::test]
async fn test_wfsd_execute() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, committee_chunks, _nt_chunks) = encoded_result.split();
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Committee,
        header.clone(),
    );
    let mut wfsd_001 = WaitingForSyncData::new(context);
    assert!(!wfsd_001.payload_state().is_reconstructed());
    assert!(!wfsd_001.payload_state().failed());

    let origin = context_provider
        .resource_provider
        .get_origin(&PeerGlobalIndex::new(0, 0, 2));
    for data in committee_chunks {
        let value_data = ValueData::new(header.clone(), data);
        let ready_data = ReadyData::new(origin, value_data);
        wfsd_001.handle_echo_ready(EchoReadyData::new(ready_data));
        wfsd_001.execute();
        if wfsd_001.payload_state().is_reconstructed() {
            break;
        }
    }
    assert!(!wfsd_001.payload_state().failed());
    assert!(wfsd_001.payload_state().is_reconstructed());
    let result = timeout(
        Duration::from_secs(1),
        wfsd_001.storage_client().read(header.hash()),
    )
    .await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_some());

    let codec = wfsd_001.payload_state_mut().payload_codec().unwrap();
    assert_eq!(codec.feed_len(), 0)
}

#[tokio::test]
async fn test_wfsd_execute_reconstruction_fails() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, committee_chunks, _nt_chunks) = encoded_result.split();
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Committee,
        header_with_origin(*header.origin()),
    );
    let mut wfsd_001 = WaitingForSyncData::new(context);
    assert!(!wfsd_001.payload_state().is_reconstructed());
    assert!(!wfsd_001.payload_state().failed());

    let origin = context_provider
        .resource_provider
        .get_origin(&PeerGlobalIndex::new(0, 0, 2));
    for data in committee_chunks {
        let value_data = ValueData::new(header.clone(), data);
        let ready_data = ReadyData::new(origin, value_data);
        wfsd_001.handle_echo_ready(EchoReadyData::new(ready_data));
        wfsd_001.execute();
    }
    assert!(wfsd_001.payload_state().failed());
    assert!(!wfsd_001.payload_state().is_reconstructed());
    let result = timeout(
        Duration::from_secs(1),
        wfsd_001.storage_client().has_key(header.hash()),
    )
    .await;
    assert!(result.is_ok());
    assert!(!result.unwrap());

    assert!(wfsd_001.response().is_some());
    let feedback = wfsd_001.take_response().unwrap().take_feedback().remove(0);
    assert!(matches!(feedback, FeedbackMessage::Error(_, _)));
}

#[tokio::test]
async fn test_wfsd_handle_echo_value() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, mut committee_chunks, _nt_chunks) = encoded_result.split();
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Committee,
        header.clone(),
    );
    let mut wfsd_001 = WaitingForSyncData::new(context);
    assert!(!wfsd_001.payload_state().is_reconstructed());
    assert!(!wfsd_001.payload_state().failed());
    assert!(!wfsd_001
        .payload_state()
        .has_chunk(broadcaster_index.position()));
    assert!(wfsd_001.payload_state().get_owned_chunk_index().is_none());
    assert!(wfsd_001.payload_state().get_owned_chunk().is_none());

    let data = committee_chunks.remove(broadcaster_index.position());
    let value_data = ValueData::new(header.clone(), data.clone());
    let echo_data = EchoValueData::new(value_data);
    wfsd_001.handle_echo_value(echo_data);
    assert!(!wfsd_001.payload_state().is_reconstructed());
    assert!(!wfsd_001.payload_state().failed());
    assert!(wfsd_001
        .payload_state()
        .has_chunk(broadcaster_index.position()));
    assert!(wfsd_001.payload_state().get_owned_chunk_index().is_none());
    assert!(wfsd_001.payload_state().get_owned_chunk().is_none());
    assert!(wfsd_001.take_response().is_none());
}

#[tokio::test]
async fn test_wfsd_handle_ready_value() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, mut committee_chunks, _nt_chunks) = encoded_result.split();
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Committee,
        header.clone(),
    );
    let mut wfsd_001 = WaitingForSyncData::new(context);
    assert!(!wfsd_001.payload_state().is_reconstructed());
    assert!(!wfsd_001.payload_state().failed());
    assert!(!wfsd_001.payload_state().has_chunk(node_index.position()));
    assert!(wfsd_001.payload_state().get_owned_chunk_index().is_none());
    assert!(wfsd_001.payload_state().get_owned_chunk().is_none());

    let data = committee_chunks.remove(node_index.position());
    let value_data = ValueData::new(header.clone(), data.clone());
    let ready_data = ReadyData::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 0, 3)),
        value_data,
    );
    wfsd_001.handle_ready(ready_data);
    assert!(!wfsd_001.payload_state().is_reconstructed());
    assert!(!wfsd_001.payload_state().failed());
    assert!(wfsd_001.payload_state().has_chunk(node_index.position()));
    assert_eq!(
        wfsd_001.payload_state().get_owned_chunk_index().unwrap(),
        node_index.position()
    );
    assert!(wfsd_001
        .payload_state()
        .get_owned_chunk()
        .unwrap()
        .data()
        .eq(data.data()));
    assert!(wfsd_001.take_response().is_none());
}

#[tokio::test]
async fn test_wfsd_handle_echo_ready_value() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, mut committee_chunks, _nt_chunks) = encoded_result.split();
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Committee,
        header.clone(),
    );
    let mut wfsd_001 = WaitingForSyncData::new(context);
    assert!(!wfsd_001.payload_state().is_reconstructed());
    assert!(!wfsd_001.payload_state().failed());
    assert!(!wfsd_001.payload_state().has_chunk(3));
    assert!(wfsd_001.payload_state().get_owned_chunk_index().is_none());
    assert!(wfsd_001.payload_state().get_owned_chunk().is_none());

    let data = committee_chunks.remove(3);
    let value_data = ValueData::new(header.clone(), data.clone());
    let echo_ready_data = EchoReadyData::new(ReadyData::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 0, 3)),
        value_data,
    ));
    wfsd_001.handle_echo_ready(echo_ready_data);
    assert!(!wfsd_001.payload_state().is_reconstructed());
    assert!(!wfsd_001.payload_state().failed());
    assert!(wfsd_001
        .payload_state()
        .has_chunk(data.data().get_chunk_index()));
    assert!(wfsd_001.payload_state().get_owned_chunk_index().is_none());
    assert!(wfsd_001.payload_state().get_owned_chunk().is_none());
    assert!(wfsd_001.take_response().is_none());
}

#[tokio::test]
async fn test_wfsd_handle_pull_request() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, mut committee_chunks, _nt_chunks) = encoded_result.split();
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Committee,
        header.clone(),
    );
    let mut wfsd_001 = WaitingForSyncData::new(context);
    assert!(!wfsd_001.payload_state().is_reconstructed());
    assert!(!wfsd_001.payload_state().failed());
    assert!(!wfsd_001.payload_state().has_chunk(node_index.position()));
    assert!(wfsd_001.payload_state().get_owned_chunk_index().is_none());
    assert!(wfsd_001.payload_state().get_owned_chunk().is_none());

    let sync_request = SyncRequest::new(header.clone(), QuorumCertificate::default());
    let committee_pull_request = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 0, 3)),
        sync_request.clone(),
    );
    let nt_pull_request = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 1, 3)),
        sync_request.clone(),
    );

    // no owned chunk no response to pull request
    wfsd_001.handle_pull_request(committee_pull_request.clone());
    assert!(!wfsd_001.payload_state().failed());
    assert!(wfsd_001.take_response().is_none());
    // nothing to send to network-peer
    wfsd_001.handle_pull_request(nt_pull_request.clone());
    assert!(!wfsd_001.payload_state().failed());
    assert!(wfsd_001.take_response().is_none());

    // add owned chunk data and check pull requests
    let data = committee_chunks.remove(node_index.position());
    let value_data = ValueData::new(header.clone(), data.clone());
    let sender = context_provider
        .resource_provider
        .get_origin(&PeerGlobalIndex::new(0, 0, 3));
    let ready_data = ReadyData::new(sender, value_data);
    wfsd_001.handle_ready(ready_data);
    assert!(!wfsd_001.payload_state().is_reconstructed());
    assert!(!wfsd_001.payload_state().failed());
    assert!(wfsd_001.payload_state().has_chunk(node_index.position()));
    assert!(wfsd_001.payload_state().get_owned_chunk().is_some());

    // owned chunk is sent as response
    wfsd_001.handle_pull_request(committee_pull_request.clone());
    assert!(!wfsd_001.payload_state().failed());
    let mut response = wfsd_001.take_response().unwrap();
    assert!(response.take_feedback().is_empty());
    let mut messages = response.take_messages().take();
    assert_eq!(messages.len(), 1);
    let (message, addresses) = messages.remove(0);
    match message {
        RBCSyncMessage::EchoValue(value) => {
            assert_eq!(value.value().chunk_data().data(), data.data());
        }
        _ => {
            assert!(false, "expected echo value, got {}", message)
        }
    }
    assert_eq!(addresses.len(), 1);

    // nothing to send to network-peer
    wfsd_001.handle_pull_request(nt_pull_request.clone());
    assert!(!wfsd_001.payload_state().failed());
    assert!(wfsd_001.take_response().is_none());
}

#[tokio::test]
async fn test_wfsd_handle_timeout() {
    let broadcaster_index = PeerGlobalIndex::new(0, 0, 0);
    let node_index = PeerGlobalIndex::new(0, 0, 1);
    let mut context_provider = ContextProvider::new(broadcaster_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, _committee_chunks, _nt_chunks) = encoded_result.split();
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        node_index,
        PayloadType::Committee,
        header.clone(),
    );
    let mut wfsd_001 = WaitingForSyncData::new(context);
    wfsd_001.handle_retry();
    let mut response = wfsd_001.take_response().unwrap();
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
    assert_eq!(
        addresses.len(),
        wfsd_001.topology().get_committee_size() - 1
    );
}
