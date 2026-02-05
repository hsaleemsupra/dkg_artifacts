use crate::states::tests::ContextProvider;
use crate::states::{DoneCommitteeFSM, DoneNetworkFSM, DoneSyncFSM};
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::messages::ResponseTypeIfc;
use crate::types::payload_state::sync::PayloadType;
use crate::types::payload_state::PayloadFlags;
use crate::{FeedbackMessage, SupraDeliveryErasureRs8Schema};
use primitives::types::{HeaderIfc, QuorumCertificate};
use primitives::PeerGlobalIndex;
use sfsm::{ReturnMessage, State};
use std::collections::BTreeSet;
use storage::StorageReadIfc;

fn random_certificate() -> QuorumCertificate {
    QuorumCertificate::new([2; 96], BTreeSet::from([0, 1, 2]))
}

#[tokio::test]
async fn test_done_committee_fsm_state_no_error() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut done_committee_001 = DoneCommitteeFSM::new(context);
    done_committee_001
        .payload_state_mut()
        .set_certificate(random_certificate());

    assert!(done_committee_001.response().is_none());
    done_committee_001.execute();
    assert!(done_committee_001.response().is_some());
    let resp = done_committee_001.response().as_ref().unwrap();
    assert!(!resp.feedback().is_empty());
    let feedback = &resp.feedback()[0];
    let mut done = false;
    if let FeedbackMessage::Done(..) = feedback {
        done = true;
    }
    assert!(done);
    let task_key = done_committee_001.payload_state().header().hash();
    let storage_client = done_committee_001.storage_client();
    let present = storage_client.has_key(task_key).await;
    assert!(present)
}

#[tokio::test]
async fn test_done_committee_fsm_return_response() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut done_committee_001 = DoneCommitteeFSM::new(context);
    done_committee_001
        .payload_state_mut()
        .set_certificate(random_certificate());
    assert!(done_committee_001.return_message().is_none());
    done_committee_001.execute();

    assert!(done_committee_001.response().is_some());
    let response = done_committee_001.return_message();
    assert!(done_committee_001.response().is_none());
    assert!(response.is_some());
    let task_key = done_committee_001.payload_state().header().hash();
    let storage_client = done_committee_001.storage_client();
    let present = storage_client.has_key(task_key).await;
    assert!(present)
}

#[tokio::test]
async fn test_done_committee_fsm_state_some_error() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut done_committee_001 = DoneCommitteeFSM::new(context);
    done_committee_001.payload_state_mut().set_error();

    assert!(done_committee_001.response().is_none());
    done_committee_001.execute();
    assert!(done_committee_001.response().is_none());
}

#[tokio::test]
async fn test_done_network_fsm_state_no_error() {
    let peer_index = PeerGlobalIndex::new(0, 1, 0);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context =
        context_provider.network_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut done_network_010 = DoneNetworkFSM::new(context);

    assert!(done_network_010.response().is_none());
    done_network_010.execute();
    assert!(done_network_010.response().is_some());
    let resp = done_network_010.response().as_ref().unwrap();
    assert!(!resp.feedback().is_empty());
    let feedback = &resp.feedback()[0];
    let mut done = false;
    if let FeedbackMessage::Done(..) = feedback {
        done = true;
    }
    assert!(done);
    let task_key = done_network_010.payload_state().header().hash();
    let storage_client = done_network_010.storage_client();
    let present = storage_client.has_key(task_key).await;
    assert!(present)
}

#[tokio::test]
async fn test_done_network_fsm_state_some_error() {
    let peer_index = PeerGlobalIndex::new(0, 1, 0);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context =
        context_provider.network_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut done_network_010 = DoneNetworkFSM::new(context);

    done_network_010.payload_state_mut().set_error();

    assert!(done_network_010.response().is_none());
    done_network_010.execute();
    assert!(done_network_010.response().is_none());
}

#[tokio::test]
async fn test_done_network_fsm_return_response() {
    let peer_index = PeerGlobalIndex::new(0, 1, 0);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context =
        context_provider.network_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut done_network_010 = DoneNetworkFSM::new(context);

    assert!(done_network_010.return_message().is_none());
    done_network_010.execute();

    assert!(done_network_010.response().is_some());
    let response = done_network_010.return_message();
    assert!(done_network_010.response().is_none());
    assert!(response.is_some());
    let task_key = done_network_010.payload_state().header().hash();
    let storage_client = done_network_010.storage_client();
    let present = storage_client.has_key(task_key).await;
    assert!(present)
}

#[tokio::test]
async fn test_done_sync_fsm() {
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
    let mut committee_sync_state = DoneSyncFSM::new(cmt_context);

    assert!(!committee_sync_state.payload_state().failed());
    committee_sync_state.entry();
    assert!(committee_sync_state.take_response().is_none());

    committee_sync_state.execute();
    let mut response = committee_sync_state.take_response().expect("Done feedback");
    assert!(response.take_messages().is_empty());
    let feedback = response.take_feedback().remove(0);
    assert!(matches!(feedback, FeedbackMessage::Done(_)));

    committee_sync_state.exit();
    assert!(committee_sync_state.take_response().is_none());

    // in case of error state no response is added by done state,
    // it is expected that error will be reported upon encounter
    committee_sync_state.payload_state_mut().set_error();

    committee_sync_state.entry();
    assert!(committee_sync_state.take_response().is_none());

    committee_sync_state.execute();
    assert!(committee_sync_state.take_response().is_none());

    committee_sync_state.exit();
    assert!(committee_sync_state.take_response().is_none());

    let mut network_sync_state = DoneSyncFSM::new(nt_context);
    assert!(!network_sync_state.payload_state().failed());

    network_sync_state.entry();
    assert!(network_sync_state.take_response().is_none());

    network_sync_state.execute();
    let mut response = network_sync_state.take_response().expect("Done feedback");
    assert!(response.take_messages().is_empty());
    let feedback = response.take_feedback().remove(0);
    assert!(matches!(feedback, FeedbackMessage::Done(_)));

    network_sync_state.exit();
    assert!(network_sync_state.take_response().is_none());

    // in case of error state no response is added by done state,
    // it is expected that error will be reported upon encounter
    network_sync_state.payload_state_mut().set_error();

    network_sync_state.entry();
    assert!(network_sync_state.take_response().is_none());

    network_sync_state.execute();
    assert!(network_sync_state.take_response().is_none());

    network_sync_state.exit();
    assert!(network_sync_state.take_response().is_none());
}
