use crate::states::handlers::{
    PullRequestBroadcaster, PullRequestBroadcasterCommittee, PullRequestBroadcasterNetwork,
};
use crate::states::tests::ContextProvider;
use crate::states::{WaitingForData, WaitingForShare};
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::messages::requests::SyncRequest;
use crate::types::messages::{RBCCommitteeMessage, RBCNetworkMessage, ResponseTypeIfc};
use crate::types::payload_state::PayloadFlags;
use crate::SupraDeliveryErasureRs8Schema;
use primitives::types::HeaderIfc;
use primitives::PeerGlobalIndex;

#[tokio::test]
async fn test_broadcast_pull_request_committee_data() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfd_001 = WaitingForData::new(context);
    let message_header = wfd_001.payload_state().get_header();
    let message_qc = context_provider
        .resource_provider
        .generate_qc(leader_index.clan_identifier(), message_header.commitment());
    let sync_request = SyncRequest::new(message_header.clone(), message_qc.clone());
    assert!(wfd_001.take_response().is_none());
    assert!(!wfd_001.payload_state().failed());

    PullRequestBroadcasterCommittee(wfd_001.context_mut()).broadcast_pull_request(sync_request);
    let mut response = wfd_001.take_response().expect("Expected response");
    assert!(response.take_feedback().is_empty());
    assert!(response.take_aux_messages().is_empty());
    let mut messages = response.take_messages().take();
    assert_eq!(messages.len(), 1);
    // Pull request sent to all peers in network
    let (message, addresses) = messages.remove(0);
    match message {
        RBCCommitteeMessage::Pull(request) => {
            let (sync, sender) = request.split();
            let (header, qc) = sync.split();
            assert_eq!(&sender, wfd_001.topology().origin());
            assert_eq!(header, message_header);
            assert_eq!(qc, message_qc);
        }
        _ => assert!(false, "Expected pull reqeust as output"),
    }
    assert_eq!(addresses.len(), wfd_001.topology().get_committee_size() - 1);
}

#[tokio::test]
async fn test_broadcast_pull_request_network_data() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.network_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfs_011 = WaitingForShare::new(context);
    let message_header = wfs_011.payload_state().get_header();
    let message_qc = context_provider
        .resource_provider
        .generate_qc(leader_index.clan_identifier(), message_header.commitment());
    let sync_request = SyncRequest::new(message_header.clone(), message_qc.clone());
    assert!(wfs_011.take_response().is_none());
    assert!(!wfs_011.payload_state().failed());

    PullRequestBroadcasterNetwork(wfs_011.context_mut()).broadcast_pull_request(sync_request);
    let mut response = wfs_011.take_response().expect("Expected response");
    assert!(response.take_feedback().is_empty());
    let mut messages = response.take_messages().take();
    assert_eq!(messages.len(), 1);
    // Pull request sent to all peers in network
    let (message, addresses) = messages.remove(0);
    match message {
        RBCNetworkMessage::Pull(request) => {
            let (sync, sender) = request.split();
            let (header, qc) = sync.split();
            assert_eq!(&sender, wfs_011.topology().origin());
            assert_eq!(header, message_header);
            assert_eq!(qc, message_qc);
        }
        _ => assert!(false, "Expected pull reqeust as output"),
    }
    assert_eq!(addresses.len(), wfs_011.topology().get_chain_size() - 1);
}
