use crate::states::handlers::NetworkShareBroadcaster;
use crate::states::tests::ContextProvider;
use crate::states::WaitingForData;
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::messages::ResponseTypeIfc;
use crate::types::payload_state::PayloadFlags;
use crate::SupraDeliveryErasureRs8Schema;
use erasure::utils::codec_trait::Setting;
use primitives::PeerGlobalIndex;
use std::collections::HashSet;

#[tokio::test]
async fn test_get_share_data() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfd_001 = WaitingForData::new(context);
    let share_data = wfd_001.get_share_data();
    assert_eq!(
        share_data.len(),
        wfd_001
            .payload_state()
            .codec()
            .network_settings()
            .as_ref()
            .unwrap()
            .total_shards()
    );
    let committee_size = wfd_001.topology().get_committee_size();
    let current_node_position = wfd_001.topology().get_position();
    share_data.into_iter().enumerate().for_each(|(idx, data)| {
        assert_eq!(idx + committee_size, data.get_network_chunk_index());
        assert!(!data.network_chunk_meta().proof().is_empty());
        assert_eq!(data.get_piece_index(), current_node_position);
    });

    assert!(wfd_001.take_response().is_none());
    assert!(wfd_001.payload_state().is_reconstructed()); // not cleaning the chunks
    assert!(wfd_001.payload_state().has_payload_data());
    assert!(wfd_001.payload_state().network_chunks().is_some()); // not cleaning the chunks
    assert!(wfd_001.payload_state().committee_chunks().is_some()); // not cleaning the chunks

    let share_data = wfd_001.get_share_data();
    assert!(!share_data.is_empty());
}

#[test]
#[should_panic]
fn test_get_share_data_with_no_payload_data() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);

    let mut wfd_001 = WaitingForData::new(context);
    assert!(!wfd_001.payload_state().is_reconstructed());
    assert!(!wfd_001.payload_state().has_payload_data());
    wfd_001.get_share_data();
}

#[tokio::test]
async fn test_broadcast_network_shares() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfd_001 = WaitingForData::new(context);
    wfd_001.broadcast_network_shares();
    assert!(wfd_001.payload_state().is_reconstructed()); // not cleaning the chunks
    assert!(wfd_001.payload_state().has_payload_data());
    assert!(wfd_001.payload_state().network_chunks().is_some()); // not cleaning the chunks
    assert!(wfd_001.payload_state().committee_chunks().is_some()); // not cleaning the chunks

    let response = wfd_001
        .take_response()
        .expect("Response with network shares");
    assert!(response.messages().is_empty());
    assert_eq!(
        response.aux_messages().len(),
        wfd_001
            .payload_state()
            .codec()
            .network_settings()
            .as_ref()
            .unwrap()
            .total_shards()
    );
    // each message is sent to unique address
    let addresses = response
        .aux_messages()
        .data()
        .iter()
        .map(|(_, address)| {
            assert_eq!(address.len(), 1);
            address[0].clone()
        })
        .collect::<HashSet<_>>();
    assert_eq!(addresses.len(), response.aux_messages().len());

    // network chunks can still be fetched until next gc timeout
    wfd_001.broadcast_network_shares();
    assert!(!wfd_001.payload_state().failed());
    assert!(wfd_001.take_response().is_some());
}

#[tokio::test]
async fn test_broadcast_network_shares_negative_case() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(peer_index);

    let mut wfd_001 = WaitingForData::new(context);

    // No data
    assert!(!wfd_001.payload_state().is_reconstructed());
    assert!(!wfd_001.payload_state().has_payload_data());
    wfd_001.broadcast_network_shares();
    assert!(wfd_001.take_response().is_none());

    let context = context_provider
        .committee_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);

    let mut wfd_001 = WaitingForData::new(context);
    wfd_001.payload_state_mut().set_error();
    wfd_001.broadcast_network_shares();
    assert!(wfd_001.payload_state().is_reconstructed());
    assert!(wfd_001.payload_state().failed());
    assert!(wfd_001.take_response().is_none());
}
