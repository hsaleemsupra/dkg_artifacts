use crate::tasks::codec::{EncodeResultIfc, SupraDeliveryCodec, SupraDeliveryErasureCodec};
use crate::types::context::ResourcesApi;
use crate::types::helpers::verifier_visitor::verify_value_data_tests::{
    encoded_chunks, rs8_codec, TestResources,
};
use crate::types::messages::chunk::{ChunkData, NetworkChunk};
use crate::types::payload_state::sync::{PayloadType, SyncPayloadState};
use crate::types::payload_state::{NetworkChunkDataSettings, PayloadDataSettings, PayloadFlags};
use crate::types::tests::header_with_origin;
use crate::{QuorumCertificate, SupraDeliveryErasureRs8Schema};
use erasure::codecs::rs8::Rs8Settings;
use erasure::utils::codec_trait::Setting;
use metrics::TimeStampTrait;
use network::topology::peer_info::Role;
use primitives::types::Header;
use primitives::PeerGlobalIndex;
use std::time::Duration;
use std::vec;
use vec_commitment::committed_chunk::CommittedChunk;

#[tokio::test]
async fn test_state_for_committee() {
    let mut state = SyncPayloadState::for_committee(
        header_with_origin([0; 32]),
        QuorumCertificate::default(),
        rs8_codec(),
    );
    assert_eq!(state.payload_type(), PayloadType::Committee);
    assert!(!state.has_payload_data());
    assert!(!state.is_reconstructed());
    assert!(state.get_owned_chunk().is_none());
    assert!(state.get_owned_chunk_index().is_none());
    assert!(state.committee_chunks().is_empty());
    assert!(state.network_chunk_pieces().is_empty());
    assert!(state.payload_codec().is_some());
    assert!(state.chunk_codec().is_none());

    let mut test_resources = TestResources::new(Role::Leader, PeerGlobalIndex::new(0, 1, 2));
    let res = test_resources.get_broadcaster_resources();
    let mut encoded_data = encoded_chunks(3, res.authenticator());
    let mut state = SyncPayloadState::ready_for_committee(
        header_with_origin([0; 32]),
        QuorumCertificate::default(),
        2,
        encoded_data.take_committee_chunks(),
        encoded_data.take_network_chunks(),
        rs8_codec(),
    );
    assert_eq!(state.payload_type(), PayloadType::Committee);
    assert!(state.has_payload_data());
    assert!(state.is_reconstructed());
    assert!(state.get_owned_chunk().is_some());
    assert_eq!(
        state
            .get_owned_chunk()
            .as_ref()
            .unwrap()
            .data()
            .get_chunk_index(),
        2
    );
    assert_eq!(state.get_owned_chunk_index().unwrap(), 2);
    assert!(!state.committee_chunks().is_empty());
    assert!(!state.network_chunk_pieces().is_empty());
    assert!(state.payload_codec().is_some());
    assert!(state.chunk_codec().is_none());
}

#[tokio::test]
async fn test_state_for_network() {
    let mut state = SyncPayloadState::for_network(
        header_with_origin([0; 32]),
        QuorumCertificate::default(),
        rs8_codec(),
    );
    assert_eq!(state.payload_type(), PayloadType::Network);
    assert!(!state.has_payload_data());
    assert!(!state.is_reconstructed());
    assert!(state.get_owned_chunk().is_none());
    assert!(state.get_owned_chunk_index().is_none());
    assert!(state.committee_chunks().is_empty());
    assert!(state.network_chunk_pieces().is_empty());
    assert!(state.payload_codec().is_some());
    assert!(state.chunk_codec().is_some());

    let mut test_resources = TestResources::new(Role::Leader, PeerGlobalIndex::new(0, 1, 2));
    let res = test_resources.get_broadcaster_resources();
    let encoded_data = encoded_chunks(3, res.authenticator());
    let mut state = SyncPayloadState::ready_for_network(
        header_with_origin([0; 32]),
        QuorumCertificate::default(),
        encoded_data.network_chunks()[7]
            .clone()
            .decode(rs8_codec())
            .unwrap(),
        rs8_codec(),
    );
    assert_eq!(state.payload_type(), PayloadType::Network);
    assert!(state.has_payload_data());
    assert!(state.is_reconstructed());
    assert!(state.get_owned_chunk().is_some());
    assert_eq!(
        state
            .get_owned_chunk()
            .as_ref()
            .unwrap()
            .data()
            .get_chunk_index(),
        7
    );
    assert_eq!(state.get_owned_chunk_index().unwrap(), 7);
    assert!(state.committee_chunks().is_empty());
    assert!(state.network_chunk_pieces().is_empty());
    assert!(state.payload_codec().is_some());
    assert!(state.chunk_codec().is_some());
}

#[tokio::test]
async fn test_add_chunk_interface_committee_payload() {
    let mut state = SyncPayloadState::for_committee(
        header_with_origin([0; 32]),
        QuorumCertificate::default(),
        rs8_codec(),
    );
    let mut test_resources = TestResources::new(Role::Leader, PeerGlobalIndex::new(0, 1, 2));
    let res = test_resources.get_broadcaster_resources();
    let encoded_data = encoded_chunks(3, res.authenticator());
    let result = state.add_chunk(encoded_data.committee_chunks()[0].clone(), false);
    assert!(result.is_ok());
    assert!(state.has_chunk(0));
    assert!(!state.has_piece(0));
    assert!(state.get_owned_chunk_index().is_none());
    assert!(state.get_owned_chunk().is_none());
    assert_eq!(state.payload_codec().unwrap().feed_len(), 1);

    let result = state.add_chunk(encoded_data.committee_chunks()[2].clone(), true);
    assert!(result.is_ok());
    assert!(state.has_chunk(0));
    assert!(state.has_chunk(2));
    assert_eq!(state.get_received_chunks().len(), 2);
    assert_eq!(state.get_received_pieces().len(), 0);
    assert!(!state.has_piece(0));
    assert!(!state.has_piece(2));
    assert_eq!(state.get_owned_chunk_index().unwrap(), 2);
    assert!(state
        .get_owned_chunk()
        .unwrap()
        .data()
        .eq(encoded_data.committee_chunks()[2].data()));
    assert_eq!(state.payload_codec().unwrap().feed_len(), 2);

    // Adding a piece results in error
    let result = state.add_piece(encoded_data.network_chunks()[0].pieces()[2].clone());
    assert!(result.is_err())
}

#[tokio::test]
async fn test_add_chunk_interface_network_payload() {
    let mut state = SyncPayloadState::for_network(
        header_with_origin([0; 32]),
        QuorumCertificate::default(),
        rs8_codec(),
    );
    let mut test_resources = TestResources::new(Role::Leader, PeerGlobalIndex::new(0, 1, 2));
    let res = test_resources.get_broadcaster_resources();
    let encoded_data = encoded_chunks(3, res.authenticator());
    let result = state.add_chunk(
        encoded_data.network_chunks()[1]
            .clone()
            .decode(rs8_codec())
            .unwrap(),
        false,
    );
    assert!(result.is_ok());
    assert!(state.has_chunk(1));
    assert!(!state.has_piece(1));
    assert!(state.get_owned_chunk_index().is_none());
    assert!(state.get_owned_chunk().is_none());
    assert_eq!(state.chunk_codec().unwrap().feed_len(), 0);

    assert_eq!(state.payload_codec().unwrap().feed_len(), 1);

    let owned_chunk = encoded_data.network_chunks()[7]
        .clone()
        .decode(rs8_codec())
        .unwrap();
    let result = state.add_chunk(owned_chunk.clone(), true);
    assert!(result.is_ok());
    assert!(state.has_chunk(1));
    assert!(state.has_chunk(7));
    assert_eq!(state.get_received_chunks().len(), 2);
    assert!(!state.has_piece(1));
    assert!(!state.has_piece(7));
    assert!(state.get_received_pieces().is_empty());
    assert_eq!(state.get_owned_chunk_index().unwrap(), 7);
    assert!(state
        .get_owned_chunk()
        .unwrap()
        .data()
        .eq(owned_chunk.data()));
    assert_eq!(state.chunk_codec().unwrap().feed_len(), 0);
    assert_eq!(state.payload_codec().unwrap().feed_len(), 2);
}

#[tokio::test]
async fn test_add_piece_interface_network_payload() {
    let mut state = SyncPayloadState::for_network(
        header_with_origin([0; 32]),
        QuorumCertificate::default(),
        rs8_codec(),
    );
    let mut test_resources = TestResources::new(Role::Leader, PeerGlobalIndex::new(0, 1, 2));
    let res = test_resources.get_broadcaster_resources();
    let encoded_data = encoded_chunks(3, res.authenticator());
    let chunk_piece_2 = encoded_data.network_chunks()[1].pieces()[2].clone();
    let result = state.add_piece(chunk_piece_2);
    assert!(result.is_ok());
    assert!(!state.has_chunk(1));
    assert!(state.has_piece(2));
    assert!(state.get_owned_chunk_index().is_none());
    assert!(state.get_owned_chunk().is_none());
    assert_eq!(state.chunk_codec().unwrap().feed_len(), 1);
    assert_eq!(state.payload_codec().unwrap().feed_len(), 0);

    let chunk_piece_0 = encoded_data.network_chunks()[1].pieces()[0].clone();
    let result = state.add_piece(chunk_piece_0);
    assert!(result.is_ok());
    assert!(state.has_piece(2));
    assert!(state.has_piece(0));
    assert_eq!(state.chunk_codec().unwrap().feed_len(), 2);
    assert_eq!(state.payload_codec().unwrap().feed_len(), 0);
}

#[tokio::test]
async fn test_set_and_flags_for_network_payload() {
    let mut network_state = SyncPayloadState::for_network(
        header_with_origin([0; 32]),
        QuorumCertificate::default(),
        rs8_codec(),
    );

    assert!(!network_state.is_reconstructed());
    assert!(!network_state.failed());
    let mut test_resources = TestResources::new(Role::Leader, PeerGlobalIndex::new(0, 1, 2));
    let res = test_resources.get_broadcaster_resources();
    let mut encoded_data = encoded_chunks(3, res.authenticator());
    let owned_chunk = encoded_data.network_chunks()[7]
        .clone()
        .decode(rs8_codec())
        .unwrap();
    let result = network_state.add_chunk(owned_chunk.clone(), true);
    assert!(result.is_ok());
    assert!(network_state.has_payload_data());
    assert!(!network_state.is_reconstructed());
    assert!(!network_state.failed());

    // Set reconstructed flag
    network_state.set_reconstructed();
    assert!(network_state.is_reconstructed());
    assert!(!network_state.failed());

    // Set error flag
    network_state.set_error();
    assert!(network_state.is_reconstructed());
    assert!(network_state.failed());

    // for network payload type set reconstructed_data will fail
    assert!(network_state
        .set_reconstructed_data(
            0,
            encoded_data.take_committee_chunks(),
            encoded_data.take_network_chunks()
        )
        .is_err());
}

#[tokio::test]
async fn test_set_and_flags_for_committee_payload() {
    let mut committee_state = SyncPayloadState::for_committee(
        header_with_origin([0; 32]),
        QuorumCertificate::default(),
        rs8_codec(),
    );
    let mut test_resources = TestResources::new(Role::Leader, PeerGlobalIndex::new(0, 1, 2));
    let res = test_resources.get_broadcaster_resources();
    let mut encoded_data = encoded_chunks(3, res.authenticator());
    let result = committee_state.add_chunk(encoded_data.committee_chunks()[0].clone(), true);
    assert!(result.is_ok());
    assert!(!committee_state.failed());
    assert!(!committee_state.has_payload_data());
    assert!(!committee_state.is_reconstructed());

    // empty network chunks when network settings exists
    assert!(committee_state
        .set_reconstructed_data(0, encoded_data.committee_chunks().clone(), vec![])
        .is_ok());

    assert!(!committee_state.failed());
    assert!(!committee_state.has_payload_data());
    assert!(!committee_state.is_reconstructed());

    assert!(committee_state
        .set_reconstructed_data(
            0,
            encoded_data.take_committee_chunks(),
            encoded_data.take_network_chunks(),
        )
        .is_ok());

    assert!(!committee_state.failed());
    assert!(committee_state.has_payload_data());
    assert!(committee_state.is_reconstructed());

    committee_state.set_error();
    assert!(committee_state.failed());
    assert!(committee_state.has_payload_data());
    assert!(committee_state.is_reconstructed());
}

#[tokio::test]
async fn test_flags_for_committee_no_network_peers() {
    let codec = SupraDeliveryCodec::new(Rs8Settings::new(3, 2), None);
    let mut committee_state = SyncPayloadState::for_committee(
        header_with_origin([0; 32]),
        QuorumCertificate::default(),
        codec,
    );
    let mut test_resources = TestResources::new(Role::Leader, PeerGlobalIndex::new(0, 1, 2));
    let res = test_resources.get_broadcaster_resources();
    let mut encoded_data = encoded_chunks(3, res.authenticator());
    let result = committee_state.add_chunk(encoded_data.committee_chunks()[0].clone(), true);
    assert!(result.is_ok());
    assert!(!committee_state.failed());
    assert!(!committee_state.has_payload_data());
    assert!(!committee_state.is_reconstructed());

    assert!(committee_state
        .set_reconstructed_data(0, encoded_data.take_committee_chunks(), vec![])
        .is_ok());

    assert!(!committee_state.failed());
    assert!(committee_state.has_payload_data());
    assert!(committee_state.is_reconstructed());
}

#[test]
fn test_payload_data_settings() {
    let mut committee_payload_state = SyncPayloadState::for_committee(
        header_with_origin([0; 32]),
        QuorumCertificate::default(),
        rs8_codec(),
    );
    let _ = committee_payload_state
        .add_chunk(ChunkData::<SupraDeliveryErasureRs8Schema>::default(), false);
    assert_eq!(
        committee_payload_state.payload_codec().unwrap().feed_len(),
        1
    );
    {
        let decoder =
            <SyncPayloadState<_> as PayloadDataSettings<_>>::decoder(&mut committee_payload_state);
        assert_eq!(decoder.feed_len(), 1);
    }
    let settings =
        <SyncPayloadState<_> as PayloadDataSettings<_>>::settings(&committee_payload_state);
    assert_eq!(
        settings,
        committee_payload_state
            .payload_codec()
            .unwrap()
            .committee_settings()
    );

    let mut network_payload_state = SyncPayloadState::for_network(
        header_with_origin([0; 32]),
        QuorumCertificate::default(),
        rs8_codec(),
    );
    let _ = network_payload_state
        .add_chunk(ChunkData::<SupraDeliveryErasureRs8Schema>::default(), false);
    assert_eq!(network_payload_state.payload_codec().unwrap().feed_len(), 1);
    {
        let decoder =
            <SyncPayloadState<_> as PayloadDataSettings<_>>::decoder(&mut network_payload_state);
        assert_eq!(decoder.feed_len(), 1);
    }
    let settings =
        <SyncPayloadState<_> as PayloadDataSettings<_>>::settings(&network_payload_state);
    assert_eq!(
        settings,
        network_payload_state
            .payload_codec()
            .unwrap()
            .network_settings()
            .unwrap()
    )
}

#[test]
fn test_network_data_settings() {
    let mut state = SyncPayloadState::for_network(
        header_with_origin([0; 32]),
        QuorumCertificate::default(),
        rs8_codec(),
    );
    let _ = state.add_piece(ChunkData::<SupraDeliveryErasureRs8Schema>::default());
    assert_eq!(state.chunk_codec().unwrap().feed_len(), 1);
    {
        let decoder = <SyncPayloadState<_> as NetworkChunkDataSettings<_>>::decoder(&mut state);
        assert_eq!(decoder.feed_len(), 1);
    }
    let settings = <SyncPayloadState<_> as NetworkChunkDataSettings<_>>::settings(&state);
    assert_eq!(settings, state.chunk_codec().unwrap().committee_settings())
}

#[test]
fn sync_payload_committee_state_timestamp_works() {
    let test_struct = SyncPayloadState::for_committee(
        Header::default(),
        QuorumCertificate::default(),
        rs8_codec(),
    );
    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}

#[test]
fn sync_payload_network_state_timestamp_works() {
    let test_struct =
        SyncPayloadState::for_network(Header::default(), QuorumCertificate::default(), rs8_codec());
    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}

#[test]
fn sync_payload_ready_for_committee_state_timestamp_works() {
    let test_struct = SyncPayloadState::<SupraDeliveryErasureRs8Schema>::ready_for_committee(
        Header::default(),
        QuorumCertificate::default(),
        1,
        vec![ChunkData::new(CommittedChunk::default())],
        vec![NetworkChunk::default()],
        rs8_codec(),
    );
    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}

#[test]
fn sync_payload_ready_for_network_state_timestamp_works() {
    let test_struct = SyncPayloadState::<SupraDeliveryErasureRs8Schema>::ready_for_network(
        Header::default(),
        QuorumCertificate::default(),
        ChunkData::default(),
        rs8_codec(),
    );
    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}
