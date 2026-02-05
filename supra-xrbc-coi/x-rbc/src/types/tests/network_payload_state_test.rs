use crate::tasks::codec::{EncodeResultIfc, SupraDeliveryCodec, SupraDeliveryErasureCodec};
use crate::types::messages::chunk::ChunkData;
use crate::types::payload_state::network::NetworkPayloadState;
use crate::types::payload_state::{NetworkChunkDataSettings, PayloadDataSettings, PayloadFlags};
use crate::types::tests::header_with_origin;
use crate::types::tests::unit_test_message::give_test_authenticator;
use crate::SupraDeliveryErasureRs16Schema;
use erasure::codecs::rs16::Rs16Settings;
use erasure::utils::codec_trait::Setting;
use metrics::TimeStampTrait;
use std::time::Duration;

pub fn get_new_network_test_payload_state() -> NetworkPayloadState<SupraDeliveryErasureRs16Schema> {
    let config: SupraDeliveryCodec<SupraDeliveryErasureRs16Schema> =
        SupraDeliveryCodec::new(Rs16Settings::new(3, 2), Some(Rs16Settings::new(7, 3)));
    NetworkPayloadState::new(header_with_origin([0; 32]), config)
}

#[tokio::test]
async fn test_network_payload_state() {
    let payload_state = get_new_network_test_payload_state();

    assert!(payload_state.reconstructed_payload().is_none());
    assert!(!payload_state.is_reconstructed());
    assert!(!payload_state.has_payload_data());
    assert!(!payload_state.failed());
}

#[test]
fn test_network_payload_state_has_chunk() {
    let mut state = get_new_network_test_payload_state();
    let (_, authenticator) = give_test_authenticator(1);
    let random_payload = vec![2; 10000];
    let result = state
        .codec()
        .encode(random_payload, &authenticator)
        .expect("Successful encode");
    let network_chunks = result.network_chunks();

    state
        .add_chunk(
            network_chunks[1]
                .clone()
                .decode(state.codec().clone())
                .unwrap(),
            false,
        )
        .expect("Chunk successfully added");
    assert_eq!(state.codec().feed_len(), 1);
    assert!(state.has_chunk(1));
    assert!(!state.has_chunk(0));

    // Add second chunk
    state
        .add_chunk(
            network_chunks[3]
                .clone()
                .decode(state.codec().clone())
                .unwrap(),
            false,
        )
        .expect("Chunk successfully added");
    assert_eq!(state.codec().feed_len(), 2);
    assert!(state.has_chunk(1));
    assert!(state.has_chunk(3));
}

#[test]
fn test_network_payload_state_has_piece() {
    let mut state = get_new_network_test_payload_state();
    let (_, authenticator) = give_test_authenticator(1);
    let random_payload = vec![2; 10000];
    let result = state
        .codec()
        .encode(random_payload, &authenticator)
        .expect("Successful encode");
    let network_chunks = result.network_chunks();

    state
        .add_piece(network_chunks[1].pieces()[0].clone())
        .expect("Chunk successfully added");
    assert_eq!(state.share_codec().feed_len(), 1);
    assert!(state.has_piece(0));
    assert!(!state.has_piece(3));

    // Add second chunk
    state
        .add_piece(network_chunks[1].pieces()[3].clone())
        .expect("Chunk successfully added");
    assert_eq!(state.share_codec().feed_len(), 2);
    assert!(state.has_piece(0));
    assert!(state.has_piece(3));
}

#[test]
fn test_payload_api() {
    let mut state = get_new_network_test_payload_state();
    assert!(state.reconstructed_payload().is_none());
    assert!(!state.is_reconstructed());
    assert!(!state.has_payload_data());

    state.set_reconstructed_payload(Some(vec![5; 1000]));
    assert!(state.reconstructed_payload().is_some());
    assert!(state.is_reconstructed());
    assert!(state.has_payload_data());
}

#[test]
fn test_payload_data_settings() {
    let mut state = get_new_network_test_payload_state();
    let _ = state.codec_mut().feed(
        ChunkData::<SupraDeliveryErasureRs16Schema>::default()
            .data_mut()
            .take_chunk(),
    );
    assert_eq!(state.codec().feed_len(), 1);
    {
        let decoder = <NetworkPayloadState<_> as PayloadDataSettings<_>>::decoder(&mut state);
        assert_eq!(decoder.feed_len(), 1);
    }
    let settings = <NetworkPayloadState<_> as PayloadDataSettings<_>>::settings(&state);
    assert_eq!(settings, state.codec().network_settings().unwrap())
}

#[test]
fn test_network_data_settings() {
    let mut state = get_new_network_test_payload_state();
    let _ = state.share_codec_mut().feed(
        ChunkData::<SupraDeliveryErasureRs16Schema>::default()
            .data_mut()
            .take_chunk(),
    );
    assert_eq!(state.share_codec().feed_len(), 1);
    {
        let decoder = <NetworkPayloadState<_> as NetworkChunkDataSettings<_>>::decoder(&mut state);
        assert_eq!(decoder.feed_len(), 1);
    }
    let settings = <NetworkPayloadState<_> as NetworkChunkDataSettings<_>>::settings(&state);
    assert_eq!(settings, state.codec().committee_settings())
}

#[test]
fn network_payload_state_timestamp_works() {
    let test_struct = get_new_network_test_payload_state();
    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}
