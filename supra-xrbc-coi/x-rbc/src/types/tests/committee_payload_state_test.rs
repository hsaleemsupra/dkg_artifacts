use crate::tasks::codec::{EncodeResultIfc, SupraDeliveryCodec, SupraDeliveryErasureCodec};
use crate::types::helpers::verifier_visitor::verify_value_data_tests::{encoded_chunks, rs8_codec};
use crate::types::messages::chunk::{ChunkData, NetworkChunk};
use crate::types::payload_state::committee::{
    CommitteePayloadFlags, CommitteePayloadState, ReconstructedData,
};
use crate::types::payload_state::{PayloadDataSettings, PayloadFlags};
use crate::types::tests::header_with_origin;
use crate::types::tests::unit_test_message::give_test_authenticator;
use crate::{SupraDeliveryErasureRs16Schema, SupraDeliveryErasureRs8Schema};
use crypto::PartialShare;
use erasure::codecs::rs16::Rs16Settings;
use erasure::utils::codec_trait::Setting;
use metrics::TimeStampTrait;
use primitives::types::QuorumCertificate;
use std::time::Duration;

pub fn get_new_committee_test_payload_state(
) -> CommitteePayloadState<SupraDeliveryErasureRs16Schema> {
    let codec: SupraDeliveryCodec<SupraDeliveryErasureRs16Schema> =
        SupraDeliveryCodec::new(Rs16Settings::new(9, 4), Some(Rs16Settings::new(9, 4)));
    CommitteePayloadState::new(header_with_origin([5; 32]), codec)
}

pub fn initialize_committee_test_payload_state(
    payload_state: &mut CommitteePayloadState<SupraDeliveryErasureRs16Schema>,
) {
    payload_state.set_reconstructed_data(ReconstructedData::new(
        vec![1, 2, 3],
        vec![ChunkData::default(); payload_state.codec().total_committee_chunks()],
        vec![NetworkChunk::default(); payload_state.codec().total_network_chunks()],
    ));
}

pub fn initialize_committer_payload_state_error(
    payload_state: &mut CommitteePayloadState<SupraDeliveryErasureRs16Schema>,
) {
    payload_state.set_error();
}

#[test]
fn test_reconstructed_data() {
    let r_data_from_payload =
        ReconstructedData::<SupraDeliveryErasureRs16Schema>::from_payload(vec![10; 25]);
    assert!(r_data_from_payload.committee_chunks().is_empty());
    assert!(r_data_from_payload.network_chunks().is_empty());
    assert!(!r_data_from_payload.payload().is_empty());

    let random_payload = vec![2; 10000];
    let (_, authenticator) = give_test_authenticator(1);
    let mut result = rs8_codec()
        .encode(random_payload.clone(), &authenticator)
        .expect("Successful encode");
    let r_data_from_payload = ReconstructedData::<SupraDeliveryErasureRs8Schema>::new(
        random_payload,
        result.take_committee_chunks(),
        result.take_network_chunks(),
    );
    assert!(!r_data_from_payload.committee_chunks().is_empty());
    assert!(!r_data_from_payload.network_chunks().is_empty());
    assert!(!r_data_from_payload.payload().is_empty());
}

#[test]
fn test_committee_payload_state() {
    let mut payload_state = get_new_committee_test_payload_state();

    assert!(!payload_state.is_certified());
    assert!(!payload_state.is_certified());
    assert!(!payload_state.failed());

    assert_eq!(payload_state.all_chunks_len(), 0);
    assert!(payload_state.reconstructed_payload().is_none());
    assert!(!payload_state.is_reconstructed());
    assert!(!payload_state.has_payload_data());
    assert!(payload_state.committee_chunks().is_none());
    assert!(payload_state.network_chunks().is_none());

    initialize_committee_test_payload_state(&mut payload_state);

    assert_eq!(
        payload_state.committee_chunks_len(),
        payload_state.codec().committee_settings().total_shards()
    );
    assert_eq!(
        payload_state.network_chunks_len(),
        payload_state
            .codec()
            .network_settings()
            .map(|ns| ns.total_shards())
            .unwrap_or(0)
    );

    assert!(payload_state.reconstructed_payload().is_some());
    assert!(payload_state.committee_chunks().is_some());
    assert!(payload_state.is_reconstructed());
    assert!(payload_state.has_payload_data());

    assert!(!payload_state.failed());
    assert!(!payload_state.is_certified());

    initialize_committer_payload_state_error(&mut payload_state);
    assert!(payload_state.failed());

    // when chunk data is missing but payload and header are available
    let _ = payload_state.take_committee_chunks();
    assert!(!payload_state.is_reconstructed());
    assert!(payload_state.has_payload_data());

    let _ = payload_state.take_network_chunks();
    assert!(!payload_state.is_reconstructed());
    assert!(payload_state.has_payload_data());

    let _ = payload_state.take_reconstructed_payload();
    assert!(!payload_state.is_reconstructed());
    assert!(!payload_state.has_payload_data());
}

#[test]
fn test_committee_payload_state_add_chunk() {
    let mut state = get_new_committee_test_payload_state();
    let (_, authenticator) = give_test_authenticator(1);
    let random_payload = vec![2; 10000];
    let result = state
        .codec()
        .encode(random_payload, &authenticator)
        .expect("Successful encode");
    let committee_chunks = result.committee_chunks();

    state
        .add_chunk(committee_chunks[0].clone(), false)
        .expect("Chunk successfully added");
    assert!(!state.has_owned_chunk());
    assert_eq!(state.codec().feed_len(), 1);
    assert!(state.has_chunk(0));
    assert!(!state.has_chunk(1));

    // Add second chunk
    state
        .add_chunk(committee_chunks[3].clone(), true)
        .expect("Chunk successfully added");
    assert!(state.has_owned_chunk());
    assert_eq!(state.codec().feed_len(), 2);
    assert!(state.has_chunk(0));
    assert!(state.has_chunk(3));

    // For the cases when chunk is not required but it is received and only index is stored to
    // avoid duplicates and not to send ready messages when certificate is received
    state.store_chunk_index(4);
    assert!(state.has_chunk(4));
}

#[test]
fn test_committee_payload_state_vote_api() {
    let mut state = get_new_committee_test_payload_state();
    let share = PartialShare::new(1, [2; 96]);
    state.add_vote(share);
    assert!(!state.has_vote(0));
    assert!(state.has_vote(1));
    assert!(state.get_vote(1).is_some());
    assert!(state.peers_with_all_chunks().contains(&1));
    assert_eq!(state.votes_len(), 1);

    // add second vote
    let share = PartialShare::new(2, [3; 96]);
    state.add_vote(share);
    assert!(state.has_vote(1));
    assert!(state.has_vote(2));
    assert!(state.get_vote(1).is_some());
    assert!(state.get_vote(2).is_some());
    assert!(state.peers_with_all_chunks().contains(&1));
    assert!(state.peers_with_all_chunks().contains(&2));
    assert_eq!(state.votes_len(), 2);

    // take votes
    assert_eq!(state.votes_len(), 2);
    let votes = state.take_votes();
    assert_eq!(votes.len(), 2);
    assert_eq!(state.votes_len(), 2);
    assert!(state.peers_with_all_chunks().contains(&1));
    assert!(state.peers_with_all_chunks().contains(&2));
    assert!(state.get_vote(1).is_none());
    assert!(state.get_vote(2).is_none());
}

#[test]
fn test_certificates() {
    let mut state_with_certificate = get_new_committee_test_payload_state();
    state_with_certificate.set_certificate(QuorumCertificate::default());

    assert!(state_with_certificate.is_certified());
    let _ = state_with_certificate.take_certificate();
    assert!(!state_with_certificate.is_certified());
}

#[test]
fn test_owned_data() {
    let mut state = get_new_committee_test_payload_state();
    assert!(!state.has_owned_chunk());
    state.set_owned_chunk(Some(ChunkData::default()));
    assert!(state.has_owned_chunk());
    let chunk = state.get_owned_chunk();
    assert!(chunk.is_some());
}

#[test]
fn test_payload_data_settings() {
    let mut state = get_new_committee_test_payload_state();
    let _ = state.codec_mut().feed(
        ChunkData::<SupraDeliveryErasureRs16Schema>::default()
            .data_mut()
            .take_chunk(),
    );
    assert_eq!(state.codec().feed_len(), 1);
    {
        let decoder = state.decoder();
        assert_eq!(decoder.feed_len(), 1);
    }
    let settings = state.settings();
    assert_eq!(settings, state.codec().committee_settings())
}

#[test]
fn committee_payload_state_timestamp_works() {
    let test_struct = get_new_committee_test_payload_state();
    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
}
