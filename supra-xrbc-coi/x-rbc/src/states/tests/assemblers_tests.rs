use crate::states::handlers::{
    GenericAssembler, NetworkChunkAssembler, PayloadAssembler, ReconstructedDataAssembler,
};
use crate::states::tests::ContextProvider;
use crate::tasks::codec::{EncodeResultIfc, SupraDeliveryErasureCodec};
use crate::tasks::errors::RBCError;
use crate::types::context::FSMContextOwner;
use crate::types::messages::chunk::ChunkData;
use crate::types::payload_state::committee::ReconstructedData;
use crate::types::payload_state::PayloadFlags;
use crate::types::tests::header_with_origin;
use crate::SupraDeliveryErasureRs8Schema;
use erasure::codecs::rs8::Rs8Chunk;
use erasure::utils::codec_trait::{Chunk, Setting};
use primitives::types::HeaderIfc;
use primitives::PeerGlobalIndex;
use rand::seq::SliceRandom;
use rand::thread_rng;
use vec_commitment::committed_chunk::{CommitmentMeta, CommittedChunk};

#[tokio::test]
async fn test_try_reconstruct_share() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let mut context = context_provider
        .network_context_with_header::<SupraDeliveryErasureRs8Schema>(
            encoded_result.header().clone(),
            peer_index,
        );
    let mut nt_chunk_assembler = NetworkChunkAssembler(&mut context);
    let (_header, _committee_chunks, mut network_chunks) = encoded_result.split();
    assert!(!nt_chunk_assembler.has_required_data());

    let result = nt_chunk_assembler.try_assemble();
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    assert_eq!(nt_chunk_assembler.decoder().feed_len(), 0);
    let network_chunk_1 = network_chunks.remove(1);
    let (meta, pieces) = network_chunk_1.split();
    let pieces_len = pieces.len();
    // no header no meta, no chunk, no failure in reconstruction
    for piece in pieces {
        assert!(nt_chunk_assembler
            .payload_state_mut()
            .add_piece(piece)
            .is_ok());
        assert!(!nt_chunk_assembler.has_required_data());
        let result = nt_chunk_assembler.try_assemble();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
    assert_eq!(nt_chunk_assembler.decoder().feed_len(), pieces_len);

    // Header is available but not own chunk meta-data
    let result = nt_chunk_assembler.try_assemble();
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    // Chunk meta is also available, then chunk will be reconstructed.
    nt_chunk_assembler
        .payload_state_mut()
        .set_owned_chunk_meta(meta);
    assert!(nt_chunk_assembler.has_required_data());
    let result = nt_chunk_assembler.try_assemble();
    assert!(result.is_ok());
    assert!(result.as_ref().unwrap().is_some());
    assert_eq!(nt_chunk_assembler.decoder().feed_len(), 0);
    let chunk_data = result.unwrap().unwrap();
    assert_eq!(chunk_data.data().get_chunk_index(), 1);
    assert_eq!(chunk_data.data().get_commitment_index(), 6);
    // Except reconstruction nothing is modified by assembler
    assert!(nt_chunk_assembler.take_response().is_none());
    assert!(!nt_chunk_assembler.payload_state().has_chunk(1));
}

#[tokio::test]
async fn test_try_reconstruct_share_invalid_meta() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let mut context = context_provider
        .network_context_with_header::<SupraDeliveryErasureRs8Schema>(
            encoded_result.header().clone(),
            peer_index,
        );
    let mut nt_chunk_assembler = NetworkChunkAssembler(&mut context);
    let (_header, _committee_chunks, mut network_chunks) = encoded_result.split();
    assert!(!nt_chunk_assembler.has_required_data());
    assert_eq!(nt_chunk_assembler.decoder().feed_len(), 0);

    assert!(nt_chunk_assembler.try_assemble().is_ok());
    assert_eq!(nt_chunk_assembler.decoder().feed_len(), 0);
    let network_chunk_1 = network_chunks.remove(1);
    let (_meta, pieces) = network_chunk_1.split();
    let pieces_len = pieces.len();
    // no header no meta, no chunk, no failure in reconstruction
    for piece in pieces {
        assert!(nt_chunk_assembler
            .payload_state_mut()
            .add_piece(piece)
            .is_ok());
    }
    assert_eq!(nt_chunk_assembler.decoder().feed_len(), pieces_len);

    // Header is available but not own chunk data
    // Chunk meta is also available, then chunk will be reconstructed.
    nt_chunk_assembler
        .payload_state_mut()
        .set_owned_chunk_meta(CommitmentMeta::default());
    let result = nt_chunk_assembler.try_assemble();
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        RBCError::MessageProcessingError(_)
    ));
    assert_eq!(nt_chunk_assembler.decoder().feed_len(), 0);

    // No response
    // nothing is added to payload codec
    assert!(nt_chunk_assembler.take_response().is_none());
    assert!(!nt_chunk_assembler.payload_state().has_chunk(1));
    assert_eq!(nt_chunk_assembler.payload_state().codec().feed_len(), 0);
}

#[tokio::test]
async fn test_try_reconstruct_share_invalid_pieces() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let mut context = context_provider
        .network_context_with_header::<SupraDeliveryErasureRs8Schema>(
            encoded_result.header().clone(),
            peer_index,
        );
    let mut nt_chunk_assembler = NetworkChunkAssembler(&mut context);
    let (_header, _committee_chunks, mut network_chunks) = encoded_result.split();
    assert!(!nt_chunk_assembler.has_required_data());
    assert_eq!(nt_chunk_assembler.decoder().feed_len(), 0);

    assert!(nt_chunk_assembler.try_assemble().is_ok());
    let network_chunk_1 = network_chunks.remove(1);
    let (meta, pieces) = network_chunk_1.split();
    let pieces_len = pieces.len();
    // no header no meta, no chunk, no failure in reconstruction
    for mut piece in pieces {
        let _ = piece.data_mut().take_chunk();
        assert!(nt_chunk_assembler
            .payload_state_mut()
            .add_piece(piece)
            .is_ok());
    }
    assert_eq!(nt_chunk_assembler.decoder().feed_len(), pieces_len);

    // Header is available but not own chunk data
    // Chunk meta is also available, then chunk will be reconstructed.
    nt_chunk_assembler
        .payload_state_mut()
        .set_owned_chunk_meta(meta);
    assert!(nt_chunk_assembler.has_required_data());

    assert!(nt_chunk_assembler.try_assemble().is_err());
    assert_eq!(nt_chunk_assembler.decoder().feed_len(), 0);

    // nothing is added to payload codec
    assert!(!nt_chunk_assembler.payload_state().has_chunk(1));
    assert_eq!(nt_chunk_assembler.payload_state().codec().feed_len(), 0);

    // No response
    assert!(nt_chunk_assembler.take_response().is_none());
}

#[tokio::test]
async fn test_try_reconstruct_payload() {
    let _ = env_logger::try_init();
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let mut context = context_provider
        .network_context_with_header::<SupraDeliveryErasureRs8Schema>(
            encoded_result.header().clone(),
            peer_index,
        );
    let mut payload_assembler = PayloadAssembler(&mut context);
    let (_header, _committee_chunks, mut network_chunks) = encoded_result.split();
    assert_eq!(payload_assembler.decoder().feed_len(), 0);
    assert!(!payload_assembler.payload_state().is_reconstructed());

    let result = payload_assembler.try_assemble();
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    assert!(!payload_assembler.payload_state().is_reconstructed());

    network_chunks.shuffle(&mut thread_rng());
    for nt_chunk in network_chunks {
        let nt_assembled_chunk = nt_chunk
            .decode(payload_assembler.payload_state().share_codec().clone())
            .unwrap();
        assert!(payload_assembler
            .payload_state_mut()
            .add_chunk(nt_assembled_chunk, false)
            .is_ok());
        let result = payload_assembler.try_assemble();
        assert!(payload_assembler.take_response().is_none());
        if let Ok(Some((data, encoded_result))) = result {
            assert!(!data.is_empty());
            assert!(!encoded_result.committee_chunks().is_empty());
            assert!(!encoded_result.network_chunks().is_empty());
            break;
        }
    }

    // payload state is not updated with reconstructed data
    assert!(!payload_assembler.payload_state().is_reconstructed());
}

#[tokio::test]
async fn test_try_reconstruct_invalid_reconstruction() {
    let _ = env_logger::try_init();
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let mut context = context_provider
        .network_context_with_header::<SupraDeliveryErasureRs8Schema>(
            encoded_result.header().clone(),
            peer_index,
        );
    let mut payload_assembler = PayloadAssembler(&mut context);
    let (_header, _committee_chunks, mut network_chunks) = encoded_result.split();
    assert!(!payload_assembler.payload_state().is_reconstructed());

    let result = payload_assembler.try_assemble();
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    network_chunks.shuffle(&mut thread_rng());
    let threshold = payload_assembler
        .payload_state()
        .codec()
        .network_settings()
        .unwrap()
        .data_shards();
    for i in 0..threshold {
        let nt_assembled_chunk =
            ChunkData::<SupraDeliveryErasureRs8Schema>::new(CommittedChunk::<Rs8Chunk>::new(
                i,
                vec![],
                Rs8Chunk::new(i, vec![], 5),
            ));
        assert!(payload_assembler
            .payload_state_mut()
            .add_chunk(nt_assembled_chunk, false)
            .is_ok());
        let result = payload_assembler.try_assemble();
        if let Err(_) = result {
            return;
        }
    }
    assert!(
        false,
        "Error is expected at some point of the time while trying to assemble the data"
    )
}

#[tokio::test]
async fn test_try_reconstruct_payload_invalid_commitment() {
    let _ = env_logger::try_init();
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let mut context = context_provider
        .network_context_with_header::<SupraDeliveryErasureRs8Schema>(
            header_with_origin(*encoded_result.header().origin()),
            peer_index,
        );
    let mut payload_assembler = PayloadAssembler(&mut context);
    let (_header, _committee_chunks, mut network_chunks) = encoded_result.split();

    let result = payload_assembler.try_assemble();
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());

    network_chunks.shuffle(&mut thread_rng());
    let threshold = payload_assembler
        .payload_state()
        .codec()
        .network_settings()
        .unwrap()
        .data_shards();
    for _ in 0..threshold {
        let nt_chunk = network_chunks.pop().unwrap();
        let nt_assembled_chunk = nt_chunk
            .decode(payload_assembler.payload_state().share_codec().clone())
            .unwrap();
        assert!(payload_assembler
            .payload_state_mut()
            .add_chunk(nt_assembled_chunk, false)
            .is_ok());
        let result = payload_assembler.try_assemble();
        if let Err(RBCError::InvalidDeliverable(origin)) = result {
            assert_eq!(origin, *payload_assembler.payload_state().origin());
            return;
        }
    }
    assert!(
        false,
        "Invalid Deliverable error is expected at some point of the time while trying to assemble the data"
    )
}

#[tokio::test]
async fn test_try_reconstruct_data_assembler_from_payload() {
    let _ = env_logger::try_init();
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, payload) =
        context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let mut context = context_provider
        .committee_context_with_header::<SupraDeliveryErasureRs8Schema>(
            encoded_result.header().clone(),
            peer_index,
        );
    let mut payload_assembler = ReconstructedDataAssembler(&mut context);
    assert_eq!(payload_assembler.decoder().feed_len(), 0);
    assert!(!payload_assembler.payload_state().is_reconstructed());

    let result = payload_assembler.try_assemble();
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    assert!(!payload_assembler.payload_state().is_reconstructed());

    let reconstructed_data = ReconstructedData::from_payload(payload.clone());
    payload_assembler
        .payload_state_mut()
        .set_reconstructed_data(reconstructed_data);
    assert!(!payload_assembler.payload_state().is_reconstructed());
    assert!(payload_assembler.payload_state().has_payload_data());

    let result = payload_assembler.try_assemble();
    assert!(result.is_ok());
    assert!(result.unwrap().is_some());
    assert!(!payload_assembler.payload_state().has_payload_data());
    assert!(!payload_assembler.payload_state().is_reconstructed());
}

#[tokio::test]
async fn test_try_reconstruct_data_assembler_from_payload_with_invalid_commitment() {
    let _ = env_logger::try_init();
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, payload) =
        context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let mut context = context_provider
        .committee_context_with_header::<SupraDeliveryErasureRs8Schema>(
            header_with_origin(*encoded_result.header().origin()),
            peer_index,
        );
    let mut payload_assembler = ReconstructedDataAssembler(&mut context);
    assert_eq!(payload_assembler.decoder().feed_len(), 0);
    assert!(!payload_assembler.payload_state().is_reconstructed());

    let result = payload_assembler.try_assemble();
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    assert!(!payload_assembler.payload_state().is_reconstructed());

    let reconstructed_data = ReconstructedData::from_payload(payload.clone());
    payload_assembler
        .payload_state_mut()
        .set_reconstructed_data(reconstructed_data);
    assert!(!payload_assembler.payload_state().is_reconstructed());
    assert!(payload_assembler.payload_state().has_payload_data());

    let result = payload_assembler.try_assemble();
    assert!(result.is_err());
}
