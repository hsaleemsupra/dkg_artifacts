use crate::states::handlers::NetworkMessageHandler;
use crate::states::tests::{can_transaction_happen, ContextProvider};
use crate::states::{DoneNetworkFSM, WaitingForShare};
use crate::tasks::codec::{EncodeResultIfc, SupraDeliveryErasureCodec};
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::messages::chunk::ChunkData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    EchoShareData, RBCNetworkMessage, ResponseTypeIfc, ShareData, ValueData,
};
use crate::types::payload_state::{NetworkChunkDataSettings, PayloadDataSettings, PayloadFlags};
use crate::types::tests::header_with_origin;
use crate::{FeedbackMessage, SupraDeliveryErasureRs8Schema};
use erasure::codecs::rs8::Rs8Chunk;
use erasure::utils::codec_trait::{Chunk, Setting};
use primitives::types::HeaderIfc;
use primitives::PeerGlobalIndex;
use rand::seq::SliceRandom;
use rand::thread_rng;
use sfsm::{ReceiveMessage, ReturnMessage, State, Transition};
use vec_commitment::committed_chunk::{CommitmentMeta, CommittedChunk};

#[tokio::test]
async fn test_handle_share() {
    let peer_index = PeerGlobalIndex::new(0, 1, 0);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.network_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfs_010 = WaitingForShare::new(context);
    let header = wfs_010.payload_state().get_header();

    let meta = CommitmentMeta::new(1, Vec::new(), [0; 32]);

    let share_data = ShareData::new(
        [0; 32],
        ValueData::new(
            header,
            ChunkData::new(CommittedChunk::new(1, vec![], Rs8Chunk::new(2, vec![], 0))),
        ),
        meta.clone(),
    );
    assert!(wfs_010.response().is_none());
    assert!(!wfs_010.payload_state().has_piece(1));
    assert!(!wfs_010.payload_state().has_piece(2));
    assert_eq!(wfs_010.payload_state().codec().feed_len(), 0);
    assert!(wfs_010.payload_state().owned_chunk_meta().is_none());
    wfs_010.handle_share(share_data);
    assert!(wfs_010.response().is_none());
    assert!(!wfs_010.payload_state().has_piece(1));
    assert!(wfs_010.payload_state().has_piece(2));
    assert_eq!(wfs_010.payload_state().share_codec().feed_len(), 1);
    assert_eq!(wfs_010.payload_state().codec().feed_len(), 0);
    assert!(wfs_010.payload_state().owned_chunk_meta().is_some());
    let set_meta = wfs_010.payload_state().owned_chunk_meta().as_ref().unwrap();
    assert!(meta.eq(set_meta));
}

#[tokio::test]
async fn test_handle_echo_share() {
    let peer_index = PeerGlobalIndex::new(0, 1, 0);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.network_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfs_010 = WaitingForShare::new(context);
    let header = wfs_010.payload_state().get_header();

    let value = ValueData::new(
        header,
        ChunkData::new(CommittedChunk::new(1, vec![], Rs8Chunk::new(2, vec![], 0))),
    );
    let echo_share = EchoShareData::new([0; 32], value);

    assert!(wfs_010.response().is_none());
    assert!(!wfs_010.payload_state().has_chunk(1));
    assert!(!wfs_010.payload_state().has_chunk(2));
    assert_eq!(wfs_010.payload_state().codec().feed_len(), 0);
    wfs_010.handle_echo_share(echo_share);
    assert!(wfs_010.response().is_none());
    assert!(!wfs_010.payload_state().has_chunk(1));
    assert!(wfs_010.payload_state().has_chunk(2));
    assert_eq!(wfs_010.payload_state().codec().feed_len(), 1);
}

#[tokio::test]
async fn test_owned_chunk_index() {
    let leader_index = PeerGlobalIndex::new(0, 1, 2);
    let mut context_provider = ContextProvider::new(leader_index);

    // Owned network chunk commitment index is 11, network chunk index is 6
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let context = context_provider.network_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let wfs_001 = WaitingForShare::new(context);
    assert_eq!(wfs_001.owned_chunk_data_index(), 6);

    // Owned network chunk commitment index is 9, network chunk index is 4
    let peer_index = PeerGlobalIndex::new(0, 2, 4);
    let context = context_provider.network_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let wfs_024 = WaitingForShare::new(context);
    assert_eq!(wfs_024.owned_chunk_data_index(), 4);
}

#[tokio::test]
async fn test_try_reconstruct_share() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let context = context_provider.network_context_with_header::<SupraDeliveryErasureRs8Schema>(
        encoded_result.header().clone(),
        peer_index,
    );
    let mut wfs_011 = WaitingForShare::new(context);
    let (_header, _committee_chunks, mut network_chunks) = encoded_result.split();
    assert!(wfs_011.payload_state().owned_chunk_meta().is_none());
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);

    assert!(wfs_011.try_reconstruct_share().is_ok());
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);
    let network_chunk_1 = network_chunks.remove(1);
    let (meta, pieces) = network_chunk_1.split();
    let pieces_len = pieces.len();
    // no header no meta, no chunk, no failure in reconstruction
    for piece in pieces {
        assert!(wfs_011.payload_state_mut().add_piece(piece).is_ok());
        assert!(wfs_011.try_reconstruct_share().is_ok());
        assert!(!wfs_011.payload_state().has_chunk(1));
    }
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), pieces_len);

    // Header is available but not own chunk data
    assert!(wfs_011.try_reconstruct_share().is_ok());
    assert!(!wfs_011.payload_state().has_chunk(1));
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), pieces_len);
    assert!(wfs_011.take_response().is_none());

    // Chunk meta is also available, then chunk will be reconstructed.
    wfs_011.payload_state_mut().set_owned_chunk_meta(meta);
    assert!(wfs_011.try_reconstruct_share().is_ok());
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);

    // chunk is added to the payload codec
    assert!(wfs_011.payload_state().has_chunk(1));
    assert_eq!(wfs_011.payload_state().codec().feed_len(), 1);

    // Check response contains EchoShare
    let response = wfs_011.take_response().unwrap();
    assert_eq!(response.messages().len(), 1);
    let (chain_size, clan_size) = {
        let topology = wfs_011.topology();
        (topology.get_chain_size(), topology.get_committee_size())
    };
    assert_eq!(
        response.messages().data()[0].1.len(),
        chain_size - clan_size - 1
    );

    // When share is reconstructed and all required data related to share is known then result is ok
    assert!(wfs_011.try_reconstruct_share().is_ok());
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);
    assert!(wfs_011.take_response().is_none());
}

#[tokio::test]
async fn test_try_reconstruct_share_invalid_meta() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let context = context_provider.network_context_with_header::<SupraDeliveryErasureRs8Schema>(
        encoded_result.header().clone(),
        peer_index,
    );
    let mut wfs_011 = WaitingForShare::new(context);
    let (_header, _committee_chunks, mut network_chunks) = encoded_result.split();
    assert!(wfs_011.payload_state().owned_chunk_meta().is_none());
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);

    assert!(wfs_011.try_reconstruct_share().is_ok());
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);
    let network_chunk_1 = network_chunks.remove(1);
    let (_meta, pieces) = network_chunk_1.split();
    let pieces_len = pieces.len();
    // no header no meta, no chunk, no failure in reconstruction
    for piece in pieces {
        assert!(wfs_011.payload_state_mut().add_piece(piece).is_ok());
        assert!(wfs_011.try_reconstruct_share().is_ok());
        assert!(!wfs_011.payload_state().has_chunk(1));
    }
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), pieces_len);

    // Header is available but not own chunk data
    // Chunk meta is also available, then chunk will be reconstructed.
    wfs_011
        .payload_state_mut()
        .set_owned_chunk_meta(CommitmentMeta::default());
    assert!(wfs_011.try_reconstruct_share().is_err());
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);

    // nothing is added to payload codec
    assert!(!wfs_011.payload_state().has_chunk(1));
    assert_eq!(wfs_011.payload_state().codec().feed_len(), 0);

    // No response
    assert!(wfs_011.take_response().is_none());
}

#[tokio::test]
async fn test_try_reconstruct_share_invalid_pieces() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let context = context_provider.network_context_with_header::<SupraDeliveryErasureRs8Schema>(
        encoded_result.header().clone(),
        peer_index,
    );
    let mut wfs_011 = WaitingForShare::new(context);
    let (_header, _committee_chunks, mut network_chunks) = encoded_result.split();
    assert!(wfs_011.payload_state().owned_chunk_meta().is_none());
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);

    assert!(wfs_011.try_reconstruct_share().is_ok());
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);
    let network_chunk_1 = network_chunks.remove(1);
    let (meta, pieces) = network_chunk_1.split();
    let pieces_len = pieces.len();
    // no header no meta, no chunk, no failure in reconstruction
    for mut piece in pieces {
        let _ = piece.data_mut().take_chunk();
        assert!(wfs_011.payload_state_mut().add_piece(piece).is_ok());
        assert!(wfs_011.try_reconstruct_share().is_ok());
        assert!(!wfs_011.payload_state().has_chunk(1));
    }
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), pieces_len);

    // Header is available but not own chunk data
    // Chunk meta is also available, then chunk will be reconstructed.
    wfs_011.payload_state_mut().set_owned_chunk_meta(meta);

    assert!(wfs_011.try_reconstruct_share().is_err());
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);

    // nothing is added to payload codec
    assert!(!wfs_011.payload_state().has_chunk(1));
    assert_eq!(wfs_011.payload_state().codec().feed_len(), 0);

    // No response
    assert!(wfs_011.take_response().is_none());
}

#[tokio::test]
async fn test_try_reconstruct_payload() {
    let _ = env_logger::try_init();
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let context = context_provider.network_context_with_header::<SupraDeliveryErasureRs8Schema>(
        encoded_result.header().clone(),
        peer_index,
    );
    let mut wfs_011 = WaitingForShare::new(context);
    let (_header, _committee_chunks, mut network_chunks) = encoded_result.split();
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);
    assert_eq!(wfs_011.payload_state().codec().feed_len(), 0);
    assert!(!wfs_011.payload_state().is_reconstructed());

    wfs_011.try_reconstruct_payload();
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);
    assert_eq!(wfs_011.payload_state().codec().feed_len(), 0);
    assert!(!wfs_011.payload_state().is_reconstructed());

    network_chunks.shuffle(&mut thread_rng());
    for nt_chunk in network_chunks {
        let nt_assembled_chunk = nt_chunk
            .decode(wfs_011.payload_state().share_codec().clone())
            .unwrap();
        assert!(wfs_011
            .payload_state_mut()
            .add_chunk(nt_assembled_chunk, false)
            .is_ok());
        wfs_011.try_reconstruct_payload();
        assert!(wfs_011.take_response().is_none());
        if wfs_011.payload_state().is_reconstructed() {
            break;
        }
    }

    // If loop exits then only with successful reconstruction
    assert!(wfs_011.payload_state().is_reconstructed());
}

#[tokio::test]
async fn test_try_reconstruct_invalid_reconstruction() {
    let _ = env_logger::try_init();
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let context = context_provider.network_context_with_header::<SupraDeliveryErasureRs8Schema>(
        encoded_result.header().clone(),
        peer_index,
    );
    let mut wfs_011 = WaitingForShare::new(context);
    let (_header, _committee_chunks, mut network_chunks) = encoded_result.split();
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);
    assert_eq!(wfs_011.payload_state().codec().feed_len(), 0);
    assert!(!wfs_011.payload_state().is_reconstructed());

    wfs_011.try_reconstruct_payload();
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);
    assert_eq!(wfs_011.payload_state().codec().feed_len(), 0);
    assert!(!wfs_011.payload_state().is_reconstructed());

    network_chunks.shuffle(&mut thread_rng());
    let threshold = wfs_011
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
        assert!(wfs_011
            .payload_state_mut()
            .add_chunk(nt_assembled_chunk, false)
            .is_ok());
        wfs_011.try_reconstruct_payload();
    }

    assert!(!wfs_011.payload_state().is_reconstructed());
    let mut response = wfs_011.take_response().unwrap();
    assert!(response.messages().is_empty());
    let feedback = response.take_feedback().remove(0);
    assert!(matches!(feedback, FeedbackMessage::InternalError(_, _)));
}

#[tokio::test]
async fn test_try_reconstruct_payload_invalid_commitment() {
    let _ = env_logger::try_init();
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let context = context_provider.network_context_with_header::<SupraDeliveryErasureRs8Schema>(
        header_with_origin(*encoded_result.header().origin()),
        peer_index,
    );
    let mut wfs_011 = WaitingForShare::new(context);
    let (_header, _committee_chunks, mut network_chunks) = encoded_result.split();
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);
    assert_eq!(wfs_011.payload_state().codec().feed_len(), 0);
    assert!(!wfs_011.payload_state().is_reconstructed());

    wfs_011.try_reconstruct_payload();
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);
    assert_eq!(wfs_011.payload_state().codec().feed_len(), 0);
    assert!(!wfs_011.payload_state().is_reconstructed());

    network_chunks.shuffle(&mut thread_rng());
    let threshold = wfs_011
        .payload_state()
        .codec()
        .network_settings()
        .unwrap()
        .data_shards();
    for _ in 0..threshold {
        let nt_chunk = network_chunks.pop().unwrap();
        let nt_assembled_chunk = nt_chunk
            .decode(wfs_011.payload_state().share_codec().clone())
            .unwrap();
        assert!(wfs_011
            .payload_state_mut()
            .add_chunk(nt_assembled_chunk, false)
            .is_ok());
        wfs_011.try_reconstruct_payload();
    }

    assert!(!wfs_011.payload_state().is_reconstructed());
    let mut response = wfs_011.take_response().unwrap();
    assert!(response.messages().is_empty());
    let feedback = response.take_feedback().remove(0);
    assert!(matches!(feedback, FeedbackMessage::Error(_, _)));
}

#[tokio::test]
async fn test_execute() {
    let _ = env_logger::try_init();
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let context = context_provider.network_context_with_header::<SupraDeliveryErasureRs8Schema>(
        encoded_result.header().clone(),
        peer_index,
    );
    let mut wfs_011 = WaitingForShare::new(context);
    let (_header, _committee_chunks, mut network_chunks) = encoded_result.split();
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);
    assert_eq!(wfs_011.payload_state().codec().feed_len(), 0);
    assert!(!wfs_011.payload_state().is_reconstructed());

    let own_chunk = network_chunks.remove(1);
    let (own_chunk_meta, mut pieces) = own_chunk.split();
    wfs_011
        .payload_state_mut()
        .set_owned_chunk_meta(own_chunk_meta);
    network_chunks.shuffle(&mut thread_rng());
    for nt_chunk in network_chunks {
        let nt_assembled_chunk = nt_chunk
            .decode(wfs_011.payload_state().share_codec().clone())
            .unwrap();
        assert!(wfs_011
            .payload_state_mut()
            .add_chunk(nt_assembled_chunk, false)
            .is_ok());
        if !pieces.is_empty() {
            assert!(wfs_011
                .payload_state_mut()
                .add_piece(pieces.pop().unwrap())
                .is_ok());
        }
        wfs_011.execute();
        if wfs_011.payload_state().is_reconstructed() {
            break;
        }
    }

    // If loop exits then only with successful reconstruction
    assert!(wfs_011.payload_state().is_reconstructed());
    let response = wfs_011.take_response().unwrap();
    assert_eq!(response.messages().data().len(), 1);
    assert!(matches!(
        response.messages().data()[0].0,
        RBCNetworkMessage::EchoShare(_)
    ));
}

#[tokio::test]
async fn test_wfs_transitions() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.network_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let wfs_011 = WaitingForShare::new(context);

    let transition = Transition::<DoneNetworkFSM<SupraDeliveryErasureRs8Schema>>::guard(&wfs_011);
    assert!(!can_transaction_happen(transition));

    let context =
        context_provider.network_context_with_payload::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut wfs_011 = WaitingForShare::new(context);

    let transition = Transition::<DoneNetworkFSM<SupraDeliveryErasureRs8Schema>>::guard(&wfs_011);
    assert!(can_transaction_happen(transition));

    wfs_011.payload_state_mut().set_error();

    let transition = Transition::<DoneNetworkFSM<SupraDeliveryErasureRs8Schema>>::guard(&wfs_011);
    assert!(can_transaction_happen(transition));
}

#[tokio::test]
async fn test_receive_return_message() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let context = context_provider.network_context_with_header::<SupraDeliveryErasureRs8Schema>(
        encoded_result.header().clone(),
        peer_index,
    );
    let mut wfs_011 = WaitingForShare::new(context);
    let (header, _committee_chunks, mut network_chunks) = encoded_result.split();
    assert!(wfs_011.payload_state().owned_chunk_meta().is_none());
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);

    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 0);
    let network_chunk_1 = network_chunks.remove(1);
    let (meta, mut pieces) = network_chunk_1.split();
    let value_data = ValueData::new(header.clone(), pieces.remove(0));
    let share_msg = ShareData::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 0, 0)),
        value_data,
        meta,
    );

    wfs_011.receive_message(RBCNetworkMessage::Share(share_msg));
    assert!(wfs_011.payload_state().owned_chunk_meta().is_some());
    assert!(wfs_011.payload_state().has_piece(0));
    assert_eq!(wfs_011.payload_state().share_codec().feed_len(), 1);

    wfs_011
        .response_mut()
        .add_feedback(FeedbackMessage::InternalError(
            header.get_meta(),
            "test error".to_string(),
        ));

    let response = wfs_011.return_message();
    assert!(response.is_some());
    assert!(matches!(
        response.unwrap().take_feedback().remove(0),
        FeedbackMessage::InternalError(_, _)
    ));
}

#[tokio::test]
async fn test_sync_request_to_any_network_peer() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let context = context_provider.network_context_with_header::<SupraDeliveryErasureRs8Schema>(
        encoded_result.header().clone(),
        peer_index,
    );
    // network_011 state
    let mut network_011 = WaitingForShare::new(context);
    let (header, _committee_chunks, _network_chunks) = encoded_result.split();
    let qc = context_provider
        .resource_provider
        .generate_qc(leader_index.clan_identifier(), header.commitment());
    let sync = SyncRequest::new(header.clone(), qc);

    // network_011 <=[sync]=
    assert!(!network_011.payload_state().failed());
    network_011.receive_message(RBCNetworkMessage::Sync(sync));
    assert!(!network_011.payload_state().failed());
    let response_011 = network_011.return_message();
    // Ongoing C2T task does not respond to internal sync request
    assert!(response_011.is_none());
}

#[tokio::test]
async fn test_pull_request_to_any_network_peer() {
    let network_011 = PeerGlobalIndex::new(0, 1, 1);
    let network_012 = PeerGlobalIndex::new(0, 1, 2);
    let network_023 = PeerGlobalIndex::new(0, 2, 3);

    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let (header, _committee_chunks, network_chunks) = encoded_result.split();

    let qc = context_provider
        .resource_provider
        .generate_qc(leader_index.clan_identifier(), header.commitment());
    let sync = SyncRequest::new(header.clone(), qc);

    // network_011 state
    let mut network_011 = WaitingForShare::new(
        context_provider.network_context_with_header::<SupraDeliveryErasureRs8Schema>(
            header.clone(),
            network_011,
        ),
    );
    let current_node_index = network_011.topology().get_position();

    for nt_chunk in network_chunks {
        let nt_assembled_chunk = nt_chunk
            .decode(network_011.payload_state().share_codec().clone())
            .unwrap();
        let chunk_index = nt_assembled_chunk.data().get_chunk_index();
        assert!(network_011
            .payload_state_mut()
            .add_chunk(nt_assembled_chunk, current_node_index == chunk_index)
            .is_ok());
        network_011.try_reconstruct_payload();
        assert!(network_011.take_response().is_none());
        if network_011.payload_state().is_reconstructed() {
            break;
        }
    }
    assert!(network_011.payload_state().has_owned_chunk());

    // network_012 state
    let mut network_012 = WaitingForShare::new(
        context_provider.network_context_with_header::<SupraDeliveryErasureRs8Schema>(
            header.clone(),
            network_012,
        ),
    );

    // network_023 state
    let network_023 = WaitingForShare::new(
        context_provider.network_context_with_header::<SupraDeliveryErasureRs8Schema>(
            header.clone(),
            network_023,
        ),
    );

    // network_011(owned) <=[pull_023]= network_023 // send owned chunk
    let pull_023 = PullRequest::new(network_023.authenticator().origin(), sync.clone());
    assert!(!network_011.payload_state().failed());
    network_011.receive_message(RBCNetworkMessage::Pull(pull_023));
    assert!(!network_011.payload_state().failed());
    let response_011 = network_011.return_message();
    assert!(response_011.is_some());
    let network_msg_011 = response_011.as_ref().unwrap().messages().data();
    assert_eq!(network_msg_011.len(), 1);
    let data = network_msg_011.first().unwrap();
    if let (RBCNetworkMessage::EchoShare(_echo_share), address) = data {
        assert_eq!(address.len(), 1);
    } else {
        panic!("echo share expected")
    }

    // network_011(owned) <=[pull_012]= network_012 // send owned chunk
    let pull_012 = PullRequest::new(network_012.authenticator().origin(), sync.clone());
    assert!(!network_011.payload_state().failed());
    network_011.receive_message(RBCNetworkMessage::Pull(pull_012));
    assert!(!network_011.payload_state().failed());
    let response_011 = network_011.return_message();
    assert!(response_011.is_some());
    let network_msg_011 = response_011.as_ref().unwrap().messages().data();
    assert_eq!(network_msg_011.len(), 1);
    let data = network_msg_011.first().unwrap();
    if let (RBCNetworkMessage::EchoShare(_echo_share), address) = data {
        assert_eq!(address.len(), 1);
    } else {
        panic!("echo share expected")
    }

    // network_012 <=[pull_023]= network_023 // do nothing
    let pull_023 = PullRequest::new(network_023.authenticator().origin(), sync.clone());
    assert!(!network_012.payload_state().failed());
    network_012.receive_message(RBCNetworkMessage::Pull(pull_023));
    assert!(!network_012.payload_state().failed());
    let response_012 = network_012.return_message();
    assert!(response_012.is_none());

    // network_012 <=[pull_011= network_011 // do nothing
    let pull_011 = PullRequest::new(network_011.authenticator().origin(), sync);
    assert!(!network_012.payload_state().failed());
    network_012.receive_message(RBCNetworkMessage::Pull(pull_011));
    assert!(!network_012.payload_state().failed());
    let response_012 = network_012.return_message();
    assert!(response_012.is_none());
}

#[tokio::test]
async fn test_sync_with_received_chunk_state() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let context = context_provider.network_context_with_header::<SupraDeliveryErasureRs8Schema>(
        encoded_result.header().clone(),
        peer_index,
    );
    let mut wfs_011 = WaitingForShare::new(context);
    let (_header, _committee_chunks, network_chunks) = encoded_result.split();

    assert_eq!(wfs_011.payload_state().get_received_chunks().len(), 0);
    assert_eq!(wfs_011.payload_state().get_received_pieces().len(), 0);

    for nt_chunk in network_chunks {
        if nt_chunk.index() == 7 || nt_chunk.index() == 11 {
            let nt_assembled_chunk = nt_chunk
                .decode(wfs_011.payload_state().share_codec().clone())
                .unwrap();
            assert!(wfs_011
                .payload_state_mut()
                .add_chunk(nt_assembled_chunk, false)
                .is_ok())
        } else if nt_chunk.index() == 6 {
            // owned chunk piece with index 3
            let (_, pieces) = nt_chunk.split();
            for piece in pieces {
                if piece.data().get_chunk_index() == 3 || piece.data().get_chunk_index() == 2 {
                    assert!(wfs_011.payload_state_mut().add_piece(piece).is_ok());
                }
            }
        }
    }

    assert_eq!(wfs_011.payload_state().get_received_chunks().len(), 2);
    assert_eq!(wfs_011.payload_state().get_received_pieces().len(), 2);

    let header = wfs_011.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(leader_index.clan_identifier(), header.commitment());
    let sync = SyncRequest::new(header.clone(), qc);
    wfs_011.receive_message(RBCNetworkMessage::Sync(sync));

    let response_001 = wfs_011.return_message();
    // Ongoing C2T task does not respond to internal sync request
    assert!(response_001.is_none());
}

#[tokio::test]
async fn test_sync_with_owned_chunk_available_state() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let (encoded_result, _) = context_provider.encoded_data::<SupraDeliveryErasureRs8Schema>();
    let context = context_provider.network_context_with_header::<SupraDeliveryErasureRs8Schema>(
        encoded_result.header().clone(),
        peer_index,
    );
    let mut wfs_011 = WaitingForShare::new(context);
    let (_header, _committee_chunks, network_chunks) = encoded_result.split();

    assert_eq!(wfs_011.payload_state().get_received_chunks().len(), 0);
    assert_eq!(wfs_011.payload_state().get_received_pieces().len(), 0);

    for nt_chunk in network_chunks {
        if nt_chunk.index() == 6 || nt_chunk.index() == 11 {
            let owned_chunk = nt_chunk.index() == 6;
            let nt_assembled_chunk = nt_chunk
                .decode(wfs_011.payload_state().share_codec().clone())
                .unwrap();
            assert!(wfs_011
                .payload_state_mut()
                .add_chunk(nt_assembled_chunk, owned_chunk)
                .is_ok())
        }
    }

    assert_eq!(wfs_011.payload_state().get_received_chunks().len(), 2);
    assert_eq!(wfs_011.payload_state().get_received_pieces().len(), 0);

    let header = wfs_011.payload_state().get_header();
    let qc = context_provider
        .resource_provider
        .generate_qc(leader_index.clan_identifier(), header.commitment());
    let sync = SyncRequest::new(header.clone(), qc);
    wfs_011.receive_message(RBCNetworkMessage::Sync(sync));

    let response_001 = wfs_011.return_message();
    // Ongoing C2T task does not respond to internal sync request
    assert!(response_001.is_none());
}
