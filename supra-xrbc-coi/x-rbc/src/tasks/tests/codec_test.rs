use crate::tasks::codec::{EncodeResultIfc, SupraDeliveryCodec, SupraDeliveryErasureCodec};
use crate::tasks::tests::TestSupraDeliveryResources;
use crate::{SupraDeliveryErasureRs16Schema, SupraDeliveryRs16Schema};
use primitives::types::HeaderIfc;

use crypto::tests::give_test_authenticator;
use crypto::traits::NodeIdentityInterface;
use crypto::NodeIdentity;
use erasure::codecs::rs16::{Rs16Chunk, Rs16Settings};
use erasure::utils::codec_trait::Setting;
use network::topology::peer_info::Role;
use primitives::serde::bincode_deserialize;
use primitives::PeerGlobalIndex;
use rand::seq::SliceRandom;
use vec_commitment::committed_chunk::CommittedChunk;
use vec_commitment::txn_generator::GeneratorType;

#[test]
fn test_network_chunk_none_setting() {
    let peer_index = PeerGlobalIndex::new(0, 0, 0);
    let auth = give_test_authenticator(peer_index);

    let schema =
        SupraDeliveryCodec::<SupraDeliveryErasureRs16Schema>::new(Rs16Settings::new(3, 2), None);
    let payload = GeneratorType::Gibberish.spawn_the_generator(1000, 50);
    let payload = bincode::serialize(&payload).unwrap();

    let encode_res = schema.encode(payload, &auth).unwrap();

    let network_chunk = encode_res.network_chunks();
    assert_eq!(network_chunk.len(), 0);
}

#[tokio::test]
async fn test_network_chunk() {
    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(0, 0, 0);
    let sd_test_obj = TestSupraDeliveryResources::<SupraDeliveryRs16Schema>::new(peer_index, role);
    let mut schema = sd_test_obj.delivery_manager.get_codec();
    let payload = GeneratorType::Gibberish.spawn_the_generator(1000, 50);
    let payload = bincode::serialize(&payload).unwrap();

    let mut encode_res = schema
        .encode(
            payload.clone(),
            sd_test_obj.delivery_manager.get_authenticator(),
        )
        .unwrap();
    assert_eq!(
        encode_res.network_chunks().len(),
        schema.total_network_chunks()
    );
    assert_eq!(
        encode_res.committee_chunks().len(),
        schema.total_committee_chunks()
    );
    let header = encode_res.header().clone();
    let leaf_count = schema.encoder_commitment_size();

    let verify = NodeIdentity::verify(
        &sd_test_obj.delivery_manager.get_authenticator().origin(),
        header.id(),
        header.commitment(),
    );
    assert!(verify.is_ok()); // header authenticity checked

    let mut rng = rand::thread_rng();
    let mut network_chunks = encode_res.take_network_chunks();
    network_chunks.shuffle(&mut rng);
    let network_setting = schema.network_settings().clone().unwrap();
    let mut payload_schema = schema.clone();
    let mut reconstructed_payload = None;

    for network_chunk in network_chunks {
        let (nt_meta, mut pieces) = network_chunk.split();
        let (nt_index, nt_proof) = nt_meta.split();
        assert_eq!(pieces.len(), schema.total_committee_chunks());

        pieces.shuffle(&mut rng);

        // Receiver side

        let committee_setting = schema.committee_settings().clone();
        let mut reconstructed_nt_chunk = None;
        for mut piece in pieces.into_iter() {
            let verify = piece.data_mut().verify(*header.commitment(), leaf_count);
            assert!(verify.unwrap_or(false)); // chunk is verified
            schema
                .feed(piece.data_mut().take_chunk())
                .expect("Successful consumption of chunk");
            let result = schema.decode(committee_setting);
            if let Ok(payload) = result {
                reconstructed_nt_chunk = bincode_deserialize::<Rs16Chunk>(&payload).ok();
                break;
            }
        }
        schema.reset_decoder();
        assert!(reconstructed_nt_chunk.is_some());
        let mut nt_chunk = reconstructed_nt_chunk
            .map(|chunk| CommittedChunk::new(nt_index, nt_proof, chunk))
            .unwrap();
        assert!(nt_chunk
            .verify(*header.commitment(), leaf_count)
            .unwrap_or(false));
        payload_schema
            .feed(nt_chunk.take_chunk())
            .expect("Successful consumption of chunk");
        let result = payload_schema.decode(network_setting);
        if let Ok(payload) = result {
            reconstructed_payload = Some(payload);
            break;
        }
    }
    assert!(reconstructed_payload.is_some());
    assert_eq!(reconstructed_payload.unwrap(), payload);
}

#[tokio::test]
async fn test_committee_chunk_function() {
    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(0, 0, 0);
    let sd_test_obj = TestSupraDeliveryResources::<SupraDeliveryRs16Schema>::new(peer_index, role);
    let mut schema = sd_test_obj.delivery_manager.get_codec();
    let payload = GeneratorType::Gibberish.spawn_the_generator(1000, 50);
    let payload = bincode::serialize(&payload).unwrap();

    let mut encode_res = schema
        .encode(
            payload.clone(),
            sd_test_obj.delivery_manager.get_authenticator(),
        )
        .unwrap();
    let header = encode_res.header().clone();
    let leaf_count = schema.total_committee_chunks()
        + schema.total_network_chunks()
        + (schema.total_committee_chunks() * schema.total_network_chunks());
    assert_eq!(schema.encoder_commitment_size(), leaf_count);

    let mut committee_chunk = encode_res.take_committee_chunks();
    assert_eq!(committee_chunk.len(), schema.total_committee_chunks());

    let mut rng = rand::thread_rng();
    committee_chunk.shuffle(&mut rng);

    // Receiver side
    let verify = NodeIdentity::verify(
        &sd_test_obj.delivery_manager.get_authenticator().origin(),
        header.id(),
        header.commitment(),
    );
    assert!(verify.is_ok()); // header authenticity checked

    let mut flag = false;

    for mut chunk_data in committee_chunk.into_iter() {
        let verify = chunk_data
            .data_mut()
            .verify(*header.commitment(), leaf_count);
        assert!(verify.is_ok()); // chunk is verified
        if verify.unwrap() {
            schema
                .feed(chunk_data.data_mut().take_chunk())
                .expect("Successful consumption of chunk");
            let result = schema.decode(schema.committee_settings());
            if let Ok(actual_result) = result {
                assert_eq!(payload, actual_result);
                println!("x");
                flag = true;
                break;
            } else {
                print!(".");
            }
        }
    }
    assert!(flag);
}
