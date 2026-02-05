use crate::tasks::codec::{EncodeResultIfc, SupraDeliveryCodec, SupraDeliveryErasureCodec};
use crate::types::helpers::message_factory::{MessageFactory, MessageFrom};
use crate::types::helpers::verifier_visitor::verify_value_data_tests::rs8_codec;
use crate::types::messages::chunk::ChunkData;
use crate::types::messages::value_data::ValueData;
use crate::types::messages::EchoValueData;
use crate::{SupraDeliveryErasureRs16Schema, SupraDeliveryErasureRs8Schema};
use crypto::dkg::config::DKGConfig;
use crypto::dkg::generate_distributed_key_for_chain;
use crypto::{Authenticator, NodeIdentity};
use erasure::codecs::rs8::Rs8Settings;
use erasure::utils::codec_trait::Setting;
use primitives::types::Header;
use primitives::PeerGlobalIndex;
use std::any::Any;

pub fn give_test_authenticator(position: usize) -> (PeerGlobalIndex, Authenticator) {
    let peer_index = PeerGlobalIndex::new(0, 0, position);
    let node_identity = NodeIdentity::random();
    let dkg_config = DKGConfig::small_config();
    let data = generate_distributed_key_for_chain(1, 1, &dkg_config, &peer_index);
    assert!(data.is_some());
    let data = data.unwrap();
    let auth = Authenticator::new(node_identity, data.1, data.0);
    assert!(auth.threshold().eq(&dkg_config.threshold()));
    (peer_index, auth)
}

#[test]
fn test_echo_message_work() {
    let (_peer_index_0, auth_0) = give_test_authenticator(0);
    let message_factory_0 = MessageFactory(&auth_0);

    let value_data =
        ValueData::<SupraDeliveryErasureRs16Schema>::new(Header::default(), ChunkData::default());
    let value_data_id = value_data.type_id();
    let echo_value: EchoValueData<SupraDeliveryErasureRs16Schema> =
        message_factory_0.message_from(value_data);
    assert!(value_data_id.ne(&echo_value.type_id()))
}

#[test]
fn test_network_chunk_decode() {
    let (_, authenticator) = give_test_authenticator(1);
    let random_payload = vec![2; 10000];
    let mut result = rs8_codec()
        .encode(random_payload, &authenticator)
        .expect("Successful encode");
    let mut network_chunks = result.take_network_chunks();
    let chunk = network_chunks.remove(1);
    let reconstructed_chunk = chunk.decode(rs8_codec());
    assert!(reconstructed_chunk.is_ok());

    let other_codec = SupraDeliveryCodec::<SupraDeliveryErasureRs8Schema>::new(
        Rs8Settings::new(2, 2),
        Some(Rs8Settings::new(10, 3)),
    );
    let chunk = network_chunks.remove(2);
    let reconstructed_chunk = chunk.decode(other_codec);
    assert!(reconstructed_chunk.is_err());
}
