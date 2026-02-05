use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::messages::chunk::ChunkData;
use crate::types::messages::{ReadyData, ShareData, ValueData};
use erasure::utils::codec_trait::{Chunk, Codec};
use primitives::types::Header;
use vec_commitment::committed_chunk::{CommitmentMeta, CommittedChunk};
pub mod committee_payload_state_test;
mod context_tests;
pub mod network_payload_state_test;
mod sync_payload_state_test;
pub mod unit_test_message;
pub mod unit_test_vote_store;
mod verify_payload_data_tests;

use crate::types::messages::certificate_data::QuorumCertificateData;
use crypto::PartialShare;
use erasure::codecs::rs8::Rs8Settings;
use erasure::utils::errors::FECError;
use primitives::serde::DeserializerCustom;
use primitives::types::QuorumCertificate;
use primitives::{Origin, Payload};
use serde::{Deserialize, Deserializer, Serialize};
use vec_commitment::txn_generator::RandomTxn;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct TestChunk(usize);

impl Chunk for TestChunk {
    fn new(index: usize, _data: Vec<u8>, _data_size: usize) -> Self {
        TestChunk(index)
    }

    fn byte_chunk_ref(&self) -> &Vec<u8> {
        todo!()
    }

    fn get_chunk_index(&self) -> usize {
        self.0
    }
}
impl DeserializerCustom for TestChunk {
    fn deserialize_wrapper<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <TestChunk as Deserialize>::deserialize(deserializer)
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct TestCodec;
impl Codec for TestCodec {
    type Setting = Rs8Settings;
    type Chunk = TestChunk;

    fn encode(_setting: Self::Setting, _input: Payload) -> Result<Vec<Self::Chunk>, FECError> {
        todo!()
    }

    fn feed(&mut self, _item: Self::Chunk) -> Result<(), FECError> {
        todo!()
    }

    fn decode(&mut self, _setting: Self::Setting) -> Result<Payload, FECError> {
        todo!()
    }

    fn feed_len(&self) -> usize {
        todo!()
    }

    fn reset_decoder(&mut self) {
        todo!()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct TestSupraCodec;
impl SupraDeliveryErasureCodecSchema for TestSupraCodec {
    type DataCodec = TestCodec;
}

pub fn get_value_data<S: SupraDeliveryErasureCodecSchema>() -> ValueData<S> {
    value_data_with_header_idx(Header::default(), 0)
}

pub fn value_data_with_header<S: SupraDeliveryErasureCodecSchema>(header: Header) -> ValueData<S> {
    value_data_with_header_idx(header, 0)
}

pub fn value_data_with_header_idx<S: SupraDeliveryErasureCodecSchema>(
    header: Header,
    index: usize,
) -> ValueData<S> {
    let part = <<S as SupraDeliveryErasureCodecSchema>::DataCodec as Codec>::Chunk::new(
        index,
        vec![],
        index + 1,
    );
    let proof = RandomTxn::generate_gibberish(0);
    let chunk = ChunkData::new(CommittedChunk::new(index, proof, part));
    ValueData::new(header, chunk)
}

pub fn header_with_origin(origin: Origin) -> Header {
    Header::new([0; 64], origin, [0; 32])
}

pub fn partial_share(index: u32) -> PartialShare {
    PartialShare::new(index, [index as u8; 96])
}

pub fn certificate_data(header: Header) -> QuorumCertificateData {
    QuorumCertificateData::new(header, [0; 64], QuorumCertificate::default())
}

pub fn ready_data<S: SupraDeliveryErasureCodecSchema>(
    sender: Origin,
    data: ValueData<S>,
) -> ReadyData<S> {
    ReadyData::new(sender, data)
}

pub fn share_data<S: SupraDeliveryErasureCodecSchema>(
    sender: Origin,
    data: ValueData<S>,
) -> ShareData<S> {
    ShareData::new(sender, data, CommitmentMeta::default())
}
