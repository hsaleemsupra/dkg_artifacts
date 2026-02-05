use crate::utils::errors::FECError;
use primitives::serde::DeserializerCustom;
use primitives::Payload;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

pub trait Codec: Debug + Default + Clone + Send + Sync {
    type Setting: Setting;
    type Chunk: Chunk;
    fn encode(setting: Self::Setting, input: Payload) -> Result<Vec<Self::Chunk>, FECError>;
    fn feed(&mut self, item: Self::Chunk) -> Result<(), FECError>;
    fn decode(&mut self, setting: Self::Setting) -> Result<Payload, FECError>;
    fn feed_len(&self) -> usize;
    fn reset_decoder(&mut self);
}

pub trait Chunk:
    Debug + Default + Clone + Send + Sync + Serialize + DeserializerCustom + PartialEq + Eq
{
    fn new(index: usize, chunk: Vec<u8>, data_size: usize) -> Self;
    fn byte_chunk_ref(&self) -> &Vec<u8>;
    fn get_chunk_index(&self) -> usize;
}

pub trait Setting:
    Debug + Default + Copy + Copy + Eq + PartialEq + Send + Sync + Serialize + DeserializeOwned
{
    fn new(data_shards: usize, parity_shards: usize) -> Self;
    fn data_shards(&self) -> usize;
    fn parity_shards(&self) -> usize;
    fn total_shards(&self) -> usize {
        self.data_shards() + self.parity_shards()
    }
}
