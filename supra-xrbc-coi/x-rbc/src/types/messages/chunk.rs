use crate::tasks::codec::{
    SupraDeliveryCodec, SupraDeliveryErasureCodec, SupraDeliveryErasureCodecSchema,
};
use crate::tasks::errors::RBCError;
use erasure::utils::codec_trait::Codec;
use erasure::utils::errors::FECError::FailedToDecode;
use primitives::serde::bincode_deserialize_custom;
use serde::{Deserialize, Serialize};
use vec_commitment::committed_chunk::{CommitmentMeta, CommittedChunk};

///
/// Committed chunk to be shared between nodes
///
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkData<C: SupraDeliveryErasureCodecSchema> {
    data: CommittedChunk<<C::DataCodec as Codec>::Chunk>,
}

impl<C: SupraDeliveryErasureCodecSchema> ChunkData<C> {
    pub fn new(data: CommittedChunk<<C::DataCodec as Codec>::Chunk>) -> ChunkData<C> {
        Self { data }
    }
    pub fn data_mut(
        &mut self,
    ) -> &mut CommittedChunk<<<C as SupraDeliveryErasureCodecSchema>::DataCodec as Codec>::Chunk>
    {
        &mut self.data
    }

    pub fn data(
        &self,
    ) -> &CommittedChunk<<<C as SupraDeliveryErasureCodecSchema>::DataCodec as Codec>::Chunk> {
        &self.data
    }
}

///
/// Network chunk along with pieces for the network peer to be  shared by committee
/// to the rest of the network
///
#[derive(Debug, Default, Clone)]
pub struct NetworkChunk<C: SupraDeliveryErasureCodecSchema> {
    /// Network chunk commitment meta information
    meta: CommitmentMeta,
    /// Pieces of the network chunk to be shared by a committee-node to dedicated network node
    pieces: Vec<ChunkData<C>>,
}

impl<C: SupraDeliveryErasureCodecSchema> NetworkChunk<C> {
    pub fn new(meta: CommitmentMeta, pieces: Vec<ChunkData<C>>) -> Self {
        Self { meta, pieces }
    }

    pub fn index(&self) -> usize {
        self.meta.index()
    }

    pub fn pieces(&self) -> &Vec<ChunkData<C>> {
        &self.pieces
    }

    pub fn meta(&self) -> &CommitmentMeta {
        &self.meta
    }

    pub fn get_meta(&self) -> CommitmentMeta {
        self.meta.clone()
    }

    pub(crate) fn split(self) -> (CommitmentMeta, Vec<ChunkData<C>>) {
        (self.meta, self.pieces)
    }

    pub(crate) fn split_ref(&self) -> (&CommitmentMeta, &Vec<ChunkData<C>>) {
        (&self.meta, &self.pieces)
    }

    pub(crate) fn decode(self, mut codec: SupraDeliveryCodec<C>) -> Result<ChunkData<C>, RBCError> {
        let settings = codec.committee_settings();
        let (meta, pieces) = self.split();
        let (index, proof) = meta.split();
        for mut p in pieces {
            codec.feed(p.data_mut().take_chunk())?;
            let result = codec.decode(settings);
            if let Ok(payload) = result {
                let chunk = bincode_deserialize_custom::<<C::DataCodec as Codec>::Chunk>(&payload);
                return chunk
                    .map(|c| CommittedChunk::new(index, proof, c))
                    .map(|c| ChunkData::<C>::new(c))
                    .map_err(RBCError::CommonError);
            }
        }
        Err(RBCError::FECError(FailedToDecode(format!(
            "Invalid network chunk: {}",
            index
        ))))
    }
}
