use crate::tasks::errors::RBCError;
use crate::types::messages::chunk::{ChunkData, NetworkChunk};
use crypto::Authenticator;
use erasure::codecs::rs16::Rs16Codec;
use erasure::codecs::rs8::Rs8Codec;
use erasure::utils::codec_trait::{Codec, Setting};
use primitives::types::Header;

use itertools::Itertools;
use primitives::serde::bincode_serializer;
use primitives::Payload;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::mem;
use vec_commitment::committed_chunk::{CommitmentMeta, CommittedChunk};

pub trait SupraDeliveryErasureCodecSchema:
    Debug + Default + Clone + Serialize + Send + Sync + 'static
{
    type DataCodec: Codec;
}

pub trait EncodeResultIfc<C: SupraDeliveryErasureCodecSchema> {
    fn committee_chunks(&self) -> &Vec<ChunkData<C>>;
    fn network_chunks(&self) -> &Vec<NetworkChunk<C>>;
    fn take_committee_chunks(&mut self) -> Vec<ChunkData<C>>;
    fn take_network_chunks(&mut self) -> Vec<NetworkChunk<C>>;
    fn header(&self) -> &Header;
    fn split(self) -> (Header, Vec<ChunkData<C>>, Vec<NetworkChunk<C>>);
}

pub struct EncodeResult<C: SupraDeliveryErasureCodecSchema> {
    header: Header,
    committee_chunks: Vec<ChunkData<C>>,
    network_chunks: Vec<NetworkChunk<C>>,
}

impl<C: SupraDeliveryErasureCodecSchema> EncodeResult<C> {
    fn new(
        header: Header,
        committee_chunks: Vec<ChunkData<C>>,
        network_chunks: Vec<NetworkChunk<C>>,
    ) -> Self {
        Self {
            header,
            committee_chunks,
            network_chunks,
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> EncodeResultIfc<C> for EncodeResult<C> {
    fn committee_chunks(&self) -> &Vec<ChunkData<C>> {
        &self.committee_chunks
    }

    fn network_chunks(&self) -> &Vec<NetworkChunk<C>> {
        &self.network_chunks
    }

    fn take_committee_chunks(&mut self) -> Vec<ChunkData<C>> {
        let mut aux = vec![];
        mem::swap(&mut aux, &mut self.committee_chunks);
        aux
    }

    fn take_network_chunks(&mut self) -> Vec<NetworkChunk<C>> {
        let mut aux = vec![];
        mem::swap(&mut aux, &mut self.network_chunks);
        aux
    }

    fn header(&self) -> &Header {
        &self.header
    }

    fn split(self) -> (Header, Vec<ChunkData<C>>, Vec<NetworkChunk<C>>) {
        (self.header, self.committee_chunks, self.network_chunks)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SupraDeliveryErasureRs16Schema;

impl SupraDeliveryErasureCodecSchema for SupraDeliveryErasureRs16Schema {
    type DataCodec = Rs16Codec;
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SupraDeliveryErasureRs8Schema;
impl SupraDeliveryErasureCodecSchema for SupraDeliveryErasureRs8Schema {
    type DataCodec = Rs8Codec;
}

pub trait SupraDeliveryErasureCodec<Schema: SupraDeliveryErasureCodecSchema> {
    fn encode(
        &self,
        payload: Payload,
        authorizer: &Authenticator,
    ) -> Result<EncodeResult<Schema>, RBCError>;

    fn decode(
        &mut self,
        setting: <Schema::DataCodec as Codec>::Setting,
    ) -> Result<Payload, RBCError>;

    fn feed(&mut self, item: <Schema::DataCodec as Codec>::Chunk) -> Result<(), RBCError>;

    fn feed_len(&self) -> usize;

    fn reset_decoder(&mut self);
}

pub struct SupraDeliveryCodec<Schema: SupraDeliveryErasureCodecSchema> {
    committee_settings: <Schema::DataCodec as Codec>::Setting,
    network_settings: Option<<Schema::DataCodec as Codec>::Setting>,
    decoder: Schema::DataCodec,
    _phantom_: PhantomData<Schema>,
}

impl<Schema: SupraDeliveryErasureCodecSchema> Clone for SupraDeliveryCodec<Schema> {
    fn clone(&self) -> Self {
        SupraDeliveryCodec::new(self.committee_settings, self.network_settings)
    }
}

impl<Schema: SupraDeliveryErasureCodecSchema> SupraDeliveryCodec<Schema> {
    pub(crate) fn new(
        committee_settings: <Schema::DataCodec as Codec>::Setting,
        network_settings: Option<<Schema::DataCodec as Codec>::Setting>,
    ) -> Self {
        Self {
            committee_settings,
            network_settings,
            decoder: Schema::DataCodec::default(),
            _phantom_: Default::default(),
        }
    }

    pub fn committee_settings(&self) -> <Schema::DataCodec as Codec>::Setting {
        self.committee_settings
    }

    pub fn network_settings(&self) -> Option<<Schema::DataCodec as Codec>::Setting> {
        self.network_settings
    }

    pub fn total_chunks(&self) -> usize {
        self.total_committee_chunks() + self.total_network_chunks()
    }

    pub fn total_committee_chunks(&self) -> usize {
        self.committee_settings.total_shards()
    }

    pub fn total_network_chunks(&self) -> usize {
        self.network_settings
            .map(|setting| setting.total_shards())
            .unwrap_or(0)
    }

    pub fn encoder_commitment_size(&self) -> usize {
        self.total_committee_chunks()
            + self.total_network_chunks()
            + (self.total_committee_chunks() * self.total_network_chunks())
    }

    fn split_chunks(
        &self,
        mut chunk_list: Vec<CommittedChunk<<Schema::DataCodec as Codec>::Chunk>>,
    ) -> (Vec<ChunkData<Schema>>, Vec<NetworkChunk<Schema>>) {
        let committee_erasure_chunk_len = self.total_committee_chunks();
        let network_erasure_chunk_len = self.total_network_chunks();
        let mut network_chunks_list = vec![];
        let mut network_chunks_pieces = vec![];
        if self.network_settings.is_some() {
            network_chunks_list = chunk_list.split_off(committee_erasure_chunk_len);
            network_chunks_pieces = network_chunks_list.split_off(network_erasure_chunk_len);
        }

        let mut network_chunks = vec![];

        let mut network_chunks_pieces = network_chunks_pieces
            .into_iter()
            .map(|chunk| ChunkData::new(chunk))
            .chunks(committee_erasure_chunk_len)
            .into_iter()
            .map(|c| c.collect::<Vec<_>>())
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<Vec<_>>>();
        for chunk in network_chunks_list {
            let net_pieces = network_chunks_pieces.pop().unwrap();
            let hash = chunk.get_hash();
            let (commitment_index, proof, _) = chunk.split();
            let meta = CommitmentMeta::new(commitment_index, proof, hash);
            network_chunks.push(NetworkChunk::new(meta, net_pieces));
        }

        let committee_chunks = chunk_list
            .into_iter()
            .map(|data| ChunkData::new(data))
            .collect();
        (committee_chunks, network_chunks)
    }
}

impl<Schema: SupraDeliveryErasureCodecSchema> SupraDeliveryErasureCodec<Schema>
    for SupraDeliveryCodec<Schema>
{
    fn encode(
        &self,
        payload: Payload,
        authorizer: &Authenticator,
    ) -> Result<EncodeResult<Schema>, RBCError> {
        let committee_erasure_setting = self.committee_settings;
        let network_erasure_setting = self.network_settings;

        let mut committee_erasure_chunk =
            Schema::DataCodec::encode(committee_erasure_setting, payload.clone())?;

        let mut network_erasure_chunk = network_erasure_setting.map_or_else(
            || Ok(vec![]),
            |setting| Schema::DataCodec::encode(setting, payload),
        )?;

        let mut flatten_network_pieces = vec![];
        for chunk in network_erasure_chunk.iter() {
            let payload = bincode_serializer(chunk).unwrap().to_vec();
            let res = Schema::DataCodec::encode(committee_erasure_setting, payload)?;
            flatten_network_pieces.extend(res);
        }

        committee_erasure_chunk.append(&mut network_erasure_chunk);
        committee_erasure_chunk.append(&mut flatten_network_pieces);

        let (commitment, chunk_list) =
            CommittedChunk::<<Schema::DataCodec as Codec>::Chunk>::commit_chunk_list(
                committee_erasure_chunk,
            )?;

        let (committee_chunks, network_chunks) = self.split_chunks(chunk_list);

        let header = Header::new(
            authorizer.sign(&commitment)?,
            authorizer.origin(),
            commitment,
        );

        Ok(EncodeResult::new(header, committee_chunks, network_chunks))
    }

    fn decode(
        &mut self,
        setting: <Schema::DataCodec as Codec>::Setting,
    ) -> Result<Payload, RBCError> {
        self.decoder.decode(setting).map_err(|e| e.into())
    }

    fn feed(&mut self, item: <Schema::DataCodec as Codec>::Chunk) -> Result<(), RBCError> {
        self.decoder.feed(item).map_err(|e| e.into())
    }

    fn feed_len(&self) -> usize {
        self.decoder.feed_len()
    }

    fn reset_decoder(&mut self) {
        self.decoder.reset_decoder();
    }
}
