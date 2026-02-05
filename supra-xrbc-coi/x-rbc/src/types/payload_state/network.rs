use crate::tasks::codec::{
    SupraDeliveryCodec, SupraDeliveryErasureCodec, SupraDeliveryErasureCodecSchema,
};
use crate::tasks::errors::RBCError;
use crate::types::messages::chunk::ChunkData;
use crate::types::payload_state::{NetworkChunkDataSettings, PayloadDataSettings, PayloadFlags};
use erasure::utils::codec_trait::Codec;
use metrics::{impl_timestamp, nanoseconds_since_unix_epoch, MetricTag, Timestamp};
use primitives::types::{Header, HeaderIfc};
use primitives::Payload;
use std::collections::HashSet;
use std::fmt::{Display, Formatter};

use vec_commitment::committed_chunk::CommitmentMeta;

///
/// Intermediate state of the deliverable when broadcast to the network peers
///
/// It stores intermediate data received related to the deliverable during delivery time.
pub struct NetworkPayloadState<Schema: SupraDeliveryErasureCodecSchema> {
    /// Received network chunk piece data from committee for network is stored in codec
    /// Codec configured with current delivery setting related to intra-committee and intra-network
    share_codec: SupraDeliveryCodec<Schema>,

    /// Received network share of the deliverable from network peers is stored in codec
    /// Codec configured with current delivery setting related to intra-committee and intra-network
    codec: SupraDeliveryCodec<Schema>,

    /// Header of the deliverable (id, commitment, broadcaster-origin)
    header: Header,

    /// Owned Network chunk meta information
    owned_chunk_meta: Option<CommitmentMeta>,

    /// Indexes of the chunks received so far
    received_chunks: HashSet<usize>,

    /// Indexes of the pieces of the owned chunks received so far
    received_pieces: HashSet<usize>,

    /// Full reconstructed data/deliverable
    reconstructed_payload: Option<Payload>,

    /// Owned ChunkData
    owned_chunk: Option<ChunkData<Schema>>,

    /// Error flag indicating invalid delivery state
    error: bool,

    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(
    timestamp,
    NetworkPayloadState<Schema: SupraDeliveryErasureCodecSchema>
);

pub(crate) enum NetworkPayloadTag {
    TagName,
    ShareDelivery,
    Delivery,
    DeliveryEnd,
    DeliveryEndSince,
}

impl Display for NetworkPayloadTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkPayloadTag::TagName => write!(f, "network-task"),
            NetworkPayloadTag::ShareDelivery => write!(f, "share-delivery-time"),
            NetworkPayloadTag::Delivery => write!(f, "delivery-time"),
            NetworkPayloadTag::DeliveryEnd => write!(f, "delivery-end-time"),
            NetworkPayloadTag::DeliveryEndSince => write!(f, "delivery-end-since-bc"),
        }
    }
}

impl MetricTag for NetworkPayloadTag {}

impl<C: SupraDeliveryErasureCodecSchema> HeaderIfc for NetworkPayloadState<C> {
    fn header(&self) -> &Header {
        &self.header
    }
}

impl<C: SupraDeliveryErasureCodecSchema> NetworkPayloadState<C> {
    pub(crate) fn new(header: Header, codec: SupraDeliveryCodec<C>) -> Self {
        Self {
            share_codec: codec.clone(),
            codec,
            header,
            owned_chunk_meta: None,
            received_chunks: Default::default(),
            received_pieces: Default::default(),
            reconstructed_payload: None,
            owned_chunk: None,
            error: false,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    ///
    /// Reference of the codec/chunk-collector of the delivery
    ///
    pub fn codec(&self) -> &SupraDeliveryCodec<C> {
        &self.codec
    }

    ///
    /// Mutable reference of the codec/chunk-collector of the delivery
    ///
    pub fn codec_mut(&mut self) -> &mut SupraDeliveryCodec<C> {
        &mut self.codec
    }

    ///
    /// Reference of the codec/chunk-collector for share-pieces of the delivery
    ///
    pub fn share_codec(&self) -> &SupraDeliveryCodec<C> {
        &self.share_codec
    }

    ///
    /// Mutable reference of the codec/chunk-collector for share-pieces of the delivery
    ///
    pub fn share_codec_mut(&mut self) -> &mut SupraDeliveryCodec<C> {
        &mut self.share_codec
    }

    pub(crate) fn owned_chunk_meta(&self) -> &Option<CommitmentMeta> {
        &self.owned_chunk_meta
    }

    ///
    /// Sets commitment meta information of the network-chunk assigned to the current node
    ///
    pub(crate) fn set_owned_chunk_meta(&mut self, meta: CommitmentMeta) {
        self.owned_chunk_meta = Some(meta);
    }

    pub(crate) fn set_reconstructed_payload(&mut self, payload: Option<Payload>) {
        self.reconstructed_payload = payload
    }

    pub(crate) fn reconstructed_payload(&self) -> &Option<Payload> {
        &self.reconstructed_payload
    }

    pub(crate) fn take_reconstructed_payload(&mut self) -> Option<Payload> {
        self.reconstructed_payload.take()
    }

    ///
    /// Returns true if the network chunk with the mentioned index is received
    ///
    pub(crate) fn has_chunk(&self, index: usize) -> bool {
        self.received_chunks.contains(&index)
    }

    ///
    /// Adds input chunk information to the payload state
    /// Does not check duplication, it's up to user to avoid adding duplicate data
    ///
    pub(crate) fn add_chunk(
        &mut self,
        mut chunk: ChunkData<C>,
        owned: bool,
    ) -> Result<(), RBCError> {
        if owned {
            self.set_owned_chunk(Some(chunk.clone()))
        }
        self.store_chunk_index(chunk.data().get_chunk_index());
        self.codec.feed(chunk.data_mut().take_chunk())
    }

    ///
    /// Adds index as received chunk index
    ///
    pub(crate) fn store_chunk_index(&mut self, index: usize) {
        self.received_chunks.insert(index);
    }

    ///
    /// Returns true if the network chunk with the mentioned index is received
    ///
    pub(crate) fn has_piece(&self, index: usize) -> bool {
        self.received_pieces.contains(&index)
    }

    ///
    /// Adds input chunk information to the payload state
    /// Does not check duplication, it's up to user to avoid adding duplicate data
    ///
    pub(crate) fn add_piece(&mut self, mut chunk: ChunkData<C>) -> Result<(), RBCError> {
        self.store_piece_index(chunk.data().get_chunk_index());
        self.share_codec.feed(chunk.data_mut().take_chunk())
    }

    ///
    /// Adds index as received chunk index
    ///
    pub(crate) fn store_piece_index(&mut self, index: usize) {
        self.received_pieces.insert(index);
    }

    pub(crate) fn has_owned_chunk(&self) -> bool {
        self.owned_chunk.is_some()
    }

    pub(crate) fn set_owned_chunk(&mut self, owned_chunk: Option<ChunkData<C>>) {
        if !self.has_owned_chunk() {
            self.owned_chunk = owned_chunk
        }
    }

    pub(crate) fn get_owned_chunk(&self) -> Option<ChunkData<C>> {
        self.owned_chunk.clone()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> PayloadFlags for NetworkPayloadState<C> {
    ///
    /// True if the deliverable is fully reconstructed, header and all chunks are available
    ///
    fn is_reconstructed(&self) -> bool {
        self.has_payload_data()
    }

    ///
    /// True if the deliverable is available along with header information
    ///
    fn has_payload_data(&self) -> bool {
        self.reconstructed_payload().is_some()
    }

    ///
    /// Returns error flag value of the payload state
    ///
    fn failed(&self) -> bool {
        self.error
    }

    ///
    /// Sets error flag
    ///
    fn set_error(&mut self) {
        self.error = true;
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Display for NetworkPayloadState<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "NetworkPayloadState")?;
        writeln!(f, "\t header: {}", self.header)?;
        if let Some(chunk_meta) = &self.owned_chunk_meta {
            writeln!(f, "\t owned_chunk_meta: {}", chunk_meta)?;
        }
        writeln!(f, "\t received pieces: {:?}", &self.received_pieces)?;
        writeln!(f, "\t received chunks: {:?}", &self.received_chunks)?;
        writeln!(
            f,
            "\t reconstructed data: {:?}",
            self.reconstructed_payload.as_ref().map(|p| p.len())
        )?;
        writeln!(
            f,
            "\t codec settings: {:?} - {:?}",
            self.codec.committee_settings(),
            self.codec.network_settings()
        )?;
        writeln!(f, "\t error: {}", self.error)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> PayloadDataSettings<C> for NetworkPayloadState<C> {
    fn decoder(&mut self) -> &mut SupraDeliveryCodec<C> {
        self.codec_mut()
    }

    fn settings(&self) -> <<C as SupraDeliveryErasureCodecSchema>::DataCodec as Codec>::Setting {
        self.codec().network_settings().unwrap()
    }

    ///
    /// List of network chunks' indexes received so far
    ///
    fn get_received_chunks(&self) -> HashSet<usize> {
        self.received_chunks.clone()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> NetworkChunkDataSettings<C> for NetworkPayloadState<C> {
    fn decoder(&mut self) -> &mut SupraDeliveryCodec<C> {
        self.share_codec_mut()
    }

    fn settings(&self) -> <C::DataCodec as Codec>::Setting {
        self.share_codec().committee_settings()
    }

    fn owned_chunk_meta(&self) -> &Option<CommitmentMeta> {
        &self.owned_chunk_meta
    }

    ///
    /// List of indexes of the owned chunk pieces received so far
    ///
    fn get_received_pieces(&self) -> HashSet<usize> {
        self.received_pieces.clone()
    }
}
