use crate::tasks::codec::{
    SupraDeliveryCodec, SupraDeliveryErasureCodec, SupraDeliveryErasureCodecSchema,
};
use crate::tasks::errors::RBCError;
use crate::types::messages::chunk::{ChunkData, NetworkChunk};
use crate::types::payload_state::{NetworkChunkDataSettings, PayloadDataSettings, PayloadFlags};
use erasure::utils::codec_trait::Codec;
use metrics::{impl_timestamp, nanoseconds_since_unix_epoch, MetricTag, Timestamp};
use primitives::types::header::{Header, HeaderIfc};
use primitives::types::QuorumCertificate;
use std::collections::HashSet;
use std::fmt::{Display, Formatter};

use vec_commitment::committed_chunk::CommitmentMeta;

///
/// Payload type of the current node that is being synced
///
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum PayloadType {
    /// For the current node the payload is from its own clan
    Committee = 0,
    /// For the current node the payload from any other clan
    Network = 1,
}

impl Display for PayloadType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadType::Committee => write!(f, "committee"),
            PayloadType::Network => write!(f, "network"),
        }
    }
}

impl PayloadType {
    pub(crate) fn index(&self) -> usize {
        *self as usize
    }
}

///
/// Data structure encapsulating delivery state in case of synchronization
///
pub(crate) struct SyncPayloadState<C: SupraDeliveryErasureCodecSchema> {
    /// Type of the payload that is being delivered/synchronized
    tpy: PayloadType,
    /// List of codecs to decode the data
    /// In case of committee payload reconstruction will require single codec at position 0
    /// In case of network payload reconstruction will require 2 codecs:
    ///     - one for to reconstruct owned network-chunk from pieces received from committee (at position 0)
    ///     - the other one for payload reconstruction from network-chunks (at position 1)
    codecs: Vec<SupraDeliveryCodec<C>>,
    /// Header of the payload to be synced
    header: Header,
    /// Certificate of the payload to be synced
    qc: QuorumCertificate,
    /// List of committee-chunks reconstructed to be shared with the committee-peers
    /// Can be empty in case of Network payload type
    /// Must be not-empty in case of Committee payload type
    committee_chunks: Vec<ChunkData<C>>,
    /// Owned Network chunk meta information
    /// None if payload type is Committee
    /// Can be some if payload type is Network
    owned_network_chunk_meta: Option<CommitmentMeta>,
    /// Chunk and/or it's index owned by the node
    /// It is committee chunk assigned to the current node if payload type is Committee
    /// Otherwise network chunk assigned to the current node if payload type is Network
    owned_chunk: Option<ChunkData<C>>,
    owned_chunk_index: Option<usize>,
    /// Network chunk pieces to be delivered to peers in the network by the current node
    /// It must not be empty in case of Committee payload type and fully reconstructed data
    /// It is empty in case of Network payload type
    network_chunk_pieces: Vec<NetworkChunk<C>>,
    /// Indexes of the committee-chunks received so far
    /// It is indexes of the committee-chunks in case of Committee payload type
    /// It is indexes of the network-chunk-pieces in case of Network payload type
    received_committee_chunks: HashSet<usize>,
    /// Indexes of the network-chunks received so far
    /// It is indexes of the committee-chunks in case of Committee payload type
    /// It is indexes of the network-chunk-pieces in case of Network payload type
    received_network_chunks: HashSet<usize>,
    /// Flag indicating error state of the payload delivery
    error: bool,
    /// Flag indicating whether sync process should be finalized
    finalize: bool,
    /// Flag indicating whether the fully reconstructed payload is available
    reconstructed: bool,

    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(
    timestamp,
    SyncPayloadState<Schema: SupraDeliveryErasureCodecSchema>
);

pub(crate) enum SyncPayloadTag {
    TagName(PayloadType),
    DeliveryEnd,
}

impl Display for SyncPayloadTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncPayloadTag::TagName(payload_type) => write!(f, "sync-task-{}", payload_type),
            SyncPayloadTag::DeliveryEnd => {
                write!(f, "delivery-end-time")
            }
        }
    }
}

impl MetricTag for SyncPayloadTag {}

impl<C: SupraDeliveryErasureCodecSchema> Display for SyncPayloadState<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "SyncPayloadState")?;
        writeln!(f, "\t header: {}", self.header)?;
        writeln!(f, "\t payload type: {:?}", self.tpy)?;
        writeln!(
            f,
            "\t received committee chunks: {:?}",
            &self.received_committee_chunks
        )?;
        if self.tpy == PayloadType::Network {
            writeln!(
                f,
                "\t received network chunks: {:?}",
                &self.received_committee_chunks
            )?;
            writeln!(
                f,
                "\t owned network chunk meta: {:?}",
                self.owned_network_chunk_meta
            )?;
        }
        writeln!(f, "\t owned chunk index: {:?}", self.owned_chunk_index)?;
        writeln!(f, "\t is reconstructed data: {:?}", self.reconstructed)?;
        writeln!(f, "\t error: {}", self.error)?;
        if let Some(codec) = self.codecs.get(0) {
            writeln!(
                f,
                "\t codec settings: {:?} - {:?}",
                codec.committee_settings(),
                codec.network_settings()
            )?;
        }
        Ok(())
    }
}

impl<C: SupraDeliveryErasureCodecSchema> SyncPayloadState<C> {
    pub(crate) fn for_committee(
        header: Header,
        qc: QuorumCertificate,
        codec: SupraDeliveryCodec<C>,
    ) -> Self {
        Self {
            tpy: PayloadType::Committee,
            codecs: vec![codec],
            header,
            qc,
            committee_chunks: vec![],
            owned_network_chunk_meta: None,
            owned_chunk: None,
            owned_chunk_index: None,
            network_chunk_pieces: vec![],
            received_committee_chunks: Default::default(),
            received_network_chunks: Default::default(),
            error: false,
            finalize: false,
            reconstructed: false,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    pub(crate) fn for_network(
        header: Header,
        qc: QuorumCertificate,
        codec: SupraDeliveryCodec<C>,
    ) -> Self {
        Self {
            tpy: PayloadType::Network,
            codecs: vec![codec.clone(), codec],
            header,
            qc,
            committee_chunks: vec![],
            owned_network_chunk_meta: None,
            owned_chunk: None,
            owned_chunk_index: None,
            network_chunk_pieces: vec![],
            received_committee_chunks: Default::default(),
            received_network_chunks: Default::default(),
            error: false,
            finalize: false,
            reconstructed: false,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    pub(crate) fn ready_for_committee(
        header: Header,
        qc: QuorumCertificate,
        owned_chunk_index: usize,
        committee_chunks: Vec<ChunkData<C>>,
        network_chunk_pieces: Vec<NetworkChunk<C>>,
        codec: SupraDeliveryCodec<C>,
    ) -> Self {
        Self {
            tpy: PayloadType::Committee,
            codecs: vec![codec],
            header,
            qc,
            committee_chunks,
            owned_network_chunk_meta: None,
            owned_chunk: None,
            owned_chunk_index: Some(owned_chunk_index),
            network_chunk_pieces,
            received_committee_chunks: Default::default(),
            received_network_chunks: Default::default(),
            error: false,
            finalize: false,
            reconstructed: true,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    pub(crate) fn ready_for_network(
        header: Header,
        qc: QuorumCertificate,
        owned_network_chunk: ChunkData<C>,
        codec: SupraDeliveryCodec<C>,
    ) -> Self {
        Self {
            tpy: PayloadType::Network,
            codecs: vec![codec.clone(), codec],
            header,
            qc,
            committee_chunks: vec![],
            owned_network_chunk_meta: None,
            owned_chunk_index: Some(owned_network_chunk.data().get_chunk_index()),
            owned_chunk: Some(owned_network_chunk),
            network_chunk_pieces: vec![],
            received_committee_chunks: Default::default(),
            received_network_chunks: Default::default(),
            error: false,
            finalize: false,
            reconstructed: true,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    pub(crate) fn payload_type(&self) -> PayloadType {
        self.tpy
    }

    ///
    /// Returns nodes owned chunk if available
    ///
    pub(crate) fn owned_chunk(&self) -> Option<&ChunkData<C>> {
        if self.is_reconstructed() {
            match self.tpy {
                PayloadType::Committee => self
                    .owned_chunk_index
                    .and_then(|idx| self.committee_chunks.get(idx)),
                PayloadType::Network => self.owned_chunk.as_ref(),
            }
        } else {
            self.owned_chunk.as_ref()
        }
    }

    ///
    /// Returns nodes owned chunk if available
    ///
    pub(crate) fn get_owned_chunk(&self) -> Option<ChunkData<C>> {
        self.owned_chunk().cloned()
    }

    ///
    /// Returns nodes owned chunk index if available
    ///
    pub(crate) fn get_owned_chunk_index(&self) -> Option<usize> {
        self.owned_chunk_index
    }

    ///
    /// Sets owned network chunk meta information
    ///
    pub(crate) fn set_owned_chunk_meta(&mut self, meta: CommitmentMeta) {
        if self.owned_network_chunk_meta.is_none() {
            self.owned_network_chunk_meta = Some(meta)
        }
    }

    ///
    /// Returns codec containing chunks to decode the payload
    ///
    pub(crate) fn payload_codec(&mut self) -> Option<&mut SupraDeliveryCodec<C>> {
        self.codecs.get_mut(self.tpy.index())
    }

    ///
    /// Returns codec containing pieces of the owned network chunk
    ///
    pub(crate) fn chunk_codec(&mut self) -> Option<&mut SupraDeliveryCodec<C>> {
        match self.tpy {
            PayloadType::Committee => None,
            PayloadType::Network => self.codecs.get_mut(PayloadType::Committee.index()),
        }
    }

    ///
    /// Returns list of chunks of the committee
    ///
    pub(crate) fn committee_chunks(&self) -> &Vec<ChunkData<C>> {
        &self.committee_chunks
    }

    ///
    /// Returns list of network-chunk-pieces of the committee
    ///
    pub(crate) fn network_chunk_pieces(&self) -> &Vec<NetworkChunk<C>> {
        &self.network_chunk_pieces
    }

    // API to add chunk and piece data to the current state

    ///
    /// Adds the chunk to the corresponding decoder
    ///
    /// If the chunk is marked as owned chunk, it is stored as it is in owned_chunk properties.
    /// If handling committee-payload, the chunk is added to codec at PayloadType::Committee index
    /// If handling network-payload, the chunk is added to codec at PayloadType::Network  index
    /// It also stores chunk index which is later used to discard duplicate input messages messages
    ///
    /// Error is reported if chunk data can not be added to codec or corresponding coded does not exists
    ///
    pub(crate) fn add_chunk(
        &mut self,
        mut chunk: ChunkData<C>,
        owned: bool,
    ) -> Result<(), RBCError> {
        if owned {
            self.set_owned_chunk(chunk.clone());
        }
        self.store_chunk_index(chunk.data().get_chunk_index());
        self.codecs
            .get_mut(self.tpy.index())
            .ok_or_else(|| {
                RBCError::InvalidPayloadState(format!(
                    "Sync task payload state does not have configured codec for chunk of {:?} payload type: {}",
                    self.tpy, self.header
                ))
            })
            .and_then(|codec| codec.feed(chunk.data_mut().take_chunk()))
    }

    pub(crate) fn set_owned_chunk(&mut self, chunk: ChunkData<C>) {
        self.owned_chunk_index = Some(chunk.data().get_chunk_index());
        self.owned_chunk = Some(chunk);
    }

    ///
    /// Stores chunk index corresponding to payload type
    ///
    pub(crate) fn store_chunk_index(&mut self, chunk_index: usize) {
        match self.tpy {
            PayloadType::Committee => self.received_committee_chunks.insert(chunk_index),
            PayloadType::Network => self.received_network_chunks.insert(chunk_index),
        };
    }

    ///
    /// Returns true if chunk with provided index has been already received, false otherwise
    ///
    pub(crate) fn has_chunk(&self, chunk_index: usize) -> bool {
        match self.tpy {
            PayloadType::Committee => self.received_committee_chunks.contains(&chunk_index),
            PayloadType::Network => self.received_network_chunks.contains(&chunk_index),
        }
    }

    ///
    /// Adds the chunk containing network-chunk-piece to codec at PayloadType::Committee as network
    /// chunk pieces are sent by broadcaster committee/clan members
    ///
    /// It also stores chunk index which is later used to discard duplicate input messages messages
    ///
    /// Error is reported if
    ///     - chunk data can not be added to codec
    ///     - or corresponding coded does not exists
    ///     - or current payload state is configured to handle committee-payload
    ///
    pub(crate) fn add_piece(&mut self, mut chunk: ChunkData<C>) -> Result<(), RBCError> {
        if self.payload_type() != PayloadType::Network {
            return Err(RBCError::InvalidPayloadState(
                "Attempts to add network-chunk piece to committee payload state".to_string(),
            ));
        }
        self.store_piece_index(chunk.data().get_chunk_index());
        self.codecs
            .get_mut(PayloadType::Committee.index())
            .ok_or_else(|| {
                RBCError::InvalidPayloadState(format!(
                    "Sync task payload state does not have configured codec for chunk of {:?} payload type: {}",
                    self.tpy, self.header
                ))
            })
            .and_then(|codec| codec.feed(chunk.data_mut().take_chunk()))
    }

    ///
    /// Returns true if network-chunk-piece with provided index has been already received, false otherwise
    ///
    pub(crate) fn has_piece(&self, piece_index: usize) -> bool {
        match self.tpy {
            PayloadType::Committee => false,
            PayloadType::Network => self.received_committee_chunks.contains(&piece_index),
        }
    }

    ///
    /// Stores chunk index corresponding to payload type
    ///
    pub(crate) fn store_piece_index(&mut self, chunk_index: usize) {
        self.received_committee_chunks.insert(chunk_index);
    }

    ///
    /// Sets reconstructed committee and network piece data
    /// If configured payload type is not Committee then error will be reported
    ///
    pub(crate) fn set_reconstructed_data(
        &mut self,
        owned_chunk_index: usize,
        committee_chunks: Vec<ChunkData<C>>,
        network_pieces: Vec<NetworkChunk<C>>,
    ) -> Result<(), RBCError> {
        if self.tpy != PayloadType::Committee {
            return Err(RBCError::InvalidPayloadState("Attempt to set committee chunk and network piece related info for the network payload".to_string()));
        }
        self.committee_chunks = committee_chunks;
        self.network_chunk_pieces = network_pieces;
        self.owned_chunk_index = Some(owned_chunk_index);
        self.owned_chunk = None;
        if self.has_payload_data() {
            self.set_reconstructed();
        }
        Ok(())
    }

    ///
    /// Returns reference to QC of the deliverable
    ///
    pub(crate) fn qc(&self) -> &QuorumCertificate {
        &self.qc
    }

    ///
    /// Returns QC of the deliverable
    ///
    pub(crate) fn get_qc(&self) -> QuorumCertificate {
        self.qc.clone()
    }

    ///
    /// Sets reconstructed flag to true
    ///
    pub(crate) fn set_reconstructed(&mut self) {
        self.reconstructed = true;
    }

    ///
    /// Sets finalize flag to true
    ///
    pub(crate) fn set_finalize(&mut self) {
        self.finalize = true;
    }

    ///
    /// Sets finalize flag to true
    ///
    pub(crate) fn should_finalize(&self) -> bool {
        self.finalize
    }

    pub(crate) fn network_settings(&self) -> Option<<C::DataCodec as Codec>::Setting> {
        self.codecs[0].network_settings()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> HeaderIfc for SyncPayloadState<C> {
    fn header(&self) -> &Header {
        &self.header
    }
}

impl<C: SupraDeliveryErasureCodecSchema> PayloadFlags for SyncPayloadState<C> {
    fn is_reconstructed(&self) -> bool {
        self.has_payload_data() && self.reconstructed
    }

    fn has_payload_data(&self) -> bool {
        match self.tpy {
            PayloadType::Committee => {
                !self.committee_chunks.is_empty()
                    && (!self.network_chunk_pieces.is_empty() || self.network_settings().is_none())
            }
            PayloadType::Network => self.owned_chunk.is_some(),
        }
    }

    fn failed(&self) -> bool {
        self.error
    }

    ///
    /// Sets error flag to true
    ///
    fn set_error(&mut self) {
        self.error = true;
    }
}

impl<C: SupraDeliveryErasureCodecSchema> PayloadDataSettings<C> for SyncPayloadState<C> {
    fn decoder(&mut self) -> &mut SupraDeliveryCodec<C> {
        self.payload_codec().unwrap()
    }

    fn settings(&self) -> <C::DataCodec as Codec>::Setting {
        match self.payload_type() {
            PayloadType::Committee => self.codecs.get(0).unwrap().committee_settings(),
            PayloadType::Network => self.codecs.get(0).unwrap().network_settings().unwrap(),
        }
    }

    fn get_received_chunks(&self) -> HashSet<usize> {
        match self.payload_type() {
            PayloadType::Committee => self.received_committee_chunks.clone(),
            PayloadType::Network => self.received_network_chunks.clone(),
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> NetworkChunkDataSettings<C> for SyncPayloadState<C> {
    fn decoder(&mut self) -> &mut SupraDeliveryCodec<C> {
        self.chunk_codec().unwrap()
    }

    fn settings(&self) -> <C::DataCodec as Codec>::Setting {
        self.codecs.get(0).unwrap().committee_settings()
    }

    fn owned_chunk_meta(&self) -> &Option<CommitmentMeta> {
        &self.owned_network_chunk_meta
    }

    fn get_received_pieces(&self) -> HashSet<usize> {
        match self.payload_type() {
            PayloadType::Committee => HashSet::new(),
            PayloadType::Network => self.received_committee_chunks.clone(),
        }
    }
}
