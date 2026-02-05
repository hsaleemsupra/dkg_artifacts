use crate::tasks::codec::{
    SupraDeliveryCodec, SupraDeliveryErasureCodec, SupraDeliveryErasureCodecSchema,
};
use crate::tasks::errors::RBCError;
use crate::types::messages::chunk::{ChunkData, NetworkChunk};
use crate::types::payload_state::vote_store::VoteStore;
use crate::types::payload_state::{PayloadDataSettings, PayloadFlags};
use crypto::PartialShare;
use erasure::utils::codec_trait::Codec;
use metrics::{impl_timestamp, nanoseconds_since_unix_epoch, MetricTag, Timestamp};
use primitives::types::header::{Header, HeaderIfc};
use primitives::types::QuorumCertificate;
use primitives::Payload;
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};

///
/// Common interface to check payload certification
///
pub(crate) trait CommitteePayloadFlags: PayloadFlags {
    ///
    /// Indicates whether Quorum Certification is registered for the deliverable
    ///
    fn is_certified(&self) -> bool;
}

pub(crate) struct ReconstructedData<C: SupraDeliveryErasureCodecSchema> {
    payload: Vec<u8>,
    committee_chunks: Vec<ChunkData<C>>,
    network_chunks: Vec<NetworkChunk<C>>,
}

impl<C: SupraDeliveryErasureCodecSchema> Debug for ReconstructedData<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReconstructedData")?;
        write!(f, "(payload_size: {}", &self.payload.len())?;
        write!(f, ", committee chunks: {}", &self.committee_chunks.len())?;
        write!(f, ", network chunks: {})", &self.network_chunks.len())
    }
}

impl<C: SupraDeliveryErasureCodecSchema> ReconstructedData<C> {
    pub(crate) fn new(
        payload: Vec<u8>,
        committee_chunks: Vec<ChunkData<C>>,
        network_chunks: Vec<NetworkChunk<C>>,
    ) -> Self {
        Self {
            payload,
            committee_chunks,
            network_chunks,
        }
    }

    pub(crate) fn from_payload(payload: Vec<u8>) -> Self {
        Self {
            payload,
            committee_chunks: vec![],
            network_chunks: vec![],
        }
    }

    pub(crate) fn take_payload(&mut self) -> Payload {
        let mut payload = Payload::new();
        std::mem::swap(&mut payload, &mut self.payload);
        payload
    }

    pub(crate) fn payload(&self) -> &Payload {
        &self.payload
    }

    pub(crate) fn take_committee_chunks(&mut self) -> Vec<ChunkData<C>> {
        let mut chunks = vec![];
        std::mem::swap(&mut chunks, &mut self.committee_chunks);
        chunks
    }

    pub(crate) fn committee_chunks(&self) -> &Vec<ChunkData<C>> {
        &self.committee_chunks
    }

    pub(crate) fn take_network_chunks(&mut self) -> Vec<NetworkChunk<C>> {
        let mut chunks = vec![];
        std::mem::swap(&mut chunks, &mut self.network_chunks);
        chunks
    }

    pub(crate) fn network_chunks(&self) -> &Vec<NetworkChunk<C>> {
        &self.network_chunks
    }
}

///
/// Intermediate state of the deliverable in committee
///
/// It stores intermediate data received related to the deliverable during delivery time.
pub struct CommitteePayloadState<Schema: SupraDeliveryErasureCodecSchema> {
    /// Received data from committee network is stored in codec
    /// Codec configured with current delivery setting related to intra-committee and intra-network
    codec: SupraDeliveryCodec<Schema>,
    /// Header of the deliverable (id, commitment, broadcaster-origin)
    header: Header,
    /// Indexes of the chunks received so far
    received_chunks: HashSet<usize>,
    /// Indexes of the peers which are registered to have all chunks
    peers_with_all_chunk: HashSet<usize>,
    /// Votes received for the deliverable from committee/clan members
    votes: VoteStore,
    /// Quorum Certificate of the committee/clan for the deliverable
    certificate: Option<QuorumCertificate>,
    /// Owned ChunkData
    owned_chunk: Option<ChunkData<Schema>>,

    reconstructed_data: Option<ReconstructedData<Schema>>,

    /// Error flag indicating invalid delivery state
    error: bool,

    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(
    timestamp,
    CommitteePayloadState<Schema: SupraDeliveryErasureCodecSchema>
);

pub(crate) enum CommitteePayloadTag {
    TagName,
    QCCreation,
    QC,
    Delivery,
    DeliveryEnd,
    DeliveryEndSince,
}

impl Display for CommitteePayloadTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CommitteePayloadTag::TagName => write!(f, "committee-task"),
            CommitteePayloadTag::QCCreation => write!(f, "qc-creation-time"),
            CommitteePayloadTag::QC => write!(f, "qc-time"),
            CommitteePayloadTag::Delivery => write!(f, "delivery-time"),
            CommitteePayloadTag::DeliveryEnd => write!(f, "delivery-end-time"),
            CommitteePayloadTag::DeliveryEndSince => write!(f, "delivery-end-since-bc"),
        }
    }
}

impl MetricTag for CommitteePayloadTag {}

impl<C: SupraDeliveryErasureCodecSchema> MetricTag for CommitteePayloadState<C> {}

impl<C: SupraDeliveryErasureCodecSchema> Display for CommitteePayloadState<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "CommitteePayloadState")?;
        writeln!(f, "\t header: {}", self.header)?;
        writeln!(f, "\t received chunks: {:?}", &self.received_chunks)?;
        writeln!(f, "\t votes: {}", self.votes)?;
        writeln!(f, "\t is certified: {}", &self.certificate.is_some())?;
        writeln!(f, "\t reconstructed data: {:?}", self.reconstructed_data)?;
        writeln!(
            f,
            "\t codec settings: {:?} - {:?}",
            self.codec.committee_settings(),
            self.codec.network_settings()
        )?;
        writeln!(f, "\t error: {}", self.error)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> HeaderIfc for CommitteePayloadState<C> {
    fn header(&self) -> &Header {
        &self.header
    }
}

impl<C: SupraDeliveryErasureCodecSchema> CommitteePayloadState<C> {
    pub(crate) fn new(header: Header, codec: SupraDeliveryCodec<C>) -> Self {
        Self {
            codec,
            header,
            received_chunks: Default::default(),
            peers_with_all_chunk: Default::default(),
            votes: Default::default(),
            certificate: None,
            owned_chunk: None,
            reconstructed_data: None,
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

    pub(crate) fn set_reconstructed_data(&mut self, reconstructed_data: ReconstructedData<C>) {
        self.reconstructed_data = Some(reconstructed_data);
    }

    ///
    /// Returns payload if it was reconstructed
    ///
    pub(crate) fn reconstructed_payload(&self) -> Option<&Payload> {
        self.reconstructed_data.as_ref().map(|data| data.payload())
    }

    pub(crate) fn take_reconstructed_payload(&mut self) -> Option<Payload> {
        self.reconstructed_data
            .as_mut()
            .map(|data| data.take_payload())
    }

    pub(crate) fn all_chunks_len(&self) -> usize {
        self.committee_chunks_len() + self.network_chunks_len()
    }

    ///
    /// Returns list of committee chunks if any
    ///
    pub(crate) fn committee_chunks(&self) -> Option<&Vec<ChunkData<C>>> {
        self.reconstructed_data
            .as_ref()
            .map(|data| data.committee_chunks())
            .filter(|chunks| !chunks.is_empty())
    }

    pub(crate) fn take_committee_chunks(&mut self) -> Option<Vec<ChunkData<C>>> {
        self.reconstructed_data
            .as_mut()
            .map(|data| data.take_committee_chunks())
    }

    ///
    /// Returns length of committee chunks if any or 0
    ///
    pub(crate) fn committee_chunks_len(&self) -> usize {
        self.committee_chunks()
            .map(|chunks| chunks.len())
            .unwrap_or(0)
    }

    ///
    /// Returns list of network_chunks chunks if any
    ///
    pub(crate) fn network_chunks(&self) -> Option<&Vec<NetworkChunk<C>>> {
        self.reconstructed_data
            .as_ref()
            .map(|data| data.network_chunks())
            .filter(|chunks| !chunks.is_empty())
    }

    pub(crate) fn take_network_chunks(&mut self) -> Option<Vec<NetworkChunk<C>>> {
        self.reconstructed_data
            .as_mut()
            .map(|data| data.take_network_chunks())
    }

    ///
    /// Returns len of network_chunks chunks if any or 0
    ///
    pub(crate) fn network_chunks_len(&self) -> usize {
        self.network_chunks()
            .map(|chunks| chunks.len())
            .unwrap_or(0)
    }

    ///
    /// Checks whether vote with provided index already received
    ///
    pub(crate) fn has_vote(&self, index: u32) -> bool {
        self.votes.has_vote(&index)
    }

    pub(crate) fn add_vote(&mut self, vote: PartialShare) {
        self.store_peer_with_all_chunks(vote.index() as usize);
        self.votes.add_vote(vote)
    }

    pub(crate) fn take_votes(&mut self) -> Vec<PartialShare> {
        self.votes.collect().unwrap_or_default()
    }

    pub(crate) fn get_vote(&self, index: u32) -> Option<PartialShare> {
        self.votes.get_vote(index)
    }

    ///
    /// Number of votes already received
    ///
    pub(crate) fn votes_len(&self) -> usize {
        self.votes.len()
    }

    ///
    /// Returns true if the committee chunk with the mentioned index is received
    ///
    pub(crate) fn has_chunk(&self, index: usize) -> bool {
        self.received_chunks.contains(&index)
    }

    ///
    /// Adds input chunk information to the payload state
    /// Does not check duplication,it's up to user to avoid adding duplicate data
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
    /// Adds origin as peer with all chunks
    ///
    pub(crate) fn store_peer_with_all_chunks(&mut self, index: usize) {
        self.peers_with_all_chunk.insert(index);
    }

    ///
    /// Peer indexes in the current clan having reconstructed data
    ///
    pub(crate) fn peers_with_all_chunks(&self) -> &HashSet<usize> {
        &self.peers_with_all_chunk
    }

    ///
    /// Sets QuorumCertificate of the payload
    ///
    pub(crate) fn set_certificate(&mut self, certificate: QuorumCertificate) {
        self.certificate = Some(certificate);
    }

    pub(crate) fn certificate(&self) -> &Option<QuorumCertificate> {
        &self.certificate
    }

    pub(crate) fn take_certificate(&mut self) -> Option<QuorumCertificate> {
        self.certificate.take()
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

impl<C: SupraDeliveryErasureCodecSchema> PayloadFlags for CommitteePayloadState<C> {
    ///
    /// True if the deliverable is fully reconstructed, header and all chunks are available
    ///
    fn is_reconstructed(&self) -> bool {
        self.has_payload_data()
            && self.committee_chunks_len() == self.codec().total_committee_chunks()
            && self.network_chunks_len() == self.codec().total_network_chunks()
    }

    ///
    /// True if reconstructed data is available
    ///
    fn has_payload_data(&self) -> bool {
        self.reconstructed_payload()
            .as_ref()
            .map(|data| !data.is_empty())
            .unwrap_or(false)
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

impl<C: SupraDeliveryErasureCodecSchema> CommitteePayloadFlags for CommitteePayloadState<C> {
    ///
    /// Payload is quorum certified if either there is quorum certificate or integrity certificate
    ///
    fn is_certified(&self) -> bool {
        self.certificate.is_some()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> PayloadDataSettings<C> for CommitteePayloadState<C> {
    fn decoder(&mut self) -> &mut SupraDeliveryCodec<C> {
        self.codec_mut()
    }

    fn settings(&self) -> <C::DataCodec as Codec>::Setting {
        self.codec().committee_settings()
    }

    ///
    /// List of chunks' indexes received so far
    ///
    fn get_received_chunks(&self) -> HashSet<usize> {
        self.received_chunks.clone()
    }
}
