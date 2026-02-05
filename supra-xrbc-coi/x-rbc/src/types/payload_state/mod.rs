use crate::tasks::codec::{SupraDeliveryCodec, SupraDeliveryErasureCodecSchema};
use erasure::utils::codec_trait::Codec;
use std::collections::HashSet;
use vec_commitment::committed_chunk::CommitmentMeta;

pub(crate) mod committee;
pub(crate) mod network;
pub(crate) mod sync;
pub(crate) mod vote_store;

///
/// Common interface to check payload/deliverable state during delivery
///
pub(crate) trait PayloadFlags {
    ///
    /// Indicates the deliverable reconstruction status along with chunks
    ///
    fn is_reconstructed(&self) -> bool;

    ///
    /// Indicates the deliverable data availability
    ///
    fn has_payload_data(&self) -> bool;

    ///
    /// Indicates the deliverable error status
    ///
    fn failed(&self) -> bool;

    ///
    /// Sets error flag to the current state
    ///
    fn set_error(&mut self);
}

///
/// Interface to retrieve Payload reconstruction means/properties to assemble it
///
pub(crate) trait PayloadDataSettings<C: SupraDeliveryErasureCodecSchema> {
    fn decoder(&mut self) -> &mut SupraDeliveryCodec<C>;
    fn settings(&self) -> <C::DataCodec as Codec>::Setting;
    fn get_received_chunks(&self) -> HashSet<usize>;
}

///
/// Interface to retrieve Network Chunk reconstruction means/properties to assemble it
///
pub(crate) trait NetworkChunkDataSettings<C: SupraDeliveryErasureCodecSchema> {
    fn decoder(&mut self) -> &mut SupraDeliveryCodec<C>;
    fn settings(&self) -> <C::DataCodec as Codec>::Setting;
    fn owned_chunk_meta(&self) -> &Option<CommitmentMeta>;
    fn get_received_pieces(&self) -> HashSet<usize>;
}
