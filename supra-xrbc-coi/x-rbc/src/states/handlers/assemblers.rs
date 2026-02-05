use crate::tasks::codec::{
    EncodeResult, EncodeResultIfc, SupraDeliveryCodec, SupraDeliveryErasureCodec,
    SupraDeliveryErasureCodecSchema,
};
use crate::tasks::errors::RBCError;
use crate::types::context::committee::{CommitteeFSMContext, CommitteeFSMContextSchema};
use crate::types::context::{FSMContext, FSMContextOwner, FSMContextSchema, ResourcesApi};
use crate::types::helpers::verifier_visitor::VerifierVisitor;
use crate::types::messages::chunk::ChunkData;
use crate::types::payload_state::committee::CommitteePayloadState;
use crate::types::payload_state::{NetworkChunkDataSettings, PayloadDataSettings};
use erasure::utils::codec_trait::Codec;
use erasure::utils::errors::FECError;
use primitives::serde::bincode_deserialize_custom;
use primitives::types::HeaderIfc;
use primitives::Payload;
use vec_commitment::committed_chunk::CommittedChunk;

///
/// Generic interface to assemble and verify the chunked data stored in the provided context
///
pub(crate) trait GenericAssembler<ContextSchema>
where
    ContextSchema: FSMContextSchema,
    Self: FSMContextOwner<Schema = ContextSchema>,
{
    ///
    /// Type of the final assembled data
    ///
    type Result;

    ///
    /// Generic implementation of the assembling logic
    /// Data is decoded, processed and verified
    ///
    /// If no enough data is present to assemble the data then None is returned
    /// If any error has encountered during decoding and/or farther processing and verification
    /// then error will be reported.
    /// Otherwise reconstructed data is returned upon successful decoding and verification
    ///
    fn try_assemble(&mut self) -> Result<Option<Self::Result>, RBCError> {
        if !self.has_required_data() {
            return Ok(None);
        }
        let maybe_reconstructed = self.get_reconstructed_data();
        match maybe_reconstructed {
            Ok(reconstructed_payload) => self
                .process_reconstructed_data(reconstructed_payload)
                .and_then(|maybe_data| self.verify_reconstructed_data(maybe_data))
                .map(Some),
            Err(RBCError::FECError(FECError::NotEnoughData)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    ///
    /// Returns codec to be used to decode the payload
    /// it is assumed that decoder has been fed with the data to be decoded
    ///
    fn decoder(&mut self) -> &mut SupraDeliveryCodec<ContextSchema::CodecSchema>;

    ///
    /// Returns settings based on which decoding should happen
    /// it is assumed that decoder has been fed with the data to be decoded
    ///
    fn settings(&self) -> <<<ContextSchema as FSMContextSchema>::CodecSchema as SupraDeliveryErasureCodecSchema>::DataCodec as Codec>::Setting;

    ///
    /// Processes reconstructed raw data
    ///
    fn process_reconstructed_data(&mut self, payload: Payload) -> Result<Self::Result, RBCError>;

    ///
    /// Verifies final reconstructed data
    ///
    fn verify_reconstructed_data(&self, data: Self::Result) -> Result<Self::Result, RBCError>;

    ///
    /// Predicate indicating whether the decoding can be done
    ///
    fn has_required_data(&self) -> bool {
        true
    }

    ///
    /// Returns reconstructed data if any
    ///
    fn get_reconstructed_data(&mut self) -> Result<Payload, RBCError> {
        let settings = self.settings();
        self.decoder().decode(settings)
    }
}

///
/// Generic structure to assemble from the pieces and verify the network chunk data stored in
/// the provided context
///
pub(crate) struct NetworkChunkAssembler<'a, ContextSchema: FSMContextSchema>(
    pub &'a mut FSMContext<ContextSchema>,
);

impl<'a, ContextSchema: FSMContextSchema> FSMContextOwner
    for NetworkChunkAssembler<'a, ContextSchema>
{
    type Schema = ContextSchema;

    fn context(&self) -> &FSMContext<Self::Schema> {
        self.0
    }

    fn context_mut(&mut self) -> &mut FSMContext<Self::Schema> {
        self.0
    }
}

impl<'a, ContextSchema: FSMContextSchema> GenericAssembler<ContextSchema>
    for NetworkChunkAssembler<'a, ContextSchema>
where
    ContextSchema::PayloadStateType: NetworkChunkDataSettings<ContextSchema::CodecSchema>,
{
    type Result = ChunkData<ContextSchema::CodecSchema>;

    fn decoder(&mut self) -> &mut SupraDeliveryCodec<ContextSchema::CodecSchema> {
        self.payload_state_mut().decoder()
    }

    fn settings(&self) -> <<ContextSchema::CodecSchema as SupraDeliveryErasureCodecSchema>::DataCodec as Codec>::Setting{
        self.payload_state().settings()
    }

    fn process_reconstructed_data(&mut self, payload: Payload) -> Result<Self::Result, RBCError> {
        let chunk = bincode_deserialize_custom::<<<ContextSchema::CodecSchema as SupraDeliveryErasureCodecSchema>::DataCodec as Codec>::Chunk>(&payload)
            .map_err(RBCError::CommonError)?;
        let (index, proof) = self
            .payload_state()
            .owned_chunk_meta()
            .clone()
            .unwrap()
            .split();
        let committed_chunk = CommittedChunk::new(index, proof, chunk);
        Ok(ChunkData::new(committed_chunk))
    }

    fn verify_reconstructed_data(&self, chunk: Self::Result) -> Result<Self::Result, RBCError> {
        VerifierVisitor::new(self.resources())
            .verify_chunk_data(*self.payload_state().commitment(), &chunk)
            .is_ok()
            .then_some(chunk)
            .ok_or(RBCError::MessageProcessingError(
                "Failed to verify reconstructed chunk".to_string(),
            ))
    }

    fn has_required_data(&self) -> bool {
        self.payload_state().owned_chunk_meta().is_some()
    }
}

///
/// Generic structure to assemble and verify the chunked payload data stored in the provided context
///
pub(crate) struct PayloadAssembler<'a, ContextSchema: FSMContextSchema>(
    pub &'a mut FSMContext<ContextSchema>,
);
impl<'a, ContextSchema: FSMContextSchema> FSMContextOwner for PayloadAssembler<'a, ContextSchema> {
    type Schema = ContextSchema;

    fn context(&self) -> &FSMContext<Self::Schema> {
        self.0
    }

    fn context_mut(&mut self) -> &mut FSMContext<Self::Schema> {
        self.0
    }
}

impl<'a, ContextSchema: FSMContextSchema> GenericAssembler<ContextSchema>
    for PayloadAssembler<'a, ContextSchema>
where
    ContextSchema::PayloadStateType: PayloadDataSettings<ContextSchema::CodecSchema>,
{
    type Result = (Payload, EncodeResult<ContextSchema::CodecSchema>);

    fn decoder(&mut self) -> &mut SupraDeliveryCodec<ContextSchema::CodecSchema> {
        self.payload_state_mut().decoder()
    }

    fn settings(&self) -> <<ContextSchema::CodecSchema as SupraDeliveryErasureCodecSchema>::DataCodec as Codec>::Setting{
        self.payload_state().settings()
    }

    fn process_reconstructed_data(&mut self, payload: Payload) -> Result<Self::Result, RBCError> {
        self.decoder()
            .clone()
            .encode(payload.clone(), self.authenticator())
            .map(|result| (payload, result))
    }

    fn verify_reconstructed_data(&self, data: Self::Result) -> Result<Self::Result, RBCError> {
        let (payload, result) = data;
        if result.header().commitment() != self.payload_state().commitment() {
            Err(RBCError::InvalidDeliverable(*self.payload_state().origin()))
        } else {
            Ok((payload, result))
        }
    }
}

///
/// Chunk constructor and payload verifier from received full payload data
///
pub(crate) struct ReconstructedDataAssembler<'a, C: SupraDeliveryErasureCodecSchema>(
    pub &'a mut CommitteeFSMContext<C>,
);

impl<'a, C: SupraDeliveryErasureCodecSchema> FSMContextOwner for ReconstructedDataAssembler<'a, C> {
    type Schema = CommitteeFSMContextSchema<C>;

    fn context(&self) -> &FSMContext<Self::Schema> {
        self.0
    }

    fn context_mut(&mut self) -> &mut FSMContext<Self::Schema> {
        self.0
    }
}

impl<'a, C: SupraDeliveryErasureCodecSchema> GenericAssembler<CommitteeFSMContextSchema<C>>
    for ReconstructedDataAssembler<'a, C>
where
    Self: FSMContextOwner<Schema = CommitteeFSMContextSchema<C>>,
{
    type Result = (Payload, EncodeResult<C>);

    fn decoder(&mut self) -> &mut SupraDeliveryCodec<C> {
        self.payload_state_mut().decoder()
    }

    fn settings(&self) -> <<C as SupraDeliveryErasureCodecSchema>::DataCodec as Codec>::Setting {
        self.payload_state().settings()
    }

    fn process_reconstructed_data(&mut self, payload: Payload) -> Result<Self::Result, RBCError> {
        self.decoder()
            .clone()
            .encode(payload.clone(), self.authenticator())
            .map(|result| (payload, result))
    }

    fn verify_reconstructed_data(&self, data: Self::Result) -> Result<Self::Result, RBCError> {
        let (payload, result) = data;
        if result.header().commitment() != self.payload_state().commitment() {
            Err(RBCError::InvalidDeliverable(*self.payload_state().origin()))
        } else {
            Ok((payload, result))
        }
    }

    fn get_reconstructed_data(&mut self) -> Result<Payload, RBCError> {
        self.payload_state_mut()
            .take_reconstructed_payload()
            .ok_or_else(|| RBCError::FECError(FECError::NotEnoughData))
    }
}
