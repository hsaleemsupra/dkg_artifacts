use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::context::{FSMContext, FSMContextSchema};
use crate::types::messages::CommitteeFSMResponseMessage;
use crate::types::payload_state::committee::CommitteePayloadState;
use std::marker::PhantomData;

///
/// Committee FSM context schema
///
pub(crate) struct CommitteeFSMContextSchema<C: SupraDeliveryErasureCodecSchema> {
    _phantom: PhantomData<C>,
}

impl<C: SupraDeliveryErasureCodecSchema> FSMContextSchema for CommitteeFSMContextSchema<C> {
    type PayloadStateType = CommitteePayloadState<C>;
    type ResponseType = CommitteeFSMResponseMessage<C>;
    type CodecSchema = C;
}

pub(crate) type CommitteeFSMContext<C> = FSMContext<CommitteeFSMContextSchema<C>>;
