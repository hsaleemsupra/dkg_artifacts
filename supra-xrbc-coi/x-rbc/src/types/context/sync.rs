use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::context::{FSMContext, FSMContextSchema};
use crate::types::messages::SyncFSMResponseMessage;
use crate::types::payload_state::sync::SyncPayloadState;
use std::marker::PhantomData;

///
/// Sync FSM context schema
///
pub(crate) struct SyncFSMContextSchema<C: SupraDeliveryErasureCodecSchema> {
    _phantom: PhantomData<C>,
}
impl<C: SupraDeliveryErasureCodecSchema> FSMContextSchema for SyncFSMContextSchema<C> {
    type PayloadStateType = SyncPayloadState<C>;
    type ResponseType = SyncFSMResponseMessage<C>;
    type CodecSchema = C;
}

pub(crate) type SyncFSMContext<C> = FSMContext<SyncFSMContextSchema<C>>;
