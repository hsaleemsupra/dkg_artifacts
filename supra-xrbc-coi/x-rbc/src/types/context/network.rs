use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::context::{FSMContext, FSMContextSchema};
use crate::types::messages::NetworkFSMResponseMessage;
use crate::types::payload_state::network::NetworkPayloadState;
use std::marker::PhantomData;

///
/// Network FSM context schema
///
pub(crate) struct NetworkFSMContextSchema<C: SupraDeliveryErasureCodecSchema> {
    _phantom: PhantomData<C>,
}

impl<C: SupraDeliveryErasureCodecSchema> FSMContextSchema for NetworkFSMContextSchema<C> {
    type PayloadStateType = NetworkPayloadState<C>;
    type ResponseType = NetworkFSMResponseMessage<C>;
    type CodecSchema = C;
}

pub(crate) type NetworkFSMContext<C> = FSMContext<NetworkFSMContextSchema<C>>;
