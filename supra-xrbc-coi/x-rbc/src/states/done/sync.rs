use crate::states::done::Done;
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::LoggingName;
use crate::types::context::sync::{SyncFSMContext, SyncFSMContextSchema};
use crate::types::context::FSMContextOwner;
use crate::types::messages::{ResponseTypeIfc, SyncFSMResponseMessage};
use crate::types::payload_state::PayloadFlags;
use crate::FeedbackMessage;
use log::info;
use primitives::types::HeaderIfc;
use sfsm::{ReturnMessage, State};

pub(crate) type DoneSyncFSM<C> = Done<SyncFSMContext<C>>;

impl<C: SupraDeliveryErasureCodecSchema> FSMContextOwner for DoneSyncFSM<C> {
    type Schema = SyncFSMContextSchema<C>;
    fn context(&self) -> &SyncFSMContext<C> {
        &self.context
    }

    fn context_mut(&mut self) -> &mut SyncFSMContext<C> {
        &mut self.context
    }
}

impl<C: SupraDeliveryErasureCodecSchema> LoggingName for DoneSyncFSM<C> {
    fn name<'a>() -> &'a str {
        "DoneSyncFSM"
    }
}

impl<C: SupraDeliveryErasureCodecSchema> State for DoneSyncFSM<C> {
    fn execute(&mut self) {
        if self.payload_state().failed() {
            return;
        }
        let id = self.payload_state().get_meta();
        let msg = FeedbackMessage::done_msg(id);
        info!("{}: {}", Self::name(), msg);
        self.response_mut().add_feedback(msg);
    }
}

impl<C: SupraDeliveryErasureCodecSchema> ReturnMessage<SyncFSMResponseMessage<C>>
    for DoneSyncFSM<C>
{
    fn return_message(&mut self) -> Option<SyncFSMResponseMessage<C>> {
        self.take_response()
    }
}
