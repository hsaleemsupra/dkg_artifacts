use crate::states::done::Done;
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::LoggingName;
use crate::types::context::committee::{CommitteeFSMContext, CommitteeFSMContextSchema};
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::messages::{CommitteeFSMResponseMessage, ResponseTypeIfc};
use crate::types::payload_state::committee::CommitteePayloadTag;
use crate::types::payload_state::PayloadFlags;
use crate::FeedbackMessage;
use log::info;
use metrics::{duration_since_unix_epoch, report, MetricValue, SystemThroughput, TimeStampTrait};
use primitives::types::HeaderIfc;
use sfsm::{ReturnMessage, State};
use storage::StorageWriteIfc;

pub(crate) type DoneCommitteeFSM<C> = Done<CommitteeFSMContext<C>>;

impl<C: SupraDeliveryErasureCodecSchema> FSMContextOwner for DoneCommitteeFSM<C> {
    type Schema = CommitteeFSMContextSchema<C>;
    fn context(&self) -> &CommitteeFSMContext<C> {
        &self.context
    }

    fn context_mut(&mut self) -> &mut CommitteeFSMContext<C> {
        &mut self.context
    }
}

impl<C: SupraDeliveryErasureCodecSchema> LoggingName for DoneCommitteeFSM<C> {
    fn name<'a>() -> &'a str {
        "DoneCommitteeFSM"
    }
}

impl<C: SupraDeliveryErasureCodecSchema> State for DoneCommitteeFSM<C> {
    fn execute(&mut self) {
        if self.payload_state().failed() {
            return;
        }
        let payload = self
            .payload_state_mut()
            .take_reconstructed_payload()
            .unwrap();
        let reconstruction_size = payload.len();
        let storage_key = self.payload_state().header().hash();
        self.resource_mut()
            .storage_client()
            .write(storage_key, payload);

        self.report(reconstruction_size);

        let id = self.payload_state().header().get_meta();
        let msg = FeedbackMessage::done_msg(id);
        info!("{}: {}", Self::name(), msg);
        self.response_mut().add_feedback(msg);
    }
}

impl<C: SupraDeliveryErasureCodecSchema> ReturnMessage<CommitteeFSMResponseMessage<C>>
    for DoneCommitteeFSM<C>
{
    fn return_message(&mut self) -> Option<CommitteeFSMResponseMessage<C>> {
        self.take_response()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> DoneCommitteeFSM<C> {
    fn report(&self, reconstruction_size: usize) {
        report(
            &[
                &CommitteePayloadTag::DeliveryEnd,
                self.payload_state().header(),
                &CommitteePayloadTag::TagName,
            ],
            MetricValue::AsSeconds(self.payload_state().elapsed_time()),
        );

        report(
            &[
                &CommitteePayloadTag::DeliveryEndSince,
                self.payload_state().header(),
                &CommitteePayloadTag::TagName,
            ],
            MetricValue::AsSeconds(self.payload_state().header().elapsed_time()),
        );

        report(
            &[
                &SystemThroughput::BatchStoring,
                self.payload_state().header(),
                &CommitteePayloadTag::TagName,
            ],
            MetricValue::AsNanoSeconds(duration_since_unix_epoch()),
        );

        report(
            &[
                &SystemThroughput::ReconstructedSize,
                self.payload_state().header(),
                &CommitteePayloadTag::TagName,
            ],
            MetricValue::AsBytes(reconstruction_size),
        );
    }
}
