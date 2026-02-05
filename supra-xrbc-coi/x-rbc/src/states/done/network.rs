use crate::states::done::Done;
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::LoggingName;
use crate::types::context::network::{NetworkFSMContext, NetworkFSMContextSchema};
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::messages::{NetworkFSMResponseMessage, ResponseTypeIfc};
use crate::types::payload_state::network::NetworkPayloadTag;
use crate::types::payload_state::PayloadFlags;
use crate::FeedbackMessage;
use log::info;
use metrics::{duration_since_unix_epoch, report, MetricValue, SystemThroughput, TimeStampTrait};
use primitives::types::HeaderIfc;
use sfsm::{ReturnMessage, State};
use storage::StorageWriteIfc;

pub(crate) type DoneNetworkFSM<C> = Done<NetworkFSMContext<C>>;

impl<C: SupraDeliveryErasureCodecSchema> FSMContextOwner for DoneNetworkFSM<C> {
    type Schema = NetworkFSMContextSchema<C>;
    fn context(&self) -> &NetworkFSMContext<C> {
        &self.context
    }

    fn context_mut(&mut self) -> &mut NetworkFSMContext<C> {
        &mut self.context
    }
}

impl<C: SupraDeliveryErasureCodecSchema> LoggingName for DoneNetworkFSM<C> {
    fn name<'a>() -> &'a str {
        "DoneNetworkFSM"
    }
}

impl<C: SupraDeliveryErasureCodecSchema> State for DoneNetworkFSM<C> {
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

impl<C: SupraDeliveryErasureCodecSchema> ReturnMessage<NetworkFSMResponseMessage<C>>
    for DoneNetworkFSM<C>
{
    fn return_message(&mut self) -> Option<NetworkFSMResponseMessage<C>> {
        self.take_response()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> DoneNetworkFSM<C> {
    fn report(&self, reconstruction_size: usize) {
        report(
            &[
                &NetworkPayloadTag::DeliveryEnd,
                self.payload_state().header(),
                &NetworkPayloadTag::TagName,
            ],
            MetricValue::AsSeconds(self.payload_state().elapsed_time()),
        );

        report(
            &[
                &NetworkPayloadTag::DeliveryEndSince,
                self.payload_state().header(),
                &NetworkPayloadTag::TagName,
            ],
            MetricValue::AsSeconds(self.payload_state().header().elapsed_time()),
        );

        report(
            &[
                &SystemThroughput::BatchStoring,
                self.payload_state().header(),
                &NetworkPayloadTag::TagName,
            ],
            MetricValue::AsNanoSeconds(duration_since_unix_epoch()),
        );

        report(
            &[
                &SystemThroughput::ReconstructedSize,
                self.payload_state().header(),
                &NetworkPayloadTag::TagName,
            ],
            MetricValue::AsBytes(reconstruction_size),
        );
    }
}
