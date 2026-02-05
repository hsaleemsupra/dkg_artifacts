use crate::states::done::Done;
use crate::states::handlers::{
    FSMErrorHandler, GenericAssembler, InputVerifier, NetworkChunkAssembler, NetworkMessageHandler,
    NetworkMessageReceiver, PayloadAssembler, PullRequestBroadcaster,
    PullRequestBroadcasterNetwork,
};
use crate::states::DoneNetworkFSM;
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::errors::RBCError;
use crate::tasks::LoggingName;
use crate::types::context::network::{NetworkFSMContext, NetworkFSMContextSchema};
use crate::types::context::{FSMContext, FSMContextOwner, ResourcesApi};
use crate::types::helpers::message_factory::{MessageFactoryTrait, MessageFrom};
use crate::types::helpers::Visitor;
use crate::types::messages::chunk::ChunkData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    EchoShareData, NetworkFSMResponseMessage, RBCNetworkMessage, ResponseTypeIfc, ShareData,
    ValueData,
};
use crate::types::payload_state::network::NetworkPayloadTag;
use crate::types::payload_state::PayloadFlags;
use crate::FeedbackMessage;
use log::error;
use log::info;
use metrics::{
    impl_timestamp, nanoseconds_since_unix_epoch, report, MetricValue, TimeStampTrait, Timestamp,
};
use primitives::types::HeaderIfc;
use primitives::{Origin, Protocol};
use sfsm::{ReceiveMessage, ReturnMessage, State, TransitGuard, Transition};
use vec_commitment::committed_chunk::CommitmentMeta;

pub(crate) struct WaitingForShare<C: SupraDeliveryErasureCodecSchema> {
    context: NetworkFSMContext<C>,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(
    timestamp,
    WaitingForShare<Schema: SupraDeliveryErasureCodecSchema>
);

impl<C: SupraDeliveryErasureCodecSchema> WaitingForShare<C> {
    pub(crate) fn new(context: NetworkFSMContext<C>) -> Self {
        Self {
            context,
            timestamp: nanoseconds_since_unix_epoch(),
        }
    }

    pub(crate) fn try_reconstruct_share(&mut self) -> Result<(), RBCError> {
        if self
            .payload_state()
            .has_chunk(self.owned_chunk_data_index())
        {
            return Ok(());
        }
        NetworkChunkAssembler(self.context_mut())
            .try_assemble()
            .map(|data| {
                if let Some(chunk) = data {
                    report(
                        &[
                            &NetworkPayloadTag::ShareDelivery,
                            self.payload_state().header(),
                            &NetworkPayloadTag::TagName,
                        ],
                        MetricValue::AsSeconds(self.payload_state().elapsed_time()),
                    );
                    self.handle_chunk(chunk)
                }
            })
    }

    pub(crate) fn handle_chunk(&mut self, chunk_data: ChunkData<C>) {
        info!(
            "{} Reconstructed share - {:?} - {:?}",
            Self::name(),
            self.payload_state().header(),
            self.payload_state().owned_chunk_meta(),
        );

        let _ = self.payload_state_mut().add_chunk(chunk_data.clone(), true);
        let value = ValueData::new(self.payload_state().get_header(), chunk_data);
        let echo_share = EchoShareData::new(*self.topology().origin(), value);
        let addresses = self
            .assignment_extractor()
            .visit_echo_share(&echo_share)
            .unwrap();
        let msg = (RBCNetworkMessage::EchoShare(echo_share), addresses);
        info!("{}: {} => {:?}", Self::name(), msg.0, msg.1);
        self.response_mut().add_message(msg);
    }

    ///
    /// send echo share message to the requester
    ///
    pub fn send_echo_share_msg_to_requester(
        &mut self,
        owned_chunk: ChunkData<C>,
        requester: &Origin,
    ) {
        let value_data = ValueData::new(self.payload_state().get_header(), owned_chunk);
        let echo = self.message_factory().message_from(value_data);
        let address = self
            .topology()
            .get_address_by_origin(Protocol::XRBC, requester)
            .unwrap();
        let msg = (RBCNetworkMessage::EchoShare(echo), vec![address]);
        info!("{}: {} => {:?}", Self::name(), msg.0, msg.1);
        self.response_mut().add_message(msg);
    }

    pub(crate) fn try_reconstruct_payload(&mut self) {
        let result = PayloadAssembler(self.context_mut()).try_assemble();
        match result {
            Ok(Some((payload, _encoded_data))) => {
                let state = self.payload_state_mut();
                state.set_reconstructed_payload(Some(payload));
                report(
                    &[
                        &NetworkPayloadTag::Delivery,
                        self.payload_state().header(),
                        &NetworkPayloadTag::TagName,
                    ],
                    MetricValue::AsSeconds(self.payload_state().elapsed_time()),
                );
            }
            Ok(None) => {}
            Err(RBCError::InvalidDeliverable(origin)) => self.register_error_feedback(
                FeedbackMessage::Error(self.payload_state().get_meta(), origin),
            ),
            Err(e) => self.register_internal_error(format!("Failed to reconstruct data: {:?}", e)),
        }
    }

    ///
    /// Store header if current state does not yet contain header details
    ///
    pub(crate) fn store_commitment_meta(&mut self, meta: CommitmentMeta) {
        if self.payload_state().owned_chunk_meta().is_none() {
            self.payload_state_mut().set_owned_chunk_meta(meta)
        }
    }
}
impl<C: SupraDeliveryErasureCodecSchema> FSMContextOwner for WaitingForShare<C> {
    type Schema = NetworkFSMContextSchema<C>;

    fn context(&self) -> &FSMContext<Self::Schema> {
        &self.context
    }

    fn context_mut(&mut self) -> &mut FSMContext<Self::Schema> {
        &mut self.context
    }
}

impl<C: SupraDeliveryErasureCodecSchema> LoggingName for WaitingForShare<C> {
    fn name<'a>() -> &'a str {
        "WaitingForShare"
    }
}

impl<C: SupraDeliveryErasureCodecSchema> State for WaitingForShare<C> {
    fn execute(&mut self) {
        let _ = self
            .try_reconstruct_share()
            .map_err(|e| error!("Failed to reconstruct share: {:?}", e));
        self.try_reconstruct_payload();
    }
}

/// Transition Interface definition from WaitingForShare for NetworkMessageStateMachine

/// ------------------------------------------------------------------------------------------------
/// WaitingForShare -> DoneNetworkFSM
///
impl<C: SupraDeliveryErasureCodecSchema> Into<DoneNetworkFSM<C>> for WaitingForShare<C> {
    fn into(self) -> DoneNetworkFSM<C> {
        Done::new(self.context)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Transition<DoneNetworkFSM<C>> for WaitingForShare<C> {
    fn guard(&self) -> TransitGuard {
        (self.payload_state().is_reconstructed() || self.payload_state().failed()).into()
    }
}

/// Message handling and Response Query interfaces for WaitingForShare state of NetworkMessageStateMachine

impl<C: SupraDeliveryErasureCodecSchema> ReturnMessage<NetworkFSMResponseMessage<C>>
    for WaitingForShare<C>
{
    fn return_message(&mut self) -> Option<NetworkFSMResponseMessage<C>> {
        self.take_response()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> InputVerifier<C, RBCNetworkMessage<C>>
    for WaitingForShare<C>
{
}

impl<C: SupraDeliveryErasureCodecSchema> NetworkMessageReceiver<C> for WaitingForShare<C> {}

impl<C: SupraDeliveryErasureCodecSchema> ReceiveMessage<RBCNetworkMessage<C>>
    for WaitingForShare<C>
{
    fn receive_message(&mut self, message: RBCNetworkMessage<C>) {
        self.handle_message(message)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> NetworkMessageHandler for WaitingForShare<C> {
    type Share = ShareData<C>;
    type EchoShare = EchoShareData<C>;

    fn handle_share(&mut self, msg: Self::Share) {
        let (_sender, value, meta) = msg.split();
        let (_header, chunk) = value.split();
        self.store_commitment_meta(meta);
        self.payload_state_mut().add_piece(chunk).unwrap();
    }

    fn handle_echo_share(&mut self, msg: Self::EchoShare) {
        let (_sender, value) = msg.split();
        let (_header, chunk) = value.split();
        self.payload_state_mut().add_chunk(chunk, false).unwrap();
    }

    fn handle_pull_request(&mut self, msg: PullRequest) {
        let (_, requester) = msg.split();
        if let Some(owned_chunk) = self.payload_state().get_owned_chunk() {
            self.send_echo_share_msg_to_requester(owned_chunk, &requester);
        }
    }

    // TODO: As a cleanup task, remove sync request handling if statement that
    // if there is an active xRBC or C2T task
    // Sync requests from local synchronizer are ignored.
    fn handle_sync_request(&mut self, msg: SyncRequest) {}
}
