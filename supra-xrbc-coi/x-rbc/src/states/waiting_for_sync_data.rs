use crate::states::handlers::{
    FSMErrorHandler, GenericAssembler, InputVerifier, NetworkChunkAssembler, PayloadAssembler,
    PullRequestBroadcaster, PullRequestBroadcasterCommittee, PullRequestBroadcasterNetwork,
    SyncMessageHandler, SyncMessageReceiver, TimeoutMessageHandler,
};
use crate::states::{DoneSyncFSM, SyncReady};
use crate::tasks::codec::{EncodeResult, EncodeResultIfc, SupraDeliveryErasureCodecSchema};
use crate::tasks::errors::RBCError;
use crate::tasks::messages::TimeoutMessage;
use crate::tasks::LoggingName;
use crate::types::context::sync::{SyncFSMContext, SyncFSMContextSchema};
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::helpers::message_factory::{MessageFactoryTrait, MessageFrom};
use crate::types::messages::chunk::ChunkData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    EchoReadyData, EchoShareData, EchoValueData, RBCSyncMessage, ReadyData, ResponseTypeIfc,
    ShareData, SyncFSMResponseMessage, ValueData,
};
use crate::types::payload_state::sync::{PayloadType, SyncPayloadTag};
use crate::types::payload_state::{NetworkChunkDataSettings, PayloadFlags};
use crate::FeedbackMessage;
use log::{error, info};
use metrics::{
    impl_timestamp, nanoseconds_since_unix_epoch, report, MetricValue, TimeStampTrait, Timestamp,
};
use primitives::types::HeaderIfc;
use primitives::{Payload, Protocol};
use sfsm::{ReceiveMessage, ReturnMessage, State, TransitGuard, Transition};
use storage::StorageWriteIfc;

pub(crate) struct WaitingForSyncData<C: SupraDeliveryErasureCodecSchema> {
    context: SyncFSMContext<C>,
    /// Created time in nanoseconds
    timestamp: Timestamp,
}

impl_timestamp!(
    timestamp,
    WaitingForSyncData<Schema: SupraDeliveryErasureCodecSchema>
);

impl<C: SupraDeliveryErasureCodecSchema> WaitingForSyncData<C>
where
    Self: FSMErrorHandler<RBCSyncMessage<C>, SyncFSMContextSchema<C>>,
{
    pub(crate) fn new(context: SyncFSMContext<C>) -> Self {
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
        NetworkChunkAssembler(&mut self.context)
            .try_assemble()
            .map(|data| {
                if let Some(chunk) = data {
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

        let _ = self.payload_state_mut().add_chunk(chunk_data, true);
    }

    pub(crate) fn try_reconstruct_payload(&mut self) {
        let result = PayloadAssembler(&mut self.context).try_assemble();
        match result {
            Ok(Some((payload, encoded_data))) => {
                self.handle_reconstructed_payload(payload, encoded_data);
            }
            Ok(None) => {}
            Err(RBCError::InvalidDeliverable(origin)) => self.register_error_feedback(
                FeedbackMessage::Error(self.payload_state().get_meta(), origin),
            ),
            Err(e) => self.register_internal_error(format!("Failed to reconstruct data: {:?}", e)),
        }
    }

    ///
    /// Stores the reconstructed payload in to the storage and updated local state with reconstructed data
    ///
    pub(crate) fn handle_reconstructed_payload(
        &mut self,
        payload: Payload,
        mut encoded_data: EncodeResult<C>,
    ) {
        self.storage_client()
            .write(self.payload_state().header().hash(), payload);
        let owned_chunk_index = self.owned_chunk_data_index();
        match self.payload_state().payload_type() {
            PayloadType::Committee => {
                let _ = self.payload_state_mut().set_reconstructed_data(
                    owned_chunk_index,
                    encoded_data.take_committee_chunks(),
                    encoded_data.take_network_chunks(),
                );
            }
            PayloadType::Network => {
                if self.payload_state().owned_chunk().is_none() {
                    let owned_chunk = encoded_data
                        .take_network_chunks()
                        .remove(owned_chunk_index)
                        .decode(self.payload_state_mut().chunk_codec().unwrap().clone())
                        .unwrap();
                    self.payload_state_mut().set_owned_chunk(owned_chunk);
                }
                self.payload_state_mut().set_reconstructed();
            }
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> FSMContextOwner for WaitingForSyncData<C> {
    type Schema = SyncFSMContextSchema<C>;
    fn context(&self) -> &SyncFSMContext<C> {
        &self.context
    }

    fn context_mut(&mut self) -> &mut SyncFSMContext<C> {
        &mut self.context
    }
}

impl<C: SupraDeliveryErasureCodecSchema> LoggingName for WaitingForSyncData<C> {
    fn name<'a>() -> &'a str {
        "WaitingForSyncData"
    }
}

impl<C: SupraDeliveryErasureCodecSchema> State for WaitingForSyncData<C> {
    fn execute(&mut self) {
        if self.payload_state().payload_type() == PayloadType::Network {
            let _ = self
                .try_reconstruct_share()
                .map_err(|e| error!("Failed to reconstruct network share: {:?}", e));
        }
        self.try_reconstruct_payload();
    }

    fn exit(&mut self) {
        report(
            &[
                &SyncPayloadTag::DeliveryEnd,
                self.payload_state().header(),
                &SyncPayloadTag::TagName(self.payload_state().payload_type()),
            ],
            MetricValue::AsSeconds(self.payload_state().elapsed_time()),
        );
    }
}

/// Transition Interface definition from WaitingForSyncData for SyncStateMachine

/// ------------------------------------------------------------------------------------------------
/// WaitingForSyncData -> SyncReady
///
impl<C: SupraDeliveryErasureCodecSchema> Into<SyncReady<C>> for WaitingForSyncData<C> {
    fn into(self) -> SyncReady<C> {
        SyncReady::new(self.context)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Transition<SyncReady<C>> for WaitingForSyncData<C> {
    fn guard(&self) -> TransitGuard {
        self.payload_state().is_reconstructed().into()
    }
}

/// ------------------------------------------------------------------------------------------------
/// WaitingForSyncData -> DoneSyncFSM
///
impl<C: SupraDeliveryErasureCodecSchema> Into<DoneSyncFSM<C>> for WaitingForSyncData<C> {
    fn into(self) -> DoneSyncFSM<C> {
        DoneSyncFSM::new(self.context)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Transition<DoneSyncFSM<C>> for WaitingForSyncData<C> {
    fn guard(&self) -> TransitGuard {
        self.payload_state().failed().into()
    }
}

/// Message handling and Response Query interfaces for WaitingForSyncData state of SyncStateMachine

impl<C: SupraDeliveryErasureCodecSchema> ReturnMessage<SyncFSMResponseMessage<C>>
    for WaitingForSyncData<C>
{
    fn return_message(&mut self) -> Option<SyncFSMResponseMessage<C>> {
        self.take_response()
    }
}

impl<C: SupraDeliveryErasureCodecSchema> ReceiveMessage<RBCSyncMessage<C>>
    for WaitingForSyncData<C>
{
    fn receive_message(&mut self, message: RBCSyncMessage<C>) {
        self.handle_message(message)
    }
}
impl<C: SupraDeliveryErasureCodecSchema> ReceiveMessage<TimeoutMessage> for WaitingForSyncData<C> {
    fn receive_message(&mut self, message: TimeoutMessage) {
        self.handle_timeout(message)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> InputVerifier<C, RBCSyncMessage<C>>
    for WaitingForSyncData<C>
{
}
impl<C: SupraDeliveryErasureCodecSchema> SyncMessageReceiver<C> for WaitingForSyncData<C> {}

impl<C: SupraDeliveryErasureCodecSchema> SyncMessageHandler for WaitingForSyncData<C> {
    type EchoValue = EchoValueData<C>;
    type Ready = ReadyData<C>;
    type EchoReady = EchoReadyData<C>;
    type Share = ShareData<C>;
    type EchoShare = EchoShareData<C>;
    type Pull = PullRequest;

    fn handle_echo_value(&mut self, msg: Self::EchoValue) {
        let data = msg.split();
        let (_header, chunk) = data.split();
        // Input echo value can not contain owned chunk
        let _ = self.payload_state_mut().add_chunk(chunk, false);
    }

    fn handle_ready(&mut self, msg: Self::Ready) {
        let (_sender, data) = msg.split();
        let (_header, chunk) = data.split();
        // Input ready value contains only owned chunk
        let _ = self.payload_state_mut().add_chunk(chunk, true);
    }

    fn handle_echo_ready(&mut self, msg: Self::EchoReady) {
        let (_sender, value_data) = msg.split().split();
        let (_header, chunk) = value_data.split();
        // Input echo ready value can not contain owned chunk
        let _ = self.payload_state_mut().add_chunk(chunk, false);
    }

    fn handle_share(&mut self, msg: Self::Share) {
        let (_sender, data, meta) = msg.split();
        self.payload_state_mut().set_owned_chunk_meta(meta);
        let (_header, chunk) = data.split();
        let _ = self.payload_state_mut().add_piece(chunk);
    }

    fn handle_echo_share(&mut self, msg: Self::EchoShare) {
        let (_sender, data) = msg.split();
        let (_header, chunk) = data.split();
        let _ = self.payload_state_mut().add_chunk(chunk, false);
    }

    ///
    /// Sends current nodes owned chunk if any exists to requester
    ///
    fn handle_pull_request(&mut self, msg: Self::Pull) {
        let (_, requester) = msg.split();
        let is_clan_member = self.topology().is_clan_member(&requester).unwrap();
        if self.payload_state().payload_type() == PayloadType::Committee && !is_clan_member {
            // no share data to send network peers at this stage
            return;
        }
        if let Some(owned_chunk) = self.payload_state().get_owned_chunk() {
            let value_data = ValueData::new(self.payload_state().get_header(), owned_chunk);
            let data = match self.payload_state().payload_type() {
                PayloadType::Committee => {
                    RBCSyncMessage::EchoValue(self.message_factory().message_from(value_data))
                }
                PayloadType::Network => {
                    RBCSyncMessage::EchoShare(self.message_factory().message_from(value_data))
                }
            };
            let address = self
                .topology()
                .get_address_by_origin(Protocol::XRBC, &requester)
                .unwrap();
            self.response_mut().add_message((data, vec![address]));
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> TimeoutMessageHandler for WaitingForSyncData<C> {
    fn handle_retry(&mut self) {
        let sync_request = SyncRequest::new(
            self.payload_state().get_header(),
            self.payload_state().get_qc(),
        );
        match self.payload_state().payload_type() {
            PayloadType::Committee => PullRequestBroadcasterCommittee(self.context_mut())
                .broadcast_pull_request(sync_request),
            PayloadType::Network => PullRequestBroadcasterNetwork(self.context_mut())
                .broadcast_pull_request(sync_request),
        };
    }
}
