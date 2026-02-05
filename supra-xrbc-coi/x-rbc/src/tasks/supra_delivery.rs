use crate::arbiter::clients::ArbiterClient;
use crate::states::{NotStartedCommitteeFSM, NotStartedNetworkFSM, NotStartedSyncFSM};
use crate::synchronizer::request::SyncResponse;
use crate::tasks::client::RBCTaskState;
use crate::tasks::codec::{
    EncodeResult, EncodeResultIfc, SupraDeliveryCodec, SupraDeliveryErasureCodec,
    SupraDeliveryErasureCodecSchema, SupraDeliveryErasureRs16Schema,
};
use crate::tasks::config::SupraDeliveryConfig;
use crate::tasks::consumer::{RBCNetworkServiceSchema, ResponseConsumer};
use crate::tasks::errors::RBCError;
use crate::tasks::messages::{DeliveryMessage, PayloadRequest, RBCMessage, RbcMessageTag};
use crate::tasks::task::{TaskSpawner, TokioTaskSpawner};
use crate::tasks::{
    CommitteeRBCTaskSchema, LoggingName, NetworkRBCTaskSchema, RBCTask, SyncRBCTaskSchema,
};
use crate::types::context::committee::CommitteeFSMContext;
use crate::types::context::network::NetworkFSMContext;
use crate::types::context::sync::SyncFSMContext;
use crate::types::context::Resources;
use crate::types::helpers::assignment_extractor::AssignmentExtractor;
use crate::types::helpers::sender_extractor::SenderExtractor;
use crate::types::helpers::VisitorAcceptor;
use crate::types::messages::requests::SyncRequest;
use crate::types::messages::{
    CommitteeFSMResponseMessage, FeedbackMessage, NetworkFSMResponseMessage, SyncFSMResponseMessage,
};
use crate::types::payload_state::committee::{CommitteePayloadState, ReconstructedData};
use crate::types::payload_state::network::NetworkPayloadState;
use crate::types::payload_state::sync::SyncPayloadState;
use crate::{InternalSyncRequest, SupraDeliveryErasureRs8Schema};
use async_trait::async_trait;
use bytes::Bytes;
use crypto::Authenticator;
use futures::sink::SinkExt;
use log::{error, info};
use metrics::{
    duration_since_unix_epoch, nanoseconds_since_unix_epoch, report, MetricValue, SystemThroughput,
    TimeStampTrait,
};
use network::client::NetworkServiceIFC;
use network::topology::peer_info::PeerInfo;
use network::topology::ChainTopology;
use network::{MessageHandler, Writer};
use primitives::error::CommonError;
use primitives::serde::{bincode_deserialize, bincode_serializer};
use primitives::types::header::{Header, HeaderIfc, MessageMeta};
use primitives::{
    FaultyNodeIdentifier, NotificationSender, Origin, Payload, Protocol, RxChannel, Stringify,
    Subscriber, TxChannel,
};
use serde::de::DeserializeOwned;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::thread::current;
use storage::storage_client::StorageClient;
use storage::StorageReadIfc;
use tokio::sync::mpsc::unbounded_channel;
use tokio::time::{interval, Instant};

const TTL: usize = 1;

///
/// Faulty Simulation
///
pub fn is_faulty_node(peer_info: &PeerInfo) -> bool {
    use std::io::Read;
    let mut content: String = String::new();
    std::fs::File::open("configs/faulty_peers.json")
        .expect("file not exist")
        .read_to_string(&mut content)
        .expect("bad file format");
    let fault_list = serde_json::from_str::<Vec<FaultyNodeIdentifier>>(&content).expect("Error");
    let is_in = fault_list
        .iter()
        .filter(|f| {
            f.tribe.eq(&peer_info.tribe())
                && f.clan.eq(&peer_info.clan())
                && f.position.eq(&peer_info.position())
        })
        .collect::<Vec<&FaultyNodeIdentifier>>();
    !is_in.is_empty()
}

pub trait SupraDeliverySchema: Clone + Send + Sync + 'static {
    type CodecSchema: SupraDeliveryErasureCodecSchema;
    type TaskSpawner: TaskSpawner + Default;
}

#[derive(Clone)]
pub struct SupraDeliveryRs16Schema;
impl SupraDeliverySchema for SupraDeliveryRs16Schema {
    type CodecSchema = SupraDeliveryErasureRs16Schema;
    type TaskSpawner = TokioTaskSpawner;
}

#[derive(Clone)]
pub struct SupraDeliveryRs8Schema;
impl SupraDeliverySchema for SupraDeliveryRs8Schema {
    type CodecSchema = SupraDeliveryErasureRs8Schema;
    type TaskSpawner = TokioTaskSpawner;
}

pub(crate) type ReturnResult<T> = Result<T, RBCError>;

pub struct SupraDelivery<Schema: SupraDeliverySchema> {
    // FEC config parameters for committee and network chunks
    config: SupraDeliveryConfig<Schema::CodecSchema>,
    // Supra node PublicKey
    // Input message channel
    rx: RxChannel<DeliveryMessage<Schema::CodecSchema>>,
    // Instance of the SupraDeliveryClient
    client: SupraDeliveryClient<Schema::CodecSchema>,
    // Channel to arbiter to send Available messages
    arbiter: ArbiterClient,
    // Output channel from SupraDelivery to Node
    output: TxChannel<FeedbackMessage>,
    // Existing task list
    tasks: HashMap<MessageMeta, RBCTaskState<Schema::CodecSchema>>,
    // Blacklisted origins
    blacklist: HashSet<Origin>,
    // Active Sync requests received from synchronizer
    sync_requests: HashMap<MessageMeta, NotificationSender<SyncResponse>>,

    // Resources
    authenticator: Authenticator,
    chain_topology: ChainTopology,
    network_service: NetworkServiceIFC<RBCNetworkServiceSchema<Schema::CodecSchema>>,
    storage_client: StorageClient,

    task_spawner: Schema::TaskSpawner,

    _phantom_: PhantomData<Schema>,
}

pub struct SupraDeliveryClient<C: SupraDeliveryErasureCodecSchema> {
    pub tx: TxChannel<DeliveryMessage<C>>,
}

impl<C: SupraDeliveryErasureCodecSchema> Clone for SupraDeliveryClient<C> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema, T> Subscriber<T> for SupraDeliveryClient<C>
where
    T: Into<DeliveryMessage<C>> + Debug,
{
    fn send(&self, msg: T) -> Result<(), CommonError> {
        self.tx
            .send(msg.into())
            .map_err(|e| CommonError::UnboundSendError(format!("{:?}", e)))
    }
}

#[async_trait]
impl<C: SupraDeliveryErasureCodecSchema + DeserializeOwned> MessageHandler
    for SupraDeliveryClient<C>
where
    Self: Subscriber<RBCMessage<C>>,
{
    async fn dispatch(&self, writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
        // Reply with an ACK.
        let ack_message = bincode_serializer(&"Ack").map_err(Box::new)?;
        let _ = writer.send(ack_message).await;

        // Deserialize and parse the message.
        let result: RBCMessage<C> = bincode_deserialize(&message).map_err(Box::new)?;

        report(
            &[&RbcMessageTag::Size, &result],
            MetricValue::AsBytes(message.len()),
        );

        report(
            &[&RbcMessageTag::TravelTime, &result],
            MetricValue::AsSeconds(result.elapsed_time()),
        );
        let _ = self.send(result).map_err(log_error);
        Ok(())
    }
}

impl<Schema: SupraDeliverySchema> LoggingName for SupraDelivery<Schema> {
    fn name<'a>() -> &'a str {
        "SupraDelivery"
    }
}

impl<Schema: SupraDeliverySchema> SupraDelivery<Schema> {
    pub(crate) fn new(
        config: SupraDeliveryConfig<Schema::CodecSchema>,
        output: TxChannel<FeedbackMessage>,
        arbiter: ArbiterClient,
        authenticator: Authenticator,
        chain_topology: ChainTopology,
        network_service: NetworkServiceIFC<RBCNetworkServiceSchema<Schema::CodecSchema>>,
        storage_client: StorageClient,
    ) -> (
        SupraDeliveryClient<Schema::CodecSchema>,
        SupraDelivery<Schema>,
    ) {
        let (tx, rx) = unbounded_channel::<DeliveryMessage<Schema::CodecSchema>>();
        let client = SupraDeliveryClient { tx };
        let delivery = SupraDelivery::<Schema> {
            config,
            rx,
            client: client.clone(),
            arbiter,
            output,
            tasks: Default::default(),
            blacklist: Default::default(),
            sync_requests: Default::default(),
            authenticator,
            chain_topology,
            network_service,
            storage_client,
            task_spawner: Schema::TaskSpawner::default(),
            _phantom_: Default::default(),
        };
        (client, delivery)
    }

    pub fn spawn(
        config: SupraDeliveryConfig<Schema::CodecSchema>,
        output: TxChannel<FeedbackMessage>,
        arbiter_client: ArbiterClient,
        authenticator: Authenticator,
        chain_topology: ChainTopology,
        network_service: NetworkServiceIFC<RBCNetworkServiceSchema<Schema::CodecSchema>>,
        storage_client: StorageClient,
    ) -> SupraDeliveryClient<Schema::CodecSchema> {
        let (deliver_client, delivery) = Self::new(
            config,
            output,
            arbiter_client,
            authenticator,
            chain_topology,
            network_service,
            storage_client,
        );
        tokio::spawn(SupraDelivery::run(delivery));
        deliver_client
    }

    pub fn spawn_blocking(
        config: SupraDeliveryConfig<Schema::CodecSchema>,
        output: TxChannel<FeedbackMessage>,
        arbiter_client: ArbiterClient,
        authenticator: Authenticator,
        chain_topology: ChainTopology,
        network_service: NetworkServiceIFC<RBCNetworkServiceSchema<Schema::CodecSchema>>,
        storage_client: StorageClient,
    ) -> SupraDeliveryClient<Schema::CodecSchema> {
        let (deliver_client, delivery) = Self::new(
            config,
            output,
            arbiter_client,
            authenticator,
            chain_topology,
            network_service,
            storage_client,
        );
        tokio::task::spawn_blocking(|| SupraDelivery::run_blocking(delivery));
        deliver_client
    }

    async fn run(mut delivery: SupraDelivery<Schema>) {
        info!("Starting {}", Self::name());
        let mut interval = interval(
            delivery
                .config
                .garbage_collector_config
                .garbage_collection_timeout,
        );
        let faulty = is_faulty_node(delivery.chain_topology.current_node());
        loop {
            let result = tokio::select! {
                Some(message) = delivery.rx.recv() => {
                    if delivery.should_be_discarded(&message, faulty) {
                        info!("[FaultyNode] {} ", message);
                        Ok(())
                    } else {
                        delivery.handle_input(message)
                    }
                }
                _ = interval.tick() => {
                    delivery.execute_gc()
                }
            };
            let _ = result.map_err(log_error);
        }
    }

    fn run_blocking(mut delivery: SupraDelivery<Schema>) {
        info!("Starting {}", Self::name());
        let faulty = is_faulty_node(delivery.chain_topology.current_node());
        let mut last_gc_time = nanoseconds_since_unix_epoch();
        loop {
            if let Some(message) = delivery.rx.blocking_recv() {
                if delivery.should_be_discarded(&message, faulty) {
                    info!("[FaultyNode] {} ", message);
                } else {
                    let _ = delivery.handle_input(message).map_err(log_error);
                }
            }
            if nanoseconds_since_unix_epoch() - last_gc_time
                >= delivery
                    .config
                    .garbage_collector_config
                    .task_stale_timeout
                    .as_nanos()
            {
                let _ = delivery.execute_gc().map_err(log_error);
                last_gc_time = nanoseconds_since_unix_epoch();
            }
        }
    }

    fn should_be_discarded(
        &self,
        input: &DeliveryMessage<Schema::CodecSchema>,
        faulty: bool,
    ) -> bool {
        match input {
            DeliveryMessage::Message(message) => {
                let for_sync_task = self
                    .tasks
                    .get(message.meta())
                    .map(|task| task.is_sync())
                    .unwrap_or(false);
                !for_sync_task && faulty
            }
            DeliveryMessage::Payload(..) => faulty,
            DeliveryMessage::Sync(..) | DeliveryMessage::InternalFeedback(..) => false,
        }
    }

    ///
    /// Processes input delivery message
    ///
    pub(crate) fn handle_input(
        &mut self,
        message: DeliveryMessage<Schema::CodecSchema>,
    ) -> ReturnResult<()> {
        info!("{:?} - {:?}", current().id(), message);
        match message {
            DeliveryMessage::Sync(sync) => self.handle_sync_request(sync),
            DeliveryMessage::Message(rbc) => self.handle_message(rbc),
            DeliveryMessage::Payload(payload_request) => self.handle_new_payload(payload_request),
            DeliveryMessage::InternalFeedback(feedback) => self.handle_feedback(feedback),
        }
    }

    ///
    /// Processes input rbc message
    ///  - if not task for provided message, create one
    ///  - if there is a task available in the tasks list, send the message via client
    ///
    pub(crate) fn handle_message(
        &mut self,
        message: RBCMessage<Schema::CodecSchema>,
    ) -> ReturnResult<()> {
        info!("HandleInput - {}", message);
        if !self.should_be_processed(&message)? {
            return Ok(());
        }

        if !self.tasks.contains_key(&message.get_meta()) {
            report(
                &[&SystemThroughput::BatchArrival, message.header()],
                MetricValue::AsNanoSeconds(duration_since_unix_epoch()),
            );
        }

        let task = self.get_task(&message)?;
        task.send(message)
    }

    ///
    /// Checks whether input message should be processed further.
    ///
    /// Conditions:
    ///     - Report Error for
    ///         - ill constructed messages
    ///         - messages from blacklisted origins
    ///         - messages for which sender can not be deduced
    ///         - for sync messages from the current broadcaster deliverables which are not yet finalized
    ///         - for the messages from the current broadcaster if there is no data and no task
    ///     - Discard messages which are not sync and delivery is already finalized
    ///
    /// If the message does not fall under any of the above mentioned conditions is processed farther
    ///
    pub(crate) fn should_be_processed(
        &mut self,
        message: &RBCMessage<Schema::CodecSchema>,
    ) -> ReturnResult<bool> {
        if !message.is_valid_message() {
            return Err(RBCError::MessageProcessingError(format!(
                "Received ill constructed message: {:?}",
                message
            )));
        }
        if self.is_from_blacklisted_origin(&message)? {
            return Err(RBCError::MessageProcessingError(format!(
                "Discarding message from blacklisted origin: {:?}",
                message
            )));
        }

        let is_sync_message = message.is_sync_message();
        let is_broadcaster_message = self.chain_topology.origin().eq(message.origin());
        let has_task = self.tasks.get(message.meta());
        // if there is a task for the message which is in done state do not query storage for the data
        // Task in done state indicates that the deliverable is written to storage, no need to extra query storage
        let has_data = has_task.map(|t| t.is_done()).unwrap_or_else(|| {
            self.storage_client
                .has_key_blocking(message.header().hash())
        });
        if has_data && !is_sync_message {
            Ok(false)
        } else if has_data && is_sync_message {
            Ok(true)
        } else if !has_data && is_sync_message && is_broadcaster_message {
            message
                .accept(&SenderExtractor::new(&self.chain_topology))
                .map(|sender| *sender.id())
                .map(|sender| self.blacklist.insert(sender));
            Err(RBCError::InvalidRequest(format!(
                "Broadcaster got pull message for own non-available data: {}\n blacklisting sender",
                message
            )))
        } else if !has_data && is_broadcaster_message && !has_task.is_some() {
            Err(RBCError::ProtocolError(format!(
                "No task for broadcaster deliverable: {}",
                message
            )))
        } else {
            Ok(true)
        }
    }

    ///
    /// Returns true if message origin is blacklisted peer or message sender is blacklisted or
    /// unknown peer
    ///
    pub(crate) fn is_from_blacklisted_origin(
        &self,
        message: &RBCMessage<Schema::CodecSchema>,
    ) -> ReturnResult<bool> {
        if self.blacklist.contains(message.origin()) {
            return Ok(true);
        }
        let sender_extractor = SenderExtractor::new(&self.chain_topology);
        let sender = message.accept(&sender_extractor);
        sender
            .map(|info| self.blacklist.contains(info.id()))
            .ok_or_else(|| {
                RBCError::MessageProcessingError(format!("Failed to extract sender: {:?}", message))
            })
    }

    ///
    /// Processes input payload
    ///  - Chunk the payload, create ID and merkle proof
    ///  - create CommitteeRBCTask
    ///  - submit chunks to task
    ///  - store (payload id -> task_client) into tasks bank
    ///
    pub(crate) fn handle_new_payload(
        &mut self,
        payload_request: PayloadRequest,
    ) -> ReturnResult<()> {
        let arrival_time = duration_since_unix_epoch();
        let (payload, notification) = payload_request.split();
        self.prepare_payload_for_delivery(payload.clone())
            .map(|result| {
                report(
                    &[&SystemThroughput::BatchArrival, result.header()],
                    MetricValue::AsNanoSeconds(arrival_time),
                );
                if let Some(notification) = notification {
                    let storage_key = result.header().hash();
                    let res = notification.send(storage_key);
                    if res.is_err() {
                        log::error!("Broken Notification Channel to Payload generator");
                    }
                }
                self.add_new_payload_task(payload, result);
            })
    }

    fn add_new_payload_task(
        &mut self,
        payload: Payload,
        result: EncodeResult<Schema::CodecSchema>,
    ) {
        let task_id = result.header().get_meta();
        let (header, committee_chunks, network_chunks) = result.split();
        info!(
            "{}: New task for a new deliverable - {}",
            Self::name(),
            header
        );
        let reconstructed_data = ReconstructedData::new(payload, committee_chunks, network_chunks);
        let mut payload_state = CommitteePayloadState::new(header, self.get_codec());
        payload_state.set_reconstructed_data(reconstructed_data);
        let (task, client) = self.create_rbc_committee_task(payload_state);
        self.tasks.insert(task_id, task);
        self.task_spawner.spawn(client);
    }

    ///
    /// Processes feedback from tasks
    ///
    pub(crate) fn handle_feedback(&mut self, feedback: FeedbackMessage) -> ReturnResult<()> {
        match feedback {
            FeedbackMessage::Done(msg_meta) => {
                self.mark_task_done(&msg_meta);
                self.update_sync_requests(&msg_meta, Ok(()));
                return self
                    .output
                    .send(FeedbackMessage::Done(msg_meta))
                    .map_err(|e| RBCError::SendError(format!("Output: {:?}", e)));
            }
            FeedbackMessage::Error(msg_meta, origin) => {
                log_error(format!("Blacklist sender {:?} for: {:?}", origin, msg_meta));
                self.blacklist.insert(origin);
                if origin.eq(msg_meta.origin()) {
                    self.mark_task_done(&msg_meta);
                }
            }
            FeedbackMessage::InternalError(msg_meta, message) => {
                let err_msg = format!("Internal Error {:?} for: {:?}", message, msg_meta);
                log_error(err_msg.clone());
                self.mark_task_done(&msg_meta);
                self.update_sync_requests(&msg_meta, Err(err_msg));
            }
            FeedbackMessage::Available(available) => self.arbiter.consume(available),
        };
        Ok(())
    }

    pub(crate) fn update_sync_requests(&mut self, task_id: &MessageMeta, response: SyncResponse) {
        let _ = self
            .sync_requests
            .remove(task_id)
            .map(|feedback| feedback.send(response));
    }

    fn mark_task_done(&mut self, msg_meta: &MessageMeta) {
        if let Some(state) = self.tasks.get_mut(msg_meta) {
            info!("{}: Done - {}", Self::name(), msg_meta);
            *state = RBCTaskState::<Schema::CodecSchema>::Done(Instant::now(), 0);
        }
    }

    pub(crate) fn execute_gc(&mut self) -> ReturnResult<()> {
        let metas = self.tasks.keys().cloned().collect::<Vec<MessageMeta>>();
        let total = metas.len();
        let to_be_dropped = metas
            .into_iter()
            .filter_map(|keys| self.execute_gc_round_for_task(keys))
            .collect();
        let count = self.drop_tasks(to_be_dropped);
        info!(
            "{} GC => {}/{} cleared/total, Active: {}",
            Self::name(),
            count,
            total,
            self.tasks.len()
        );
        Ok(())
    }

    ///
    /// Runs GC round for the task corresponding to the input key.
    ///
    ///   - if a task is a sync task or current broadcaster task do not run GC round for them
    ///   - otherwise run the GC round for a task
    ///     - if a task is done and task TTL has reached send the task to be removed
    ///     - if a task is done but TTL has not reached, increase GC round
    ///     - if a task is in-progress and staled send the task to be removed
    ///
    pub(crate) fn execute_gc_round_for_task(
        &mut self,
        meta: MessageMeta,
    ) -> Option<(MessageMeta, SyncResponse)> {
        let task = self.tasks.get_mut(&meta).unwrap();
        if self.chain_topology.origin() == meta.origin() && !task.is_done() {
            None // if broadcaster then do nothing
        } else if task.is_sync() {
            task.refresh();
            None
        } else if task.is_done() && task.gc_round() > TTL {
            Some((meta, Ok(())))
        } else if task.is_done() {
            task.increment_gc_round();
            None
        } else if task.is_stale(self.config.garbage_collector_config.task_stale_timeout) {
            Some((meta, Err("Staled task dropped".to_string())))
        } else {
            None
        }
    }

    ///
    /// Drop list of tasks
    ///
    pub(crate) fn drop_tasks(&mut self, droppable: Vec<(MessageMeta, SyncResponse)>) -> usize {
        let count = droppable.len();
        droppable.iter().for_each(|(meta, resp)| {
            self.update_sync_requests(meta, resp.clone());
            self.tasks.remove(meta);
        });
        count
    }

    ///
    /// Processes sync request received from internal synchronizer component
    ///
    /// A new sync task will be created corresponding to the request if no active task is available.
    /// Otherwise sync request will be simply forwarded to the existing active task.
    /// Error will be reported if there is an existing sync-request corresponding to this request.
    /// If it happens so that the data is already available in the local store, no task will be
    /// created and okay feedback will be directly sent back.
    ///
    pub(crate) fn handle_sync_request(&mut self, request: InternalSyncRequest) -> ReturnResult<()> {
        let (header, qc, feedback) = self.validate_sync_request(request)?.split();
        if self.storage_client.has_key_blocking(header.hash()) {
            let _ = feedback.send(Ok(()));
            return Ok(());
        }
        let task_id = header.get_meta();
        let sync_request = RBCMessage::<Schema::CodecSchema>::Sync(SyncRequest::new(header, qc));
        match self.get_task(&sync_request) {
            Ok(task) => {
                if task.client().filter(|t| !t.is_sync()).is_some() {
                    task.send(sync_request)?;
                }
                let _ = self.sync_requests.insert(task_id, feedback);
                Ok(())
            }
            Err(e) => {
                let _ = feedback.send(Err(format!("{:?}", e)));
                Err(e)
            }
        }
    }

    ///
    /// Validates sync requests received from synchronizer
    ///     - only one sync reqeust is expected per deliverable, as it can be part of only single block
    ///     - if the node is a broadcaster, it will never receive sync request for its own data
    /// If any of the above mentioned statements violated sync request is considered invalid and
    /// error is sent immediately as feedback, otherwise the sync-request is returned as valid result
    ///
    pub(crate) fn validate_sync_request(
        &self,
        internal_sync: InternalSyncRequest,
    ) -> ReturnResult<InternalSyncRequest> {
        let task_id = internal_sync.meta();
        if internal_sync.origin().eq(self.chain_topology.origin()) {
            let (header, _, feedback) = internal_sync.split();
            let msg = format!(
                "FATAL: Possible protocol error. Received sync request for owned data: {} - {}",
                self.chain_topology.origin().hex_display(),
                header
            );
            let _ = feedback.send(Err(msg.clone()));
            return Err(RBCError::InvalidRequest(msg));
        } else if self.sync_requests.contains_key(task_id) {
            let (header, _, feedback) = internal_sync.split();
            let msg = format!("Sync request already exists for message: {}", header);
            let _ = feedback.send(Err(msg.clone()));
            return Err(RBCError::InvalidRequest(msg));
        }
        Ok(internal_sync)
    }

    pub(crate) fn create_rbc_committee_task(
        &self,
        payload_state: CommitteePayloadState<Schema::CodecSchema>,
    ) -> (
        RBCTaskState<<Schema as SupraDeliverySchema>::CodecSchema>,
        RBCTask<CommitteeRBCTaskSchema<<Schema as SupraDeliverySchema>::CodecSchema>>,
    ) {
        let context: CommitteeFSMContext<Schema::CodecSchema> =
            CommitteeFSMContext::new(payload_state, self.get_resources());
        let start_state = NotStartedCommitteeFSM::new(context);
        let response_consumer =
            self.get_response_consumer::<CommitteeFSMResponseMessage<Schema::CodecSchema>>();
        let (client, task) = RBCTask::<CommitteeRBCTaskSchema<Schema::CodecSchema>>::new(
            self.config.state_idle_time_config.clone(),
            response_consumer,
            start_state,
        );
        (RBCTaskState::InProgress(client, Instant::now()), task)
    }

    pub(crate) fn create_rbc_network_task(
        &self,
        message: &RBCMessage<Schema::CodecSchema>,
    ) -> (
        RBCTaskState<<Schema as SupraDeliverySchema>::CodecSchema>,
        RBCTask<NetworkRBCTaskSchema<<Schema as SupraDeliverySchema>::CodecSchema>>,
    ) {
        let payload_state = NetworkPayloadState::new(message.get_header(), self.get_codec());
        let context: NetworkFSMContext<Schema::CodecSchema> =
            NetworkFSMContext::new(payload_state, self.get_resources());
        let start_state = NotStartedNetworkFSM::new(context);
        let response_consumer =
            self.get_response_consumer::<NetworkFSMResponseMessage<Schema::CodecSchema>>();
        let (client, task) = RBCTask::<NetworkRBCTaskSchema<Schema::CodecSchema>>::new(
            self.config.state_idle_time_config.clone(),
            response_consumer,
            start_state,
        );
        (RBCTaskState::InProgress(client, Instant::now()), task)
    }

    pub(crate) fn create_rbc_sync_task(
        &self,
        message: &RBCMessage<Schema::CodecSchema>,
    ) -> ReturnResult<(
        RBCTaskState<Schema::CodecSchema>,
        RBCTask<SyncRBCTaskSchema<Schema::CodecSchema>>,
    )> {
        let payload_state = self.prepare_sync_task_state(message)?;
        let context: SyncFSMContext<Schema::CodecSchema> =
            SyncFSMContext::new(payload_state, self.get_resources());
        let start_state = NotStartedSyncFSM::new(context);
        let response_consumer =
            self.get_response_consumer::<SyncFSMResponseMessage<Schema::CodecSchema>>();
        let (client, task) = RBCTask::<SyncRBCTaskSchema<Schema::CodecSchema>>::new(
            self.config.state_idle_time_config.clone(),
            response_consumer,
            start_state,
        );
        Ok((RBCTaskState::InProgress(client, Instant::now()), task))
    }

    pub(crate) fn prepare_sync_task_state(
        &self,
        message: &RBCMessage<Schema::CodecSchema>,
    ) -> ReturnResult<SyncPayloadState<Schema::CodecSchema>> {
        let storage_key = message.header().hash();
        let committee_deliverable = self
            .chain_topology
            .is_clan_member(message.origin())
            .ok_or_else(|| {
                RBCError::InvalidRequest(format!(
                    "Origin of the deliverable is unknown: {}",
                    message.header()
                ))
            })?;
        if let Some(payload) = self.storage_client.read_blocking(storage_key) {
            self.prepare_sync_task_state_with_payload(message, committee_deliverable, payload)
        } else {
            Ok(self.prepare_sync_task_state_with_no_data(message, committee_deliverable))
        }
    }

    pub(crate) fn prepare_sync_task_state_with_payload(
        &self,
        message: &RBCMessage<Schema::CodecSchema>,
        from_committee: bool,
        pld: Payload,
    ) -> ReturnResult<SyncPayloadState<Schema::CodecSchema>> {
        let (header, qc) = match message {
            RBCMessage::Pull(request) => (request.get_header(), request.get_qc()),
            RBCMessage::Sync(request) => {
                return Err(RBCError::InvalidRequest(format!(
                    "Unexpected Sync message state: {}",
                    request
                )))
            }
            _ => panic!("Not a sync request while preparing sync task state"),
        };
        let (enc_header, committee_chunks, mut nt_chunks) =
            self.prepare_payload_for_delivery(pld)?.split();
        SupraDelivery::<Schema>::validate_commitments(&header, &enc_header)?;
        let state = if from_committee {
            SyncPayloadState::ready_for_committee(
                header,
                qc,
                self.chain_topology.get_position(),
                committee_chunks,
                nt_chunks,
                self.get_codec(),
            )
        } else {
            let assignment_extractor = AssignmentExtractor::new(
                &self.chain_topology,
                Protocol::XRBC,
                &self.config.dissemination_rule,
            );
            let nt_commitment_idx = assignment_extractor.assigned_chunk_index(message.origin());
            let nt_chunk_index = nt_commitment_idx - self.chain_topology.get_committee_size();
            let network_chunk = nt_chunks.remove(nt_chunk_index).decode(self.get_codec())?;
            SyncPayloadState::ready_for_network(header, qc, network_chunk, self.get_codec())
        };
        Ok(state)
    }

    pub(crate) fn validate_commitments(
        request_header: &Header,
        encoded_header: &Header,
    ) -> ReturnResult<()> {
        if request_header.commitment().ne(encoded_header.commitment()) {
            Err(RBCError::InvalidRequest(format!(
                "Request header commitment does not correspond to locally created commitment: {}",
                request_header
            )))
        } else {
            Ok(())
        }
    }

    pub(crate) fn prepare_sync_task_state_with_no_data(
        &self,
        message: &RBCMessage<Schema::CodecSchema>,
        from_committee: bool,
    ) -> SyncPayloadState<Schema::CodecSchema> {
        let (header, qc) = match message {
            RBCMessage::Pull(request) => (request.get_header(), request.get_qc()),
            RBCMessage::Sync(request) => (request.get_header(), request.get_qc()),
            _ => panic!("Not a sync request while preparing sync task state"),
        };
        if from_committee {
            SyncPayloadState::for_committee(header, qc, self.get_codec())
        } else {
            SyncPayloadState::for_network(header, qc, self.get_codec())
        }
    }

    pub(crate) fn get_task(
        &mut self,
        message: &RBCMessage<Schema::CodecSchema>,
    ) -> ReturnResult<&RBCTaskState<Schema::CodecSchema>> {
        let id = message.get_meta();
        // info!("Available tasks: {:?}", self.tasks.keys());
        let spawned_task = if let Some(task) = self.tasks.get(&id) {
            if task.is_done() && message.is_sync_message() {
                info!(
                    "{}: Switching to Sync Task - {}",
                    Self::name(),
                    message.header()
                );
                let (client, sync_task) = self.create_rbc_sync_task(message)?;
                self.task_spawner.spawn(sync_task);
                Some(client)
            } else {
                None
            }
        } else {
            info!(
                "{}: New task for a new message - {}",
                Self::name(),
                message.header()
            );
            if message.is_sync_message() {
                let (client, task) = self.create_rbc_sync_task(message)?;
                self.task_spawner.spawn(task);
                Some(client)
            } else if message.is_committee_message() {
                let payload_state =
                    CommitteePayloadState::new(message.get_header(), self.get_codec());
                let (client, task) = self.create_rbc_committee_task(payload_state);
                self.task_spawner.spawn(task);
                Some(client)
            } else {
                let (client, task) = self.create_rbc_network_task(message);
                self.task_spawner.spawn(task);
                Some(client)
            }
        };
        spawned_task.and_then(|task| self.tasks.insert(id, task));

        let task = self.tasks.get_mut(message.meta()).ok_or_else(|| {
            RBCError::ProtocolError(format!("No task is available for message: {}", message))
        })?;
        task.refresh();
        Ok(task)
    }

    pub(crate) fn get_resources(&self) -> Resources {
        Resources::new(
            self.chain_topology.clone(),
            self.authenticator.clone(),
            self.storage_client.clone(),
            self.config.dissemination_rule.clone(),
        )
    }

    pub(crate) fn get_codec(&self) -> SupraDeliveryCodec<Schema::CodecSchema> {
        SupraDeliveryCodec::new(
            self.config.committee_erasure_config,
            self.config.network_erasure_config,
        )
    }

    fn get_response_consumer<ResponseType>(
        &self,
    ) -> ResponseConsumer<Schema::CodecSchema, ResponseType> {
        ResponseConsumer::<Schema::CodecSchema, ResponseType>::new(
            self.network_service.clone(),
            self.client.clone(),
        )
    }

    pub(crate) fn prepare_payload_for_delivery(
        &self,
        payload: Payload,
    ) -> Result<EncodeResult<Schema::CodecSchema>, RBCError> {
        // chunk the payload, create merkle root, sign and create Value Data
        self.get_codec().encode(payload, &self.authenticator)
    }

    pub(crate) fn tasks(
        &self,
    ) -> &HashMap<MessageMeta, RBCTaskState<<Schema as SupraDeliverySchema>::CodecSchema>> {
        &self.tasks
    }

    pub(crate) fn sync_requests(&self) -> &HashMap<MessageMeta, NotificationSender<SyncResponse>> {
        &self.sync_requests
    }

    pub(crate) fn blacklist(&self) -> &HashSet<Origin> {
        &self.blacklist
    }

    pub(crate) fn get_authenticator(&self) -> &Authenticator {
        &self.authenticator
    }
}

#[cfg(test)]
impl<Schema: SupraDeliverySchema> SupraDelivery<Schema> {
    pub(crate) fn internal_rx(&mut self) -> &mut RxChannel<DeliveryMessage<Schema::CodecSchema>> {
        &mut self.rx
    }
}
fn log_error<T: Debug>(error: T) {
    error!("Reporting: {:?}", error);
}
