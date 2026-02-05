mod client;
pub mod codec;
pub mod config;
pub(crate) mod consumer;
pub mod errors;
pub mod messages;
pub mod supra_delivery;

pub(crate) mod task;
#[cfg(test)]
pub(crate) mod tests;

use crate::fsm::committee_state_machine::CommitteeFSMSchema;
use crate::fsm::network_message_state_machine::NetworkMessageFSMSchema;
use crate::fsm::CommitteeStateMachine;
use crate::fsm::NetworkMessageStateMachine;
use crate::fsm::SyncStateMachine;
use crate::fsm::{ExecutionStatus, FSMSchema, RBCStateMachine};
use crate::tasks::client::{
    CommitteeRBCClientProvider, NetworkRBCClientProvider, RBCClientProvider, RBCTaskClientType,
    SyncRBCClientProvider,
};
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::consumer::{ResponseConsumer, ResponseConsumerTrait};

use crate::tasks::task::Task;
use async_trait::async_trait;

use crate::fsm::sync_state_machine::SyncFSMSchema;

use crate::tasks::config::RBCTaskStateTimeConfig;
use crate::tasks::messages::TimeoutMessage;
use log::{debug, error, info};
use primitives::RxChannel;
use sfsm::StateMachine;
use std::marker::PhantomData;
use tokio::sync::mpsc::unbounded_channel;
use tokio::time::timeout;

pub trait LoggingName {
    fn name<'a>() -> &'a str;
}

///
/// RBC Task is a generic single-thread asynchronously running sub-component of the supra-delivery
/// responsible for a single deliverable/message.
///
/// It is driven by finite-state-machine executed upon each new input arrival and
/// it is also responsible to consumes any response produced as a result of the input handling.
///
/// RBC Task is communicated by RBC Client corresponding to the task.
/// RBC tasks are differentiated by engine(FSM), input type/client, and response type and consumption
/// which is done via generic parameter.
///
/// RBC task also provides means to handle timeouts caused by delays of input data.
/// Timeout on inputs are configurable parameter provided upon startup of chain via input config-file.
///
///
pub(crate) struct RBCTask<Schema: RBCTaskSchema> {
    fsm: Schema::RBCStateMachineType,
    rx: RxChannel<<Schema::FSMType as FSMSchema>::InputMessageType>,
    response_consumer: Schema::ResponseConsumerType,
    state_idle_time_config: RBCTaskStateTimeConfig,
}

impl<Schema: RBCTaskSchema> RBCTask<Schema> {
    fn new(
        config: RBCTaskStateTimeConfig,
        consumer: Schema::ResponseConsumerType,
        start_state: <Schema::RBCStateMachineType as StateMachine>::InitialState,
    ) -> (<Schema as RBCTaskSchema>::ClientType, RBCTask<Schema>) {
        let (tx, rx) = unbounded_channel::<<Schema::FSMType as FSMSchema>::InputMessageType>();
        let mut task = RBCTask::<Schema> {
            rx,
            fsm: Schema::RBCStateMachineType::default(),
            response_consumer: consumer,
            state_idle_time_config: config,
        };
        task.initialize(start_state);
        (Schema::ClientProvider::new(tx), task)
    }

    fn initialize(
        &mut self,
        initial_state: <Schema::RBCStateMachineType as StateMachine>::InitialState,
    ) {
        self.fsm
            .do_start(initial_state)
            .expect("FSM initialization failed")
    }

    pub(crate) fn get_state_machine(&mut self) -> &mut Schema::RBCStateMachineType {
        &mut self.fsm
    }

    pub(crate) async fn run_state_machine(&mut self) -> ExecutionStatus {
        loop {
            let previous_state = self.fsm.get_state_hash();
            let _ = self.fsm.do_step().map_err(|e| self.handle_error(e));
            if !self.fsm.did_transition(previous_state) {
                break;
            }
        }
        self.consume_response().await;
        self.fsm.get_execution_status()
    }

    async fn consume_response(&mut self) {
        let result = self.fsm.get_response();
        if let Err(error) = result {
            return self.handle_error(error);
        }
        if let Some(response) = result.unwrap() {
            self.response_consumer.consume(response).await;
        }
    }

    fn handle_error(
        &self,
        error: <Schema::RBCStateMachineType as RBCStateMachine<Schema::FSMType>>::RbcSmError,
    ) {
        // all the error cases related to protocol should be handled internally and mentioned in the response
        // so basically execution should be always successful, and errors should be reported via response
        // So here I guess we can simply log the error and move forward
        // TODO: add API to have external error-handler injected
        error!("{:?}", error)
    }

    fn handle_timeout(&mut self) {
        let _ = self
            .fsm
            .handle_timeout(TimeoutMessage::Retry)
            .map_err(|e| self.handle_error(e));
    }
}

#[async_trait]
impl<Schema: RBCTaskSchema> Task for RBCTask<Schema> {
    async fn run(mut self) {
        debug!("Started a new RBC task");
        loop {
            let status = self.run_state_machine().await;
            if status == ExecutionStatus::Done {
                debug!("RBC Task moved to final state");
                break;
            }
            let message = timeout(
                self.state_idle_time_config.state_idle_timeout,
                self.rx.recv(),
            )
            .await;
            match message {
                Ok(Some(msg)) => {
                    let _ = self
                        .fsm
                        .process_message(msg)
                        .map_err(|e| self.handle_error(e));
                }
                Ok(None) => {
                    info!("RBC Task input channel is closed, no messages expected. End the task");
                    break;
                }
                Err(_) => self.handle_timeout(),
            }
        }
    }
}

///
/// Provides means to define RBC task engine, client interface and response consumer
///
pub(crate) trait RBCTaskSchema: Send + Sync + 'static {
    /// Codec schema used to encode/decode deliverable/message
    type CodecSchema: SupraDeliveryErasureCodecSchema + Send;
    /// Client type used to communicate with the task
    type ClientType: Send;
    /// State machine schema driving the task
    type FSMType: FSMSchema + Send;
    /// Client provider/creator communicating with task
    type ClientProvider: RBCClientProvider<Self::FSMType, Self::ClientType> + Send;
    /// State machine type driving the task
    type RBCStateMachineType: RBCStateMachine<Self::FSMType> + Default + Send + Sync;
    /// Response Consumer type of the task
    type ResponseConsumerType: ResponseConsumerTrait<<Self::FSMType as FSMSchema>::ResponseType>
        + Send
        + Sync;
}

///
/// RBC Task schema for handling committee-message delivery (delivery between the peers in
/// the broadcaster clan)
///
pub(crate) struct CommitteeRBCTaskSchema<C: SupraDeliveryErasureCodecSchema> {
    _phantom_: PhantomData<C>,
}

impl<CS: SupraDeliveryErasureCodecSchema> RBCTaskSchema for CommitteeRBCTaskSchema<CS> {
    type CodecSchema = CS;
    type ClientType = RBCTaskClientType<CS>;

    type FSMType = CommitteeFSMSchema<Self::CodecSchema>;
    type ClientProvider = CommitteeRBCClientProvider<Self::CodecSchema>;
    type RBCStateMachineType = CommitteeStateMachine<Self::CodecSchema>;
    type ResponseConsumerType =
        ResponseConsumer<Self::CodecSchema, <Self::FSMType as FSMSchema>::ResponseType>;
}

///
/// RBC Task schema for handling network-message delivery (delivery between the peers in
/// the chain except broadcast clan)
///
pub(crate) struct NetworkRBCTaskSchema<C: SupraDeliveryErasureCodecSchema> {
    _phantom_: PhantomData<C>,
}

impl<CS: SupraDeliveryErasureCodecSchema> RBCTaskSchema for NetworkRBCTaskSchema<CS> {
    type CodecSchema = CS;
    type ClientType = RBCTaskClientType<CS>;

    type FSMType = NetworkMessageFSMSchema<Self::CodecSchema>;
    type ClientProvider = NetworkRBCClientProvider<Self::CodecSchema>;
    type RBCStateMachineType = NetworkMessageStateMachine<Self::CodecSchema>;
    type ResponseConsumerType =
        ResponseConsumer<Self::CodecSchema, <Self::FSMType as FSMSchema>::ResponseType>;
}

///
/// RBC Task schema for handling synchronization of the requested deliverable.
/// Handles synchronization of both the committee and network deliverables.
///
pub(crate) struct SyncRBCTaskSchema<C: SupraDeliveryErasureCodecSchema> {
    _phantom_: PhantomData<C>,
}

impl<CS: SupraDeliveryErasureCodecSchema> RBCTaskSchema for SyncRBCTaskSchema<CS> {
    type CodecSchema = CS;
    type ClientType = RBCTaskClientType<CS>;

    type FSMType = SyncFSMSchema<Self::CodecSchema>;
    type ClientProvider = SyncRBCClientProvider<Self::CodecSchema>;
    type RBCStateMachineType = SyncStateMachine<Self::CodecSchema>;
    type ResponseConsumerType =
        ResponseConsumer<Self::CodecSchema, <Self::FSMType as FSMSchema>::ResponseType>;
}
