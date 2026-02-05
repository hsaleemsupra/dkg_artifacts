use crate::fsm::{ExecutionStatus, FSMSchema, RBCStateMachine};
use crate::tasks::client::{
    CommitteeRBCClientProvider, NetworkRBCClientProvider, RBCClientProvider, RBCTaskClient,
    RBCTaskState, SyncRBCClientProvider,
};
use crate::tasks::consumer::ResponseConsumerTrait;
use crate::tasks::task::Task;
use crate::tasks::{RBCTask, RBCTaskSchema};
use crate::SupraDeliveryErasureRs8Schema;
use std::collections::HashMap;

use crate::tasks::config::RBCTaskStateTimeConfig;
use crate::tasks::messages::{RBCMessage, TimeoutMessage};
use crate::types::messages::{RBCCommitteeMessage, RBCNetworkMessage};
use crate::types::tests::{share_data, value_data_with_header};
use async_trait::async_trait;
use primitives::types::Header;
use primitives::TxChannel;
use sfsm::StateMachine;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::mpsc::unbounded_channel;
use tokio::time::{sleep, Instant};

struct TestFSMSchema;
impl FSMSchema for TestFSMSchema {
    type InputMessageType = u32;
    type ResponseType = u32;
    type CodecSchema = SupraDeliveryErasureRs8Schema;
}

struct TestRBCClientProvider;
impl RBCClientProvider<TestFSMSchema, RBCTaskClient<TestFSMSchema, u32>> for TestRBCClientProvider {
    fn new(
        tx: TxChannel<<TestFSMSchema as FSMSchema>::InputMessageType>,
    ) -> RBCTaskClient<TestFSMSchema, u32> {
        RBCTaskClient::<TestFSMSchema, u32>::new(tx)
    }
}

///
/// Transition: Start -> Preparing ---- state.data > 100 ----> Waiting ---- state.flag ----> Done
/// Input Handling (input):
///     - Start: None
///     - Preparing: state.data + input
///     - Waiting: state.flag = (input == 42) ? Some(true) : None
///     - Done: None
/// Execution:
///     - Start: None
///     - Preparing: state.data + 25
///     - Waiting:  if state.flag.is_some(true) state.data = 42, else if state.flag.is_some(false) state.data = 1024
///     - Done: None
/// Timeout message handling (timeout):
///     - Start: None
///     - Preparing: None
///     - Waiting:  state.data - 100; if state.data < 0 ? state.flag = Some(false): None
///     - Done: None
/// Response:
///     - Start: None
///     - Preparing: Some(state.data)
///     - Waiting:  Some(0)
///     - Done: Some(state.data)
///
#[derive(Debug, PartialEq, Clone, Hash, Eq)]
enum TestFsmStates {
    Unknown,
    Start,
    Preparing,
    Waiting,
    Done,
}

#[derive(Debug)]
struct TestFsm {
    state: TestFsmStates,
    data: i32,
    flag: Option<bool>,
    timeout_called: HashMap<TestFsmStates, u32>,
}

impl Default for TestFsm {
    fn default() -> Self {
        Self {
            state: TestFsmStates::Unknown,
            data: 0,
            flag: None,
            timeout_called: Default::default(),
        }
    }
}

impl StateMachine for TestFsm {
    type InitialState = TestFsmStates;
    type Error = TestFsmStates;
    type StatesEnum = TestFsmStates;

    fn start(&mut self, state: Self::InitialState) -> Result<(), Self::Error> {
        if state != TestFsmStates::Start {
            return Err(TestFsmStates::Unknown);
        }
        self.state = state;
        Ok(())
    }

    fn step(&mut self) -> Result<(), Self::Error> {
        let new_state = match &self.state {
            TestFsmStates::Start => TestFsmStates::Preparing,
            TestFsmStates::Preparing => {
                if self.data > 100_i32 {
                    TestFsmStates::Waiting
                } else {
                    self.data += 25;
                    TestFsmStates::Preparing
                }
            }
            TestFsmStates::Waiting => match self.flag {
                None => TestFsmStates::Waiting,
                Some(true) => {
                    self.data = 42;
                    TestFsmStates::Done
                }
                Some(false) => {
                    println!("timeout response");
                    self.data = 1024;
                    TestFsmStates::Done
                }
            },
            TestFsmStates::Done => TestFsmStates::Done,
            _ => return Err(TestFsmStates::Unknown),
        };
        self.state = new_state;
        println!("Next state: {:?}", self);
        Ok(())
    }

    fn stop(self) -> Result<Self::StatesEnum, Self::Error> {
        Ok(self.state)
    }

    fn peek_state(&self) -> &Self::StatesEnum {
        &self.state
    }
}
impl RBCStateMachine<TestFSMSchema> for TestFsm {
    type StateHash = TestFsmStates;
    type RbcSmError = TestFsmStates;

    fn process_message(
        &mut self,
        input: <TestFSMSchema as FSMSchema>::InputMessageType,
    ) -> Result<(), Self::RbcSmError> {
        match &mut self.state {
            TestFsmStates::Unknown => {
                return Err(TestFsmStates::Unknown);
            }
            TestFsmStates::Preparing => {
                self.data += input as i32;
            }
            TestFsmStates::Waiting => {
                self.flag = (input == 42).then_some(true);
            }
            _ => {}
        };
        Ok(())
    }

    ///
    /// When in waiting state and time-out expired set flag true
    ///
    fn handle_timeout(&mut self, input: TimeoutMessage) -> Result<(), Self::RbcSmError> {
        println!("Timeout: {:?} - {:?}", self.get_state_hash(), input);
        let value = self
            .timeout_called
            .entry(self.get_state_hash())
            .or_insert(0);
        *value += 1;
        match &self.state {
            TestFsmStates::Waiting => match input {
                TimeoutMessage::Retry => {
                    self.data -= 100;
                    println!("Data {}", self.data);
                    if self.data < 0 {
                        self.flag = Some(false);
                    }
                }
            },
            _ => {}
        }
        Ok(())
    }

    fn get_response(
        &mut self,
    ) -> Result<Option<<TestFSMSchema as FSMSchema>::ResponseType>, Self::RbcSmError> {
        match &self.state {
            TestFsmStates::Start => Ok(None),
            TestFsmStates::Preparing => Ok(Some(self.data as u32)),
            TestFsmStates::Waiting => Ok(Some(0)),
            TestFsmStates::Done => Ok(Some(self.data as u32)),
            _ => Ok(None),
        }
    }

    fn get_execution_status(&self) -> ExecutionStatus {
        if self.state == TestFsmStates::Done {
            return ExecutionStatus::Done;
        }
        ExecutionStatus::InProgress
    }

    fn get_state_hash(&self) -> Self::StateHash {
        self.state.clone()
    }
}

struct TestResponseConsumer {
    responses: Vec<u32>,
    index: AtomicUsize,
}

impl TestResponseConsumer {
    fn new(responses: Vec<u32>) -> Self {
        Self {
            responses,
            index: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl ResponseConsumerTrait<u32> for TestResponseConsumer {
    async fn consume(&self, response: u32) {
        let idx = self.index.fetch_add(1, Ordering::Relaxed);
        assert_eq!(response, self.responses[idx]);
    }
}

struct TestRBCTaskSchema;
impl RBCTaskSchema for TestRBCTaskSchema {
    type CodecSchema = SupraDeliveryErasureRs8Schema;
    type ClientType = RBCTaskClient<TestFSMSchema, u32>;
    type FSMType = TestFSMSchema;
    type ClientProvider = TestRBCClientProvider;
    type RBCStateMachineType = TestFsm;
    type ResponseConsumerType = TestResponseConsumer;
}

#[test]
fn successful_rbc_task_creation() {
    let start = TestFsmStates::Start;
    let response_consumer = TestResponseConsumer::new(vec![]);
    let (_client, mut task) = RBCTask::<TestRBCTaskSchema>::new(
        RBCTaskStateTimeConfig::default(),
        response_consumer,
        start,
    );
    assert_eq!(task.get_state_machine().state, TestFsmStates::Start);
}

#[test]
#[should_panic]
fn failed_rbc_task_creation() {
    let start = TestFsmStates::Done;
    let response_consumer = TestResponseConsumer::new(vec![]);
    let (_client, _task) =
        RBCTask::<TestRBCTaskSchema>::new(Default::default(), response_consumer, start);
}

#[tokio::test]
async fn check_rbc_task_consume_response() {
    let start = TestFsmStates::Start;
    let response_consumer = TestResponseConsumer::new(vec![0]);
    let (_client, mut task) =
        RBCTask::<TestRBCTaskSchema>::new(Default::default(), response_consumer, start);
    assert_eq!(task.get_state_machine().state, TestFsmStates::Start);

    // In start state there is no response
    task.consume_response().await;
    let response_idx = task.response_consumer.index.load(Ordering::Relaxed);
    assert_eq!(response_idx, 0);

    // In Any other valid state which has a response of 0
    task.get_state_machine().state = TestFsmStates::Waiting;
    task.consume_response().await;
    let response_idx = task.response_consumer.index.load(Ordering::Relaxed);
    assert_eq!(response_idx, 1);

    // In a state when error is returned in case of response request, no attempt to consume
    task.get_state_machine().state = TestFsmStates::Unknown;
    task.consume_response().await;
    let response_idx = task.response_consumer.index.load(Ordering::Relaxed);
    assert_eq!(response_idx, 1);
}

#[tokio::test]
async fn check_rbc_task_run_state_machine() {
    let start = TestFsmStates::Start;
    let response_consumer = TestResponseConsumer::new(vec![25, 50, 75, 100, 125, 0, 0, 42, 42]);
    let (_client, mut task) =
        RBCTask::<TestRBCTaskSchema>::new(Default::default(), response_consumer, start);
    let execution_state = task.run_state_machine().await;
    // Moves to Preparing State
    assert_eq!(execution_state, ExecutionStatus::InProgress);
    assert_eq!(
        task.get_state_machine().get_state_hash(),
        TestFsmStates::Preparing
    );

    // Stays in Preparing state
    let execution_state = task.run_state_machine().await;
    assert_eq!(execution_state, ExecutionStatus::InProgress);
    assert_eq!(
        task.get_state_machine().get_state_hash(),
        TestFsmStates::Preparing
    );
    let execution_state = task.run_state_machine().await;
    assert_eq!(execution_state, ExecutionStatus::InProgress);

    let execution_state = task.run_state_machine().await;
    assert_eq!(execution_state, ExecutionStatus::InProgress);

    let execution_state = task.run_state_machine().await;
    assert_eq!(execution_state, ExecutionStatus::InProgress);

    // After 4 steps moves to Waiting
    let execution_state = task.run_state_machine().await;
    assert_eq!(execution_state, ExecutionStatus::InProgress);
    assert_eq!(
        task.get_state_machine().get_state_hash(),
        TestFsmStates::Waiting
    );

    // Remains in waiting unless flag is true
    let execution_state = task.run_state_machine().await;
    assert_eq!(execution_state, ExecutionStatus::InProgress);
    assert_eq!(
        task.get_state_machine().get_state_hash(),
        TestFsmStates::Waiting
    );

    // Enable flag to move to Done state
    task.get_state_machine().flag = Some(true);
    let execution_state = task.run_state_machine().await;
    assert_eq!(execution_state, ExecutionStatus::Done);
    assert_eq!(
        task.get_state_machine().get_state_hash(),
        TestFsmStates::Done
    );

    // Remains in the done state
    task.get_state_machine().flag = Some(true);
    let execution_state = task.run_state_machine().await;
    assert_eq!(execution_state, ExecutionStatus::Done);
    assert_eq!(
        task.get_state_machine().get_state_hash(),
        TestFsmStates::Done
    );
}

#[tokio::test]
async fn check_rbc_task_as_standalone_task() {
    let _ = env_logger::try_init();
    let start = TestFsmStates::Start;
    let response_consumer = TestResponseConsumer::new(vec![25, 60, 95, 0, 0, 42]);
    let (client, task) =
        RBCTask::<TestRBCTaskSchema>::new(Default::default(), response_consumer, start);

    // Moves to Preparing State and waits for input
    let handler = tokio::spawn(Task::run(task));

    // consumes 10 and adds to the data (resulting 25 + 10 = 35),
    // runs step, remains in Preparing state, updates the data with 25, resulting to (35 + 25) 60
    let _ = client.tx.send(10);
    // consumes 10 and adds to the data (resulting 60 + 10 = 70),
    // runs step, remains in Preparing state, updates the data with 25, resulting to (70 + 25) 95
    let _ = client.tx.send(10);
    // Consumes 10 and runs step and moves to Waiting state,
    // runs step one more time and remains in Waiting state
    let _ = client.tx.send(10);
    // Consumes 10 and remains in Waiting state
    let _ = client.tx.send(10);
    // Consumes 42 and moves to Done state, Task execution stops, tx channel is closed
    let _ = client.tx.send(42);
    let result = handler.await;
    assert!(result.is_ok());
    assert!(client.tx.is_closed())
}

#[tokio::test]
async fn check_rbc_task_waits_for_inputs_with_timeout() {
    let _ = env_logger::try_init();
    let start = TestFsmStates::Start;
    let response_consumer = TestResponseConsumer::new(vec![25, 60, 85, 110, 0, 0, 1024]);
    let state_idle_config = RBCTaskStateTimeConfig::new(Duration::from_secs(1));
    let (client, task) =
        RBCTask::<TestRBCTaskSchema>::new(state_idle_config.clone(), response_consumer, start);

    // Moves to Preparing State and waits for input
    let handler = tokio::spawn(Task::run(task));
    let client_handler = tokio::spawn(async move {
        // Send a single input and then due to timeout Preparing state will add up 25 default value
        // after 2 time-outs and the state-value will be 110, and will move to Waiting State.
        let _ = client.tx.send(10);
        // Sleep to cause 2 rounds of timeout in Preparing state which will cause move to Waiting state as
        // state-value is > 100
        // and 2 rounds of timeout in Waiting state and causing transition to Done state due to
        // Timeout handling logic in  Waiting state
        sleep(state_idle_config.state_idle_timeout * 10).await;
        // Send 42 to move from Waiting state to Done state successfully without timeout.
    });
    let client_result = client_handler.await;
    assert!(client_result.is_ok());
    let result = handler.await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn check_rbc_task_is_done_when_client_is_done() {
    let _ = env_logger::try_init();
    let start = TestFsmStates::Start;
    let response_consumer = TestResponseConsumer::new(vec![25, 60]);
    let state_idle_config = RBCTaskStateTimeConfig::new(Duration::from_secs(5));
    let (client, task) =
        RBCTask::<TestRBCTaskSchema>::new(state_idle_config, response_consumer, start);

    // Moves to Preparing State and waits for input
    let handler = tokio::spawn(Task::run(task));
    let client_handler = tokio::spawn(async move { client.tx.send(10) });
    sleep(Duration::from_secs(3)).await;
    // when thread is done client drops TX which causes to Task to stop as well.
    let client_result = client_handler.await;
    assert!(client_result.is_ok());
    let result = handler.await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn check_rbc_task_state_apis() {
    let _ = env_logger::try_init();
    let (committee_tx, mut committee_rx) =
        unbounded_channel::<RBCCommitteeMessage<SupraDeliveryErasureRs8Schema>>();
    let committee_client =
        CommitteeRBCClientProvider::<SupraDeliveryErasureRs8Schema>::new(committee_tx);
    let mut committee_client_state = RBCTaskState::InProgress(committee_client, Instant::now());
    assert!(committee_client_state
        .send(RBCMessage::Composite(vec![]))
        .is_ok());
    assert!(committee_rx.try_recv().is_ok());
    assert!(!committee_client_state.is_done());
    assert!(committee_client_state.is_inprogress());
    assert!(committee_client_state.client().is_some());
    sleep(Duration::from_secs(2)).await;
    assert!(committee_client_state.is_stale(Duration::from_secs(1)));
    assert!(!committee_client_state.is_stale(Duration::from_secs(10)));
    let elapsed = committee_client_state.elapsed();
    committee_client_state.refresh();
    assert!(committee_client_state.elapsed() < elapsed);

    let (nt_tx, mut nt_rx) =
        unbounded_channel::<RBCNetworkMessage<SupraDeliveryErasureRs8Schema>>();
    let network_client = NetworkRBCClientProvider::<SupraDeliveryErasureRs8Schema>::new(nt_tx);

    let mut nt_client_state = RBCTaskState::InProgress(network_client, Instant::now());
    assert!(nt_client_state
        .send(RBCMessage::Share(share_data(
            [0; 32],
            value_data_with_header(Header::default())
        )))
        .is_ok());
    assert!(nt_rx.try_recv().is_ok());
    assert!(!nt_client_state.is_done());
    assert!(nt_client_state.is_inprogress());
    sleep(Duration::from_secs(2)).await;
    assert!(nt_client_state.is_stale(Duration::from_secs(1)));
    assert!(!nt_client_state.is_stale(Duration::from_secs(10)));
    let elapsed = nt_client_state.elapsed();
    nt_client_state.refresh();
    assert!(nt_client_state.elapsed() < elapsed);

    let mut done_state = RBCTaskState::<SupraDeliveryErasureRs8Schema>::Done(Instant::now(), 0);
    assert!(done_state.send(RBCMessage::Composite(vec![])).is_ok());
    assert!(done_state.is_done());
    assert!(done_state.client().is_none());
    assert!(!done_state.is_inprogress());
    sleep(Duration::from_secs(2)).await;
    assert!(done_state.is_stale(Duration::from_secs(1)));
    assert!(!done_state.is_stale(Duration::from_secs(10)));

    let elapsed = done_state.elapsed();
    done_state.refresh();
    assert!(done_state.elapsed() < elapsed);
}

#[test]
fn check_client_type_flags() {
    let (tx, _rx) = unbounded_channel();
    let committee_client = CommitteeRBCClientProvider::<SupraDeliveryErasureRs8Schema>::new(tx);
    assert!(committee_client.is_committee());
    assert!(!committee_client.is_sync());
    assert!(!committee_client.is_network());

    let (tx, _rx) = unbounded_channel();
    let sync_client = SyncRBCClientProvider::<SupraDeliveryErasureRs8Schema>::new(tx);
    assert!(!sync_client.is_committee());
    assert!(sync_client.is_sync());
    assert!(!sync_client.is_network());

    let (tx, _rx) = unbounded_channel();
    let nt_client = NetworkRBCClientProvider::<SupraDeliveryErasureRs8Schema>::new(tx);
    assert!(!nt_client.is_committee());
    assert!(!nt_client.is_sync());
    assert!(nt_client.is_network());
}
