use sfsm::{MessageError, StateMachine};
use std::fmt::Debug;
use std::hash::Hash;

pub(crate) mod committee_state_machine;
pub(crate) mod errors;
pub(crate) mod network_message_state_machine;
pub(crate) mod sync_state_machine;

use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::messages::TimeoutMessage;
pub(crate) use committee_state_machine::CommitteeStateMachine;
pub(crate) use network_message_state_machine::NetworkMessageStateMachine;
pub(crate) use sync_state_machine::SyncStateMachine;

#[derive(PartialEq, Debug)]
pub(crate) enum ExecutionStatus {
    Done,
    InProgress,
}

///
/// State machine input output type definition
///
pub(crate) trait FSMSchema {
    /// Input Messages consumed by the states of the state-machine
    type InputMessageType: Send + Sync + Debug;
    /// Output produced upon state-machine execution
    type ResponseType: Send;
    /// Encoding schema of the data processed by the state machine
    type CodecSchema: SupraDeliveryErasureCodecSchema;
}

pub(crate) trait RBCStateMachine<Schema: FSMSchema>
where
    Self: StateMachine,
{
    type StateHash: PartialEq + Debug + Hash + Eq + Send;
    type RbcSmError: From<Self::StateHash> + Debug + Send;

    ///
    /// Handles external input messages
    ///
    fn process_message(&mut self, input: Schema::InputMessageType) -> Result<(), Self::RbcSmError>;

    ///
    /// Handles internal timeout-messages
    ///
    fn handle_timeout(&mut self, input: TimeoutMessage) -> Result<(), Self::RbcSmError>;

    fn do_step(&mut self) -> Result<(), Self::RbcSmError> {
        let state = self.get_state_hash();
        self.step().map_err(|_| Self::RbcSmError::from(state))
    }

    fn do_start(
        &mut self,
        initial_state: <Self as StateMachine>::InitialState,
    ) -> Result<(), Self::RbcSmError> {
        let state = self.get_state_hash();
        self.start(initial_state)
            .map_err(|_| Self::RbcSmError::from(state))
    }

    fn get_response(&mut self) -> Result<Option<Schema::ResponseType>, Self::RbcSmError>;

    fn get_execution_status(&self) -> ExecutionStatus;

    fn get_state_hash(&self) -> Self::StateHash;

    fn did_transition(&self, previous_state: Self::StateHash) -> bool {
        let current_state = self.get_state_hash();
        current_state != previous_state
    }
}

pub(crate) fn extract_data<T>(message_error: MessageError<T>) -> Option<T> {
    match message_error {
        MessageError::StateIsNotActive(data) => Some(data),
        _ => None,
    }
}
