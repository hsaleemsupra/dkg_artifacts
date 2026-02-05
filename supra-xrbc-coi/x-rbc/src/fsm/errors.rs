use crate::tasks::messages::TimeoutMessage;
use sfsm::MessageError;
use std::fmt::Debug;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FSMError<MsgType: Debug, StateType: Debug> {
    #[error("{0}: {1}")]
    InputInvalidState(StateType, Option<MsgType>),
    #[error("{0}: {1:?}")]
    TimeoutInvalidState(StateType, Option<TimeoutMessage>),
    #[error("No response can be retrieved in state: {0}")]
    ResponseInvalidState(StateType),
    #[error("{0}: {1}")]
    InputInactiveState(StateType, Option<MsgType>),
    #[error("{0} is inactive")]
    ResponseInactiveState(StateType),
    #[error("{0}: {1:?}")]
    TimeoutInactiveState(StateType, Option<TimeoutMessage>),
    #[error("Failed in state: {0}")]
    ExecutionError(StateType),
    #[error("Unknown/unhandled state")]
    UnknownState,
}

impl<MsgType: Debug, StateType: Debug> From<(MessageError<MsgType>, StateType)>
    for FSMError<MsgType, StateType>
{
    fn from((msg_error, state): (MessageError<MsgType>, StateType)) -> Self {
        match msg_error {
            MessageError::StateIsNotActive(data) => FSMError::InputInactiveState(state, Some(data)),
            _ => {
                panic!("Unsupported type")
            }
        }
    }
}

impl<MsgType: Debug, StateType: Debug> From<StateType> for FSMError<MsgType, StateType> {
    fn from(state: StateType) -> Self {
        FSMError::ExecutionError(state)
    }
}
