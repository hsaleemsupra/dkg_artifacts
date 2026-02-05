use crate::fsm::errors::FSMError;
use crate::fsm::{ExecutionStatus, FSMSchema, RBCStateMachine};
use crate::states::{DoneNetworkFSM, NotStartedNetworkFSM, WaitingForShare};
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::messages::TimeoutMessage;
use crate::types::messages::{NetworkFSMResponseMessage, RBCNetworkMessage};
use log::warn;
use sfsm::*;
use std::marker::PhantomData;

add_state_machine!(
    ///
    /// State machine definition for non-committee-payload|network-message handling
    /// Non-committee payload|network-message is the data shared by the broadcaster clan with the rest
    /// of the clans in the chain. The pseudo-name of this process is also Clan2Tribe(c2t) distribution
    ///
    pub(crate) NetworkMessageStateMachine<C: SupraDeliveryErasureCodecSchema>,
    NotStartedNetworkFSM<C>,
    [NotStartedNetworkFSM<C>, WaitingForShare<C>, DoneNetworkFSM<C>],
    [
        NotStartedNetworkFSM<C> => WaitingForShare<C>,
        WaitingForShare<C> => DoneNetworkFSM<C>
    ]
);

///
/// Input and Output Messages handled by NetworkMessageStateMachine states
///
add_messages!(NetworkMessageStateMachine<C: SupraDeliveryErasureCodecSchema>,
    [
        RBCNetworkMessage<C> -> WaitingForShare<C>,
        NetworkFSMResponseMessage<C> <- WaitingForShare<C>,
        NetworkFSMResponseMessage<C> <- DoneNetworkFSM<C>,
    ]
);

impl<C: SupraDeliveryErasureCodecSchema> Default for NetworkMessageStateMachine<C> {
    fn default() -> Self {
        NetworkMessageStateMachine::<C>::new()
    }
}

///
/// Data structure holding static information about Input & Output of the network message(c2t)
/// processing state-machine
///
pub(crate) struct NetworkMessageFSMSchema<C: SupraDeliveryErasureCodecSchema> {
    _phantom_: PhantomData<C>,
}

///
/// Input & Output definition of the network message(c2t) processing state-machine
///
impl<C: SupraDeliveryErasureCodecSchema> FSMSchema for NetworkMessageFSMSchema<C> {
    type InputMessageType = RBCNetworkMessage<C>;
    type ResponseType = NetworkFSMResponseMessage<C>;
    type CodecSchema = C;
}

///
/// Shortcut names of the states of the network message(c2t) processing state-machine
///
#[derive(PartialEq, Debug, Hash, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum NetworkMessageStateHash {
    NS,
    WFS,
    DONE,
}

///
/// Common RBCStateMachine interface definition for the network message(c2t) processing state-machine
///
impl<C: SupraDeliveryErasureCodecSchema> RBCStateMachine<NetworkMessageFSMSchema<C>>
    for NetworkMessageStateMachine<C>
{
    type StateHash = NetworkMessageStateHash;
    type RbcSmError = FSMError<RBCNetworkMessage<C>, NetworkMessageStateHash>;

    fn process_message(&mut self, input: RBCNetworkMessage<C>) -> Result<(), Self::RbcSmError> {
        let state_hash: NetworkMessageStateHash = self.get_state_hash();
        let result = match state_hash {
            NetworkMessageStateHash::NS => {
                return Err(FSMError::InputInvalidState(
                    NetworkMessageStateHash::NS,
                    Some(input),
                ));
            }
            NetworkMessageStateHash::WFS => {
                PushMessage::<WaitingForShare<C>, RBCNetworkMessage<C>>::push_message(self, input)
            }
            NetworkMessageStateHash::DONE => {
                warn!("Network FSM is in Done state, skipping input message handling");
                Ok(())
            }
        };
        result.map_err(|e| FSMError::from((e, state_hash)))
    }

    ///
    /// Network State Machine states does have specific handling logic for timeouts at state-level
    ///
    fn handle_timeout(&mut self, _input: TimeoutMessage) -> Result<(), Self::RbcSmError> {
        Ok(())
    }

    fn get_response(&mut self) -> Result<Option<NetworkFSMResponseMessage<C>>, Self::RbcSmError> {
        let state_hash: NetworkMessageStateHash = self.get_state_hash();
        let result = match state_hash {
            NetworkMessageStateHash::NS => {
                return Err(FSMError::ResponseInvalidState(NetworkMessageStateHash::NS));
            }
            NetworkMessageStateHash::WFS => {
                PollMessage::<WaitingForShare<C>, NetworkFSMResponseMessage<C>>::poll_message(self)
            }
            NetworkMessageStateHash::DONE => {
                PollMessage::<DoneNetworkFSM<C>, NetworkFSMResponseMessage<C>>::poll_message(self)
            }
        };
        result.map_err(|_e| FSMError::ResponseInactiveState(state_hash))
    }

    fn get_execution_status(&self) -> ExecutionStatus {
        if IsState::<DoneNetworkFSM<C>>::is_state(self) {
            ExecutionStatus::Done
        } else {
            ExecutionStatus::InProgress
        }
    }

    fn get_state_hash(&self) -> Self::StateHash {
        if IsState::<NotStartedNetworkFSM<C>>::is_state(self) {
            NetworkMessageStateHash::NS
        } else if IsState::<WaitingForShare<C>>::is_state(self) {
            NetworkMessageStateHash::WFS
        } else {
            NetworkMessageStateHash::DONE
        }
    }
}

#[cfg(test)]
#[path = "tests/network_message_state_machine_tests.rs"]
pub mod network_message_state_machine_tests;
