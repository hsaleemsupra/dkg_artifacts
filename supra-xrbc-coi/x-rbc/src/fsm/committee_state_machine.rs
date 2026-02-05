use crate::fsm::errors::FSMError;
use crate::fsm::{extract_data, ExecutionStatus, FSMSchema, RBCStateMachine};
use crate::states::{
    DoneCommitteeFSM, NotStartedCommitteeFSM, WaitingForCertificate, WaitingForData, WaitingForVote,
};
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::messages::TimeoutMessage;
use crate::types::messages::{CommitteeFSMResponseMessage, RBCCommitteeMessage};
use log::warn;
use sfsm::IsState;
use sfsm::*;
use std::marker::PhantomData;

add_state_machine!(
    ///
    /// Committee Message handling state machine
    /// Committee message is the data shared between the peers in broadcaster(message producer) clan
    ///
    pub(crate) CommitteeStateMachine <C: SupraDeliveryErasureCodecSchema>,
    NotStartedCommitteeFSM<C>,
    [NotStartedCommitteeFSM<C>, WaitingForData<C>, WaitingForVote<C>, WaitingForCertificate<C>, DoneCommitteeFSM<C>],
    [
        NotStartedCommitteeFSM<C> => WaitingForData<C>,
        NotStartedCommitteeFSM<C> => WaitingForVote<C>,
        WaitingForData<C> => WaitingForVote<C>,
        WaitingForData<C> => WaitingForCertificate<C>,
        WaitingForData<C> => DoneCommitteeFSM<C>,
        WaitingForVote<C> => WaitingForCertificate<C>,
        WaitingForVote<C> => DoneCommitteeFSM<C>,
        WaitingForCertificate<C> => DoneCommitteeFSM<C>,
    ]
);

///
/// Input and Output Messages handled by CommitteeStateMachine states
///
add_messages!(CommitteeStateMachine<C: SupraDeliveryErasureCodecSchema>,
    [
        RBCCommitteeMessage<C> -> WaitingForData<C>,
        RBCCommitteeMessage<C> -> WaitingForVote<C>,
        TimeoutMessage -> WaitingForVote<C>,
        RBCCommitteeMessage<C> -> WaitingForCertificate<C>,
        CommitteeFSMResponseMessage<C> <- WaitingForData<C>,
        CommitteeFSMResponseMessage<C> <- WaitingForVote<C>,
        CommitteeFSMResponseMessage<C> <- WaitingForCertificate<C>,
        CommitteeFSMResponseMessage<C> <- DoneCommitteeFSM<C>,
    ]

);

impl<C: SupraDeliveryErasureCodecSchema> Default for CommitteeStateMachine<C> {
    fn default() -> Self {
        CommitteeStateMachine::<C>::new()
    }
}

///
/// Data structure holding static information about Input & Output of the committee message
/// processing state-machine
///
pub(crate) struct CommitteeFSMSchema<C: SupraDeliveryErasureCodecSchema> {
    _phantom_: PhantomData<C>,
}

///
/// Input & Output definition of the committee message processing state-machine
///
impl<C: SupraDeliveryErasureCodecSchema> FSMSchema for CommitteeFSMSchema<C> {
    type InputMessageType = RBCCommitteeMessage<C>;
    type ResponseType = CommitteeFSMResponseMessage<C>;
    type CodecSchema = C;
}

///
/// Shortcut names of the states of the committee state-machine
///
#[derive(PartialEq, Debug, Hash, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum CommitteeStateHash {
    NS,
    WFD,
    WFV,
    WFC,
    DONE,
}

///
/// Common RBCStateMachine interface definition for the committee message processing state-machine
///
impl<C: SupraDeliveryErasureCodecSchema> RBCStateMachine<CommitteeFSMSchema<C>>
    for CommitteeStateMachine<C>
{
    type StateHash = CommitteeStateHash;
    type RbcSmError = FSMError<RBCCommitteeMessage<C>, CommitteeStateHash>;

    fn process_message(&mut self, input: RBCCommitteeMessage<C>) -> Result<(), Self::RbcSmError> {
        let state_hash: CommitteeStateHash = self.get_state_hash();
        let result = match state_hash {
            CommitteeStateHash::NS => {
                return Err(FSMError::InputInvalidState(
                    CommitteeStateHash::NS,
                    Some(input),
                ));
            }
            CommitteeStateHash::WFD => {
                PushMessage::<WaitingForData<C>, RBCCommitteeMessage<C>>::push_message(self, input)
            }
            CommitteeStateHash::WFV => {
                PushMessage::<WaitingForVote<C>, RBCCommitteeMessage<C>>::push_message(self, input)
            }

            CommitteeStateHash::WFC => PushMessage::<
                WaitingForCertificate<C>,
                RBCCommitteeMessage<C>,
            >::push_message(self, input),
            CommitteeStateHash::DONE => {
                warn!("FSM is in Done state, skipping input message handling");
                Ok(())
            }
        };
        result.map_err(|e| FSMError::from((e, state_hash)))
    }

    ///
    /// Handles state stale timeout message
    ///
    fn handle_timeout(&mut self, input: TimeoutMessage) -> Result<(), Self::RbcSmError> {
        let state_hash: CommitteeStateHash = self.get_state_hash();
        let result = match state_hash {
            CommitteeStateHash::NS => {
                return Err(FSMError::TimeoutInvalidState(
                    CommitteeStateHash::NS,
                    Some(input),
                ));
            }
            CommitteeStateHash::WFV => {
                PushMessage::<WaitingForVote<C>, TimeoutMessage>::push_message(self, input)
            }
            CommitteeStateHash::WFD | CommitteeStateHash::WFC | CommitteeStateHash::DONE => Ok(()),
        };
        result.map_err(|e| {
            FSMError::TimeoutInactiveState(state_hash, extract_data::<TimeoutMessage>(e))
        })
    }

    fn get_response(&mut self) -> Result<Option<CommitteeFSMResponseMessage<C>>, Self::RbcSmError> {
        let state_hash: CommitteeStateHash = self.get_state_hash();
        let result = match state_hash {
            CommitteeStateHash::NS => {
                return Err(FSMError::ResponseInvalidState(CommitteeStateHash::NS));
            }
            CommitteeStateHash::WFD => {
                PollMessage::<WaitingForData<C>, CommitteeFSMResponseMessage<C>>::poll_message(self)
            }
            CommitteeStateHash::WFV => {
                PollMessage::<WaitingForVote<C>, CommitteeFSMResponseMessage<C>>::poll_message(self)
            }
            CommitteeStateHash::WFC => PollMessage::<
                WaitingForCertificate<C>,
                CommitteeFSMResponseMessage<C>,
            >::poll_message(self),
            CommitteeStateHash::DONE => PollMessage::<
                DoneCommitteeFSM<C>,
                CommitteeFSMResponseMessage<C>,
            >::poll_message(self),
        };
        result.map_err(|_e| FSMError::ResponseInactiveState(state_hash))
    }

    fn get_execution_status(&self) -> ExecutionStatus {
        if IsState::<DoneCommitteeFSM<C>>::is_state(self) {
            ExecutionStatus::Done
        } else {
            ExecutionStatus::InProgress
        }
    }

    fn get_state_hash(&self) -> Self::StateHash
    where
        Self: StateMachine,
    {
        if IsState::<NotStartedCommitteeFSM<C>>::is_state(self) {
            CommitteeStateHash::NS
        } else if IsState::<WaitingForData<C>>::is_state(self) {
            CommitteeStateHash::WFD
        } else if IsState::<WaitingForVote<C>>::is_state(self) {
            CommitteeStateHash::WFV
        } else if IsState::<WaitingForCertificate<C>>::is_state(self) {
            CommitteeStateHash::WFC
        } else {
            CommitteeStateHash::DONE
        }
    }
}

#[cfg(test)]
#[path = "tests/committee_state_machine_tests.rs"]
pub mod committee_state_machine_tests;
