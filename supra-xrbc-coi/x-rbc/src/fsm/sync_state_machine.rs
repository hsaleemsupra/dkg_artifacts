use crate::fsm::errors::FSMError;
use crate::fsm::{extract_data, ExecutionStatus, FSMSchema, RBCStateMachine};
use crate::states::{DoneSyncFSM, NotStartedSyncFSM, SyncReady, WaitingForSyncData};
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::messages::{RBCSyncMessage, SyncFSMResponseMessage};

use crate::tasks::messages::TimeoutMessage;
use log::warn;
use sfsm::IsState;
use sfsm::*;
use std::marker::PhantomData;

add_state_machine!(
    ///
    /// State machine handling synchronization of the payload in the chain
    ///
    pub(crate) SyncStateMachine <C: SupraDeliveryErasureCodecSchema>,
    NotStartedSyncFSM<C>,
    [NotStartedSyncFSM<C>, WaitingForSyncData<C>, SyncReady<C>, DoneSyncFSM<C>],
    [
        NotStartedSyncFSM<C> => WaitingForSyncData<C>,
        NotStartedSyncFSM<C> => SyncReady<C>,
        WaitingForSyncData<C> => SyncReady<C>,
        WaitingForSyncData<C> => DoneSyncFSM<C>,
        SyncReady<C> => DoneSyncFSM<C>,
    ]
);

///
/// Input and output Messages consumed and produced by SyncStateMachine states
///
add_messages!(SyncStateMachine<C: SupraDeliveryErasureCodecSchema>,
    [
        RBCSyncMessage<C> -> WaitingForSyncData<C>,
        TimeoutMessage -> WaitingForSyncData<C>,
        RBCSyncMessage<C> -> SyncReady<C>,
        TimeoutMessage -> SyncReady<C>,
        SyncFSMResponseMessage<C> <- WaitingForSyncData<C>,
        SyncFSMResponseMessage<C> <- SyncReady<C>,
        SyncFSMResponseMessage<C> <- DoneSyncFSM<C>,
    ]

);

impl<C: SupraDeliveryErasureCodecSchema> Default for SyncStateMachine<C> {
    fn default() -> Self {
        SyncStateMachine::<C>::new()
    }
}

///
/// Data structure holding static information about Input & Output of the sync state machine
///
pub(crate) struct SyncFSMSchema<C: SupraDeliveryErasureCodecSchema> {
    _phantom_: PhantomData<C>,
}

///
/// Input & Output definition of the sync state-machine
///
impl<C: SupraDeliveryErasureCodecSchema> FSMSchema for SyncFSMSchema<C> {
    type InputMessageType = RBCSyncMessage<C>;
    type ResponseType = SyncFSMResponseMessage<C>;
    type CodecSchema = C;
}

///
/// Shortcut names of the states of the sync state-machine
///
#[derive(PartialEq, Debug, Hash, Eq)]
#[allow(clippy::upper_case_acronyms)]
#[allow(non_camel_case_types)]
pub(crate) enum SyncStateHash {
    NS,
    WFSD,
    SYC_RDY,
    DONE,
}

///
/// Common RBCStateMachine interface definition for the sync state-machine
///
impl<C: SupraDeliveryErasureCodecSchema> RBCStateMachine<SyncFSMSchema<C>> for SyncStateMachine<C> {
    type StateHash = SyncStateHash;
    type RbcSmError = FSMError<RBCSyncMessage<C>, SyncStateHash>;

    fn process_message(&mut self, input: RBCSyncMessage<C>) -> Result<(), Self::RbcSmError> {
        let state_hash: SyncStateHash = self.get_state_hash();
        let result = match state_hash {
            SyncStateHash::NS => {
                return Err(FSMError::InputInvalidState(SyncStateHash::NS, Some(input)));
            }
            SyncStateHash::WFSD => {
                PushMessage::<WaitingForSyncData<C>, RBCSyncMessage<C>>::push_message(self, input)
            }
            SyncStateHash::SYC_RDY => {
                PushMessage::<SyncReady<C>, RBCSyncMessage<C>>::push_message(self, input)
            }

            SyncStateHash::DONE => {
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
        let state_hash: SyncStateHash = self.get_state_hash();
        let result = match state_hash {
            SyncStateHash::NS => {
                return Err(FSMError::TimeoutInvalidState(
                    SyncStateHash::NS,
                    Some(input),
                ));
            }
            SyncStateHash::WFSD => {
                PushMessage::<WaitingForSyncData<C>, TimeoutMessage>::push_message(self, input)
            }
            SyncStateHash::SYC_RDY => {
                PushMessage::<SyncReady<C>, TimeoutMessage>::push_message(self, input)
            }
            SyncStateHash::DONE => {
                return Err(FSMError::TimeoutInvalidState(
                    SyncStateHash::DONE,
                    Some(input),
                ));
            }
        };
        result.map_err(|e| {
            FSMError::TimeoutInactiveState(state_hash, extract_data::<TimeoutMessage>(e))
        })
    }

    fn get_response(&mut self) -> Result<Option<SyncFSMResponseMessage<C>>, Self::RbcSmError> {
        let state_hash: SyncStateHash = self.get_state_hash();
        let result = match state_hash {
            SyncStateHash::NS => {
                return Err(FSMError::ResponseInvalidState(SyncStateHash::NS));
            }
            SyncStateHash::WFSD => {
                PollMessage::<WaitingForSyncData<C>, SyncFSMResponseMessage<C>>::poll_message(self)
            }
            SyncStateHash::SYC_RDY => {
                PollMessage::<SyncReady<C>, SyncFSMResponseMessage<C>>::poll_message(self)
            }
            SyncStateHash::DONE => {
                PollMessage::<DoneSyncFSM<C>, SyncFSMResponseMessage<C>>::poll_message(self)
            }
        };
        result.map_err(|_e| FSMError::ResponseInactiveState(state_hash))
    }

    fn get_execution_status(&self) -> ExecutionStatus {
        if IsState::<DoneSyncFSM<C>>::is_state(self) {
            ExecutionStatus::Done
        } else {
            ExecutionStatus::InProgress
        }
    }

    fn get_state_hash(&self) -> Self::StateHash
    where
        Self: StateMachine,
    {
        if IsState::<NotStartedSyncFSM<C>>::is_state(self) {
            SyncStateHash::NS
        } else if IsState::<WaitingForSyncData<C>>::is_state(self) {
            SyncStateHash::WFSD
        } else if IsState::<SyncReady<C>>::is_state(self) {
            SyncStateHash::SYC_RDY
        } else {
            SyncStateHash::DONE
        }
    }
}

#[cfg(test)]
#[path = "tests/sync_state_machine_tests.rs"]
pub mod sync_state_machine_tests;
