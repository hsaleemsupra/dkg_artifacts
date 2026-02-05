use crate::fsm::errors::FSMError;
use crate::fsm::sync_state_machine::SyncStateHash;
use crate::fsm::sync_state_machine::SyncStateMachineStates;
use crate::fsm::RBCStateMachine;
use crate::fsm::{ExecutionStatus, SyncStateMachine};
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;

use crate::types::messages::{EchoValueData, RBCSyncMessage, SyncFSMResponseMessage};

use crate::tasks::messages::TimeoutMessage;
use crate::types::tests::get_value_data;
use crate::SupraDeliveryErasureRs16Schema;

fn check_execution_status_state_hash<Schema: SupraDeliveryErasureCodecSchema>(
    fsm: &SyncStateMachine<Schema>,
    status: ExecutionStatus,
    state: SyncStateHash,
) {
    assert_eq!(state, fsm.get_state_hash());
    assert_eq!(status, fsm.get_execution_status());
}

#[test]
fn check_state_machine_flags() {
    let mut sync_fsm = SyncStateMachine::new();
    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedSyncFSMCState(None);
    check_execution_status_state_hash(&sync_fsm, ExecutionStatus::InProgress, SyncStateHash::NS);

    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForSyncDataCState(None);

    check_execution_status_state_hash(&sync_fsm, ExecutionStatus::InProgress, SyncStateHash::WFSD);
    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::SyncReadyCState(None);
    check_execution_status_state_hash(
        &sync_fsm,
        ExecutionStatus::InProgress,
        SyncStateHash::SYC_RDY,
    );

    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::DoneSyncFSMCState(None);
    check_execution_status_state_hash(&sync_fsm, ExecutionStatus::Done, SyncStateHash::DONE);
}

#[test]
fn check_process_message() {
    type ProcessResult =
        Result<(), FSMError<RBCSyncMessage<SupraDeliveryErasureRs16Schema>, SyncStateHash>>;

    let check = |result: Result<_, _>, state: SyncStateHash| {
        assert!(result.is_err());
        match result.unwrap_err() {
            FSMError::InputInactiveState(e_state, data) => {
                assert_eq!(e_state, state);
                assert!(data.is_some());
            }
            _ => {
                panic!()
            }
        };
    };
    let echo_value = || -> EchoValueData<SupraDeliveryErasureRs16Schema> {
        EchoValueData::new(get_value_data::<SupraDeliveryErasureRs16Schema>())
    };

    let mut sync_fsm = SyncStateMachine::new();
    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedSyncFSMCState(None);
    let result: ProcessResult = sync_fsm.process_message(RBCSyncMessage::EchoValue(echo_value()));
    assert!(result.is_err());
    match result.unwrap_err() {
        FSMError::InputInvalidState(state, data) => {
            assert_eq!(state, SyncStateHash::NS);
            assert!(data.is_some());
        }
        _ => {
            panic!()
        }
    };

    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForSyncDataCState(None);
    let result: ProcessResult = sync_fsm.process_message(RBCSyncMessage::EchoValue(echo_value()));
    check(result, SyncStateHash::WFSD);

    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::SyncReadyCState(None);
    let result: ProcessResult = sync_fsm.process_message(RBCSyncMessage::EchoValue(echo_value()));
    check(result, SyncStateHash::SYC_RDY);

    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::DoneSyncFSMCState(None);
    let result: ProcessResult = sync_fsm.process_message(RBCSyncMessage::EchoValue(echo_value()));
    assert!(result.is_ok());
}

#[test]
fn check_get_response() {
    type ResponseResult = Result<
        Option<SyncFSMResponseMessage<SupraDeliveryErasureRs16Schema>>,
        FSMError<RBCSyncMessage<SupraDeliveryErasureRs16Schema>, SyncStateHash>,
    >;
    let check = |result: Result<_, _>, state: SyncStateHash| {
        assert!(result.is_err());
        match result.unwrap_err() {
            FSMError::ResponseInactiveState(e_state) => {
                assert_eq!(e_state, state);
            }
            _ => {
                panic!()
            }
        };
    };
    let mut sync_fsm = SyncStateMachine::new();
    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedSyncFSMCState(None);
    let result: ResponseResult = sync_fsm.get_response();
    assert!(result.is_err());
    match result.unwrap_err() {
        FSMError::ResponseInvalidState(state) => {
            assert_eq!(state, SyncStateHash::NS);
        }
        _ => {
            panic!()
        }
    };

    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForSyncDataCState(None);

    let result: ResponseResult = sync_fsm.get_response();
    check(result, SyncStateHash::WFSD);

    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::SyncReadyCState(None);
    let result: ResponseResult = sync_fsm.get_response();
    check(result, SyncStateHash::SYC_RDY);

    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::DoneSyncFSMCState(None);
    let result: ResponseResult = sync_fsm.get_response();
    check(result, SyncStateHash::DONE);
}

#[test]
fn check_handle_timeout() {
    type ProcessResult =
        Result<(), FSMError<RBCSyncMessage<SupraDeliveryErasureRs16Schema>, SyncStateHash>>;
    let check_timeout_message_in_inactive_state =
        |sync_fsm: &mut SyncStateMachine<SupraDeliveryErasureRs16Schema>,
         e_state: SyncStateHash| {
            let result: ProcessResult = sync_fsm.handle_timeout(TimeoutMessage::Retry);
            assert!(result.is_err());
            match result.unwrap_err() {
                FSMError::TimeoutInactiveState(a_state, message) => {
                    assert_eq!(e_state, a_state);
                    assert_eq!(message, Some(TimeoutMessage::Retry));
                }
                _ => {
                    panic!()
                }
            };
        };

    let check_timeout_message_is_invalid_for_state =
        |sync_fsm: &mut SyncStateMachine<SupraDeliveryErasureRs16Schema>,
         e_state: SyncStateHash| {
            let result: ProcessResult = sync_fsm.handle_timeout(TimeoutMessage::Retry);
            assert!(result.is_err());
            match result.unwrap_err() {
                FSMError::TimeoutInvalidState(state, message) => {
                    assert_eq!(state, e_state);
                    assert_eq!(message, Some(TimeoutMessage::Retry))
                }
                _ => {
                    panic!()
                }
            };
        };

    let mut sync_fsm = SyncStateMachine::<SupraDeliveryErasureRs16Schema>::new();
    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedSyncFSMCState(None);
    check_timeout_message_is_invalid_for_state(&mut sync_fsm, SyncStateHash::NS);

    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForSyncDataCState(None);
    check_timeout_message_in_inactive_state(&mut sync_fsm, SyncStateHash::WFSD);

    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::SyncReadyCState(None);
    check_timeout_message_in_inactive_state(&mut sync_fsm, SyncStateHash::SYC_RDY);

    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::DoneSyncFSMCState(None);
    check_timeout_message_is_invalid_for_state(&mut sync_fsm, SyncStateHash::DONE);
}

#[test]
fn check_did_transition() {
    let mut sync_fsm = SyncStateMachine::new();
    sync_fsm.states =
        SyncStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedSyncFSMCState(None);
    let result = sync_fsm.did_transition(SyncStateHash::NS);
    assert!(!result);

    let result = sync_fsm.did_transition(SyncStateHash::WFSD);
    assert!(result)
}
