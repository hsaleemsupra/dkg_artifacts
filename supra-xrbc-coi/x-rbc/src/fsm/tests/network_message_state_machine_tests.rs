use crate::fsm::errors::FSMError;
use crate::fsm::network_message_state_machine::NetworkMessageStateHash;
use crate::fsm::network_message_state_machine::NetworkMessageStateMachine;
use crate::fsm::network_message_state_machine::NetworkMessageStateMachineStates;
use crate::fsm::ExecutionStatus;
use crate::fsm::RBCStateMachine;
use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::messages::TimeoutMessage;
use crate::types::messages::chunk::ChunkData;
use crate::types::messages::share_data::ShareData;
use crate::types::messages::value_data::ValueData;
use crate::types::messages::{NetworkFSMResponseMessage, RBCNetworkMessage};
use crate::SupraDeliveryErasureRs16Schema;
use erasure::utils::codec_trait::Codec;
use primitives::types::Header;
use vec_commitment::committed_chunk::{CommitmentMeta, CommittedChunk};

fn check_execution_status_state_hash<Schema: SupraDeliveryErasureCodecSchema>(
    fsm: &NetworkMessageStateMachine<Schema>,
    status: ExecutionStatus,
    state: NetworkMessageStateHash,
) {
    assert_eq!(state, fsm.get_state_hash());
    assert_eq!(status, fsm.get_execution_status());
}

#[test]
fn check_state_machine_flags() {
    let mut network_fsm = NetworkMessageStateMachine::new();
    network_fsm.states =
        NetworkMessageStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedNetworkFSMCState(
            None,
        );
    check_execution_status_state_hash(
        &network_fsm,
        ExecutionStatus::InProgress,
        NetworkMessageStateHash::NS,
    );

    network_fsm.states =
        NetworkMessageStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForShareCState(
            None,
        );

    check_execution_status_state_hash(
        &network_fsm,
        ExecutionStatus::InProgress,
        NetworkMessageStateHash::WFS,
    );
    network_fsm.states =
        NetworkMessageStateMachineStates::<SupraDeliveryErasureRs16Schema>::DoneNetworkFSMCState(
            None,
        );
    check_execution_status_state_hash(
        &network_fsm,
        ExecutionStatus::Done,
        NetworkMessageStateHash::DONE,
    );
}

fn get_share_data<S: SupraDeliveryErasureCodecSchema>() -> ShareData<S> {
    let header = Header::default();
    let chunk = ChunkData::new(CommittedChunk::<
        <<S as SupraDeliveryErasureCodecSchema>::DataCodec as Codec>::Chunk,
    >::default());
    let value = ValueData::<S>::new(header, chunk);
    ShareData::<S>::new([2; 32], value, CommitmentMeta::default())
}

#[test]
fn check_process_message() {
    type ProcessResult = Result<
        (),
        FSMError<RBCNetworkMessage<SupraDeliveryErasureRs16Schema>, NetworkMessageStateHash>,
    >;
    let check = |result: Result<_, _>, state: NetworkMessageStateHash| {
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
    let mut network_fsm = NetworkMessageStateMachine::new();
    network_fsm.states =
        NetworkMessageStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedNetworkFSMCState(
            None,
        );
    let input = get_share_data::<SupraDeliveryErasureRs16Schema>();
    let result: ProcessResult = network_fsm.process_message(RBCNetworkMessage::Share(input));
    assert!(result.is_err());
    match result.unwrap_err() {
        FSMError::InputInvalidState(state, data) => {
            assert_eq!(state, NetworkMessageStateHash::NS);
            assert!(data.is_some());
        }
        _ => {
            panic!()
        }
    };

    network_fsm.states =
        NetworkMessageStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForShareCState(
            None,
        );

    let input = get_share_data::<SupraDeliveryErasureRs16Schema>();
    let result: ProcessResult = network_fsm.process_message(RBCNetworkMessage::Share(input));
    check(result, NetworkMessageStateHash::WFS);

    network_fsm.states =
        NetworkMessageStateMachineStates::<SupraDeliveryErasureRs16Schema>::DoneNetworkFSMCState(
            None,
        );
    let input = get_share_data::<SupraDeliveryErasureRs16Schema>();
    let result: ProcessResult = network_fsm.process_message(RBCNetworkMessage::Share(input));
    assert!(result.is_ok());
}

#[test]
fn check_get_response() {
    type ResponseResult = Result<
        Option<NetworkFSMResponseMessage<SupraDeliveryErasureRs16Schema>>,
        FSMError<RBCNetworkMessage<SupraDeliveryErasureRs16Schema>, NetworkMessageStateHash>,
    >;
    let check = |result: Result<_, _>, state: NetworkMessageStateHash| {
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
    let mut network_fsm = NetworkMessageStateMachine::new();
    network_fsm.states =
        NetworkMessageStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedNetworkFSMCState(
            None,
        );
    let result: ResponseResult = network_fsm.get_response();
    assert!(result.is_err());
    match result.unwrap_err() {
        FSMError::ResponseInvalidState(state) => {
            assert_eq!(state, NetworkMessageStateHash::NS);
        }
        _ => {
            panic!()
        }
    };

    network_fsm.states =
        NetworkMessageStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForShareCState(
            None,
        );

    let result: ResponseResult = network_fsm.get_response();
    check(result, NetworkMessageStateHash::WFS);

    network_fsm.states =
        NetworkMessageStateMachineStates::<SupraDeliveryErasureRs16Schema>::DoneNetworkFSMCState(
            None,
        );
    let result: ResponseResult = network_fsm.get_response();
    check(result, NetworkMessageStateHash::DONE);
}

#[test]
fn check_handle_timeout() {
    type ProcessResult = Result<
        (),
        FSMError<RBCNetworkMessage<SupraDeliveryErasureRs16Schema>, NetworkMessageStateHash>,
    >;
    let mut network_fsm = NetworkMessageStateMachine::<SupraDeliveryErasureRs16Schema>::new();

    let check_timeout_message_sequence =
        |network_fsm: &mut NetworkMessageStateMachine<SupraDeliveryErasureRs16Schema>| {
            let result: ProcessResult = network_fsm.handle_timeout(TimeoutMessage::Retry);
            assert!(result.is_ok());
            let result: ProcessResult = network_fsm.handle_timeout(TimeoutMessage::Retry);
            assert!(result.is_ok());
        };

    network_fsm.states =
        NetworkMessageStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedNetworkFSMCState(
            None,
        );
    check_timeout_message_sequence(&mut network_fsm);

    network_fsm.states =
        NetworkMessageStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForShareCState(
            None,
        );
    check_timeout_message_sequence(&mut network_fsm);

    network_fsm.states =
        NetworkMessageStateMachineStates::<SupraDeliveryErasureRs16Schema>::DoneNetworkFSMCState(
            None,
        );
    check_timeout_message_sequence(&mut network_fsm);
}
