use crate::fsm::committee_state_machine::CommitteeStateHash;
use crate::fsm::committee_state_machine::CommitteeStateMachineStates;
use crate::fsm::errors::FSMError;
use crate::fsm::RBCStateMachine;
use crate::fsm::{CommitteeStateMachine, ExecutionStatus};
use crate::states::not_started::NotStarted;
use crate::states::tests::ContextProvider;
use crate::tasks::codec::{EncodeResultIfc, SupraDeliveryErasureCodecSchema};
use crate::tasks::messages::TimeoutMessage;
use crate::types::context::committee::CommitteeFSMContext;
use crate::types::context::ResourcesApi;
use crate::types::messages::{
    CommitteeFSMResponseMessage, EchoValueData, RBCCommitteeMessage, ValueData, VoteData,
};
use crate::types::payload_state::committee::{CommitteePayloadState, ReconstructedData};
use crate::types::payload_state::vote_store::VoteStore;
use crate::types::tests::get_value_data;
use crate::{QuorumCertificateData, SupraDeliveryErasureRs16Schema};
use primitives::types::{HeaderIfc, QuorumCertificate};
use primitives::PeerGlobalIndex;

fn check_execution_status_state_hash<Schema: SupraDeliveryErasureCodecSchema>(
    fsm: &CommitteeStateMachine<Schema>,
    status: ExecutionStatus,
    state: CommitteeStateHash,
) {
    assert_eq!(state, fsm.get_state_hash());
    assert_eq!(status, fsm.get_execution_status());
}

#[test]
fn check_state_machine_flags() {
    let mut committee_fsm = CommitteeStateMachine::new();
    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedCommitteeFSMCState(
            None,
        );
    check_execution_status_state_hash(
        &committee_fsm,
        ExecutionStatus::InProgress,
        CommitteeStateHash::NS,
    );

    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForDataCState(None);

    check_execution_status_state_hash(
        &committee_fsm,
        ExecutionStatus::InProgress,
        CommitteeStateHash::WFD,
    );
    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForVoteCState(None);
    check_execution_status_state_hash(
        &committee_fsm,
        ExecutionStatus::InProgress,
        CommitteeStateHash::WFV,
    );

    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForCertificateCState(
            None,
        );
    check_execution_status_state_hash(
        &committee_fsm,
        ExecutionStatus::InProgress,
        CommitteeStateHash::WFC,
    );
    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::DoneCommitteeFSMCState(None);
    check_execution_status_state_hash(
        &committee_fsm,
        ExecutionStatus::Done,
        CommitteeStateHash::DONE,
    );
}

#[test]
fn check_process_message() {
    type ProcessResult = Result<
        (),
        FSMError<RBCCommitteeMessage<SupraDeliveryErasureRs16Schema>, CommitteeStateHash>,
    >;

    let check = |result: Result<_, _>, state: CommitteeStateHash| {
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

    let mut committee_fsm = CommitteeStateMachine::new();
    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedCommitteeFSMCState(
            None,
        );
    let input = get_value_data::<SupraDeliveryErasureRs16Schema>();
    let result: ProcessResult = committee_fsm.process_message(RBCCommitteeMessage::Value(input));
    assert!(result.is_err());
    match result.unwrap_err() {
        FSMError::InputInvalidState(state, data) => {
            assert_eq!(state, CommitteeStateHash::NS);
            assert!(data.is_some());
        }
        _ => {
            panic!()
        }
    };

    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForDataCState(None);

    let input = get_value_data::<SupraDeliveryErasureRs16Schema>();
    let result: ProcessResult = committee_fsm.process_message(RBCCommitteeMessage::Value(input));
    check(result, CommitteeStateHash::WFD);

    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForVoteCState(None);
    let input = get_value_data::<SupraDeliveryErasureRs16Schema>();
    let result: ProcessResult = committee_fsm.process_message(RBCCommitteeMessage::Value(input));
    check(result, CommitteeStateHash::WFV);

    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForCertificateCState(
            None,
        );
    let input = get_value_data::<SupraDeliveryErasureRs16Schema>();
    let result: ProcessResult = committee_fsm.process_message(RBCCommitteeMessage::Value(input));
    check(result, CommitteeStateHash::WFC);

    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::DoneCommitteeFSMCState(None);
    let input = get_value_data::<SupraDeliveryErasureRs16Schema>();
    let result: ProcessResult = committee_fsm.process_message(RBCCommitteeMessage::Value(input));
    assert!(result.is_ok());
}

#[test]
fn check_get_response() {
    type ResponseResult = Result<
        Option<CommitteeFSMResponseMessage<SupraDeliveryErasureRs16Schema>>,
        FSMError<RBCCommitteeMessage<SupraDeliveryErasureRs16Schema>, CommitteeStateHash>,
    >;
    let check = |result: Result<_, _>, state: CommitteeStateHash| {
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
    let mut committee_fsm = CommitteeStateMachine::new();
    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedCommitteeFSMCState(
            None,
        );
    let result: ResponseResult = committee_fsm.get_response();
    assert!(result.is_err());
    match result.unwrap_err() {
        FSMError::ResponseInvalidState(state) => {
            assert_eq!(state, CommitteeStateHash::NS);
        }
        _ => {
            panic!()
        }
    };

    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForDataCState(None);

    let result: ResponseResult = committee_fsm.get_response();
    check(result, CommitteeStateHash::WFD);

    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForVoteCState(None);
    let result: ResponseResult = committee_fsm.get_response();
    check(result, CommitteeStateHash::WFV);

    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForCertificateCState(
            None,
        );
    let result: ResponseResult = committee_fsm.get_response();
    check(result, CommitteeStateHash::WFC);

    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::DoneCommitteeFSMCState(None);
    let result: ResponseResult = committee_fsm.get_response();
    check(result, CommitteeStateHash::DONE);
}

#[test]
fn check_handle_timeout() {
    type ProcessResult = Result<
        (),
        FSMError<RBCCommitteeMessage<SupraDeliveryErasureRs16Schema>, CommitteeStateHash>,
    >;
    let check = |result: Result<_, _>, timeout: TimeoutMessage| {
        assert!(result.is_err());
        match result.unwrap_err() {
            FSMError::TimeoutInactiveState(e_state, message) => {
                assert_eq!(e_state, CommitteeStateHash::WFV);
                assert_eq!(message, Some(timeout));
            }
            _ => {
                panic!()
            }
        };
    };

    let check_timeout_message_sequence =
        |committee_fsm: &mut CommitteeStateMachine<SupraDeliveryErasureRs16Schema>| {
            let result: ProcessResult = committee_fsm.handle_timeout(TimeoutMessage::Retry);
            assert!(result.is_ok());
            let result: ProcessResult = committee_fsm.handle_timeout(TimeoutMessage::Retry);
            assert!(result.is_ok());
        };

    let mut committee_fsm = CommitteeStateMachine::<SupraDeliveryErasureRs16Schema>::new();
    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedCommitteeFSMCState(
            None,
        );
    let result: ProcessResult = committee_fsm.handle_timeout(TimeoutMessage::Retry);
    assert!(result.is_err());
    match result.unwrap_err() {
        FSMError::TimeoutInvalidState(state, message) => {
            assert_eq!(state, CommitteeStateHash::NS);
            assert_eq!(message, Some(TimeoutMessage::Retry))
        }
        _ => {
            panic!()
        }
    };

    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForDataCState(None);
    check_timeout_message_sequence(&mut committee_fsm);

    // Only WFV state responds to time-outs
    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForVoteCState(None);
    let result: ProcessResult = committee_fsm.handle_timeout(TimeoutMessage::Retry);
    check(result, TimeoutMessage::Retry);
    let result: ProcessResult = committee_fsm.handle_timeout(TimeoutMessage::Retry);
    check(result, TimeoutMessage::Retry);

    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::WaitingForCertificateCState(
            None,
        );
    check_timeout_message_sequence(&mut committee_fsm);

    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::DoneCommitteeFSMCState(None);
    check_timeout_message_sequence(&mut committee_fsm);
}

#[test]
fn check_did_transition() {
    let mut committee_fsm = CommitteeStateMachine::new();
    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedCommitteeFSMCState(
            None,
        );
    let result = committee_fsm.did_transition(CommitteeStateHash::NS);
    assert!(!result);

    let result = committee_fsm.did_transition(CommitteeStateHash::WFV);
    assert!(result)
}

///
/// - NS -> WFV -> WFC -> Done
///
#[tokio::test]
async fn check_state_transition_flow_ns_wfv_wfc() {
    let broadcaster = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(broadcaster);
    let broadcaster_resource = context_provider
        .resource_provider()
        .get_resources(broadcaster);

    let (encoded_res, payload) = context_provider.encoded_data::<SupraDeliveryErasureRs16Schema>();
    let header = encoded_res.header().clone();
    let codec = context_provider.codec();
    let mut payload_state = CommitteePayloadState::new(header.clone(), codec);

    let reconstructed_data = ReconstructedData::new(
        payload,
        encoded_res.committee_chunks().clone(),
        encoded_res.network_chunks().clone(),
    );
    payload_state.set_reconstructed_data(reconstructed_data);

    let context: CommitteeFSMContext<SupraDeliveryErasureRs16Schema> =
        CommitteeFSMContext::new(payload_state, broadcaster_resource);

    let mut committee_fsm = CommitteeStateMachine::<SupraDeliveryErasureRs16Schema>::new();
    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedCommitteeFSMCState(
            Some(NotStarted::new(context)),
        );

    assert_eq!(committee_fsm.get_state_hash(), CommitteeStateHash::NS);

    committee_fsm.do_step().expect("cannot step");
    assert_eq!(committee_fsm.get_state_hash(), CommitteeStateHash::WFV);
    assert!(committee_fsm.get_response().is_ok());

    for idx in 1..4 {
        let res = context_provider
            .resource_provider()
            .get_resources(PeerGlobalIndex::new(0, 0, idx));
        let sign = res
            .authenticator()
            .partial_signature(header.commitment())
            .unwrap();
        let vote_data = VoteData::new(header.clone(), sign);
        let message = RBCCommitteeMessage::Vote(vote_data);
        committee_fsm
            .process_message(message)
            .expect("cannot process message");
    }

    committee_fsm.do_step().expect("cannot step");
    assert_eq!(committee_fsm.get_state_hash(), CommitteeStateHash::WFC);
    assert!(committee_fsm.get_response().is_ok());

    committee_fsm.do_step().expect("cannot step");
    assert_eq!(committee_fsm.get_state_hash(), CommitteeStateHash::DONE);
    assert!(committee_fsm.get_response().is_ok());
}

///
/// - NS-> WFD-> WFV->WFC->Done
///
#[tokio::test]
async fn check_state_transition_flow_ns_wfd_wfv_wfc() {
    let broadcaster = PeerGlobalIndex::new(0, 0, 0);
    let this_peer = PeerGlobalIndex::new(0, 0, 1);

    let mut context_provider = ContextProvider::new(broadcaster);
    let broadcaster_resource = context_provider
        .resource_provider()
        .get_resources(broadcaster);
    let this_resource = context_provider
        .resource_provider()
        .get_resources(this_peer);

    let (encoded_res, _) = context_provider.encoded_data::<SupraDeliveryErasureRs16Schema>();
    let header = encoded_res.header().clone();
    let codec = context_provider.codec();
    let payload_state = CommitteePayloadState::new(header.clone(), codec);

    let context: CommitteeFSMContext<SupraDeliveryErasureRs16Schema> =
        CommitteeFSMContext::new(payload_state, this_resource);

    let mut committee_fsm = CommitteeStateMachine::<SupraDeliveryErasureRs16Schema>::new();
    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedCommitteeFSMCState(
            Some(NotStarted::new(context)),
        );

    assert_eq!(committee_fsm.get_state_hash(), CommitteeStateHash::NS);

    committee_fsm.do_step().expect("cannot step");
    assert_eq!(committee_fsm.get_state_hash(), CommitteeStateHash::WFD);
    assert!(committee_fsm.get_response().is_ok());

    // Reconstruct data
    for chunk in encoded_res.committee_chunks() {
        let value = ValueData::new(header.clone(), chunk.clone());
        let message = {
            if value.get_chunk_index() == this_peer.position() {
                RBCCommitteeMessage::Value(value)
            } else {
                let echo = EchoValueData::new(value);
                RBCCommitteeMessage::EchoValue(echo)
            }
        };
        committee_fsm
            .process_message(message)
            .expect("cannot process message");
        assert!(committee_fsm.get_response().is_ok());
    }

    committee_fsm.do_step().expect("cannot step");
    assert_eq!(committee_fsm.get_state_hash(), CommitteeStateHash::WFV);

    committee_fsm.do_step().expect("cannot step");
    assert_eq!(committee_fsm.get_state_hash(), CommitteeStateHash::WFC);
    assert!(committee_fsm.get_response().is_ok());

    let mut votes = VoteStore::default();
    for idx in 2..5 {
        let contributing_resource = context_provider
            .resource_provider()
            .get_resources(PeerGlobalIndex::new(0, 0, idx));
        let sign = contributing_resource
            .authenticator()
            .partial_signature(header.commitment())
            .unwrap();
        votes.add_vote(sign)
    }

    let votes = votes.collect().unwrap();
    let participants = votes.iter().map(|vote| vote.index()).collect();
    let maybe_qc = broadcaster_resource
        .authenticator()
        .threshold_signature(votes)
        .map(|cert| QuorumCertificate::new(cert, participants))
        .unwrap();
    let qc_bytes = bincode::serialize(&maybe_qc).unwrap();
    let qc_signature = broadcaster_resource
        .authenticator()
        .sign(&qc_bytes)
        .unwrap();
    let qc_data = QuorumCertificateData::new(header, qc_signature, maybe_qc);
    let message = RBCCommitteeMessage::Certificate(qc_data);
    committee_fsm
        .process_message(message)
        .expect("TODO: panic message");

    committee_fsm.do_step().expect("cannot step");

    assert_eq!(committee_fsm.get_state_hash(), CommitteeStateHash::DONE);
    assert!(committee_fsm.get_response().is_ok());
}

///
/// - NS -> WFD-> WFC -> Done
///
#[tokio::test]
async fn check_state_transition_flow_ns_wfd_wfc() {
    let broadcaster = PeerGlobalIndex::new(0, 0, 0);
    let this_peer = PeerGlobalIndex::new(0, 0, 1);

    let mut context_provider = ContextProvider::new(broadcaster);
    let this_resources = context_provider
        .resource_provider()
        .get_resources(this_peer);
    let broadcaster_resource = context_provider
        .resource_provider()
        .get_resources(broadcaster);

    let (encoded_res, _) = context_provider.encoded_data::<SupraDeliveryErasureRs16Schema>();
    let header = encoded_res.header().clone();
    let codec = context_provider.codec();

    let payload_state = CommitteePayloadState::new(header.clone(), codec);

    let context: CommitteeFSMContext<SupraDeliveryErasureRs16Schema> =
        CommitteeFSMContext::new(payload_state, this_resources);

    let mut committee_fsm = CommitteeStateMachine::<SupraDeliveryErasureRs16Schema>::new();
    committee_fsm.states =
        CommitteeStateMachineStates::<SupraDeliveryErasureRs16Schema>::NotStartedCommitteeFSMCState(
            Some(NotStarted::new(context)),
        );

    assert_eq!(committee_fsm.get_state_hash(), CommitteeStateHash::NS);

    committee_fsm.do_step().expect("cannot step");
    assert_eq!(committee_fsm.get_state_hash(), CommitteeStateHash::WFD);
    assert!(committee_fsm.get_response().is_ok());

    // Reconstruct data
    for chunk in encoded_res.committee_chunks() {
        let value = ValueData::new(header.clone(), chunk.clone());
        let message = {
            if value.get_chunk_index() == this_peer.position() {
                RBCCommitteeMessage::Value(value)
            } else {
                let echo = EchoValueData::new(value);
                RBCCommitteeMessage::EchoValue(echo)
            }
        };
        committee_fsm
            .process_message(message)
            .expect("cannot process message");
        assert!(committee_fsm.get_response().is_ok());
    }

    let mut votes = VoteStore::default();
    for idx in 2..5 {
        let contributing_resource = context_provider
            .resource_provider()
            .get_resources(PeerGlobalIndex::new(0, 0, idx));
        let sign = contributing_resource
            .authenticator()
            .partial_signature(header.commitment())
            .unwrap();
        votes.add_vote(sign)
    }

    let votes = votes.collect().unwrap();
    let participants = votes.iter().map(|vote| vote.index()).collect();
    let maybe_qc = broadcaster_resource
        .authenticator()
        .threshold_signature(votes)
        .map(|cert| QuorumCertificate::new(cert, participants))
        .unwrap();
    let qc_bytes = bincode::serialize(&maybe_qc).unwrap();
    let qc_signature = broadcaster_resource
        .authenticator()
        .sign(&qc_bytes)
        .unwrap();
    let qc_data = QuorumCertificateData::new(header, qc_signature, maybe_qc);
    let message = RBCCommitteeMessage::Certificate(qc_data);
    committee_fsm
        .process_message(message)
        .expect("TODO: panic message");

    committee_fsm.do_step().expect("cannot step");
    assert_eq!(committee_fsm.get_state_hash(), CommitteeStateHash::WFC);
    assert!(committee_fsm.get_response().is_ok());

    committee_fsm.do_step().expect("cannot step");
    assert_eq!(committee_fsm.get_state_hash(), CommitteeStateHash::DONE);
    assert!(committee_fsm.get_response().is_ok());
}
