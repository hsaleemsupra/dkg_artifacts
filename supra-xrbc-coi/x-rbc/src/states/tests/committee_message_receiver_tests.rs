use crate::states::handlers::{
    CommitteeMessageHandler, CommitteeMessageReceiver, FSMErrorHandler, InputVerifier,
};
use crate::states::tests::ContextProvider;
use crate::tasks::LoggingName;
use crate::types::context::committee::{CommitteeFSMContext, CommitteeFSMContextSchema};
use crate::types::context::{FSMContext, FSMContextOwner};
use crate::types::helpers::verifier_visitor::VerificationResult;
use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    EchoReadyData, EchoValueData, RBCCommitteeMessage, ReadyData, ResponseTypeIfc, ValueData,
    VoteData,
};
use crate::types::payload_state::committee::ReconstructedData;
use crate::types::payload_state::{PayloadDataSettings, PayloadFlags};
use crate::types::tests::{certificate_data, partial_share, value_data_with_header_idx};
use crate::{
    FeedbackMessage, QuorumCertificate, QuorumCertificateData, SupraDeliveryErasureRs8Schema,
};
use primitives::types::header::{Header, HeaderIfc};
use primitives::PeerGlobalIndex;
use sfsm::ReceiveMessage;
use std::sync::atomic::{AtomicBool, Ordering};

struct TestCmtState {
    context: CommitteeFSMContext<SupraDeliveryErasureRs8Schema>,
    verification_called: AtomicBool,
    handle_value_called: AtomicBool,
    handle_echo_value_called: AtomicBool,
    handle_vote_called: AtomicBool,
    handle_ready_called: AtomicBool,
    handle_echo_ready_called: AtomicBool,
    handle_certificate_called: AtomicBool,
    handle_pull_called: AtomicBool,
    handle_sync_called: AtomicBool,
    handle_payload_called: AtomicBool,
}

impl TestCmtState {
    fn new(context: CommitteeFSMContext<SupraDeliveryErasureRs8Schema>) -> Self {
        Self {
            context,
            verification_called: Default::default(),
            handle_value_called: Default::default(),
            handle_echo_value_called: Default::default(),
            handle_vote_called: Default::default(),
            handle_ready_called: Default::default(),
            handle_echo_ready_called: Default::default(),
            handle_certificate_called: Default::default(),
            handle_pull_called: Default::default(),
            handle_sync_called: Default::default(),
            handle_payload_called: Default::default(),
        }
    }

    fn clear_call_flags(self) -> Self {
        TestCmtState::new(self.context)
    }
}

impl LoggingName for TestCmtState {
    fn name<'a>() -> &'a str {
        "TestCmtState"
    }
}

impl FSMContextOwner for TestCmtState {
    type Schema = CommitteeFSMContextSchema<SupraDeliveryErasureRs8Schema>;

    fn context(&self) -> &FSMContext<Self::Schema> {
        &self.context
    }

    fn context_mut(&mut self) -> &mut FSMContext<Self::Schema> {
        &mut self.context
    }
}

impl CommitteeMessageHandler for TestCmtState {
    type Value = ValueData<SupraDeliveryErasureRs8Schema>;
    type EchoValue = EchoValueData<SupraDeliveryErasureRs8Schema>;
    type Ready = ReadyData<SupraDeliveryErasureRs8Schema>;
    type EchoReady = EchoReadyData<SupraDeliveryErasureRs8Schema>;

    fn handle_value(&mut self, msg: Self::Value) {
        self.handle_value_called.store(true, Ordering::Relaxed);
        self.payload_state_mut()
            .store_chunk_index(msg.get_chunk_index());
    }

    fn handle_echo_value(&mut self, msg: Self::EchoValue) {
        self.handle_echo_value_called.store(true, Ordering::Relaxed);
        self.payload_state_mut()
            .store_chunk_index(msg.get_chunk_index());
    }

    fn handle_vote(&mut self, msg: VoteData) {
        self.handle_vote_called.store(true, Ordering::Relaxed);
        let (_, vote) = msg.split();
        self.payload_state_mut().add_vote(vote);
    }

    fn handle_ready(&mut self, msg: Self::Ready) {
        self.handle_ready_called.store(true, Ordering::Relaxed);
        self.payload_state_mut()
            .store_chunk_index(msg.value().get_chunk_index());
    }

    fn handle_echo_ready(&mut self, msg: Self::EchoReady) {
        self.handle_echo_ready_called.store(true, Ordering::Relaxed);
        self.payload_state_mut()
            .store_chunk_index(msg.value().get_chunk_index());
    }

    fn handle_certificate(&mut self, msg: QuorumCertificateData) {
        self.handle_certificate_called
            .store(true, Ordering::Relaxed);
        let (_, _, qc) = msg.split();
        self.payload_state_mut().set_certificate(qc);
    }

    fn handle_pull_request(&mut self, _msg: PullRequest) {
        self.handle_pull_called.store(true, Ordering::Relaxed);
    }

    fn handle_sync_request(&mut self, _msg: SyncRequest) {
        self.handle_sync_called.store(true, Ordering::Relaxed);
    }

    fn handle_payload(&mut self, msg: PayloadData) {
        let (_, pld) = msg.split();
        self.handle_payload_called.store(true, Ordering::Relaxed);
        self.payload_state_mut()
            .set_reconstructed_data(ReconstructedData::from_payload(pld))
    }
}

impl CommitteeMessageReceiver<SupraDeliveryErasureRs8Schema> for TestCmtState {}

impl ReceiveMessage<RBCCommitteeMessage<SupraDeliveryErasureRs8Schema>> for TestCmtState {
    fn receive_message(&mut self, message: RBCCommitteeMessage<SupraDeliveryErasureRs8Schema>) {
        self.handle_message(message)
    }
}

impl
    InputVerifier<SupraDeliveryErasureRs8Schema, RBCCommitteeMessage<SupraDeliveryErasureRs8Schema>>
    for TestCmtState
{
    // For message with odd index verification will fail, otherwise it will be successful
    // Verification of the certificate is always success
    fn verify(
        &self,
        message: &RBCCommitteeMessage<SupraDeliveryErasureRs8Schema>,
    ) -> VerificationResult {
        self.verification_called.store(true, Ordering::Relaxed);
        let message_index_is_even = message.data_index().unwrap_or_default() % 2 == 0;
        match message {
            RBCCommitteeMessage::Certificate(_)
            | RBCCommitteeMessage::Pull(_)
            | RBCCommitteeMessage::Sync(_)
            | RBCCommitteeMessage::Payload(_) => VerificationResult::Success,
            _ => VerificationResult::from(message_index_is_even),
        }
    }
}

#[tokio::test]
async fn test_duplicate_value_items_are_not_ignored() {
    // SPT-961 - ValueData should be re-broadcast that's why we do not checks it's duplication
    let broadcaster = PeerGlobalIndex::new(0, 0, 0);
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let context = ContextProvider::new(broadcaster)
        .committee_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let header = context.payload_state().header().clone();
    let mut test_state = TestCmtState::new(context);

    let data_index = 2;
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let value_msg = RBCCommitteeMessage::Value(value_data);
    let is_duplicate = test_state.is_duplicate(&value_msg);
    assert!(!is_duplicate);
    let v_result = test_state.verify_message(&value_msg);
    assert!(v_result.is_ok(), "{:?}", v_result);
    test_state.handle_message(value_msg);
    assert!(test_state.payload_state().has_chunk(data_index));
    assert_eq!(test_state.payload_state().get_received_chunks().len(), 1);

    // Send duplicate value data one more time
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let value_msg = RBCCommitteeMessage::Value(value_data);
    let is_duplicate = test_state.is_duplicate(&value_msg);
    assert!(!is_duplicate);
    let v_result = test_state.verify_message(&value_msg);
    assert!(v_result.is_ok(), "{:?}", v_result);
    test_state.handle_message(value_msg);
    assert!(test_state.payload_state().has_chunk(data_index));
    assert_eq!(test_state.payload_state().get_received_chunks().len(), 1);
}

#[tokio::test]
async fn test_payload_message_handling() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let header = context.payload_state().header().clone();
    let mut test_state = TestCmtState::new(context);
    let payload = vec![10; 50];
    let payload_data = PayloadData::new(header.clone(), payload.clone());
    let payload_data_dup = PayloadData::new(header.clone(), payload.clone());
    let payload_msg = RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::Payload(payload_data);
    let payload_msg_dup =
        RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::Payload(payload_data_dup);

    // duplicate predicate for Payload message returns always false;
    assert!(!test_state.is_duplicate(&payload_msg));
    assert!(test_state.verify(&payload_msg).is_ok());
    test_state.handle_message(payload_msg);
    assert!(test_state.handle_payload_called.load(Ordering::Relaxed));
    test_state = test_state.clear_call_flags();

    // duplicate predicate for Payload message returns always false;
    test_state.handle_message(payload_msg_dup);
    assert!(test_state.verification_called.load(Ordering::Relaxed));
    assert!(test_state.handle_payload_called.load(Ordering::Relaxed));
}

#[tokio::test]
async fn test_duplicated_items_are_ignored() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let header = context.payload_state().header().clone();
    let broadcaster_context = context_provider
        .committee_context_with_header::<SupraDeliveryErasureRs8Schema>(
            header.clone(),
            leader_index,
        );
    let mut test_state = TestCmtState::new(context);
    let mut broadcaster_state = TestCmtState::new(broadcaster_context);

    let check_duplicate_message_consumption =
        |state: &mut TestCmtState,
         msg: RBCCommitteeMessage<SupraDeliveryErasureRs8Schema>,
         chunk_index: Option<usize>,
         vote_index: Option<u32>| {
            let is_duplicate = state.is_duplicate(&msg);
            assert!(is_duplicate);
            let v_result = state.verify_message(&msg);
            assert!(v_result.is_ignore());
            state.handle_message(msg);
            let _ = chunk_index.map(|index| {
                assert!(state.payload_state().has_chunk(index));
                assert_eq!(state.payload_state().get_received_chunks().len(), 1);
            });
            let _ = vote_index.map(|index| {
                assert!(state.payload_state().has_vote(index));
                assert_eq!(state.payload_state().votes_len(), 1);
            });
            // Duplicate message is not verified
            assert!(!state.verification_called.load(Ordering::Relaxed));
        };

    let data_index = 2;
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let value_msg = RBCCommitteeMessage::Value(value_data);
    let is_duplicate = test_state.is_duplicate(&value_msg);
    assert!(!is_duplicate);
    let v_result = test_state.verify_message(&value_msg);
    assert!(v_result.is_ok(), "{:?}", v_result);
    test_state.handle_message(value_msg);
    assert!(test_state.payload_state().has_chunk(data_index));
    assert_eq!(test_state.payload_state().get_received_chunks().len(), 1);
    test_state = test_state.clear_call_flags();

    // duplicate message
    let echo_value_data = EchoValueData::new(value_data_with_header_idx::<
        SupraDeliveryErasureRs8Schema,
    >(header.clone(), data_index));
    let echo_value_msg = RBCCommitteeMessage::EchoValue(echo_value_data);
    check_duplicate_message_consumption(&mut test_state, echo_value_msg, Some(data_index), None);

    let ready_data = ReadyData::new(
        [4; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index),
    );
    let ready_msg = RBCCommitteeMessage::Ready(ready_data);
    check_duplicate_message_consumption(&mut test_state, ready_msg, Some(data_index), None);

    // a new vote message
    let vote_index = 4;
    let vote = VoteData::new(header.clone(), partial_share(vote_index));
    let vote_msg = RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::Vote(vote);
    let is_duplicate = broadcaster_state.is_duplicate(&vote_msg);
    assert!(!is_duplicate);
    let v_result = broadcaster_state.verify_message(&vote_msg);
    assert!(v_result.is_ok());
    broadcaster_state.handle_message(vote_msg);
    assert!(broadcaster_state.payload_state().has_vote(vote_index));
    assert_eq!(broadcaster_state.payload_state().votes_len(), 1);
    broadcaster_state = broadcaster_state.clear_call_flags();

    // duplicate vote message
    let dup_vote = VoteData::new(header.clone(), partial_share(vote_index));
    let dup_vote_msg = RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::Vote(dup_vote);
    check_duplicate_message_consumption(
        &mut broadcaster_state,
        dup_vote_msg,
        None,
        Some(vote_index),
    );

    // For certificate no duplication can be defined
    let certificate_data = certificate_data(header);
    let certificate_msg =
        RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::Certificate(certificate_data);
    assert!(!test_state.is_duplicate(&certificate_msg));
    assert!(test_state.verify_message(&certificate_msg).is_ok());
}

#[tokio::test]
async fn test_input_message_wrt_delivery_state_non_broadcaster() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let context = ContextProvider::new(leader_index)
        .committee_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let header = context.payload_state().header().clone();
    let mut non_broadcaster_state = TestCmtState::new(context);

    let data_index = 2;
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let value_msg = RBCCommitteeMessage::Value(value_data);

    let result = non_broadcaster_state.verify_message_wrt_delivery_state(&value_msg);
    assert!(result.is_ok());

    let v_result = non_broadcaster_state.verify_message(&value_msg);
    assert!(v_result.is_ok(), "{:?}", v_result);
    assert!(non_broadcaster_state
        .verification_called
        .load(Ordering::Relaxed));
    non_broadcaster_state.handle_message(value_msg);
    assert!(non_broadcaster_state.payload_state().has_chunk(data_index));
    assert_eq!(
        non_broadcaster_state
            .payload_state()
            .get_received_chunks()
            .len(),
        1
    );
    non_broadcaster_state = non_broadcaster_state.clear_call_flags();

    // another message
    let data_index = 4;
    let echo_value_data = EchoValueData::new(value_data_with_header_idx::<
        SupraDeliveryErasureRs8Schema,
    >(header.clone(), data_index));
    let echo_value_msg = RBCCommitteeMessage::EchoValue(echo_value_data);
    let result = non_broadcaster_state.verify_message_wrt_delivery_state(&echo_value_msg);
    assert!(result.is_ok());

    let v_result = non_broadcaster_state.verify_message(&echo_value_msg);
    assert!(v_result.is_ok(), "{:?}", v_result);
    assert!(non_broadcaster_state
        .verification_called
        .load(Ordering::Relaxed));
    non_broadcaster_state.handle_message(echo_value_msg);
    assert!(non_broadcaster_state.payload_state().has_chunk(data_index));
    assert_eq!(
        non_broadcaster_state
            .payload_state()
            .get_received_chunks()
            .len(),
        2
    );
    non_broadcaster_state = non_broadcaster_state.clear_call_flags();

    // a vote message is not expected for non-broadcaster case
    let vote_index = 4;
    let vote = VoteData::new(header.clone(), partial_share(vote_index));
    let vote_msg = RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::Vote(vote);
    let result = non_broadcaster_state.verify_message_wrt_delivery_state(&vote_msg);
    assert!(result.is_err());
    let v_result = non_broadcaster_state.verify_message(&vote_msg);
    assert!(v_result.is_err());
    non_broadcaster_state.handle_message(vote_msg);
    assert!(!non_broadcaster_state
        .verification_called
        .load(Ordering::Relaxed));
    assert!(!non_broadcaster_state.payload_state().has_vote(vote_index));
    let error_feedback = non_broadcaster_state
        .take_response()
        .unwrap()
        .take_feedback()
        .remove(0);
    assert!(matches!(error_feedback, FeedbackMessage::Error(_, _)));
}

#[tokio::test]
async fn test_input_message_wrt_delivery_state_broadcaster() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let context = ContextProvider::new(leader_index)
        .committee_context::<SupraDeliveryErasureRs8Schema>(leader_index);
    let mut broadcaster_state = TestCmtState::new(context);
    let header = broadcaster_state.payload_state().get_header();

    let data_index = 2;
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let value_msg = RBCCommitteeMessage::Value(value_data);

    let result = broadcaster_state.verify_message_wrt_delivery_state(&value_msg);
    assert!(result.is_err());

    let v_result = broadcaster_state.verify_message(&value_msg);
    assert!(v_result.is_err(), "{:?}", v_result);
    assert!(!broadcaster_state
        .verification_called
        .load(Ordering::Relaxed));
    broadcaster_state.handle_message(value_msg);
    assert!(!broadcaster_state.payload_state().has_chunk(data_index));
    let error_feedback = broadcaster_state
        .take_response()
        .unwrap()
        .take_feedback()
        .remove(0);
    assert!(matches!(error_feedback, FeedbackMessage::Error(_, _)));
    broadcaster_state = broadcaster_state.clear_call_flags();

    // another message
    let data_index = 4;
    let echo_value_data = EchoValueData::new(value_data_with_header_idx::<
        SupraDeliveryErasureRs8Schema,
    >(header.clone(), data_index));
    let echo_value_msg = RBCCommitteeMessage::EchoValue(echo_value_data);
    let result = broadcaster_state.verify_message_wrt_delivery_state(&echo_value_msg);
    assert!(result.is_err());

    let v_result = broadcaster_state.verify_message(&echo_value_msg);
    assert!(v_result.is_err(), "{:?}", v_result);
    assert!(!broadcaster_state
        .verification_called
        .load(Ordering::Relaxed));
    broadcaster_state.handle_message(echo_value_msg);
    assert!(!broadcaster_state.payload_state().has_chunk(data_index));
    let error_feedback = broadcaster_state
        .take_response()
        .unwrap()
        .take_feedback()
        .remove(0);
    assert!(matches!(error_feedback, FeedbackMessage::Error(_, _)));
    broadcaster_state = broadcaster_state.clear_call_flags();

    // a vote message is not expected for non-broadcaster case
    let vote_index = 4;
    let vote = VoteData::new(header.clone(), partial_share(vote_index));
    let vote_msg = RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::Vote(vote);
    let result = broadcaster_state.verify_message_wrt_delivery_state(&vote_msg);
    assert!(result.is_ok());
    let v_result = broadcaster_state.verify_message(&vote_msg);
    assert!(v_result.is_ok());
    broadcaster_state.handle_message(vote_msg);
    assert!(broadcaster_state
        .verification_called
        .load(Ordering::Relaxed));
    assert!(broadcaster_state.payload_state().has_vote(vote_index));
    assert!(broadcaster_state.response().is_none());
}

fn check_verification_and_handler_are_called(
    state: &mut TestCmtState,
    msg: RBCCommitteeMessage<SupraDeliveryErasureRs8Schema>,
    get_flag: impl Fn(&TestCmtState) -> &AtomicBool,
) {
    state.handle_message(msg);
    assert!(state.verification_called.load(Ordering::Relaxed));
    assert!(get_flag(state).load(Ordering::Relaxed));
}

#[tokio::test]
async fn test_verification_and_handler_is_called_for_all_messages() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut test_state = TestCmtState::new(context);
    let brd_context =
        context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(leader_index);
    let mut broadcaster_state = TestCmtState::new(brd_context);
    let header = broadcaster_state.payload_state().get_header();

    let data_index = 2;
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let value_msg = RBCCommitteeMessage::Value(value_data);
    check_verification_and_handler_are_called(&mut test_state, value_msg, |st| {
        &st.handle_value_called
    });
    test_state = test_state.clear_call_flags();

    // duplicate message
    let echo_value_data = EchoValueData::new(value_data_with_header_idx::<
        SupraDeliveryErasureRs8Schema,
    >(header.clone(), data_index * 2));
    let echo_value_msg = RBCCommitteeMessage::EchoValue(echo_value_data);
    check_verification_and_handler_are_called(&mut test_state, echo_value_msg, |st| {
        &st.handle_echo_value_called
    });
    test_state = test_state.clear_call_flags();

    let ready_data = ReadyData::new(
        [4; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index * 3),
    );
    let ready_msg = RBCCommitteeMessage::Ready(ready_data);
    check_verification_and_handler_are_called(&mut test_state, ready_msg, |st| {
        &st.handle_ready_called
    });
    test_state = test_state.clear_call_flags();

    let echo_ready_data = EchoReadyData::new(ReadyData::new(
        [4; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index * 4),
    ));
    let echo_ready_msg = RBCCommitteeMessage::EchoReady(echo_ready_data);
    check_verification_and_handler_are_called(&mut test_state, echo_ready_msg, |st| {
        &st.handle_echo_ready_called
    });
    test_state = test_state.clear_call_flags();

    // a new vote message
    let vote_index = 4;
    let vote = VoteData::new(header.clone(), partial_share(vote_index));
    let vote_msg = RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::Vote(vote);
    check_verification_and_handler_are_called(&mut broadcaster_state, vote_msg, |st| {
        &st.handle_vote_called
    });

    // Certificate message
    let certificate_data = certificate_data(header.clone());
    let certificate_msg =
        RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::Certificate(certificate_data);
    check_verification_and_handler_are_called(&mut test_state, certificate_msg, |st| {
        &st.handle_certificate_called
    });
    test_state = test_state.clear_call_flags();

    // Pull
    let pull_data = PullRequest::new(
        [1; 32],
        SyncRequest::new(header.clone(), QuorumCertificate::default()),
    );
    let pull_message = RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::Pull(pull_data);
    check_verification_and_handler_are_called(&mut test_state, pull_message, |st| {
        &st.handle_pull_called
    });
    test_state = test_state.clear_call_flags();

    // Sync
    let sync_data = SyncRequest::new(header.clone(), QuorumCertificate::default());
    let sync_msg = RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::Sync(sync_data);
    check_verification_and_handler_are_called(&mut test_state, sync_msg, |st| {
        &st.handle_sync_called
    });
    test_state = test_state.clear_call_flags();

    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index * 5);
    let value_msg = RBCCommitteeMessage::Value(value_data);

    let echo_value_data = EchoValueData::new(value_data_with_header_idx::<
        SupraDeliveryErasureRs8Schema,
    >(header, data_index * 6));
    let echo_value_msg = RBCCommitteeMessage::EchoValue(echo_value_data);
    let composite = RBCCommitteeMessage::Composite(vec![value_msg, echo_value_msg]);
    test_state.handle_message(composite);
    assert!(test_state.verification_called.load(Ordering::Relaxed));
    assert!(test_state.handle_value_called.load(Ordering::Relaxed));
    assert!(test_state.handle_echo_value_called.load(Ordering::Relaxed));
}

#[tokio::test]
async fn test_verification_failure_send_error_as_feedback() {
    let peer_index = PeerGlobalIndex::new(0, 0, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut test_state = TestCmtState::new(context);
    let header = test_state.payload_state().get_header();

    // Verification fails for data with odd index
    let data_index = 1;
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let value_msg = RBCCommitteeMessage::Value(value_data);
    test_state.handle_message(value_msg);
    assert!(test_state.verification_called.load(Ordering::Relaxed));
    assert!(!test_state.handle_value_called.load(Ordering::Relaxed));
    let mut response = test_state.take_response().expect("Response is expected");
    assert!(response.messages().is_empty());
    assert!(response.aux_messages().is_empty());
    let feedback = response.take_feedback().remove(0);
    match feedback {
        FeedbackMessage::Error(meta, origin) => {
            assert_eq!(&meta, header.meta());
            assert_eq!(&origin, header.origin())
        }
        _ => {
            panic!("expected FeedbackMessage::Error")
        }
    }
    test_state = test_state.clear_call_flags();

    // Verification failure as origin can not be found
    let header = Header::new([0; 64], [1; 32], [3; 32]);
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let value_msg = RBCCommitteeMessage::Value(value_data);
    test_state.handle_message(value_msg);
    assert!(test_state.verification_called.load(Ordering::Relaxed));
    assert!(!test_state.handle_value_called.load(Ordering::Relaxed));
    let mut response = test_state.take_response().expect("Response is expected");
    assert!(response.messages().is_empty());
    assert!(response.aux_messages().is_empty());
    let feedback = response.take_feedback().remove(0);
    match feedback {
        FeedbackMessage::InternalError(meta, _) => {
            assert_eq!(&meta, header.meta());
        }
        _ => {
            panic!("expected FeedbackMessage::InternalError")
        }
    }
}

#[tokio::test]
async fn check_register_error_apis() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(leader_index);
    let mut test_state = TestCmtState::new(context);
    let header = test_state.payload_state().get_header();

    // Check register error when message metadata can be retrieved
    let data_index = 1;
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let value_msg = RBCCommitteeMessage::Value(value_data);

    test_state.register_error(value_msg);
    // Payload state is not marked as failed
    assert!(!test_state.payload_state().failed());
    let mut response = test_state.take_response().expect("Expected response");
    assert!(response.messages().is_empty());
    assert!(response.aux_messages().is_empty());
    let feedback = response.take_feedback().remove(0);
    match feedback {
        FeedbackMessage::Error(meta, origin) => {
            assert_eq!(&meta, header.meta());
            assert_eq!(&origin, header.origin())
        }
        _ => {
            panic!("expected FeedbackMessage::Error")
        }
    }

    // Check register error when message metadata cannot be fully retrieved
    let header = Header::default();
    let data_index = 1;
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let value_msg = RBCCommitteeMessage::Value(value_data);

    test_state.register_error(value_msg);
    // Payload state is not marked as failed
    assert!(!test_state.payload_state().failed());
    let mut response = test_state.take_response().expect("Expected response");
    assert!(response.messages().is_empty());
    assert!(response.aux_messages().is_empty());
    let feedback = response.take_feedback().remove(0);
    match feedback {
        FeedbackMessage::InternalError(meta, _) => {
            assert_eq!(&meta, header.meta());
        }
        _ => {
            panic!("expected FeedbackMessage::InternalError")
        }
    }
}

#[tokio::test]
async fn check_register_internal_error_apis_positive() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(leader_index);
    let mut test_state = TestCmtState::new(context);
    let header = test_state.payload_state().get_header();
    // Check register internal error
    let msg = "Register internal error";
    test_state.register_internal_error(msg.to_string());
    assert!(test_state.payload_state().failed());
    let mut response = test_state.take_response().expect("Expected response");
    assert!(response.messages().is_empty());
    assert!(response.aux_messages().is_empty());
    let feedback = response.take_feedback().remove(0);
    match feedback {
        FeedbackMessage::InternalError(meta, err_msg) => {
            assert_eq!(&meta, header.meta());
            assert_eq!(&err_msg, msg)
        }
        _ => {
            panic!("expected FeedbackMessage::InternalError")
        }
    }

    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(leader_index);
    let mut test_state = TestCmtState::new(context);
    let header = test_state.payload_state().get_header();
    // Check register feedback error
    let err_origin = [3; 32];
    test_state.register_error_feedback(FeedbackMessage::err_msg(header.get_meta(), err_origin));
    assert!(test_state.payload_state().failed());
    let mut response = test_state.take_response().expect("Expected response");
    assert!(response.messages().is_empty());
    assert!(response.aux_messages().is_empty());
    let feedback = response.take_feedback().remove(0);
    match feedback {
        FeedbackMessage::Error(meta, origin) => {
            assert_eq!(&meta, header.meta());
            assert_eq!(origin, err_origin)
        }
        _ => {
            panic!("expected FeedbackMessage::InternalError")
        }
    }
}

#[test]
#[should_panic]
fn check_register_internal_error_apis_negative() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.committee_context::<SupraDeliveryErasureRs8Schema>(leader_index);
    let mut test_state = TestCmtState::new(context);

    test_state.register_error_feedback(FeedbackMessage::err_msg(Default::default(), [1; 32]));
    assert!(test_state.payload_state().failed());

    // Check register internal error when no header info is available should panic
    let msg = "Register internal error";
    test_state.register_internal_error(msg.to_string());
}
