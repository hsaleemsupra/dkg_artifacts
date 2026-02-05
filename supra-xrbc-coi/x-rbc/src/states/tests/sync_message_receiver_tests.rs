use crate::states::handlers::{InputVerifier, SyncMessageHandler, SyncMessageReceiver};
use crate::states::tests::ContextProvider;
use crate::tasks::LoggingName;
use crate::types::context::sync::{SyncFSMContext, SyncFSMContextSchema};
use crate::types::context::{FSMContext, FSMContextOwner};
use crate::types::helpers::verifier_visitor::VerificationResult;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    EchoReadyData, EchoShareData, EchoValueData, RBCSyncMessage, ReadyData, ResponseTypeIfc,
    ShareData,
};
use crate::types::payload_state::sync::PayloadType;
use crate::types::tests::value_data_with_header_idx;
use crate::{FeedbackMessage, QuorumCertificate, SupraDeliveryErasureRs8Schema};
use primitives::types::Header;
use primitives::PeerGlobalIndex;
use sfsm::ReceiveMessage;
use std::sync::atomic::{AtomicBool, Ordering};
use vec_commitment::committed_chunk::CommitmentMeta;

struct TestSyncState {
    context: SyncFSMContext<SupraDeliveryErasureRs8Schema>,
    verification_called: AtomicBool,
    handle_echo_value_called: AtomicBool,
    handle_ready_called: AtomicBool,
    handle_echo_ready_called: AtomicBool,
    handle_share_called: AtomicBool,
    handle_echo_share_called: AtomicBool,
    handle_pull_called: AtomicBool,
}

impl TestSyncState {
    fn new(context: SyncFSMContext<SupraDeliveryErasureRs8Schema>) -> Self {
        Self {
            context,
            verification_called: Default::default(),
            handle_echo_value_called: Default::default(),
            handle_ready_called: Default::default(),
            handle_echo_ready_called: Default::default(),
            handle_share_called: Default::default(),
            handle_echo_share_called: Default::default(),
            handle_pull_called: Default::default(),
        }
    }

    fn clear_call_flags(self) -> Self {
        TestSyncState::new(self.context)
    }
}

impl LoggingName for TestSyncState {
    fn name<'a>() -> &'a str {
        "TestCmtState"
    }
}

impl FSMContextOwner for TestSyncState {
    type Schema = SyncFSMContextSchema<SupraDeliveryErasureRs8Schema>;

    fn context(&self) -> &FSMContext<Self::Schema> {
        &self.context
    }

    fn context_mut(&mut self) -> &mut FSMContext<Self::Schema> {
        &mut self.context
    }
}

impl SyncMessageHandler for TestSyncState {
    type Pull = PullRequest;
    type Share = ShareData<SupraDeliveryErasureRs8Schema>;
    type EchoShare = EchoShareData<SupraDeliveryErasureRs8Schema>;
    type EchoValue = EchoValueData<SupraDeliveryErasureRs8Schema>;
    type Ready = ReadyData<SupraDeliveryErasureRs8Schema>;
    type EchoReady = EchoReadyData<SupraDeliveryErasureRs8Schema>;

    fn handle_share(&mut self, msg: Self::Share) {
        self.handle_share_called.store(true, Ordering::Relaxed);
        self.payload_state_mut()
            .store_piece_index(msg.value().get_chunk_index());
    }

    fn handle_echo_value(&mut self, msg: Self::EchoValue) {
        self.handle_echo_value_called.store(true, Ordering::Relaxed);
        self.payload_state_mut()
            .store_chunk_index(msg.value().get_chunk_index());
    }

    fn handle_echo_share(&mut self, msg: Self::EchoShare) {
        self.handle_echo_share_called.store(true, Ordering::Relaxed);
        self.payload_state_mut()
            .store_chunk_index(msg.value().get_chunk_index())
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

    fn handle_pull_request(&mut self, _msg: Self::Pull) {
        self.handle_pull_called.store(true, Ordering::Relaxed);
    }
}

impl SyncMessageReceiver<SupraDeliveryErasureRs8Schema> for TestSyncState {}

impl ReceiveMessage<RBCSyncMessage<SupraDeliveryErasureRs8Schema>> for TestSyncState {
    fn receive_message(&mut self, message: RBCSyncMessage<SupraDeliveryErasureRs8Schema>) {
        self.handle_message(message)
    }
}

impl InputVerifier<SupraDeliveryErasureRs8Schema, RBCSyncMessage<SupraDeliveryErasureRs8Schema>>
    for TestSyncState
{
    // For message with odd index verification will fail, otherwise it will be successful
    // Verification of the certificate is always success
    fn verify(
        &self,
        message: &RBCSyncMessage<SupraDeliveryErasureRs8Schema>,
    ) -> VerificationResult {
        self.verification_called.store(true, Ordering::Relaxed);
        let message_index_is_even = message.data_index().unwrap_or_default() % 2 == 0;
        match message {
            RBCSyncMessage::Pull(_) => VerificationResult::Success,
            _ => VerificationResult::from(message_index_is_even),
        }
    }
}

#[tokio::test]
async fn test_duplicated_items_are_ignored_committee_payload() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let header = Header::new(
        [0; 64],
        context_provider.resource_provider.get_origin(&leader_index),
        [3; 32],
    );
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        peer_index,
        PayloadType::Committee,
        header.clone(),
    );
    let mut test_state = TestSyncState::new(context);

    let check_duplicate_message_consumption =
        |state: &mut TestSyncState,
         msg: RBCSyncMessage<SupraDeliveryErasureRs8Schema>,
         chunk_index: usize| {
            let is_duplicate = state.is_duplicate(&msg);
            assert!(is_duplicate);
            let v_result = state.verify_message(&msg);
            assert!(v_result.is_ignore());
            state.handle_message(msg);
            assert!(state.payload_state().has_chunk(chunk_index));
            // Duplicate message is not verified
            assert!(!state.verification_called.load(Ordering::Relaxed));
        };

    let data_index = 2;
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let value_msg = RBCSyncMessage::EchoValue(EchoValueData::new(value_data));
    let is_duplicate = test_state.is_duplicate(&value_msg);
    assert!(!is_duplicate);
    let v_result = test_state.verify_message(&value_msg);
    assert!(v_result.is_ok(), "{:?}", v_result);
    test_state.handle_message(value_msg);
    assert!(test_state.payload_state().has_chunk(data_index));
    test_state = test_state.clear_call_flags();

    // duplicate message
    let echo_value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let echo_value_msg = RBCSyncMessage::EchoValue(EchoValueData::new(echo_value_data));
    check_duplicate_message_consumption(&mut test_state, echo_value_msg, data_index);

    let ready_data = ReadyData::new(
        [4; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index),
    );
    let ready_msg = RBCSyncMessage::Ready(ready_data);
    check_duplicate_message_consumption(&mut test_state, ready_msg, data_index);

    // For pull no duplication can be defined
    let pull_request = PullRequest::new(
        [2; 32],
        SyncRequest::new(header.clone(), QuorumCertificate::default()),
    );
    let pull_msg = RBCSyncMessage::<SupraDeliveryErasureRs8Schema>::Pull(pull_request);
    assert!(!test_state.is_duplicate(&pull_msg));
    assert!(test_state.verify_message(&pull_msg).is_ok());
}

#[tokio::test]
async fn test_duplicated_items_are_ignored_network_payload() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let header = Header::new(
        [0; 64],
        context_provider.resource_provider.get_origin(&leader_index),
        [3; 32],
    );
    let peer_index = PeerGlobalIndex::new(0, 1, 2);
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        peer_index,
        PayloadType::Network,
        header.clone(),
    );
    let mut test_state = TestSyncState::new(context);

    let check_duplicate_message_consumption =
        |state: &mut TestSyncState,
         msg: RBCSyncMessage<SupraDeliveryErasureRs8Schema>,
         chunk_index: Option<usize>,
         piece_index: Option<usize>| {
            let is_duplicate = state.is_duplicate(&msg);
            assert!(is_duplicate);
            let v_result = state.verify_message(&msg);
            assert!(v_result.is_ignore());
            state.handle_message(msg);
            chunk_index.map(|index| assert!(state.payload_state().has_chunk(index)));
            piece_index.map(|index| assert!(state.payload_state().has_piece(index)));
            // Duplicate message is not verified
            assert!(!state.verification_called.load(Ordering::Relaxed));
        };

    let data_index = 2;
    let share_data = ShareData::new(
        [2; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index),
        CommitmentMeta::default(),
    );
    let share_msg = RBCSyncMessage::Share(share_data);
    let is_duplicate = test_state.is_duplicate(&share_msg);
    assert!(!is_duplicate);
    let v_result = test_state.verify_message(&share_msg);
    assert!(v_result.is_ok(), "{:?}", v_result);
    test_state.handle_message(share_msg);
    assert!(test_state.payload_state().has_piece(data_index));
    test_state = test_state.clear_call_flags();

    let value_data = ShareData::new(
        [2; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index),
        CommitmentMeta::default(),
    );
    let share_msg = RBCSyncMessage::Share(value_data);
    check_duplicate_message_consumption(&mut test_state, share_msg, None, Some(data_index));

    let data_index = 8;
    let echo_share_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let echo_share_msg = RBCSyncMessage::EchoShare(EchoShareData::new([3; 32], echo_share_data));
    let is_duplicate = test_state.is_duplicate(&echo_share_msg);
    assert!(!is_duplicate);
    let v_result = test_state.verify_message(&echo_share_msg);
    assert!(v_result.is_ok(), "{:?}", v_result);
    test_state.handle_message(echo_share_msg);
    assert!(test_state.payload_state().has_chunk(data_index));
    test_state = test_state.clear_call_flags();

    // duplicate message
    let echo_share_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let echo_share_msg = RBCSyncMessage::EchoShare(EchoShareData::new([3; 32], echo_share_data));
    check_duplicate_message_consumption(&mut test_state, echo_share_msg, Some(data_index), None);

    // For pull no duplication can be defined
    let pull_request = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 1, 1)),
        SyncRequest::new(header.clone(), QuorumCertificate::default()),
    );
    let pull_msg = RBCSyncMessage::<SupraDeliveryErasureRs8Schema>::Pull(pull_request);
    assert!(!test_state.is_duplicate(&pull_msg));
    assert!(test_state.verify_message(&pull_msg).is_ok());
}

#[tokio::test]
async fn test_input_message_wrt_delivery_state_committee() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let header = Header::new(
        [0; 64],
        context_provider.resource_provider.get_origin(&leader_index),
        [3; 32],
    );
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        peer_index,
        PayloadType::Committee,
        header.clone(),
    );
    let mut committee_sync_state = TestSyncState::new(context);

    let data_index = 2;
    let share_data = ShareData::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 1, 0)),
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index),
        CommitmentMeta::default(),
    );
    let share_msg = RBCSyncMessage::Share(share_data);
    let result = committee_sync_state.verify_message_wrt_delivery_state(&share_msg);
    assert!(result.is_err());
    committee_sync_state.handle_message(share_msg);
    assert!(!committee_sync_state
        .verification_called
        .load(Ordering::Relaxed));
    assert!(!committee_sync_state.payload_state().has_chunk(data_index));
    let error_feedback = committee_sync_state
        .take_response()
        .unwrap()
        .take_feedback()
        .remove(0);
    assert!(
        matches!(error_feedback, FeedbackMessage::Error(_, _)),
        "{}",
        error_feedback
    );

    let data_index = 4;
    let share_data = EchoShareData::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 1, 0)),
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index),
    );
    let echo_share_msg = RBCSyncMessage::EchoShare(share_data);
    let result = committee_sync_state.verify_message_wrt_delivery_state(&echo_share_msg);
    assert!(result.is_err());
    committee_sync_state.handle_message(echo_share_msg);
    assert!(!committee_sync_state
        .verification_called
        .load(Ordering::Relaxed));
    assert!(!committee_sync_state.payload_state().has_chunk(data_index));
    let error_feedback = committee_sync_state
        .take_response()
        .unwrap()
        .take_feedback()
        .remove(0);
    assert!(matches!(error_feedback, FeedbackMessage::Error(_, _)));

    let pull_request_from_peer = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 0, 3)),
        SyncRequest::new(header.clone(), QuorumCertificate::default()),
    );
    let pull_request_from_nt_peer = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 1, 3)),
        SyncRequest::new(header.clone(), QuorumCertificate::default()),
    );
    let result = committee_sync_state
        .verify_message_wrt_delivery_state(&RBCSyncMessage::Pull(pull_request_from_peer));
    assert!(result.is_ok());
    let result = committee_sync_state
        .verify_message_wrt_delivery_state(&RBCSyncMessage::Pull(pull_request_from_nt_peer));
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_input_message_wrt_delivery_state_network() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let header = Header::new(
        [0; 64],
        context_provider.resource_provider.get_origin(&leader_index),
        [3; 32],
    );
    let peer_index = PeerGlobalIndex::new(0, 1, 2);
    let context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        peer_index,
        PayloadType::Network,
        header.clone(),
    );
    let mut network_sync_state = TestSyncState::new(context);

    let data_index = 2;
    let echo_data = EchoValueData::new(
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index),
    );
    let echo_msg = RBCSyncMessage::EchoValue(echo_data);
    let result = network_sync_state.verify_message_wrt_delivery_state(&echo_msg);
    assert!(result.is_err());
    network_sync_state.handle_message(echo_msg);
    assert!(!network_sync_state
        .verification_called
        .load(Ordering::Relaxed));
    assert!(!network_sync_state.payload_state().has_chunk(data_index));
    let error_feedback = network_sync_state
        .take_response()
        .unwrap()
        .take_feedback()
        .remove(0);
    assert!(matches!(error_feedback, FeedbackMessage::Error(_, _)));

    let data_index = 4;
    let ready_data = ReadyData::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 0, 4)),
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index),
    );
    let ready_msg = RBCSyncMessage::Ready(ready_data);
    let result = network_sync_state.verify_message_wrt_delivery_state(&ready_msg);
    assert!(result.is_err());
    network_sync_state.handle_message(ready_msg);
    assert!(!network_sync_state
        .verification_called
        .load(Ordering::Relaxed));
    assert!(!network_sync_state.payload_state().has_chunk(data_index));
    let error_feedback = network_sync_state
        .take_response()
        .unwrap()
        .take_feedback()
        .remove(0);
    assert!(matches!(error_feedback, FeedbackMessage::Error(_, _)));

    let pull_request_from_peer = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 0, 3)),
        SyncRequest::new(header.clone(), QuorumCertificate::default()),
    );
    let pull_request_from_nt_peer = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 1, 3)),
        SyncRequest::new(header.clone(), QuorumCertificate::default()),
    );
    let result = network_sync_state
        .verify_message_wrt_delivery_state(&RBCSyncMessage::Pull(pull_request_from_peer));
    assert!(result.is_err());
    let result = network_sync_state
        .verify_message_wrt_delivery_state(&RBCSyncMessage::Pull(pull_request_from_nt_peer));
    assert!(result.is_ok());
}

fn check_verification_and_handler_are_called(
    state: &mut TestSyncState,
    msg: RBCSyncMessage<SupraDeliveryErasureRs8Schema>,
    get_flag: impl Fn(&TestSyncState) -> &AtomicBool,
) {
    state.handle_message(msg);
    assert!(state.verification_called.load(Ordering::Relaxed));
    assert!(get_flag(state).load(Ordering::Relaxed));
}

#[tokio::test]
async fn test_verification_and_handler_is_called_for_all_messages() {
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let header = Header::new(
        [0; 64],
        context_provider.resource_provider.get_origin(&leader_index),
        [3; 32],
    );

    let data_index = 2;
    let nt_peer_index = PeerGlobalIndex::new(0, 1, 2);
    let peer_index = PeerGlobalIndex::new(0, 0, 2);
    let nt_context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        nt_peer_index,
        PayloadType::Network,
        header.clone(),
    );
    let cmt_context = context_provider.sync_context::<SupraDeliveryErasureRs8Schema>(
        peer_index,
        PayloadType::Committee,
        header.clone(),
    );
    let mut committee_sync_state = TestSyncState::new(cmt_context);
    let mut network_sync_state = TestSyncState::new(nt_context);

    let echo_value_data = EchoValueData::new(value_data_with_header_idx::<
        SupraDeliveryErasureRs8Schema,
    >(header.clone(), data_index * 2));
    let echo_value_msg = RBCSyncMessage::EchoValue(echo_value_data);
    check_verification_and_handler_are_called(&mut committee_sync_state, echo_value_msg, |st| {
        &st.handle_echo_value_called
    });
    committee_sync_state = committee_sync_state.clear_call_flags();

    let ready_data = ReadyData::new(
        [4; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index * 3),
    );
    let ready_msg = RBCSyncMessage::Ready(ready_data);
    check_verification_and_handler_are_called(&mut committee_sync_state, ready_msg, |st| {
        &st.handle_ready_called
    });
    committee_sync_state = committee_sync_state.clear_call_flags();

    let echo_ready_data = EchoReadyData::new(ReadyData::new(
        [4; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index * 4),
    ));
    let echo_ready_msg = RBCSyncMessage::EchoReady(echo_ready_data);
    check_verification_and_handler_are_called(&mut committee_sync_state, echo_ready_msg, |st| {
        &st.handle_echo_ready_called
    });
    committee_sync_state = committee_sync_state.clear_call_flags();

    let data_index = 2;
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let share_msg = RBCSyncMessage::Share(ShareData::new(
        [0; 32],
        value_data,
        CommitmentMeta::default(),
    ));
    check_verification_and_handler_are_called(&mut network_sync_state, share_msg, |st| {
        &st.handle_share_called
    });
    network_sync_state = network_sync_state.clear_call_flags();

    let data_index = 4;
    let value_data =
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index);
    let share_msg = RBCSyncMessage::EchoShare(EchoShareData::new([0; 32], value_data));
    check_verification_and_handler_are_called(&mut network_sync_state, share_msg, |st| {
        &st.handle_echo_share_called
    });
    network_sync_state = network_sync_state.clear_call_flags();

    // Pull
    let pull_data = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 1, 1)),
        SyncRequest::new(header.clone(), QuorumCertificate::default()),
    );
    let pull_message = RBCSyncMessage::<SupraDeliveryErasureRs8Schema>::Pull(pull_data);
    check_verification_and_handler_are_called(&mut committee_sync_state, pull_message, |st| {
        &st.handle_pull_called
    });

    // Pull
    let pull_data = PullRequest::new(
        context_provider
            .resource_provider
            .get_origin(&PeerGlobalIndex::new(0, 1, 1)),
        SyncRequest::new(header.clone(), QuorumCertificate::default()),
    );
    let pull_message = RBCSyncMessage::<SupraDeliveryErasureRs8Schema>::Pull(pull_data);
    check_verification_and_handler_are_called(&mut network_sync_state, pull_message, |st| {
        &st.handle_pull_called
    });
}
