use crate::states::handlers::{InputVerifier, NetworkMessageHandler, NetworkMessageReceiver};
use crate::states::tests::ContextProvider;
use crate::tasks::LoggingName;
use crate::types::context::network::{NetworkFSMContext, NetworkFSMContextSchema};
use crate::types::context::{FSMContext, FSMContextOwner};
use crate::types::helpers::verifier_visitor::VerificationResult;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{EchoShareData, RBCNetworkMessage, ResponseTypeIfc, ShareData};
use crate::types::payload_state::{NetworkChunkDataSettings, PayloadDataSettings};
use crate::types::tests::{share_data, value_data_with_header_idx};
use crate::{FeedbackMessage, QuorumCertificate, SupraDeliveryErasureRs8Schema};
use primitives::types::header::HeaderIfc;
use primitives::PeerGlobalIndex;
use sfsm::ReceiveMessage;
use std::sync::atomic::{AtomicBool, Ordering};

struct TestNtwState {
    context: NetworkFSMContext<SupraDeliveryErasureRs8Schema>,
    verification_called: AtomicBool,
    handle_share_called: AtomicBool,
    handle_echo_share_called: AtomicBool,
    handle_pull_called: AtomicBool,
    handle_sync_called: AtomicBool,
}

impl TestNtwState {
    fn new(context: NetworkFSMContext<SupraDeliveryErasureRs8Schema>) -> Self {
        Self {
            context,
            verification_called: Default::default(),
            handle_share_called: Default::default(),
            handle_echo_share_called: Default::default(),
            handle_pull_called: Default::default(),
            handle_sync_called: Default::default(),
        }
    }

    fn clear_call_flags(self) -> Self {
        TestNtwState::new(self.context)
    }
}

impl FSMContextOwner for TestNtwState {
    type Schema = NetworkFSMContextSchema<SupraDeliveryErasureRs8Schema>;

    fn context(&self) -> &FSMContext<Self::Schema> {
        &self.context
    }

    fn context_mut(&mut self) -> &mut FSMContext<Self::Schema> {
        &mut self.context
    }
}

impl NetworkMessageHandler for TestNtwState {
    type Share = ShareData<SupraDeliveryErasureRs8Schema>;
    type EchoShare = EchoShareData<SupraDeliveryErasureRs8Schema>;

    fn handle_share(&mut self, msg: Self::Share) {
        self.handle_share_called.store(true, Ordering::Relaxed);
        self.payload_state_mut()
            .store_piece_index(msg.value().get_chunk_index());
    }

    fn handle_echo_share(&mut self, msg: Self::EchoShare) {
        self.handle_echo_share_called.store(true, Ordering::Relaxed);
        self.payload_state_mut()
            .store_chunk_index(msg.value().get_chunk_index());
    }

    fn handle_pull_request(&mut self, _msg: PullRequest) {
        self.handle_pull_called.store(true, Ordering::Relaxed);
    }

    fn handle_sync_request(&mut self, _msg: SyncRequest) {
        self.handle_sync_called.store(true, Ordering::Relaxed);
    }
}

impl NetworkMessageReceiver<SupraDeliveryErasureRs8Schema> for TestNtwState {}

impl ReceiveMessage<RBCNetworkMessage<SupraDeliveryErasureRs8Schema>> for TestNtwState {
    fn receive_message(&mut self, message: RBCNetworkMessage<SupraDeliveryErasureRs8Schema>) {
        self.handle_message(message)
    }
}
impl LoggingName for TestNtwState {
    fn name<'a>() -> &'a str {
        "TestNtwState"
    }
}

impl InputVerifier<SupraDeliveryErasureRs8Schema, RBCNetworkMessage<SupraDeliveryErasureRs8Schema>>
    for TestNtwState
{
    // For message with odd index verification will fail, otherwise it will be successful
    // Verification of the certificate is always success
    fn verify(
        &self,
        message: &RBCNetworkMessage<SupraDeliveryErasureRs8Schema>,
    ) -> VerificationResult {
        self.verification_called.store(true, Ordering::Relaxed);
        let message_index_is_even = message.data_index().unwrap_or_default() % 2 == 0;
        VerificationResult::from(message_index_is_even)
    }
}

#[tokio::test]
async fn test_duplicated_share_items_are_ignored() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.network_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut test_state = TestNtwState::new(context);
    let header = test_state.payload_state().get_header();

    let data_index = 2;
    let share = share_data(
        [1; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index),
    );
    let share_msg = RBCNetworkMessage::Share(share);
    let is_duplicate = test_state.is_duplicate(&share_msg);
    assert!(!is_duplicate);
    let v_result = test_state.verify_message(&share_msg);
    assert!(v_result.is_ok(), "{:?}", v_result);
    test_state.handle_message(share_msg);
    assert!(test_state.payload_state().has_piece(data_index));
    assert_eq!(test_state.payload_state().get_received_pieces().len(), 1);
    test_state = test_state.clear_call_flags();

    // duplicate message
    let share = share_data(
        [1; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header, data_index),
    );
    let share_msg = RBCNetworkMessage::Share(share);
    let is_duplicate = test_state.is_duplicate(&share_msg);
    assert!(is_duplicate);
    let v_result = test_state.verify_message(&share_msg);
    assert!(v_result.is_ignore());
    test_state.handle_message(share_msg);
    assert!(test_state.payload_state().has_piece(data_index));
    assert_eq!(test_state.payload_state().get_received_pieces().len(), 1);
    // Duplicate message is not verified
    assert!(!test_state.verification_called.load(Ordering::Relaxed));
}

#[tokio::test]
async fn test_duplicated_echo_share_items_are_ignored() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.network_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut test_state = TestNtwState::new(context);
    let header = test_state.payload_state().get_header();

    let data_index = 2;
    let echo_shared_data = EchoShareData::new(
        [1; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index),
    );
    let echo_share_msg = RBCNetworkMessage::EchoShare(echo_shared_data);
    let is_duplicate = test_state.is_duplicate(&echo_share_msg);
    assert!(!is_duplicate);
    let v_result = test_state.verify_message(&echo_share_msg);
    assert!(v_result.is_ok(), "{:?}", v_result);
    test_state.handle_message(echo_share_msg);
    assert!(test_state.payload_state().has_chunk(data_index));
    assert_eq!(test_state.payload_state().get_received_chunks().len(), 1);
    test_state = test_state.clear_call_flags();

    // duplicate message
    let echo_shared_data = EchoShareData::new(
        [1; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header, data_index),
    );
    let echo_share_msg = RBCNetworkMessage::EchoShare(echo_shared_data);
    let is_duplicate = test_state.is_duplicate(&echo_share_msg);
    assert!(is_duplicate);
    let v_result = test_state.verify_message(&echo_share_msg);
    assert!(v_result.is_ignore());
    test_state.handle_message(echo_share_msg);
    assert!(test_state.payload_state().has_chunk(data_index));
    assert_eq!(test_state.payload_state().get_received_chunks().len(), 1);
    // Duplicate message is not verified
    assert!(!test_state.verification_called.load(Ordering::Relaxed));
}

fn check_verification_and_handler_are_called(
    state: &mut TestNtwState,
    msg: RBCNetworkMessage<SupraDeliveryErasureRs8Schema>,
    get_flag: impl Fn(&TestNtwState) -> &AtomicBool,
) {
    state.handle_message(msg);
    assert!(state.verification_called.load(Ordering::Relaxed));
    assert!(get_flag(state).load(Ordering::Relaxed));
}

#[tokio::test]
async fn test_verification_and_handler_is_called_for_all_messages() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.network_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut test_state = TestNtwState::new(context);
    let header = test_state.payload_state().get_header();

    let data_index = 2;
    let share = share_data(
        [1; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index),
    );
    let share_msg = RBCNetworkMessage::Share(share);
    check_verification_and_handler_are_called(&mut test_state, share_msg, |st| {
        &st.handle_share_called
    });
    test_state = test_state.clear_call_flags();

    let echo_shared_data = EchoShareData::new(
        [1; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index * 2),
    );
    let echo_share_msg = RBCNetworkMessage::EchoShare(echo_shared_data);
    check_verification_and_handler_are_called(&mut test_state, echo_share_msg, |st| {
        &st.handle_echo_share_called
    });

    // Pull
    let pull_data = PullRequest::new(
        [1; 32],
        SyncRequest::new(header.clone(), QuorumCertificate::default()),
    );
    let pull_message = RBCNetworkMessage::<SupraDeliveryErasureRs8Schema>::Pull(pull_data);
    check_verification_and_handler_are_called(&mut test_state, pull_message, |st| {
        &st.handle_pull_called
    });
    test_state = test_state.clear_call_flags();

    // Sync
    let sync_data = SyncRequest::new(header.clone(), QuorumCertificate::default());
    let sync_msg = RBCNetworkMessage::<SupraDeliveryErasureRs8Schema>::Sync(sync_data);
    check_verification_and_handler_are_called(&mut test_state, sync_msg, |st| {
        &st.handle_sync_called
    });
}

#[tokio::test]
async fn test_verification_failure_send_error_as_feedback() {
    let peer_index = PeerGlobalIndex::new(0, 1, 1);
    let leader_index = PeerGlobalIndex::new(0, 0, 0);
    let mut context_provider = ContextProvider::new(leader_index);
    let context = context_provider.network_context::<SupraDeliveryErasureRs8Schema>(peer_index);
    let mut test_state = TestNtwState::new(context);
    let header = test_state.payload_state().get_header();

    // Verification fails for data with odd index
    let data_index = 1;
    let sender_origin = context_provider
        .resource_provider
        .get_origin(&PeerGlobalIndex::new(0, 0, 1));
    let share = share_data(
        sender_origin,
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index),
    );
    let share_msg = RBCNetworkMessage::Share(share);
    test_state.handle_message(share_msg);
    assert!(test_state.verification_called.load(Ordering::Relaxed));
    assert!(!test_state.handle_share_called.load(Ordering::Relaxed));
    let mut response = test_state.take_response().expect("Response is expected");
    assert!(response.messages().is_empty());
    let feedback = response.take_feedback().remove(0);
    match feedback {
        FeedbackMessage::Error(meta, origin) => {
            assert_eq!(&meta, header.meta());
            assert_eq!(origin, sender_origin)
        }
        _ => {
            panic!("expected FeedbackMessage::Error")
        }
    }
    test_state = test_state.clear_call_flags();

    // Verification failure as origin can not be found
    let share = share_data(
        [1; 32],
        value_data_with_header_idx::<SupraDeliveryErasureRs8Schema>(header.clone(), data_index),
    );
    let share_msg = RBCNetworkMessage::Share(share);
    test_state.handle_message(share_msg);
    assert!(test_state.verification_called.load(Ordering::Relaxed));
    assert!(!test_state.handle_share_called.load(Ordering::Relaxed));
    let mut response = test_state.take_response().expect("Response is expected");
    assert!(response.messages().is_empty());
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
