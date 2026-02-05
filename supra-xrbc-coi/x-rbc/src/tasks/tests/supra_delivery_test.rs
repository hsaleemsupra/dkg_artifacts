use crate::synchronizer::request::SyncResponse;
use crate::tasks::codec::EncodeResultIfc;
use crate::tasks::messages::{PayloadRequest, RBCMessage};
use crate::tasks::tests::{
    check_task_state_is_done, check_task_state_is_in_progress, consume_random_payload, task_list,
    TestSupraDeliveryResources,
};
use crate::types::context::ResourcesApi;
use crate::types::helpers::verifier_visitor::verify_value_data_tests::{
    encoded_chunks, payload, TestResources,
};
use crate::types::messages::chunk::ChunkData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{ValueData, VoteData};
use crate::types::payload_state::sync::PayloadType;
use crate::types::payload_state::PayloadFlags;
use crate::types::tests::{header_with_origin, share_data, value_data_with_header};
use crate::{
    FeedbackMessage, InternalSyncRequest, SupraDelivery, SupraDeliveryErasureRs16Schema,
    SupraDeliveryErasureRs8Schema, SupraDeliveryRs16Schema, SupraDeliveryRs8Schema,
};
use crypto::PartialShare;
use itertools::Itertools;
use network::topology::peer_info::Role;
use primitives::types::header::{Header, HeaderIfc, MessageMeta};
use primitives::types::QuorumCertificate;
use primitives::PeerGlobalIndex;
use std::time::Duration;
use storage::{StorageReadIfc, StorageWriteIfc};
use tokio::runtime::Handle;
use tokio::task;
use tokio::time::timeout;

#[tokio::test]
async fn test_handle_new_payload() {
    let role = Role::Basic;
    let peer_index = PeerGlobalIndex::new(0, 0, 0);
    let mut sd_test_obj =
        TestSupraDeliveryResources::<SupraDeliveryRs16Schema>::new(peer_index, role);

    assert_eq!(sd_test_obj.delivery_manager.tasks().len(), 0);
    consume_random_payload(&mut sd_test_obj);

    assert_eq!(sd_test_obj.delivery_manager.tasks().len(), 1);
    consume_random_payload(&mut sd_test_obj);
    assert_eq!(sd_test_obj.delivery_manager.tasks().len(), 2);
}

#[tokio::test]
async fn test_handle_done_feedback() {
    let role = Role::Leader;
    let peer_index = PeerGlobalIndex::new(0, 0, 0);
    let mut test_resources =
        TestSupraDeliveryResources::<SupraDeliveryRs16Schema>::new(peer_index, role);

    consume_random_payload(&mut test_resources);
    consume_random_payload(&mut test_resources);

    let msg_meta: Vec<MessageMeta> = task_list(&test_resources);
    let done_feedback = FeedbackMessage::Done(msg_meta[0].clone());
    assert!(test_resources
        .delivery_manager
        .handle_feedback(done_feedback)
        .is_ok());
    check_task_state_is_done(&test_resources, &msg_meta[0]);
    check_task_state_is_in_progress(&test_resources, &msg_meta[1]);
    let delivery_feedback = test_resources.payload_consumer.try_recv().unwrap();
    if let FeedbackMessage::Done(meta) = delivery_feedback {
        assert_eq!(meta, msg_meta[0]);
    }
}

#[tokio::test]
async fn test_handle_error_feedback() {
    let role = Role::Leader;
    let peer_index = PeerGlobalIndex::new(0, 0, 0);
    let mut test_resources =
        TestSupraDeliveryResources::<SupraDeliveryRs16Schema>::new(peer_index, role);

    consume_random_payload(&mut test_resources);
    consume_random_payload(&mut test_resources);

    let msg_meta: Vec<MessageMeta> = task_list(&test_resources);
    let blacklisted_origin = [2; 32];
    let error_feedback = FeedbackMessage::Error(msg_meta[0].clone(), blacklisted_origin);
    assert!(test_resources
        .delivery_manager
        .handle_feedback(error_feedback)
        .is_ok());
    // origin is blacklisted but task is still active
    check_task_state_is_in_progress(&test_resources, &msg_meta[0]);
    check_task_state_is_in_progress(&test_resources, &msg_meta[1]);
    assert!(test_resources.payload_consumer.try_recv().is_err());
    assert!(test_resources
        .delivery_manager
        .blacklist()
        .contains(&blacklisted_origin));

    // Blacklisted origin is the owner of deliverable
    let blacklisted_origin = *msg_meta[1].origin();
    let error_feedback = FeedbackMessage::Error(msg_meta[1].clone(), blacklisted_origin);
    assert!(test_resources
        .delivery_manager
        .handle_feedback(error_feedback)
        .is_ok());
    check_task_state_is_in_progress(&test_resources, &msg_meta[0]);
    // origin is blacklisted and the task is moved to done state
    check_task_state_is_done(&test_resources, &msg_meta[1]);
    assert!(test_resources.payload_consumer.try_recv().is_err());
    assert!(test_resources
        .delivery_manager
        .blacklist()
        .contains(&blacklisted_origin))
}

#[tokio::test]
async fn test_handle_internal_error_feedback() {
    let role = Role::Leader;
    let peer_index = PeerGlobalIndex::new(0, 0, 0);
    let mut test_resources =
        TestSupraDeliveryResources::<SupraDeliveryRs16Schema>::new(peer_index, role);

    consume_random_payload(&mut test_resources);
    consume_random_payload(&mut test_resources);

    let msg_meta: Vec<MessageMeta> = task_list(&test_resources);
    let internal_error = FeedbackMessage::InternalError(
        msg_meta[0].clone(),
        "Something happened with delivery".to_string(),
    );
    assert!(test_resources
        .delivery_manager
        .handle_feedback(internal_error)
        .is_ok());
    check_task_state_is_done(&test_resources, &msg_meta[0]);
    check_task_state_is_in_progress(&test_resources, &msg_meta[1]);
    assert!(test_resources.payload_consumer.try_recv().is_err());
    assert!(test_resources.delivery_manager.blacklist().is_empty());
}

#[tokio::test]
async fn test_handle_message() {
    let handler = tokio::task::spawn_blocking(|| {
        let role = Role::Leader;
        let peer_index = PeerGlobalIndex::new(0, 0, 0);
        let mut test_resources =
            TestSupraDeliveryResources::<SupraDeliveryRs16Schema>::new(peer_index, role);

        let resources = test_resources.delivery_manager.get_resources();

        // Ill constructed message -> error
        let invalid_message = RBCMessage::<SupraDeliveryErasureRs16Schema>::Composite(vec![]);
        let result = test_resources
            .delivery_manager
            .handle_message(invalid_message);
        assert!(result.is_err());

        // Blacklisted Sender -> error
        let origin_0 = *resources.topology().peer_by_position(0).unwrap().id();
        let origin_1 = *resources.topology().peer_by_position(1).unwrap().id();
        let error_feedback = FeedbackMessage::Error(MessageMeta::new([0; 64], origin_0), origin_1);
        assert!(test_resources
            .delivery_manager
            .handle_feedback(error_feedback)
            .is_ok());
        let value_data =
            value_data_with_header::<SupraDeliveryErasureRs16Schema>(header_with_origin(origin_1));
        let msg = RBCMessage::Value(value_data);
        let result = test_resources.delivery_manager.handle_message(msg);
        assert!(result.is_err());

        // Blacklisted Origin -> error
        let origin_2 = *resources.topology().peer_by_position(2).unwrap().id();
        let error_feedback = FeedbackMessage::Error(MessageMeta::new([0; 64], origin_2), origin_2);
        assert!(test_resources
            .delivery_manager
            .handle_feedback(error_feedback)
            .is_ok());
        let value_data =
            value_data_with_header::<SupraDeliveryErasureRs16Schema>(header_with_origin(origin_2));
        let msg = RBCMessage::Value(value_data);
        let result = test_resources.delivery_manager.handle_message(msg);
        assert!(result.is_err());

        // sender origin could not be found
        let value_data =
            value_data_with_header::<SupraDeliveryErasureRs16Schema>(header_with_origin([5; 32]));
        let msg = RBCMessage::Value(value_data);
        let result = test_resources.delivery_manager.handle_message(msg);
        assert!(result.is_err());

        // Valid message to be processed but no task for it
        let vote_data = VoteData::new(header_with_origin(origin_0), PartialShare::new(4, [0; 96]));
        let msg = RBCMessage::<SupraDeliveryErasureRs16Schema>::Vote(vote_data);
        let result = test_resources.delivery_manager.handle_message(msg);
        assert!(result.is_err(), "{:?}", result);
        let payload_req = PayloadRequest::new(vec![10; 1000], None);
        let result = test_resources
            .delivery_manager
            .handle_new_payload(payload_req);
        assert!(result.is_ok());
        let task_id = test_resources
            .delivery_manager
            .tasks()
            .iter()
            .find_or_first(|_t| false)
            .unwrap()
            .0
            .clone();

        // Valid message to be processed
        let vote_data = VoteData::new(
            Header::new(task_id.id().clone(), task_id.origin().clone(), [0; 32]),
            PartialShare::new(4, [0; 96]),
        );
        let msg = RBCMessage::<SupraDeliveryErasureRs16Schema>::Vote(vote_data);
        let result = test_resources.delivery_manager.handle_message(msg);
        assert!(result.is_ok(), "{:?}", result);
    });
    assert!(handler.await.is_ok());
}

#[test]
fn test_commitment_validation() {
    let request_header = Header::new([0; 64], [1; 32], [3; 32]);
    let local_encoded_header = Header::new([2; 64], [3; 32], [5; 32]);
    let local_encoded_header_with_matching_commitment = Header::new([3; 64], [4; 32], [3; 32]);
    assert!(
        SupraDelivery::<SupraDeliveryRs8Schema>::validate_commitments(
            &request_header,
            &local_encoded_header
        )
        .is_err()
    );
    assert!(
        SupraDelivery::<SupraDeliveryRs8Schema>::validate_commitments(
            &request_header,
            &local_encoded_header_with_matching_commitment
        )
        .is_ok()
    );
}

#[test]
#[should_panic]
fn test_negative_payload_state_for_sync_task_no_payload() {
    let test_data = TestSupraDeliveryResources::<SupraDeliveryRs8Schema>::new(
        PeerGlobalIndex::new(0, 0, 0),
        Role::Basic,
    );
    let value_data = value_data_with_header::<SupraDeliveryErasureRs8Schema>(Header::default());
    test_data
        .delivery_manager
        .prepare_sync_task_state_with_no_data(
            &RBCMessage::<SupraDeliveryErasureRs8Schema>::Value(value_data),
            false,
        );
}

#[tokio::test]
async fn test_payload_state_for_sync_task_no_payload() {
    let h = tokio::task::spawn_blocking(|| {
        let mut test_data = TestSupraDeliveryResources::<SupraDeliveryRs8Schema>::new(
            PeerGlobalIndex::new(0, 0, 0),
            Role::Basic,
        );
        let resources_001 = test_data
            .resource_provider
            .get_resources(PeerGlobalIndex::new(0, 0, 1));
        let resources_011 = test_data
            .resource_provider
            .get_resources(PeerGlobalIndex::new(0, 1, 1));
        // data from the current clan
        let sync_request = RBCMessage::<SupraDeliveryErasureRs8Schema>::Sync(SyncRequest::new(
            TestResources::generate_header(resources_001.authenticator(), [2; 32]),
            QuorumCertificate::default(),
        ));
        // data from other clan then current node
        let pull_request = RBCMessage::<SupraDeliveryErasureRs8Schema>::Pull(PullRequest::new(
            [2; 32],
            SyncRequest::new(
                TestResources::generate_header(resources_011.authenticator(), [3; 32]),
                QuorumCertificate::default(),
            ),
        ));

        // State for the committee-deliverable synchronization
        let state = test_data
            .delivery_manager
            .prepare_sync_task_state_with_no_data(&sync_request, true);
        assert!(!state.has_payload_data());
        assert_eq!(state.payload_type(), PayloadType::Committee);
        assert_eq!(state.header(), sync_request.header());

        let state = test_data
            .delivery_manager
            .prepare_sync_task_state(&sync_request)
            .expect("Valid sync state");
        assert!(!state.has_payload_data());
        assert_eq!(state.payload_type(), PayloadType::Committee);
        assert_eq!(state.header(), sync_request.header());

        // State for the network-deliverable synchronization
        let state = test_data
            .delivery_manager
            .prepare_sync_task_state_with_no_data(&pull_request, false);
        assert!(!state.has_payload_data());
        assert_eq!(state.payload_type(), PayloadType::Network);
        assert_eq!(state.header(), pull_request.header());

        let state = test_data
            .delivery_manager
            .prepare_sync_task_state(&pull_request)
            .expect("Valid sync state");
        assert!(!state.has_payload_data());
        assert_eq!(state.payload_type(), PayloadType::Network);
        assert_eq!(state.header(), pull_request.header());
    });
    assert!(h.await.is_ok());
}

#[tokio::test]
#[should_panic]
async fn test_negative_payload_state_for_sync_task_with_payload() {
    let test_data = TestSupraDeliveryResources::<SupraDeliveryRs8Schema>::new(
        PeerGlobalIndex::new(0, 0, 0),
        Role::Basic,
    );
    let value_data = value_data_with_header::<SupraDeliveryErasureRs8Schema>(Header::default());
    let _ = test_data
        .delivery_manager
        .prepare_sync_task_state_with_payload(
            &RBCMessage::<SupraDeliveryErasureRs8Schema>::Value(value_data),
            false,
            [5; 1024].to_vec(),
        );
}

#[tokio::test]
async fn test_negative_for_sync_request_payload_state_for_sync_task_with_payload() {
    let test_data = TestSupraDeliveryResources::<SupraDeliveryRs8Schema>::new(
        PeerGlobalIndex::new(0, 0, 0),
        Role::Basic,
    );
    let sync_request = SyncRequest::new(Header::default(), QuorumCertificate::default());
    let result = test_data
        .delivery_manager
        .prepare_sync_task_state_with_payload(
            &RBCMessage::<SupraDeliveryErasureRs8Schema>::Sync(sync_request),
            false,
            [5; 1024].to_vec(),
        );
    assert!(result.is_err());
}

#[tokio::test]
async fn test_payload_state_for_sync_task_with_committee_payload() {
    let h = tokio::task::spawn_blocking(|| {
        let mut test_data = TestSupraDeliveryResources::<SupraDeliveryRs8Schema>::new(
            PeerGlobalIndex::new(0, 0, 0),
            Role::Basic,
        );

        let resources_001 = test_data
            .resource_provider
            .get_resources(PeerGlobalIndex::new(0, 0, 1));
        let payload = payload(1);
        let encoded_data = encoded_chunks(1, resources_001.authenticator());
        let current_resources = test_data.delivery_manager.get_resources();
        current_resources
            .storage_client()
            .write(encoded_data.header().hash(), payload.clone());
        assert!(current_resources
            .storage_client()
            .has_key_blocking(encoded_data.header().hash()));

        let pull_request = RBCMessage::<SupraDeliveryErasureRs8Schema>::Pull(PullRequest::new(
            [0; 32],
            SyncRequest::new(encoded_data.header().clone(), QuorumCertificate::default()),
        ));
        // State for the committee-deliverable synchronization
        let state = test_data
            .delivery_manager
            .prepare_sync_task_state_with_payload(&pull_request, true, payload)
            .expect("Valid sync state");
        assert!(state.has_payload_data());
        assert_eq!(state.payload_type(), PayloadType::Committee);
        assert_eq!(state.header(), encoded_data.header());

        let state = test_data
            .delivery_manager
            .prepare_sync_task_state(&pull_request)
            .expect("Valid sync state");
        assert!(state.has_payload_data());
        assert_eq!(state.payload_type(), PayloadType::Committee);
        assert_eq!(state.header(), encoded_data.header());
    });
    assert!(h.await.is_ok());
}

#[tokio::test]
async fn test_payload_state_for_sync_task_with_network_payload() {
    let h = tokio::task::spawn_blocking(|| {
        let mut test_data = TestSupraDeliveryResources::<SupraDeliveryRs8Schema>::new(
            PeerGlobalIndex::new(0, 0, 0),
            Role::Basic,
        );

        let resources_011 = test_data
            .resource_provider
            .get_resources(PeerGlobalIndex::new(0, 1, 1));
        let payload = payload(2);
        let encoded_data = encoded_chunks(2, resources_011.authenticator());
        let current_resources = test_data.delivery_manager.get_resources();
        current_resources
            .storage_client()
            .write(encoded_data.header().hash(), payload.clone());
        assert!(current_resources
            .storage_client()
            .has_key_blocking(encoded_data.header().hash()));

        let pull_request = RBCMessage::<SupraDeliveryErasureRs8Schema>::Pull(PullRequest::new(
            [0; 32],
            SyncRequest::new(encoded_data.header().clone(), QuorumCertificate::default()),
        ));
        // State for the network-deliverable synchronization
        let state = test_data
            .delivery_manager
            .prepare_sync_task_state_with_payload(&pull_request, false, payload)
            .expect("Valid sync state");
        assert!(state.has_payload_data());
        assert_eq!(state.payload_type(), PayloadType::Network);
        assert_eq!(state.header(), encoded_data.header());

        // State for the network-deliverable synchronization
        let state = test_data
            .delivery_manager
            .prepare_sync_task_state(&pull_request)
            .expect("Valid sync state");
        assert!(state.has_payload_data());
        assert_eq!(state.payload_type(), PayloadType::Network);
        assert_eq!(state.header(), encoded_data.header());
    });
    assert!(h.await.is_ok());
}

#[tokio::test]
async fn test_payload_state_for_sync_with_unknown_origin() {
    let test_data = TestSupraDeliveryResources::<SupraDeliveryRs8Schema>::new(
        PeerGlobalIndex::new(0, 0, 0),
        Role::Basic,
    );

    let pull_request = RBCMessage::<SupraDeliveryErasureRs8Schema>::Pull(PullRequest::new(
        [0; 32],
        SyncRequest::new(header_with_origin([2; 32]), QuorumCertificate::default()),
    ));

    let state = test_data
        .delivery_manager
        .prepare_sync_task_state(&pull_request);
    assert!(state.is_err());

    let syc_request = RBCMessage::<SupraDeliveryErasureRs8Schema>::Sync(SyncRequest::new(
        header_with_origin([2; 32]),
        QuorumCertificate::default(),
    ));

    let state = test_data
        .delivery_manager
        .prepare_sync_task_state(&syc_request);
    assert!(state.is_err());
}

#[tokio::test]
async fn test_get_task_api() {
    let handle = task::spawn_blocking(|| {
        let mut test_data = TestSupraDeliveryResources::<SupraDeliveryRs8Schema>::new(
            PeerGlobalIndex::new(0, 0, 0),
            Role::Basic,
        );
        let resources_001 = test_data
            .resource_provider
            .get_resources(PeerGlobalIndex::new(0, 0, 1));
        let sync_request = RBCMessage::<SupraDeliveryErasureRs8Schema>::Sync(SyncRequest::new(
            TestResources::generate_header(resources_001.authenticator(), [2; 32]),
            QuorumCertificate::default(),
        ));
        let sync_task_id = sync_request.header().meta().clone();

        let sync_task_state = test_data
            .delivery_manager
            .get_task(&sync_request)
            .expect("valid task state");
        assert!(sync_task_state.client().is_some());
        assert!(sync_task_state.client().as_ref().unwrap().is_sync());
        assert_eq!(test_data.delivery_manager.tasks().len(), 1);
        assert!(test_data
            .delivery_manager
            .tasks()
            .contains_key(&sync_task_id));

        let value_data =
            RBCMessage::<SupraDeliveryErasureRs8Schema>::Value(value_data_with_header::<
                SupraDeliveryErasureRs8Schema,
            >(
                TestResources::generate_header(resources_001.authenticator(), [3; 32]),
            ));
        let committee_task_id = value_data.header().meta().clone();

        let committee_task_state = test_data
            .delivery_manager
            .get_task(&value_data)
            .expect("valid task state");
        assert!(committee_task_state.client().is_some());
        assert!(committee_task_state
            .client()
            .as_ref()
            .unwrap()
            .is_committee());
        assert_eq!(test_data.delivery_manager.tasks().len(), 2);
        assert!(test_data
            .delivery_manager
            .tasks()
            .contains_key(&committee_task_id));

        let share_data = RBCMessage::<SupraDeliveryErasureRs8Schema>::Share(share_data(
            [5; 32],
            value_data_with_header::<SupraDeliveryErasureRs8Schema>(
                TestResources::generate_header(resources_001.authenticator(), [4; 32]),
            ),
        ));
        let network_task_id = share_data.header().meta().clone();

        let network_task_state = test_data
            .delivery_manager
            .get_task(&share_data)
            .expect("valid task state");
        assert!(network_task_state.client().is_some());
        assert!(network_task_state.client().as_ref().unwrap().is_network());
        assert_eq!(test_data.delivery_manager.tasks().len(), 3);
        assert!(test_data
            .delivery_manager
            .tasks()
            .contains_key(&network_task_id));

        // No new task is added
        test_data
            .delivery_manager
            .get_task(&sync_request)
            .expect("valid task state");
        test_data
            .delivery_manager
            .get_task(&value_data)
            .expect("valid task state");
        test_data
            .delivery_manager
            .get_task(&share_data)
            .expect("valid task state");
        assert_eq!(test_data.delivery_manager.tasks().len(), 3);
    });
    assert!(handle.await.is_ok());
}

#[tokio::test]
async fn test_handle_sync_request() {
    let h = tokio::task::spawn_blocking(|| {
        let mut test_data = TestSupraDeliveryResources::<SupraDeliveryRs8Schema>::new(
            PeerGlobalIndex::new(0, 0, 0),
            Role::Basic,
        );

        let sync_request_header =
            check_sync_request_with_no_existing_task_and_payload(&mut test_data);
        check_sync_request_with_existing_sync_task(&mut test_data, &sync_request_header);
        check_sync_request_for_owned_data(&mut test_data);
        check_sync_request_with_existing_payload_in_store(&mut test_data);
        // TODO: uncomment when sync requests are properly handled by Committee & Network tasks
        // check_sync_request_with_existing_non_sync_task(&mut test_data).await;
    });
    assert!(h.await.is_ok());
}

fn check_sync_request_with_no_existing_task_and_payload(
    test_data: &mut TestSupraDeliveryResources<SupraDeliveryRs8Schema>,
) -> Header {
    let existing_tasks = test_data.delivery_manager.tasks().len();
    let resources_001 = test_data
        .resource_provider
        .get_resources(PeerGlobalIndex::new(0, 0, 1));

    let header = TestResources::generate_header(resources_001.authenticator(), [2; 32]);
    let qc = test_data.resource_provider.generate_qc(
        resources_001.topology().current_node().clan_identifier(),
        header.commitment(),
    );
    let (feedback_tx, feedback_rx) = tokio::sync::oneshot::channel::<SyncResponse>();
    let internal_sync_request = InternalSyncRequest::new(header.clone(), qc, feedback_tx);
    let result = test_data
        .delivery_manager
        .handle_sync_request(internal_sync_request);
    assert!(result.is_ok());
    assert_eq!(test_data.delivery_manager.tasks().len(), existing_tasks + 1);
    assert!(test_data
        .delivery_manager
        .tasks()
        .contains_key(header.meta()));
    assert!(test_data
        .delivery_manager
        .sync_requests()
        .contains_key(header.meta()));
    // feedback is not expected
    Handle::current().block_on(async move {
        assert!(timeout(Duration::from_secs(1), feedback_rx).await.is_err());
    });
    header
}

fn check_sync_request_with_existing_sync_task(
    test_data: &mut TestSupraDeliveryResources<SupraDeliveryRs8Schema>,
    header: &Header,
) {
    let existing_tasks = test_data.delivery_manager.tasks().len();
    let qc = QuorumCertificate::default();
    let (feedback_tx, feedback_rx) = tokio::sync::oneshot::channel::<SyncResponse>();
    let internal_sync_request = InternalSyncRequest::new(header.clone(), qc, feedback_tx);
    let result = test_data
        .delivery_manager
        .handle_sync_request(internal_sync_request);
    assert!(result.is_err());
    assert_eq!(test_data.delivery_manager.tasks().len(), existing_tasks);
    assert!(test_data
        .delivery_manager
        .tasks()
        .contains_key(header.meta()));
    assert!(test_data
        .delivery_manager
        .sync_requests()
        .contains_key(header.meta()));
    // expect error as there was already ongoing sync task previously requested
    Handle::current().block_on(async move {
        assert!(feedback_rx.await.expect("Expect error response").is_err());
    });
}

fn check_sync_request_for_owned_data(
    test_data: &mut TestSupraDeliveryResources<SupraDeliveryRs8Schema>,
) -> Header {
    let existing_tasks = test_data.delivery_manager.tasks().len();
    let current_node_resources = test_data.delivery_manager.get_resources();

    let header = TestResources::generate_header(current_node_resources.authenticator(), [2; 32]);
    let qc = test_data.resource_provider.generate_qc(
        current_node_resources
            .topology()
            .current_node()
            .clan_identifier(),
        header.commitment(),
    );
    let (feedback_tx, feedback_rx) = tokio::sync::oneshot::channel::<SyncResponse>();
    let internal_sync_request = InternalSyncRequest::new(header.clone(), qc, feedback_tx);
    let result = test_data
        .delivery_manager
        .handle_sync_request(internal_sync_request);
    assert!(result.is_err());
    assert_eq!(test_data.delivery_manager.tasks().len(), existing_tasks);
    assert!(!test_data
        .delivery_manager
        .sync_requests()
        .contains_key(header.meta()));
    // feedback error is expected
    Handle::current().block_on(async move {
        assert!(timeout(Duration::from_secs(1), feedback_rx).await.is_ok());
    });
    header
}

fn check_sync_request_with_existing_payload_in_store(
    test_data: &mut TestSupraDeliveryResources<SupraDeliveryRs8Schema>,
) {
    let existing_tasks = test_data.delivery_manager.tasks().len();
    let resources_001 = test_data
        .resource_provider
        .get_resources(PeerGlobalIndex::new(0, 0, 1));

    let header = TestResources::generate_header(resources_001.authenticator(), [3; 32]);
    let current_resources = test_data.delivery_manager.get_resources();
    let key = header.hash();
    current_resources
        .storage_client()
        .write(key, [5; 1024].to_vec());
    assert!(current_resources.storage_client().has_key_blocking(key));
    let qc = test_data.resource_provider.generate_qc(
        resources_001.topology().current_node().clan_identifier(),
        header.commitment(),
    );
    let (feedback_tx, feedback_rx) = tokio::sync::oneshot::channel::<SyncResponse>();
    let internal_sync_request = InternalSyncRequest::new(header.clone(), qc, feedback_tx);
    let result = test_data
        .delivery_manager
        .handle_sync_request(internal_sync_request);
    assert!(result.is_ok());
    assert_eq!(test_data.delivery_manager.tasks().len(), existing_tasks);
    assert!(!test_data
        .delivery_manager
        .tasks()
        .contains_key(header.meta()));
    assert!(!test_data
        .delivery_manager
        .sync_requests()
        .contains_key(header.meta()));
    // expect non error feedback
    Handle::current().block_on(async move {
        assert!(feedback_rx.await.expect("error response").is_ok());
    });
}

async fn check_sync_request_with_existing_non_sync_task(
    test_data: &mut TestSupraDeliveryResources<SupraDeliveryRs8Schema>,
) {
    let existing_tasks = test_data.delivery_manager.tasks().len();
    let broadcaster_res = test_data.resource_provider.get_broadcaster_resources();
    let encoded_data = encoded_chunks(10, broadcaster_res.authenticator());
    let header = encoded_data.header();
    let value_data = ValueData::new(header.clone(), encoded_data.committee_chunks()[0].clone());
    test_data
        .delivery_manager
        .handle_message(RBCMessage::Value(value_data))
        .expect("successful handling");
    assert_eq!(test_data.delivery_manager.tasks().len(), existing_tasks + 1);

    let qc = test_data.resource_provider.generate_qc(
        broadcaster_res.topology().current_node().clan_identifier(),
        header.commitment(),
    );
    let (feedback_tx, _feedback_rx) = tokio::sync::oneshot::channel::<SyncResponse>();
    let internal_sync_request = InternalSyncRequest::new(header.clone(), qc, feedback_tx);
    let result = test_data
        .delivery_manager
        .handle_sync_request(internal_sync_request);
    assert!(result.is_ok());
    assert_eq!(test_data.delivery_manager.tasks().len(), existing_tasks + 1);
    assert!(test_data
        .delivery_manager
        .tasks()
        .contains_key(header.meta()));
    assert!(!test_data
        .delivery_manager
        .sync_requests()
        .contains_key(header.meta()));
}

#[tokio::test]
async fn test_sync_requests_on_error_feedback_message() {
    let h = tokio::task::spawn_blocking(|| {
        let mut test_data = TestSupraDeliveryResources::<SupraDeliveryRs8Schema>::new(
            PeerGlobalIndex::new(0, 0, 0),
            Role::Basic,
        );

        let resources_001 = test_data
            .resource_provider
            .get_resources(PeerGlobalIndex::new(0, 0, 1));

        let header1 = TestResources::generate_header(resources_001.authenticator(), [2; 32]);
        let qc1 = test_data.resource_provider.generate_qc(
            resources_001.topology().current_node().clan_identifier(),
            header1.commitment(),
        );
        let (feedback1_tx, feedback1_rx) = tokio::sync::oneshot::channel::<SyncResponse>();
        let internal_sync_request = InternalSyncRequest::new(header1.clone(), qc1, feedback1_tx);
        let result = test_data
            .delivery_manager
            .handle_sync_request(internal_sync_request);
        assert!(result.is_ok());

        test_data
            .delivery_manager
            .handle_feedback(FeedbackMessage::Error(header1.get_meta(), [5; 32]))
            .expect("successful handling");

        assert!(test_data
            .delivery_manager
            .sync_requests()
            .contains_key(header1.meta()));

        test_data
            .delivery_manager
            .handle_feedback(FeedbackMessage::InternalError(
                header1.get_meta(),
                "Error".to_string(),
            ))
            .expect("successful handling");

        assert!(!test_data
            .delivery_manager
            .sync_requests()
            .contains_key(header1.meta()));

        Handle::current().block_on(async move {
            let response = feedback1_rx.await.expect("Error Response");
            assert!(response.is_err());
        });
    });
    assert!(h.await.is_ok());
}

#[tokio::test]
async fn test_sync_requests_on_done_feedback_message() {
    let h = tokio::task::spawn_blocking(|| {
        let mut test_data = TestSupraDeliveryResources::<SupraDeliveryRs8Schema>::new(
            PeerGlobalIndex::new(0, 0, 0),
            Role::Basic,
        );

        let resources_001 = test_data
            .resource_provider
            .get_resources(PeerGlobalIndex::new(0, 0, 1));

        let header2 = TestResources::generate_header(resources_001.authenticator(), [3; 32]);
        let qc2 = test_data.resource_provider.generate_qc(
            resources_001.topology().current_node().clan_identifier(),
            header2.commitment(),
        );

        let (feedback2_tx, feedback2_rx) = tokio::sync::oneshot::channel::<SyncResponse>();
        let internal_sync_request = InternalSyncRequest::new(header2.clone(), qc2, feedback2_tx);
        let result = test_data
            .delivery_manager
            .handle_sync_request(internal_sync_request);
        assert!(result.is_ok());
        assert_eq!(test_data.delivery_manager.tasks().len(), 1);
        assert!(test_data
            .delivery_manager
            .sync_requests()
            .contains_key(header2.meta()));

        test_data
            .delivery_manager
            .handle_feedback(FeedbackMessage::Done(header2.get_meta()))
            .expect("successful handling");
        assert!(!test_data
            .delivery_manager
            .sync_requests()
            .contains_key(header2.meta()));
        Handle::current().block_on(async move {
            let response = feedback2_rx.await.expect("Ok Response");
            assert!(response.is_ok());
        });
    });
    assert!(h.await.is_ok());
}

#[tokio::test]
async fn test_should_be_processed_error() {
    let role = Role::Leader;
    let peer_000 = PeerGlobalIndex::new(0, 0, 0);
    let mut delivery_resources =
        TestSupraDeliveryResources::<SupraDeliveryRs16Schema>::new(peer_000, role);

    let res_001 = delivery_resources
        .resource_provider
        .get_resources(PeerGlobalIndex::new(0, 0, 1));
    let header_001 = TestResources::generate_header(res_001.authenticator(), [0; 32]);

    let value_data = value_data_with_header::<SupraDeliveryErasureRs16Schema>(header_001.clone());
    let feedback = FeedbackMessage::err_msg(value_data.get_meta(), *value_data.origin());
    // add 001 to blacklist
    let _ = delivery_resources
        .delivery_manager
        .handle_feedback(feedback);

    let should = delivery_resources
        .delivery_manager
        .should_be_processed(&RBCMessage::Value(value_data));
    assert!(should.is_err())
}

#[tokio::test]
async fn test_should_be_processed_basic() {
    let h = tokio::task::spawn_blocking(|| {
        let peer_000 = PeerGlobalIndex::new(0, 0, 0);
        // Broadcaster
        let peer_001 = PeerGlobalIndex::new(0, 0, 1);
        let mut delivery_resources =
            TestSupraDeliveryResources::<SupraDeliveryRs16Schema>::new_with_broadcaster(
                peer_001, peer_000,
            );

        let res_000 = delivery_resources.delivery_manager.get_resources();
        let res_001 = delivery_resources
            .resource_provider
            .get_resources(PeerGlobalIndex::new(0, 0, 1));
        let header_001 = TestResources::generate_header(res_001.authenticator(), [0; 32]);
        let key = header_001.hash();
        let qc_001 = delivery_resources.resource_provider.generate_qc(
            res_001.topology().current_node().clan_identifier(),
            header_001.commitment(),
        );
        let sync = SyncRequest::new(header_001.clone(), qc_001);
        let value =
            ValueData::<SupraDeliveryErasureRs16Schema>::new(header_001, ChunkData::default());

        res_000.storage_client().write(key, [0; 100].to_vec());

        let should = delivery_resources
            .delivery_manager
            .should_be_processed(&RBCMessage::Value(value))
            .unwrap();
        assert!(!should); // has_data && !is_sync_message

        let should = delivery_resources
            .delivery_manager
            .should_be_processed(&RBCMessage::Sync(sync))
            .unwrap();
        assert!(should); // has_data && is_sync_message

        let header_002 = TestResources::generate_header(res_001.authenticator(), [1; 32]);
        let value =
            ValueData::<SupraDeliveryErasureRs16Schema>::new(header_002, ChunkData::default());
        let should = delivery_resources
            .delivery_manager
            .should_be_processed(&RBCMessage::Value(value))
            .unwrap();
        assert!(should); // !has_data && !is_sync_message && !is_broadcaster && !has_task
    });
    assert!(h.await.is_ok());
}

#[tokio::test]
async fn test_should_be_processed_leader() {
    let h = tokio::task::spawn_blocking(|| {
        let role = Role::Leader;
        let peer_000 = PeerGlobalIndex::new(0, 0, 0);
        let mut delivery_resources =
            TestSupraDeliveryResources::<SupraDeliveryRs16Schema>::new(peer_000, role);

        let res_000 = delivery_resources.delivery_manager.get_resources();
        let header_000 = TestResources::generate_header(res_000.authenticator(), [0; 32]);
        let qc_000 = delivery_resources.resource_provider.generate_qc(
            res_000.topology().current_node().clan_identifier(),
            header_000.commitment(),
        );
        let sync = SyncRequest::new(header_000.clone(), qc_000);

        let should = delivery_resources
            .delivery_manager
            .should_be_processed(&RBCMessage::Sync(sync));
        assert!(should.is_err()); // !has_data && is_sync_message && is_broadcaster_message

        let mut votes = delivery_resources.resource_provider.generate_votes(
            res_000.topology().current_node().clan_identifier(),
            &header_000,
        );
        let vote_msg = RBCMessage::Vote(votes.remove(0));

        let should = delivery_resources
            .delivery_manager
            .should_be_processed(&vote_msg);
        assert!(should.is_err()); // !has_data && !is_sync_message && is_broadcaster_message && !has_task
    });
    assert!(h.await.is_ok());
}
