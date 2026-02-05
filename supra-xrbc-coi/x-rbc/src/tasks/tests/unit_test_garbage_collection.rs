use crate::synchronizer::request::SyncResponse;
use crate::tasks::messages::RBCMessage;
use crate::tasks::tests::{
    consume_random_message, consume_random_payload, sync_list, task_list,
    TestSupraDeliveryResources,
};
use crate::types::context::ResourcesApi;
use crate::types::helpers::verifier_visitor::verify_value_data_tests::TestResources;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::tests::value_data_with_header;
use crate::{FeedbackMessage, InternalSyncRequest, SupraDeliveryRs16Schema};
use network::topology::peer_info::Role;
use primitives::types::header::MessageMeta;
use primitives::types::QuorumCertificate;
use primitives::PeerGlobalIndex;
use std::time::Duration;

fn compair_gc_round(
    delivery_resources: &TestSupraDeliveryResources<SupraDeliveryRs16Schema>,
    meta: &MessageMeta,
    expected: usize,
) -> bool {
    let done_task = delivery_resources
        .delivery_manager
        .tasks()
        .get(meta)
        .unwrap();
    done_task.gc_round() == expected
}

#[tokio::test]
async fn test_garbage_collector_gc_rounds() {
    let h = tokio::task::spawn_blocking(|| {
        let role = Role::Leader;
        let peer_000 = PeerGlobalIndex::new(0, 0, 0);
        let mut delivery_resources =
            TestSupraDeliveryResources::<SupraDeliveryRs16Schema>::new(peer_000, role);

        let peer_010 = PeerGlobalIndex::new(0, 1, 0);
        let res_010 = delivery_resources.resource_provider.get_resources(peer_010);

        consume_random_payload(&mut delivery_resources);
        consume_random_payload(&mut delivery_resources);

        let header_010 = TestResources::generate_header(res_010.authenticator(), [5; 32]);
        let value_data = value_data_with_header(header_010);

        consume_random_message(&mut delivery_resources, RBCMessage::Value(value_data));
        let msg_meta_list = task_list(&delivery_resources);
        assert!(msg_meta_list.len().eq(&3));

        let task_0 = msg_meta_list.get(0).unwrap();
        let task_1 = msg_meta_list.get(1).unwrap();
        let task_2 = msg_meta_list.get(2).unwrap();
        let done_feedback_0 = FeedbackMessage::Done(task_0.clone());
        let done_feedback_1 = FeedbackMessage::Done(task_1.clone());
        let done_feedback_2 = FeedbackMessage::Done(task_2.clone());

        let _ = delivery_resources.delivery_manager.execute_gc();
        let msg_meta_list = task_list(&delivery_resources);
        assert_eq!(msg_meta_list.len(), 3);
        assert!(compair_gc_round(&delivery_resources, &task_0, 0));
        assert!(compair_gc_round(&delivery_resources, &task_1, 0));
        assert!(compair_gc_round(&delivery_resources, &task_2, 0));

        let _ = delivery_resources
            .delivery_manager
            .handle_feedback(done_feedback_0);

        let _ = delivery_resources.delivery_manager.execute_gc();
        let msg_meta_list = task_list(&delivery_resources);
        assert_eq!(msg_meta_list.len(), 3);
        assert!(compair_gc_round(&delivery_resources, &task_0, 1));
        assert!(compair_gc_round(&delivery_resources, &task_1, 0));
        assert!(compair_gc_round(&delivery_resources, &task_2, 0));

        let _ = delivery_resources
            .delivery_manager
            .handle_feedback(done_feedback_1);

        let _ = delivery_resources.delivery_manager.execute_gc();
        let msg_meta_list = task_list(&delivery_resources);
        assert_eq!(msg_meta_list.len(), 3);
        assert!(compair_gc_round(&delivery_resources, &task_0, 2));
        assert!(compair_gc_round(&delivery_resources, &task_1, 1));
        assert!(compair_gc_round(&delivery_resources, &task_2, 0));

        let _ = delivery_resources
            .delivery_manager
            .handle_feedback(done_feedback_2);

        let _ = delivery_resources.delivery_manager.execute_gc();
        let msg_meta_list = task_list(&delivery_resources);
        assert_eq!(msg_meta_list.len(), 2);
        let done_task = delivery_resources.delivery_manager.tasks().get(task_0);
        assert!(done_task.is_none());
        assert!(compair_gc_round(&delivery_resources, &task_1, 2));
        assert!(compair_gc_round(&delivery_resources, &task_2, 1));

        let _ = delivery_resources.delivery_manager.execute_gc();
        let msg_meta_list = task_list(&delivery_resources);
        assert_eq!(msg_meta_list.len(), 1);
        let done_task = delivery_resources.delivery_manager.tasks().get(task_1);
        assert!(done_task.is_none());
        assert!(compair_gc_round(&delivery_resources, &task_2, 2));

        let _ = delivery_resources.delivery_manager.execute_gc();
        let msg_meta_list = task_list(&delivery_resources);
        assert_eq!(msg_meta_list.len(), 0);
        let done_task = delivery_resources.delivery_manager.tasks().get(task_2);
        assert!(done_task.is_none());
    });
    assert!(h.await.is_ok());
}

#[tokio::test]
async fn test_garbage_collector_task_handling() {
    let h = tokio::task::spawn_blocking(|| {
        let role = Role::Leader;
        let peer_000 = PeerGlobalIndex::new(0, 0, 0);
        let mut delivery_resources =
            TestSupraDeliveryResources::<SupraDeliveryRs16Schema>::new(peer_000, role);

        let res_001 = delivery_resources
            .resource_provider
            .get_resources(PeerGlobalIndex::new(0, 0, 1));
        let header_001 = TestResources::generate_header(res_001.authenticator(), [5; 32]);
        let res_010 = delivery_resources
            .resource_provider
            .get_resources(PeerGlobalIndex::new(0, 1, 0));
        let header_010 = TestResources::generate_header(res_010.authenticator(), [5; 32]);

        let (feedback, _) = tokio::sync::oneshot::channel::<SyncResponse>();
        let sync_req = InternalSyncRequest::new(header_010, QuorumCertificate::default(), feedback);
        let _ = delivery_resources
            .delivery_manager
            .handle_sync_request(sync_req);

        let _ = delivery_resources.delivery_manager.execute_gc();
        let sync_keys = sync_list(&delivery_resources);
        assert_eq!(sync_keys.len(), 1);
        let task_keys = task_list(&delivery_resources);
        assert_eq!(task_keys.len(), 1);
        let task = task_keys
            .iter()
            .filter(|meta| meta.origin() == res_010.topology().origin())
            .collect::<Vec<&MessageMeta>>();
        let task = delivery_resources
            .delivery_manager
            .tasks()
            .get(task.first().unwrap())
            .unwrap();
        assert!(task.is_sync());

        let value_data = value_data_with_header(header_001.clone());
        consume_random_message(&mut delivery_resources, RBCMessage::Value(value_data));
        let sync_keys = sync_list(&delivery_resources);
        assert_eq!(sync_keys.len(), 1);
        let task_keys = task_list(&delivery_resources);
        assert_eq!(task_keys.len(), 2);
        let task = task_keys
            .iter()
            .filter(|meta| meta.origin() == res_001.topology().origin())
            .collect::<Vec<&MessageMeta>>();
        let task = delivery_resources
            .delivery_manager
            .tasks()
            .get(task.first().unwrap())
            .unwrap();
        assert!(!task.is_sync());

        std::thread::sleep(Duration::from_secs(11));
        let _ = delivery_resources.delivery_manager.execute_gc();
        let sync_keys = sync_list(&delivery_resources);
        assert_eq!(sync_keys.len(), 1);
        let task_keys = task_list(&delivery_resources);
        assert_eq!(task_keys.len(), 1);

        let task = task_keys
            .iter()
            .filter(|meta| meta.origin() == res_001.topology().origin())
            .collect::<Vec<&MessageMeta>>();
        assert_eq!(task.len(), 0);

        // pull request on non sync task
        let value_data = value_data_with_header(header_001.clone());
        consume_random_message(&mut delivery_resources, RBCMessage::Value(value_data));
        let sync_req = SyncRequest::new(header_001, QuorumCertificate::default());
        let pull_req = PullRequest::new(res_010.authenticator().origin(), sync_req);
        let _ = delivery_resources
            .delivery_manager
            .handle_message(RBCMessage::Pull(pull_req.clone()));
        let _ = delivery_resources.delivery_manager.execute_gc();
        let sync_keys = sync_list(&delivery_resources);
        assert_eq!(sync_keys.len(), 1);
        let task_keys = task_list(&delivery_resources);
        assert_eq!(task_keys.len(), 2);
        let task = task_keys
            .iter()
            .filter(|meta| meta.origin() == res_001.topology().origin())
            .collect::<Vec<&MessageMeta>>();
        let message_meta = task[0];
        let done_feedback = FeedbackMessage::Done(message_meta.clone());
        let task = delivery_resources
            .delivery_manager
            .tasks()
            .get(message_meta)
            .unwrap();
        assert!(!task.is_sync());
        assert!(task.is_inprogress());

        let _ = delivery_resources
            .delivery_manager
            .handle_feedback(done_feedback);
        let task_keys = task_list(&delivery_resources);
        assert_eq!(task_keys.len(), 2); // one sync and one done
        let task = delivery_resources
            .delivery_manager
            .tasks()
            .get(message_meta)
            .unwrap();
        assert!(!task.is_sync());
        assert!(task.is_done());

        let _ = delivery_resources
            .delivery_manager
            .handle_message(RBCMessage::Pull(pull_req.clone()));
        let task_keys = task_list(&delivery_resources);
        assert_eq!(task_keys.len(), 2); // one sync and one done
        let _ = task_keys.iter().map(|meta| {
            let task = delivery_resources
                .delivery_manager
                .tasks()
                .get(meta)
                .unwrap();
            assert!(task.is_sync())
        }); // both task are now sync task
    });
    assert!(h.await.is_ok());
}
