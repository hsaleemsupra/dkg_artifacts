use crate::tasks::client::RBCTaskState;
use crate::tasks::codec::{EncodeResult, EncodeResultIfc, SupraDeliveryErasureCodecSchema};
use crate::tasks::messages::{DeliveryMessage, RBCMessage};
use crate::tasks::supra_delivery::SupraDeliverySchema;
use crate::tasks::task::Task;
use crate::tasks::tests::TestSupraDeliveryResources;
use crate::types::context::ResourcesApi;
use crate::types::helpers::verifier_visitor::verify_value_data_tests::{
    encoded_chunks, TestResources,
};
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    EchoReadyData, EchoShareData, EchoValueData, ReadyData, ShareData, ValueData,
};
use crate::{FeedbackMessage, SupraDeliveryErasureRs8Schema, SupraDeliveryRs8Schema};
use network::client::Action;
use primitives::serde::bincode_deserialize;
use primitives::types::{Header, HeaderIfc};
use primitives::{PeerGlobalIndex, RxChannel};
use std::thread::sleep;
use std::time::Duration;
use storage::storage_client::StorageClient;
use storage::StorageReadIfc;
use tokio::runtime::Handle;
use tokio::time::timeout;

#[derive(Debug)]
enum MessageType {
    // chunk-index
    EchoValue(usize),
    // sender-index, chunk-index
    Ready(PeerGlobalIndex, usize),
    // sender-index, chunk-index
    EchoReady(PeerGlobalIndex, usize),
    // sender-index, chunk-index
    Share(PeerGlobalIndex, usize),
    // sender-index, chunk-index
    EchoShare(PeerGlobalIndex, usize),
}

impl MessageType {
    fn index(&self) -> usize {
        match self {
            MessageType::EchoValue(idx) => *idx,
            MessageType::Ready(_, idx) => *idx,
            MessageType::EchoReady(_, idx) => *idx,
            MessageType::Share(_, idx) => *idx,
            MessageType::EchoShare(_, idx) => *idx,
        }
    }
}

#[tokio::test]
async fn test_sync_task_for_missing_network_payload() {
    let h = tokio::task::spawn_blocking(|| {
        let broadcaster = PeerGlobalIndex::new(0, 0, 0);
        let peer_index = PeerGlobalIndex::new(0, 1, 1);
        let mut supra_delivery_resources =
            TestSupraDeliveryResources::<SupraDeliveryRs8Schema>::new_with_broadcaster(
                broadcaster,
                peer_index,
            );

        let broadcaster_resource = supra_delivery_resources
            .resource_provider
            .get_resources(broadcaster);
        let current_node_resources = supra_delivery_resources.delivery_manager.get_resources();
        let encoded_data = encoded_chunks(1, &broadcaster_resource.authenticator());
        let qc = supra_delivery_resources.resource_provider.generate_qc(
            broadcaster.clan_identifier(),
            encoded_data.header().commitment(),
        );
        let sync_data = SyncRequest::new(encoded_data.header().clone(), qc);
        let sync_msg = RBCMessage::Sync(sync_data.clone());
        let (mut client, task) = supra_delivery_resources
            .delivery_manager
            .create_rbc_sync_task(&sync_msg)
            .expect("Valid task is created");
        let task_handler = tokio::spawn(task.run());
        receive_output_pull_requests_on(
            &mut supra_delivery_resources.network_rx,
            broadcaster_resource.topology().get_chain_size() - 1,
        );

        // Send owned chunk piece from broadcaster as Share message
        send_network_chunk(
            &mut client,
            &encoded_data,
            MessageType::Share(broadcaster, peer_index.position()),
            &mut supra_delivery_resources,
        );
        no_output_data_is_expected(
            &mut supra_delivery_resources.network_rx,
            supra_delivery_resources.delivery_manager.internal_rx(),
        );
        // Send pull request from clan peer and expect error at output
        let clan_peer = PeerGlobalIndex::new(0, 0, 4);
        send_external_pull_request(
            &mut client,
            &supra_delivery_resources.resource_provider,
            clan_peer,
            &sync_data,
        );

        check_data_feedback(
            supra_delivery_resources.delivery_manager.internal_rx(),
            FeedbackMessage::err_msg(
                encoded_data.header().get_meta(),
                supra_delivery_resources
                    .resource_provider
                    .get_origin(&clan_peer),
            ),
        );

        // Send pull request from network peer and expect no output as no own chunk is available
        let nt_peer = PeerGlobalIndex::new(0, 1, 4);
        send_external_pull_request(
            &mut client,
            &supra_delivery_resources.resource_provider,
            nt_peer,
            &sync_data,
        );
        no_output_data_is_expected(
            &mut supra_delivery_resources.network_rx,
            supra_delivery_resources.delivery_manager.internal_rx(),
        );
        // Send another chunk piece
        let clan_peer = PeerGlobalIndex::new(0, 0, 2);
        send_network_chunk(
            &mut client,
            &encoded_data,
            MessageType::Share(clan_peer, peer_index.position()),
            &mut supra_delivery_resources,
        );
        no_output_data_is_expected(
            &mut supra_delivery_resources.network_rx,
            supra_delivery_resources.delivery_manager.internal_rx(),
        );
        // Test internal state-timeout sends another set of pull requests to clan-peers
        sleep(Duration::from_secs(6));
        // exclude filter [2, 0]
        receive_output_pull_requests_on(
            &mut supra_delivery_resources.network_rx,
            broadcaster_resource.topology().get_chain_size() - 3,
        );

        // Send another chunk, after which it is expected that owned chunk is fully reconstructed
        let clan_peer = PeerGlobalIndex::new(0, 0, 3);
        send_network_chunk(
            &mut client,
            &encoded_data,
            MessageType::Share(clan_peer, peer_index.position()),
            &mut supra_delivery_resources,
        );
        no_output_data_is_expected(
            &mut supra_delivery_resources.network_rx,
            supra_delivery_resources.delivery_manager.internal_rx(),
        );
        check_data_in_storage(
            current_node_resources.storage_client(),
            encoded_data.header(),
            false,
        );
        // Now for network pull requests we will have response
        let nt_peer = PeerGlobalIndex::new(0, 1, 4);
        send_external_pull_request(
            &mut client,
            &mut supra_delivery_resources.resource_provider,
            nt_peer,
            &sync_data,
        );
        // Share data for network pull
        check_output_message(
            &mut supra_delivery_resources.network_rx,
            MessageType::EchoShare(peer_index, peer_index.position()),
        );
        // send rest of the echo shares to reconstruct full data
        send_echo_shares(
            &mut client,
            &encoded_data,
            &mut supra_delivery_resources,
            (2, 8),
        );

        // Check that for unsupported input messages error is reported
        let clan_peer = PeerGlobalIndex::new(0, 0, 4);
        send_committee_chunk(
            &mut client,
            &encoded_data,
            MessageType::Ready(clan_peer, 4),
            &mut supra_delivery_resources.resource_provider,
        );
        check_data_feedback(
            supra_delivery_resources.delivery_manager.internal_rx(),
            FeedbackMessage::err_msg(
                encoded_data.header().get_meta(),
                supra_delivery_resources
                    .resource_provider
                    .get_origin(&clan_peer),
            ),
        );

        // Now for network pull requests we will have response
        let nt_peer = PeerGlobalIndex::new(0, 1, 4);
        send_external_pull_request(
            &mut client,
            &mut supra_delivery_resources.resource_provider,
            nt_peer,
            &sync_data,
        );
        // Share data for network pull
        check_output_message(
            &mut supra_delivery_resources.network_rx,
            MessageType::EchoShare(peer_index, peer_index.position()),
        );
        // Check that after internal state-timeout in Ready state task transitions to done state and
        // finishes the task successfully
        sleep(Duration::from_secs(6));
        Handle::current().block_on(async {
            let result = timeout(Duration::from_secs(1), task_handler).await;
            assert!(result.is_ok());
        });
        check_data_feedback(
            supra_delivery_resources.delivery_manager.internal_rx(),
            FeedbackMessage::done_msg(encoded_data.header().get_meta()),
        );
    });
    assert!(h.await.is_ok());
}

#[tokio::test]
async fn test_sync_task_for_missing_committee_payload() {
    let h = tokio::task::spawn_blocking(|| {
        let broadcaster = PeerGlobalIndex::new(0, 0, 0);
        let peer_index = PeerGlobalIndex::new(0, 0, 1);
        let mut supra_delivery_resources =
            TestSupraDeliveryResources::<SupraDeliveryRs8Schema>::new_with_broadcaster(
                broadcaster,
                peer_index,
            );

        let broadcaster_resource = supra_delivery_resources
            .resource_provider
            .get_resources(broadcaster);
        let current_node_resources = supra_delivery_resources.delivery_manager.get_resources();
        let encoded_data = encoded_chunks(1, &broadcaster_resource.authenticator());
        let qc = supra_delivery_resources.resource_provider.generate_qc(
            broadcaster.clan_identifier(),
            encoded_data.header().commitment(),
        );
        let sync_data = SyncRequest::new(encoded_data.header().clone(), qc);
        let sync_msg = RBCMessage::Sync(sync_data.clone());
        let (mut client, task) = supra_delivery_resources
            .delivery_manager
            .create_rbc_sync_task(&sync_msg)
            .expect("Valid task is created");
        let task_handler = tokio::spawn(task.run());
        receive_output_pull_requests_on(
            &mut supra_delivery_resources.network_rx,
            broadcaster_resource.topology().get_committee_size() - 1,
        );

        // Send owned chunk from broadcaster as Ready message
        send_committee_chunk(
            &mut client,
            &encoded_data,
            MessageType::Ready(broadcaster, peer_index.position()),
            &supra_delivery_resources.resource_provider,
        );
        no_output_data_is_expected(
            &mut supra_delivery_resources.network_rx,
            supra_delivery_resources.delivery_manager.internal_rx(),
        );
        // Send pull request from clan peer and expect unicast of EchoValue output
        let clan_peer = PeerGlobalIndex::new(0, 0, 4);
        send_external_pull_request(
            &mut client,
            &supra_delivery_resources.resource_provider,
            clan_peer,
            &sync_data,
        );

        check_output_message(
            &mut supra_delivery_resources.network_rx,
            MessageType::EchoValue(peer_index.position()),
        );

        // Send pull request from network peer and expect no output
        let nt_peer = PeerGlobalIndex::new(0, 1, 4);
        send_external_pull_request(
            &mut client,
            &supra_delivery_resources.resource_provider,
            nt_peer,
            &sync_data,
        );
        no_output_data_is_expected(
            &mut supra_delivery_resources.network_rx,
            supra_delivery_resources.delivery_manager.internal_rx(),
        );
        // Send another chunk
        let clan_peer = PeerGlobalIndex::new(0, 0, 2);
        send_committee_chunk(
            &mut client,
            &encoded_data,
            MessageType::EchoReady(clan_peer, clan_peer.position()),
            &supra_delivery_resources.resource_provider,
        );
        no_output_data_is_expected(
            &mut supra_delivery_resources.network_rx,
            supra_delivery_resources.delivery_manager.internal_rx(),
        );
        // Test internal state-timeout sends another set of pull requests to clan-peers
        sleep(Duration::from_secs(6));
        // exclude filter [1, 2]

        receive_output_pull_requests_on(
            &mut supra_delivery_resources.network_rx,
            broadcaster_resource.topology().get_committee_size() - 2,
        );

        check_data_in_storage(
            current_node_resources.storage_client(),
            encoded_data.header(),
            false,
        );
        // Send another chunk, after which it is expected that payload is fully reconstructed and stored in storage
        let clan_peer = PeerGlobalIndex::new(0, 0, 3);
        send_committee_chunk(
            &mut client,
            &encoded_data,
            MessageType::EchoValue(clan_peer.position()),
            &supra_delivery_resources.resource_provider,
        );
        no_output_data_is_expected(
            &mut supra_delivery_resources.network_rx,
            supra_delivery_resources.delivery_manager.internal_rx(),
        );
        check_data_in_storage(
            current_node_resources.storage_client(),
            encoded_data.header(),
            true,
        );
        // Now for all pull requests we will have responses
        let nt_peer = PeerGlobalIndex::new(0, 1, 4);
        send_external_pull_request(
            &mut client,
            &mut supra_delivery_resources.resource_provider,
            nt_peer,
            &sync_data,
        );
        // Share data for network pull
        check_output_message(
            &mut supra_delivery_resources.network_rx,
            MessageType::Share(peer_index, peer_index.position()),
        );

        // EchoReady(current node chunk) and Ready(requester chunk) for clan peer pull request
        let clan_peer = PeerGlobalIndex::new(0, 0, 4);
        send_external_pull_request(
            &mut client,
            &mut supra_delivery_resources.resource_provider,
            clan_peer,
            &sync_data,
        );
        check_output_message(
            &mut supra_delivery_resources.network_rx,
            MessageType::EchoReady(peer_index, peer_index.position()),
        );
        check_output_message(
            &mut supra_delivery_resources.network_rx,
            MessageType::Ready(peer_index, clan_peer.position()),
        );
        // Check that for unsupported input messages error is reported
        let nt_peer = PeerGlobalIndex::new(0, 1, 4);
        send_network_chunk(
            &mut client,
            &encoded_data,
            MessageType::Share(nt_peer, 0),
            &mut supra_delivery_resources,
        );
        check_data_feedback(
            supra_delivery_resources.delivery_manager.internal_rx(),
            FeedbackMessage::err_msg(
                encoded_data.header().get_meta(),
                supra_delivery_resources
                    .resource_provider
                    .get_origin(&nt_peer),
            ),
        );

        // Check that after internal state-timeout in Ready state task transitions to done state and
        // finishes the task successfully
        sleep(Duration::from_secs(6));
        Handle::current().block_on(async move {
            let result = timeout(Duration::from_secs(1), task_handler).await;
            assert!(result.is_ok());
        });
        check_data_feedback(
            supra_delivery_resources.delivery_manager.internal_rx(),
            FeedbackMessage::done_msg(encoded_data.header().get_meta()),
        );
    });
    assert!(h.await.is_ok());
}

fn receive_output_pull_requests_on(network_rx: &mut RxChannel<Action>, target_size: usize) {
    Handle::current().block_on(async {
        let output_data = timeout(Duration::from_secs(1), network_rx.recv())
            .await
            .expect("output of pull request to all peers in clan")
            .expect("Valid action as output");
        match output_data {
            Action::Broadcast(addresses, message) => {
                let pull_request =
                    bincode_deserialize::<RBCMessage<SupraDeliveryErasureRs8Schema>>(&message)
                        .expect("Valid rbc message");
                assert!(matches!(pull_request, RBCMessage::Pull(_)));
                assert_eq!(addresses.len(), target_size);
            }
            _ => {
                assert!(false, "Expected broadcast message got: {:?}", output_data);
            }
        }
    });
}

fn no_output_data_is_expected<C: SupraDeliveryErasureCodecSchema>(
    network_rx: &mut RxChannel<Action>,
    feedback_channel: &mut RxChannel<DeliveryMessage<C>>,
) {
    Handle::current().block_on(async {
        let output_data = timeout(Duration::from_secs(2), network_rx.recv()).await;
        assert!(output_data.is_err(), "{:?}", output_data);
        let feedback_data = timeout(Duration::from_secs(2), feedback_channel.recv()).await;
        assert!(feedback_data.is_err(), "{:?}", feedback_data);
    });
}

fn send_committee_chunk<C: SupraDeliveryErasureCodecSchema>(
    client: &mut RBCTaskState<C>,
    encoded_data: &EncodeResult<C>,
    message_type: MessageType,
    resource_provider: &TestResources,
) {
    let chunk_data = encoded_data
        .committee_chunks()
        .get(message_type.index())
        .unwrap()
        .clone();
    let value_data = ValueData::new(encoded_data.header().clone(), chunk_data);
    let message = match message_type {
        MessageType::EchoValue(_) => RBCMessage::EchoValue(EchoValueData::new(value_data)),
        MessageType::Ready(sender_index, _) => {
            let origin = resource_provider.get_origin(&sender_index);
            RBCMessage::Ready(ReadyData::new(origin, value_data))
        }
        MessageType::EchoReady(sender_index, _) => {
            let origin = resource_provider.get_origin(&sender_index);
            RBCMessage::EchoReady(EchoReadyData::new(ReadyData::new(origin, value_data)))
        }
        _ => {
            assert!(
                false,
                "Invalid message type for committee message: {:?}",
                message_type
            );
            return;
        }
    };
    let result = client.send(message);
    assert!(result.is_ok());
}

fn send_external_pull_request<C: SupraDeliveryErasureCodecSchema>(
    client: &mut RBCTaskState<C>,
    resource_provider: &TestResources,
    sender_index: PeerGlobalIndex,
    sync_request: &SyncRequest,
) {
    let pull_request = PullRequest::new(
        resource_provider.get_origin(&sender_index),
        sync_request.clone(),
    );
    let result = client.send(RBCMessage::Pull(pull_request));
    assert!(result.is_ok());
}

fn check_output_message(network_rx: &mut RxChannel<Action>, message_type: MessageType) {
    Handle::current().block_on(async move {
        let output_data = timeout(Duration::from_secs(2), network_rx.recv())
            .await
            .expect("output of pull request to all peers in clan")
            .expect("Valid action as output");
        match output_data {
            Action::Unicast(_addresses, message) => {
                let message =
                    bincode_deserialize::<RBCMessage<SupraDeliveryErasureRs8Schema>>(&message)
                        .expect("Valid rbc message");
                match message_type {
                    MessageType::EchoValue(_) => {
                        assert!(matches!(message, RBCMessage::EchoValue(_)))
                    }
                    MessageType::Ready(_, _) => {
                        assert!(matches!(message, RBCMessage::Ready(_)))
                    }
                    MessageType::EchoReady(_, _) => {
                        assert!(matches!(message, RBCMessage::EchoReady(_)), "{:?}", message)
                    }
                    MessageType::Share(_, _) => {
                        assert!(matches!(message, RBCMessage::Share(_)))
                    }
                    MessageType::EchoShare(_, _) => {
                        assert!(matches!(message, RBCMessage::EchoShare(_)))
                    }
                }
            }
            _ => {
                assert!(false, "Expected unicast message got: {:?}", output_data);
            }
        }
    });
}

fn check_data_in_storage(storage_client: &StorageClient, header: &Header, exists: bool) {
    Handle::current().block_on(async move {
        let result = timeout(
            Duration::from_secs(1),
            storage_client.has_key(header.hash()),
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), exists)
    });
}

fn check_data_feedback<C: SupraDeliveryErasureCodecSchema>(
    feedback_channel: &mut RxChannel<DeliveryMessage<C>>,
    expected_feedback: FeedbackMessage,
) {
    Handle::current().block_on(async {
        let feedback_data = timeout(Duration::from_secs(2), feedback_channel.recv())
            .await
            .expect("Expected feedback")
            .expect("Valid data is expected");
        match feedback_data {
            DeliveryMessage::InternalFeedback(f) => {
                assert_eq!(expected_feedback, f);
            }
            _ => {
                assert!(false, "Expected feedback got : {}", feedback_data)
            }
        }
    });
}

fn send_network_chunk<Schema: SupraDeliverySchema>(
    client: &mut RBCTaskState<Schema::CodecSchema>,
    encoded_data: &EncodeResult<Schema::CodecSchema>,
    message_type: MessageType,
    test_resources: &mut TestSupraDeliveryResources<Schema>,
) {
    let resource_provider = &mut test_resources.resource_provider;
    let nt_chunk = encoded_data
        .network_chunks()
        .get(message_type.index())
        .unwrap()
        .clone();
    let message = match message_type {
        MessageType::Share(sender_index, _) => {
            let origin = resource_provider.get_origin(&sender_index);
            let value_data = ValueData::new(
                encoded_data.header().clone(),
                nt_chunk.pieces()[sender_index.position()].clone(),
            );
            let share_data = ShareData::new(origin, value_data, nt_chunk.get_meta());
            RBCMessage::Share(share_data)
        }
        MessageType::EchoShare(sender_index, _) => {
            let origin = resource_provider.get_origin(&sender_index);
            let chunk = nt_chunk
                .decode(test_resources.delivery_manager.get_codec())
                .unwrap();
            let value_data = ValueData::new(encoded_data.header().clone(), chunk);
            let echo_share_data = EchoShareData::new(origin, value_data);
            RBCMessage::EchoShare(echo_share_data)
        }
        _ => {
            assert!(false, "Invalid message type for the network chunk");
            return;
        }
    };
    let result = client.send(message);
    assert!(result.is_ok());
}

fn send_echo_shares<Schema: SupraDeliverySchema>(
    client: &mut RBCTaskState<Schema::CodecSchema>,
    encoded_data: &EncodeResult<Schema::CodecSchema>,
    supra_delivery_resources: &mut TestSupraDeliveryResources<Schema>,
    range: (usize, usize),
) {
    let broadcaster_resources = supra_delivery_resources
        .resource_provider
        .get_broadcaster_resources();
    let current_node_resources = supra_delivery_resources.delivery_manager.get_resources();
    let clan_size = current_node_resources.topology().get_committee_size();

    for index in range.0..(range.1 - 1) {
        let peer_info = broadcaster_resources
            .topology()
            .get_info_relative_to_current_node(index + clan_size)
            .unwrap();
        send_network_chunk(
            client,
            &encoded_data,
            MessageType::EchoShare(peer_info.global_index(), index),
            supra_delivery_resources,
        );
        no_output_data_is_expected(
            &mut supra_delivery_resources.network_rx,
            supra_delivery_resources.delivery_manager.internal_rx(),
        );
        check_data_in_storage(
            current_node_resources.storage_client(),
            encoded_data.header(),
            false,
        );
    }
    let peer_info = broadcaster_resources
        .topology()
        .get_info_relative_to_current_node(range.1 + clan_size)
        .unwrap();
    send_network_chunk(
        client,
        &encoded_data,
        MessageType::EchoShare(peer_info.global_index(), range.1),
        supra_delivery_resources,
    );
    no_output_data_is_expected(
        &mut supra_delivery_resources.network_rx,
        supra_delivery_resources.delivery_manager.internal_rx(),
    );
    Handle::current().block_on(async move {
        let result = timeout(
            Duration::from_secs(1),
            current_node_resources
                .storage_client()
                .subscribe(encoded_data.header().hash()),
        )
        .await;
        assert!(result.is_ok());
    });
}
