use crate::tasks::consumer::{ResponseConsumer, ResponseConsumerTrait};
use crate::tasks::messages::DeliveryMessage;
use crate::types::messages::{
    CommitteeFSMResponseMessage, EchoShareData, EchoValueData, NetworkFSMResponseMessage,
    RBCCommitteeMessage, RBCNetworkMessage, RBCSyncMessage, ResponseTypeIfc, ShareData,
    SyncFSMResponseMessage,
};
use crate::types::tests::{header_with_origin, value_data_with_header};
use crate::{
    FeedbackMessage, RBCNetworkServiceSchema, SupraDeliveryClient, SupraDeliveryErasureRs8Schema,
};
use network::client::{Action, NetworkServiceIFC};
use primitives::types::header::MessageMeta;
use tokio::sync::mpsc::unbounded_channel;
use vec_commitment::committed_chunk::CommitmentMeta;

#[tokio::test]
async fn test_committee_consumer() {
    let (feedback_tx, mut feedback_rx) =
        unbounded_channel::<DeliveryMessage<SupraDeliveryErasureRs8Schema>>();
    let feedback_subscriber = SupraDeliveryClient { tx: feedback_tx };
    let (nt_tx, mut nt_rx) = unbounded_channel::<Action>();
    let nt_service =
        NetworkServiceIFC::<RBCNetworkServiceSchema<SupraDeliveryErasureRs8Schema>>::new(nt_tx);
    let consumer = ResponseConsumer::<
        SupraDeliveryErasureRs8Schema,
        CommitteeFSMResponseMessage<SupraDeliveryErasureRs8Schema>,
    >::new(nt_service, feedback_subscriber);

    let response = CommitteeFSMResponseMessage::<SupraDeliveryErasureRs8Schema>::default();
    consumer.consume(response).await;

    assert!(nt_rx.try_recv().is_err());
    assert!(feedback_rx.try_recv().is_err());

    let mut response = CommitteeFSMResponseMessage::<SupraDeliveryErasureRs8Schema>::default();
    response.add_feedback(FeedbackMessage::InternalError(
        MessageMeta::default(),
        "test error".to_string(),
    ));
    let value_data = value_data_with_header(header_with_origin([3; 32]));
    let echo_value = EchoValueData::new(value_data);
    response.add_message((
        RBCCommitteeMessage::<SupraDeliveryErasureRs8Schema>::EchoValue(echo_value),
        vec![
            "192.168.1.1:3030".parse().unwrap(),
            "192.168.1.2:3030".parse().unwrap(),
        ],
    ));
    let value_data = value_data_with_header(header_with_origin([1; 32]));
    let share_data = ShareData::new([2; 32], value_data, CommitmentMeta::default());
    response.add_aux_message((
        RBCNetworkMessage::<SupraDeliveryErasureRs8Schema>::Share(share_data),
        vec!["192.168.1.1:3030".parse().unwrap()],
    ));

    consumer.consume(response).await;
    assert!(feedback_rx.try_recv().is_ok());
    let action_broadcast = nt_rx.try_recv().expect("Valid action");
    assert!(matches!(action_broadcast, Action::Broadcast(_, _)));
    let action_send = nt_rx.try_recv().expect("Valid action");
    assert!(matches!(action_send, Action::Unicast(_, _)));
    assert!(nt_rx.try_recv().is_err());
}

#[tokio::test]
async fn test_network_response_consumer() {
    let (feedback_tx, mut feedback_rx) =
        unbounded_channel::<DeliveryMessage<SupraDeliveryErasureRs8Schema>>();
    let feedback_subscriber = SupraDeliveryClient { tx: feedback_tx };
    let (nt_tx, mut nt_rx) = unbounded_channel::<Action>();
    let nt_service =
        NetworkServiceIFC::<RBCNetworkServiceSchema<SupraDeliveryErasureRs8Schema>>::new(nt_tx);
    let consumer = ResponseConsumer::<
        SupraDeliveryErasureRs8Schema,
        NetworkFSMResponseMessage<SupraDeliveryErasureRs8Schema>,
    >::new(nt_service, feedback_subscriber);

    let response = NetworkFSMResponseMessage::<SupraDeliveryErasureRs8Schema>::default();
    consumer.consume(response).await;

    assert!(nt_rx.try_recv().is_err());
    assert!(feedback_rx.try_recv().is_err());

    let mut response = NetworkFSMResponseMessage::<SupraDeliveryErasureRs8Schema>::default();
    response.add_feedback(FeedbackMessage::InternalError(
        MessageMeta::default(),
        "test error".to_string(),
    ));
    let value_data = value_data_with_header(header_with_origin([3; 32]));
    let echo_value = EchoShareData::new([8; 32], value_data);
    response.add_message((
        RBCNetworkMessage::<SupraDeliveryErasureRs8Schema>::EchoShare(echo_value),
        vec![
            "192.168.1.1:3030".parse().unwrap(),
            "192.168.1.2:3030".parse().unwrap(),
        ],
    ));
    consumer.consume(response).await;
    assert!(feedback_rx.try_recv().is_ok());
    let action_broadcast = nt_rx.try_recv().expect("Valid action");
    assert!(matches!(action_broadcast, Action::Broadcast(_, _)));
    assert!(nt_rx.try_recv().is_err());
}

#[tokio::test]
async fn test_sync_response_consumer() {
    let (feedback_tx, mut feedback_rx) =
        unbounded_channel::<DeliveryMessage<SupraDeliveryErasureRs8Schema>>();
    let feedback_subscriber = SupraDeliveryClient { tx: feedback_tx };
    let (nt_tx, mut nt_rx) = unbounded_channel::<Action>();
    let nt_service =
        NetworkServiceIFC::<RBCNetworkServiceSchema<SupraDeliveryErasureRs8Schema>>::new(nt_tx);
    let consumer = ResponseConsumer::<
        SupraDeliveryErasureRs8Schema,
        SyncFSMResponseMessage<SupraDeliveryErasureRs8Schema>,
    >::new(nt_service, feedback_subscriber);

    let response = SyncFSMResponseMessage::<SupraDeliveryErasureRs8Schema>::default();
    consumer.consume(response).await;

    assert!(nt_rx.try_recv().is_err());
    assert!(feedback_rx.try_recv().is_err());

    let mut response = SyncFSMResponseMessage::<SupraDeliveryErasureRs8Schema>::default();
    response.add_feedback(FeedbackMessage::InternalError(
        MessageMeta::default(),
        "test error".to_string(),
    ));
    let value_data = value_data_with_header(header_with_origin([3; 32]));
    let echo_value = EchoValueData::new(value_data);
    response.add_message((
        RBCSyncMessage::<SupraDeliveryErasureRs8Schema>::EchoValue(echo_value),
        vec![
            "192.168.1.1:3030".parse().unwrap(),
            "192.168.1.2:3030".parse().unwrap(),
        ],
    ));
    consumer.consume(response).await;
    assert!(feedback_rx.try_recv().is_ok());
    let action_broadcast = nt_rx.try_recv().expect("Valid action");
    assert!(matches!(action_broadcast, Action::Broadcast(_, _)));
    assert!(nt_rx.try_recv().is_err());
}
