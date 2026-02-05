use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::messages::RBCMessage;
use crate::types::messages::{
    CommitteeFSMResponseMessage, FeedbackMessage, NetworkFSMResponseMessage, OutputMessages,
    ResponseTypeIfc, SyncFSMResponseMessage,
};
use crate::SupraDeliveryClient;
use async_trait::async_trait;
use log::error;
use network::client::{NetworkServiceIFC, NetworkServiceSchema};
use primitives::{Subscriber, TxChannel};
use std::marker::PhantomData;

///
/// Generic interface to consume responses
///
#[async_trait]
pub(crate) trait ResponseConsumerTrait<ResponseType> {
    async fn consume(&self, response: ResponseType);
}

///
/// Struct defining schema for the network service interface which will be used to disseminate RBC
/// data to other nodes in network
///
#[derive(Clone)]
pub struct RBCNetworkServiceSchema<C: SupraDeliveryErasureCodecSchema> {
    _phantom_: PhantomData<C>,
}

impl<C: SupraDeliveryErasureCodecSchema> NetworkServiceSchema for RBCNetworkServiceSchema<C> {
    type TargetType = RBCMessage<C>;
}

///
/// Response consumer implementations for RBC messages used in scope of RBC Tasks to consume any
/// produced message by state machine execution
///
/// NtServiceSchema: defines network schema in terms of type of the data to be transmitted via network
/// ResponseType: generic argument is define RBC Task response which will be consumed
///
pub struct ResponseConsumer<C: SupraDeliveryErasureCodecSchema, ResponseType> {
    network_service: NetworkServiceIFC<RBCNetworkServiceSchema<C>>,
    feedback: SupraDeliveryClient<C>,
    _state: PhantomData<ResponseType>,
}

impl<C: SupraDeliveryErasureCodecSchema, ResponseType> ResponseConsumer<C, ResponseType> {
    pub(crate) fn new(
        network_service: NetworkServiceIFC<RBCNetworkServiceSchema<C>>,
        feedback: SupraDeliveryClient<C>,
    ) -> Self {
        Self {
            network_service,
            feedback,
            _state: Default::default(),
        }
    }
}

///
/// Response consumer custom implementation for Committee FSM response
///
#[async_trait]
impl<C: SupraDeliveryErasureCodecSchema> ResponseConsumerTrait<CommitteeFSMResponseMessage<C>>
    for ResponseConsumer<C, CommitteeFSMResponseMessage<C>>
{
    async fn consume(&self, mut response: CommitteeFSMResponseMessage<C>) {
        response.take_feedback().into_iter().for_each(|feedback| {
            let _ = self
                .feedback
                .send(feedback)
                .map_err(|e| error!("Failed to send feedback massage: {:?}", e));
        });
        consume_messages(response.take_messages(), &self.network_service).await;
        consume_messages(response.take_aux_messages(), &self.network_service).await;
    }
}

///
/// Response consumer custom implementation for Network Message FSM response
///
#[async_trait]
impl<C: SupraDeliveryErasureCodecSchema> ResponseConsumerTrait<NetworkFSMResponseMessage<C>>
    for ResponseConsumer<C, NetworkFSMResponseMessage<C>>
{
    async fn consume(&self, mut response: NetworkFSMResponseMessage<C>) {
        response.take_feedback().into_iter().for_each(|feedback| {
            let _ = self
                .feedback
                .send(feedback)
                .map_err(|e| error!("Failed to send feedback massage: {:?}", e));
        });
        consume_messages(response.take_messages(), &self.network_service).await;
    }
}

///
/// Response consumer custom implementation for Sync FSM response
///
#[async_trait]
impl<C: SupraDeliveryErasureCodecSchema> ResponseConsumerTrait<SyncFSMResponseMessage<C>>
    for ResponseConsumer<C, SyncFSMResponseMessage<C>>
{
    async fn consume(&self, mut response: SyncFSMResponseMessage<C>) {
        response.take_feedback().into_iter().for_each(|feedback| {
            let _ = self
                .feedback
                .send(feedback)
                .map_err(|e| error!("Failed to send feedback massage: {:?}", e));
        });
        consume_messages(response.take_messages(), &self.network_service).await;
    }
}

async fn consume_messages<T, Schema: NetworkServiceSchema>(
    mut messages: OutputMessages<T>,
    consumer: &NetworkServiceIFC<Schema>,
) where
    T: Into<Schema::TargetType>,
{
    for (data, addresses) in messages.take() {
        let result = if addresses.len() == 1 {
            consumer.send(addresses[0], data).await
        } else {
            consumer.broadcast(addresses, data).await
        };
        let _ = result.map_err(|e| error!("Failed to send data via Network IFC: {:?}", e));
    }
}
