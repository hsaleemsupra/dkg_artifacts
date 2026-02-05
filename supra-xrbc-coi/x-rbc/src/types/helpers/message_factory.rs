use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::context::{FSMContextOwner, ResourcesApi};
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::{
    EchoReadyData, EchoShareData, EchoValueData, ReadyData, ShareData, ValueData,
};
use crypto::Authenticator;
use vec_commitment::committed_chunk::CommitmentMeta;

pub(crate) trait MessageFactoryTrait: FSMContextOwner {
    fn message_factory(&self) -> MessageFactory;
}

impl<T: FSMContextOwner + ?Sized> MessageFactoryTrait for T {
    fn message_factory(&self) -> MessageFactory {
        MessageFactory::new(self.authenticator())
    }
}

pub trait MessageFrom<T, R>: Sized {
    fn message_from(&self, from: T) -> R;
}

pub struct MessageFactory<'a>(pub &'a Authenticator);

impl<'a> MessageFactory<'a> {
    pub(crate) fn new(authenticator: &'a Authenticator) -> Self {
        Self(authenticator)
    }
}

impl<'a, C: SupraDeliveryErasureCodecSchema> MessageFrom<ValueData<C>, EchoValueData<C>>
    for MessageFactory<'a>
{
    fn message_from(&self, from: ValueData<C>) -> EchoValueData<C> {
        EchoValueData::new(from)
    }
}

impl<'a, C: SupraDeliveryErasureCodecSchema> MessageFrom<ValueData<C>, ReadyData<C>>
    for MessageFactory<'a>
{
    fn message_from(&self, from: ValueData<C>) -> ReadyData<C> {
        ReadyData::new(self.0.origin(), from)
    }
}

impl<'a, C: SupraDeliveryErasureCodecSchema>
    MessageFrom<(ValueData<C>, CommitmentMeta), ShareData<C>> for MessageFactory<'a>
{
    fn message_from(&self, from: (ValueData<C>, CommitmentMeta)) -> ShareData<C> {
        let (piece_value, meta) = from;
        ShareData::new(self.0.origin(), piece_value, meta)
    }
}
impl<'a, C: SupraDeliveryErasureCodecSchema> MessageFrom<ReadyData<C>, EchoReadyData<C>>
    for MessageFactory<'a>
{
    fn message_from(&self, from: ReadyData<C>) -> EchoReadyData<C> {
        EchoReadyData::new(from)
    }
}

impl<'a, C: SupraDeliveryErasureCodecSchema> MessageFrom<ValueData<C>, EchoShareData<C>>
    for MessageFactory<'a>
{
    fn message_from(&self, from: ValueData<C>) -> EchoShareData<C> {
        EchoShareData::new(self.0.origin(), from)
    }
}

impl<'a> MessageFrom<SyncRequest, PullRequest> for MessageFactory<'a> {
    fn message_from(&self, from: SyncRequest) -> PullRequest {
        PullRequest::new(self.0.origin(), from)
    }
}
