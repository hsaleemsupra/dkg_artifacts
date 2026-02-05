use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::helpers::{Visitor, VisitorAcceptor};
use crate::types::messages::feedback::FeedbackMessage;
use crate::types::messages::ready_data::EchoReadyData;
use crate::types::messages::ready_data::ReadyData;
use crate::types::messages::requests::PullRequest;
use crate::types::messages::value_data::EchoValueData;
use crate::types::messages::{EchoShareData, OutputMessages, ResponseTypeIfc, ShareData};
use primitives::types::header::{Header, HeaderIfc};
use primitives::Addresses;
use std::fmt::{Debug, Display, Formatter};

// Payload Related Messages while sync is in progress
pub(crate) enum RBCSyncMessage<C: SupraDeliveryErasureCodecSchema> {
    EchoValue(EchoValueData<C>),
    Ready(ReadyData<C>),
    EchoReady(EchoReadyData<C>),
    Share(ShareData<C>),
    EchoShare(EchoShareData<C>),
    Pull(PullRequest),
}

impl<C: SupraDeliveryErasureCodecSchema> Display for RBCSyncMessage<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RBCSyncMessage::EchoValue(data) => write!(f, "{}", data),
            RBCSyncMessage::Ready(data) => write!(f, "{}", data),
            RBCSyncMessage::EchoReady(data) => write!(f, "{}", data),
            RBCSyncMessage::Pull(data) => write!(f, "{}", data),
            RBCSyncMessage::Share(data) => write!(f, "{}", data),
            RBCSyncMessage::EchoShare(data) => write!(f, "{}", data),
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> From<PullRequest> for RBCSyncMessage<C> {
    fn from(pull_request: PullRequest) -> Self {
        Self::Pull(pull_request)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Debug for RBCSyncMessage<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> RBCSyncMessage<C> {
    pub(crate) fn data_index(&self) -> Option<usize> {
        match self {
            RBCSyncMessage::EchoValue(data) => Some(data.get_chunk_index()),
            RBCSyncMessage::Ready(data) => Some(data.value().get_chunk_index()),
            RBCSyncMessage::EchoReady(data) => Some(data.value().get_chunk_index()),
            RBCSyncMessage::Pull(_) => None,
            RBCSyncMessage::Share(data) => Some(data.value().get_chunk_index()),
            RBCSyncMessage::EchoShare(data) => Some(data.value().get_chunk_index()),
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> HeaderIfc for RBCSyncMessage<C> {
    fn header(&self) -> &Header {
        match self {
            RBCSyncMessage::EchoValue(data) => data.header(),
            RBCSyncMessage::Ready(data) => data.header(),
            RBCSyncMessage::EchoReady(data) => data.header(),
            RBCSyncMessage::Pull(data) => data.header(),
            RBCSyncMessage::Share(data) => data.header(),
            RBCSyncMessage::EchoShare(data) => data.header(),
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> VisitorAcceptor<C> for RBCSyncMessage<C> {
    fn accept<V>(&self, v: &V) -> V::ReturnType
    where
        V: Visitor<C>,
    {
        v.visit_sync_message(self)
    }
}

///
/// Response messages generated during sync state machine execution
///
#[derive(Debug, Default)]
pub struct SyncFSMResponseMessage<C: SupraDeliveryErasureCodecSchema> {
    /// RBC messages as response to be sent to the other peers in the chain upon input reqeust
    messages: OutputMessages<RBCSyncMessage<C>>,
    /// Feedback message to be sent to RBCTaskManager/SupraDelivery
    feedback: Vec<FeedbackMessage>,
}

impl<C: SupraDeliveryErasureCodecSchema> ResponseTypeIfc for SyncFSMResponseMessage<C> {
    type MessageType = RBCSyncMessage<C>;
    type FeedbackType = FeedbackMessage;
    type AuxMessageType = RBCSyncMessage<C>;

    fn add_message(&mut self, message: (Self::MessageType, Addresses)) {
        self.messages.add(message);
    }

    fn add_aux_message(&mut self, message: (Self::AuxMessageType, Addresses)) {
        self.add_message(message);
    }

    fn add_feedback(&mut self, message: Self::FeedbackType) {
        self.feedback.push(message);
    }

    fn messages(&self) -> &OutputMessages<Self::MessageType> {
        &self.messages
    }

    fn aux_messages(&self) -> &OutputMessages<Self::AuxMessageType> {
        self.messages()
    }

    fn feedback(&self) -> &Vec<FeedbackMessage> {
        &self.feedback
    }

    fn take_messages(&mut self) -> OutputMessages<Self::MessageType> {
        std::mem::take(&mut self.messages)
    }

    fn take_aux_messages(&mut self) -> OutputMessages<Self::AuxMessageType> {
        self.take_messages()
    }

    fn take_feedback(&mut self) -> Vec<FeedbackMessage> {
        std::mem::take(&mut self.feedback)
    }
}
