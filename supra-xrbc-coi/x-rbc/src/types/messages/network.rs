use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::helpers::{Visitor, VisitorAcceptor};
use crate::types::messages::feedback::FeedbackMessage;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::share_data::EchoShareData;
use crate::types::messages::share_data::ShareData;
use crate::types::messages::{OutputMessages, ResponseTypeIfc};
use primitives::types::header::{Header, HeaderIfc};
use primitives::Addresses;
use std::fmt::{Debug, Display, Formatter};

// NonCommittee Payload Related Messages
pub(crate) enum RBCNetworkMessage<C: SupraDeliveryErasureCodecSchema> {
    Share(ShareData<C>),
    EchoShare(EchoShareData<C>),
    Pull(PullRequest),
    Sync(SyncRequest),
}

impl<C: SupraDeliveryErasureCodecSchema> Display for RBCNetworkMessage<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RBCNetworkMessage::Share(data) => write!(f, "{}", data),
            RBCNetworkMessage::EchoShare(data) => write!(f, "{}", data),
            RBCNetworkMessage::Pull(data) => write!(f, "{}", data),
            RBCNetworkMessage::Sync(data) => write!(f, "{}", data),
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> From<PullRequest> for RBCNetworkMessage<C> {
    fn from(pull_request: PullRequest) -> Self {
        Self::Pull(pull_request)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Debug for RBCNetworkMessage<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> RBCNetworkMessage<C> {
    pub(crate) fn data_index(&self) -> Option<usize> {
        match self {
            RBCNetworkMessage::Share(data) => Some(data.value().get_chunk_index()),
            RBCNetworkMessage::EchoShare(data) => Some(data.value().get_chunk_index()),
            RBCNetworkMessage::Pull(_) | RBCNetworkMessage::Sync(_) => None,
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> VisitorAcceptor<C> for RBCNetworkMessage<C> {
    fn accept<V>(&self, v: &V) -> V::ReturnType
    where
        V: Visitor<C>,
    {
        v.visit_network_message(self)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> HeaderIfc for RBCNetworkMessage<C> {
    fn header(&self) -> &Header {
        match self {
            RBCNetworkMessage::Share(data) => data.header(),
            RBCNetworkMessage::EchoShare(data) => data.header(),
            RBCNetworkMessage::Pull(data) => data.header(),
            RBCNetworkMessage::Sync(data) => data.header(),
        }
    }
}

///
/// Response messages generated during network message state machine execution
///
#[derive(Debug, Default)]
pub struct NetworkFSMResponseMessage<C: SupraDeliveryErasureCodecSchema> {
    /// RBC Network messages to be sent to the other peers in the network
    network_messages: OutputMessages<RBCNetworkMessage<C>>,
    /// Feedback message to be sent to RBCTaskManager/SupraDelivery
    feedback: Vec<FeedbackMessage>,
}

impl<C: SupraDeliveryErasureCodecSchema> ResponseTypeIfc for NetworkFSMResponseMessage<C> {
    type MessageType = RBCNetworkMessage<C>;
    type FeedbackType = FeedbackMessage;
    type AuxMessageType = RBCNetworkMessage<C>;

    fn add_message(&mut self, message: (Self::MessageType, Addresses)) {
        self.network_messages.add(message)
    }

    fn add_aux_message(&mut self, message: (Self::AuxMessageType, Addresses)) {
        self.add_message(message)
    }

    fn add_feedback(&mut self, message: Self::FeedbackType) {
        self.feedback.push(message);
    }

    fn messages(&self) -> &OutputMessages<Self::MessageType> {
        &self.network_messages
    }

    fn aux_messages(&self) -> &OutputMessages<Self::AuxMessageType> {
        self.messages()
    }

    fn feedback(&self) -> &Vec<FeedbackMessage> {
        &self.feedback
    }

    fn take_messages(&mut self) -> OutputMessages<Self::MessageType> {
        std::mem::take(&mut self.network_messages)
    }

    fn take_aux_messages(&mut self) -> OutputMessages<Self::AuxMessageType> {
        self.take_messages()
    }

    fn take_feedback(&mut self) -> Vec<FeedbackMessage> {
        std::mem::take(&mut self.feedback)
    }
}
