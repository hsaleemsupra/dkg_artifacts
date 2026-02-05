use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::helpers::{Visitor, VisitorAcceptor};
use crate::types::messages::certificate_data::QuorumCertificateData;
use crate::types::messages::feedback::FeedbackMessage;
use crate::types::messages::network::RBCNetworkMessage;
use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::ready_data::EchoReadyData;
use crate::types::messages::ready_data::ReadyData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::value_data::EchoValueData;
use crate::types::messages::value_data::ValueData;
use crate::types::messages::vote_data::VoteData;
use crate::types::messages::{OutputMessages, ResponseTypeIfc};
use primitives::types::header::{Header, HeaderIfc};
use primitives::Addresses;
use std::fmt::{Debug, Display, Formatter};

// Committee Payload Related Messages
pub(crate) enum RBCCommitteeMessage<C: SupraDeliveryErasureCodecSchema> {
    Value(ValueData<C>),
    EchoValue(EchoValueData<C>),
    Vote(VoteData),
    Certificate(QuorumCertificateData),
    Ready(ReadyData<C>),
    EchoReady(EchoReadyData<C>),
    Pull(PullRequest),
    Sync(SyncRequest),
    Composite(Vec<RBCCommitteeMessage<C>>),
    Payload(PayloadData),
}

impl<C: SupraDeliveryErasureCodecSchema> Display for RBCCommitteeMessage<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RBCCommitteeMessage::Value(data) => write!(f, "{}", data),
            RBCCommitteeMessage::EchoValue(data) => write!(f, "{}", data),
            RBCCommitteeMessage::Vote(data) => write!(f, "{}", data),
            RBCCommitteeMessage::Certificate(data) => write!(f, "{}", data),
            RBCCommitteeMessage::Ready(data) => write!(f, "{}", data),
            RBCCommitteeMessage::EchoReady(data) => write!(f, "{}", data),
            RBCCommitteeMessage::Composite(data) => {
                data.iter()
                    .for_each(|m| write!(f, "Composite {}", m).unwrap());
                write!(f, "Total {}", data.len())
            }
            RBCCommitteeMessage::Sync(data) => write!(f, "{}", data),
            RBCCommitteeMessage::Pull(data) => write!(f, "{}", data),
            RBCCommitteeMessage::Payload(data) => write!(f, "{}", data),
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Debug for RBCCommitteeMessage<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> RBCCommitteeMessage<C> {
    pub(crate) fn data_index(&self) -> Option<usize> {
        match self {
            RBCCommitteeMessage::Value(data) => Some(data.get_chunk_index()),
            RBCCommitteeMessage::EchoValue(data) => Some(data.get_chunk_index()),
            RBCCommitteeMessage::Vote(data) => Some(data.index() as usize),
            RBCCommitteeMessage::Certificate(_) => None,
            RBCCommitteeMessage::Ready(data) => Some(data.value().get_chunk_index()),
            RBCCommitteeMessage::EchoReady(data) => Some(data.value().get_chunk_index()),
            RBCCommitteeMessage::Composite(data) => data.get(0).and_then(|item| item.data_index()),
            RBCCommitteeMessage::Pull(_) | RBCCommitteeMessage::Sync(_) => None,
            RBCCommitteeMessage::Payload(data) => None,
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> HeaderIfc for RBCCommitteeMessage<C> {
    fn header(&self) -> &Header {
        match self {
            RBCCommitteeMessage::Value(data) => data.header(),
            RBCCommitteeMessage::EchoValue(data) => data.header(),
            RBCCommitteeMessage::Vote(data) => data.header(),
            RBCCommitteeMessage::Certificate(data) => data.header(),
            RBCCommitteeMessage::Ready(data) => data.header(),
            RBCCommitteeMessage::EchoReady(data) => data.header(),
            RBCCommitteeMessage::Composite(data) => data[0].header(),
            RBCCommitteeMessage::Pull(data) => data.header(),
            RBCCommitteeMessage::Sync(data) => data.header(),
            RBCCommitteeMessage::Payload(data) => data.header(),
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> From<VoteData> for RBCCommitteeMessage<C> {
    fn from(vote: VoteData) -> Self {
        Self::Vote(vote)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> From<PullRequest> for RBCCommitteeMessage<C> {
    fn from(pull_request: PullRequest) -> Self {
        Self::Pull(pull_request)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> VisitorAcceptor<C> for RBCCommitteeMessage<C> {
    fn accept<V>(&self, v: &V) -> V::ReturnType
    where
        V: Visitor<C>,
    {
        v.visit_committee_message(self)
    }
}

///
/// Response messages generated during committee state machine execution
///
#[derive(Debug, Default)]
pub struct CommitteeFSMResponseMessage<C: SupraDeliveryErasureCodecSchema> {
    /// RBC committee messages to be sent to the other peers in the current committee
    committee_messages: OutputMessages<RBCCommitteeMessage<C>>,
    /// RBC Network messages to be sent to the other peers in the network
    network_messages: OutputMessages<RBCNetworkMessage<C>>,
    /// Feedback message to be sent to RBCTaskManager/SupraDelivery
    feedback: Vec<FeedbackMessage>,
}

impl<C: SupraDeliveryErasureCodecSchema> ResponseTypeIfc for CommitteeFSMResponseMessage<C> {
    type MessageType = RBCCommitteeMessage<C>;
    type FeedbackType = FeedbackMessage;
    type AuxMessageType = RBCNetworkMessage<C>;

    fn add_message(&mut self, message: (Self::MessageType, Addresses)) {
        self.committee_messages.add(message)
    }

    fn add_aux_message(&mut self, message: (Self::AuxMessageType, Addresses)) {
        self.network_messages.add(message)
    }

    fn add_feedback(&mut self, message: Self::FeedbackType) {
        self.feedback.push(message)
    }

    fn messages(&self) -> &OutputMessages<Self::MessageType> {
        &self.committee_messages
    }

    fn aux_messages(&self) -> &OutputMessages<Self::AuxMessageType> {
        &self.network_messages
    }

    fn feedback(&self) -> &Vec<FeedbackMessage> {
        &self.feedback
    }

    fn take_messages(&mut self) -> OutputMessages<Self::MessageType> {
        std::mem::take(&mut self.committee_messages)
    }

    fn take_aux_messages(&mut self) -> OutputMessages<Self::AuxMessageType> {
        std::mem::take(&mut self.network_messages)
    }

    fn take_feedback(&mut self) -> Vec<FeedbackMessage> {
        std::mem::take(&mut self.feedback)
    }
}
