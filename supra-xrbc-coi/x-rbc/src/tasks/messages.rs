use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::errors::RBCError;
use crate::types::helpers::{Visitor, VisitorAcceptor};
use crate::types::messages::certificate_data::QuorumCertificateData;
use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::ready_data::EchoReadyData;
use crate::types::messages::ready_data::ReadyData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::share_data::EchoShareData;
use crate::types::messages::share_data::ShareData;
use crate::types::messages::sync::RBCSyncMessage;
use crate::types::messages::value_data::EchoValueData;
use crate::types::messages::value_data::ValueData;
use crate::types::messages::vote_data::VoteData;
use crate::types::messages::{RBCCommitteeMessage, RBCNetworkMessage};
use crate::{FeedbackMessage, InternalSyncRequest};
use itertools::Itertools;
use metrics::{MetricTag, TimeStampTrait, Timestamp};
use primitives::types::header::{Header, HeaderIfc};
use primitives::{NotificationSender, Payload};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::time::Duration;
use storage::StorageKey;

///
/// Payload Related Messages passed through network between peers
///
#[derive(Serialize, Deserialize)]
pub enum RBCMessage<C: SupraDeliveryErasureCodecSchema> {
    Value(ValueData<C>),
    EchoValue(EchoValueData<C>),
    Vote(VoteData),
    Certificate(QuorumCertificateData),
    Ready(ReadyData<C>),
    EchoReady(EchoReadyData<C>),
    Share(ShareData<C>),
    EchoShare(EchoShareData<C>),
    /// External sync request to pull data from current node
    Pull(PullRequest),
    /// Is created only by local supra-delivery upon internal sync request from synchronizer
    /// It never goes out of the node, i.e. can not be created from Committee&Network messages
    Sync(SyncRequest),
    Composite(Vec<RBCMessage<C>>),
    Payload(PayloadData),
}

pub enum RbcMessageTag {
    TravelTime,
    Size,
}

impl Display for RbcMessageTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RbcMessageTag::TravelTime => write!(f, "travel-time"),
            RbcMessageTag::Size => write!(f, "message-size"),
        }
    }
}

impl MetricTag for RbcMessageTag {}

impl<C: SupraDeliveryErasureCodecSchema> MetricTag for RBCMessage<C> {}

impl<C: SupraDeliveryErasureCodecSchema> TimeStampTrait for RBCMessage<C> {
    fn created_time(&self) -> Timestamp {
        match self {
            RBCMessage::Value(data) => data.created_time(),
            RBCMessage::EchoValue(data) => data.created_time(),
            RBCMessage::Vote(data) => data.created_time(),
            RBCMessage::Certificate(data) => data.created_time(),
            RBCMessage::Ready(data) => data.created_time(),
            RBCMessage::EchoReady(data) => data.created_time(),
            RBCMessage::Share(data) => data.created_time(),
            RBCMessage::EchoShare(data) => data.created_time(),
            RBCMessage::Pull(data) => data.created_time(),
            RBCMessage::Sync(data) => data.created_time(),
            RBCMessage::Composite(data) => data.iter().map(|msg| msg.created_time()).min().unwrap(),
            RBCMessage::Payload(data) => data.created_time(),
        }
    }

    fn elapsed_time(&self) -> Duration {
        match self {
            RBCMessage::Value(data) => data.elapsed_time(),
            RBCMessage::EchoValue(data) => data.elapsed_time(),
            RBCMessage::Vote(data) => data.elapsed_time(),
            RBCMessage::Certificate(data) => data.elapsed_time(),
            RBCMessage::Ready(data) => data.elapsed_time(),
            RBCMessage::EchoReady(data) => data.elapsed_time(),
            RBCMessage::Share(data) => data.elapsed_time(),
            RBCMessage::EchoShare(data) => data.elapsed_time(),
            RBCMessage::Pull(data) => data.elapsed_time(),
            RBCMessage::Sync(data) => data.elapsed_time(),
            RBCMessage::Composite(data) => data.iter().map(|msg| msg.elapsed_time()).max().unwrap(),
            RBCMessage::Payload(data) => data.elapsed_time(),
        }
    }
}

impl<CS: SupraDeliveryErasureCodecSchema> VisitorAcceptor<CS> for RBCMessage<CS> {
    fn accept<V: Visitor<CS>>(&self, v: &V) -> <V as Visitor<CS>>::ReturnType {
        match self {
            RBCMessage::Value(data) => v.visit_value(data),
            RBCMessage::EchoValue(data) => v.visit_echo_value(data),
            RBCMessage::Vote(data) => v.visit_vote(data),
            RBCMessage::Certificate(data) => v.visit_certificate(data),
            RBCMessage::Ready(data) => v.visit_ready(data),
            RBCMessage::EchoReady(data) => v.visit_echo_ready(data),
            RBCMessage::Share(data) => v.visit_share(data),
            RBCMessage::EchoShare(data) => v.visit_echo_share(data),
            RBCMessage::Composite(data) => data[0].accept(v),
            RBCMessage::Pull(data) => v.visit_pull_request(data),
            RBCMessage::Sync(data) => v.visit_sync_request(data),
            RBCMessage::Payload(data) => v.visit_payload(data),
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Display for RBCMessage<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RBCMessage::Value(data) => write!(f, "{}", data),
            RBCMessage::EchoValue(data) => write!(f, "{}", data),
            RBCMessage::Vote(data) => write!(f, "{}", data),
            RBCMessage::Certificate(data) => write!(f, "{}", data),
            RBCMessage::Ready(data) => write!(f, "{}", data),
            RBCMessage::EchoReady(data) => write!(f, "{}", data),
            RBCMessage::Composite(data) => {
                data.iter()
                    .for_each(|m| write!(f, "Composite {}", m).unwrap());
                write!(f, "Total {}", data.len())
            }
            RBCMessage::Share(data) => {
                write!(f, "{}", data)
            }
            RBCMessage::EchoShare(data) => {
                write!(f, "{}", data)
            }
            RBCMessage::Pull(data) => write!(f, "{}", data),
            RBCMessage::Sync(data) => write!(f, "{}", data),
            RBCMessage::Payload(data) => write!(f, "{}", data),
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Debug for RBCMessage<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> RBCMessage<C> {
    fn to_committee_message(
        messages: Vec<RBCMessage<C>>,
    ) -> Result<RBCCommitteeMessage<C>, RBCError> {
        messages
            .into_iter()
            .map(|data| data.try_into())
            .try_collect()
            .map(|result| RBCCommitteeMessage::Composite(result))
    }

    fn from_committee_messages(messages: Vec<RBCCommitteeMessage<C>>) -> RBCMessage<C> {
        let result = messages.into_iter().map(RBCMessage::from).collect();
        RBCMessage::Composite(result)
    }

    pub(crate) fn is_sync_message(&self) -> bool {
        matches!(self, RBCMessage::Pull(_) | RBCMessage::Sync(_))
    }

    pub(crate) fn is_committee_message(&self) -> bool {
        match self {
            RBCMessage::Value(_)
            | RBCMessage::Payload(_)
            | RBCMessage::EchoValue(_)
            | RBCMessage::Vote(_)
            | RBCMessage::Certificate(_)
            | RBCMessage::Ready(_)
            | RBCMessage::EchoReady(_)
            | RBCMessage::Pull(_)
            | RBCMessage::Sync(_)
            | RBCMessage::Composite(_) => true,
            RBCMessage::Share(_) | RBCMessage::EchoShare(_) => false,
        }
    }

    pub(crate) fn is_valid_message(&self) -> bool {
        // TODO: Define validity constructed message properly
        match self {
            RBCMessage::Value(_)
            | RBCMessage::Payload(_)
            | RBCMessage::EchoValue(_)
            | RBCMessage::Vote(_)
            | RBCMessage::Certificate(_)
            | RBCMessage::Ready(_)
            | RBCMessage::EchoReady(_)
            | RBCMessage::Share(_)
            | RBCMessage::Pull(_)
            | RBCMessage::Sync(_)
            | RBCMessage::EchoShare(_) => true,
            RBCMessage::Composite(data) => !data.is_empty(),
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> HeaderIfc for RBCMessage<C> {
    fn header(&self) -> &Header {
        match self {
            RBCMessage::Value(v) => v.header(),
            RBCMessage::EchoValue(v) => v.header(),
            RBCMessage::Vote(v) => v.header(),
            RBCMessage::Certificate(v) => v.header(),
            RBCMessage::Ready(v) => v.header(),
            RBCMessage::EchoReady(v) => v.header(),
            RBCMessage::Share(v) => v.header(),
            RBCMessage::EchoShare(v) => v.header(),
            RBCMessage::Composite(v) => v[0].header(),
            RBCMessage::Pull(v) => v.header(),
            RBCMessage::Sync(v) => v.header(),
            RBCMessage::Payload(v) => v.header(),
        }
    }
}

///
/// Conversion form RBCMessage to RBCCommitteeMessage
///
impl<C: SupraDeliveryErasureCodecSchema> TryInto<RBCCommitteeMessage<C>> for RBCMessage<C> {
    type Error = RBCError;

    fn try_into(self) -> Result<RBCCommitteeMessage<C>, Self::Error> {
        let result = match self {
            RBCMessage::Value(data) => RBCCommitteeMessage::Value(data),
            RBCMessage::EchoValue(data) => RBCCommitteeMessage::EchoValue(data),
            RBCMessage::Vote(data) => RBCCommitteeMessage::Vote(data),
            RBCMessage::Certificate(data) => RBCCommitteeMessage::Certificate(data),
            RBCMessage::Ready(data) => RBCCommitteeMessage::Ready(data),
            RBCMessage::EchoReady(data) => RBCCommitteeMessage::EchoReady(data),
            RBCMessage::Pull(data) => RBCCommitteeMessage::Pull(data),
            RBCMessage::Sync(data) => RBCCommitteeMessage::Sync(data),
            RBCMessage::Composite(data) => RBCMessage::to_committee_message(data)?,
            RBCMessage::Payload(data) => RBCCommitteeMessage::Payload(data),
            _ => return Err(RBCError::ConversionError),
        };
        Ok(result)
    }
}

///
/// Conversion form RBCMessage to RBCNetworkMessage
///
impl<C: SupraDeliveryErasureCodecSchema> TryInto<RBCNetworkMessage<C>> for RBCMessage<C> {
    type Error = RBCError;

    fn try_into(self) -> Result<RBCNetworkMessage<C>, Self::Error> {
        let result = match self {
            RBCMessage::Share(data) => RBCNetworkMessage::Share(data),
            RBCMessage::EchoShare(data) => RBCNetworkMessage::EchoShare(data),
            RBCMessage::Pull(data) => RBCNetworkMessage::Pull(data),
            RBCMessage::Sync(data) => RBCNetworkMessage::Sync(data),
            _ => return Err(RBCError::ConversionError),
        };
        Ok(result)
    }
}

///
/// Conversion form RBCMessage to RBCSyncMessage
///
impl<C: SupraDeliveryErasureCodecSchema> TryInto<RBCSyncMessage<C>> for RBCMessage<C> {
    type Error = RBCError;

    fn try_into(self) -> Result<RBCSyncMessage<C>, Self::Error> {
        let result = match self {
            RBCMessage::EchoValue(data) => RBCSyncMessage::EchoValue(data),
            RBCMessage::Ready(data) => RBCSyncMessage::Ready(data),
            RBCMessage::EchoReady(data) => RBCSyncMessage::EchoReady(data),
            RBCMessage::Pull(data) => RBCSyncMessage::Pull(data),
            RBCMessage::Share(data) => RBCSyncMessage::Share(data),
            RBCMessage::EchoShare(data) => RBCSyncMessage::EchoShare(data),
            _ => return Err(RBCError::ConversionError),
        };
        Ok(result)
    }
}

///
/// Conversion form RBCCommitteeMessage to RBCMessage
///
impl<C: SupraDeliveryErasureCodecSchema> From<RBCCommitteeMessage<C>> for RBCMessage<C> {
    fn from(data: RBCCommitteeMessage<C>) -> Self {
        match data {
            RBCCommitteeMessage::Value(v) => RBCMessage::Value(v),
            RBCCommitteeMessage::EchoValue(v) => RBCMessage::EchoValue(v),
            RBCCommitteeMessage::Vote(v) => RBCMessage::Vote(v),
            RBCCommitteeMessage::Certificate(v) => RBCMessage::Certificate(v),
            RBCCommitteeMessage::Ready(v) => RBCMessage::Ready(v),
            RBCCommitteeMessage::EchoReady(v) => RBCMessage::EchoReady(v),
            RBCCommitteeMessage::Composite(v) => RBCMessage::from_committee_messages(v),
            RBCCommitteeMessage::Pull(v) => RBCMessage::Pull(v),
            RBCCommitteeMessage::Payload(v) => RBCMessage::Payload(v),
            RBCCommitteeMessage::Sync(_v) => panic!("Invalid Sync request source"),
        }
    }
}

///
/// Conversion form RBCNetworkMessage to RBCMessage
///
impl<C: SupraDeliveryErasureCodecSchema> From<RBCNetworkMessage<C>> for RBCMessage<C> {
    fn from(data: RBCNetworkMessage<C>) -> Self {
        match data {
            RBCNetworkMessage::Share(v) => RBCMessage::Share(v),
            RBCNetworkMessage::EchoShare(v) => RBCMessage::EchoShare(v),
            RBCNetworkMessage::Pull(v) => RBCMessage::Pull(v),
            RBCNetworkMessage::Sync(_v) => panic!("Invalid Sync request source"),
        }
    }
}

///
/// Conversion form RBCSyncMessage to RBCMessage
///
impl<C: SupraDeliveryErasureCodecSchema> From<RBCSyncMessage<C>> for RBCMessage<C> {
    fn from(data: RBCSyncMessage<C>) -> Self {
        match data {
            RBCSyncMessage::EchoValue(v) => RBCMessage::EchoValue(v),
            RBCSyncMessage::Ready(v) => RBCMessage::Ready(v),
            RBCSyncMessage::EchoReady(v) => RBCMessage::EchoReady(v),
            RBCSyncMessage::Share(v) => RBCMessage::Share(v),
            RBCSyncMessage::EchoShare(v) => RBCMessage::EchoShare(v),
            RBCSyncMessage::Pull(v) => RBCMessage::Pull(v),
        }
    }
}

///
/// TimeoutMessage fired when RBC task is idling
///
#[derive(Debug, Clone, PartialEq)]
pub enum TimeoutMessage {
    Retry,
}

impl Display for TimeoutMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub struct PayloadRequest {
    payload: Payload,
    notification_channel: Option<NotificationSender<StorageKey>>,
}

impl PayloadRequest {
    pub fn new(
        payload: Payload,
        notification_channel: Option<NotificationSender<StorageKey>>,
    ) -> Self {
        Self {
            payload,
            notification_channel,
        }
    }

    pub fn split(self) -> (Payload, Option<NotificationSender<StorageKey>>) {
        (self.payload, self.notification_channel)
    }
}

pub enum DeliveryMessage<C: SupraDeliveryErasureCodecSchema> {
    Sync(InternalSyncRequest),
    Message(RBCMessage<C>),
    Payload(PayloadRequest),
    InternalFeedback(FeedbackMessage),
}

impl<C: SupraDeliveryErasureCodecSchema> Debug for DeliveryMessage<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DeliveryMessage::Sync(value) => {
                write!(f, "{:?}", value)
            }
            DeliveryMessage::Message(value) => {
                write!(f, "{}", value)
            }
            DeliveryMessage::Payload(..) => {
                write!(f, "Payload")
            }
            DeliveryMessage::InternalFeedback(value) => {
                write!(f, "{}", value)
            }
        }
    }
}

impl<C: SupraDeliveryErasureCodecSchema> Display for DeliveryMessage<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> From<PayloadRequest> for DeliveryMessage<C> {
    fn from(value: PayloadRequest) -> Self {
        DeliveryMessage::Payload(value)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> From<RBCMessage<C>> for DeliveryMessage<C> {
    fn from(value: RBCMessage<C>) -> Self {
        DeliveryMessage::Message(value)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> From<InternalSyncRequest> for DeliveryMessage<C> {
    fn from(value: InternalSyncRequest) -> Self {
        DeliveryMessage::Sync(value)
    }
}

impl<C: SupraDeliveryErasureCodecSchema> From<FeedbackMessage> for DeliveryMessage<C> {
    fn from(value: FeedbackMessage) -> Self {
        DeliveryMessage::InternalFeedback(value)
    }
}
