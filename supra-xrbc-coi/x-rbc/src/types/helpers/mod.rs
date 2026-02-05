use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::sync::RBCSyncMessage;
use crate::types::messages::{
    EchoReadyData, EchoShareData, EchoValueData, QuorumCertificateData, ReadyData, ShareData,
    ValueData, VoteData,
};
use crate::types::messages::{RBCCommitteeMessage, RBCNetworkMessage};

pub(crate) mod assignment_extractor;
pub(crate) mod message_factory;
pub(crate) mod sender_extractor;
pub(crate) mod verifier_visitor;

pub(crate) trait Visitor<C: SupraDeliveryErasureCodecSchema> {
    type ReturnType;

    fn visit_sync_message(&self, data: &RBCSyncMessage<C>) -> Self::ReturnType {
        match data {
            RBCSyncMessage::EchoValue(data) => self.visit_echo_value(data),
            RBCSyncMessage::Ready(data) => self.visit_ready(data),
            RBCSyncMessage::EchoReady(data) => self.visit_echo_ready(data),
            RBCSyncMessage::Pull(data) => self.visit_pull_request(data),
            RBCSyncMessage::Share(data) => self.visit_share(data),
            RBCSyncMessage::EchoShare(data) => self.visit_echo_share(data),
        }
    }

    fn visit_committee_message(&self, data: &RBCCommitteeMessage<C>) -> Self::ReturnType {
        match data {
            RBCCommitteeMessage::Value(data) => self.visit_value(data),
            RBCCommitteeMessage::EchoValue(data) => self.visit_echo_value(data),
            RBCCommitteeMessage::Vote(data) => self.visit_vote(data),
            RBCCommitteeMessage::Certificate(data) => self.visit_certificate(data),
            RBCCommitteeMessage::Ready(data) => self.visit_ready(data),
            RBCCommitteeMessage::EchoReady(data) => self.visit_echo_ready(data),
            RBCCommitteeMessage::Composite(data) => self.visit_composite(data),
            RBCCommitteeMessage::Pull(data) => self.visit_pull_request(data),
            RBCCommitteeMessage::Sync(data) => self.visit_sync_request(data),
            RBCCommitteeMessage::Payload(data) => self.visit_payload(data),
        }
    }

    fn visit_network_message(&self, data: &RBCNetworkMessage<C>) -> Self::ReturnType {
        match data {
            RBCNetworkMessage::Share(data) => self.visit_share(data),
            RBCNetworkMessage::EchoShare(data) => self.visit_echo_share(data),
            RBCNetworkMessage::Pull(data) => self.visit_pull_request(data),
            RBCNetworkMessage::Sync(data) => self.visit_sync_request(data),
        }
    }

    fn visit_value(&self, data: &ValueData<C>) -> Self::ReturnType;
    fn visit_echo_value(&self, data: &EchoValueData<C>) -> Self::ReturnType;
    fn visit_vote(&self, data: &VoteData) -> Self::ReturnType;
    fn visit_certificate(&self, data: &QuorumCertificateData) -> Self::ReturnType;
    fn visit_ready(&self, data: &ReadyData<C>) -> Self::ReturnType;
    fn visit_echo_ready(&self, data: &EchoReadyData<C>) -> Self::ReturnType;
    fn visit_share(&self, data: &ShareData<C>) -> Self::ReturnType;
    fn visit_echo_share(&self, data: &EchoShareData<C>) -> Self::ReturnType;
    fn visit_pull_request(&self, data: &PullRequest) -> Self::ReturnType;
    fn visit_sync_request(&self, data: &SyncRequest) -> Self::ReturnType;
    fn visit_composite(&self, data: &[RBCCommitteeMessage<C>]) -> Self::ReturnType;
    fn visit_payload(&self, data: &PayloadData) -> Self::ReturnType;
}

pub(crate) trait VisitorAcceptor<C: SupraDeliveryErasureCodecSchema> {
    fn accept<V: Visitor<C>>(&self, v: &V) -> <V as Visitor<C>>::ReturnType;
}
