use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::helpers::Visitor;
use crate::types::messages::certificate_data::QuorumCertificateData;
use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::share_data::EchoShareData;
use crate::types::messages::vote_data::VoteData;
use crate::types::messages::{
    EchoReadyData, EchoValueData, RBCCommitteeMessage, ReadyData, ShareData, ValueData,
};
use network::topology::peer_info::PeerInfo;
use network::topology::ChainTopology;
use primitives::types::HeaderIfc;
use primitives::Origin;
use std::collections::HashSet;

pub(crate) trait SenderIfc {
    fn sender(&self) -> &Origin;
}

pub(crate) struct SenderExtractor<'a> {
    topology: &'a ChainTopology,
}

impl<'a> SenderExtractor<'a> {
    pub(crate) fn new(topology: &'a ChainTopology) -> Self {
        Self { topology }
    }

    pub(crate) fn sender_by_origin(&self, origin: &Origin) -> Option<&'a PeerInfo> {
        self.topology.info_by_origin(origin)
    }

    pub(crate) fn sender_by_position(&self, position: usize) -> Option<&'a PeerInfo> {
        self.topology.peer_by_position(position)
    }
}

impl<'a, C: SupraDeliveryErasureCodecSchema> Visitor<C> for SenderExtractor<'a> {
    type ReturnType = Option<&'a PeerInfo>;

    fn visit_value(&self, data: &ValueData<C>) -> Self::ReturnType {
        self.sender_by_origin(data.origin())
    }

    fn visit_echo_value(&self, data: &EchoValueData<C>) -> Self::ReturnType {
        self.sender_by_position(data.get_chunk_index())
    }

    fn visit_vote(&self, data: &VoteData) -> Self::ReturnType {
        self.sender_by_position(data.index() as usize)
    }

    fn visit_certificate(&self, data: &QuorumCertificateData) -> Self::ReturnType {
        self.sender_by_origin(data.header().origin())
    }

    fn visit_ready(&self, data: &ReadyData<C>) -> Self::ReturnType {
        self.sender_by_origin(data.sender())
    }

    fn visit_echo_ready(&self, data: &EchoReadyData<C>) -> Self::ReturnType {
        self.sender_by_position(data.value().get_chunk_index())
    }

    fn visit_share(&self, data: &ShareData<C>) -> Self::ReturnType {
        self.sender_by_origin(data.sender())
    }

    fn visit_echo_share(&self, data: &EchoShareData<C>) -> Self::ReturnType {
        self.sender_by_origin(data.sender())
    }

    fn visit_pull_request(&self, data: &PullRequest) -> Self::ReturnType {
        self.sender_by_origin(data.sender())
    }

    fn visit_sync_request(&self, _data: &SyncRequest) -> Self::ReturnType {
        Some(self.topology.current_node())
    }

    fn visit_composite(&self, data: &[RBCCommitteeMessage<C>]) -> Self::ReturnType {
        let senders = data
            .iter()
            .map(|msg| self.visit_committee_message(msg))
            .collect::<HashSet<_>>();
        if senders.len() != 1 {
            return None;
        }
        senders.into_iter().next().unwrap()
    }

    fn visit_payload(&self, data: &PayloadData) -> Self::ReturnType {
        self.sender_by_origin(data.origin())
    }
}

#[cfg(test)]
#[path = "../tests/sender_extractor_tests.rs"]
pub mod sender_extractor_tests;
