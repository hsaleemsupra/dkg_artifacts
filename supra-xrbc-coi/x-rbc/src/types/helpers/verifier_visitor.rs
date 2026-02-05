use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::types::context::{Resources, ResourcesApi};
use crate::types::helpers::sender_extractor::SenderExtractor;
use crate::types::helpers::{Visitor, VisitorAcceptor};
use crate::types::messages::chunk::ChunkData;
use crate::types::messages::payload_data::PayloadData;
use crate::types::messages::requests::{PullRequest, SyncRequest};
use crate::types::messages::RBCCommitteeMessage;
use crate::types::messages::{
    EchoReadyData, EchoShareData, EchoValueData, QuorumCertificateData, ReadyData, ShareData,
    ValueData, VoteData,
};
use crypto::Authenticator;
use network::topology::peer_info::PeerInfo;
use network::topology::ChainTopology;
use primitives::types::header::{Header, HeaderIfc};
use primitives::types::QuorumCertificate;
use primitives::HASH32;
use std::collections::HashSet;
use vec_commitment::committed_chunk::CommitmentMeta;

#[derive(Debug, PartialEq)]
pub(crate) enum VerificationResult {
    Failed,
    Ignore,
    Success,
}

impl From<bool> for VerificationResult {
    fn from(flag: bool) -> Self {
        match flag {
            true => VerificationResult::Success,
            false => VerificationResult::Failed,
        }
    }
}

impl VerificationResult {
    fn map<T>(self, apply: T) -> Self
    where
        T: FnOnce() -> bool,
    {
        match self {
            VerificationResult::Failed => self,
            VerificationResult::Ignore => self,
            VerificationResult::Success => VerificationResult::from(apply()),
        }
    }
    pub(crate) fn and_then<T>(self, apply: T) -> Self
    where
        T: FnOnce() -> VerificationResult,
    {
        match self {
            VerificationResult::Failed => self,
            VerificationResult::Ignore => self,
            VerificationResult::Success => apply(),
        }
    }

    pub(crate) fn is_ok(&self) -> bool {
        *self == VerificationResult::Success
    }

    pub(crate) fn is_ignore(&self) -> bool {
        *self == VerificationResult::Ignore
    }

    pub(crate) fn is_err(&self) -> bool {
        *self == VerificationResult::Failed
    }
}

pub(crate) struct VerifierVisitor<'a> {
    resources: &'a Resources,
}

impl<'a> VerifierVisitor<'a> {
    pub(crate) fn new(resources: &'a Resources) -> Self {
        Self { resources }
    }

    fn topology(&self) -> &ChainTopology {
        self.resources.topology()
    }

    fn authenticator(&self) -> &Authenticator {
        self.resources.authenticator()
    }

    fn sender_extractor(&self) -> SenderExtractor {
        SenderExtractor::new(self.topology())
    }

    ///
    /// current_peer.id != value_data.origin
    /// chunk_owner.IsFromSameClan(Res.GetPeerInfo(value_data.origin))
    /// Res.IsBroadcaster(value_data.origin)
    /// Res.VerifySignature(value_data.commitment, value_data.id, value_data.origin)
    /// value_data.committed_chunk.verifyProof(value_data.commitment)
    /// value_data.committed_chunk.chunk_index() == chunk_owner.position
    ///
    fn verify_value_data<C: SupraDeliveryErasureCodecSchema>(
        &self,
        data: &ValueData<C>,
        owner: &PeerInfo,
    ) -> VerificationResult {
        let origin = data.origin();
        VerificationResult::from(data.get_chunk_index() == owner.position())
            .map(|| origin.ne(self.topology().origin()))
            .map(|| {
                self.sender_extractor()
                    .visit_value(data)
                    .map(|sender| sender.is_from_same_clan(owner))
                    .unwrap_or(false)
            })
            .and_then(|| self.verify_value_content(data))
    }

    fn verify_value_content<C: SupraDeliveryErasureCodecSchema>(
        &self,
        data: &ValueData<C>,
    ) -> VerificationResult {
        self.verify_header(data.header())
            .and_then(|| self.verify_chunk_data(*data.commitment(), data.chunk_data()))
    }

    fn verify_commitment_meta(&self, header: &Header, meta: &CommitmentMeta) -> VerificationResult {
        let res = meta.verify(*header.commitment(), self.xrbc_delivery_commitment_size());
        VerificationResult::from(res.unwrap_or(false))
    }

    pub(crate) fn verify_chunk_data<C: SupraDeliveryErasureCodecSchema>(
        &self,
        commitment: HASH32,
        data: &ChunkData<C>,
    ) -> VerificationResult {
        data.data()
            .verify(commitment, self.xrbc_delivery_commitment_size())
            .map(VerificationResult::from)
            .unwrap_or(VerificationResult::Failed)
    }

    fn verify_header(&self, header: &Header) -> VerificationResult {
        Authenticator::verify(header.origin(), header.id(), header.commitment())
            .map(|_| VerificationResult::Success)
            .unwrap_or(VerificationResult::Failed)
            .map(|| self.topology().is_proposer(header.origin()))
    }

    ///
    /// Verifies that QC was generated with required amount of participants and the generated
    /// QC is valid one
    ///
    fn verify_qc(&self, header: &Header, qc: &QuorumCertificate) -> VerificationResult {
        VerificationResult::from(qc.participants().len() == self.authenticator().threshold()).map(
            || {
                self.topology()
                    .info_by_origin(header.origin())
                    .map(|peer_info| peer_info.clan_identifier())
                    .and_then(|clan| {
                        self.authenticator()
                            .verify_threshold_signature(&clan, qc.data(), header.commitment())
                            .ok()
                    })
                    .is_some()
            },
        )
    }

    fn xrbc_delivery_commitment_size(&self) -> usize {
        let committee_size = self.topology().get_committee_size();
        let chain_size = self.topology().get_chain_size();
        let non_committee_size = chain_size - committee_size;
        // committee_chunks
        // + network_chunks
        // + network_chunks_pieces(committee_size pieces for each network_chunk)
        chain_size + non_committee_size * committee_size
    }
}

impl<'a, C: SupraDeliveryErasureCodecSchema> Visitor<C> for VerifierVisitor<'a> {
    type ReturnType = VerificationResult;

    fn visit_value(&self, data: &ValueData<C>) -> Self::ReturnType {
        self.verify_value_data(data, self.resources.topology().current_node())
    }

    ///
    /// sender_info = Res.GetPeerInfo(sender)
    /// Res.CurrentPeerInfo().isFromSameClan(sender_info)
    /// Verify(data.value_data, sender_info, Res)
    ///
    fn visit_echo_value(&self, data: &EchoValueData<C>) -> Self::ReturnType {
        let current_peer = self.topology().current_node();
        let sender = self.sender_extractor().visit_echo_value(data);
        VerificationResult::from(sender.is_some())
            .map(|| current_peer.is_from_same_clan(sender.unwrap()))
            .and_then(|| self.verify_value_data(data.value(), sender.unwrap()))
    }

    ///
    /// Verify(vote_data: VoteData, Res: Resources)
    /// Res.IsBroadcaster(vote_data.origin)
    /// Res.CurrentPeerInfo().id == vote_data.origin
    /// sender_info = Res.GetPeerInfo(vote_data.vote_origin)
    /// Res.CurrentPeerInfo().isFromSameClan(sender_info)
    /// Res.VerifyVote(commitment, signature, vote_origin)
    ///
    fn visit_vote(&self, data: &VoteData) -> Self::ReturnType {
        let current_peer = self.topology().current_node();
        let sender_extractor: Box<dyn Visitor<C, ReturnType = Option<&PeerInfo>>> =
            Box::new(self.sender_extractor());
        // Vote.origin() is the actual data origin for which vote was created
        VerificationResult::from(current_peer.id() == data.origin())
            .map(|| current_peer.position() != data.index() as usize)
            .and_then(|| self.verify_header(data.header()))
            .and_then(|| {
                sender_extractor
                    .visit_vote(data)
                    .map(|sender| {
                        VerificationResult::from(current_peer.is_from_same_clan(sender)).map(|| {
                            self.authenticator()
                                .verify_partial_signature(data.vote(), data.commitment())
                                .is_ok()
                        })
                    })
                    .unwrap_or(VerificationResult::Failed)
            })
    }

    ///
    /// Verify Header, QC, and broadcaster signature on qc
    ///
    fn visit_certificate(&self, data: &QuorumCertificateData) -> Self::ReturnType {
        let qc_bytes = bincode::serialize(data.qc()).unwrap();
        let auth = Authenticator::verify(data.origin(), data.proof(), &qc_bytes);
        if auth.is_err() {
            log::error!("Broadcaster Signature verification failed");
            return VerificationResult::Failed;
        }
        self.verify_header(data.header())
            .and_then(|| self.verify_qc(data.header(), data.qc()))
    }

    ///
    /// sender_info = Res.GetPeerInfo(sender)
    /// current_peer = Res.CurrentPeerInfo()
    /// current_peer.IsFromSameClan(sender_info)
    /// Verify(data.value_data, current_peer, Res)
    ///
    fn visit_ready(&self, data: &ReadyData<C>) -> Self::ReturnType {
        let current_peer = self.topology().current_node();
        let sender = self.sender_extractor().visit_ready(data);
        VerificationResult::from(sender.is_some())
            .map(|| current_peer.is_from_same_clan(sender.unwrap()))
            .and_then(|| self.verify_value_data(data.value(), current_peer))
    }

    ///
    /// sender_info = Res.GetPeerInfo(sender)
    /// current_peer = Res.CurrentPeerInfo()
    /// current_peer.IsFromSameClan(sender_info)
    /// Verify(data.ready_data, sender, Res)
    ///
    fn visit_echo_ready(&self, data: &EchoReadyData<C>) -> Self::ReturnType {
        let current_peer = self.topology().current_node();
        let sender = self.sender_extractor().visit_echo_ready(data);
        VerificationResult::from(sender.is_some())
            .map(|| current_peer.is_from_same_clan(sender.unwrap()))
            .and_then(|| self.verify_value_data(data.value(), sender.unwrap()))
    }

    ///
    /// Verify data origin is not from current peer clan
    /// Verify data origin and sender are from the same clan
    /// Verify data header
    /// Verify NetworkChunk commitment
    /// Verify receiver owns chunk data
    ///
    fn visit_share(&self, data: &ShareData<C>) -> Self::ReturnType {
        let current_peer = self.topology().current_node();
        let sender_info = self.sender_extractor().visit_share(data);
        let origin_info = self.sender_extractor().sender_by_origin(data.origin());
        let expected_receiver = sender_info.and_then(|sender| {
            self.topology()
                .get_info_relative_to_origin(sender.id(), data.get_network_chunk_index())
        });
        VerificationResult::from(
            origin_info.is_some() && sender_info.is_some() && expected_receiver.is_some(),
        )
        .map(|| !origin_info.unwrap().is_from_same_clan(current_peer))
        .map(|| origin_info.unwrap().is_from_same_clan(sender_info.unwrap()))
        .map(|| expected_receiver.unwrap().eq(current_peer))
        .map(|| sender_info.unwrap().position() == data.value().get_chunk_index())
        .and_then(|| self.verify_value_content(data.value()))
        .and_then(|| self.verify_commitment_meta(data.value().header(), data.network_chunk_meta()))
    }

    ///
    /// Verify data origin is not from current peer clan
    /// Verify data header
    /// Verify NetworkChunk commitment
    /// Verify sender owns chunk data
    ///
    fn visit_echo_share(&self, data: &EchoShareData<C>) -> Self::ReturnType {
        let current_peer = self.topology().current_node();
        let sender_info = self.sender_extractor().visit_echo_share(data);
        let origin_info = self.sender_extractor().sender_by_origin(data.origin());
        let expected_receiver = origin_info.and_then(|origin| {
            self.topology()
                .get_info_relative_to_origin(origin.id(), data.value().get_commitment_index())
        });
        VerificationResult::from(
            origin_info.is_some() && sender_info.is_some() && expected_receiver.is_some(),
        )
        .map(|| !origin_info.unwrap().is_from_same_clan(current_peer))
        .map(|| !origin_info.unwrap().is_from_same_clan(sender_info.unwrap()))
        .map(|| expected_receiver.eq(&sender_info))
        .and_then(|| self.verify_value_content(data.value()))
    }

    ///
    /// broadcaster never receive pull request
    ///
    fn visit_pull_request(&self, data: &PullRequest) -> Self::ReturnType {
        if data.header().origin() == data.sender() {
            return VerificationResult::Failed;
        }
        self.verify_header(data.header())
            .and_then(|| self.verify_qc(data.header(), &data.get_qc()))
    }

    ///
    /// broadcaster never receive sync request
    ///
    fn visit_sync_request(&self, data: &SyncRequest) -> Self::ReturnType {
        if self.resources.topology().origin() == data.header().origin() {
            return VerificationResult::Failed;
        }
        self.verify_header(data.header())
            .and_then(|| self.verify_qc(data.header(), &data.get_qc()))
    }

    ///
    /// All messages share the same header and verification of each individual message is success
    ///
    fn visit_composite(&self, data: &[RBCCommitteeMessage<C>]) -> Self::ReturnType {
        let the_same_header = data.iter().map(|msg| msg.header()).collect::<HashSet<_>>();
        VerificationResult::from(the_same_header.len() == 1).map(|| {
            data.iter()
                .map(|msg| msg.accept(self))
                .all(|r| r == VerificationResult::Success)
        })
    }

    fn visit_payload(&self, data: &PayloadData) -> Self::ReturnType {
        self.verify_header(data.header())
    }
}

#[cfg(test)]
#[path = "../tests/verify_value_data_tests.rs"]
pub mod verify_value_data_tests;

#[cfg(test)]
#[path = "../tests/verify_echo_value_data_tests.rs"]
pub mod verify_echo_value_data_tests;

#[cfg(test)]
#[path = "../tests/verify_vote_data_tests.rs"]
pub mod verify_vote_data_tests;

#[cfg(test)]
#[path = "../tests/verify_certificate_tests.rs"]
pub mod verify_certificate_tests;

#[cfg(test)]
#[path = "../tests/verify_ready_data_tests.rs"]
pub mod verify_ready_data_tests;

#[cfg(test)]
#[path = "../tests/verify_echo_ready_data_tests.rs"]
pub mod verify_echo_ready_data_tests;

#[cfg(test)]
#[path = "../tests/verify_composite_tests.rs"]
pub mod verify_composite_tests;

#[cfg(test)]
#[path = "../tests/verify_share_data_tests.rs"]
pub mod verify_share_data_tests;

#[cfg(test)]
#[path = "../tests/verify_echo_share_data_tests.rs"]
pub mod verify_echo_share_data_tests;

#[cfg(test)]
#[path = "../tests/verify_syncronizer_req_tests.rs"]
pub mod verify_syncronizer_req_tests;
