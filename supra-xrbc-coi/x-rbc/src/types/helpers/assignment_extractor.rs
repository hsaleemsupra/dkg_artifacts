use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use crate::tasks::config::{DisseminationRule, EchoTarget};
use crate::types::helpers::sender_extractor::SenderExtractor;
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
use network::topology::{ChainTopology, PeerFilterPredicate};
use primitives::types::HeaderIfc;
use primitives::{Address, Addresses, Origin, Protocol};

///
/// Deduces target addresses for the specified protocol the input data should be sent
///
pub(crate) struct AssignmentExtractor<'a> {
    topology: &'a ChainTopology,
    protocol: Protocol,
    dissemination_rule: &'a DisseminationRule,
    position_order: Vec<usize>,
    predicate: Option<PeerFilterPredicate<'a>>,
}

impl<'a> AssignmentExtractor<'a> {
    pub(crate) fn new(
        topology: &'a ChainTopology,
        protocol: Protocol,
        dissemination_rule: &'a DisseminationRule,
    ) -> Self {
        let position_order = if let DisseminationRule::Partial(rule) = dissemination_rule {
            match rule {
                EchoTarget::Left(_) => AssignmentExtractor::position_order_by_left_rule(
                    topology.current_node().position(),
                    topology.get_committee_size(),
                ),
                EchoTarget::Right(_) => AssignmentExtractor::position_order_by_right_rule(
                    topology.current_node().position(),
                    topology.get_committee_size(),
                ),
                EchoTarget::All => vec![],
            }
        } else {
            vec![]
        };
        Self {
            topology,
            protocol,
            dissemination_rule,
            position_order,
            predicate: None,
        }
    }

    ///
    /// Returns address of the node by origin
    ///
    pub(crate) fn address_by_origin(&self, origin: &Origin) -> Option<Address> {
        self.topology.get_address_by_origin(self.protocol, origin)
    }

    ///
    /// Returns address of the peer by position from current clan
    ///
    pub(crate) fn address_by_position(&self, position: usize) -> Option<Address> {
        self.topology
            .get_address_by_position(self.protocol, position)
    }

    ///
    /// Returns index of committed chunk assigned to current node by the broadcaster of the deliverable
    /// TODO: think about returning chunk index instead of commitment-index
    ///
    pub fn assigned_chunk_index(&self, broadcaster: &Origin) -> usize {
        self.target_chunk_index(broadcaster, self.topology.origin())
    }

    ///
    /// Returns index of committed chunk assigned to target node by the broadcaster of the deliverable
    ///
    pub fn target_chunk_index(&self, broadcaster: &Origin, target: &Origin) -> usize {
        let broadcaster_info = self.topology.info_by_origin(broadcaster).unwrap();
        let broadcaster_flattened_index = self
            .topology
            .get_origin_flattened_index(broadcaster)
            .unwrap();
        let broadcaster_clan_start_index =
            broadcaster_flattened_index - broadcaster_info.position();

        let chain_size = self.topology.get_chain_size();
        // shift making broadcaster node clan to be in (0, 0) position
        let shift_delta = chain_size - broadcaster_clan_start_index;

        let target_info = self.topology.info_by_origin(target).unwrap();
        let target_flattened_index = self.topology.get_peer_flattened_index(target_info);
        //Target node index relative to the broadcaster-clan being in (0, 0) position
        (target_flattened_index + shift_delta) % chain_size //assigned_chunk_index
    }

    ///
    /// Returns flattened index of peer which was assigned by input broadcaster to a chunk with
    /// input committed index
    ///
    pub fn assigned_target_index_by_commitment_index(
        &self,
        broadcaster: &Origin,
        committed_chunk_index: usize,
    ) -> usize {
        let broadcaster_info = self.topology.info_by_origin(broadcaster).unwrap();
        let broadcaster_flattened_index = self
            .topology
            .get_origin_flattened_index(broadcaster)
            .unwrap();
        let broadcaster_clan_start_index =
            broadcaster_flattened_index - broadcaster_info.position();

        let chain_size = self.topology.get_chain_size();
        (committed_chunk_index + broadcaster_clan_start_index) % chain_size
    }

    pub(crate) fn add_custom_filter(&mut self, predicate: PeerFilterPredicate<'a>) {
        self.predicate = Some(predicate)
    }

    ///
    /// Get sorted list of all position by left rule
    /// zeroth index is the next peer position
    ///
    fn position_order_by_left_rule(this_pos: usize, total_peers: usize) -> Vec<usize> {
        let mut position_list = Vec::<usize>::new();
        for pos in 0..total_peers {
            let position = (total_peers - pos + this_pos - 1) % total_peers;
            position_list.push(position)
        }
        position_list.pop();
        position_list
    }

    ///
    /// Get sorted list of all position by right rule
    /// zeroth index is the next peer position
    ///
    fn position_order_by_right_rule(this_pos: usize, total_peers: usize) -> Vec<usize> {
        let mut position_list = Vec::<usize>::new();
        for pos in 0..total_peers {
            let position = (pos + this_pos + 1) % total_peers;
            position_list.push(position)
        }
        position_list.pop();
        position_list
    }

    ///
    /// Returns address based on count of partial peer list
    ///
    fn get_address_for_target_positions(
        &self,
        broadcaster_pos: usize,
        mut node_count: usize,
        peers: Vec<&PeerInfo>,
    ) -> Addresses {
        let mut addresses = Vec::new();

        for position in self.position_order.iter() {
            if node_count < 1 {
                break;
            }
            let peer = peers
                .iter()
                .filter(|p| &p.position() == position && p.position() != broadcaster_pos)
                .collect::<Vec<&&PeerInfo>>();
            if !peer.is_empty() {
                let peer = peer.first().unwrap();
                addresses.push(peer.get_address(self.protocol).unwrap());
                node_count -= 1;
            }
        }

        addresses
    }

    ///
    /// Apply the dissemination rule and return Vec<Address>
    ///
    fn get_target_address_by_dissemination_rule(
        &self,
        broadcaster_position: usize,
        peers: Vec<&PeerInfo>,
    ) -> Addresses {
        match self.dissemination_rule {
            DisseminationRule::Full => {
                panic!("Protocol Error: No EchoValue is expected with DisseminationRule::Full")
            }
            DisseminationRule::Partial(EchoTarget::All) => peers
                .iter()
                .map(|p| p.get_address(self.protocol).unwrap())
                .collect::<Addresses>(),
            DisseminationRule::Partial(EchoTarget::Left(node_count)) => {
                self.get_address_for_target_positions(broadcaster_position, *node_count, peers)
            }
            DisseminationRule::Partial(EchoTarget::Right(node_count)) => {
                self.get_address_for_target_positions(broadcaster_position, *node_count, peers)
            }
        }
    }
}

impl<'a, C: SupraDeliveryErasureCodecSchema> Visitor<C> for AssignmentExtractor<'a> {
    type ReturnType = Option<Addresses>;

    fn visit_value(&self, data: &ValueData<C>) -> Self::ReturnType {
        self.address_by_position(data.get_chunk_index())
            .map(|a| vec![a])
    }

    fn visit_echo_value(&self, data: &EchoValueData<C>) -> Self::ReturnType {
        self.topology
            .info_by_origin(data.origin())
            .map(|broadcaster| {
                let peers = self
                    .topology
                    .get_peers_info(PeerFilterPredicate::NotAtPosition(
                        &[broadcaster.position()],
                    ));
                self.get_target_address_by_dissemination_rule(broadcaster.position(), peers)
            })
    }

    fn visit_vote(&self, data: &VoteData) -> Self::ReturnType {
        self.address_by_origin(data.origin()).map(|a| vec![a])
    }

    fn visit_certificate(&self, data: &QuorumCertificateData) -> Self::ReturnType {
        self.topology
            .info_by_origin(data.origin())
            .filter(|peer_info| self.topology.is_clan_member(peer_info.id()).unwrap())
            .map(|peer| {
                self.topology.get_peer_addresses(
                    self.protocol,
                    PeerFilterPredicate::NotAtPosition(&[peer.position()]),
                )
            })
    }

    fn visit_ready(&self, data: &ReadyData<C>) -> Self::ReturnType {
        self.address_by_position(data.value().get_chunk_index())
            .map(|a| vec![a])
    }

    fn visit_echo_ready(&self, data: &EchoReadyData<C>) -> Self::ReturnType {
        self.topology
            .info_by_origin(data.origin())
            .map(|broadcaster| vec![broadcaster.position()])
            .and_then(|mut exclude| {
                SenderExtractor::new(self.topology)
                    .visit_ready(data.ready_data())
                    .map(|sender| {
                        exclude.push(sender.position());
                        exclude
                    })
            })
            .map(|exclude| {
                self.topology
                    .get_peer_addresses(self.protocol, PeerFilterPredicate::NotAtPosition(&exclude))
            })
    }

    fn visit_share(&self, data: &ShareData<C>) -> Self::ReturnType {
        self.topology
            .get_node_address_relative_to_current_node(
                self.protocol,
                data.network_chunk_meta().index(),
            )
            .map(|a| vec![a])
    }

    fn visit_echo_share(&self, data: &EchoShareData<C>) -> Self::ReturnType {
        self.topology
            .info_by_origin(data.origin())
            .map(|info| info.clan_identifier())
            .map(|clan| {
                self.topology
                    .get_nodes_addresses(self.protocol, PeerFilterPredicate::NotInClan(clan))
            })
    }

    ///
    /// depending on the current node relationship with the data.origin the targets are different.
    /// if current node and data.origin are from the same clan targets are all peers in the clan,
    /// else targets are all peers in the network
    ///
    fn visit_pull_request(&self, data: &PullRequest) -> Self::ReturnType {
        let predicate = self.predicate.unwrap_or(PeerFilterPredicate::Pass);
        let result = if self.topology.is_clan_member(data.origin()).unwrap() {
            self.topology.get_peer_addresses(self.protocol, predicate)
        } else {
            self.topology.get_nodes_addresses(Protocol::XRBC, predicate)
        };
        Some(result)
    }

    fn visit_sync_request(&self, _data: &SyncRequest) -> Self::ReturnType {
        panic!("SyncRequest does not go out of the node, it has no external target/assignee")
    }

    fn visit_composite(&self, _data: &[RBCCommitteeMessage<C>]) -> Self::ReturnType {
        panic!("Assignees deduction is not supported for composite message")
    }

    fn visit_payload(&self, _data: &PayloadData) -> Self::ReturnType {
        Some(
            self.topology
                .get_peer_addresses(self.protocol, PeerFilterPredicate::Pass),
        )
    }
}

#[cfg(test)]
#[path = "../tests/assignment_extractor_tests.rs"]
pub mod assignment_extractor_tests;
