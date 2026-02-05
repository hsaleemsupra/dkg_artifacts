use crate::topology::config::NetworkConfig;
use crate::topology::peer_info::PeerInfo;
use crate::topology::tribe::Tribe;

use crate::errors::NetworkError;
use crate::topology::clan::Clan;
use itertools::Itertools;
use primitives::{Address, Addresses, ClanIdentifier, Origin, PeerGlobalIndex, Protocol};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

pub mod clan;
pub mod config;
pub mod peer_info;
pub mod tribe;

pub mod tests;

///
/// Data structures encapsulating all peers topological and identity details
/// It contains:
///     - current node peer reference
///     - all peers' details in the network
///     - tribe/clan topological details
///     - list of all proposer/leader origins in the network
///
/// It is guaranteed that any instance of the struct is well-formed against the input
/// network configuration, i.e.
///     - all clans/committees in all tribes have the same size
///     - peers are not shared between clans
///     - all peers' details are well-formed
///     - proposers in tribe and clan correspond to the input configuration
///
#[derive(Clone, Debug)]
pub struct ChainTopology {
    current_node: PeerInfo,
    peers: HashMap<Origin, PeerInfo>,
    tribes: Vec<Tribe>,
    proposers: HashSet<Origin>,
    block_proposer: PeerInfo,
}

impl ChainTopology {
    pub fn new(
        config: &NetworkConfig,
        peers: HashMap<Origin, PeerInfo>,
        current: &Origin,
    ) -> Result<Self, NetworkError> {
        let current = peers
            .get(current)
            .ok_or_else(|| {
                NetworkError::NetworkConfigError(
                    "No peer info could be found for the provided origin".to_string(),
                )
            })?
            .clone();
        let block_proposer = peers
            .values()
            .filter(|peer| peer.is_block_proposer())
            .collect::<Vec<&PeerInfo>>();
        if block_proposer.len() != 1 {
            return Err(NetworkError::ChainTopologyError(format!(
                "Invalid number({}) of block-proposers in chain, it should be 1",
                block_proposer.len()
            )));
        };
        let block_proposer = (*block_proposer.first().unwrap()).clone();

        let mut topology = ChainTopology {
            current_node: current,
            peers,
            tribes: vec![],
            proposers: Default::default(),
            block_proposer,
        };
        topology.validate_all_peers_info()?;
        topology.fill_tribe_data();
        topology.fill_proposer_data();
        topology.validate_chain_topology(config)
    }

    /// Private API to construct ChainTopology valid instance

    fn fill_tribe_data(&mut self) {
        self.tribes = self
            .peers_by_clan_identifier()
            .into_iter()
            .map(|(clan_idx, peers)| (clan_idx, ChainTopology::peer_origins_by_position(peers)))
            .map(|(clan_idx, peers)| (clan_idx.tribe, Clan::new(clan_idx.clan, peers)))
            .group_by(|(tribe_id, _)| *tribe_id)
            .into_iter()
            .fold(
                HashMap::<usize, Vec<(usize, Clan)>>::new(),
                ChainTopology::fold_by_key,
            )
            .into_iter()
            .map(|(tribe_id, clans)| Tribe::new(tribe_id, ChainTopology::clans_by_position(clans)))
            .sorted_by(|t1, t2| t1.index().cmp(&t2.index()))
            .collect();
    }

    fn peers_by_clan_identifier(&self) -> HashMap<ClanIdentifier, Vec<&PeerInfo>> {
        self.peers
            .values()
            .group_by(|info| info.clan_identifier())
            .into_iter()
            .fold(
                HashMap::<ClanIdentifier, Vec<&PeerInfo>>::new(),
                ChainTopology::fold_by_key,
            )
    }

    fn fold_by_key<K: Hash + Eq, V>(
        mut acc: HashMap<K, Vec<V>>,
        (key, value): (K, impl Iterator<Item = V>),
    ) -> HashMap<K, Vec<V>> {
        if let Some(values) = acc.get_mut(&key) {
            values.extend(value)
        } else {
            acc.insert(key, value.collect());
        }
        acc
    }

    fn peer_origins_by_position(peers: Vec<&PeerInfo>) -> Vec<Origin> {
        peers
            .into_iter()
            .sorted_by(|p1, p2| p1.position().cmp(&p2.position()))
            .map(|peer| *peer.id())
            .collect::<Vec<Origin>>()
    }

    fn clans_by_position(clans: Vec<(usize, Clan)>) -> Vec<Clan> {
        clans
            .into_iter()
            .sorted_by(|(_, c1), (_, c2)| c1.index().cmp(&c2.index()))
            .map(|(_, c)| c)
            .collect::<Vec<Clan>>()
    }

    fn fill_proposer_data(&mut self) {
        self.proposers = self
            .peers
            .values()
            .filter(|peer| peer.is_proposer())
            .map(|peer| *peer.id())
            .collect()
    }

    /// Public API

    ///
    /// Checks whether current origin is a proposer
    ///
    pub fn is_proposer(&self, id: &Origin) -> bool {
        self.proposers.contains(id)
    }

    ///
    /// Returns true if the input origin is from the current node clan
    ///
    pub fn is_clan_member(&self, origin: &Origin) -> Option<bool> {
        self.info_by_origin(origin)
            .map(|origin_info| origin_info.is_from_same_clan(&self.current_node))
    }

    ///
    /// Returns true if the input origins are from the same clan
    ///
    pub fn are_clan_peers(&self, origin1: &Origin, origin2: &Origin) -> Option<bool> {
        let origin1_info = self.info_by_origin(origin1)?;
        let origin2_info = self.info_by_origin(origin2)?;
        Some(origin1_info.is_from_same_clan(origin2_info))
    }

    ///
    /// Returns details of the peer at specified input position from the current node clan
    ///
    pub fn peer_by_position(&self, position: usize) -> Option<&PeerInfo> {
        self.tribes[self.current_node.tribe()].clans()[self.current_node.clan()]
            .peers()
            .get(position)
            .and_then(|origin| self.peers.get(origin))
    }

    ///
    /// Returns details of the peer with specified origin if any
    ///
    pub fn info_by_origin(&self, id: &Origin) -> Option<&PeerInfo> {
        self.peers.get(id)
    }

    ///
    /// Returns current peer details
    ///
    pub fn current_node(&self) -> &PeerInfo {
        &self.current_node
    }

    ///
    /// Returns the block proposer node information
    ///
    pub fn get_block_proposer_info(&self) -> &PeerInfo {
        &self.block_proposer
    }

    ///
    /// Returns current peer origin/id information
    ///
    pub fn origin(&self) -> &Origin {
        self.current_node.id()
    }

    ///
    /// Returns network peer matching input peer global index relative to current node position.
    ///
    /// The input index is treated as flattened index in the imaginary chain system where
    /// the current node has global index (0, 0, current_peer_position)
    /// I.e. for input index equal to current_peer_position, current peer address will be returned
    /// for input index equal to current_peer_position - 1, current node's left neighbour peer info will be returned
    /// for input index equal to current_peer_position + 1, current node's right neighbour peer_info will be returned
    ///
    /// Differs from clan to clan, but deterministic for the same index for all peers from the same clan
    ///
    pub fn get_info_relative_to_current_node(
        &self,
        relative_global_index: usize,
    ) -> Option<&PeerInfo> {
        self.get_info_relative_to_clan(self.current_node.clan(), relative_global_index)
    }

    ///
    /// Returns network peer matching input peer global index relative to origin clan position.
    ///
    /// The input index is treated as flattened index in the imaginary chain system where
    /// the origin's clan has global index (0, 0, origin_position)
    ///
    /// Differs from clan to clan, but deterministic for the same index for all peers from the same clan
    ///
    pub fn get_info_relative_to_origin(
        &self,
        origin: &Origin,
        relative_global_index: usize,
    ) -> Option<&PeerInfo> {
        self.peers.get(origin).and_then(|peer_info| {
            self.get_info_relative_to_clan(peer_info.clan(), relative_global_index)
        })
    }

    ///
    /// Returns network peer matching input peer global index relative to input clan index.
    ///
    /// The input index is treated as flattened index in the imaginary chain system where
    /// the input clan is in (0, 0) position
    ///
    /// Differs from clan to clan, but deterministic for the same index for all peers from the same clan
    ///
    pub fn get_info_relative_to_clan(
        &self,
        clan_id: usize,
        relative_global_index: usize,
    ) -> Option<&PeerInfo> {
        self.calculate_global_index(relative_global_index)
            .map(|peer_index| {
                let clans_in_tribe = self.tribes[0].len();
                let tribes_in_chain = self.tribes.len();

                // shift with clan position and define a network clan position
                // assuming the current clan is in (0, 0) clan position
                let shifted_clan = peer_index.clan() + clan_id;
                let net_peer_clan = shifted_clan % clans_in_tribe;
                // check if tribe shift also happened when clan was shifted
                let tribe_shift_delta = (shifted_clan / clans_in_tribe > 0) as usize;
                let net_peer_tribe = (peer_index.tribe() + tribe_shift_delta) % tribes_in_chain;
                PeerGlobalIndex::new(net_peer_tribe, net_peer_clan, peer_index.position())
            })
            .and_then(|peer_index| self.info_by_global_index(peer_index))
    }

    ///
    /// Returns network peer address matching input peer global index relative to current node position.
    ///
    /// The input index is treated as flattened index in the imaginary chain system where
    /// the current node has global index (0, 0, current_peer_position)
    /// I.e. for input index equal to current_peer_position, current peer address will be returned
    /// for input index equal to current_peer_position - 1, current node's left neighbour address will be returned
    /// for input index equal to current_peer_position + 1, current node's right neighbour address will be returned
    ///
    /// Differs from clan to clan, but deterministic for the same index for all peers from the same clan
    ///
    pub fn get_node_address_relative_to_current_node(
        &self,
        protocol: Protocol,
        relative_global_index: usize,
    ) -> Option<Address> {
        self.get_info_relative_to_current_node(relative_global_index)
            .and_then(|peer| peer.get_address(protocol))
    }

    ///
    /// Returns current node flattened index in the chain
    ///
    pub fn get_flattened_index(&self) -> usize {
        self.get_peer_flattened_index(&self.current_node)
    }

    ///
    /// Returns origin's flattened index in the chain
    ///
    pub fn get_origin_flattened_index(&self, origin: &Origin) -> Option<usize> {
        self.peers
            .get(origin)
            .map(|peer| self.get_peer_flattened_index(peer))
    }

    ///
    /// Returns peer's flattened index in the chain
    ///
    pub fn get_peer_flattened_index(&self, peer_info: &PeerInfo) -> usize {
        peer_info
            .global_index()
            .flatten(self.get_tribe_size(), self.get_committee_size())
            .unwrap()
    }
    ///
    /// Returns current node position in the clan
    ///
    pub fn get_position(&self) -> usize {
        self.current_node.position()
    }

    ///
    /// Returns committee/clan size of network
    ///
    pub fn get_committee_size(&self) -> usize {
        let peer = self.current_node();
        self.tribes[peer.tribe()].clans()[peer.clan()].peers().len()
    }

    ///
    /// Returns total number of clans in a single tribe
    ///
    pub fn get_tribe_size(&self) -> usize {
        self.tribes[0].len()
    }

    ///
    /// Returns total number of tribes in the chain
    ///
    pub fn get_tribes_len(&self) -> usize {
        self.tribes.len()
    }

    ///
    /// Returns total number of peers in the network/chain
    ///
    pub fn get_chain_size(&self) -> usize {
        self.peers.len()
    }

    ///
    /// Gets peer info of the peers from the current node clan excluding the ones in specified position
    ///
    pub fn get_peers_info(&self, predicate: PeerFilterPredicate) -> Vec<&PeerInfo> {
        self.tribes[self.current_node().tribe()].clans()[self.current_node().clan()]
            .peers()
            .iter()
            .enumerate()
            .filter(|(_idx, origin)| *origin != self.origin())
            .filter(|(idx, origin)| {
                predicate.for_origin_with_index(
                    origin,
                    PeerGlobalIndex::in_clan_at_position(self.current_node.clan_identifier(), *idx),
                )
            })
            .map(|(_, peer)| self.peers.get(peer).unwrap())
            .collect()
    }

    ///
    /// Gets addresses of the peers from the current node clan excluding the ones in specified position
    ///
    pub fn get_peer_addresses(
        &self,
        protocol: Protocol,
        predicate: PeerFilterPredicate,
    ) -> Vec<Address> {
        self.get_peers_info(predicate)
            .iter()
            .map(|peer_info| peer_info.get_address(protocol).unwrap())
            .collect()
    }

    ///
    /// Gets socket address of the node by specified origin
    ///
    pub fn get_address_by_origin(&self, protocol: Protocol, origin: &Origin) -> Option<Address> {
        self.info_by_origin(origin)
            .and_then(|peer| peer.get_address(protocol))
    }

    ///
    /// Gets socket address of the peer from current node clan at the specified position
    ///
    pub fn get_address_by_position(&self, protocol: Protocol, position: usize) -> Option<Address> {
        self.peer_by_position(position)
            .and_then(|peer| peer.get_address(protocol))
    }

    ///
    /// Gets socket address for the provided protocol of the nodes excluding the provided list
    /// and current node
    ///
    pub fn get_nodes_addresses(
        &self,
        protocol: Protocol,
        predicate: PeerFilterPredicate,
    ) -> Addresses {
        self.get_nodes(predicate)
            .iter()
            .map(|peer_info| peer_info.get_address(protocol).unwrap())
            .collect()
    }

    ///
    /// Gets socket address for the provided protocol of the nodes excluding the provided list
    /// and current node
    ///
    pub fn get_nodes(&self, predicate: PeerFilterPredicate) -> Vec<&PeerInfo> {
        self.peers
            .iter()
            .filter(|(k, peer_info)| *k != self.origin() && predicate.apply(peer_info))
            .map(|(_, peer)| peer)
            .collect()
    }

    /// Internal Helpers

    ///
    /// Returns details of the peer corresponding to global index
    ///
    /// If any of indexes exceeds the chain-topology boundaries None is returned
    ///
    pub fn info_by_global_index(&self, peer_index: PeerGlobalIndex) -> Option<&PeerInfo> {
        self.tribes
            .get(peer_index.tribe())
            .map(Tribe::clans)
            .and_then(|clans| clans.get(peer_index.clan()))
            .map(Clan::peers)
            .and_then(|peers| peers.get(peer_index.position()))
            .and_then(|origin| self.peers.get(origin))
    }

    ///
    /// Converts global flattened index to PeerGlobalIndex representing tribe clan position
    /// distribution in network
    ///
    /// If input index is greater or equal to the total nodes in the chain None is returned.
    ///
    pub fn calculate_global_index(&self, flattened_index: usize) -> Option<PeerGlobalIndex> {
        if flattened_index >= self.get_chain_size() {
            return None;
        }
        let clan_size = self.get_committee_size();
        let clans_in_tribe = self.tribes[0].len();

        let position = flattened_index % clan_size;

        // global clan index (tribe_idx * clans_in_tribe + clan_idx)
        let g_clan_index = flattened_index / clan_size;
        // tribe and clan indexes assuming current node was at position(0, 0, nt_peer_position)
        let tribe = g_clan_index / clans_in_tribe;
        let clan = g_clan_index % clans_in_tribe;
        Some(PeerGlobalIndex::new(tribe, clan, position))
    }

    /// Helper APIs to validate chain topology

    pub fn validate_proposer_per_tribe(&self, config: &NetworkConfig) -> Result<(), NetworkError> {
        let mut proposer_per_tribe: HashMap<usize, HashSet<usize>> = HashMap::new();

        for peer in &self.proposers {
            if let Some(peer_info) = self.peers.get(peer) {
                if let Some(clans) = proposer_per_tribe.get_mut(&peer_info.tribe()) {
                    clans.insert(peer_info.clan());
                } else {
                    proposer_per_tribe.insert(peer_info.tribe(), HashSet::from([peer_info.clan()]));
                }
            }
        }

        for (_, v) in proposer_per_tribe.iter() {
            if config.proposer_per_tribe().ne(&v.len()) {
                return Err(NetworkError::NetworkConfigError(
                    "Invalid proposer per tribe".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn validate_proposers_per_clan(&self, config: &NetworkConfig) -> Result<(), NetworkError> {
        let mut proposers_per_clan = HashMap::new();

        for peer in &self.proposers {
            if let Some(peer_info) = self.peers.get(peer) {
                if let Some(origin_count) =
                    proposers_per_clan.get_mut(&(peer_info.tribe(), peer_info.clan()))
                {
                    *origin_count += 1;
                } else {
                    proposers_per_clan.insert((peer_info.tribe(), peer_info.clan()), 1);
                }
            }
        }

        for (_, v) in proposers_per_clan.iter() {
            if config.proposers_per_clan().ne(v) {
                return Err(NetworkError::NetworkConfigError(
                    "Invalid proposers per clan".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn validate_all_peers_info(&self) -> Result<(), NetworkError> {
        for peer_info in self.peers.values() {
            if let Err(e) = peer_info.validate() {
                return Err(NetworkError::NetworkConfigError(e));
            }
        }
        Ok(())
    }

    pub fn validate_chain_topology(
        self,
        config: &NetworkConfig,
    ) -> Result<ChainTopology, NetworkError> {
        if self.tribes.len().ne(&config.tribes()) {
            return Err(NetworkError::NetworkConfigError(
                "invalid tribe size".to_string(),
            ));
        }
        for t in &self.tribes {
            t.validate_tribe(config)?
        }
        self.validate_all_peers_info()?;
        self.validate_proposers(config)?;
        self.validate_ordering_in_clan_tribe()?;
        Ok(self)
    }

    fn validate_proposers(&self, config: &NetworkConfig) -> Result<(), NetworkError> {
        let expected_count =
            config.proposers_per_clan() * config.proposer_per_tribe() * config.tribes();
        if self.proposers.len() != expected_count {
            return Err(NetworkError::NetworkConfigError(format!(
                "Invalid number of proposers. Expected: {}, Actual: {}",
                expected_count,
                self.proposers.len()
            )));
        }
        self.validate_proposer_per_tribe(config)?;
        self.validate_proposers_per_clan(config)
    }

    fn validate_ordering_in_clan_tribe(&self) -> Result<(), NetworkError> {
        for t in &self.tribes {
            for c in t.clans() {
                for p in 0..c.peers().len() {
                    let peer_index = PeerGlobalIndex::new(t.index(), c.index(), p);
                    let peer = self
                        .info_by_global_index(peer_index)
                        .expect("Expected peer by global index");
                    if &c.peers()[p] != peer.id() || peer.global_index() != peer_index {
                        return Err(NetworkError::NetworkConfigError(
                            "Incorrect ordering of the peers in the clan/tribe".to_string(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub enum PeerFilterPredicate<'a> {
    ///
    /// List of flattened indexes of the peers to be ignored, tribe size, and clan size of the chain
    ///
    NotWithFlattenedIndex(&'a [usize], usize, usize),
    /// List of origins to be excluded
    NotWithOrigin(&'a [Origin]),
    /// List of peer positions to be excluded
    NotAtPosition(&'a [usize]),
    /// Clan which peers should be excluded
    NotInClan(ClanIdentifier),
    /// Pass through filter
    Pass,
    And(&'a PeerFilterPredicate<'a>, &'a PeerFilterPredicate<'a>),
}

impl<'a> PeerFilterPredicate<'a> {
    ///
    /// Returns true if predicate is true for the input peer
    ///
    pub fn apply(&self, peer_info: &PeerInfo) -> bool {
        match self {
            PeerFilterPredicate::NotWithOrigin(origins) => !origins.contains(peer_info.id()),
            PeerFilterPredicate::NotInClan(clan_identifier) => {
                *clan_identifier != peer_info.clan_identifier()
            }
            PeerFilterPredicate::Pass => true,
            PeerFilterPredicate::NotWithFlattenedIndex(indexes, tribe_size, clan_size) => peer_info
                .global_index()
                .flatten(*tribe_size, *clan_size)
                .map(|index| !indexes.contains(&index))
                .unwrap_or(false),
            PeerFilterPredicate::NotAtPosition(positions) => {
                !positions.contains(&peer_info.position())
            }
            PeerFilterPredicate::And(p1, p2) => p1.apply(peer_info) && p2.apply(peer_info),
        }
    }

    pub fn for_origin_with_index(&self, origin: &Origin, global_index: PeerGlobalIndex) -> bool {
        match self {
            PeerFilterPredicate::NotWithOrigin(origins) => !origins.contains(origin),
            PeerFilterPredicate::NotInClan(clan_identifier) => {
                global_index.clan_identifier().ne(clan_identifier)
            }
            PeerFilterPredicate::Pass => true,
            PeerFilterPredicate::NotWithFlattenedIndex(indexes, tribe_size, clan_size) => {
                global_index
                    .flatten(*tribe_size, *clan_size)
                    .map(|index| !indexes.contains(&index))
                    .unwrap_or(false)
            }
            PeerFilterPredicate::NotAtPosition(positions) => {
                !positions.contains(&global_index.position())
            }
            PeerFilterPredicate::And(p1, p2) => {
                p1.for_origin_with_index(origin, global_index)
                    && p2.for_origin_with_index(origin, global_index)
            }
        }
    }
}
