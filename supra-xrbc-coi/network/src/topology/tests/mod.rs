use crate::topology::config::NetworkConfig;
use crate::topology::peer_info::{PeerInfo, Role, COI_DEFAULT_PORT, XRBC_DEFAULT_PORT};
use crate::topology::ChainTopology;
use crypto::traits::NodeIdentityInterface;
use crypto::NodeIdentity;
use primitives::{Origin, PeerGlobalIndex, Protocol};
use rand::{thread_rng, RngCore};
use std::collections::{HashMap, HashSet};

#[cfg(test)]
mod topology;

pub struct TopologyGenerator {
    identities: HashMap<PeerGlobalIndex, NodeIdentity>,
    peers: Vec<PeerInfo>,
    current_identity: Option<NodeIdentity>,
    current_peer_index: PeerGlobalIndex,
    current_node_role: Role,
    config: NetworkConfig,
}

impl TopologyGenerator {
    pub fn new(
        current_node_role: Role,
        peer_index: PeerGlobalIndex,
        config: NetworkConfig,
    ) -> Self {
        config
            .validate()
            .expect("Invalid config to generate topology");
        TopologyGenerator {
            identities: HashMap::new(),
            peers: vec![],
            current_identity: None,
            current_peer_index: peer_index,
            current_node_role,
            config,
        }
    }

    pub fn generate_random_topology(
        current_node_role: Role,
        peer_index: PeerGlobalIndex,
        config: &NetworkConfig,
    ) -> (ChainTopology, NodeIdentity) {
        let (network_peers, identity) = TopologyGenerator::generate_random_topology_peers(
            current_node_role,
            peer_index,
            config,
        );

        let current_origin = identity.public_key();
        let chain_topology = ChainTopology::new(config, network_peers, &current_origin)
            .expect("Failed to generate random topology");

        (chain_topology, identity)
    }

    pub fn generate_random_topology_peers(
        current_node_role: Role,
        peer_index: PeerGlobalIndex,
        config: &NetworkConfig,
    ) -> (HashMap<Origin, PeerInfo>, NodeIdentity) {
        let mut generator = TopologyGenerator::new(current_node_role, peer_index, config.clone());
        generator.run();
        (
            generator.get_network_peers(),
            generator.current_identity.unwrap(),
        )
    }

    pub fn topology_for_peer(&self, peer_index: PeerGlobalIndex) -> (ChainTopology, NodeIdentity) {
        let identity = self
            .identities
            .get(&peer_index)
            .expect("Peer with index exists");
        let chain_topology = ChainTopology::new(
            &self.config,
            self.get_network_peers(),
            &identity.public_key(),
        )
        .expect("Failed to generate random topology");

        (chain_topology, identity.clone())
    }

    pub fn get_origin(&self, peer_index: &PeerGlobalIndex) -> Origin {
        self.identities.get(peer_index).unwrap().public_key()
    }

    pub fn network_config(&self) -> &NetworkConfig {
        &self.config
    }

    pub fn get_broadcaster_index(&self) -> PeerGlobalIndex {
        self.peers
            .iter()
            .find(|peer| peer.is_proposer())
            .map(|peer| peer.global_index())
            .unwrap()
    }

    pub fn identities(&self) -> &HashMap<PeerGlobalIndex, NodeIdentity> {
        &self.identities
    }

    pub fn run(&mut self) {
        for tribe in 0..self.config.tribes() {
            let mut tribe_peers = self.generate_tribe_peers(
                tribe,
                self.config.clans(),
                self.config.clan_size(),
                self.config.proposer_per_tribe(),
                self.config.proposers_per_clan(),
            );
            self.peers.append(&mut tribe_peers);
        }
        self.assign_chain_block_proposer();
    }

    pub fn get_network_peers(&self) -> HashMap<Origin, PeerInfo> {
        self.peers
            .iter()
            .cloned()
            .map(|peer| (*peer.id(), peer))
            .collect::<HashMap<Origin, PeerInfo>>()
    }

    fn generate_clan_peers(
        &mut self,
        tribe: usize,
        clan: usize,
        clan_size: usize,
    ) -> Vec<PeerInfo> {
        let mut peers = Vec::<PeerInfo>::new();
        for i in 0..clan_size {
            peers.push(self.generate_peer_info(i, clan, tribe));
        }
        peers
    }

    fn generate_peer_info(&mut self, position: usize, clan_id: usize, tribe_id: usize) -> PeerInfo {
        let identity = NodeIdentity::random();
        let origin = identity.public_key();
        let mut peer_info = PeerInfo::local(origin);
        peer_info.set_position(position);
        peer_info.set_tribe(tribe_id);
        peer_info.set_clan(clan_id);
        peer_info.set_role(Role::Basic);
        peer_info.set_port(
            Protocol::XRBC,
            self.get_port(Protocol::XRBC, tribe_id, clan_id, position),
        );
        peer_info.set_port(
            Protocol::COI,
            self.get_port(Protocol::COI, tribe_id, clan_id, position),
        );
        let _ = self
            .identities
            .insert(peer_info.global_index(), identity.clone());
        if peer_info.global_index() == self.current_peer_index {
            peer_info.set_role(self.current_node_role.clone());
            self.current_identity = Some(identity);
        }
        peer_info
    }

    fn get_port(&self, protocol: Protocol, tribe: usize, clan: usize, position: usize) -> u16 {
        let port = 100 * tribe as u16 + 10 * clan as u16 + position as u16;
        match protocol {
            Protocol::XRBC => XRBC_DEFAULT_PORT + port,
            Protocol::COI => COI_DEFAULT_PORT + port,
        }
    }

    fn generate_tribe_peers(
        &mut self,
        tribe: usize,
        tribe_size: usize,
        clan_size: usize,
        mut proposers_in_tribe: usize,
        proposers_in_clan: usize,
    ) -> Vec<PeerInfo> {
        let mut tribe_peers = Vec::<Vec<PeerInfo>>::new();
        for clan in 0..tribe_size {
            tribe_peers.push(self.generate_clan_peers(tribe, clan, clan_size))
        }
        let mut ignore = None;
        let clan = self.current_peer_index.clan();
        println!("Generate roles");
        if tribe == self.current_peer_index.tribe() && self.current_node_role == Role::Leader {
            proposers_in_tribe -= 1;
            self.assign_clan_proposers(&mut tribe_peers[clan], proposers_in_clan);
            ignore = Some(clan);
        } else if self.current_node_role != Role::Leader && proposers_in_clan == clan_size {
            ignore = Some(clan)
        }
        println!("Ignore clan: {:?}", ignore);
        let random_set =
            TopologyGenerator::generate_random_set(tribe_size, ignore, proposers_in_tribe);
        println!("Generate roles for clans: {:?}", random_set);
        random_set
            .into_iter()
            .for_each(|i| self.assign_clan_proposers(&mut tribe_peers[i], proposers_in_clan));
        tribe_peers.into_iter().flatten().collect()
    }

    fn assign_chain_block_proposer(&mut self) {
        if self.current_node_role == Role::BlockProposer {
            return;
        }
        for peer in &mut self.peers {
            if !peer.is_proposer() && self.current_peer_index != peer.global_index() {
                peer.set_role(Role::BlockProposer);
                break;
            }
        }
    }

    fn assign_clan_proposers(&self, peers: &mut Vec<PeerInfo>, mut proposers: usize) {
        assert!(proposers <= peers.len());
        let mut ignore = None;
        if self.current_peer_index.clan_identifier() == peers[0].clan_identifier() {
            // role of the current node has already been assigned when peer info was created
            // so we are reducing # of proposers, as the node will be skipped as well
            ignore = Some(self.current_peer_index.position());
            proposers -= (self.current_node_role == Role::Leader) as usize;
        }
        let random_set = TopologyGenerator::generate_random_set(peers.len(), ignore, proposers);
        random_set
            .into_iter()
            .for_each(|i| peers[i].set_role(Role::Leader));
    }

    fn generate_random_set(
        value_upper_bound: usize,
        ignore: Option<usize>,
        count: usize,
    ) -> HashSet<usize> {
        let mut set = HashSet::new();
        while set.len() != count {
            let mut rand = thread_rng();
            let next_clan = (rand.next_u64() as usize) % value_upper_bound;
            if Some(next_clan) == ignore {
                continue;
            }
            set.insert(next_clan);
        }
        set
    }
}
