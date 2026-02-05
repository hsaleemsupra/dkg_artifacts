use crypto::traits::NodeIdentityInterface;
use crypto::NodeIdentity;
use primitives::{is_valid_port, Origin, Protocol, Stringify};
use primitives::{ClanIdentifier, PeerGlobalIndex};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::net::SocketAddr;
use std::str::FromStr;

pub const XRBC_DEFAULT_PORT: u16 = 3050;
pub const COI_DEFAULT_PORT: u16 = 4040;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub struct PeerInfo {
    id: Origin,
    address: String,
    ports: Vec<u16>,
    position: usize,
    clan: usize,
    tribe: usize,
    role: Role,
}

impl Display for PeerInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PeerInfo ({}, {:?}, {}, {:?}, {:?})",
            self.global_index(),
            self.role(),
            self.id.hex_display(),
            self.address,
            self.ports
        )
    }
}

impl PeerInfo {
    pub fn new(id: Origin) -> PeerInfo {
        PeerInfo {
            id,
            address: "".to_string(),
            ports: vec![u16::MAX, u16::MAX],
            position: usize::MAX,
            clan: usize::MAX,
            tribe: usize::MAX,
            role: Role::Basic,
        }
    }

    pub fn local(id: Origin) -> PeerInfo {
        PeerInfo {
            id,
            address: "127.0.0.1".to_string(),
            ports: vec![XRBC_DEFAULT_PORT, COI_DEFAULT_PORT],
            position: 0,
            clan: 0,
            tribe: 0,
            role: Role::Basic,
        }
    }

    pub fn is_from_same_clan(&self, other: &PeerInfo) -> bool {
        self.tribe.eq(&other.tribe) && self.clan.eq(&other.clan)
    }

    pub fn get_address(&self, protocol: Protocol) -> Option<SocketAddr> {
        let full_address = format!("{}:{}", self.address, self.port(protocol));
        SocketAddr::from_str(&full_address).ok()
    }

    pub fn get_ip(&self) -> String {
        self.address.clone()
    }

    pub fn ip(&self) -> &String {
        &self.address
    }

    pub fn clan_identifier(&self) -> ClanIdentifier {
        ClanIdentifier {
            tribe: self.tribe,
            clan: self.clan,
        }
    }

    pub fn global_index(&self) -> PeerGlobalIndex {
        PeerGlobalIndex::new(self.tribe, self.clan, self.position)
    }

    pub fn validate(&self) -> Result<(), String> {
        NodeIdentity::is_valid_public_key(&self.id).map_err(|e| format!("{:?}", e))?;
        let has_valid_ports = self.ports.iter().all(is_valid_port);
        let has_unique_ports = self.ports.iter().collect::<HashSet<_>>().len() == self.ports.len();
        let is_valid = !self.ports.is_empty()
            && has_valid_ports
            && has_unique_ports
            && self.get_address(Protocol::XRBC).is_some()
            && self.position != usize::MAX
            && self.clan != usize::MAX
            && self.tribe != usize::MAX;
        is_valid
            .then_some(())
            .ok_or_else(|| format!("Invalid peer info, {}", self))
    }

    pub fn is_proposer(&self) -> bool {
        self.role == Role::Leader
    }

    pub fn is_block_proposer(&self) -> bool {
        self.role == Role::BlockProposer
    }

    pub fn id(&self) -> &Origin {
        &self.id
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn tribe(&self) -> usize {
        self.tribe
    }

    pub fn clan(&self) -> usize {
        self.clan
    }

    pub fn role(&self) -> &Role {
        &self.role
    }

    pub fn port(&self, protocol: Protocol) -> u16 {
        *self.ports.get(protocol.index()).unwrap()
    }

    pub fn set_id(&mut self, id: Origin) {
        self.id = id;
    }

    pub fn set_port(&mut self, protocol: Protocol, port: u16) {
        self.ports[protocol.index()] = port;
    }

    pub fn set_address(&mut self, address: String) {
        self.address = address;
    }

    pub fn set_position(&mut self, position: usize) {
        self.position = position;
    }

    pub fn set_tribe(&mut self, tribe: usize) {
        self.tribe = tribe;
    }

    pub fn set_clan(&mut self, clan: usize) {
        self.clan = clan;
    }

    pub fn set_role(&mut self, role: Role) {
        self.role = role;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
pub enum Role {
    Leader,
    Basic,
    BlockProposer,
}

#[cfg(test)]
#[path = "tests/peer_info_tests.rs"]
mod peer_info_tests;
