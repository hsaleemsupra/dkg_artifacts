use crate::errors::NetworkError;
use crate::topology::config::NetworkConfig;
use primitives::Origin;

#[derive(Clone, Debug)]
pub struct Clan {
    /// Clan index in the tribe
    idx: usize,
    /// Peers of the clans ordered by their position in the clan
    peers: Vec<Origin>,
}

impl Clan {
    pub(crate) fn new(idx: usize, peers: Vec<Origin>) -> Self {
        Self { idx, peers }
    }
    pub fn validate_clan(&self, config: &NetworkConfig) -> Result<(), NetworkError> {
        if self.peers.len().ne(&config.clan_size()) {
            return Err(NetworkError::NetworkConfigError(
                "Invalid clan size".to_string(),
            ));
        }
        Ok(())
    }

    pub fn index(&self) -> usize {
        self.idx
    }

    pub fn peers(&self) -> &Vec<Origin> {
        &self.peers
    }
}
