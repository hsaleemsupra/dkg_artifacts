use crate::errors::NetworkError;
use crate::topology::clan::Clan;
use crate::topology::config::NetworkConfig;

#[derive(Clone, Debug)]
pub struct Tribe {
    /// Tribe index in the chain
    idx: usize,
    /// Clans of the tribe order by position
    clans: Vec<Clan>,
}

impl Tribe {
    pub(crate) fn new(idx: usize, clans: Vec<Clan>) -> Self {
        Self { idx, clans }
    }

    pub fn validate_tribe(&self, config: &NetworkConfig) -> Result<(), NetworkError> {
        if self.clans.len().ne(&config.clans()) {
            return Err(NetworkError::NetworkConfigError(
                "Invalid clan size".to_string(),
            ));
        }
        for c in &self.clans {
            c.validate_clan(config)?
        }
        Ok(())
    }

    pub fn index(&self) -> usize {
        self.idx
    }

    pub fn clans(&self) -> &Vec<Clan> {
        &self.clans
    }

    pub fn len(&self) -> usize {
        self.clans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.clans.is_empty()
    }
}
