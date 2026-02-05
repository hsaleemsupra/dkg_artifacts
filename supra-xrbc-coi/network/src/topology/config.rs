use serde::{Deserialize, Serialize};

const MIN_NON_BATCH_PROPOSER_NODES_IN_SINGLE_TRIBE_CLAN: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Total Tribes in Chain
    tribes: usize,
    /// Total clans in tribe
    clans: usize,
    /// Total nodes on clan
    clan_size: usize,
    /// Total # of proposer clans per tribe
    proposers_per_tribe: usize,
    /// Total number of proposers per clan,
    proposers_per_clan: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self::new(1, 1, 125, 1, 5)
    }
}

impl NetworkConfig {
    pub fn new(
        tribes: usize,
        clans: usize,
        clan_size: usize,
        proposers_per_tribe: usize,
        proposers_per_clan: usize,
    ) -> NetworkConfig {
        Self {
            tribes,
            clans,
            clan_size,
            proposers_per_tribe,
            proposers_per_clan,
        }
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.total_nodes() == 0 {
            Err(format!(
                "tribe({}), clan({}) or clan size({}) can not be 0",
                self.tribes, self.clans, self.clan_size
            ))
        } else if self.clan_size < self.proposers_per_clan {
            Err(format!(
                "Number of proposers per clan ({}) exceeds clan size ({})",
                self.proposers_per_clan, self.clan_size
            ))
        } else if self.clans < self.proposers_per_tribe {
            Err(format!(
                "Number of proposers clan per tribe ({}) exceeds clan per tribe ({})",
                self.proposers_per_tribe, self.clans
            ))
        } else if (self.clan_size - MIN_NON_BATCH_PROPOSER_NODES_IN_SINGLE_TRIBE_CLAN)
            < self.proposers_per_clan
            && self.clans == 1
        {
            Err(format!(
                "With current configuration {:?} single clan tribe can support max {} proposers per clan.",
                self,
                self.clan_size - MIN_NON_BATCH_PROPOSER_NODES_IN_SINGLE_TRIBE_CLAN
            ))
        } else if self.clan_size == self.proposers_per_clan
            && self.clans == self.proposers_per_tribe
        {
            Err(format!(
                "With current configuration {:?} max {} proposer clans per tribe is supported.",
                self,
                self.clans - 1
            ))
        } else {
            Ok(())
        }
    }

    pub fn total_nodes(&self) -> usize {
        self.tribes * self.clans * self.clan_size
    }

    pub fn tribes(&self) -> usize {
        self.tribes
    }

    pub fn clans(&self) -> usize {
        self.clans
    }

    pub fn clan_size(&self) -> usize {
        self.clan_size
    }

    pub fn proposer_per_tribe(&self) -> usize {
        self.proposers_per_tribe
    }

    pub fn proposers_per_clan(&self) -> usize {
        self.proposers_per_clan
    }

    #[cfg(feature = "test")]
    pub fn invalid_config() -> Self {
        NetworkConfig {
            tribes: 0,
            ..NetworkConfig::default()
        }
    }

    ///
    /// Returns Network configuration which has 5 peers in total in 1 tribe ana 1 clan with 1 leader
    /// Available only for tests when "test" feature is enabled.
    ///
    // #[cfg(feature = "test")]
    pub fn small() -> Self {
        Self {
            tribes: 1,
            clans: 1,
            clan_size: 5,
            proposers_per_tribe: 1,
            proposers_per_clan: 1,
        }
    }
}

#[test]
fn check_config_validity() {
    let default = NetworkConfig::default();
    assert!(default.validate().is_ok());

    let invalid_tribe_size = NetworkConfig {
        tribes: 0,
        ..NetworkConfig::default()
    };
    assert!(invalid_tribe_size.validate().is_err());

    let invalid_clan_count = NetworkConfig {
        clans: 0,
        ..NetworkConfig::default()
    };
    assert!(invalid_clan_count.validate().is_err());

    let invalid_clan_size = NetworkConfig {
        clan_size: 0,
        ..NetworkConfig::default()
    };
    assert!(invalid_clan_size.validate().is_err());

    let invalid_proposers_per_tribe = NetworkConfig {
        clans: 5,
        proposers_per_tribe: 6,
        ..NetworkConfig::default()
    };
    assert!(invalid_proposers_per_tribe.validate().is_err());

    let invalid_proposers_per_clan = NetworkConfig {
        clan_size: 5,
        proposers_per_clan: 6,
        ..NetworkConfig::default()
    };
    assert!(invalid_proposers_per_clan.validate().is_err());

    let invalid_proposers_per_clan = NetworkConfig {
        tribes: 1,
        clans: 1,
        clan_size: 5,
        proposers_per_tribe: 1,
        proposers_per_clan: 5,
    };
    assert!(invalid_proposers_per_clan.validate().is_err());

    let invalid_proposers_per_tribe = NetworkConfig {
        tribes: 1,
        clans: 2,
        clan_size: 5,
        proposers_per_tribe: 2,
        proposers_per_clan: 5,
    };
    assert!(invalid_proposers_per_tribe.validate().is_err());

    let valid_config = NetworkConfig {
        tribes: 1,
        clans: 3,
        clan_size: 5,
        proposers_per_tribe: 2,
        proposers_per_clan: 5,
    };
    assert!(valid_config.validate().is_ok());

    let valid_config = NetworkConfig {
        tribes: 5,
        clans: 5,
        clan_size: 5,
        proposers_per_tribe: 3,
        proposers_per_clan: 3,
    };
    assert!(valid_config.validate().is_ok());
}
