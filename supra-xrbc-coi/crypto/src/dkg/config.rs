use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DKGConfig {
    /// Threshold parameter of Distributed Key,
    /// Minimum number of shares required to construct threshold signature
    /// Threshold should be grater for the half of the participants number
    threshold: usize,
    /// Total number of nodes participating in Distributed key generation
    participants: usize,
}

impl Default for DKGConfig {
    fn default() -> Self {
        Self::new(63, 125)
    }
}

impl DKGConfig {
    pub fn new(threshold: usize, participants: usize) -> Self {
        Self {
            threshold,
            participants,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if (self.participants / 2) >= self.threshold || self.participants < self.threshold {
            Err(format!(
                "Expected: participants(actual - {}) <= 2 * threshold(actual -{}) - 1",
                self.participants, self.threshold
            ))
        } else {
            Ok(())
        }
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn participants(&self) -> usize {
        self.participants
    }

    #[cfg(feature = "test")]
    pub fn invalid_config() -> Self {
        DKGConfig {
            threshold: 5,
            participants: 12,
        }
    }

    // #[cfg(feature = "test")]
    pub fn small_config() -> Self {
        DKGConfig {
            threshold: 3,
            participants: 5,
        }
    }
}

#[test]
fn check_config_validity() {
    let default = DKGConfig::default();

    assert!(default.validate().is_ok());
    let invalid_config = DKGConfig {
        threshold: 5,
        participants: 15,
    };
    assert!(invalid_config.validate().is_err());

    let invalid_config = DKGConfig {
        threshold: 5,
        participants: 11,
    };
    assert!(invalid_config.validate().is_err());

    let invalid_config = DKGConfig {
        threshold: 5,
        participants: 10,
    };
    assert!(invalid_config.validate().is_err());

    let invalid_config = DKGConfig {
        threshold: 5,
        participants: 4,
    };
    assert!(invalid_config.validate().is_err());

    let valid_config = DKGConfig {
        threshold: 5,
        participants: 9,
    };
    assert!(valid_config.validate().is_ok());

    let valid_config = DKGConfig {
        threshold: 5,
        participants: 8,
    };
    assert!(valid_config.validate().is_ok());
}
