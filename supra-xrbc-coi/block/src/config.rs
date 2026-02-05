use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationSecondsWithFrac};
use std::time::Duration;

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProposerConfig {
    // Frequency to generate the blocks in seconds
    #[serde_as(as = "DurationSecondsWithFrac<f64>")]
    timeout_in_secs: Duration,
    // Max # of batches included in block
    batch_count: usize,
}

impl Default for BlockProposerConfig {
    fn default() -> Self {
        Self::new(10.0, 100)
    }
}

impl BlockProposerConfig {
    pub fn new(timeout_in_secs: f64, batch_count: usize) -> BlockProposerConfig {
        BlockProposerConfig {
            timeout_in_secs: Duration::from_secs_f64(timeout_in_secs),
            batch_count,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.batch_count == 0 {
            Err("BlockProposerConfig: Batch Count  should be > 0".to_string())
        } else if self.timeout_in_secs.is_zero() {
            Err("BlockProposerConfig: block generation timeout should be > 0".to_string())
        } else {
            Ok(())
        }
    }

    pub fn get_timeout_in_secs(&self) -> Duration {
        self.timeout_in_secs
    }

    pub fn get_batch_count(&self) -> usize {
        self.batch_count
    }
    #[cfg(feature = "test")]
    pub fn invalid_config() -> Self {
        BlockProposerConfig::new(0.0, 10)
    }
}

#[test]
fn check_config() {
    let default = BlockProposerConfig::default();
    assert!(default.validate().is_ok());
    let invalid_timeout = BlockProposerConfig::new(0.0, 10);
    assert!(invalid_timeout.validate().is_err());
    let invalid_batch_size = BlockProposerConfig::new(10.0, 0);
    assert!(invalid_batch_size.validate().is_err());
    let valid = BlockProposerConfig::new(10.0, 10);
    assert!(valid.validate().is_ok());
}
