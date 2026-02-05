use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationSecondsWithFrac};
use std::fmt::{Display, Formatter};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BatchCreationRule {
    Infinite(IntervalTimeout),
    Finite(IntervalTimeout, usize),
    InfiniteLoopBack,
    FiniteLoopBack(usize),
}

impl Display for BatchCreationRule {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            BatchCreationRule::Infinite(time_out) => format!("Infinite({})", time_out),
            BatchCreationRule::Finite(time_out, count) => {
                format!("Finite({}, {})", time_out, count)
            }
            BatchCreationRule::InfiniteLoopBack => "InfiniteLoopBack".to_string(),
            BatchCreationRule::FiniteLoopBack(count) => format!("FiniteLoopBack({})", count),
        };
        write!(f, "{}", str)
    }
}

impl Default for BatchCreationRule {
    fn default() -> Self {
        let payload_frequency = IntervalTimeout {
            timeout_in_secs: Duration::from_secs_f64(10.0),
        };
        Self::Infinite(payload_frequency)
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntervalTimeout {
    // Frequency to generate the batch in seconds
    #[serde_as(as = "DurationSecondsWithFrac<f64>")]
    timeout_in_secs: Duration,
}

impl Display for IntervalTimeout {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.timeout_in_secs.as_secs_f64().to_string())
    }
}

impl IntervalTimeout {
    pub fn timeout_in_sec(&self) -> Duration {
        self.timeout_in_secs
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadGeneratorConfig {
    rule: BatchCreationRule,
    // Size in bytes in batch
    size_in_bytes: usize,
}

impl Default for PayloadGeneratorConfig {
    fn default() -> Self {
        Self::new(5000000, BatchCreationRule::default())
    }
}

impl PayloadGeneratorConfig {
    pub fn new(size_in_bytes: usize, rule: BatchCreationRule) -> Self {
        Self {
            rule,
            size_in_bytes,
        }
    }

    pub fn size_in_bytes(&self) -> usize {
        self.size_in_bytes
    }

    pub fn rule(&self) -> &BatchCreationRule {
        &self.rule
    }

    #[cfg(feature = "test")]
    pub fn invalid_config() -> Self {
        PayloadGeneratorConfig::new(0, BatchCreationRule::InfiniteLoopBack)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.size_in_bytes == 0 {
            Err("PayloadGeneratorConfig: Batch Size  should be > 0".to_string())
        } else {
            Ok(())
        }
    }
}
