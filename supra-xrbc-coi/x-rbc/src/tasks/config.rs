use crate::tasks::codec::SupraDeliveryErasureCodecSchema;
use erasure::utils::codec_trait::{Codec, Setting};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::Duration;

pub const DEFAULT_EXCLUDED_NODE_COUNT: usize = 2; // excluding broadcaster and current node

///
/// RBC Task configuration to handle use-case of RBC state idling
///
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RBCTaskStateTimeConfig {
    ///
    /// Timeout after which state-idling should be followed up
    /// Useful when it is required
    ///     - to re-broadcast messages to check-lifeness of the network
    ///     - to implement waiting logic in particular state
    ///
    #[serde(serialize_with = "serialize_u64_duration")]
    #[serde(deserialize_with = "deserialize_u64_duration")]
    pub state_idle_timeout: Duration,
}

impl RBCTaskStateTimeConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.state_idle_timeout.is_zero() {
            return Err("Task state idling timeout should be greater than 0".to_string());
        }
        Ok(())
    }

    pub fn new(duration: Duration) -> Self {
        Self {
            state_idle_timeout: duration,
        }
    }
}

impl Default for RBCTaskStateTimeConfig {
    fn default() -> Self {
        Self::new(Duration::from_secs(1))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GarbageCollectorConfig {
    /// Timeout of the state-tasks
    #[serde(serialize_with = "serialize_u64_duration")]
    #[serde(deserialize_with = "deserialize_u64_duration")]
    pub task_stale_timeout: Duration,
    /// Timeout to check tasks active time
    #[serde(serialize_with = "serialize_u64_duration")]
    #[serde(deserialize_with = "deserialize_u64_duration")]
    pub garbage_collection_timeout: Duration,
}

fn serialize_u64_duration<S>(d: &Duration, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_u64(d.as_secs())
}

fn deserialize_u64_duration<'de, D>(d: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    u64::deserialize(d).map(Duration::from_secs)
}

impl GarbageCollectorConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.task_stale_timeout.is_zero() {
            return Err("Task stale timeout should be greater than 0".to_string());
        } else if self.garbage_collection_timeout.is_zero() {
            return Err("Garbage collection timeout should be greater than 0".to_string());
        }
        Ok(())
    }
}

impl Default for GarbageCollectorConfig {
    fn default() -> Self {
        GarbageCollectorConfig {
            task_stale_timeout: Duration::from_secs(3),
            garbage_collection_timeout: Duration::from_secs(5),
        }
    }
}

///
/// Dissemination rule specify the Default Full peer list or Partial list
///
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum DisseminationRule {
    /// Disseminate payload as a one piece
    Full,
    /// Disseminate payload as chunks
    Partial(EchoTarget),
}

impl Default for DisseminationRule {
    fn default() -> Self {
        DisseminationRule::Partial(EchoTarget::All)
    }
}

impl DisseminationRule {
    ///
    /// Returns the configured count of partial peer nodes , None if Rule is set to default Full
    ///
    pub(crate) fn node_count(&self) -> Option<usize> {
        match self {
            DisseminationRule::Full => None,
            DisseminationRule::Partial(echo_target) => echo_target.node_count(),
        }
    }
}

///
/// Dissemination of the echo data in scope of the clan relative the the current node
///
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum EchoTarget {
    /// Disseminate echo-value to the left-side peers and only to the specified number of the nodes
    Left(usize),
    /// Disseminate echo-value to the right-side peers and only to the specified number of the nodes
    Right(usize),
    /// Disseminate echo-value to all peers and only to the specified number of the nodes
    All,
}

impl EchoTarget {
    ///
    /// Returns the configured count of partial peer nodes count
    ///
    pub fn node_count(&self) -> Option<usize> {
        match self {
            EchoTarget::Left(nodes) => Some(*nodes),
            EchoTarget::Right(nodes) => Some(*nodes),
            EchoTarget::All => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SupraDeliveryConfig<C: SupraDeliveryErasureCodecSchema> {
    /// FEC config parameters for committee chunks
    pub committee_erasure_config: <C::DataCodec as Codec>::Setting,
    /// FEC config parameters for network chunks
    pub network_erasure_config: Option<<C::DataCodec as Codec>::Setting>,
    /// Configuration to follow up on staled tasks
    pub garbage_collector_config: GarbageCollectorConfig,
    /// Delivery tasks internal state-idling-timeout configuration
    pub state_idle_time_config: RBCTaskStateTimeConfig,
    /// committee data dissemination rules
    pub dissemination_rule: DisseminationRule,
}

impl<C: SupraDeliveryErasureCodecSchema> SupraDeliveryConfig<C> {
    pub fn new(
        committee_config: <C::DataCodec as Codec>::Setting,
        network_config: Option<<C::DataCodec as Codec>::Setting>,
        garbage_collector_config: GarbageCollectorConfig,
        state_idle_time_config: RBCTaskStateTimeConfig,
        dissemination_rule: DisseminationRule,
    ) -> Self {
        Self {
            committee_erasure_config: committee_config,
            network_erasure_config: network_config,
            garbage_collector_config,
            state_idle_time_config,
            dissemination_rule,
        }
    }

    pub fn get_committee_erasure_config(&self) -> &<C::DataCodec as Codec>::Setting {
        &self.committee_erasure_config
    }

    pub fn get_network_erasure_config(&self) -> &Option<<C::DataCodec as Codec>::Setting> {
        &self.network_erasure_config
    }

    pub fn committee_size(&self) -> usize {
        self.committee_erasure_config.data_shards() + self.committee_erasure_config.parity_shards()
    }

    pub fn network_size(&self) -> usize {
        self.network_erasure_config
            .as_ref()
            .map(|config| config.data_shards() + config.parity_shards() + self.committee_size())
            .unwrap_or(0)
    }

    pub fn has_network_config(&self) -> bool {
        self.network_erasure_config.is_some()
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_task_timeout_parameters()?;
        self.validate_dissemination_rule()?;
        let committee_chunk_count = self.committee_size();
        let network_chunk_count = self
            .network_erasure_config
            .as_ref()
            .map(|config| config.data_shards() + config.parity_shards())
            .unwrap_or(0);
        if committee_chunk_count == 0 {
            Err(format!(
                "Invalid committee erasure encoding settings: {:?}",
                self.committee_erasure_config
            ))
        } else if network_chunk_count == 0 && self.network_erasure_config.is_some() {
            Err(format!(
                "Invalid network erasure encoding settings: {:?}",
                self.network_erasure_config
            ))
        } else if network_chunk_count % committee_chunk_count != 0 {
            Err(format!(
                "Network erasure chunks should be multiple to committee erasure chunks:\
                 committee {} - network {}",
                committee_chunk_count, network_chunk_count
            ))
        } else {
            Ok(())
        }
    }

    ///
    ///
    ///
    fn validate_dissemination_rule(&self) -> Result<(), String> {
        if let Some(nodes) = self.dissemination_rule.node_count() {
            if nodes < self.committee_erasure_config.data_shards()
                || nodes > self.committee_size() - DEFAULT_EXCLUDED_NODE_COUNT
            {
                Err(format!(
                    "at-least {} nodes required to make delivery work properly",
                    self.committee_erasure_config.data_shards()
                ))
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    fn validate_task_timeout_parameters(&self) -> Result<(), String> {
        self.garbage_collector_config.validate()?;
        self.state_idle_time_config.validate()?;
        if self.state_idle_time_config.state_idle_timeout
            > self.garbage_collector_config.task_stale_timeout
        {
            return Err(
                "Task state idling timeout should not be greater than task stale timeout"
                    .to_string(),
            );
        }
        Ok(())
    }
}
