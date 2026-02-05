//! This library is providing the generalise interface to create and log metrics
//! on different project irrespective of where the metrics will be logged.
mod default_logger;
pub mod errors;
mod metric;
pub mod types;

pub use crate::default_logger::{DefaultMetricRegistryClient, LoggerBackendState};
use crate::errors::MetricError;
pub use crate::metric::Metric;
pub use crate::metric::MetricsBuilder;
pub use crate::types::{MetricValue, TagEntry, Tags};
use async_trait::async_trait;
use once_cell::sync::OnceCell;
use std::time::{Duration, SystemTime};

pub type Timestamp = u128;

pub fn nanoseconds_since_unix_epoch() -> Timestamp {
    duration_since_unix_epoch().as_nanos()
}

///
/// Return duration since [UNIX_EPOCH][UNIX_EPOCH]
///
/// [UNIX_EPOCH]: SystemTime::UNIX_EPOCH
///
pub fn duration_since_unix_epoch() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
}

///
/// Metric Registry interface
///
#[async_trait]
pub trait MetricRegistry: Send + Sync {
    /// Add new metrics to registry
    async fn add(&mut self, metric: Metric, timestamp: Timestamp);
    /// Update the value of the metric
    async fn update(&mut self, key: &str, value: MetricValue, timestamp: Timestamp);
    /// Increment the value of the metric
    async fn inc(&mut self, key: &str, value: MetricValue, timestamp: Timestamp);
    /// Append a new metric if one with provided key does not exists
    /// or create a merged version of the metrics and record the value
    async fn record(&mut self, metric: Metric, timestamp: Timestamp);
    /// record current state of the registry
    async fn record_state(&self);
    /// Add tags which will be assigned to all registered metrics by default
    async fn add_tags(&mut self, tags: Vec<TagEntry>);
    /// Api to stop metrics-registry
    async fn stop(&mut self);

    async fn consume_command(&mut self, command: MetricRegistryCommand) {
        match command {
            MetricRegistryCommand::ADD(data, t) => self.add(data, t).await,
            MetricRegistryCommand::UPDATE(key, value, t) => self.update(&key, value, t).await,
            MetricRegistryCommand::INC(key, value, t) => self.inc(&key, value, t).await,
            MetricRegistryCommand::RECORD(metric, t) => self.record(metric, t).await,
            MetricRegistryCommand::RECORD_STATE => self.record_state().await,
            MetricRegistryCommand::ADD_TAGS(data) => self.add_tags(data).await,
            MetricRegistryCommand::STOP => self.stop().await,
        }
    }

    async fn try_init_with_tags(tags: Tags) -> Result<Box<dyn MetricRegistryClient>, MetricError>;
}

pub enum MetricRegistryCommand {
    ADD(Metric, Timestamp),
    UPDATE(String, MetricValue, Timestamp),
    INC(String, MetricValue, Timestamp),
    RECORD(Metric, Timestamp),
    RECORD_STATE,
    ADD_TAGS(Vec<TagEntry>),
    STOP,
}

///
/// Registry Client interface used to submit reqeust to the registry
///
pub trait MetricRegistryClient: Send + Sync {
    /// Add new metrics to registry
    fn add(&self, metric: Metric);
    /// Update the value of the metric if any exists in registry
    fn update(&self, key: &str, value: MetricValue);
    /// Increment the value of the metric
    fn inc_value(&self, key: &str, value: MetricValue);
    /// Record a metric without updating a registry
    fn record(&self, metric: Metric);
    /// Record current state of the registry
    fn record_state(&self);
    /// Add tags which will be assigned to all registered metrics by default
    fn add_tags(&self, tags: Vec<TagEntry>);
    /// Api to stop metrics-registry
    fn stop(&self);
}

/// Dummy Registry
struct NoRegistry;
impl MetricRegistryClient for NoRegistry {
    fn add(&self, _metric: Metric) {}

    fn update(&self, _key: &str, _value: MetricValue) {}

    fn inc_value(&self, _key: &str, _value: MetricValue) {}

    fn record(&self, _metric: Metric) {}

    fn record_state(&self) {}

    fn add_tags(&self, _tags: Vec<TagEntry>) {}

    fn stop(&self) {}
}

static REGISTRY: OnceCell<Box<dyn MetricRegistryClient>> = OnceCell::new();

fn set_registry(new_registry: Box<dyn MetricRegistryClient>) -> Result<(), MetricError> {
    REGISTRY
        .set(new_registry)
        .map_err(|_e| MetricError::MetricRegistryAlreadySet)
}

fn get_registry() -> Option<&'static Box<dyn MetricRegistryClient>> {
    REGISTRY.get()
}

///
/// Public user interface to register metrics registry
///

pub fn try_init() -> Result<(), MetricError> {
    set_registry(Box::new(NoRegistry))
}

pub async fn try_init_with_tags<T: MetricRegistry + 'static>(
    tags: Tags,
) -> Result<(), MetricError> {
    let client = T::try_init_with_tags(tags).await;
    client.and_then(|c| set_registry(c))
}

pub async fn try_init_with_logger() -> Result<(), MetricError> {
    let client = LoggerBackendState::try_init_with_tags(Tags::default()).await;
    client.and_then(|c| set_registry(c))
}

///
/// Public user interface to log metrics
///

pub fn add(metric: Metric) {
    get_registry().map(|registry| registry.add(metric));
}

pub fn update(key: &str, value: MetricValue) {
    let _ = get_registry().map(|registry| registry.update(key, value));
}

pub fn inc(key: &str, value: MetricValue) {
    let _ = get_registry().map(|registry| registry.inc_value(key, value));
}

pub fn record(metric: Metric) {
    let _ = get_registry().map(|registry| registry.record(metric));
}

pub fn record_state() {
    let _ = get_registry().map(|registry| registry.record_state());
}

pub fn add_tags(tags: Vec<TagEntry>) {
    let _ = get_registry().map(|registry| registry.add_tags(tags));
}

#[cfg(test)]
mod tests {
    use crate::metric::MetricsBuilder;
    use crate::{add, inc, record, try_init_with_logger, update, MetricValue};
    use std::thread;

    use std::time::Duration;

    #[tokio::test]
    async fn try_init() {
        let _ = env_logger::try_init();
        let result = try_init_with_logger().await;
        thread::sleep(Duration::from_secs(5));
        assert!(result.is_ok());
        add(MetricsBuilder::new()
            .with_key("test1")
            .with_value(MetricValue::Int(12))
            .build()
            .unwrap());
        thread::spawn(|| {
            inc("test1", MetricValue::Int(12));
        });
        thread::sleep(Duration::from_secs(2));
        thread::spawn(|| {
            inc("test1", MetricValue::Int(12));
        });
        thread::sleep(Duration::from_secs(2));
        thread::spawn(|| {
            record(
                MetricsBuilder::new()
                    .with_key("test1")
                    .with_value(MetricValue::Int(12))
                    .with_tag((
                        "source".to_string(),
                        format!("{:?}", thread::current().id()),
                    ))
                    .build()
                    .unwrap(),
            );
        });
        thread::sleep(Duration::from_secs(2));
        thread::spawn(|| {
            inc("test1", MetricValue::Int(12));
        });
        thread::sleep(Duration::from_secs(2));
        thread::spawn(|| {
            inc("test1", MetricValue::Int(12));
        });
        thread::sleep(Duration::from_secs(2));
        thread::spawn(|| {
            update("test1", MetricValue::Int(50));
        });
        thread::sleep(Duration::from_secs(2));
        inc("test1", MetricValue::Int(24));
        thread::sleep(Duration::from_secs(10));
    }
}
