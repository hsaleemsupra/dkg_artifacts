use crate::errors::MetricError;
use crate::types::MetricValue;
use crate::{
    nanoseconds_since_unix_epoch, Metric, MetricRegistry, MetricRegistryClient,
    MetricRegistryCommand, TagEntry, Tags, Timestamp,
};
use std::collections::HashMap;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tracing_log::log::{error, info, warn};

pub struct LoggerBackendState {
    rx: UnboundedReceiver<MetricRegistryCommand>,
    metrics: HashMap<String, Metric>,
    tags: Tags,
    is_active: bool,
}

impl LoggerBackendState {
    pub(crate) fn new(rx: UnboundedReceiver<MetricRegistryCommand>) -> Self {
        Self {
            rx,
            metrics: Default::default(),
            tags: Default::default(),
            is_active: false,
        }
    }

    pub(crate) async fn run_loop(mut self) {
        self.is_active = true;
        while self.is_active {
            match self.rx.recv().await {
                Some(command) => {
                    self.consume_command(command).await;
                }
                None => {
                    warn!("Metrics Registry input channel has no data");
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl MetricRegistry for LoggerBackendState {
    async fn add(&mut self, metric: Metric, _timestamp: Timestamp) {
        if !self.metrics.contains_key(metric.key()) {
            self.metrics.insert(metric.get_key(), metric);
        } else {
            error!("Metric with provided key already exists: {}", metric.key());
        }
    }

    async fn update(&mut self, key: &str, value: MetricValue, _timestamp: Timestamp) {
        self.metrics.get_mut(key).map_or_else(
            || {
                warn!("No registered metric with key: {:?}", key);
            },
            |old_value| {
                let _ = old_value.update(value).map_err(|e| {
                    error!("Failed to update value: {} - {:?}", key, e);
                });
                info!("{:?}", old_value);
            },
        );
    }

    async fn inc(&mut self, key: &str, value: MetricValue, _timestamp: Timestamp) {
        self.metrics.get_mut(key).map_or_else(
            || {
                warn!("No registered metric with key: {:?}", key);
            },
            |old_value| {
                let _ = old_value.inc(value).map_err(|e| {
                    error!("Failed to increment value: {} - {:?}", key, e);
                });
                info!("{:?}", old_value);
            },
        );
    }

    async fn record(&mut self, metric: Metric, _timestamp: Timestamp) {
        let key = metric.get_key();
        self.metrics.get_mut(&key).map_or_else(
            || {
                warn!("No registered metric with key: {:?}", key);
            },
            |old_value| {
                let _ = old_value.merge(metric).map_or_else(
                    |e| error!("Failed to merge value: {:?}", e),
                    |value| info!("{:?}", value),
                );
            },
        );
    }

    async fn record_state(&self) {}

    async fn add_tags(&mut self, _tags: Vec<TagEntry>) {}

    async fn stop(&mut self) {
        self.is_active = false;
    }

    async fn try_init_with_tags(_tags: Tags) -> Result<Box<dyn MetricRegistryClient>, MetricError> {
        let (tx, rx) = unbounded_channel::<MetricRegistryCommand>();
        let server_state = LoggerBackendState::new(rx);
        let handler = tokio::spawn(LoggerBackendState::run_loop(server_state));
        let client = DefaultMetricRegistryClient::new(tx, handler);
        Ok(Box::new(client))
    }
}

pub struct DefaultMetricRegistryClient {
    tx: UnboundedSender<MetricRegistryCommand>,
    handler: Option<JoinHandle<()>>,
}

impl Drop for DefaultMetricRegistryClient {
    fn drop(&mut self) {
        let _ = self.send(MetricRegistryCommand::STOP);
        let handler = self.handler.take();
        let _ = handler.map(|h| h.abort());
    }
}

impl DefaultMetricRegistryClient {
    pub fn new(tx: UnboundedSender<MetricRegistryCommand>, handler: JoinHandle<()>) -> Self {
        Self {
            tx,
            handler: Some(handler),
        }
    }

    pub(crate) fn send(&self, command: MetricRegistryCommand) {
        let _ = self.tx.send(command).map_err(|_e| {
            error!("No active metric receiver is available");
        });
    }
}

unsafe impl Send for DefaultMetricRegistryClient {}
unsafe impl Sync for DefaultMetricRegistryClient {}

impl MetricRegistryClient for DefaultMetricRegistryClient {
    fn add(&self, metric: Metric) {
        self.send(MetricRegistryCommand::ADD(
            metric,
            nanoseconds_since_unix_epoch(),
        ));
    }

    fn update(&self, key: &str, value: MetricValue) {
        self.send(MetricRegistryCommand::UPDATE(
            key.to_string(),
            value,
            nanoseconds_since_unix_epoch(),
        ));
    }

    fn inc_value(&self, key: &str, value: MetricValue) {
        self.send(MetricRegistryCommand::INC(
            key.to_string(),
            value,
            nanoseconds_since_unix_epoch(),
        ));
    }

    fn record(&self, metric: Metric) {
        self.send(MetricRegistryCommand::RECORD(
            metric,
            nanoseconds_since_unix_epoch(),
        ));
    }

    fn record_state(&self) {
        self.send(MetricRegistryCommand::RECORD_STATE);
    }

    fn add_tags(&self, tags: Vec<TagEntry>) {
        self.send(MetricRegistryCommand::ADD_TAGS(tags));
    }

    fn stop(&self) {
        self.send(MetricRegistryCommand::STOP);
    }
}
