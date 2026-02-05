use crate::influx_collector::config::InfluxDBConfig;
use crate::influx_collector::error::InfluxDBError;
use crate::influx_collector::InfluxDBResult;
use async_trait::async_trait;
use futures_lite::{stream, Stream, StreamExt};
use influxdb2::api::organization::ListOrganizationRequest;
use influxdb2::models::{DataPoint, FieldValue, PostBucketRequest};
use influxdb2::Client as InfluxClient;
use log::{info, warn};
use metrics_logger::errors::MetricError;
use metrics_logger::{
    DefaultMetricRegistryClient, Metric, MetricRegistry, MetricRegistryClient,
    MetricRegistryCommand, MetricValue, TagEntry, Tags, Timestamp,
};
use std::thread::sleep;
use std::time::Duration;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

const INFLUX_BACKEND_CLIENT_IDLE_TIME_IN_SECS: u64 = 10;
const MAX_DATA_POINTS: usize = 50;

pub struct InfluxBackend {
    rx: UnboundedReceiver<MetricRegistryCommand>,
    influx: InfluxClient,
    bucket: String,
    tags: Tags,
    is_active: bool,
}

impl InfluxBackend {
    pub async fn new(
        influx_conf: InfluxDBConfig,
        rx: UnboundedReceiver<MetricRegistryCommand>,
        tags: Tags,
    ) -> InfluxDBResult<InfluxBackend> {
        let influx =
            influxdb2::Client::new(influx_conf.host(), influx_conf.org(), influx_conf.token());
        let bucket = influx_conf.bucket().to_owned();
        InfluxBackend::create_bucket_if_not_exist(&influx, bucket.clone()).await?;
        let backend = Self {
            rx,
            influx,
            bucket,
            tags,
            is_active: false,
        };
        Ok(backend)
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
            info!("Sent data to influx");
        }
    }

    pub(crate) fn run_loop_blocking(mut self) {
        self.is_active = true;
        while self.is_active {
            sleep(Duration::from_secs(INFLUX_BACKEND_CLIENT_IDLE_TIME_IN_SECS));
            let mut commands = Vec::new();
            while commands.len() <= MAX_DATA_POINTS {
                let data = self.rx.try_recv();
                if let Ok(command) = data {
                    commands.push(command);
                } else {
                    break;
                }
            }
            info!("Sending data to influx: {}", commands.len());
            let data = stream::iter(self.commands_to_data_points(commands));
            let influx_client = self.influx.clone();
            tokio::spawn(InfluxBackend::send_points(
                influx_client,
                self.bucket.clone(),
                data,
            ));
            info!("Sent data to influx");
        }
    }

    fn commands_to_data_points(&mut self, commands: Vec<MetricRegistryCommand>) -> Vec<DataPoint> {
        commands
            .into_iter()
            .map(|c| match c {
                MetricRegistryCommand::RECORD(v, t) => Some(self.create_data_point(v, t)),
                MetricRegistryCommand::STOP => {
                    self.is_active = false;
                    None
                }
                _ => None,
            })
            .flatten()
            .collect::<Vec<_>>()
    }

    fn create_data_point(&self, metric: Metric, timestamp: Timestamp) -> DataPoint {
        let event = if metric.key().contains("message-size") {
            "message-size"
        } else if metric.key().contains("travel-time") {
            "travel-time"
        } else if metric.key().contains("system") {
            "throughput"
        } else {
            "delivery_metrics"
        };
        let mut d = DataPoint::builder(event).timestamp(timestamp as i64);
        for (k, v) in metric.tags() {
            d = d.tag(k, v);
        }
        for (k, v) in &self.tags {
            d = d.tag(k, v);
        }
        d = d.field(metric.key(), into_influxdb_field(metric.value()));
        d.build().unwrap()
    }

    pub(crate) async fn create_bucket_if_not_exist(
        client: &InfluxClient,
        new_bucket: String,
    ) -> InfluxDBResult<()> {
        let org = client
            .list_organizations(ListOrganizationRequest::default())
            .await
            .map_err(InfluxDBError::InfluxRequestError)?;
        let this_org = org
            .orgs
            .iter()
            .find(|o| o.name == client.org)
            .ok_or(InfluxDBError::OrganizationAbsent(client.org.to_owned()))?;
        let org_id = this_org.id.clone().unwrap();

        let bucket = client
            .list_buckets(None)
            .await
            .map_err(InfluxDBError::InfluxRequestError)?;
        let this_bucket = bucket.buckets.iter().find(|b| b.name == new_bucket);

        if this_bucket.is_none() {
            let new_bucket_req = PostBucketRequest::new(org_id, new_bucket);
            client
                .create_bucket(Some(new_bucket_req))
                .await
                .map_err(InfluxDBError::InfluxRequestError)
        } else {
            Ok(())
        }
    }

    async fn send_points(
        client: InfluxClient,
        bucket: String,
        dp_stream: impl Stream<Item = DataPoint> + Send + Sync + 'static,
    ) {
        if let Err(e) = client.write(bucket.as_str(), dp_stream).await {
            log::warn!("failed to send data to influxdb! {e}");
        }
    }
}

#[async_trait]
impl MetricRegistry for InfluxBackend {
    async fn add(&mut self, _metric: Metric, _timestamp: Timestamp) {
        // convert metrics to data-point and send via client in case local InfluxBackend is not going to store metrics
    }

    async fn update(&mut self, _key: &str, _value: MetricValue, _timestamp: Timestamp) {}

    async fn inc(&mut self, _key: &str, _value: MetricValue, _timestamp: Timestamp) {}

    async fn record(&mut self, metric: Metric, timestamp: Timestamp) {
        let dp = self.create_data_point(metric, timestamp);
        let dp_stream = stream::once(dp);
        Self::send_points(self.influx.clone(), self.bucket.clone(), dp_stream).await;
    }

    async fn record_state(&self) {}

    async fn add_tags(&mut self, tags: Vec<TagEntry>) {
        self.tags.extend(tags)
    }

    async fn stop(&mut self) {
        self.is_active = false
    }

    async fn try_init_with_tags(tags: Tags) -> Result<Box<dyn MetricRegistryClient>, MetricError> {
        let config =
            InfluxDBConfig::new().map_err(|e| MetricError::BackendConfigError(e.to_string()))?;
        let (tx, rx) = unbounded_channel::<MetricRegistryCommand>();
        let influx_backend = InfluxBackend::new(config, rx, tags)
            .await
            .map_err(|e| MetricError::BackendError(e.to_string()))?;
        let handler =
            tokio::task::spawn_blocking(|| InfluxBackend::run_loop_blocking(influx_backend));
        let client = DefaultMetricRegistryClient::new(tx, handler);
        Ok(Box::new(client))
    }
}

fn into_influxdb_field(field: &MetricValue) -> FieldValue {
    match field {
        MetricValue::Bool(b) => FieldValue::Bool(*b),
        MetricValue::Int(number) => FieldValue::I64(*number as i64),
        MetricValue::UInt(number) => FieldValue::I64(*number as i64),
        MetricValue::Int64(number) => FieldValue::I64(*number),
        MetricValue::UInt64(number) => FieldValue::I64(*number as i64),
        MetricValue::Usize(number) => FieldValue::I64(*number as i64),
        MetricValue::Int128(number) => FieldValue::I64(*number as i64),
        MetricValue::UInt128(number) => FieldValue::I64(*number as i64),
        MetricValue::Float32(decimal) => FieldValue::F64(*decimal as f64),
        MetricValue::Float64(decimal) => FieldValue::F64(*decimal),
        MetricValue::String(string) => FieldValue::String(string.to_owned()),
    }
}
