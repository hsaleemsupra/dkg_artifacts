use crate::influx_collector::backend::InfluxBackend;
use crate::influx_collector::config::InfluxDBConfig;
use metrics_logger::{MetricRegistryCommand, Tags};
use tokio::sync::mpsc::unbounded_channel;

fn un_set_influx_config_env() {
    std::env::remove_var("INFLUXDB_HOST");
    std::env::remove_var("INFLUXDB_ORG");
    std::env::remove_var("INFLUXDB_TOKEN");
    std::env::remove_var("INFLUXDB_BUCKET");
}

fn set_influx_config_env() {
    std::env::set_var("INFLUXDB_HOST", "http://localhost:8086");
    std::env::set_var("INFLUXDB_ORG", "");
    std::env::set_var("INFLUXDB_TOKEN", "");
    std::env::set_var("INFLUXDB_BUCKET", "");
}

// #[tokio::test]
// #[should_panic]
// async fn test_influx_backend_panic() {
//     set_influx_config_env();
//     std::env::set_var("INFLUXDB_HOST", "");
//     let conf = InfluxDBConfig::new().unwrap();
//     let (_, rx) = unbounded_channel::<MetricRegistryCommand>();
//     let _ = InfluxBackend::new(conf, rx, Tags::default()).await;
//     un_set_influx_config_env();
// }

#[tokio::test]
async fn test_influx_backend_should_not_panic() {
    set_influx_config_env();

    let conf = InfluxDBConfig::new().unwrap();
    let (_, rx) = unbounded_channel::<MetricRegistryCommand>();
    let backend = InfluxBackend::new(conf, rx, Tags::default()).await;
    assert!(backend.is_err()); // because cannot create bucket

    let conf = InfluxDBConfig::new().unwrap();
    let influx = influxdb2::Client::new(conf.host(), conf.org(), conf.token());
    let bucket = conf.bucket().to_owned();
    let bucket_creation = InfluxBackend::create_bucket_if_not_exist(&influx, bucket.clone()).await;
    assert!(bucket_creation.is_err());

    un_set_influx_config_env();
}
