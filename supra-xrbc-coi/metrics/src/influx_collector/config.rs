use crate::influx_collector::error::InfluxDBError;
use crate::influx_collector::InfluxDBResult;

pub struct InfluxDBConfig {
    host: String,
    org: String,
    token: String,
    bucket: String,
}

impl InfluxDBConfig {
    pub fn new() -> InfluxDBResult<Self> {
        match (
            dotenv::var("INFLUXDB_HOST"),
            dotenv::var("INFLUXDB_ORG"),
            dotenv::var("INFLUXDB_TOKEN"),
            dotenv::var("INFLUXDB_BUCKET"),
        ) {
            (Ok(host), Ok(org), Ok(token), Ok(bucket)) => Ok(Self {
                host,
                org,
                token,
                bucket,
            }),
            _ => Err(InfluxDBError::ConfigEmptyValue),
        }
    }

    pub fn host(&self) -> &String {
        &self.host
    }

    pub fn org(&self) -> &String {
        &self.org
    }

    pub fn token(&self) -> &String {
        &self.token
    }

    pub fn bucket(&self) -> &String {
        &self.bucket
    }
}
