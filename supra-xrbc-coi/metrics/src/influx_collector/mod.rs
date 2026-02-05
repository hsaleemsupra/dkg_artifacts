pub mod backend;
pub mod config;
mod error;

use crate::influx_collector::error::InfluxDBError;

pub type InfluxDBResult<T> = Result<T, InfluxDBError>;
