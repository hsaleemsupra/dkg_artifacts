use influxdb2::RequestError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum InfluxDBError {
    #[error("General Error: {0}")]
    GeneralError(String),

    #[error("Not all configuration parameter are setup correctly")]
    ConfigEmptyValue,

    #[error("{0}")]
    InfluxRequestError(RequestError),

    #[error("Organization {0} doesn't exist")]
    OrganizationAbsent(String),
}
