use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("{0}")]
    NetworkConfigError(String),
    #[error("{0}")]
    ChainTopologyError(String),
}
