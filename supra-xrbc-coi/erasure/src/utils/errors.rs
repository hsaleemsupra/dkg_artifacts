use thiserror::Error;

#[derive(Debug, Error)]
pub enum FECError {
    #[error("{0}")]
    FailedToEncode(String),
    #[error("{0}")]
    FailedToDecode(String),
    #[error("Not enough chunk to proceed")]
    NotEnoughData,
    #[error("{0}")]
    ConfigError(String),
}
