use crypto::error::CryptoError;
use primitives::error::CommonError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArbiterError {
    #[error("Failed to send input data: {0}")]
    SendError(String),

    #[error("{0}")]
    CommonError(#[from] CommonError),

    #[error("{0}")]
    CryptoError(#[from] CryptoError),

    #[error("{0}")]
    InvalidMessage(String),
}
