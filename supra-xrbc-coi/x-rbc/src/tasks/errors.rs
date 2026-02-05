use crypto::error::CryptoError;
use erasure::utils::errors::FECError;
use primitives::error::CommonError;
use primitives::Origin;
use thiserror::Error;
use vec_commitment::errors::CommitmentError;

#[derive(Error, Debug)]
pub enum RBCError {
    #[error("Failed to send input data: {0}")]
    SendError(String),

    #[error("Failed to convert data")]
    ConversionError,

    #[error("{0}")]
    CryptoError(#[from] CryptoError),

    #[error("{0}")]
    CommitmentError(#[from] CommitmentError),

    #[error("{0}")]
    FECError(#[from] FECError),

    #[error("Failed to split encode result into committee and network chunks due to invalid number of chunks")]
    InvalidNumberOfChunks,

    #[error("{0}")]
    MessageProcessingError(String),

    #[error("{0}")]
    CommonError(#[from] CommonError),

    #[error("{0}")]
    InvalidRequest(String),

    #[error("{0}")]
    InvalidPayloadState(String),

    #[error("Invalid deliverable from {0:?}")]
    InvalidDeliverable(Origin),

    #[error("{0}")]
    ProtocolError(String),
}
