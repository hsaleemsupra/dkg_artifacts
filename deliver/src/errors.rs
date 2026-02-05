use thiserror::Error;
use socrypto::{Hash};

#[derive(Error, Debug)]
pub enum DeliverError {
    #[error("General err:{0}")]
    GeneralError(String),
    #[error("Unable to verify chunk with root: {0}")]
    ChunkVerificationError(Hash),
    #[error("Serialization error:{0}")]
    SerializationError(String),
    #[error("Deserialization error:{0}")]
    DeserializationError(String),
}