use thiserror::Error;
use socrypto::{Identity};

#[derive(Error, Debug)]
pub enum CSDeliverError {
    #[error("General err:{0}")]
    GeneralError(String),
    #[error("Unable to verify chunk for sender: {0}")]
    ChunkVerificationError(Identity),
    #[error("Serialization error:{0}")]
    SerializationError(String),
    #[error("Deserialization error:{0}")]
    DeserializationError(String),
}