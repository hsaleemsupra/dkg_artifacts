use crate::bls12381::key_pop_zk::PopZkError as PopZkErrorBls12381;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DkgError {
    #[error("General err:{0}")]
    GeneralError(String),
    #[error("Error during dealing verification err:{0}")]
    DealingVerificationError(String),
    #[error("Error during public share verification err:{0}")]
    PublicShareVerificationError(String),
    #[error("Error during serialization err:{0}")]
    SerializationError(String),
    #[error("Error during deserialization err:{0}")]
    DeserializationError(String),
    #[error("Error during aggregation err:{0}")]
    AggregationError(String),
    #[error("{0:?}")]
    PopZkError12381(PopZkErrorBls12381),
    #[error("{0}")]
    ClassGroupTypeError(&'static str),
    #[error("Error during encrypted dealing generation err:{0}")]
    EncryptedDealingGenerationError(String),
    #[error("Error during encrypted dealing verification err:{0}")]
    EncryptedDealingVerificationError(String),
}
