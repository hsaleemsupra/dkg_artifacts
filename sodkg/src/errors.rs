use crypto::dealing::Hash;
use socrypto::Identity;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DkgError {
    #[error("General err:{0}")]
    GeneralError(String),
    #[error("Error during dealing verification err:{0}")]
    DealingVerificationError(String),
    #[error("Error during public share verification err:{0}")]
    PublicShareVerificationError(String),
    #[error("Error during partial signature verification err:{0}")]
    PartialSignVerificationError(String),
    #[error("Error during Class Group public info verification. Err:{0}")]
    ClassGroupPubVerificationError(String),
    #[error("Unexpected input bytes length: {0}")]
    SupraCryptoError(#[from] socrypto::SupraCryptoError),
    #[error("Unexpected error during NiDKG process: {0}")]
    NiDkgError(#[from] crypto::errors::DkgError),
    #[error("Unexpected error during Deliver process: {0}")]
    DeliverError(#[from] deliver::errors::DeliverError),
    #[error("Unexpected error during CS Deliver process: {0}")]
    CSDeliverError(#[from] cs_deliver::errors::CSDeliverError),
    #[error("Unexpected error during BLS sign aggregation: {0}")]
    BlsAggregationError(#[from] AggregationError),
    #[error("Unexpected error during Smr tx conversion error: {0}")]
    TransactionConversionError(String),
    #[error("Unexpected error during Smr tx creation error: {0}")]
    TransactionCreationError(#[from] crate::sosmr_types::SmrError),
    #[error("Unexpected error during digest: {0}")]
    DigestError(#[from] std::array::TryFromSliceError),
    #[error("Unexpected error during signing: {0}")]
    SignError(String),
    #[error(
        "Unexpected availability proof from node: {0}. The node have not received dealing from {0}"
    )]
    UnexpectedAvailabilityProof(Identity),
    #[error("Invalid availability proof hash, expected: {expected:?}, actual: {actual:?}")]
    InvalidAvailabilityProofHash { expected: Hash, actual: Hash },
    #[error("Failed to verify aggregated proof for the dealing from node {0}")]
    InvalidAvailabilityProof(Identity),
    #[error("Error during encrypted dealing verification err:{0}")]
    EncryptedDealingVerificationError(String),
}

#[derive(Error, Debug)]
pub enum AggregationError {
    #[error("General err:{0}")]
    GeneralError(String),
}
