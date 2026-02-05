use socrypto::SupraCryptoError;
use soserde::SoSerdeError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SmrError {
    #[error("SupraCryptoError: {0}")]
    SupraCryptoError(#[from] SupraCryptoError),
    #[error(transparent)]
    SoSerdeError(#[from] SoSerdeError),
    #[error("CertificateBlsThresholdPublicKeyMissing")]
    CertificateBlsThresholdPublicKeyMissing,
    #[error("BLS private key share is missing.")]
    BlsPrivateKeyShareMissing,
    #[error("Invalid signature from {0}")]
    InvalidSignature(String),
    #[error("General error: {0}")]
    GeneralError(String),
    #[error("Invalid vote signature type: {0}")]
    InvalidVoteSignature(String),
    #[error("Invalid chain id. Expected: {0}:{1}, Found: {2}:{3}")]
    InvalidChainId(String, u8, String, u8),
    #[error("Invalid epoch. Expected: {0}:{1}, Found: {2}:{3}")]
    InvalidEpoch(String, u64, String, u64),
    #[error("Unauthorized: {0}")]
    Unauthorized(socrypto::Identity),
    #[error("NoPreviousEpoch: {0}")]
    NoPreviousEpoch(crate::sosmr_types::EpochId),
    #[error("CannotEnterEpoch: {0} {1}")]
    CannotEnterEpoch(crate::sosmr_types::EpochId, crate::sosmr_types::EpochId),
    #[error("NoPreviousRound: {0}")]
    NoPreviousRound(crate::sosmr_types::View),
}
