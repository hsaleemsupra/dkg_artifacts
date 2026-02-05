use std::array::TryFromSliceError;

use crate::types::identity::Identity;
use crate::types::order::Order;
use base64::DecodeError;
use ed25519_dalek::ed25519::Error as DalekError_;
use hex::FromHexError;
use thiserror::Error;

/// Represents all possible error types reported by crypto types.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Unknown verification key
    #[error("Unknown public key with identity {0}")]
    UnknownPkError(Identity),

    /// Unknown verification key
    #[error("Unknown public key with order {0}")]
    UnknownPkOrderError(Order),

    /// Insufficient partial signatures to aggregate
    #[error("InsufficientPartialSignatures to aggregate: {0}")]
    InsufficientPartialSignatures(Order),

    /// Partial signature verification error.
    /// Signature schema domain string and error message provided as input.
    #[error("PartialSignatureVerification: Failed to verify {domain} partial signature: {msg}")]
    PartialSignatureVerification { domain: &'static str, msg: String },

    /// Aggregated signature verification error
    #[error(
        "AggregatedSignatureVerification: Failed to verify {domain} aggregated signature: {msg}"
    )]
    AggregatedSignatureVerification { domain: &'static str, msg: String },

    /// Invalid threshold value
    #[error("InvalidThresholdValue: upper_bound: {upper_bound}, threshold: {threshold}")]
    InvalidThresholdValue {
        upper_bound: Order,
        threshold: Order,
    },

    /// Aggregation Error caused by underlying cryptographic libraries
    #[error("AggregationError: Cryptographic Aggregation Error: {0}")]
    AggregationError(String),

    /// Serialization error
    #[error("CryptoSerdeError: {0}")]
    CryptoSerdeError(String),

    /// Error from Dalek Library
    #[error("DalekError: {0}")]
    DalekError(#[from] DalekError_),

    /// Base64 decoder error
    #[error("Base64DecodeError: {0}")]
    Base64DecodeError(#[from] DecodeError),

    /// Hex decoder error
    #[error("HexDecodeError: {0}")]
    HexDecodeError(#[from] FromHexError),

    /// Error from digest conversion.
    #[error("HashError: Failed to construct hash from slice: {0}")]
    HashError(#[from] TryFromSliceError),

    /// Variant to report Proof of Possession errors
    #[error("PoPVerificationError: Failed to verify proof of possession for domain: {0}")]
    PoPVerificationError(String),

    /// Represents error when conversion fails due to size parameter of the objects
    #[error("ConversionSizeError: Raw representation conversion error, size mismatch. Expected: {expected}, Actual: {actual}")]
    ConversionSizeError { expected: usize, actual: usize },
}

/// Convenience type to report results with CryptoError type.
pub type CryptoResult<T> = Result<T, CryptoError>;
