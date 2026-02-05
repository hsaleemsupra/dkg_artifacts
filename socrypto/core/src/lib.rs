//! Supra Crypto types API
use crate::types::error::CryptoResult;

/// Provide instantiations of signature schemes defined in types. Also provides type aliases to be
/// used in application API and additional implementations.
pub mod api;
/// Contains type definition for cryptographic primitives as well as "crate types" such as CryptoResult and CryptoError
/// additionally contains wrapper structs and associated implementations which provide application-level api.
pub mod types;
