//! Describes unique identity of the secret owner in the application layer.

use crate::types::impls::helpers::serde::{decode_hex, encode_hex};
use crate::types::CryptoError;
use serde::{Deserialize, Serialize};
use soserde::HexHumanReadableSerdeWithPrefix;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use utoipa::ToSchema;

/// Length of the identity in bytes. At present, it is set to 32 bytes which must be suitable for most use cases, e.g.
/// a SHA-256 hash, ed25519 public key, Aptos AccountAddress all have 32 bytes.
///
pub const IDENTITY_LENGTH: usize = 32;

/// Represents abstract identity in the application layer.
//------------------------------------------------------------------------------
// # Design Note (Keep it as private docs! Type is used in OpenAPI schema):
//
//  - It is application's responsibility to provide globally unique and deterministic raw bytes value to create a new identity.
//    For example, application can use `PublicKey` or `UUID` or `AccountAddress` to create a new identity.
//  - The Identity type itself must not make any assumption about the content of the raw bytes.
//
// # Use Cases:
//
// The Identity type is designed to be used as key in a map or as a reference to an entity in application, not specific
// as cryptographic identity.
// It is recommended to use Identity as opaque key to map to other data, so that when the identity construction changes,
// the map/table does not need to be changed.
//
// The design mainly considers below use cases:
//
//   - Case 1: Application create Identity using initial PublicKey. During runtime, application is possible to switch
//     Identity construction using AccountAddress or any other type without breaking changes.
//
//   - Case 1: Application create Identity using initial AccountAddress. Then use this identity to create mapping to any other data.
//     The data associated with the identity can be changed without changing the identity itself.
//
//   - Case 3: Application design with assumption that there is initial input type to create Identity.
//     During the lifecycle of the product, the assumption may no longer holds true later, then application can switch to
//     use another input type to create Identity without breaking changes.
//
// # Compatibility
//
//  - It is backward-compatible that to increase the size of the identity.
//  - It may **NOT** be backward-compatible to reduce the size of the identity.
//    If "new size" < "max size used by application", then the change is non-backward-compatible.
//
#[derive(
    Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Default, Serialize, Deserialize, ToSchema,
)]
pub struct Identity(
    #[serde(with = "HexHumanReadableSerdeWithPrefix")] pub(crate) [u8; IDENTITY_LENGTH],
);

impl Identity {
    /// Creates a new `Identity` from a raw byte slice.
    ///
    /// # Panics
    /// Panics if the length of the raw bytes is greater than [`IDENTITY_LENGTH`].
    pub fn new<T: AsRef<[u8]>>(inner: T) -> Self {
        let inner = inner.as_ref();
        if inner.len() > IDENTITY_LENGTH {
            panic!("Expect max {IDENTITY_LENGTH} bytes",);
        }
        // If the length of the inner bytes is less than IDENTITY_LENGTH, then fill the remaining bytes with 0.
        let mut bytes = [0; IDENTITY_LENGTH];
        bytes[..inner.len()].copy_from_slice(inner);

        Self(bytes)
    }
}
impl Debug for Identity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({})", String::from(self))
    }
}
impl Display for Identity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<Identity> for String {
    fn from(value: Identity) -> Self {
        encode_hex(&value)
    }
}

impl From<&Identity> for String {
    fn from(value: &Identity) -> Self {
        encode_hex(value)
    }
}

impl TryFrom<&str> for Identity {
    type Error = CryptoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // Strip the leading '0x' if the string is in human-readable format.
        let hex = if let Some(formatted_hex) = value.strip_prefix("0x") {
            formatted_hex
        } else {
            value
        };
        let digest = decode_hex(hex)?.as_slice().try_into()?;
        Ok(Identity(digest))
    }
}

impl From<[u8; IDENTITY_LENGTH]> for Identity {
    fn from(value: [u8; IDENTITY_LENGTH]) -> Self {
        Identity(value)
    }
}

impl AsRef<[u8; IDENTITY_LENGTH]> for Identity {
    fn as_ref(&self) -> &[u8; IDENTITY_LENGTH] {
        &self.0
    }
}

impl AsRef<[u8]> for Identity {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_log_format() {
        const BYTES: [u8; 3] = [1, 2, 3];
        let identity = Identity::new(BYTES);
        let mut slice_inner = [0; IDENTITY_LENGTH];
        slice_inner[..BYTES.len()].copy_from_slice(&BYTES);

        let expected_str = format!("Identity({})", encode_hex(&slice_inner));
        // Display
        assert_eq!(identity.to_string(), expected_str);
        // Debug
        assert_eq!(format!("{:}", identity), expected_str);
        // Pretty Debug
        assert_eq!(format!("{:?}", identity), expected_str);
    }
}
