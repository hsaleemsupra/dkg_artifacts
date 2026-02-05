use crate::types::serde::TRawRepresentation;
use crate::types::{CryptoError, CryptoResult};
use ed25519_dalek::{ed25519, Signature, SigningKey, VerifyingKey};

// TCryptoSerde bounds for ed25519_dalek::SigningKey type
/// Length of the ED25519 secret key.
pub const SECRET_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;

impl TRawRepresentation for SigningKey {
    type Raw = ed25519_dalek::SecretKey;

    fn create() -> Self::Raw {
        [0; SECRET_KEY_LENGTH]
    }

    fn from_raw(src: Self::Raw) -> CryptoResult<Self> {
        Ok(SigningKey::from_bytes(&src))
    }

    fn to_raw(&self) -> Self::Raw {
        self.to_bytes()
    }
}

/// Length of the ED25519 public/verifying key.
pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
impl TRawRepresentation for VerifyingKey {
    type Raw = [u8; PUBLIC_KEY_LENGTH];

    fn create() -> Self::Raw {
        [0; PUBLIC_KEY_LENGTH]
    }

    fn from_raw(src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized,
    {
        VerifyingKey::from_bytes(&src).map_err(CryptoError::from)
    }

    fn to_raw(&self) -> Self::Raw {
        self.to_bytes()
    }
}

/// Length of the ED25519 signature.
pub const SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;

impl TRawRepresentation for Signature {
    type Raw = ed25519::SignatureBytes;

    fn create() -> Self::Raw {
        [0; SIGNATURE_LENGTH]
    }

    fn from_raw(src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized,
    {
        Ok(Signature::from_bytes(&src))
    }

    fn to_raw(&self) -> Self::Raw {
        self.to_bytes()
    }
}
