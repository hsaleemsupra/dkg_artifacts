use crate::types::impls::helpers::hasher::HasherBuilder;
use crate::types::impls::helpers::serde::{decode_hex, encode_hex};
use crate::types::CryptoError;
use serde::{Deserialize, Serialize};
use sha3::Keccak256;
use soserde::HexHumanReadableSerdeWithPrefix;
use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::ops::{Deref, DerefMut};
use utoipa::ToSchema;

pub const HASH_LENGTH: usize = 32;

/// Represents a hash digest (32 bytes).
#[derive(
    Hash, PartialEq, Default, Eq, Clone, Ord, PartialOrd, Copy, ToSchema, Serialize, Deserialize,
)]
pub struct Hash(#[serde(with = "HexHumanReadableSerdeWithPrefix")] pub [u8; HASH_LENGTH]);

#[allow(missing_docs)] // Reason: function names are self-explanatory
impl Hash {
    pub fn new(hash: [u8; HASH_LENGTH]) -> Self {
        Self(hash)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn dummy() -> Self {
        Hash([0; HASH_LENGTH])
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", encode_hex(self))
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Hash {
    type Target = [u8; HASH_LENGTH];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&[u8]> for Hash {
    type Error = TryFromSliceError;
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        Ok(Hash(item.try_into()?))
    }
}

impl From<[u8; 32]> for Hash {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<Hash> for String {
    fn from(value: Hash) -> Self {
        encode_hex(&value)
    }
}

impl From<&Hash> for String {
    fn from(value: &Hash) -> Self {
        encode_hex(value)
    }
}

impl TryFrom<&str> for Hash {
    type Error = CryptoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // Strip the leading '0x' if the string is in human-readable format.
        let hex = if let Some(formatted_hex) = value.strip_prefix("0x") {
            formatted_hex
        } else {
            value
        };
        let digest = decode_hex(hex)?.as_slice().try_into()?;
        Ok(Hash(digest))
    }
}
/// This trait is implemented by all messages that can be hashed.
pub trait Digest {
    /// Returns 32 bytes digest of the object.
    fn digest(&self) -> Hash {
        let mut hasher = HasherBuilder::<Keccak256>::get_hasher();
        self.feed_to(hasher.deref_mut());
        Hash(hasher.hash())
    }

    /// Appends to the provided hasher the data that builds up the hash of the data.
    /// This API can be used to append current data digest components to the owner data hasher.
    fn feed_to<THasher: sha3::Digest>(&self, hasher: &mut THasher);
}

/// Default implementation for slice array.
impl Digest for &[u8] {
    fn feed_to<THasher: sha3::Digest>(&self, hasher: &mut THasher) {
        hasher.update(self)
    }
}

pub fn digest<T: AsRef<[u8]>>(bytes: T) -> Hash {
    bytes.as_ref().digest()
}
