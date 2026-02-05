use std::fmt::Debug;

use crate::types::impls::helpers::bls12381::big_as_sk::BigSk as BIG_BLS12381;
use crate::types::serde::TRawRepresentation;
use crate::CryptoResult;
use serde::{Deserializer, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

impl TCryptoZeroize for BIG_BLS12381 {
    fn zeroize_crypto(&mut self) {
        self.zero()
    }
}

/// Trait to implement zeroize for wrapper structs whose inner fields don't implement zeroize.
pub trait TCryptoZeroize {
    /// Manually zeroize self
    fn zeroize_crypto(&mut self);
}

/// Wrapper struct holding a secret we want to handle carefully in memory.
pub struct SecretWrapper<T: TCryptoZeroize>(pub(crate) T);

impl<T: TCryptoZeroize> Debug for SecretWrapper<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecretKey").field(&"...").finish()
    }
}

impl<T: TCryptoZeroize> Drop for SecretWrapper<T> {
    fn drop(&mut self) {}
}

impl<T: TCryptoZeroize> Zeroize for SecretWrapper<T> {
    fn zeroize(&mut self) {
        self.0.zeroize_crypto();
    }
}
impl<T: TCryptoZeroize> ZeroizeOnDrop for SecretWrapper<T> {}

impl<T: TCryptoZeroize + TRawRepresentation> TRawRepresentation for SecretWrapper<T> {
    type Raw = T::Raw;

    fn create() -> Self::Raw {
        T::create()
    }

    fn from_raw(src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized,
    {
        T::from_raw(src).map(Self)
    }

    fn to_raw(&self) -> Self::Raw {
        self.0.to_raw()
    }

    fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self::Raw, D::Error> {
        <T as TRawRepresentation>::deserialize(deserializer)
    }

    fn serialize<S: Serializer>(raw: &Self::Raw, serializer: S) -> Result<S::Ok, S::Error> {
        <T as TRawRepresentation>::serialize(raw, serializer)
    }
}
