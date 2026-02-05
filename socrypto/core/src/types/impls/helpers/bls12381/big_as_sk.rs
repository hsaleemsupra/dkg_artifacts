use crate::types::serde::TRawRepresentation;
use crate::types::CryptoResult;
use miracl_core_bls12381::bls12381::big::BIG;
use serde::{Deserializer, Serializer};
use soserde::HexHumanReadableSerdeWithoutPrefix;
use std::ops::{Deref, DerefMut};
use zeroize::Zeroizing;

/// Wrapper on top of BIG to be used as secret key with zeroizing feature for raw representation
pub struct BigSk(pub(crate) BIG);

impl Deref for BigSk {
    type Target = BIG;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for BigSk {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<BIG> for BigSk {
    fn as_ref(&self) -> &BIG {
        &self.0
    }
}

impl From<BIG> for BigSk {
    fn from(value: BIG) -> Self {
        Self(value)
    }
}

impl TRawRepresentation for BigSk {
    type Raw = Zeroizing<<BIG as TRawRepresentation>::Raw>;

    fn create() -> Self::Raw {
        BIG::create().into()
    }

    fn from_raw(src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized,
    {
        let big = BIG::frombytes(src.as_ref());
        Ok(Self(big))
    }

    fn to_raw(&self) -> Self::Raw {
        let mut raw_signature = Self::create();
        self.tobytes(raw_signature.as_mut());
        raw_signature
    }

    fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self::Raw, D::Error> {
        HexHumanReadableSerdeWithoutPrefix::deserialize::<'de, D, <BIG as TRawRepresentation>::Raw>(
            deserializer,
        )
        .map(Into::into)
    }

    fn serialize<S: Serializer>(raw: &Self::Raw, serializer: S) -> Result<S::Ok, S::Error> {
        HexHumanReadableSerdeWithoutPrefix::serialize(raw.deref(), serializer)
    }
}
