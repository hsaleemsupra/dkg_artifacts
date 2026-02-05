use super::{SignatureScheme, VerificationKeyWrapperSig};
use crate::types::impls::helpers::serde::encode_hex;
use crate::types::serde::{TCryptoSerde, TRawRepresentation};
use crate::types::CryptoError;
use crate::CryptoResult;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

/// Wrapper struct representing a signature for a single signer signature scheme.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(transparent)]
pub struct SignatureWrapper<T: SignatureScheme> {
    #[serde(with = "TCryptoSerde")]
    pub(crate) inner: T::SignatureType,
}

impl<T: SignatureScheme> SignatureWrapper<T> {
    /// Verify that `self` is a signature on message `msg` w.r.t. verification key `vk`.
    pub fn verify<M: AsRef<[u8]>>(
        &self,
        msg: &M,
        vk: &VerificationKeyWrapperSig<T>,
    ) -> CryptoResult<()> {
        T::verify_signature(msg, &vk.inner, &self.inner)
    }

    /// Converts to raw representation of the enclosed data.
    pub fn to_bytes(&self) -> <<T as SignatureScheme>::SignatureType as TRawRepresentation>::Raw {
        self.inner.to_raw()
    }

    pub(crate) fn new(inner: T::SignatureType) -> Self {
        Self { inner }
    }
}

impl<T: SignatureScheme> Debug for SignatureWrapper<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", encode_hex(&self.to_bytes()))
    }
}

impl<T: SignatureScheme> Display for SignatureWrapper<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<'a, T: SignatureScheme> TryFrom<&'a [u8]> for SignatureWrapper<T> {
    type Error = CryptoError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        <T::SignatureType as TRawRepresentation>::from(value)
            .and_then(T::SignatureType::from_raw)
            .map(|inner| Self { inner })
    }
}
