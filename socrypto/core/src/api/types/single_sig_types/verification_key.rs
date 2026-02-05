use super::{PopWrapperSig, SignatureScheme, SignatureWrapper};
use crate::types::impls::helpers::serde::encode_hex;
use crate::types::ownable::Ownable;
use crate::types::serde::{TCryptoSerde, TRawRepresentation};
use crate::types::CryptoError;
use crate::CryptoResult;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

/// Wrapper struct representing a verification (public) key for a single signer signature scheme.
#[derive(PartialEq, Eq, Hash, Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub struct VerificationKeyWrapperSig<T: SignatureScheme> {
    #[serde(with = "TCryptoSerde")]
    pub(crate) inner: T::VerificationKeyType,
}

impl<T: SignatureScheme> Debug for VerificationKeyWrapperSig<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", encode_hex(&self.to_bytes()))
    }
}

impl<T: SignatureScheme> Display for VerificationKeyWrapperSig<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<T: SignatureScheme> VerificationKeyWrapperSig<T> {
    /// Verify signature `sig` on message `msg` using `self` as verification key.
    pub fn verify<M: AsRef<[u8]>>(&self, msg: &M, sig: &SignatureWrapper<T>) -> CryptoResult<()> {
        T::verify_signature(msg, &self.inner, &sig.inner)
    }

    pub(crate) fn new(inner: T::VerificationKeyType) -> Self {
        Self { inner }
    }

    /// Converts to raw representation of the enclosed data.
    pub fn to_bytes(
        &self,
    ) -> <<T as SignatureScheme>::VerificationKeyType as TRawRepresentation>::Raw {
        self.inner.to_raw()
    }
}

impl<T: SignatureScheme> TryFrom<&[u8]> for VerificationKeyWrapperSig<T> {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <T::VerificationKeyType as TRawRepresentation>::from(bytes)
            .and_then(T::VerificationKeyType::from_raw)
            .map(|inner| Self { inner })
    }
}

impl<T: SignatureScheme> VerificationKeyWrapperSig<T>
where
    T::SigningKeyType: Ownable<PublicType = T::VerificationKeyType>,
    <T::SigningKeyType as Ownable>::PopType: TCryptoSerde,
{
    /// Verify proof of possession `pop` of secret key associated with self.
    pub fn verify_possession(
        &self,
        pop: &PopWrapperSig<T>,
    ) -> Result<(), <T::SigningKeyType as Ownable>::Error> {
        <T::SigningKeyType as Ownable>::verify_possession(&self.inner, &pop.inner)
    }
}
