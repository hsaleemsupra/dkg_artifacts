use super::{SignatureScheme, VerificationKeyWrapperSig};
use crate::types::serde::TRawRepresentation;
use crate::types::{ownable::Ownable, serde::TCryptoSerde};
use serde::{Deserialize, Serialize};

/// Wrapper struct representing a proof of possession of signing key for a single signer signature scheme.
#[derive(Serialize, Deserialize)]
pub struct PopWrapperSig<T: SignatureScheme>
where
    T::SigningKeyType: Ownable<PublicType = T::VerificationKeyType>,
    <T::SigningKeyType as Ownable>::PopType: TCryptoSerde,
{
    #[serde(with = "TCryptoSerde")]
    pub(crate) inner: <T::SigningKeyType as Ownable>::PopType,
}

impl<T: SignatureScheme> PopWrapperSig<T>
where
    T::SigningKeyType: Ownable<PublicType = T::VerificationKeyType>,
    <T::SigningKeyType as Ownable>::PopType: TCryptoSerde,
{
    /// Verifies `self` as proof of possession on verification key `vk`.
    pub fn verify_possession(
        &self,
        vk: &VerificationKeyWrapperSig<T>,
    ) -> Result<(), <T::SigningKeyType as Ownable>::Error> {
        <T::SigningKeyType as Ownable>::verify_possession(&vk.inner, &self.inner)
    }

    pub(crate) fn new(inner: <T::SigningKeyType as Ownable>::PopType) -> Self {
        Self { inner }
    }

    /// Returns raw representation of the type.
    pub fn to_bytes(
        &self,
    ) -> <<<T as SignatureScheme>::SigningKeyType as Ownable>::PopType as TRawRepresentation>::Raw
    {
        self.inner.to_raw()
    }
}
