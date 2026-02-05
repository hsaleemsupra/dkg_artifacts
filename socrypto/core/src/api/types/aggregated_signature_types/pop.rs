//! Defines common proof of possession concept for multi-party signature service.
use super::AggregateSignatureScheme;
use crate::api::types::aggregated_signature_types::verification_key::VerificationKeyWrapperAggSig;
use crate::types::ownable::Ownable;
use crate::types::serde::{TCryptoSerde, TRawRepresentation};
use serde::{Deserialize, Serialize};

/// Wrapper struct representing a proof of possession of signing key for a multi-signer signature scheme.
#[derive(Serialize, Deserialize)]
pub struct PopWrapperAggSig<T: AggregateSignatureScheme>
where
    T::SigningKeyType: Ownable<PublicType = T::VerificationKeyType>,
    <T::SigningKeyType as Ownable>::PopType: TCryptoSerde,
{
    #[serde(with = "TCryptoSerde")]
    pub(crate) inner: <T::SigningKeyType as Ownable>::PopType,
}

impl<T: AggregateSignatureScheme> PopWrapperAggSig<T>
where
    T::SigningKeyType: Ownable<PublicType = T::VerificationKeyType>,
    <T::SigningKeyType as Ownable>::PopType: TCryptoSerde,
{
    /// Verifies [self] as proof of possession on verification key `vk`.
    pub fn verify_possession(
        &self,
        vk: &VerificationKeyWrapperAggSig<T>,
    ) -> Result<(), <T::SigningKeyType as Ownable>::Error> {
        <T::SigningKeyType as Ownable>::verify_possession(vk.as_ref(), &self.inner)
    }

    pub(crate) fn new(inner: <T::SigningKeyType as Ownable>::PopType) -> Self {
        Self { inner }
    }

    /// Returns raw representation of the type.
    pub fn to_bytes(
        &self,
    ) -> <<<T as AggregateSignatureScheme>::SigningKeyType as Ownable>::PopType as TRawRepresentation>::Raw
    {
        self.inner.to_raw()
    }
}

impl<T: AggregateSignatureScheme> AsRef<<T::SigningKeyType as Ownable>::PopType>
    for PopWrapperAggSig<T>
where
    T::SigningKeyType: Ownable<PublicType = T::VerificationKeyType>,
    <T::SigningKeyType as Ownable>::PopType: TCryptoSerde,
{
    fn as_ref(&self) -> &<T::SigningKeyType as Ownable>::PopType {
        &self.inner
    }
}
