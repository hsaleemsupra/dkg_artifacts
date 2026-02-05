//! Defines common partial verification key concept for multi-party signature service based on the schema.
use super::{AggregateSignatureScheme, MultiSignatureScheme, ThresholdSignatureScheme};
use super::{PartialSignatureWrapper, PopWrapperAggSig};
use crate::types::ownable::Ownable;
use crate::types::serde::TCryptoSerde;
use crate::CryptoResult;
use serde::{Deserialize, Serialize};

/// Wrapper struct representing a partial verification (public) key for a multi-signer signature scheme.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct VerificationKeyWrapperAggSig<T: AggregateSignatureScheme> {
    #[serde(with = "TCryptoSerde")]
    pub(crate) inner: T::VerificationKeyType,
}

impl<T: AggregateSignatureScheme> VerificationKeyWrapperAggSig<T> {
    pub(crate) fn new(inner: T::VerificationKeyType) -> Self {
        Self { inner }
    }

    /// Verify partial signature `sig` on message `msg` using [self] as verification key
    pub fn verify<M: AsRef<[u8]>>(
        &self,
        msg: &M,
        sig: &PartialSignatureWrapper<T>,
    ) -> CryptoResult<()> {
        T::verify_partial_signature(msg, sig.as_ref(), self.as_ref())
    }
}

impl<T: AggregateSignatureScheme> VerificationKeyWrapperAggSig<T>
where
    T::SigningKeyType: Ownable<PublicType = T::VerificationKeyType>,
    <T::SigningKeyType as Ownable>::PopType: TCryptoSerde,
{
    /// Verify proof of possession `pop` of secret key associated with self
    pub fn verify_possession(
        &self,
        pop: &PopWrapperAggSig<T>,
    ) -> Result<(), <T::SigningKeyType as Ownable>::Error> {
        <T::SigningKeyType as Ownable>::verify_possession(self.as_ref(), pop.as_ref())
    }
}

impl<T: AggregateSignatureScheme> AsRef<T::VerificationKeyType>
    for VerificationKeyWrapperAggSig<T>
{
    fn as_ref(&self) -> &T::VerificationKeyType {
        &self.inner
    }
}

impl<T: ThresholdSignatureScheme> VerificationKeyWrapperAggSig<T> {}
impl<T: MultiSignatureScheme> VerificationKeyWrapperAggSig<T> {}
