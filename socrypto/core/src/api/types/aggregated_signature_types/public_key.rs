//! Defines common partial verification key concept for multi-party signature service based on the schema.
use super::AggregateSignatureScheme;
use super::AggregatedSignatureWrapper;
use crate::types::serde::TCryptoSerde;
use crate::types::CryptoResult;
use serde::{Deserialize, Serialize};

/// Wrapper struct representing a shared public key for a multi-signer signature scheme.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct PublicKeyWrapperAggSig<T: AggregateSignatureScheme> {
    #[serde(with = "TCryptoSerde")]
    pub(crate) inner: T::PublicKeyType,
}

impl<T: AggregateSignatureScheme> PublicKeyWrapperAggSig<T> {
    pub(crate) fn new(inner: T::PublicKeyType) -> Self {
        Self { inner }
    }

    /// Verify aggregate signature `sig` on message `msg` w.r.t. [self] as public parameters
    pub fn verify_aggregated_signature<M: AsRef<[u8]>>(
        &self,
        msg: &M,
        sig: &AggregatedSignatureWrapper<T>,
    ) -> CryptoResult<()> {
        T::verify_aggregated_signature(msg, sig.as_ref(), self.as_ref())
    }
}

impl<T: AggregateSignatureScheme> AsRef<T::PublicKeyType> for PublicKeyWrapperAggSig<T> {
    fn as_ref(&self) -> &T::PublicKeyType {
        &self.inner
    }
}
