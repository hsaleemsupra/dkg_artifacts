//! Defines generic aggregated signature concept for multi-party signature service based on the schema.
use super::{AggregateSignatureScheme, TPublicParameters};
use crate::api::types::aggregated_signature_types::{
    PublicKeyWrapperAggSig, PublicParametersWrapperAggSig,
};
use crate::types::schemes::aggregated_signature_scheme::MultiSignatureScheme;
use crate::types::serde::TCryptoSerde;
use crate::types::Order;
use crate::CryptoResult;
use serde::{Deserialize, Serialize};

/// Wrapper struct representing an aggregated signature for a multi-party signature scheme
#[derive(Serialize, Deserialize, Clone)]
pub struct AggregatedSignatureWrapper<T: AggregateSignatureScheme> {
    #[serde(with = "TCryptoSerde")]
    pub(crate) inner: T::AggregatedSignatureType,
}

impl<T: AggregateSignatureScheme> AggregatedSignatureWrapper<T> {
    pub(crate) fn new(inner: T::AggregatedSignatureType) -> Self {
        Self { inner }
    }

    /// Verify that [self] is an aggregated signature on message `msg` w.r.t. public parameters `pp`
    pub fn verify<M: AsRef<[u8]>>(
        &self,
        msg: &M,
        pp: &PublicParametersWrapperAggSig<T>,
    ) -> CryptoResult<()> {
        T::verify_aggregated_signature(msg, self.as_ref(), pp.as_ref().public_key())
    }

    /// Verify that [self] is an aggregated signature on message `msg` w.r.t. public key `pk`
    pub fn verify_with_public_key<M: AsRef<[u8]>>(
        &self,
        msg: &M,
        pk: &PublicKeyWrapperAggSig<T>,
    ) -> CryptoResult<()> {
        T::verify_aggregated_signature(msg, self.as_ref(), pk.as_ref())
    }
}

impl<T: AggregateSignatureScheme> AsRef<T::AggregatedSignatureType>
    for AggregatedSignatureWrapper<T>
{
    fn as_ref(&self) -> &T::AggregatedSignatureType {
        &self.inner
    }
}

impl<T: MultiSignatureScheme> AggregatedSignatureWrapper<T> {
    /// Returns the identities of the signers of a message
    pub fn signers(&self) -> Vec<Order> {
        T::get_signers(self.as_ref())
    }
}
