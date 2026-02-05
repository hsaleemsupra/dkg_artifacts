//! Defines common partial signature concept for multi-party signature service based on the schema.
use super::AggregateSignatureScheme;
use crate::api::types::aggregated_signature_types::verification_key::VerificationKeyWrapperAggSig;
use crate::api::types::aggregated_signature_types::PublicParametersWrapperAggSig;
use crate::types::identity::Identity;
use crate::types::order::Order;
use crate::types::serde::TCryptoSerde;
use crate::types::CryptoResult;
use serde::{Deserialize, Serialize};

/// Wrapper struct representing a partial signature for a multi-party signature scheme.
#[derive(Serialize, Deserialize, Clone)]
pub struct PartialSignatureWrapper<T: AggregateSignatureScheme> {
    #[serde(with = "TCryptoSerde")]
    pub(crate) inner: T::PartialSignatureType,
}

impl<T: AggregateSignatureScheme> PartialSignatureWrapper<T> {
    pub(crate) fn new(inner: T::PartialSignatureType) -> Self {
        Self { inner }
    }

    /// Verify that [self] is a valid partial signature on message `msg` w.r.t. verification key `vk`
    pub fn verify<M: AsRef<[u8]>>(
        &self,
        msg: &M,
        vk: &VerificationKeyWrapperAggSig<T>,
    ) -> CryptoResult<()> {
        T::verify_partial_signature(msg, self.as_ref(), vk.as_ref())
    }

    /// Verify that [self] is a signature on message `msg` w.r.t. the verification key associated with `signer_identity`
    pub fn verify_by_identity<M: AsRef<[u8]>>(
        &self,
        msg: &M,
        signer_identity: &Identity,
        pp: &PublicParametersWrapperAggSig<T>,
    ) -> CryptoResult<()> {
        pp.verify_partial_signature_by_identity(msg, self, signer_identity)
    }

    /// Verify that [self] is a signature on message `msg` w.r.t. the verification key associated with `signer_order`
    pub fn verify_by_order<M: AsRef<[u8]>>(
        &self,
        msg: &M,
        signer_order: &Order,
        pp: &PublicParametersWrapperAggSig<T>,
    ) -> CryptoResult<()> {
        pp.verify_partial_signature_by_order(msg, self, signer_order)
    }
}

impl<T: AggregateSignatureScheme> AsRef<T::PartialSignatureType> for PartialSignatureWrapper<T> {
    fn as_ref(&self) -> &T::PartialSignatureType {
        &self.inner
    }
}
