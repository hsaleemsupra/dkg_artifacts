//! Defines public parameters of the multi-party signature service
use super::{AggregateSignatureScheme, TPublicParameters};
use crate::api::types::aggregated_signature_types::aggregate_signature::AggregatedSignatureWrapper;
use crate::api::types::aggregated_signature_types::partial_signature::PartialSignatureWrapper;
use crate::api::types::aggregated_signature_types::{
    PublicKeyWrapperAggSig, VerificationKeyWrapperAggSig,
};
use crate::types::identity::Identity;
use crate::types::order::Order;
use crate::types::CryptoError;
use crate::CryptoResult;

/// Wrapper struct representing a public parameters for a multi-party signature scheme
///     - for multi-signatures signatures contains hashmap from identity to verification keys and
///       threshold long with the assigned order.
///     - for threshold signatures ALSO contains committee public key
pub struct PublicParametersWrapperAggSig<T: AggregateSignatureScheme> {
    pub(crate) inner: T::PublicParametersType,
}

impl<T: AggregateSignatureScheme> PublicParametersWrapperAggSig<T> {
    /// Initialize self from inner representation of public-parameters
    /// TODO consider updating this interface to accept set of verification keys and public key to construct it if applicable.
    pub fn new(inner: T::PublicParametersType) -> Self {
        Self { inner }
    }

    /// Returns expected minimum number of parties to form a aggregated signature
    pub fn threshold(&self) -> usize {
        self.as_ref().threshold()
    }

    /// Get shared group public key from public-parameters.
    pub fn public_key(&self) -> PublicKeyWrapperAggSig<T> {
        PublicKeyWrapperAggSig::new(self.as_ref().public_key().clone())
    }

    /// Get the verification key based on the input identity if any.
    pub fn verification_key(&self, identity: &Identity) -> Option<VerificationKeyWrapperAggSig<T>> {
        self.as_ref()
            .verification_key(identity)
            .cloned()
            .map(VerificationKeyWrapperAggSig::new)
    }

    /// Get the verification key based on the input identity order if any.
    pub fn verification_key_by_order(
        &self,
        order: &Order,
    ) -> Option<VerificationKeyWrapperAggSig<T>> {
        self.as_ref()
            .verification_key_by_order(order)
            .cloned()
            .map(VerificationKeyWrapperAggSig::new)
    }

    /// Aggregate partial signatures using [self] as public parameters WITHOUT VALIDATING `psigs`
    /// DO NOT USE UNLESS `psigs` CONTAINS ONLY VALID PARTIAL SIGNATURES
    pub fn aggregate_partial_signatures<
        M: AsRef<[u8]>,
        I: IntoIterator<Item = (Identity, PartialSignatureWrapper<T>)>,
    >(
        &self,
        msg: &M,
        psigs: I,
    ) -> CryptoResult<AggregatedSignatureWrapper<T>> {
        T::aggregate_partial_signatures(msg, psigs, self.as_ref())
            .map(|agg_sig| AggregatedSignatureWrapper::new(agg_sig))
    }

    /// Validate and aggregate the signatures in `psigs`
    /// If validation fails for any party an error is returned.
    /// If the number of partial signatures is not enough an error is returned.
    pub fn try_aggregate_partial_signatures<
        M: AsRef<[u8]>,
        I: IntoIterator<Item = (Identity, PartialSignatureWrapper<T>)>,
    >(
        &self,
        msg: &M,
        psigs: I,
    ) -> CryptoResult<AggregatedSignatureWrapper<T>> {
        let valid_psigs = psigs
            .into_iter()
            .map(|(id, psig)| {
                self.as_ref()
                    .verification_key(&id)
                    .ok_or(CryptoError::UnknownPkError(id))
                    .and_then(|vk| T::verify_partial_signature(msg, psig.as_ref(), vk))
                    .map(|_| (id, psig))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.aggregate_partial_signatures(msg, valid_psigs)
    }

    /// Verify aggregate signature `sig` on message `msg` w.r.t. [self] as public parameters
    pub fn verify_aggregated_signature<M: AsRef<[u8]>>(
        &self,
        msg: &M,
        sig: &AggregatedSignatureWrapper<T>,
    ) -> CryptoResult<()> {
        T::verify_aggregated_signature(msg, sig.as_ref(), self.as_ref().public_key())
    }

    /// Verify that `psig`is a partial signature on `msg` with respect to the verification key associated with `id`.
    pub fn verify_partial_signature_by_identity<M: AsRef<[u8]>>(
        &self,
        msg: &M,
        psig: &PartialSignatureWrapper<T>,
        id: &Identity,
    ) -> CryptoResult<()> {
        self.as_ref()
            .verification_key(id)
            .ok_or(CryptoError::UnknownPkError(*id))
            .and_then(|vk| T::verify_partial_signature(msg, psig.as_ref(), vk))
    }

    /// Verify that `psig`is a partial signature on `msg` with respect to the verification key associated with `id`.
    pub fn verify_partial_signature_by_order<M: AsRef<[u8]>>(
        &self,
        msg: &M,
        psig: &PartialSignatureWrapper<T>,
        signer_order: &Order,
    ) -> CryptoResult<()> {
        self.as_ref()
            .verification_key_by_order(signer_order)
            .ok_or(CryptoError::UnknownPkOrderError(*signer_order))
            .and_then(|vk| T::verify_partial_signature(msg, psig.as_ref(), vk))
    }

    /// Returns order of the identity in the public parameter set if any.
    pub fn identity_order(&self, identity: &Identity) -> Option<&Order> {
        self.as_ref().identity_order(identity)
    }

    /// Return an identity corresponding to the input order if any.
    pub fn identity_by_order(&self, order: &Order) -> Option<&Identity> {
        self.as_ref().identity_by_order(order)
    }

    /// Return known identities by the public-parameter set
    pub fn identities(&self) -> Vec<&Identity> {
        self.as_ref().identities()
    }
}

impl<T: AggregateSignatureScheme> AsRef<T::PublicParametersType>
    for PublicParametersWrapperAggSig<T>
{
    fn as_ref(&self) -> &T::PublicParametersType {
        &self.inner
    }
}
