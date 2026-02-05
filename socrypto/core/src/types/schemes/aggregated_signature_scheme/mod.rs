use crate::types::identity::Identity;
use crate::types::order::Order;
use crate::types::serde::{TCryptoSecureSerde, TCryptoSerde};
use crate::types::CryptoResult;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Sub-trait of AggregateSignatureScheme representing multisignature schemes.
pub mod multisig_scheme;
/// Sub-trait of AggregateSignatureScheme representing threshold signature schemes.
pub mod threshold_sig_scheme;

pub(crate) use multisig_scheme::MultiSignatureScheme;
pub(crate) use threshold_sig_scheme::ThresholdSignatureScheme;

/// Generic interface for public parameters of the aggregate signature schema.
///
///  - [VerificationKey] - type describing the verification key type for multi-party signature service
///  - [PublicKey] - type describing the shared group public key
///
/// Expected to have one to one mapping between identity and order.
pub trait TPublicParameters<VerificationKey, PublicKey> {
    /// Gets shared group public key of the multi-party signature service
    fn public_key(&self) -> &PublicKey;

    /// Get the verification key based on the input identity if any.
    fn verification_key(&self, identity: &Identity) -> Option<&VerificationKey>;

    /// Get the verification key based on the input identity order if any.
    fn verification_key_by_order(&self, order: &Order) -> Option<&VerificationKey>;

    /// Returns expected minimum number of parties to form a aggregated signature
    fn threshold(&self) -> usize;

    /// Returns order of the identity in the public parameter set if any.
    fn identity_order(&self, identity: &Identity) -> Option<&Order>;

    /// Return an identity corresponding to the input order if any.
    fn identity_by_order(&self, order: &Order) -> Option<&Identity>;

    /// Return known identities by the public-parameter set
    fn identities(&self) -> Vec<&Identity>;
}

///
/// Generic type system for the aggregate signature schemas (multi-signer, multi-party)
///
pub trait AggregateSignatureScheme {
    /// Secret key type used to generate partial signatures in multi-party signature scheme
    type SigningKeyType: ZeroizeOnDrop + Zeroize + Drop + TCryptoSecureSerde + TCryptoSerde;
    /// Public key type used to verify partial signatures in multi-party signature scheme
    type VerificationKeyType: Clone + Eq + PartialEq + std::hash::Hash + TCryptoSerde;
    /// Partial signature type which are aggregated in multi-party signature scheme
    type PartialSignatureType: Clone + TCryptoSerde;
    /// Aggregated signature type in multi-party scheme
    ///  - for threshold signature contains a single group element (the signature)
    ///  - for multi-signature contains group element (signature) as well as set of signers
    type AggregatedSignatureType: Clone + TCryptoSerde;
    /// Publicly known parameters of multi-party signature service
    /// It is expected to include verification key of each individual participant, threshold
    /// and shared public key of the group of participants.
    /// Shared public key
    ///  - for multi-signature no extra info is required it is the same set of verification-keys
    ///  - for threshold signature it is defined by the actual scheme
    type PublicParametersType: TPublicParameters<Self::VerificationKeyType, Self::PublicKeyType>
        + Clone;
    /// Shared public key of the group which can be used to verify threshold signature
    ///  - for multi-signature it holds the same info as PublicParameterType
    ///  - for threshold signature it holds threshold and shared public key
    type PublicKeyType: Clone + TCryptoSerde;

    /// Generate partial signature on message `msg` using signing key `sk` and verification key `vk`
    /// `vk` might be used to generate a proof.
    fn sign<T: AsRef<[u8]>>(
        msg: &T,
        sk: &Self::SigningKeyType,
        vk: &Self::VerificationKeyType,
    ) -> Self::PartialSignatureType;

    /// Generate partial signature on message `msg` using secret key `sk` without associated verification key.
    fn sign_no_vk<T: AsRef<[u8]>>(msg: &T, sk: &Self::SigningKeyType)
        -> Self::PartialSignatureType;

    /// Validate that `psig`is a partial signature on `msg` for verification key `vk`
    fn verify_partial_signature<T: AsRef<[u8]>>(
        msg: &T,
        psig: &Self::PartialSignatureType,
        vk: &Self::VerificationKeyType,
    ) -> CryptoResult<()>;

    /// Aggregate partial signatures WITHOUT VALIDATING THEM
    /// ONLY CALL IF `psigs` CONTAINS ONLY VALID PARTIAL SIGNATURES
    fn aggregate_partial_signatures<
        T: AsRef<[u8]>,
        PS: AsRef<Self::PartialSignatureType>,
        I: IntoIterator<Item = (Identity, PS)>,
    >(
        msg: &T,
        psigs: I,
        pp: &Self::PublicParametersType,
    ) -> CryptoResult<Self::AggregatedSignatureType>;

    /// Verify that [sig] is an aggregated signature on message `msg` with respect to
    /// public parameters [pp].
    fn verify_aggregated_signature<T: AsRef<[u8]>>(
        msg: &T,
        sig: &Self::AggregatedSignatureType,
        pk: &Self::PublicKeyType,
    ) -> CryptoResult<()>;
}
