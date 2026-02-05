use crate::types::error::CryptoResult;
use crate::types::serde::TCryptoSerde;
use std::hash::Hash;
use zeroize::ZeroizeOnDrop;

/// Generic type system for the single signer public-key signature system.
pub trait SignatureScheme {
    /// Secret key type used to sign message in signature scheme.
    type SigningKeyType: TCryptoSerde + ZeroizeOnDrop;
    /// Public key type used to verify signatures in signature scheme.
    type VerificationKeyType: Clone + Eq + PartialEq + Hash + TCryptoSerde;
    /// Signature type for single signer scheme.
    type SignatureType: Clone + Eq + PartialEq + TCryptoSerde;

    /// Generate new random secret key.
    fn new_sk() -> Self::SigningKeyType;

    /// Generate signature on message `msg` using secret key `sk` with associated verification key `vk`.
    fn sign<T: AsRef<[u8]>>(
        sk: &Self::SigningKeyType,
        msg: &T,
        vk: &Self::VerificationKeyType,
    ) -> Self::SignatureType;

    /// Generate signature on message `msg` using secret key `sk` without associated verification key.
    /// Note default implementation generates vk from sk so is less efficient than calling `sign` when vk is known
    fn sign_no_vk<T: AsRef<[u8]>>(sk: &Self::SigningKeyType, msg: &T) -> Self::SignatureType {
        Self::sign(sk, msg, &Self::vk_from_sk(sk))
    }

    /// Verify that message `msg` was signed by owner of verification key `vk` by validating signature `sig`.
    fn verify_signature<T: AsRef<[u8]>>(
        msg: &T,
        vk: &Self::VerificationKeyType,
        sig: &Self::SignatureType,
    ) -> CryptoResult<()>;

    /// Generate new verification key `vk` from secret key `sk`.
    fn vk_from_sk(sk: &Self::SigningKeyType) -> Self::VerificationKeyType;
}
