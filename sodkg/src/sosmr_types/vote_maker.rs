use crate::sosmr_types::transactions::vote::Vote;
use crate::sosmr_types::VoteSignature;
use socrypto::{Digest, Identity};
use std::marker::PhantomData;
use zeroize::ZeroizeOnDrop;

/// A trait implemented by the [Signer] of a [VoteMaker] to create signatures.
pub trait TSigner<S> {
    /// Defines verification key type of the signer.
    type VerificationKey;
    /// Returns a signature [S] on the given `message_bytes`.
    fn sign<T: AsRef<[u8]>>(&self, message_bytes: &T) -> S;

    fn verification_key(&self) -> Self::VerificationKey;
}

/// The [VoteMaker] provides a single interface for constructing generic [Vote]s
/// signed by a generic [Signer].
#[derive(Clone)]
pub struct VoteMaker<Signature, Signer> {
    /// A type capable of creating [Signature]s on byte slices.
    signer: Signer,
    _signature_holder: PhantomData<Signature>,
}

/// The interface exposed by structs that concretize [SignatureService].
impl<Signature, Signer> VoteMaker<Signature, Signer>
where
    Signature: Into<VoteSignature>,
    Signer: TSigner<Signature> + ZeroizeOnDrop,
{
    pub fn new(signer: Signer) -> Self {
        Self {
            signer,
            _signature_holder: PhantomData,
        }
    }

    /// Returns a [Vote] for [D] signed by the [Signer] of this [VoteMaker].
    pub fn create_signed_vote<D>(&self, author: Identity, data: D) -> Vote<D>
    where
        D: Clone + Digest + Send,
    {
        let vote = Vote::new_unsigned(author, data.clone());
        let signature = self.signer.sign(&vote.digest());
        Vote::new(author, data, signature.into())
    }

    /// Consumes this [VoteMaker] and destroys its [Signer].
    pub fn destroy(self) {
        // Implicitly calls `self.signer.zeroize_on_drop`.
        drop(self)
    }
}
