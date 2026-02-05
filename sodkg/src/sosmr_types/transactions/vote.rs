use crate::sosmr_types::vote_maker::{TSigner, VoteMaker};
use crate::sosmr_types::SmrError;
use nidkg_helper::{BlsPrivateKey, BlsPublicKey, BlsSignature};
use serde::{Deserialize, Serialize};
use socrypto::{Digest, Hash, Identity, PublicKey, SecretKey, Signature};
use std::fmt;

/// A [VoteMaker] for BLS threshold [Vote]s.
pub type BlsThresholdVoteMaker = VoteMaker<BlsSignature, BlsPrivateKey>;
/// A [VoteMaker] for ED25519 [Vote]s.
pub type Ed25519VoteMaker = VoteMaker<Signature, SecretKey>;

#[derive(Clone, Serialize, Deserialize)]
pub struct Vote<T> {
    /// The public id of the creator of this message.
    author: Identity,
    /// The data from which `signature` is derived.
    data: T,
    /// Signature of `author` on `data`.
    signature: VoteSignature,
}

impl<T: Digest> Vote<T> {
    //----------------------------------------Constructors----------------------------------------

    pub fn new(author: Identity, data: T, signature: VoteSignature) -> Self {
        Self {
            author,
            data,
            signature,
        }
    }

    pub fn new_unsigned(author: Identity, data: T) -> Self {
        Self {
            author,
            data,
            signature: VoteSignature::default(),
        }
    }

    //-----------------------------------------Accessors-----------------------------------------

    /// Public identity of the node that created this vote.
    pub fn author(&self) -> &Identity {
        &self.author
    }

    /// The data certified by this vote.
    pub fn data(&self) -> &T {
        &self.data
    }

    /// Signature of `author` on `data`.
    pub fn signature(&self) -> &VoteSignature {
        &self.signature
    }
}

impl<T: Digest> Digest for Vote<T> {
    /// Returns the digest of `self.data`. Since this does not factor in `self.author` or
    /// `self.signature`, the digests of votes sent by different nodes for the same data
    /// are identical (unless they contain other author-derived values).
    fn digest(&self) -> Hash {
        self.data.digest()
    }

    fn feed_to<THasher: sha3::Digest>(&self, hasher: &mut THasher) {
        self.data.feed_to(hasher);
    }
}

impl<T: fmt::Debug> fmt::Debug for Vote<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("Vote")
            .field("author", &self.author)
            .field("data", &self.data)
            .field("signature", &self.signature.to_string())
            .finish()
    }
}

impl<T: fmt::Debug> fmt::Display for Vote<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{self:?}")
    }
}

impl<T: Digest> PartialEq for Vote<T> {
    fn eq(&self, other: &Self) -> bool {
        self.digest() == other.digest()
    }
}

/// The various concrete types that can be used as signatures within [Vote]s.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum VoteSignature {
    Ed25519(Signature),
    Committee(Box<BlsSignature>),
}

impl Default for VoteSignature {
    fn default() -> Self {
        VoteSignature::Ed25519(Signature::default())
    }
}

impl fmt::Display for VoteSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let name = match self {
            VoteSignature::Ed25519(_) => "ED25519",
            VoteSignature::Committee(_) => "BLS",
        };
        write!(f, "{name}")
    }
}

impl From<BlsSignature> for VoteSignature {
    fn from(s: BlsSignature) -> Self {
        Self::Committee(Box::new(s))
    }
}

impl From<Signature> for VoteSignature {
    fn from(s: Signature) -> Self {
        Self::Ed25519(s)
    }
}

/// Returns the underlying concrete type [S] wrapped by the given [VoteSignature] variant, or an
/// error if `v` wraps some type other than [S].
pub trait FromVoteSignature<S> {
    fn from_vote_signature(v: &VoteSignature) -> Result<S, SmrError>;
}

impl FromVoteSignature<BlsSignature> for BlsSignature {
    fn from_vote_signature(v: &VoteSignature) -> Result<BlsSignature, SmrError> {
        match v {
            VoteSignature::Ed25519(_) => Err(SmrError::InvalidVoteSignature(
                std::any::type_name::<BlsSignature>().to_string(),
            )),
            VoteSignature::Committee(s) => Ok(*s.to_owned()),
        }
    }
}

impl FromVoteSignature<Signature> for Signature {
    fn from_vote_signature(v: &VoteSignature) -> Result<Signature, SmrError> {
        match v {
            VoteSignature::Ed25519(s) => Ok(*s),
            VoteSignature::Committee(_) => Err(SmrError::InvalidVoteSignature(
                std::any::type_name::<Signature>().to_string(),
            )),
        }
    }
}

impl TSigner<BlsSignature> for BlsPrivateKey {
    type VerificationKey = BlsPublicKey;

    fn sign<T: AsRef<[u8]>>(&self, message_bytes: &T) -> BlsSignature {
        self.sign_chain(message_bytes.as_ref())
    }

    fn verification_key(&self) -> Self::VerificationKey {
        self.public_key()
    }
}

impl TSigner<Signature> for SecretKey {
    type VerificationKey = PublicKey;

    fn sign<T: AsRef<[u8]>>(&self, message_bytes: &T) -> Signature {
        self.sign_no_vk(message_bytes)
    }

    fn verification_key(&self) -> Self::VerificationKey {
        self.gen_vk()
    }
}
