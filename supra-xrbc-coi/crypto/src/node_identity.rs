use crate::error::CryptoError;
use crate::traits::NodeIdentityInterface;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use primitives::{Origin, HASH64};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeIdentity {
    key_pair: Keypair,
}

impl Clone for NodeIdentity {
    fn clone(&self) -> Self {
        let key_pair = Keypair::from_bytes(&self.key_pair.to_bytes()).unwrap();
        NodeIdentity { key_pair }
    }
}

impl NodeIdentity {
    pub fn random() -> NodeIdentity {
        NodeIdentity {
            key_pair: Keypair::generate(&mut thread_rng()),
        }
    }
}

impl NodeIdentityInterface for NodeIdentity {
    type Error = CryptoError;
    type RawPublicKey = Origin;
    type Signature = HASH64;

    fn sign(&self, message: &[u8]) -> Result<HASH64, Self::Error> {
        self.key_pair
            .try_sign(message)
            .map(|sgn| sgn.to_bytes())
            .map_err(CryptoError::Ed25519Error)
    }

    fn verify(
        origin: &Self::RawPublicKey,
        signature: &Self::Signature,
        msg: &[u8],
    ) -> Result<(), Self::Error> {
        let signature = Signature::from_bytes(signature)?;
        PublicKey::from_bytes(origin)
            .and_then(|key| key.verify(msg, &signature))
            .map_err(CryptoError::Ed25519Error)
    }

    fn public_key(&self) -> Self::RawPublicKey {
        self.key_pair.public.to_bytes()
    }

    fn is_valid_public_key(origin: &Origin) -> Result<(), Self::Error> {
        PublicKey::from_bytes(origin)
            .map(|_| {})
            .map_err(CryptoError::Ed25519Error)
    }
}
