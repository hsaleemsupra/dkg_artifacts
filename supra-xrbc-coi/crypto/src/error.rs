use crate::distributed_key::DistributedKeyPairError;
use ed25519_dalek::SignatureError;
use primitives::ClanIdentifier;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("{0}")]
    Ed25519Error(#[from] SignatureError),
    #[error("{0}")]
    DistributedKeyError(#[from] DistributedKeyPairError),
    #[error("Clan public key not found: {0}")]
    ClanPublicKeyNotFound(ClanIdentifier),
}
