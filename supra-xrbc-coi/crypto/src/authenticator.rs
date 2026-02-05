use crate::distributed_key::DistributedKeyPair;
use crate::error::CryptoError;
use crate::node_identity::NodeIdentity;
use crate::traits::{DistributedKeyPairInterface, NodeIdentityInterface};
use primitives::{ClanIdentifier, ClanOrigin, Origin, HASH32, HASH64, HASH96};
use std::collections::HashMap;

#[derive(Clone)]
pub struct Authenticator {
    identity: NodeIdentity,
    distributed_key: DistributedKeyPair,
    clan_identities: HashMap<ClanIdentifier, ClanOrigin>,
}

impl Authenticator {
    pub fn new(
        identity: NodeIdentity,
        distributed_key: DistributedKeyPair,
        clan_identities: HashMap<ClanIdentifier, ClanOrigin>,
    ) -> Self {
        Authenticator {
            identity,
            distributed_key,
            clan_identities,
        }
    }

    pub fn origin(&self) -> Origin {
        self.identity.public_key()
    }

    pub fn sign(&self, message: &[u8]) -> Result<HASH64, CryptoError> {
        self.identity.sign(message)
    }

    pub fn verify(
        origin: &Origin,
        signature: &<NodeIdentity as NodeIdentityInterface>::Signature,
        message: &[u8],
    ) -> Result<(), CryptoError> {
        NodeIdentity::verify(origin, signature, message)
    }

    pub fn partial_signature(
        &self,
        message: &HASH32,
    ) -> Result<<DistributedKeyPair as DistributedKeyPairInterface>::PartialShare, CryptoError>
    {
        self.distributed_key
            .partial_signature(message)
            .map_err(CryptoError::DistributedKeyError)
    }

    pub fn verify_partial_signature(
        &self,
        share: &<DistributedKeyPair as DistributedKeyPairInterface>::PartialShare,
        message: &HASH32,
    ) -> Result<(), CryptoError> {
        self.distributed_key
            .verify_partial_signature(share, message)
            .map_err(CryptoError::DistributedKeyError)
    }

    pub fn threshold_signature(
        &self,
        shares: Vec<<DistributedKeyPair as DistributedKeyPairInterface>::PartialShare>,
    ) -> Result<HASH96, CryptoError> {
        self.distributed_key
            .threshold_signature(shares)
            .map_err(CryptoError::DistributedKeyError)
    }

    pub fn verify_threshold_signature(
        &self,
        clan_identifier: &ClanIdentifier,
        signature: &<DistributedKeyPair as DistributedKeyPairInterface>::Signature,
        message: &HASH32,
    ) -> Result<(), CryptoError> {
        self.clan_identities
            .get(clan_identifier)
            .ok_or(CryptoError::ClanPublicKeyNotFound(*clan_identifier))
            .and_then(|public_key| {
                DistributedKeyPair::verify_threshold_signature_for_key(
                    public_key, signature, message,
                )
                .map_err(CryptoError::DistributedKeyError)
            })
    }

    pub fn threshold(&self) -> usize {
        self.distributed_key.threshold()
    }
}
