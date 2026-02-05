use blsttc::{PublicKey, PublicKeySet, SecretKeyShare, Signature, SignatureShare};
use primitives::{ClanOrigin, Stringify, HASH32, HASH96};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::hash_map::RandomState;
use std::collections::HashSet;
use std::fmt::{Display, Formatter};

use crate::traits::DistributedKeyPairInterface;
use thiserror::Error;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PartialShare {
    index: u32,
    #[serde(with = "BigArray")]
    signature: HASH96,
}

impl Display for PartialShare {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PartialShare ({}, {})",
            self.index,
            self.signature.hex_display()
        )
    }
}

impl PartialShare {
    pub fn new(index: u32, signature: HASH96) -> Self {
        Self { index, signature }
    }

    pub fn index(&self) -> u32 {
        self.index
    }
}

#[derive(Debug, Error)]
pub enum DistributedKeyPairError {
    #[error("Not enough partial shares to generate threshold signature")]
    NotEnoughShares,
    #[error("Invalid Partial Signature")]
    InvalidPartialSignature,
    #[error("Invalid Threshold Signature")]
    InvalidThresholdSignature,
    #[error("{0}")]
    FromBlsttcError(#[from] blsttc::Error),
}

#[derive(Clone)]
pub struct DistributedKeyPair {
    threshold: usize,
    index: u32,
    secret_key_share: SecretKeyShare,
    public_key_set: PublicKeySet,
}

impl DistributedKeyPair {
    pub fn new(threshold: usize, index: u32, secret: SecretKeyShare, public: PublicKeySet) -> Self {
        Self {
            threshold,
            index,
            secret_key_share: secret,
            public_key_set: public,
        }
    }
}

impl DistributedKeyPairInterface for DistributedKeyPair {
    type Error = DistributedKeyPairError;
    type RawPublicKey = ClanOrigin;
    type Signature = HASH96;
    type PartialShare = PartialShare;

    fn threshold(&self) -> usize {
        self.threshold
    }

    fn partial_signature(&self, message: &HASH32) -> Result<PartialShare, Self::Error> {
        let share = self.secret_key_share.sign(message);
        let partial_share = PartialShare {
            index: self.index,
            signature: share.to_bytes(),
        };
        Ok(partial_share)
    }

    fn threshold_signature(
        &self,
        shares: Vec<Self::PartialShare>,
    ) -> Result<Self::Signature, Self::Error> {
        let share = HashSet::<&PartialShare, RandomState>::from_iter(shares.iter());
        if share.len() < self.threshold {
            return Err(DistributedKeyPairError::NotEnoughShares);
        }

        let mut share_list = HashSet::new();
        for x in shares {
            let sig = SignatureShare::from_bytes(x.signature)
                .map_err(DistributedKeyPairError::FromBlsttcError)?;
            share_list.insert((x.index as usize, sig));
        }

        self.public_key_set
            .combine_signatures(share_list)
            .map(|sig| sig.to_bytes() as HASH96)
            .map_err(DistributedKeyPairError::FromBlsttcError)
    }

    fn verify_partial_signature(
        &self,
        partial_share: &Self::PartialShare,
        message: &HASH32,
    ) -> Result<(), Self::Error> {
        SignatureShare::from_bytes(partial_share.signature)
            .map_err(DistributedKeyPairError::FromBlsttcError)
            .map(|s| {
                self.public_key_set
                    .public_key_share(partial_share.index as usize)
                    .verify(&s, message)
            })?
            .then_some(())
            .ok_or(DistributedKeyPairError::InvalidPartialSignature)
    }

    fn verify_threshold_signature(
        &self,
        signature: &Self::Signature,
        message: &HASH32,
    ) -> Result<(), Self::Error> {
        Signature::from_bytes(*signature)
            .map_err(DistributedKeyPairError::FromBlsttcError)
            .map(|s| self.public_key_set.public_key().verify(&s, message))?
            .then_some(())
            .ok_or(DistributedKeyPairError::InvalidPartialSignature)
    }

    fn public_key(&self) -> Self::RawPublicKey {
        self.public_key_set.public_key().to_bytes()
    }

    fn verify_threshold_signature_for_key(
        public_key: &Self::RawPublicKey,
        signature: &Self::Signature,
        message: &HASH32,
    ) -> Result<(), Self::Error> {
        let p =
            PublicKey::from_bytes(*public_key).map_err(DistributedKeyPairError::FromBlsttcError)?;
        let s =
            Signature::from_bytes(*signature).map_err(DistributedKeyPairError::FromBlsttcError)?;
        p.verify(&s, message)
            .then_some(())
            .ok_or(DistributedKeyPairError::InvalidPartialSignature)
    }
}
