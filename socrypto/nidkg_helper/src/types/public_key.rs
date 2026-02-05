use blsttc::{G1Projective, PublicKey, Signature};
use crypto::errors::DkgError;
use crate::types::signature::BlsSignature;
use serde::{de, Deserialize, Serialize};
use std::cmp::Ordering;

pub const BLS_PUBLIC_KEY_LEN: usize = 48;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsPublicKey {
    // using G1Projective instead of PublicKey because this is still both VK and PK
    pub bls12381: G1Projective,
}

impl Serialize for BlsPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        //Brute force serialization
        serializer.serialize_str(&hex::encode(self.to_vec()))
    }
}

impl<'de> Deserialize<'de> for BlsPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        //Brute force serialization
        let bytes = hex::decode(s).map_err(|e| de::Error::custom(e.to_string()))?;
        let arr: &[u8] = &bytes;
        let value = BlsPublicKey::try_from(arr).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl PartialOrd for BlsPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlsPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        if !self.bls12381.eq(&other.bls12381) {
            PublicKey::from(self.bls12381).cmp(&other.bls12381.into())
        } else {
            Ordering::Equal
        }
    }
}

impl BlsPublicKey {
    pub fn to_vec(&self) -> Vec<u8> {
        self.bls12381.to_compressed().to_vec()
    }

    pub fn verify(&self, msg: &[u8], signature: &BlsSignature) -> bool {
        // pairing is a private function so we have to convert G2Projective to Signature
        let sig_blsttc = Signature::from_bytes(signature.bls12381.to_compressed()).unwrap();
        PublicKey::from(self.bls12381).verify(&sig_blsttc, msg)
    }
/*
    pub fn verify_domain(&self, msg: &[u8], signature: &BlsSignature, domain: &[u8]) -> bool {
        verify_point_ecp_12381(
            &hash_to_ecp_12381(msg, domain),
            &signature.bls12381.sig_g1,
            &self.bls12381.pub_key_g2,
        ) && verify_point_ecp2_12381(
            &hash_to_ecp2_12381(msg, domain),
            &signature.bls12381.sig_g2,
            &self.bls12381.pub_key_g1,
        )
    }
*/
    // TODO_BLSTTC, this is only done so sosmr compiles
    pub fn verify_chain(&self, msg: &[u8], signature: &BlsSignature) -> bool {
        self.verify(msg, signature)
    }

}

impl TryFrom<&[u8]> for BlsPublicKey {
    type Error = DkgError;

    fn try_from(pk: &[u8]) -> Result<Self, Self::Error> {
        if pk.len() < BLS_PUBLIC_KEY_LEN {
            return Err(DkgError::DeserializationError(
                "Input array is not 48 bytes long".to_owned(),
            ));
        }
        Ok(BlsPublicKey {
            bls12381: G1Projective::from_compressed(pk.try_into().expect("wrong length")).expect("failed to convert pk from bytes")
        })
    }
}