use crate::types::public_key::BlsPublicKey;
use crate::types::signature::BlsSignature;
use blsttc::group::ff::Field;
use blsttc::group::Group;
use blsttc::{hash_g2, Fr, G1Projective, G2Projective};
use crypto::bls12381::rng::RAND_ChaCha20;
use rand::{thread_rng, Rng};
use serde::{de, ser, Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const BLS_PRIVATE_KEY_LEN: usize = 32;

#[derive(Clone)]
pub struct BlsPrivateKey {
    pub bls12381: Fr,
}

impl Debug for BlsPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlsPrivateKey: [SECRET_KEY_REDACTED]")
    }
}

impl Zeroize for BlsPrivateKey {
    fn zeroize(&mut self) {
        self.bls12381 *= Fr::zero();
    }
}

impl Drop for BlsPrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for BlsPrivateKey {}

impl BlsPrivateKey {
    /// Generates random [BlsPrivateKey]. For testing proposes only.
    pub fn random() -> Self {
        let seed = thread_rng().gen::<[u8; 32]>();
        let mut rng = &mut RAND_ChaCha20::new(seed);
        Self {
            bls12381: Fr::random(&mut rng),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.bls12381.to_bytes_be().to_vec()
    }

    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey {
            bls12381: G1Projective::generator() * self.bls12381
        }
    }

    pub fn sign(&self, msg: &[u8]) -> BlsSignature {
        let h = G2Projective::from(hash_g2(msg));
        BlsSignature {
            bls12381: h * self.bls12381
        }
    }
/*
    pub fn sign_domain(&self, msg: &[u8], dst: &[u8]) -> BlsSignature {
        BlsSignature {
            bls12381: BlsSignature12381 {
                sig_g1: sign_point_ecp_12381(&hash_to_ecp_12381(msg, dst), &self.bls12381),
                sig_g2: sign_point_ecp2_12381(&hash_to_ecp2_12381(msg, dst), &self.bls12381),
            }
        }
    }
*/
    // TODO_BLSTTC: this is only here so that sosmr will compile
    pub fn sign_chain(&self, msg: &[u8]) -> BlsSignature {
        self.sign(msg)
    }
}

impl Serialize for BlsPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        //Brute force serialization
        serializer.serialize_str(&hex::encode(self.to_vec()))
    }
}

impl<'de> Deserialize<'de> for BlsPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        //Brute force serialization
        let bytes = hex::decode(s).map_err(|e| de::Error::custom(e.to_string()))?;
        let arr: &[u8] = &bytes;
        let value = BlsPrivateKey::try_from(arr).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl TryFrom<&[u8]> for BlsPrivateKey {
    type Error = anyhow::Error;

    fn try_from(raw_bytes: &[u8]) -> anyhow::Result<Self> {
        if raw_bytes.len() < BLS_PRIVATE_KEY_LEN {
            return Err(anyhow::anyhow!("Invalid private key length"));
        }
        Ok(BlsPrivateKey {
            bls12381: Fr::from_bytes_be((&raw_bytes[0..32]).try_into().expect("failed to convert &[u8] to [u8;32]")).expect("failed to deser"), // 48
        })
    }
}