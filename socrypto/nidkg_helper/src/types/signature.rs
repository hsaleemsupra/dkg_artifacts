use blsttc::G2Projective;
use crypto::errors::DkgError;
use crate::utils::convert_g2_proj_to_bytes;
use serde::{de, Deserialize, Serialize};

pub const BLS_SIGNATURE_LEN: usize = 96;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BlsSignature {
    // using G2Projective instead of Signature because this is both agg and partial signature
    pub bls12381: G2Projective,
}

impl BlsSignature {
    // I am not sure how much it makes sense or it's worth it in terms of optimization
    // but into_bytes functions can be optimized to have
    // vector buffer with predefined size and pass it as input to converter function to fill
    // the required data instead of doing small conversions and concat.
    pub fn to_vec(&self) -> Vec<u8> {
        convert_g2_proj_to_bytes(&self.bls12381)
    }
}

impl Serialize for BlsSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        //Brute force serialization
        serializer.serialize_str(&hex::encode(self.to_vec()))
    }
}

impl<'de> Deserialize<'de> for BlsSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        //Brute force serialization
        let bytes = hex::decode(s).map_err(|e| de::Error::custom(e.to_string()))?;
        let arr: &[u8] = &bytes;
        let value = BlsSignature::try_from(arr).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl TryFrom<&[u8]> for BlsSignature {
    type Error = DkgError;

    fn try_from(pk: &[u8]) -> Result<Self, Self::Error> {
        if pk.len() < BLS_SIGNATURE_LEN {
            return Err(DkgError::DeserializationError(
                "Input array is not 96 bytes long".to_owned(),
            ));
        }
        Ok(BlsSignature {
            bls12381: G2Projective::from_compressed(pk.try_into().expect("incorrect length")).expect("failed to convert bytes to BlsSignature")
        })
    }
}

// BlsSignature has been updated to only contain g2
// keeping BlsSignature12381G2 to avoid refactor
pub type BlsSignature12381G2 = BlsSignature;