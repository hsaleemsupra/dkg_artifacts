use blsttc::{G1Projective};
use crypto::errors::DkgError;
use crate::utils::{
    convert_g1_proj_to_bytes, convert_vec_g1_proj_to_bytes,
};
use crypto::bls12381::public_evals::PublicEvals as PublicEvals12381;
//use miracl_core_bls12381::bls12381::ecp::ECP as BLS12381ECP;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct PublicEvals {
    pub public_evals_bls12381: PublicEvals12381,
}

#[allow(clippy::type_complexity)]
#[derive(Serialize, Deserialize, Debug)]
pub struct PublicEvalsBytes {
    pub public_evals_bls12381: (Vec<u8>, Vec<Vec<u8>>),
}

impl PublicEvals {
    pub fn into_bytes(&self) -> Vec<u8> {
        let public_evals_12381: (Vec<u8>, Vec<Vec<u8>>) = (
            convert_g1_proj_to_bytes(&self.public_evals_bls12381.g),
            convert_vec_g1_proj_to_bytes(&self.public_evals_bls12381.evals),
        );

        let pub_poly_bytes = PublicEvalsBytes {
            public_evals_bls12381: public_evals_12381,
        };

        bincode::serialize(&pub_poly_bytes).unwrap()
    }
}

impl TryFrom<&[u8]> for PublicEvals {
    type Error = DkgError;
    fn try_from(raw_bytes: &[u8]) -> Result<Self, Self::Error> {
        let m: Result<PublicEvalsBytes, _> = bincode::deserialize(raw_bytes);
        if let Ok(d) = m {
            Ok(PublicEvals {
                public_evals_bls12381:
                PublicEvals12381 {
                    g: G1Projective::from_compressed(&d.public_evals_bls12381.0.try_into().expect("vec wrong length")).expect("failed to deser"),
                    evals: d
                        .public_evals_bls12381
                        .1
                        .iter()
                        .map(|x| G1Projective::from_compressed(&<[u8;48]>::try_from(x.clone()).expect("vec wrong length")).expect("failed to deser"))
                        .collect(),
                        // TODO_BLSTTC: inefficient code, clone necessary to make it work
                },
            })
        } else {
            Err(DkgError::DeserializationError(
                "error during deserialization".to_string(),
            ))
        }
    }
}
