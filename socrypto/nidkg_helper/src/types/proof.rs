use blsttc::Fr;
// use crypto::bls12381::nizk_dleq::ZkProofDLEq as ZkProofDLEq12381;

use crypto::errors::DkgError; // needed for from_bytes_be? NO, Fr::from_bytes_be likely exists on Fr directly or via Field trait? blsttc Fr usually has generic methods.
                              // Check blsttc crate docs or usage. code used Fr::from_bytes_be.

pub const BLS_PROOF_LEN: usize = 64;
#[derive(Debug, Clone)]
pub struct DLEqProof {
    pub c: Fr,
    pub s: Fr,
}

impl DLEqProof {
    pub fn to_vec(&self) -> Vec<u8> {
        [self.c.to_bytes_be(), self.s.to_bytes_be()].concat()
    }
}

impl TryFrom<&[u8]> for DLEqProof {
    type Error = DkgError;

    fn try_from(dleq_bytes: &[u8]) -> Result<Self, Self::Error> {
        if dleq_bytes.len() < BLS_PROOF_LEN {
            return Err(DkgError::DeserializationError(
                "Input array is not 64 bytes long".to_owned(),
            ));
        }
        Ok(DLEqProof {
            c: Fr::from_bytes_be(&dleq_bytes[0..32].try_into().unwrap()).unwrap(), // TODO: safe unwrap or handle error. existing code expected success or panic
            s: Fr::from_bytes_be(&dleq_bytes[32..64].try_into().unwrap()).unwrap(),
        })
    }
}
