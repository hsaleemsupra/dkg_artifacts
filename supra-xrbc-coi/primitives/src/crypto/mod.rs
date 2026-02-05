use crate::HASH32;
use sha3::{digest::FixedOutput, Digest, Keccak256};

pub struct Hashers;

impl Hashers {
    pub fn keccak256(data: &[u8]) -> HASH32 {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        <HASH32>::from(hasher.finalize_fixed())
    }

    pub fn keccak256_collection(data: Vec<&[u8]>) -> HASH32 {
        let mut hasher = Keccak256::new();
        for d in data {
            hasher.update(d);
        }
        <HASH32>::from(hasher.finalize_fixed())
    }
}
