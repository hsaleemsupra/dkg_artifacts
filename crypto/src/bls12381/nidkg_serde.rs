use bicycl::CiphertextBox;
use blsttc::{Fr, G1Projective, G2Projective};

pub fn convert_fr_to_bytes(x: &Fr) -> Vec<u8> {
    x.to_bytes_be().to_vec()
}

pub fn convert_vec_fr_to_bytes(x: &[Fr]) -> Vec<Vec<u8>> {
    x.iter().map(convert_fr_to_bytes).collect()
}

pub fn convert_g1_proj_to_bytes(x: &G1Projective) -> Vec<u8> {
    x.to_compressed().to_vec()
}

pub fn convert_vec_g1_proj_to_bytes(x: &[G1Projective]) -> Vec<Vec<u8>> {
    x.iter().map(convert_g1_proj_to_bytes).collect()
}

pub fn convert_g2_proj_to_bytes(x: &G2Projective) -> Vec<u8> {
    x.to_compressed().to_vec()
}

pub fn convert_cipher_to_bytes(x: &CiphertextBox) -> Vec<u8> {
    unsafe { x.to_bytes() }
}

pub fn convert_vec_cipher_to_bytes(x: &[CiphertextBox]) -> Vec<Vec<u8>>{
    x.iter().map(convert_cipher_to_bytes).collect()
}