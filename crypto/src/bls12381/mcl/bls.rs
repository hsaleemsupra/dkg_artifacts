use super::{
    hash::hash_to_ecp,
    pair,
    rom::{self, g2_generator},
};
use lazy_static::lazy_static;
use miracl_core_bls12381::{
    bls12381::{
        big::{self, BIG},
        dbig::DBIG,
        ecp::{self, ECP, G2_TABLE},
        ecp2::ECP2,
        fp4::FP4,
    },
    hmac,
    rand::RAND,
};

use crate::{
    bls12381::bls12381_serde::ecp2_to_bytes,
    bls12381::context::{Context, DomainSeparationContext},
};

pub const DOMAIN_MCL_POP: &str = "crypto-mcl-pop";

pub const BFS: usize = big::MODBYTES;
pub const BGS: usize = big::MODBYTES;
pub const BLS_OK: isize = 0;
pub const BLS_FAIL: isize = -1;

lazy_static! {
    static ref G2_TAB_MCL: [FP4; G2_TABLE] = precomp_g2_tab_mcl();
}

fn precomp_g2_tab_mcl() -> [FP4; G2_TABLE] {
    let mut ret = [FP4::new(); G2_TABLE];
    let g = g2_generator();
    pair::precomp(&mut ret, &g);
    ret
}

fn ceil(a: usize, b: usize) -> usize {
    (a - 1) / b + 1
}

/* generate key pair, private key s, public key w */
pub fn key_pair_generate(ikm: &[u8], s: &mut [u8], w: &mut [u8]) -> isize {
    let r = BIG::new_ints(&rom::CURVE_ORDER);
    let nbr = r.nbits();
    let el = ceil(3 * ceil(nbr, 8), 2);
    let g = g2_generator();
    let mut len: [u8; 2] = [0; 2];
    hmac::inttobytes(el, &mut len);
    let salt = "BLS-SIG-KEYGEN-SALT-MCL-";

    let mut prk: [u8; 64] = [0; 64];
    let mut okm: [u8; 128] = [0; 128];
    let mut aikm: [u8; 65] = [0; 65];
    let likm = ikm.len();
    aikm[..likm].copy_from_slice(&ikm[..likm]);
    aikm[likm] = 0;

    let hlen = ecp::HASH_TYPE;

    hmac::hkdf_extract(
        hmac::MC_SHA2,
        hlen,
        &mut prk,
        Some(salt.as_bytes()),
        &aikm[0..likm + 1],
    );
    hmac::hkdf_expand(hmac::MC_SHA2, hlen, &mut okm, el, &prk[0..hlen], &len);

    let mut dx = DBIG::frombytes(&okm[0..el]);
    let sc = dx.ctdmod(&r, 8 * el - nbr);
    sc.tobytes(s);
    // SkToPk
    pair::g2mul(&g, &sc).tobytes(w, true); // true for public key compression
    BLS_OK
}

pub fn keypair_from_seed(ikm: &[u8; 32]) -> (BIG, ECP2) {
    const MB: usize = 2 * big::MODBYTES + 1;
    let mut w = [0u8; MB];
    let mut s = [0u8; big::MODBYTES];

    key_pair_generate(ikm, &mut s, &mut w);
    (BIG::frombytes(&s), ECP2::frombytes(&w))
}
#[allow(clippy::needless_range_loop)]
pub fn keypair_from_rng(rng: &mut dyn RAND) -> (BIG, ECP2) {
    let mut ikm = [0u8; 32];
    for i in 0..32 {
        ikm[i] = rng.getbyte();
    }
    keypair_from_seed(&ikm)
}

pub fn public_key_from_secret_key(secret_key: &BIG) -> ECP2 {
    pair::g2mul(&g2_generator(), secret_key)
}

pub fn sign_point(point: &ECP, secret_key: &BIG) -> ECP {
    pair::g1mul(point, secret_key)
}

pub fn sign_message(message: &[u8], secret_key: &BIG) -> ECP {
    let d = hash_to_ecp(message);
    sign_point(&d, secret_key)
}

pub fn domain_separated_public_key_bytes(public_key: &ECP2) -> Vec<u8> {
    let public_key_bytes = ecp2_to_bytes(public_key);

    let mut domain_separated_public_key: Vec<u8> = vec![];
    domain_separated_public_key.extend(DomainSeparationContext::new(DOMAIN_MCL_POP).as_bytes());
    domain_separated_public_key.extend(&public_key_bytes[..]);
    domain_separated_public_key
}

// SAME AS BLS12381

pub fn combine_signatures(signatures: &[ECP]) -> ECP {
    signatures
        .iter()
        .fold(ECP::new(), |mut accumulator, point| {
            accumulator.add(point);
            accumulator
        })
}

// SAME AS BLS12381

pub fn combine_public_keys(public_keys: &[ECP2]) -> ECP2 {
    public_keys
        .iter()
        .fold(ECP2::new(), |mut accumulator, point| {
            accumulator.add(point);
            accumulator
        })
}

// verify that given g1^xi and g2^yi, xi == yi
// verify using the check: e(g1^sk_i, g2) ?= e(g1, g2^sk_i)
pub fn verify_public_key(g1_ski: &ECP, g2_ski: &ECP2) -> bool {
    if !pair::g1member(g1_ski) {
        return false;
    }
    let mut d = g1_ski.clone();
    d.neg();

    if !pair::g2member(g2_ski) {
        return false;
    }

    // Use new multi-pairing mechanism
    let mut r = pair::initmp();

    pair::another_pc(&mut r, &G2_TAB_MCL[..], &d);
    pair::another(&mut r, g2_ski, &ECP::generator());
    let mut v = pair::miller(&mut r);

    v = pair::fexp(&v);
    v.isunity()
}

pub fn verify_point(hash: &ECP, signature: &ECP, public_key: &ECP2) -> bool {
    if !pair::g1member(signature) {
        return false;
    }
    let mut d = signature.clone();
    d.neg();

    if !pair::g2member(public_key) {
        return false;
    }

    // Use new multi-pairing mechanism
    let mut r = pair::initmp();

    pair::another_pc(&mut r, &G2_TAB_MCL[..], &d);
    pair::another(&mut r, public_key, hash);
    let mut v = pair::miller(&mut r);

    // let mut v = pair::ate2(&g, &d, public_key, hash);

    v = pair::fexp(&v);
    v.isunity()
}

pub fn verify_message_signature(message: &[u8], signature: &ECP, public_key: &ECP2) -> bool {
    let hash = hash_to_ecp(message);
    verify_point(&hash, signature, public_key)
}

pub fn verify_combined_message_signature(
    message: &[u8],
    signature: &ECP,
    public_keys: &[ECP2],
) -> bool {
    let public_key = combine_public_keys(public_keys);
    verify_message_signature(message, signature, &public_key)
}

pub fn create_pop_sig(public_key: &ECP2, secret_key: &BIG) -> ECP {
    let domain_separated_public_key = domain_separated_public_key_bytes(public_key);
    sign_message(&domain_separated_public_key[..], secret_key)
}

pub fn verify_pop_sig(pop: &ECP, public_key: &ECP2) -> bool {
    let domain_separated_public_key = domain_separated_public_key_bytes(public_key);
    verify_message_signature(&domain_separated_public_key, pop, public_key)
}
