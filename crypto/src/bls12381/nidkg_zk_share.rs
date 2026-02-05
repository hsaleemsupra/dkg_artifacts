use std::collections::BTreeMap;
use std::ffi::c_ulong;
use blsttc::group::ff::Field;
use cpp_core::{Ref, MutRef};
use blsttc::{Fr, G1Projective};
use bicycl::b_i_c_y_c_l::{Mpz, QFI, RandGen};
use crate::bls12381::random_oracle::{HashedMap, random_oracle_to_fr, UniqueHash};
use crate::bls12381::utils::{fr_to_mpz, get_cl};
use bicycl::{CiphertextBox, MpzBox, PublicKeyBox, QFIBox, rust_vec_to_cpp};
use bicycl::{VectorOfMpz, VectorOfQFI};
use cpp_std::VectorOfUchar;
use rand::Rng;
use crate::bls12381::cg_constants::{LAMBDA_BITS, LAMBDA_ST_BITS};
use crate::dealing::DkgConfig;
use crate::bls12381::rng::RAND_ChaCha20;

/// Domain separators for the zk proof of sharing
const DOMAIN_PROOF_OF_SHARING_INSTANCE: &str = "crypto-cgdkg-bls12381-zk-proof-of-sharing-instance";
const DOMAIN_PROOF_OF_SHARING_CHALLENGE: &str = "crypto-cgdkg-bls12381-zk-proof-of-sharing-challenge";

///   instance = (g_cl,g,[y_1..y_n], [A_0..A_{t-1}], R, [C_1..C_n])
///   g_cl is the generator h from classgroup
///   g is the generator of G1Projective
pub struct SharingInstance {
    pub g_cl: QFIBox,
    pub g: G1Projective,
    pub public_keys: BTreeMap<u32,PublicKeyBox>,
    pub public_evals: Vec<G1Projective>,
    pub randomizer: QFIBox,
    pub ciphertexts: Vec<CiphertextBox>,
}

/// Witness for the validity of a sharing instance.
///
///   Witness = (r, s= [s_1..s_n])
pub struct SharingWitness {
    pub scalar_r: MpzBox,
    pub scalars_m: BTreeMap<u32,Fr>, // David m_i
}

/// Zero-knowledge proof of sharing.
#[derive(Clone, Debug)]
pub struct ZkProofSharing {
    pub ff: QFIBox,
    pub aa: G1Projective,
    pub yy: QFIBox,
    pub z_r: MpzBox,
    pub z_alpha: Fr,
}

struct FirstMoveSharing {
    pub ff: QFIBox,
    pub aa: G1Projective,
    pub yy: QFIBox,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkProofSharingError {
    InvalidProof,
    InvalidInstance,
}

impl UniqueHash for SharingInstance {
    fn unique_hash(&self) -> [u8; 32] {
        let mut map = HashedMap::new();
        map.insert_hashed("g_cl", &self.g_cl);
        map.insert_hashed("g-value", &self.g);
        map.insert_hashed("public-keys", &self.public_keys.values().cloned().collect::<Vec<_>>());
        map.insert_hashed("public-coefficients", &self.public_evals);
        map.insert_hashed("randomizer", &self.randomizer);
        map.insert_hashed("ciphertext", &self.ciphertexts);
        map.unique_hash()
    }
}

impl SharingInstance {
    // Computes the hash of the instance.
    pub fn hash_to_scalar(&self) -> Fr {
        random_oracle_to_fr(DOMAIN_PROOF_OF_SHARING_INSTANCE, self)
    }

    pub fn check_instance(&self) -> Result<(), ZkProofSharingError> {
        if self.public_keys.is_empty() || self.public_evals.is_empty() {
            return Err(ZkProofSharingError::InvalidInstance);
        };
        if self.public_keys.len() != self.ciphertexts.len() {
            return Err(ZkProofSharingError::InvalidInstance);
        };
        Ok(())
    }
}

impl UniqueHash for FirstMoveSharing {
    fn unique_hash(&self) -> [u8; 32] {
        let mut map = HashedMap::new();
        map.insert_hashed("ff", &self.ff);
        map.insert_hashed("aa", &self.aa);
        map.insert_hashed("yy", &self.yy);
        map.unique_hash()
    }
}

fn sharing_proof_challenge(hashed_instance: &Fr, first_move: &FirstMoveSharing) -> Fr {
    let mut map = HashedMap::new();
    map.insert_hashed("instance-hash", hashed_instance);
    map.insert_hashed("first-move", first_move);
    random_oracle_to_fr(DOMAIN_PROOF_OF_SHARING_CHALLENGE, &map)
}

pub fn prove_sharing(
    config: &DkgConfig,
    instance: &SharingInstance,
    witness: &SharingWitness,
) -> ZkProofSharing {

    let seed = rand::thread_rng().gen::<[u8; 32]>();
    let rng = &mut RAND_ChaCha20::new(seed.clone());
    let seed_cpp = unsafe { rust_vec_to_cpp(seed.to_vec()) };
    let ref_seed: cpp_core::Ref<VectorOfUchar> = unsafe { cpp_core::Ref::from_raw_ref(&seed_cpp) };
    let seed_mpz = unsafe { Mpz::from_vector_of_uchar(ref_seed) };
    let ref_seed_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref(&seed_mpz)};
    let mut rng_cpp = unsafe { RandGen::new_1a(ref_seed_mpz) };

    let c = get_cl();

    let node_indices_for_proof: Vec<_> = witness.scalars_m.keys().cloned().collect();

    //   instance = ([y_1..y_n], [A_0..A_{t-1}], R, [C_1..C_n])
    //   witness = (r, [s_1..s_n])
    instance.check_instance().expect("The sharing proof instance is invalid");

    // Hash of instance: x = oracle(instance)
    let x = instance.hash_to_scalar();

    // First move (prover)
    let alpha = Fr::random(rng);
    //refer to: https://eprint.iacr.org/2023/451.pdf for details about the security bit requirements
    let rho = unsafe{rng_cpp.random_mpz_2exp((c.encrypt_randomness_bound().nbits() + LAMBDA_BITS + LAMBDA_ST_BITS) as c_ulong)};
    let ref_rho: Ref<Mpz> = unsafe {Ref::from_raw_ref(&rho)};
    let alpha_mpz = unsafe{ fr_to_mpz(alpha)};

    // F = G^rho
    // A = g^alpha
    // Y = product [y_i^x^i | i <- [1..n]]^rho * g_1^alpha
    let mut ff = unsafe{QFI::new_0a()};
    let mutref_ff: MutRef<QFI> = unsafe {MutRef::from_raw_ref(&mut ff)};
    unsafe{ c.power_of_h(mutref_ff, ref_rho)};
    let aa = instance.g * alpha;

    let mut x_pows = Vec::new();
    x_pows.push(x);
    for i in 1..config.n{
        let mut x_pow = x_pows[(i-1) as usize];
        x_pow *= x;
        x_pows.push(x_pow);
    }

    //only storing x_pows that are required based on the node indices for which proof is created
    let mut x_pows_required = Vec::new();
    for index in node_indices_for_proof.clone(){
        x_pows_required.push(x_pows[index as usize]);
    }
    x_pows = x_pows_required;

    let mut x_pows_mpz = unsafe{VectorOfMpz::new()};
    for x_pow in &x_pows{
        let x_pow_mpz = unsafe{ fr_to_mpz(x_pow.clone())};
        let ref_xpow_mpz: Ref<Mpz> = unsafe {Ref::from_raw_ref(&x_pow_mpz)};
        unsafe{x_pows_mpz.push_back(ref_xpow_mpz)};
    }
    let ref_x_pows_mpz: Ref<VectorOfMpz> = unsafe {Ref::from_raw_ref(&x_pows_mpz)};

    let mut pks_qfi = unsafe{VectorOfQFI::new()};
    for (_index,pk) in &instance.public_keys{
        unsafe{pks_qfi.push_back(pk.0.elt())};
    }
    let ref_pks_qfi : Ref<VectorOfQFI> = unsafe {Ref::from_raw_ref(&pks_qfi)};
    let mut acc_pk = unsafe{QFI::new_0a()};
    let mutref_acc_pk: MutRef<QFI> = unsafe {MutRef::from_raw_ref(&mut acc_pk)};
    unsafe{ c.cl_g().mult_exp(mutref_acc_pk, ref_pks_qfi, ref_x_pows_mpz)};

    let ref_alpha_mpz : Ref<Mpz> = unsafe {Ref::from_raw_ref(&alpha_mpz)};
    let f_aa = unsafe{ c.power_of_f(ref_alpha_mpz)};
    let ref_f_aa : Ref<QFI> = unsafe {Ref::from_raw_ref(&f_aa)};

    let mut yy = unsafe{QFI::new_0a()};
    let mutref_yy : MutRef<QFI> = unsafe {MutRef::from_raw_ref(&mut yy)};
    unsafe{ c.cl_g().nupow_3a(mutref_yy, mutref_acc_pk, ref_rho)};
    unsafe{ c.cl_delta().nucomp(mutref_yy, mutref_yy, ref_f_aa)};

    let first_move = FirstMoveSharing {
        ff: QFIBox(ff),
        aa: aa.clone(),
        yy: QFIBox(yy),
    };

    // Second move (verifier's challenge)
    // x' = oracle(x, F, A, Y)
    let x_challenge = sharing_proof_challenge(&x, &first_move);
    let x_challenge_mpz = unsafe{ fr_to_mpz(x_challenge)};
    let ref_x_challenge_mpz: Ref<Mpz> = unsafe{Ref::from_raw_ref(&x_challenge_mpz)};

    // Third move (prover)
    // z_r = r * x' + rho mod p
    // z_alpha = x' * sum [s_i*x^i | i <- [1..n]] + alpha mod p
    let mut z_r = unsafe{Mpz::new()};
    let mutref_z_r: MutRef<Mpz> = unsafe{MutRef::from_raw_ref(&mut z_r)};
    let ref_r: Ref<Mpz> = unsafe{Ref::from_raw_ref(&witness.scalar_r.0)};
    unsafe{Mpz::mul_mpz2_mpz(mutref_z_r, ref_r, ref_x_challenge_mpz)};
    unsafe{Mpz::add_mpz2_mpz(mutref_z_r, mutref_z_r, ref_rho)};

    let mut z_alpha = witness.scalars_m[&node_indices_for_proof[0]] * &x_pows[0];
    for i in 1..node_indices_for_proof.len(){
        let tmp = witness.scalars_m[&node_indices_for_proof[i]] * &x_pows[i];
        z_alpha += tmp;
    }
    z_alpha *= x_challenge;
    z_alpha += alpha;

    ZkProofSharing {
        ff: first_move.ff.clone(),
        aa: aa.clone(),
        yy: first_move.yy.clone(),
        z_r: MpzBox(z_r),
        z_alpha,
    }
}

pub fn verify_sharing(
    config: &DkgConfig,
    instance: &SharingInstance,
    nizk: &ZkProofSharing,
) -> Result<(), ZkProofSharingError> {

    let c = get_cl();
    let node_indices_for_proof: Vec<_> = instance.public_keys.keys().cloned().collect();

    instance.check_instance()?;
    // Hash of Instance
    // x = oracle(instance)
    let x = instance.hash_to_scalar();

    let ref_ff: Ref<QFI> = unsafe{Ref::from_raw_ref(&nizk.ff.0)};
    let ref_yy: Ref<QFI> = unsafe{Ref::from_raw_ref(&nizk.yy.0)};

    let first_move = FirstMoveSharing {
        ff: nizk.ff.clone(),
        aa: nizk.aa.clone(),
        yy: nizk.yy.clone(),
    };

    // Verifier's challenge
    // x' = oracle(x, F, A, Y)
    let x_challenge = sharing_proof_challenge(&x, &first_move);
    let x_challenge_mpz = unsafe{ fr_to_mpz(x_challenge)};
    let ref_x_challenge_mpz: Ref<Mpz> = unsafe {Ref::from_raw_ref(&x_challenge_mpz)};

    let mut x_pows = Vec::new();
    x_pows.push(x);
    for i in 1..config.n{
        let mut x_pow = x_pows[(i-1) as usize];
        x_pow *= x;
        x_pows.push(x_pow);
    }

    //only storing x_pows that are required based on the node indices for which proof is created
    let mut x_pows_required = Vec::new();
    for index in node_indices_for_proof.clone(){
        x_pows_required.push(x_pows[index as usize]);
    }
    x_pows = x_pows_required;

    let mut x_pows_mpz = unsafe{VectorOfMpz::new()};
    for x_pow in &x_pows{
        let x_pow_mpz = unsafe{ fr_to_mpz(x_pow.clone())};
        let ref_xpow_mpz: Ref<Mpz> = unsafe {Ref::from_raw_ref(&x_pow_mpz)};
        unsafe{x_pows_mpz.push_back(ref_xpow_mpz)};
    }
    let ref_xpows_mpz: Ref<VectorOfMpz> = unsafe {Ref::from_raw_ref(&x_pows_mpz)};

    // First verification equation
    // R^x' * F == g_1^z_r

    let mut lhs_first = unsafe{QFI::new_0a()};
    let mutref_lhs_first: MutRef<QFI> = unsafe {MutRef::from_raw_ref(&mut lhs_first)};
    let ref_randomizer: Ref<QFI> = unsafe {Ref::from_raw_ref(&instance.randomizer.0)};
    unsafe{ c.cl_g().nupow_3a(mutref_lhs_first, ref_randomizer, ref_x_challenge_mpz)};
    unsafe{ c.cl_delta().nucomp(mutref_lhs_first, mutref_lhs_first, ref_ff)};

    let mut rhs_first = unsafe{QFI::new_0a()};
    let mutref_rhs_first: MutRef<QFI> = unsafe {MutRef::from_raw_ref(&mut rhs_first)};
    let ref_rhs_first: Ref<QFI> = unsafe {Ref::from_raw_ref(&rhs_first)};
    let ref_z_r: Ref<Mpz> = unsafe {Ref::from_raw_ref(&nizk.z_r.0)};
    unsafe{ c.power_of_h(mutref_rhs_first, ref_z_r)};

    if !(lhs_first == ref_rhs_first) {
        return Err(ZkProofSharingError::InvalidProof);
    }

    // Second Verification
    // Verify: product [A_k ^ [ x^i | i <- [1..n]] ]^x' * A
    // == g_2^z_alpha
    let mut public_evals_required: Vec<G1Projective> = Vec::new();
    for index in node_indices_for_proof.clone(){
        if instance.public_evals.get(index as usize).is_none(){
            return Err(ZkProofSharingError::InvalidProof);
        }
        public_evals_required.push(instance.public_evals[index as usize].clone());
    }

    let mut lhs: G1Projective = G1Projective::multi_exp(public_evals_required.as_slice(), x_pows.as_slice());

    lhs *= x_challenge;
    lhs += nizk.aa;

    let rhs = instance.g * nizk.z_alpha;
    if !lhs.eq(&rhs) {
        return Err(ZkProofSharingError::InvalidProof);
    }

    // Third verification equation
    // LHS = product [C_i ^ x^i | i <- [1..n]]^x' * Y
    // RHS = product [y_i ^ x^i | i <- 1..n]^z_r * g_1^z_alpha
    let mut ciphers =unsafe{VectorOfQFI::new()};
    for i in 0..instance.public_keys.len(){
        unsafe{ciphers.push_back(instance.ciphertexts[i].0.c2())};
    }
    let ref_ciphers: Ref<VectorOfQFI> = unsafe {Ref::from_raw_ref(&ciphers)};

    let mut lhs_qfi = unsafe{QFI::new_0a()};
    let mut rhs_qfi = unsafe{QFI::new_0a()};
    let mutref_lhs: MutRef<QFI> = unsafe {MutRef::from_raw_ref(&mut lhs_qfi)};
    let mutref_rhs: MutRef<QFI> = unsafe {MutRef::from_raw_ref(&mut rhs_qfi)};
    let ref_rhs: Ref<QFI> = unsafe {Ref::from_raw_ref(&rhs_qfi)};
    unsafe{ c.cl_g().mult_exp(mutref_lhs, ref_ciphers, ref_xpows_mpz)};
    unsafe{ c.cl_g().nupow_3a(mutref_lhs, mutref_lhs, ref_x_challenge_mpz)};
    unsafe{ c.cl_delta().nucomp(mutref_lhs, mutref_lhs, ref_yy)};

    let mut pks = unsafe{VectorOfQFI::new()};
    for (_index, pk) in &instance.public_keys{
        unsafe{pks.push_back(pk.0.elt())};
    }
    let ref_pks: Ref<VectorOfQFI> = unsafe {Ref::from_raw_ref(&pks)};

    unsafe{ c.cl_g().mult_exp(mutref_rhs, ref_pks, ref_xpows_mpz)};

    let z_alpha_mpz = unsafe{ fr_to_mpz(nizk.z_alpha)};
    let ref_z_alpha_mpz: Ref<Mpz> = unsafe {Ref::from_raw_ref(&z_alpha_mpz)};
    let f_z_alpha = unsafe{ c.power_of_f(ref_z_alpha_mpz)};
    let ref_f_z_alpha: Ref<QFI> = unsafe {Ref::from_raw_ref(&f_z_alpha)};
    let ref_z_r: Ref<Mpz> = unsafe {Ref::from_raw_ref(&nizk.z_r.0)};
    unsafe{ c.cl_g().nupow_3a(mutref_rhs, mutref_rhs, ref_z_r)};
    unsafe{ c.cl_delta().nucomp(mutref_rhs, mutref_rhs, ref_f_z_alpha)};

    if!(lhs_qfi == ref_rhs){
        return Err(ZkProofSharingError::InvalidProof);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use bicycl::b_i_c_y_c_l::CLHSMqk;
    use blsttc::group::Group;
    use cpp_core::CppBox;
    use cpp_std::VectorOfUchar;
    use bicycl::b_i_c_y_c_l::utils::{CLHSMPublicKeyOfCLHSMqk as PublicKey};
    use bicycl::rust_vec_to_cpp;
    use rand::RngCore;
    use crate::bls12381::cg_encryption::{encrypt_all, keygen};
    use crate::bls12381::polynomial::Polynomial;
    use crate::bls12381::public_evals::PublicEvals;
    use crate::bls12381::rng::RAND_ChaCha20;
    use crate::bls12381::utils::get_cl;
    use super::*;

    // FUNCTIONAL CHANGE, RngCore instead of RAND
    fn setup_sharing_instance_and_witness(c: &cpp_core::CppBox<CLHSMqk>, rng: &mut impl RngCore, rng_cpp: &mut CppBox<RandGen>)
        -> (QFIBox, G1Projective, BTreeMap<u32,PublicKeyBox>, Vec<G1Projective>, Vec<CiphertextBox>, MpzBox, QFIBox, BTreeMap<u32,Fr>, DkgConfig) {
        let g = G1Projective::generator();
        let mut pks = BTreeMap::new();
        let node_count = 28;
        let threshold = 10;

        let config = DkgConfig { t: threshold, n: node_count };

        let associated_data = Vec::new();

        for i in 0..node_count {
            let(_sk,pk, _pop) = keygen(&c, rng_cpp, &associated_data);
            pks.insert(i as u32, pk);
        }

        //each node generates a random polynomial with THRESHOLD coefficients
        //i.e. >=THRESHOLD shares required for reconstruction
        let poly = Polynomial::random(threshold as usize, rng);

        //a node generates n evaluations using his secret polynomial one for each of the n total nodes
        let mut evaluations= BTreeMap::new();
        for j in 0..node_count{
            evaluations.insert(j, poly.evaluate_at(&Fr::from((j + 1) as u64)));
        }

        let evals: Vec<Fr> = evaluations.values().cloned().collect();
        // Here we use a different generator h
        // This is done to prevent the key biasing attack.
        let pub_evals = PublicEvals::from_evals(&evals, &g);

        let (ciphers, r) = encrypt_all(&pks.values().cloned().collect(), evaluations.values().cloned().collect());

        let mut g_r = unsafe{QFI::new_0a()};
        let ref_r: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref(&r.0)};
        let mutref_g_r: cpp_core::MutRef<QFI> = unsafe{cpp_core::MutRef::from_raw_ref(&mut g_r)};
        unsafe{ c.power_of_h(mutref_g_r, ref_r)};

        let ffi_h = unsafe{bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
            cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(c.h())
                .as_raw_ptr(),
        )};
        let h_qfi = unsafe{cpp_core::CppBox::from_raw(ffi_h)}.expect("attempted to construct a null CppBox");
        let h_qfi_box = QFIBox(h_qfi);

        (h_qfi_box, g, pks, pub_evals.evals, ciphers, r, QFIBox(g_r), evaluations, config)
    }

    #[test]
    fn sharing_nizk_should_verify() {

        let seed = [4u8; 32];
        let seed_cpp = unsafe { rust_vec_to_cpp(seed.to_vec()) };
        let ref_seed: cpp_core::Ref<VectorOfUchar> = unsafe { cpp_core::Ref::from_raw_ref(&seed_cpp) };
        let seed_mpz = unsafe { Mpz::from_vector_of_uchar(ref_seed) };
        let ref_seed_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref(&seed_mpz)};
        let rng = &mut RAND_ChaCha20::new(seed);
        let mut rng_cpp = unsafe { RandGen::new_1a(ref_seed_mpz) };

        let c = get_cl();
        let (h, g, pk, aa, cc, r, g_r, s, config) = setup_sharing_instance_and_witness(&c, rng, &mut rng_cpp);

        let instance = SharingInstance {
            g_cl: h,
            g: g,
            public_keys: pk,
            public_evals: aa,
            randomizer: g_r,
            ciphertexts: cc,
        };
        let witness = SharingWitness {
            scalar_r: r,
            scalars_m: s.clone(),
        };
        let sharing_proof = prove_sharing(&config, &instance, &witness);
        assert_eq!(
            Ok(()),
            verify_sharing(&config, &instance, &sharing_proof),
            "verify_sharing verifies NIZK proof"
        );
    }

    #[test]
    #[should_panic(expected = "The sharing proof instance is invalid: InvalidInstance")]
    fn sharing_prover_should_panic_on_empty_coefficients() {
        let seed = [4u8; 32];
        let seed_cpp = unsafe { rust_vec_to_cpp(seed.to_vec()) };
        let ref_seed: cpp_core::Ref<VectorOfUchar> = unsafe { cpp_core::Ref::from_raw_ref(&seed_cpp) };
        let seed_mpz = unsafe { Mpz::from_vector_of_uchar(ref_seed) };
        let ref_seed_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref(&seed_mpz)};
        let rng = &mut RAND_ChaCha20::new(seed);
        let mut rng_cpp = unsafe { RandGen::new_1a(ref_seed_mpz) };

        let c = get_cl();

        let (h, g, pk, _aa, cc, r, g_r, s, config) = setup_sharing_instance_and_witness(&c, rng, &mut rng_cpp);

        let instance = SharingInstance {
            g_cl: h,
            g: g,
            public_keys: pk,
            public_evals: vec![],
            randomizer: g_r,
            ciphertexts: cc,
        };
        let witness = SharingWitness {
            scalar_r: r,
            scalars_m: s.clone(),
        };

        let _panic_one = prove_sharing(&config,&instance, &witness);
    }

    #[test]
    #[should_panic(expected = "The sharing proof instance is invalid: InvalidInstance")]
    fn sharing_prover_should_panic_on_invalid_instance() {
        let seed = [4u8; 32];
        let seed_cpp = unsafe { rust_vec_to_cpp(seed.to_vec()) };
        let ref_seed: cpp_core::Ref<VectorOfUchar> = unsafe { cpp_core::Ref::from_raw_ref(&seed_cpp) };
        let seed_mpz = unsafe { Mpz::from_vector_of_uchar(ref_seed) };
        let ref_seed_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref(&seed_mpz)};
        let rng = &mut RAND_ChaCha20::new(seed);
        let mut rng_cpp = unsafe { RandGen::new_1a(ref_seed_mpz) };

        let c = get_cl();

        let (h, g, mut pk, aa, cc, r, g_r, s, config) = setup_sharing_instance_and_witness(&c, rng, &mut rng_cpp);

        let nodes_indices_for_proof: Vec<_> = s.keys().cloned().collect();

        pk.insert(nodes_indices_for_proof[nodes_indices_for_proof.len()-1]+1,unsafe{PublicKeyBox(PublicKey::new())});

        let instance = SharingInstance {
            g_cl: h,
            g: g,
            public_keys: pk,
            public_evals: aa,
            randomizer: g_r,
            ciphertexts: cc,
        };
        let witness = SharingWitness {
            scalar_r: r,
            scalars_m: s.clone(),
        };

        let _panic_one = prove_sharing(&config,&instance, &witness);
    }


    #[test]
    fn sharing_nizk_should_fail_on_invalid_proof() {
        let seed = [4u8; 32];
        let seed_cpp = unsafe { rust_vec_to_cpp(seed.to_vec()) };
        let ref_seed: cpp_core::Ref<VectorOfUchar> = unsafe { cpp_core::Ref::from_raw_ref(&seed_cpp) };
        let seed_mpz = unsafe { Mpz::from_vector_of_uchar(ref_seed) };
        let ref_seed_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref(&seed_mpz)};
        let rng = &mut RAND_ChaCha20::new(seed);
        let mut rng_cpp = unsafe { RandGen::new_1a(ref_seed_mpz) };

        let c = get_cl();

        let (h, g, pk, aa, cc, r, g_r, s, config) = setup_sharing_instance_and_witness(&c, rng, &mut rng_cpp);

        let instance = SharingInstance {
            g_cl: h,
            g: g,
            public_keys: pk,
            public_evals: aa,
            randomizer: g_r,
            ciphertexts: cc,
        };
        let witness = SharingWitness {
            scalar_r: r,
            scalars_m: s.clone(),
        };
        let sharing_proof = prove_sharing(&config, &instance, &witness);

        let invalid_proof = ZkProofSharing {
            ff: sharing_proof.ff,
            aa: sharing_proof.aa,
            yy: unsafe{QFIBox(QFI::new_0a())},
            z_r: sharing_proof.z_r,
            z_alpha: sharing_proof.z_alpha,
        };
        assert_eq!(
            Err(ZkProofSharingError::InvalidProof),
            verify_sharing(&config, &instance, &invalid_proof),
            "verify_sharing fails on invalid proof"
        );
    }
}
