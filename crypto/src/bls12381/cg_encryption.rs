use std::collections::BTreeMap;
use blsttc::group::Group;
use cpp_core::CppBox;
use blsttc::{Fr, G1Projective};
use bicycl::b_i_c_y_c_l::{Mpz, RandGen, QFI};
use crate::bls12381::key_pop_zk::{create_pop_zk, PopZk, PopZkInstance};
use bicycl::b_i_c_y_c_l::utils::{CLHSMSecretKeyOfCLHSMqk as SecretKey, CLHSMPublicKeyOfCLHSMqk as PublicKey, CLHSMClearTextOfCLHSMqk as ClearText, CLHSMCipherTextOfCLHSMqk as CipherText};
use crate::bls12381::utils::{fr_to_mpz, get_cl};
use bicycl::b_i_c_y_c_l::CLHSMqk;
use bicycl::{CiphertextBox, MpzBox, PublicKeyBox, QFIBox, rust_vec_to_cpp, SecretKeyBox, VectorOfCLHSMClearTextOfCLHSMqk, VectorOfCLHSMPublicKeyOfCLHSMqk};
use bicycl::__ffi;
use cpp_std::VectorOfUchar;
use rand::Rng;
use crate::bls12381::nidkg_zk_share::{prove_sharing, verify_sharing, SharingInstance, SharingWitness, ZkProofSharing};
use crate::errors::DkgError;
use crate::dealing::DkgConfig;

#[derive(Debug, Clone)]
pub struct CiphersWithSharingProof{
    pub ciphers: Vec<CiphertextBox>,
    pub zk_sharing_proof: ZkProofSharing,
    pub randomizer: QFIBox //required by ZK proof instance
}

pub fn get_r_for_encryption() -> MpzBox{
    let seed = rand::thread_rng().gen::<[u8; 32]>();
    let seed_cpp = unsafe { rust_vec_to_cpp(seed.to_vec()) };
    let ref_seed: cpp_core::Ref<VectorOfUchar> = unsafe { cpp_core::Ref::from_raw_ref(&seed_cpp) };
    let seed_mpz = unsafe { Mpz::from_vector_of_uchar(ref_seed) };
    let ref_seed_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref(&seed_mpz)};
    let mut rng_cpp = unsafe { RandGen::new_1a(ref_seed_mpz) };

    let c = get_cl();
    let r_cpp = unsafe { Mpz::new_copy(&rng_cpp.random_mpz(c.encrypt_randomness_bound())) };
    let r = MpzBox(r_cpp);
    r
}

impl CiphersWithSharingProof {
    pub fn new(shares_to_encrypt: BTreeMap<u32,Fr>,
               node_pks_for_shares_to_encrypt: BTreeMap<u32,PublicKeyBox>,
               dealing_public_coefficients: Vec<G1Projective>,
               config: DkgConfig) -> Result<Self, DkgError> {

        //Ensure that the node_ids are same in both the shares maps and pks map
        let share_keys: Vec<u32> = shares_to_encrypt.keys().cloned().collect();
        let node_pks: Vec<u32> = node_pks_for_shares_to_encrypt.keys().cloned().collect();

        if share_keys!=node_pks{
            return Err(DkgError::GeneralError("Node ids mismatch for shares_to_encrypt and node_pks".to_string()));
        }

        if dealing_public_coefficients.len() != config.n as usize{
            return Err(DkgError::GeneralError( format!("dealing_public_coefficients len should be equal to n: {:?} but is: {:?} ", config.n, dealing_public_coefficients.len())));

        }

        let c = get_cl();

        let (ciphers, r) = encrypt_all(&node_pks_for_shares_to_encrypt.values().cloned().collect(),
                                       shares_to_encrypt.values().cloned().collect());

        let mut g_r = unsafe { QFI::new_0a() };
        let ref_r: cpp_core::Ref<Mpz> = unsafe { cpp_core::Ref::from_raw_ref(&r.0) };
        let mutref_g_r: cpp_core::MutRef<QFI> = unsafe { cpp_core::MutRef::from_raw_ref(&mut g_r) };
        unsafe { c.power_of_h(mutref_g_r, ref_r) };

        let ffi_h = unsafe{bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
            cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(c.h())
                .as_raw_ptr(),
        )};
        let h_qfi = unsafe{cpp_core::CppBox::from_raw(ffi_h)}.expect("attempted to construct a null CppBox");
        let h = QFIBox(h_qfi);

        let aa = dealing_public_coefficients;
        let instance = SharingInstance {
            g_cl: h,
            g: G1Projective::generator(),
            public_keys: node_pks_for_shares_to_encrypt,
            public_evals: aa,
            randomizer: QFIBox(g_r),
            ciphertexts: ciphers.clone(),
        };

        let witness = SharingWitness {
            scalar_r: r,
            scalars_m: shares_to_encrypt,
        };

        let zk_share = prove_sharing(
            &config,
            &instance,
            &witness);

        Ok(CiphersWithSharingProof {
            ciphers,
            zk_sharing_proof: zk_share,
            randomizer: instance.randomizer.clone(),
        })
    }
    pub fn verify(&self, pks_for_encrypted_shares: BTreeMap<u32, PublicKeyBox>,
                  dealing_commitment_evals: Vec<G1Projective>, config: DkgConfig)-> bool{

        let c = get_cl();
        let ffi_h = unsafe{bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
            cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(c.h())
                .as_raw_ptr(),
        )};
        let h_qfi = unsafe{cpp_core::CppBox::from_raw(ffi_h)}.expect("attempted to construct a null CppBox");
        let h = QFIBox(h_qfi);

        let instance = SharingInstance {
            g_cl: h,
            g: G1Projective::generator(),
            public_keys: pks_for_encrypted_shares,
            public_evals: dealing_commitment_evals,
            randomizer: self.randomizer.clone(),
            ciphertexts: self.ciphers.clone(),
        };

        match verify_sharing(&config, &instance, &self.zk_sharing_proof) {
            Ok(_) => {
                true
            },
            Err(e) => {
                println!("Verification failed: {:?}", e);
                false
            },
        }
    }
}

pub fn encrypt_all(pks: &Vec<PublicKeyBox>, evaluations: Vec<Fr>) -> (Vec<CiphertextBox>, MpzBox) {

    let seed = rand::thread_rng().gen::<[u8; 32]>();
    let seed_cpp = unsafe { rust_vec_to_cpp(seed.to_vec()) };
    let ref_seed: cpp_core::Ref<VectorOfUchar> = unsafe { cpp_core::Ref::from_raw_ref(&seed_cpp) };
    let seed_mpz = unsafe { Mpz::from_vector_of_uchar(ref_seed) };
    let ref_seed_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref(&seed_mpz)};
    let mut rng_cpp = unsafe { RandGen::new_1a(ref_seed_mpz) };

    let c = get_cl();
    let ref_c: cpp_core::Ref<CLHSMqk> = unsafe {cpp_core::Ref::from_raw_ref(&c)};

    let mut pks_cpp = unsafe { VectorOfCLHSMPublicKeyOfCLHSMqk::new() };
    for pk in pks {
        let ref_pk: cpp_core::Ref<PublicKey> = unsafe {cpp_core::Ref::from_raw_ref(&pk.0)};
        unsafe { pks_cpp.push_back(ref_pk) };
    }

    let mut evals_cleartext = unsafe { VectorOfCLHSMClearTextOfCLHSMqk::new() };
    for i in 0..evaluations.len(){
        let eval_mpz = unsafe{ fr_to_mpz(evaluations[i])};
        let cleartext = unsafe { ClearText::from_c_l_h_s_mqk_mpz(ref_c, &eval_mpz) };
        unsafe { evals_cleartext.push_back(&cleartext) };
    }

    let ref_pks_cpp: cpp_core::Ref<VectorOfCLHSMPublicKeyOfCLHSMqk> = unsafe {cpp_core::Ref::from_raw_ref(&pks_cpp)};
    let ref_cleartext_cpp: cpp_core::Ref<VectorOfCLHSMClearTextOfCLHSMqk> = unsafe {cpp_core::Ref::from_raw_ref(&evals_cleartext)};
    let r = unsafe { Mpz::new_copy(&rng_cpp.random_mpz(c.encrypt_randomness_bound())) };

    let ciphers = unsafe { c.encrypt_all_3a(ref_pks_cpp, ref_cleartext_cpp, &r) };

    let mut ciphers_rust = Vec::new();
    for i in 0..unsafe{ciphers.size()}{

        let ffi_result = unsafe{__ffi::ctr_bicycl_ffi_BICYCL__Utils_CL_HSM_CipherText_BICYCL_CL_HSMqk_CL_HSM_CipherText7(cpp_core::CastInto::<::cpp_core::Ref<bicycl::b_i_c_y_c_l::utils::CLHSMCipherTextOfCLHSMqk>>::cast_into(ciphers.at(i)).as_raw_ptr())};
        let cpp_cipher = unsafe{cpp_core::CppBox::from_raw(ffi_result)}.expect("attempted to construct a null CppBox");
         ciphers_rust.push(CiphertextBox(cpp_cipher));
    }

    (ciphers_rust,MpzBox(r))
}

pub fn encrypt(pk: &PublicKeyBox, evaluation: Fr, r: &MpzBox) -> CiphertextBox {

    let c = get_cl();
    let ref_c: cpp_core::Ref<CLHSMqk> = unsafe {cpp_core::Ref::from_raw_ref(&c)};

    let ref_pk: cpp_core::Ref<PublicKey> = unsafe {cpp_core::Ref::from_raw_ref(&pk.0)};
    let eval_mpz = unsafe{ fr_to_mpz(evaluation)};
    let cleartext = unsafe { ClearText::from_c_l_h_s_mqk_mpz(ref_c, &eval_mpz) };
    let ref_cleartext_cpp: cpp_core::Ref<ClearText> = unsafe {cpp_core::Ref::from_raw_ref(&cleartext)};

    let ref_r: cpp_core::Ref<Mpz> = unsafe {cpp_core::Ref::from_raw_ref(&r.0)};
    let cipher = unsafe {c.encrypt_c_l_h_s_m_public_key_of_c_l_h_s_mqk_c_l_h_s_m_clear_text_of_c_l_h_s_mqk_mpz(ref_pk, ref_cleartext_cpp, ref_r)};

    let cipher_ref: cpp_core::Ref<CipherText> = unsafe {cpp_core::Ref::from_raw_ref(&cipher)};
    let ffi_result = unsafe{__ffi::ctr_bicycl_ffi_BICYCL__Utils_CL_HSM_CipherText_BICYCL_CL_HSMqk_CL_HSM_CipherText7(cpp_core::CastInto::<::cpp_core::Ref<bicycl::b_i_c_y_c_l::utils::CLHSMCipherTextOfCLHSMqk>>::cast_into(cipher_ref).as_raw_ptr())};
    let cpp_cipher = unsafe{cpp_core::CppBox::from_raw(ffi_result)}.expect("attempted to construct a null CppBox");

    CiphertextBox(cpp_cipher)
}

pub fn decrypt(c: &cpp_core::CppBox<CLHSMqk>, sk: &SecretKeyBox, cipher: &CiphertextBox) -> MpzBox {

    let ref_sk: cpp_core::Ref<SecretKey> = unsafe {cpp_core::Ref::from_raw_ref(&sk.0)};
    let ref_cipher: cpp_core::Ref<CipherText> = unsafe {cpp_core::Ref::from_raw_ref(&cipher.0)};
    let mut cleartext = unsafe{ c.decrypt(ref_sk, ref_cipher)};
    let cleartext_mpz = unsafe{cleartext.get_mpz()};
    return MpzBox(cleartext_mpz);
}

pub fn keygen(c: &cpp_core::CppBox<CLHSMqk>, rng: &mut CppBox<RandGen>, associated_data: &Vec<u8>) -> (SecretKeyBox, PublicKeyBox, PopZk) {

    let mutref_rng: cpp_core::MutRef<RandGen> = unsafe {cpp_core::MutRef::from_raw_ref(rng)};
    let mut sk = unsafe{ c.keygen_rand_gen(mutref_rng)};
    let pk = unsafe{ c.keygen_c_l_h_s_m_secret_key_of_c_l_h_s_mqk(&sk)};

    let sk_mpz = unsafe{sk.get_mpz()};

    let ffi_gen_h = unsafe{bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
        cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(c.h())
            .as_raw_ptr(),
    )};
    let gen_h = unsafe{cpp_core::CppBox::from_raw(ffi_gen_h)}.expect("attempted to construct a null CppBox");

    let instance = PopZkInstance {
        gen: QFIBox(gen_h),
        public_key: PublicKeyBox(pk),
        associated_data: associated_data.clone(),
    };
    let pop = create_pop_zk(&instance, &sk_mpz, c, rng).unwrap();

    (SecretKeyBox(sk), instance.public_key,pop)
}


#[cfg(test)]
mod test {
    use blsttc::group::ff::Field;
    use cpp_std::VectorOfUchar;
    use bicycl::rust_vec_to_cpp;
    use crate::bls12381::key_pop_zk::verify_pop_zk;
    use super::*;
    use crate::bls12381::rng::RAND_ChaCha20;
    use crate::bls12381::utils::{get_cl, mpz_to_fr};

    #[test]
    fn test_encrypt_all_decrypt_one_with_encrypt_all() {
        let num_nodes = 10;
        let seed = [4u8; 32];
        let seed_cpp = unsafe { rust_vec_to_cpp(seed.to_vec()) };
        let ref_seed: cpp_core::Ref<VectorOfUchar> = unsafe { cpp_core::Ref::from_raw_ref(&seed_cpp) };
        let seed_mpz = unsafe { Mpz::from_vector_of_uchar(ref_seed) };
        let ref_seed_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref(&seed_mpz)};
        let rng = &mut RAND_ChaCha20::new(seed);
        let mut rng_cpp = unsafe { RandGen::new_1a(ref_seed_mpz) };

        let c = get_cl();

        // Used to store encryption key pairs of each node i
        let mut sks = Vec::new();
        let mut pks = Vec::new();
        let associated_data = Vec::new();

        for _i in 0..num_nodes{
            let(sk,pk, pop) = keygen(&c, &mut rng_cpp, &associated_data);

            let ffi_gen_h = unsafe{bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
                cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(c.h())
                    .as_raw_ptr(),
            )};
            let gen_h = unsafe{cpp_core::CppBox::from_raw(ffi_gen_h)}.expect("attempted to construct a null CppBox");

            let instance = PopZkInstance {
                gen: QFIBox(gen_h),
                public_key: pk.clone(),
                associated_data: associated_data.clone(),
            };

            verify_pop_zk(
                &instance,
                &pop,
                &c
            ).expect("Cannot verify Pop");

            sks.push(sk);
            pks.push(pk);
        }


        let msgs: Vec<_> = (0..num_nodes)
            .map(|_| Fr::random(&mut *rng))
            .collect();

        let (cc, _r) = encrypt_all(&pks, msgs.clone());

        let m: Vec<_> = cc.iter().zip(sks)
            .map(|(cc_i, sk_i)| {
                decrypt(&c, &sk_i, &cc_i)
            }).collect();

        msgs.iter().zip(m)
            .for_each(|(x, mut y)| unsafe {
                let mut x = x.clone();
                let y= mpz_to_fr(&mut y.0);
                x -= y;
                assert!(bool::from(x.is_zero()));
            });
    }

    #[test]
    fn test_encrypt_all_decrypt_one_with_encrypt() {
        let num_nodes = 10;
        let seed = [4u8; 32];
        let seed_cpp = unsafe { rust_vec_to_cpp(seed.to_vec()) };
        let ref_seed: cpp_core::Ref<VectorOfUchar> = unsafe { cpp_core::Ref::from_raw_ref(&seed_cpp) };
        let seed_mpz = unsafe { Mpz::from_vector_of_uchar(ref_seed) };
        let ref_seed_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref(&seed_mpz)};
        let rng = &mut RAND_ChaCha20::new(seed);
        let mut rng_cpp = unsafe { RandGen::new_1a(ref_seed_mpz) };

        let c = get_cl();

        // Used to store encryption key pairs of each node i
        let mut sks = Vec::new();
        let mut pks = Vec::new();
        let associated_data = Vec::new();

        for _i in 0..num_nodes{
            let(sk,pk, pop) = keygen(&c, &mut rng_cpp, &associated_data);

            let ffi_gen_h = unsafe{bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
                cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(c.h())
                    .as_raw_ptr(),
            )};
            let gen_h = unsafe{cpp_core::CppBox::from_raw(ffi_gen_h)}.expect("attempted to construct a null CppBox");

            let instance = PopZkInstance {
                gen: QFIBox(gen_h),
                public_key: pk.clone(),
                associated_data: associated_data.clone(),
            };

            verify_pop_zk(
                &instance,
                &pop,
                &c
            ).expect("Cannot verify Pop");

            sks.push(sk);
            pks.push(pk);
        }


        let msgs: Vec<_> = (0..num_nodes)
            .map(|_| Fr::random(&mut *rng))
            .collect();

        let r = get_r_for_encryption();
        let mut cc = Vec::new();
        for i in 0..pks.len() {
            let cipher = encrypt(&pks[i], msgs[i], &r);
            cc.push(cipher);
        }

        let m: Vec<_> = cc.iter().zip(sks)
            .map(|(cc_i, sk_i)| {
                decrypt(&c, &sk_i, &cc_i)
            }).collect();

        msgs.iter().zip(m)
            .for_each(|(x, mut y)| unsafe {
                let mut x = x.clone();
                let y= mpz_to_fr(&mut y.0);
                x -= y;
                assert!(bool::from(x.is_zero()));
            });
    }
}