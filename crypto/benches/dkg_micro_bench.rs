#![allow(unused)]
use criterion::{criterion_group, criterion_main, Criterion, black_box};
use std::collections::{BTreeMap, HashMap};
use std::ops::Add;
use bicycl::b_i_c_y_c_l::{Mpz, QFI};
use bicycl::{MpzBox, PublicKeyBox, QFIBox};
use blsttc::{Fr, G1Projective};
use blsttc::group::Group;
use crypto::dealing::{DealerSecret, DkgConfig, CGCombinedDealing, CGIndividualDealing, EncryptedDealingWithProof, DealingCommitment, CiphersWithSharingProof, ShareCommitment};
use crypto::public_key::CGPublicKey;
use crypto::secret_key::CGSecretKey;
use ed25519_dalek::{Signature, Verifier};
use crypto::bls12381::public_evals::PublicEvals;
use crypto::errors::DkgError;
use crypto::bls12381::cg_encryption::{encrypt, encrypt_all, get_r_for_encryption, CiphersWithSharingProof as CiphersWithSharingProof12381};
use crypto::bls12381::nidkg_zk_share::{prove_sharing, SharingInstance, SharingWitness};
use crypto::bls12381::utils::get_cl;
use ed25519_dalek::{VerifyingKey as PublicKey};

fn setup_nodes(n: u32) -> HashMap<u32, (CGSecretKey, CGPublicKey)> {
    let mut node_keys = HashMap::new();
    for i in 0..n {
        let node_cg_key = CGSecretKey::generate();
        let node_cg_pub_key = CGPublicKey::try_from(&node_cg_key).unwrap();
        node_keys.insert(i, (node_cg_key, node_cg_pub_key));
    }
    node_keys
}

///
/// This single function sets up the environment and runs *all* the DKG-related benchmarks
/// so that `n` and `t` come from one place.
///
fn bench_all_dkg_operations(c: &mut Criterion) {
    // ------------------------------------------------------
    // 1. Specify n, t just once, and build all the common data
    // ------------------------------------------------------
    let n = 256;
    let t = 171;
    let config = DkgConfig { n, t };

    // All node keys
    let node_keys = setup_nodes(config.n);

    // Dealer secret and combined dealing
    let dealer_secret = DealerSecret::new(&config);
    let combined_dealing = dealer_secret.into_combined_dealing(&config, 1, 2);

    // Individual dealings
    let individual_dealings = combined_dealing.get_individual_dealings_without_commitment();

    // Gather signatures from all nodes (for demonstration).
    let mut sigs = BTreeMap::new();
    for i in 0..config.t {
        let mut dealing = individual_dealings[i as usize].clone();
        dealing = CGIndividualDealing::try_from(dealing.to_vec().as_slice()).unwrap();
        let (priv_key, _) = node_keys.get(&i).unwrap();
        let dealing_sig = priv_key.sign_commitment(&dealing);
        sigs.insert(i, dealing_sig.signature);
    }

    // Create a BTreeMap of encryption keys
    let encryption_keys: BTreeMap<u32, _> = node_keys
        .iter()
        .map(|(index, (_, pub_key))| (*index, pub_key.encryption_key_bls12381.key.clone()))
        .collect();

    // Create the EncryptedDealingWithProof once so we can reuse it in multiple benches
    let encrypted_dealing = EncryptedDealingWithProof::new(
        &combined_dealing,
        &sigs,
        &encryption_keys,
        config.t,
    )
        .expect("Failed to create EncryptedDealingWithProof");

    // Public keys for verify
    let node_pks: BTreeMap<u32, CGPublicKey> = node_keys
        .iter()
        .map(|(index, (_, pub_key))| (*index, pub_key.clone()))
        .collect();

    // ------------------------------------------------------
    // 2. Now define multiple benchmark measurements
    // ------------------------------------------------------

    // (B) Benchmark into_combined_dealing Polynomial Evals
    c.bench_function("DealerSecret::Polynomial Evals", |b| {
        b.iter(|| {

            let mut evals_12381: Vec<Fr> = Vec::new();
            let mut index_big = Fr::from(0);
            let mut index = 0;
            while index <= config.n {
                evals_12381.push(dealer_secret.polynomial_12381.evaluate_at(&index_big));
                index_big = index_big.add(&Fr::from(1));
                index += 1;
            }
        });
    });

    let mut evals_12381: Vec<Fr> = Vec::new();
    let mut index_big = Fr::from(0);
    let mut index = 0;
    while index <= config.n {
        evals_12381.push(dealer_secret.polynomial_12381.evaluate_at(&index_big));
        index_big = index_big.add(&Fr::from(1));
        index += 1;
    }

    // (C) Benchmark into_combined_dealing Commitment Computation
    c.bench_function("DealerSecret::Evaluation Commitments Computation", |b| {
        b.iter(|| {
            let commitment_12381 = PublicEvals::from_evals(&evals_12381, &G1Projective::generator());
        });
    });

    // (D) Benchmark into_combined_dealing Commitment Computation Parallel
    c.bench_function("DealerSecret::Evaluation Commitments Computation Parallel", |b| {
        b.iter(|| {
            let commitment_12381 = PublicEvals::from_evals_parallelized(&evals_12381, &G1Projective::generator());
        });
    });

    // (E) Benchmark signature generation (just re-sign the first dealing)
    {
        let mut dealing = individual_dealings[0].clone();
        dealing = CGIndividualDealing::try_from(dealing.to_vec().as_slice()).unwrap();

        let (priv_key, _) = node_keys.get(&0).unwrap();
        c.bench_function("Sign CGIndividualDealing", |b| {
            b.iter(|| {
                let _sig = priv_key.sign_commitment(&dealing);
            });
        });
    }

    let n = config.n;
    let t = config.t;

    //dealer generates encrypted shares and proof of sharing for nodes that did not send back signatures
    let mut shares_to_encrypt = BTreeMap::new();
    let mut node_pks_for_shares_to_encrypt = BTreeMap::new();

    for i in 0..n {
        if !sigs.contains_key(&i) {
            shares_to_encrypt.insert(i, combined_dealing.evals_12381[i as usize]);
            node_pks_for_shares_to_encrypt.insert(i, encryption_keys.get(&i)
                .ok_or(DkgError::EncryptedDealingGenerationError("Encryption Key missing".to_string())).unwrap().clone());
        }
    }

    let cl = get_cl();

    let (ciphers, r) = encrypt_all(&node_pks_for_shares_to_encrypt.values().cloned().collect(),
                                   shares_to_encrypt.values().cloned().collect());

    // (F) Benchmark Encryption Serial
    c.bench_function("Encrypt all Serial", |b| {
        b.iter(|| {

            let pks: Vec<_> = node_pks_for_shares_to_encrypt.values().cloned().collect();
            let shares: Vec<_> = shares_to_encrypt.values().cloned().collect();
            let r = get_r_for_encryption();

            let mut ciphers = Vec::new();

            for i in 0..node_pks_for_shares_to_encrypt.len(){
                let cipher = encrypt(&pks[i], shares[i], &r);
                ciphers.push(cipher);
            }
            black_box(ciphers);
        });
    });

    // (F) Benchmark Encryption Parallel
    c.bench_function("Encrypt all Parallel", |b| {
        b.iter(|| {
            let (ciphers, r) = encrypt_all(&node_pks_for_shares_to_encrypt.values().cloned().collect(),
                                           shares_to_encrypt.values().cloned().collect());
            black_box(ciphers);
            black_box(r);
        });
    });


    let mut g_r = unsafe { QFI::new_0a() };
    let ref_r: cpp_core::Ref<Mpz> = unsafe { cpp_core::Ref::from_raw_ref(&r.0) };
    let mutref_g_r: cpp_core::MutRef<QFI> = unsafe { cpp_core::MutRef::from_raw_ref(&mut g_r) };
    unsafe { cl.power_of_h(mutref_g_r, ref_r) };

    let ffi_h = unsafe{bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
        cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(cl.h())
            .as_raw_ptr(),
    )};
    let h_qfi = unsafe{cpp_core::CppBox::from_raw(ffi_h)}.expect("attempted to construct a null CppBox");
    let h = QFIBox(h_qfi);

    let dealing_public_coefficients = combined_dealing.dealing_commitment.bls12381_commitment.evals[1..].to_vec();
    let aa = dealing_public_coefficients;
    let g_r_box = QFIBox(g_r);
    let instance = SharingInstance {
        g_cl: h.clone(),
        g: G1Projective::generator(),
        public_keys: node_pks_for_shares_to_encrypt.clone(),
        public_evals: aa.clone(),
        randomizer: g_r_box.clone(),
        ciphertexts: ciphers.clone(),
    };

    let witness = SharingWitness {
        scalar_r: r.clone(),
        scalars_m: shares_to_encrypt.clone(),
    };

    let zk_share = prove_sharing(
        &config,
        &instance,
        &witness);

    // (G) Benchmark Prove Sharing
    c.bench_function("EncryptedDealingWithProof:: Prove Sharing", |b| {
        b.iter(|| {
            let instance = SharingInstance {
                g_cl: h.clone(),
                g: G1Projective::generator(),
                public_keys: node_pks_for_shares_to_encrypt.clone(),
                public_evals: aa.clone(),
                randomizer: g_r_box.clone(),
                ciphertexts: ciphers.clone(),
            };

            let witness = SharingWitness {
                scalar_r: r.clone(),
                scalars_m: shares_to_encrypt.clone(),
            };

            let zk_share = prove_sharing(
                &config,
                &instance,
                &witness);
        });
    });

    // (H) Benchmark constructing new EncryptedDealingWithProof
    /*c.bench_function("EncryptedDealingWithProof::new", |b| {
        b.iter(|| {
            let _enc_dealing = EncryptedDealingWithProof::new(
                black_box(&combined_dealing),
                black_box(&sigs),
                black_box(&encryption_keys),
                black_box(config.t),
            )
                .unwrap();
        });
    });*/

    // (E) Benchmark verify step
    /*c.bench_function("EncryptedDealingWithProof::verify", |b| {
        b.iter(|| {
            let result = encrypted_dealing.verify(
                black_box(&node_pks),
                black_box(config.t),
            );
            black_box(result);
        });
    });*/


    //verify the signatures are valid
    let vks_for_nodes_that_signed: Vec<PublicKey> = node_pks.iter()
        .filter(|(node_id, _)| encrypted_dealing.signatures.contains_key(node_id))
        .map(|(_, vk)| vk.verification_key.clone())
        .collect();

    let share_comm_and_sigs_for_nodes_that_signed: Vec<(ShareCommitment, Signature)> = node_pks.iter()
        .filter(|(node_id, _)| sigs.contains_key(node_id))
        .map(|(node_id, _)| (
            ShareCommitment{
                dealer_id: 1,
                instance_id: 2,
                g_12381: encrypted_dealing.dealing_commitment.bls12381_commitment.g.clone(),
                commitment_12381: encrypted_dealing.dealing_commitment.bls12381_commitment.evals[((*node_id)+1) as usize].clone(),
            },
            encrypted_dealing.signatures[node_id].clone())
        )
        .collect();

    //verify all signatures on node share commitments
    for i in 0..vks_for_nodes_that_signed.len(){
        let (share_commitment, sig) = share_comm_and_sigs_for_nodes_that_signed[i].clone();
        let share_comm_bytes = share_commitment.to_vec();
        if vks_for_nodes_that_signed[i].verify(&share_comm_bytes, &sig).is_err(){

        }
    }

    //verify the commitment using low degree test

    c.bench_function("EncryptedDealingWithProof:: Verify Commitment (Low Degree Test)", |b| {
        b.iter(|| {
            let commitment_verified_flag = encrypted_dealing.dealing_commitment.bls12381_commitment.perform_low_degree_test(DkgConfig{
                n,
                t,
            });

            black_box(commitment_verified_flag);
        });
    });

    let dual_codewords = PublicEvals::get_dual_codeword((t - 1) as usize, n as usize);

    c.bench_function("EncryptedDealingWithProof:: Verify Commitment (Low Degree Test) (With Precomputation)", |b| {
        b.iter(|| {
            let commitment_verified_flag = encrypted_dealing.dealing_commitment.bls12381_commitment.
                perform_low_degree_test_with_precomputation(DkgConfig{
                n,
                t,
            },&dual_codewords);

            black_box(commitment_verified_flag);
        });
    });

    c.bench_function("EncryptedDealingWithProof::verify all signatures", |b| {
        b.iter(|| {
            for i in 0..vks_for_nodes_that_signed.len(){
                let (share_commitment, sig) = share_comm_and_sigs_for_nodes_that_signed[i].clone();
                let share_comm_bytes = share_commitment.to_vec();
                if vks_for_nodes_that_signed[i].verify(&share_comm_bytes, &sig).is_err(){
                }
            }
        });
    });

    //verify proof of sharing is correct
    let ciphers_with_sharing_proof = encrypted_dealing.ciphers_with_sharing_proof.unwrap();

    let pks_for_nodes_with_encrypted_shares_12381: BTreeMap<u32, PublicKeyBox> = node_pks.iter()
        .filter(|(node_id, _)| !encrypted_dealing.signatures.contains_key(node_id))
        .map(|(node_id, pk)| (*node_id, pk.encryption_key_bls12381.key.clone()))
        .collect();

    //verify that the proof of sharing for encrypted shares
    let verified_flag = ciphers_with_sharing_proof.ciphers_with_sharing_proof_12381
        .verify(pks_for_nodes_with_encrypted_shares_12381.clone(),
                encrypted_dealing.dealing_commitment.bls12381_commitment.evals[1..].to_vec(),
                DkgConfig
                {
                    n,
                    t,
                });

    c.bench_function("EncryptedDealingWithProof::verify sharing proof", |b| {
        b.iter(|| {
            let verified_flag = ciphers_with_sharing_proof.ciphers_with_sharing_proof_12381
                .verify(pks_for_nodes_with_encrypted_shares_12381.clone(),
                        encrypted_dealing.dealing_commitment.bls12381_commitment.evals[1..].to_vec(),
                        DkgConfig
                        {
                            n,
                            t,
                        });
            black_box(verified_flag);
        });
    });


}

// ------------------------------------------------------
// 3. Create the criterion group & main entry point
// ------------------------------------------------------
criterion_group!(dkg_bench_group, bench_all_dkg_operations);
criterion_main!(dkg_bench_group);
