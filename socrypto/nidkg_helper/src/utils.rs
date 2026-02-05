use anyhow::bail;
use blsttc::{G1Projective, G2Projective};
// use crypto::bls12381::nizk_dleq::{
//     prove_gen as prove_gen12381, prove_gen_2 as prove_gen_2_12381,
//     DLEqInstance as DLEqInstance12381, DleqInstance2 as DLEqInstance_2_12381,
//     DLEqWitness as DLEqWitness12381, ZkProofDLEq as ZkProofDLEq12381,
// };
use crate::BlsSignature;
use crate::{BlsPublicKey, PublicEvals};
use crypto::errors::DkgError;
use erasure::codecs::rs8::{Rs8Codec, Rs8Settings};
use erasure::utils::codec_trait::{Codec, Setting};
use miracl_core_bls12381::bls12381::ecp::ECP as ECP12381;
use miracl_core_bls12381::bls12381::ecp2::ECP2 as ECP2_12381;
use socrypto_core::types::Hash;
use std::collections::{BTreeMap, HashMap};
use vec_commitment::committed_chunk::CommittedChunk;
// use crypto::bls12381::threshold_signature::{combine_public_keys_g1_proj, combine_signatures_g2_proj};
use crypto::bls12381::interpolate::{interpolate_g1, interpolate_g2, x_for_index}; // Check if needed, usually Fr::from is enough but let's see. Use library provided Fr conversion.

// these methods were all copied, now deleted and publicly used
use blst::min_pk::{
    AggregatePublicKey as AggregatePublicKeyBLS, AggregateSignature as AggregateSignatureBLS,
    Signature as SignatureBLS,
};
pub use crypto::bls12381::nidkg_serde::{
    convert_cipher_to_bytes, convert_fr_to_bytes, convert_g1_proj_to_bytes,
    convert_g2_proj_to_bytes, convert_vec_cipher_to_bytes, convert_vec_fr_to_bytes,
    convert_vec_g1_proj_to_bytes,
};
use crypto::public_key::{verify_signature, CGPublicKey};
use itertools::Itertools;

// try to create an aggregate signature from >= threshold signatures if we have
// atleast threshold valid signatures
pub fn try_create_bls_aggregate_signature(
    msg: &Vec<u8>,
    sigs_and_vks: &HashMap<u32, (SignatureBLS, CGPublicKey)>,
    threshold: usize,
) -> Option<(Vec<u32>, AggregateSignatureBLS)> {
    // If there aren’t enough signatures, return None.
    if sigs_and_vks.len() < threshold {
        return None;
    }

    // Collect the available items into a vector and sort them by signer index
    let mut items: Vec<(u32, &SignatureBLS, &CGPublicKey)> = sigs_and_vks
        .iter()
        .map(|(&k, (sig, pk))| (k, sig, pk))
        .collect();
    items.sort_by_key(|(k, _, _)| *k);

    // Iterate over all combinations of items with the required threshold
    for combination in items.iter().combinations(threshold) {
        // Extract the signer indices, signatures, and public keys from this combination
        let signer_indices: Vec<u32> = combination.iter().map(|&&(k, _, _)| k).collect();
        let sigs: Vec<&SignatureBLS> = combination.iter().map(|&&(_k, sig, _)| sig).collect();
        let pks: Vec<&_> = combination
            .iter()
            .map(|&&(_k, _, pk)| &pk.verification_key_bls)
            .collect();

        // Try to aggregate the signatures
        let agg_sig = match AggregateSignatureBLS::aggregate(sigs.as_slice(), false) {
            Ok(agg) => agg,
            Err(_) => continue, // Skip to the next combination if aggregation fails
        };

        // Convert the aggregate signature into a signature type
        let signature = agg_sig.to_signature();

        // Try to aggregate the public keys
        let agg_public_key = match AggregatePublicKeyBLS::aggregate(pks.as_slice(), false) {
            Ok(agg_pk) => agg_pk,
            Err(_) => continue,
        };

        let vk = agg_public_key.to_public_key();

        // Verify the aggregated signature against the message
        if verify_signature(&vk, msg, &signature) {
            return Some((signer_indices, agg_sig));
        }
    }

    // If no valid combination was found, return None.
    None
}

pub fn compute_accumulation_value(
    data: &Vec<u8>,
    total_shards: usize,
    data_shards: usize,
) -> Result<Hash, DkgError> {
    let chunks = Rs8Codec::encode(
        Rs8Settings::new(data_shards, total_shards - data_shards),
        data.clone(),
    )
    .map_err(|_e| DkgError::GeneralError("Error while creating chunks".to_string()))?;

    let (root, _) = CommittedChunk::commit_chunk_list(chunks).map_err(|_e| {
        DkgError::GeneralError("Error while creating accumulation root".to_string())
    })?;

    Ok(Hash(root))
}

pub fn convert_49bg1_48bg1(g1pt: ECP12381) -> Vec<u8> {
    // check if y > -y
    let mut g1pt_clone = g1pt.clone();
    g1pt_clone.neg();
    let mut orig = vec![0; 48];
    let mut negated = vec![0; 48];
    g1pt.gety().tobytes(&mut orig);
    g1pt_clone.gety().tobytes(&mut negated);
    let mut set_bit = false;
    if orig > negated {
        set_bit = true
    }

    let mut g1_49b: Vec<u8> = vec![0; 49];
    g1pt.tobytes(&mut g1_49b, true);

    // set the compression bit
    let mut carr: Vec<u8> = vec![g1_49b[1] | 1 << 7];
    // if y>-y then set the 5th bit
    // we're going to set the 6th to 0 because we're not counting on it being infinity
    if set_bit {
        carr[0] |= 1 << 5;
    }
    carr.extend_from_slice(&g1_49b[2..]);
    carr
}

pub fn convert_97bg2_96bg2(g2pt: ECP2_12381) -> Vec<u8> {
    // check if y > -y
    let mut g2pt_clone = g2pt.clone();
    g2pt_clone.neg();
    let mut orig = vec![0; 96];
    let mut negated = vec![0; 96];
    g2pt.gety().tobytes(&mut orig);
    g2pt_clone.gety().tobytes(&mut negated);
    let mut set_bit = false;
    if orig > negated {
        set_bit = true
    }

    let mut g2_97b: Vec<u8> = vec![0; 97];
    g2pt.tobytes(&mut g2_97b, true);

    // set the compression bit
    let mut carr: Vec<u8> = vec![g2_97b[1] | 1 << 7];
    // if y>-y then set the 5th bit
    // we're going to set the 6th to 0 because we're not counting on it being infinity
    if set_bit {
        carr[0] |= 1 << 5;
    }
    carr.extend_from_slice(&g2_97b[2..]);
    carr
}

// gen_dleq_proof functions removed due to missing dependencies
/*
pub fn gen_dleq_proof_12381(
    sk: Fr,
    hash_point: G1Projective,
) -> (DLEqInstance12381, ZkProofDLEq12381) {
    let seed = rand::thread_rng().gen::<[u8; 32]>();
    let mut rng = &mut RAND_ChaCha20::new(seed);
    let r = Fr::random(&mut rng);
    let g = G1Projective::generator();
    let g_x = g * sk;
    let h_x = hash_point * sk;
    let instance = DLEqInstance12381 {
        g,
        h: hash_point,
        g_x,
        h_x,
    };
    let witness = DLEqWitness12381 {
        scalar_x: sk,
        scalar_r: r,
    };
    (instance.clone(), prove_gen12381(&instance, &witness))
}

pub fn gen_dleq_proof_2_12381(
    sk: Fr,
    hash_point: G2Projective,
) -> (DLEqInstance_2_12381, ZkProofDLEq12381) {
    let seed = rand::thread_rng().gen::<[u8; 32]>();
    let mut rng = &mut RAND_ChaCha20::new(seed);
    let r = Fr::random(&mut rng);
    let g = G2Projective::generator();
    let g_x = g * sk;
    let h_x = hash_point * sk;
    let instance = DLEqInstance_2_12381 {
        g,
        h: hash_point,
        g_x,
        h_x,
    };
    let witness = DLEqWitness12381 {
        scalar_x: sk,
        scalar_r: r,
    };
    (instance.clone(), prove_gen_2_12381(&instance, &witness))
}
*/

pub fn aggregate_public_key_set(
    pubshares: &BTreeMap<u32, BlsPublicKey>,
    threshold: usize,
    public_evals: Option<PublicEvals>,
) -> anyhow::Result<BlsPublicKey> {
    let mut pkeylist_12381_g1 = vec![];
    if pubshares.len() < threshold {
        bail!(format!(
            "not enough shares to aggregate. shares: {}, threshold: {}",
            pubshares.len(),
            threshold
        ));
    } else if let Some((max_idx, _)) = pubshares.iter().next_back() {
        for i in 0..(max_idx + 1) {
            let r = pubshares.get(&i);
            match r {
                None => {
                    pkeylist_12381_g1.push(None);
                }
                Some(pk) => {
                    pkeylist_12381_g1.push(Some(pk.bls12381.clone()));
                }
            }
        }
    } else {
        bail!("unable to get max");
    }

    let pk_12381_g1;

    if let Some(public_evals) = public_evals {
        pk_12381_g1 = public_evals.public_evals_bls12381.evals[0].clone();
    } else {
        if let Ok(x) = combine_public_keys_g1_proj(&pkeylist_12381_g1, threshold) {
            pk_12381_g1 = x;
        } else {
            bail!("combining 12381 G1 keys failed");
        };
    }

    Ok(BlsPublicKey {
        bls12381: pk_12381_g1,
    })
}

pub fn combine_signatures(
    sig_shares: &BTreeMap<u32, BlsSignature>,
    threshold: usize,
) -> anyhow::Result<BlsSignature> {
    let mut siglist_12381_g2 = vec![];
    if sig_shares.len() < threshold {
        bail!(format!(
            "not enough shares to aggregate. shares: {}, threshold: {}",
            sig_shares.len(),
            threshold
        ));
    } else if let Some((max_idx, _)) = sig_shares.iter().next_back() {
        for i in 0..(max_idx + 1) {
            let r = sig_shares.get(&i);
            match r {
                None => {
                    siglist_12381_g2.push(None);
                }
                Some(sig) => {
                    siglist_12381_g2.push(Some(sig.bls12381.clone()));
                }
            }
        }
    } else {
        bail!("unable to get max");
    }
    let sig_12381_g2 = if let Ok(x) = combine_signatures_g2_proj(&siglist_12381_g2, threshold) {
        x
    } else {
        bail!("combining 12381 G2 keys failed");
    };

    Ok(BlsSignature {
        bls12381: sig_12381_g2,
    })
}

pub fn combine_public_keys_g1_proj(
    keys: &Vec<Option<G1Projective>>,
    _threshold: usize,
) -> Result<G1Projective, DkgError> {
    let mut points = Vec::new();
    for (i, opt_key) in keys.iter().enumerate() {
        if let Some(key) = opt_key {
            let x = x_for_index(i as u32);
            points.push((x, key.clone()));
        }
    }
    interpolate_g1(&points).map_err(|_| DkgError::GeneralError("Interpolation failed".into()))
}

pub fn combine_signatures_g2_proj(
    sigs: &Vec<Option<G2Projective>>,
    _threshold: usize,
) -> Result<G2Projective, DkgError> {
    let mut points = Vec::new();
    for (i, opt_sig) in sigs.iter().enumerate() {
        if let Some(sig) = opt_sig {
            let x = x_for_index(i as u32);
            points.push((x, sig.clone()));
        }
    }
    interpolate_g2(&points).map_err(|_| DkgError::GeneralError("Interpolation failed".into()))
}
