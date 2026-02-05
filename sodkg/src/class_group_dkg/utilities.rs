/*use crate::class_group_dkg::types::signatures::BlsMultiSignature;
use crate::errors::AggregationError;
use crypto::errors::DkgError;
use nidkg_helper::utils::{aggregate_public_key_set, combine_signatures};
use nidkg_helper::{BlsPublicKey, PublicEvals};
use nidkg_helper::BlsSignature;
use std::collections::BTreeMap;
use crypto::bls12381::bls_signature::verify_public_key as verify_public_key_bls12381;
use crypto::bn254::bls_signature::verify_public_key as verify_public_key_bn254;

pub(crate) fn verify_public_share(
    node_num: u32,
    pub_key: &BlsPublicKey,
    pub_evals: &PublicEvals,
) -> bool {

    let node_pk_12381 = pub_evals.public_evals_bls12381.evals[(node_num + 1) as usize].clone();
    let node_pk_254 = pub_evals.public_evals_bn254.evals[(node_num + 1) as usize].clone();

    if !node_pk_12381.equals(&pub_key.bls12381.pub_key_g1)||
        !node_pk_254.equals(&pub_key.bn254.pub_key_g1){
        return false;
    }

    //verify the sk in both g1^x and g2^x are equal using the pairing equation
    verify_public_key_bls12381(&pub_key.bls12381.pub_key_g1, &pub_key.bls12381.pub_key_g2)
        && verify_public_key_bn254(&pub_key.bn254.pub_key_g1, &pub_key.bn254.pub_key_g2)
}

pub(crate) fn aggregate_public_share(
    pubshares: BTreeMap<u32, BlsPublicKey>,
    threshold: usize,
    public_evals: Option<PublicEvals>,
) -> Result<BlsPublicKey, DkgError> {
    match aggregate_public_key_set(&pubshares, threshold, public_evals) {
        Ok(pk) => Ok(pk),
        Err(e) => Err(DkgError::GeneralError(e.to_string())),
    }
}

pub(crate) fn aggregate_signature_share(
    sigshares: BTreeMap<u32, BlsSignature>,
    threshold: usize,
) -> Result<BlsThresholdSignature, AggregationError> {
    match combine_signatures(&sigshares, threshold) {
        Ok(sig) => Ok(BlsThresholdSignature(sig)),
        Err(e) => Err(AggregationError::GeneralError(e.to_string())),
    }
}
*/