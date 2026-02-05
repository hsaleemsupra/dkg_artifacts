use super::bls12381::{
    AggregatedSignature, BlsThresholdBls12381, PartialSignature, PublicKey, PublicParameters,
    SigningKey, VerificationKey,
};

use super::{AggregateSignatureScheme, PlaceholderCgKeys};
use crate::types::domain::UniqueDomain;
use crate::types::impls::helpers::bls12381::ecp_wrapper::EcpWrapper;
use crate::types::impls::helpers::rand::rng_from_seed;
use crate::types::impls::helpers::secret_handler::SecretWrapper;
use crate::types::schemes::aggregated_signature_scheme::threshold_sig_scheme::GenericPublicParameters;
use crate::types::schemes::aggregated_signature_scheme::ThresholdSignatureScheme;
use crate::types::{CryptoError, CryptoResult, Identity, Order};
use crypto::bls12381::mcl::bls::verify_message_signature;
use crypto::bls12381::mcl::hash::hash_to_ecp;
use crypto::bls12381::mcl::mcl_helper::g2_generator;
use crypto::bls12381::mcl::pair::g2mul;
use crypto::bls12381::nizk_dleq::{prove_gen, verify_proof, DLEqInstance, DLEqWitness};
use crypto::bls12381::polynomial::Polynomial;
use miracl_core_bls12381::bls12381::pair::g1mul;
use miracl_core_bls12381::bls12381::{big::BIG, ecp::ECP};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::marker::PhantomData;

/// BLS Threshold signature schema implemented on BLS 12381 elliptic curve
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct BlsThresholdMcl<T: UniqueDomain>(PhantomData<T>);

impl<DST: UniqueDomain> AggregateSignatureScheme for BlsThresholdMcl<DST> {
    type SigningKeyType = SigningKey;
    type VerificationKeyType = VerificationKey;
    type PartialSignatureType = PartialSignature;
    type AggregatedSignatureType = AggregatedSignature;
    type PublicParametersType = PublicParameters;
    type PublicKeyType = PublicKey;

    /// Generate partial signature on message `msg` using signing key `sk` and verification key `vk`
    fn sign<T: AsRef<[u8]>>(
        msg: &T,
        sk: &Self::SigningKeyType,
        vk: &Self::VerificationKeyType,
    ) -> Self::PartialSignatureType {
        let rng = &mut rng_from_seed();
        let r = BIG::random(rng);
        let mut wit = DLEqWitness {
            // CRYPTO_TODO: note BIG implements Copy. we should be extra careful with this w.r.t. key handling
            scalar_x: sk.0 .0,
            scalar_r: r,
        };

        // CRYPTO_TODO: accept domain string (Multiversx currently does not)
        let h = hash_to_ecp(msg.as_ref());

        let h_x = g1mul(&h, &sk.0);
        let signature = EcpWrapper(h_x.clone());

        let inst = DLEqInstance {
            g: ECP::generator(),
            h,
            // TODO: update underlying crypto repo to use pointers
            g_x: vk.0.clone(),
            h_x,
        };

        let proof = prove_gen(&inst, &wit);

        // zeroize sk from dleq_wit and randomness used to generate proof
        wit.scalar_x.zero();
        wit.scalar_r.zero();

        PartialSignature { signature, proof }
    }

    /// Validate that `psig` is a partial signature on `msg` for verification key `vk`
    fn verify_partial_signature<T: AsRef<[u8]>>(
        msg: &T,
        psig: &Self::PartialSignatureType,
        vk: &Self::VerificationKeyType,
    ) -> CryptoResult<()> {
        let inst = DLEqInstance {
            g: ECP::generator(),
            // CRYPTO_TODO: accept domain string
            h: hash_to_ecp(msg.as_ref()),
            // TODO: update underlying crypto repo to use pointers
            g_x: vk.0.clone(),
            h_x: psig.signature.0.clone(),
        };
        match verify_proof(&inst, &psig.proof) {
            Ok(_) => Ok(()),
            Err(e) => Err(CryptoError::PartialSignatureVerification {
                domain: DST::domain(),
                msg: format!("{:?}", e),
            }),
        }
    }

    /// Aggregate partial signatures WITHOUT VALIDATING THEM
    /// ONLY CALL IF `psigs` CONTAINS ONLY VALID PARTIAL SIGNATURES
    fn aggregate_partial_signatures<
        T: AsRef<[u8]>,
        PS: AsRef<Self::PartialSignatureType>,
        I: IntoIterator<Item = (Identity, PS)>,
    >(
        msg: &T,
        psigs: I,
        pp: &Self::PublicParametersType,
    ) -> CryptoResult<Self::AggregatedSignatureType> {
        BlsThresholdBls12381::<DST>::aggregate_partial_signatures(msg, psigs, pp)
    }

    /// Verify that `sig` is an aggregated signature on message `msg` with respect to
    /// public key `pk`.
    fn verify_aggregated_signature<T: AsRef<[u8]>>(
        msg: &T,
        sig: &Self::AggregatedSignatureType,
        pk: &Self::PublicKeyType,
    ) -> CryptoResult<()> {
        if verify_message_signature(msg.as_ref(), sig, pk) {
            Ok(())
        } else {
            Err(CryptoError::AggregatedSignatureVerification {
                domain: DST::domain(),
                msg: "Verification error".to_string(),
            })
        }
    }

    fn sign_no_vk<T: AsRef<[u8]>>(
        msg: &T,
        sk: &Self::SigningKeyType,
    ) -> Self::PartialSignatureType {
        let vk = EcpWrapper(g1mul(&ECP::generator(), &sk.0 .0));
        Self::sign(msg, sk, &vk)
    }
}

// EVENTUALLY GENERIC IMPLEMENTATION BASED ON DKG SCHEME PREFERABLE
impl<DST: UniqueDomain> ThresholdSignatureScheme for BlsThresholdMcl<DST> {
    type DkgPublicParameters = PlaceholderCgKeys;
    type DkgSecretKeys = PlaceholderCgKeys;
    type DkgTranscript = PlaceholderCgKeys;

    fn init_as_signer(
        _sk_dkg: &Self::DkgSecretKeys,
        _pp_dkg: &Self::DkgPublicParameters,
        _transcript: &Self::DkgTranscript,
    ) -> (
        <Self as AggregateSignatureScheme>::SigningKeyType,
        <Self as AggregateSignatureScheme>::PublicParametersType,
    ) {
        todo!()
    }
    fn init_as_verifier(
        _pp_dkg: &Self::DkgPublicParameters,
        _transcript: Self::DkgTranscript,
    ) -> <Self as AggregateSignatureScheme>::PublicParametersType {
        todo!()
    }
    fn trusted_dkg(
        thresh: Order,
        num_parties: Order,
    ) -> (
        Vec<<Self as AggregateSignatureScheme>::SigningKeyType>,
        <Self as AggregateSignatureScheme>::PublicParametersType,
    ) {
        let mut rng = rng_from_seed();
        // generate `threshold` coefficients. This is a degree `threshold - 1` polynomial and requires `threshold` shares to recreate
        let poly = Polynomial::random(thresh.index(), &mut rng);

        let mut sks = Vec::new();
        let mut vk_map = HashMap::new();

        let gen = ECP::generator();

        for i in 0..num_parties.index() {
            let mut id_raw = [0u8; 32];
            id_raw[4] = i as u8;
            let id = Identity::from(id_raw);

            let sk_i = poly.evaluate_at(&BIG::new_int(i as isize + 1));
            let vk_i = g1mul(&gen, &sk_i);

            sks.push(SecretWrapper(sk_i.into()));
            vk_map.insert(id, EcpWrapper(vk_i));
        }

        let committee_sk_big = poly.evaluate_at(&BIG::new_int(0));
        let pk = g2mul(&g2_generator(), &committee_sk_big);

        let pub_param = GenericPublicParameters::new(vk_map, pk, thresh).expect(" ");

        (sks, pub_param)
    }
}

#[cfg(test)]
mod tests {
    use super::AggregateSignatureScheme;
    use crate::api::instances::bls_threshold_mcl::{
        BlsThresholdMclSchema, DOMAIN_BLS_THRESHOLD_MCL,
    };
    use crate::types::impls::helpers::bls12381::big_as_sk::BigSk;
    use crate::types::impls::helpers::bls12381::ecp_wrapper::EcpWrapper;
    use crate::types::impls::helpers::rand::rng_from_seed;
    use crate::types::impls::helpers::secret_handler::SecretWrapper;
    use crate::types::schemes::aggregated_signature_scheme::{
        TPublicParameters, ThresholdSignatureScheme,
    };
    use crate::types::{Identity, Order};
    use crypto::bls12381::mcl::hash::hash_to_ecp;
    use miracl_core_bls12381::bls12381::pair::g1mul;
    use miracl_core_bls12381::bls12381::{big::BIG, ecp::ECP};

    pub const THRESHOLD: u16 = 3;
    pub const NUM_NODES: u16 = 5;

    /// Generate new random secret key.
    fn new_sk() -> SecretWrapper<BigSk> {
        SecretWrapper(BIG::random(&mut rng_from_seed()).into())
    }

    /// Generate new verification key `vk` from secret key `sk`.
    fn vk_from_sk(sk: &SecretWrapper<BigSk>) -> EcpWrapper {
        EcpWrapper(g1mul(&ECP::generator(), &sk.0))
    }

    // Note this also checks partial_signature::PartialSignature, later we can separate out the tests
    #[test]
    fn check_threshold_bls_mcl_signing_api_partial_signature() {
        let signing_key = new_sk();
        let expected_vk = vk_from_sk(&signing_key);
        let msg = b"test_message";
        let other_msg = b"test_other_message";
        let expected_signature = g1mul(&hash_to_ecp(msg), &signing_key.0);

        let psig_with_vk = BlsThresholdMclSchema::sign(msg, &signing_key, &expected_vk);
        let psig_no_vk = BlsThresholdMclSchema::sign_no_vk(msg, &signing_key);
        let psig_other_message = BlsThresholdMclSchema::sign(other_msg, &signing_key, &expected_vk);

        assert!(expected_signature.equals(&psig_with_vk.signature.0));
        assert!(expected_signature.equals(&psig_no_vk.signature.0));
        assert!(!expected_signature.equals(&psig_other_message.signature.0));

        assert_eq!(psig_with_vk, psig_no_vk);
        assert_ne!(psig_with_vk, psig_other_message);

        assert!(psig_with_vk
            .validate_mcl(msg, &expected_vk, DOMAIN_BLS_THRESHOLD_MCL)
            .is_ok());
        assert!(psig_no_vk
            .validate_mcl(msg, &expected_vk, DOMAIN_BLS_THRESHOLD_MCL)
            .is_ok());
        assert!(psig_other_message
            .validate_mcl(other_msg, &expected_vk, DOMAIN_BLS_THRESHOLD_MCL)
            .is_ok());

        assert!(psig_with_vk
            .validate_mcl(other_msg, &expected_vk, DOMAIN_BLS_THRESHOLD_MCL)
            .is_err());
        assert!(psig_no_vk
            .validate_mcl(other_msg, &expected_vk, DOMAIN_BLS_THRESHOLD_MCL)
            .is_err());
        assert!(psig_other_message
            .validate_mcl(msg, &expected_vk, DOMAIN_BLS_THRESHOLD_MCL)
            .is_err());

        let result =
            BlsThresholdMclSchema::verify_partial_signature(msg, &psig_with_vk, &expected_vk);
        assert!(result.is_ok(), "{:?}", result);

        let result =
            BlsThresholdMclSchema::verify_partial_signature(other_msg, &psig_with_vk, &expected_vk);
        assert!(result.is_err(), "{:?}", result);

        let result =
            BlsThresholdMclSchema::verify_partial_signature(msg, &psig_no_vk, &expected_vk);
        assert!(result.is_ok(), "{:?}", result);

        let result =
            BlsThresholdMclSchema::verify_partial_signature(other_msg, &psig_no_vk, &expected_vk);
        assert!(result.is_err(), "{:?}", result);

        let result =
            BlsThresholdMclSchema::verify_partial_signature(msg, &psig_other_message, &expected_vk);
        assert!(result.is_err(), "{:?}", result);

        let result = BlsThresholdMclSchema::verify_partial_signature(
            other_msg,
            &psig_other_message,
            &expected_vk,
        );
        assert!(result.is_ok(), "{:?}", result);

        let bad_vk = vk_from_sk(&new_sk());
        assert_ne!(bad_vk, expected_vk);

        let result = BlsThresholdMclSchema::verify_partial_signature(msg, &psig_no_vk, &bad_vk);
        assert!(result.is_err(), "{:?}", result);

        let result =
            BlsThresholdMclSchema::verify_partial_signature(other_msg, &psig_no_vk, &bad_vk);
        assert!(result.is_err(), "{:?}", result);
    }

    #[test]
    fn check_threshold_bls_mcl_signing_api_trusted_dkg() {
        let (sks, pp) = BlsThresholdMclSchema::trusted_dkg(Order(THRESHOLD), Order(NUM_NODES));
        let mut psigs = Vec::new();

        let msg = String::from("beacon for round X");
        let other_msg = String::from("BAD STRING SHOULDN'T VERIFY");

        for (i, sk_i) in sks.iter().enumerate().take(NUM_NODES as usize) {
            let vk_i = pp
                .verification_key_by_order(&Order::from(i))
                .expect("iterator i should not go o.o.b.");
            let psig = BlsThresholdMclSchema::sign(&msg, sk_i, vk_i);

            assert!(BlsThresholdMclSchema::verify_partial_signature(&msg, &psig, vk_i).is_ok());
            assert!(
                BlsThresholdMclSchema::verify_partial_signature(&other_msg, &psig, vk_i).is_err()
            );

            let vk_next = pp
                .verification_key_by_order(&Order::from((i + 1) % NUM_NODES as usize))
                .expect("iterator i should not go o.o.b.");
            assert!(BlsThresholdMclSchema::verify_partial_signature(&msg, &psig, vk_next).is_err());

            let mut id_raw = [0u8; 32];
            id_raw[4] = i as u8;
            let id = Identity::from(id_raw);

            let vk_i_id = pp.verification_key(&id).expect("id should exist");
            assert!(BlsThresholdMclSchema::verify_partial_signature(&msg, &psig, vk_i_id).is_ok());

            psigs.push((id, psig));
        }

        let aggregated_signature =
            BlsThresholdMclSchema::aggregate_partial_signatures(&msg, psigs, &pp)
                .expect("should not panic on >=THREHSOLD honest inputs");

        assert!(BlsThresholdMclSchema::verify_aggregated_signature(
            &msg,
            &aggregated_signature,
            pp.public_key()
        )
        .is_ok());
        assert!(BlsThresholdMclSchema::verify_aggregated_signature(
            &other_msg,
            &aggregated_signature,
            pp.public_key()
        )
        .is_err());
    }
}
