use crate::api::types::aggregated_signature_types::{
    AggregatedSignatureWrapper,
    PartialSignatureWrapper,
    PublicKeyWrapperAggSig,
    PublicParametersWrapperAggSig,
    SigningKeyWrapperAggSig,
    VerificationKeyWrapperAggSig,
    // note Pop not used for threshold signatures, everything validated via NIDKG
    // PopWrapperAggSig,
};
use crate::types::domain::UniqueDomain;
use crate::types::impls::threshold_bls::bls12381::BlsThresholdBls12381;
use crate::types::Order;

pub(crate) const DOMAIN_BLS_THRESHOLD_BLS12381: &str = "bls-threshold-signature-bls-12381";

/// Threshold signature domain definition based on BLS12381 curve.
pub struct BlsThresholdDomainBls12381;
impl UniqueDomain for BlsThresholdDomainBls12381 {
    fn domain<'a>() -> &'a str {
        DOMAIN_BLS_THRESHOLD_BLS12381
    }
}

/// Bls Threshold aggregated signature schema based on BLS12381 curve.
pub type BlsThresholdBls12381Schema = BlsThresholdBls12381<BlsThresholdDomainBls12381>;

/// Aggregate Signature Wrapper struct for bls threshold signature on BLS12381 curve.
pub type AggregatedSignatureBlsThresholdBls12381 =
    AggregatedSignatureWrapper<BlsThresholdBls12381Schema>;
/// Partial Signature Wrapper struct for bls threshold signature on BLS12381 curve.
pub type PartialSignatureBlsThresholdBls12381 = PartialSignatureWrapper<BlsThresholdBls12381Schema>;
/// Public Key Wrapper struct for bls threshold signature on BLS12381 curve.
pub type PublicKeyBlsThresholdBls12381 = PublicKeyWrapperAggSig<BlsThresholdBls12381Schema>;
/// Public Parameters Wrapper struct for bls threshold signature on BLS12381.
pub type PublicParametersBlsThresholdBls12381 =
    PublicParametersWrapperAggSig<BlsThresholdBls12381Schema>;
/// Signing Key Wrapper struct for bls threshold signature on BLS12381.
pub type SigningKeyBlsThresholdBls12381 = SigningKeyWrapperAggSig<BlsThresholdBls12381Schema>;
/// Verification Key Wrapper struct for bls threshold signature on BLS12381.
pub type VerificationKeyBlsThresholdBls12381 =
    VerificationKeyWrapperAggSig<BlsThresholdBls12381Schema>;

// TODO: This can be done for all threshold schemes with a macro
/// DKG using trusted party who distributes secret keys and publishes public parameters.
pub fn trusted_dkg_bls_threshold_bls12381(
    thresh: Order,
    num_nodes: Order,
) -> (
    Vec<SigningKeyBlsThresholdBls12381>,
    PublicParametersBlsThresholdBls12381,
) {
    crate::api::types::aggregated_signature_types::trusted_dkg(thresh, num_nodes)
}

#[cfg(test)]
mod test {
    use crate::types::{Identity, Order};

    const THRESHOLD: u16 = 3;
    const NUM_NODES: u16 = 5;

    #[test]
    fn check_threshold_bls12381_signing_api_wrappers_trusted_dkg() {
        let (sks, pp) =
            super::trusted_dkg_bls_threshold_bls12381(Order(THRESHOLD), Order(NUM_NODES));
        let mut psigs = Vec::new();

        let msg = String::from("beacon for round X");
        let other_msg = String::from("BAD STRING SHOULDN'T VERIFY");

        for (i, sk_i) in sks.iter().enumerate().take(NUM_NODES as usize) {
            let vk_i = pp
                .verification_key_by_order(&Order::from(i))
                .expect("iterator i should not go o.o.b.");
            let psig = sk_i.sign(&msg, &vk_i);

            assert!(psig.verify(&msg, &vk_i).is_ok());
            assert!(psig.verify(&other_msg, &vk_i).is_err());

            let vk_next = pp
                .verification_key_by_order(&Order::from((i + 1) % NUM_NODES as usize))
                .expect("iterator i should not go o.o.b.");
            assert!(psig.verify(&msg, &vk_next).is_err());

            let mut id_raw = [0u8; 32];
            id_raw[4] = i as u8;
            let id = Identity::from(id_raw);

            assert!(psig.verify_by_identity(&msg, &id, &pp).is_ok());

            psigs.push((id, psig));
        }

        let aggregated_signature = pp
            .try_aggregate_partial_signatures(&msg, psigs)
            .expect("should not panic on >=THREHSOLD honest inputs");
        assert!(pp
            .verify_aggregated_signature(&msg, &aggregated_signature)
            .is_ok());
        assert!(pp
            .verify_aggregated_signature(&other_msg, &aggregated_signature)
            .is_err());
        assert!(pp
            .public_key()
            .verify_aggregated_signature(&msg, &aggregated_signature)
            .is_ok());
    }
}
