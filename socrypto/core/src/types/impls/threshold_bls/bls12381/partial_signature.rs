use super::VerificationKey;
use crate::types::impls::helpers::bls12381::ecp_wrapper::EcpWrapper;
use crate::types::impls::helpers::bls12381::serde::{BIG_RAW_SIZE, ECP_RAW_SIZE};
use crate::types::serde::TRawRepresentation;
use crate::types::{CryptoError, CryptoResult};
use crypto::bls12381::hash_to_point::hash_to_ecp;
use crypto::bls12381::mcl::mcl_helper::hash_to_ecp as hash_to_ecp_mcl;
use crypto::bls12381::nizk_dleq::{verify_proof, DLEqInstance, ZkProofDLEq};
use miracl_core_bls12381::bls12381::{big::BIG, ecp::ECP};

pub(crate) const PARTIAL_SIGNATURE_LEN: usize = ECP_RAW_SIZE + 2 * BIG_RAW_SIZE;

/// Partial signature with GLOW Proof (based on nizk_dleq)
/// It creates own generator and takes vk instead of saving in instance
#[derive(Clone, Debug)]
pub struct PartialSignature {
    pub(crate) signature: EcpWrapper,
    pub(crate) proof: ZkProofDLEq,
}

impl PartialEq for PartialSignature {
    fn eq(&self, other: &Self) -> bool {
        self.signature.eq(&other.signature)
    }
}

impl AsRef<PartialSignature> for PartialSignature {
    fn as_ref(&self) -> &PartialSignature {
        self
    }
}

impl PartialSignature {
    /// Return copy of partial signature (maybe we can just return pointer if used safely)
    pub fn get_signature(&self) -> ECP {
        self.signature.as_ref().clone()
    }

    /// Validate partial signature
    pub fn validate(
        &self,
        msg: &[u8],
        vk: &VerificationKey,
        domain: &'static str,
    ) -> CryptoResult<()> {
        let g = ECP::generator();
        let h = hash_to_ecp(msg, domain.as_bytes());

        let g_x = vk.0.clone();
        let h_x = self.get_signature();

        let inst = DLEqInstance { g, h, g_x, h_x };

        verify_proof(&inst, &self.proof).map_err(|e| CryptoError::PartialSignatureVerification {
            domain,
            msg: format!("{:?}", e),
        })
    }

    /// Validate partial signature
    pub fn validate_mcl(
        &self,
        msg: &[u8],
        vk: &VerificationKey,
        domain: &'static str,
    ) -> CryptoResult<()> {
        let g = ECP::generator();
        let h = hash_to_ecp_mcl(msg);

        let g_x = vk.0.clone();
        let h_x = self.get_signature();

        let inst = DLEqInstance { g, h, g_x, h_x };

        verify_proof(&inst, &self.proof).map_err(|e| CryptoError::PartialSignatureVerification {
            domain,
            msg: format!("{:?}", e),
        })
    }
}

impl TRawRepresentation for PartialSignature {
    type Raw = [u8; PARTIAL_SIGNATURE_LEN];

    fn create() -> Self::Raw {
        [0u8; PARTIAL_SIGNATURE_LEN]
    }

    fn from_raw(src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized,
    {
        let psig_raw: [u8; ECP_RAW_SIZE] = src[..ECP_RAW_SIZE]
            .try_into()
            .expect("Raw: [u8; PARTIAL_SIGNATURE_SIZE] should not be o.o.b.");
        let c_raw: [u8; BIG_RAW_SIZE] = src[ECP_RAW_SIZE..ECP_RAW_SIZE + BIG_RAW_SIZE]
            .try_into()
            .expect("Raw: [u8; PARTIAL_SIGNATURE_SIZE] should not be o.o.b.");
        let s_raw: [u8; BIG_RAW_SIZE] = src[ECP_RAW_SIZE + BIG_RAW_SIZE..]
            .try_into()
            .expect("Raw: [u8; PARTIAL_SIGNATURE_SIZE] should not be o.o.b.");
        let construct = || -> CryptoResult<PartialSignature> {
            let psig = EcpWrapper::from_raw(psig_raw)?;
            let c = BIG::from_raw(c_raw)?;
            let s = BIG::from_raw(s_raw)?;
            Ok(PartialSignature {
                signature: psig,
                proof: ZkProofDLEq { c, s },
            })
        };
        construct().map_err(|e| {
            CryptoError::CryptoSerdeError(format!(
                "failed to deserialize partial signature, Cause: {e}",
            ))
        })
    }

    fn to_raw(&self) -> Self::Raw {
        let mut raw = Self::create();
        raw[..ECP_RAW_SIZE].clone_from_slice(&self.signature.to_raw());
        raw[ECP_RAW_SIZE..ECP_RAW_SIZE + BIG_RAW_SIZE].clone_from_slice(&self.proof.c.to_raw());
        raw[ECP_RAW_SIZE + BIG_RAW_SIZE..].clone_from_slice(&self.proof.s.to_raw());

        raw
    }
}

#[cfg(test)]
mod tests {
    use crate::api::instances::bls_threshold_bls12381::BlsThresholdBls12381Schema;
    use crate::types::impls::helpers::bls12381::big_as_sk::BigSk;
    use crate::types::impls::helpers::bls12381::ecp_wrapper::EcpWrapper;
    use crate::types::impls::helpers::rand::rng_from_seed;
    use crate::types::impls::helpers::secret_handler::SecretWrapper;
    use crate::types::impls::threshold_bls::bls12381::PartialSignature;
    use crate::types::schemes::aggregated_signature_scheme::AggregateSignatureScheme;
    use crate::types::serde::TRawRepresentation;
    use miracl_core_bls12381::bls12381::pair::g1mul;
    use miracl_core_bls12381::bls12381::{big::BIG, ecp::ECP};

    // Note this also checks partial_signature::PartialSignature, later we can separate out the tests
    #[test]
    fn check_threshold_bls_12381_partial_signature_raw_representation() {
        let signing_key = SecretWrapper(BigSk(BIG::random(&mut rng_from_seed())));
        let expected_vk = EcpWrapper(g1mul(&ECP::generator(), &signing_key.0));
        let msg = b"test_message";

        let psig_with_vk = BlsThresholdBls12381Schema::sign(msg, &signing_key, &expected_vk);
        let raw_psig = psig_with_vk.to_raw();
        let psig_from_raw =
            PartialSignature::from_raw(raw_psig).expect("Successful PSig reconstruction from raw");
        assert_eq!(psig_with_vk, psig_from_raw);
    }
}
