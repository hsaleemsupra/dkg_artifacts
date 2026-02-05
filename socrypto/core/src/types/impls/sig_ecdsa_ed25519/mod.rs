mod serde_impls;

use super::helpers::rand::rng_for_dalek;
use crate::types::error::{CryptoError, CryptoResult};
use crate::types::schemes::single_sig_scheme::SignatureScheme;

use ed25519_dalek::{
    Signature as SignatureDalek, Signer, SigningKey as SigningKeyDalek,
    VerifyingKey as VerificationKeyDalek,
};
use serde::{Deserialize, Serialize};

pub use serde_impls::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};

/// Single signature schema for ECDSA ED255159 domain
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub struct EcdsaSignatureSchemeEd25519;

impl SignatureScheme for EcdsaSignatureSchemeEd25519 {
    type SigningKeyType = SigningKeyDalek;
    type VerificationKeyType = VerificationKeyDalek;
    type SignatureType = SignatureDalek;

    fn new_sk() -> SigningKeyDalek {
        let rng = &mut rng_for_dalek();
        ed25519_dalek::SigningKey::generate(rng)
    }

    fn sign<T: AsRef<[u8]>>(
        sk: &SigningKeyDalek,
        msg: &T,
        _vk: &VerificationKeyDalek,
    ) -> SignatureDalek {
        sign_message_ed25519(msg.as_ref(), sk)
    }

    fn sign_no_vk<T: AsRef<[u8]>>(sk: &SigningKeyDalek, msg: &T) -> SignatureDalek {
        sign_message_ed25519(msg.as_ref(), sk)
    }

    fn verify_signature<T: AsRef<[u8]>>(
        msg: &T,
        pk: &VerificationKeyDalek,
        sig: &SignatureDalek,
    ) -> CryptoResult<()> {
        verify_sig_ed25519(msg.as_ref(), pk, sig)
    }

    fn vk_from_sk(sk: &SigningKeyDalek) -> VerificationKeyDalek {
        sk.verifying_key()
    }
}

fn sign_message_ed25519(msg: &[u8], sk: &SigningKeyDalek) -> SignatureDalek {
    sk.sign(msg)
}

fn verify_sig_ed25519(
    msg: &[u8],
    vk: &VerificationKeyDalek,
    sig: &SignatureDalek,
) -> CryptoResult<()> {
    vk.verify_strict(msg, sig).map_err(CryptoError::from)
}

#[cfg(test)]
mod tests {
    use super::SignatureScheme;
    use crate::types::impls::sig_ecdsa_ed25519::EcdsaSignatureSchemeEd25519;
    use ed25519_dalek::Signer;

    #[test]
    fn check_ed255159_sig_schema_api() {
        let signing_key = EcdsaSignatureSchemeEd25519::new_sk();
        let msg = b"test_message";
        let other_msg = b"test_other_message";
        let expected_signature = signing_key.sign(msg);

        assert_eq!(
            expected_signature,
            EcdsaSignatureSchemeEd25519::sign_no_vk(&signing_key, msg)
        );

        assert_ne!(
            EcdsaSignatureSchemeEd25519::sign_no_vk(&signing_key, msg),
            EcdsaSignatureSchemeEd25519::sign_no_vk(&signing_key, other_msg)
        );

        let expected_vk = signing_key.verifying_key();
        let actual_vk = EcdsaSignatureSchemeEd25519::vk_from_sk(&signing_key);
        assert_eq!(expected_vk, actual_vk);

        assert!(EcdsaSignatureSchemeEd25519::verify_signature(
            msg,
            &actual_vk,
            &expected_signature
        )
        .is_ok());
    }
}
