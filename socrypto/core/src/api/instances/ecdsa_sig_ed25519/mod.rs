mod signature;
mod signing_key;
mod verification_key;

use crate::api::types::single_sig_types::{
    PublicParametersWrapperSig, SignatureWrapper, SigningKeyWrapperSig, VerificationKeyWrapperSig,
};
use crate::types::impls::sig_ecdsa_ed25519::EcdsaSignatureSchemeEd25519;

/// Signing key wrapper for ECDSA signature on ED25519 curve.
pub type SigningKeyEd25519Sig = SigningKeyWrapperSig<EcdsaSignatureSchemeEd25519>;
/// Verification key wrapper for ECDSA signature on ED25519 curve.
pub type VerificationKeyEd25519Sig = VerificationKeyWrapperSig<EcdsaSignatureSchemeEd25519>;
/// Signature wrapper for ECDSA signature on ED25519 curve.
pub type SignatureEd25519Sig = SignatureWrapper<EcdsaSignatureSchemeEd25519>;
/// Public parameters wrapper for ECDSA signature on ED25519 curve.
pub type PublicParametersEd25519Sig = PublicParametersWrapperSig<EcdsaSignatureSchemeEd25519>;

#[cfg(test)]
mod tests {
    use crate::api::instances::ecdsa_sig_ed25519::{
        SignatureEd25519Sig, SigningKeyEd25519Sig, VerificationKeyEd25519Sig,
    };
    use crate::types::impls::helpers::serde::encode_hex;

    #[test]
    fn check_signing_key_serde() {
        let data = SigningKeyEd25519Sig::new();
        // prepare expected data
        let encoded = encode_hex(&data.to_bytes());
        let expected_serialized_data = format!(r#""{encoded}""#);

        let result = serde_json::to_string(&data);
        assert!(result.is_ok());

        let actual_result = result.unwrap();
        assert_eq!(actual_result, expected_serialized_data);
        println!("{actual_result}");

        let de_result = serde_json::from_str::<SigningKeyEd25519Sig>(actual_result.as_str());
        assert!(de_result.is_ok());
        assert_eq!(de_result.unwrap().inner, data.inner);

        let encoded_data = r#""{{"inner":"invalid_signing_key"}}"#;
        let de_result = serde_json::from_str::<SigningKeyEd25519Sig>(encoded_data);
        assert!(de_result.is_err());
    }

    #[test]
    fn check_verifying_key_serde() {
        let sk = SigningKeyEd25519Sig::new();
        let vk = sk.gen_vk();
        // prepare expected data
        let encoded = encode_hex(&vk.to_bytes());
        let expected_serialized_data = format!(r#""{encoded}""#);

        let result = serde_json::to_string(&vk);
        assert!(result.is_ok());

        let actual_result = result.unwrap();
        assert_eq!(actual_result, expected_serialized_data);

        let de_result = serde_json::from_str::<VerificationKeyEd25519Sig>(actual_result.as_str());
        assert!(de_result.is_ok());
        assert_eq!(de_result.unwrap().inner, vk.inner);

        let encoded_data = r#"{{"inner":"invalid_verifying_key"}}"#;
        let de_result = serde_json::from_str::<VerificationKeyEd25519Sig>(encoded_data);
        assert!(de_result.is_err());
    }

    #[test]
    fn check_signature_serde() {
        let sk = SigningKeyEd25519Sig::new();
        let msg = b"test-message";
        let sig = sk.sign_no_vk(msg);
        // prepare expected data
        let encoded = encode_hex(&sig.to_bytes());
        let expected_serialized_data = format!(r#""{encoded}""#);

        let result = serde_json::to_string(&sig);
        assert!(result.is_ok());

        let actual_result = result.unwrap();
        assert_eq!(actual_result, expected_serialized_data);

        let de_result = serde_json::from_str::<SignatureEd25519Sig>(actual_result.as_str());
        assert!(de_result.is_ok());
        assert_eq!(de_result.unwrap().inner, sig.inner);

        let encoded_data = r#"{{"inner":"invalid_signature_data_key"}}"#;
        let de_result = serde_json::from_str::<VerificationKeyEd25519Sig>(encoded_data);
        assert!(de_result.is_err());
    }
}
