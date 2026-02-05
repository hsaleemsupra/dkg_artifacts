use crate::api::instances::ecdsa_sig_ed25519::{SignatureEd25519Sig, SigningKeyEd25519Sig};
use crate::types::impls::helpers::rand::u32_to_u8_array;
use crate::types::impls::sig_ecdsa_ed25519::{EcdsaSignatureSchemeEd25519, SECRET_KEY_LENGTH};
use crate::types::schemes::single_sig_scheme::SignatureScheme;
use crate::types::serde::TRawRepresentation;

impl From<[u8; SECRET_KEY_LENGTH]> for SigningKeyEd25519Sig {
    fn from(bytes: [u8; SECRET_KEY_LENGTH]) -> Self {
        <<EcdsaSignatureSchemeEd25519 as SignatureScheme>::SigningKeyType as TRawRepresentation>::from_raw(bytes)
                .map(|inner| Self {inner})
            .expect("SigningKeyEd25519Sig for static array of SECRET_KEY_LENGTH is always successful")
    }
}

impl SigningKeyEd25519Sig {
    /// Convenience API to generate test signing key from seed corresponding to u32 byte representation.
    /// **Note:** For testing only
    pub fn from_seed(seed: u32) -> SigningKeyEd25519Sig {
        SigningKeyEd25519Sig::from(u32_to_u8_array(seed))
    }

    /// Signs the message without verification key
    pub fn sign<M: AsRef<[u8]>>(&self, msg: &M) -> SignatureEd25519Sig {
        self.sign_no_vk(msg)
    }
}

#[cfg(test)]
mod test {
    use crate::api::instances::ecdsa_sig_ed25519::SigningKeyEd25519Sig;
    use crate::types::impls::sig_ecdsa_ed25519::SECRET_KEY_LENGTH;

    #[test]
    fn check_to_from_api() {
        let signing_key = SigningKeyEd25519Sig::new();
        let signing_key_bytes = signing_key.to_bytes();
        let signing_key_from_bytes = SigningKeyEd25519Sig::from(signing_key_bytes);
        let bytes = signing_key_from_bytes.to_bytes();
        assert_eq!(signing_key_bytes, bytes);

        // random array of valid length does not panic
        let valid_bytes = [5u8; SECRET_KEY_LENGTH];
        let _ = SigningKeyEd25519Sig::from(valid_bytes);
    }

    #[test]
    fn check_reconstruction_from_slice() {
        let valid_bytes = [5u8; SECRET_KEY_LENGTH];
        let from_bytes = SigningKeyEd25519Sig::try_from(valid_bytes.as_slice());
        assert!(from_bytes.is_ok(), "{:?}", from_bytes);

        let less_bytes = [5u8; SECRET_KEY_LENGTH - 5];
        let result = SigningKeyEd25519Sig::try_from(less_bytes.as_slice());
        assert!(result.is_err());

        let more_bytes = [5u8; SECRET_KEY_LENGTH + 5];
        let result = SigningKeyEd25519Sig::try_from(more_bytes.as_slice());
        assert!(result.is_err());
    }
}
