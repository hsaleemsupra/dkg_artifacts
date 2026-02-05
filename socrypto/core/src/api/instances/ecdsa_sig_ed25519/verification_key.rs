use crate::api::instances::ecdsa_sig_ed25519::VerificationKeyEd25519Sig;
use crate::types::impls::sig_ecdsa_ed25519::{EcdsaSignatureSchemeEd25519, PUBLIC_KEY_LENGTH};
use crate::types::schemes::single_sig_scheme::SignatureScheme;
use crate::types::serde::TRawRepresentation;
use crate::types::{CryptoError, Digest, Hash};

impl Digest for VerificationKeyEd25519Sig {
    fn digest(&self) -> Hash {
        Hash(*self.inner.as_bytes())
    }

    fn feed_to<THasher: sha3::Digest>(&self, hasher: &mut THasher) {
        hasher.update(self.inner.as_bytes())
    }
}

impl TryFrom<[u8; PUBLIC_KEY_LENGTH]> for VerificationKeyEd25519Sig {
    type Error = CryptoError;

    fn try_from(bytes: [u8; PUBLIC_KEY_LENGTH]) -> Result<Self, Self::Error> {
        <<EcdsaSignatureSchemeEd25519 as SignatureScheme>::VerificationKeyType as TRawRepresentation>::from_raw(bytes)
            .map(|inner| Self {inner})
    }
}

impl Copy for VerificationKeyEd25519Sig {}

#[cfg(test)]
mod test {
    use crate::api::instances::ecdsa_sig_ed25519::{
        SigningKeyEd25519Sig, VerificationKeyEd25519Sig,
    };
    use crate::types::impls::sig_ecdsa_ed25519::PUBLIC_KEY_LENGTH;

    #[test]
    fn check_to_from_api() {
        let signing_key = SigningKeyEd25519Sig::new();
        let verifying_key = signing_key.gen_vk();
        let verifying_key_bytes = verifying_key.to_bytes();
        let verifying_key_from_bytes = VerificationKeyEd25519Sig::try_from(verifying_key_bytes)
            .expect("Valid VerificationKey construction");
        let bytes = verifying_key_from_bytes.to_bytes();
        assert_eq!(verifying_key_bytes, bytes);

        // random array of valid length does not panic
        let valid_bytes = [5u8; PUBLIC_KEY_LENGTH];
        let result = VerificationKeyEd25519Sig::try_from(valid_bytes);
        assert!(result.is_err())
    }

    #[test]
    fn check_reconstruction_from_slice() {
        let signing_key = SigningKeyEd25519Sig::new();
        let verifying_key = signing_key.gen_vk();
        let valid_bytes = verifying_key.to_bytes();
        let from_bytes = VerificationKeyEd25519Sig::try_from(valid_bytes.as_slice());
        assert!(from_bytes.is_ok(), "{:?}", from_bytes);

        let less_bytes = [5u8; PUBLIC_KEY_LENGTH - 5];
        let result = VerificationKeyEd25519Sig::try_from(less_bytes.as_slice());
        assert!(result.is_err());

        let more_bytes = [5u8; PUBLIC_KEY_LENGTH + 5];
        let result = VerificationKeyEd25519Sig::try_from(more_bytes.as_slice());
        assert!(result.is_err());
    }
}
