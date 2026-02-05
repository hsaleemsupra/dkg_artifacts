use crate::api::instances::ecdsa_sig_ed25519::SignatureEd25519Sig;
use crate::types::impls::sig_ecdsa_ed25519::{EcdsaSignatureSchemeEd25519, SIGNATURE_LENGTH};
use crate::types::schemes::single_sig_scheme::SignatureScheme;
use crate::types::serde::TRawRepresentation;
use std::hash::{Hash, Hasher};

impl SignatureEd25519Sig {
    /// Checks whether the signature is empty/dummy one
    /// Default signature is considered dummy/empty signature
    pub fn is_empty(&self) -> bool {
        Self::default().eq(self)
    }
}
impl Default for SignatureEd25519Sig {
    fn default() -> Self {
        Self::from([0u8; SIGNATURE_LENGTH])
    }
}

impl Copy for SignatureEd25519Sig {}

impl Hash for SignatureEd25519Sig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}

impl From<[u8; SIGNATURE_LENGTH]> for SignatureEd25519Sig {
    fn from(bytes: [u8; SIGNATURE_LENGTH]) -> Self {
        <<EcdsaSignatureSchemeEd25519 as SignatureScheme>::SignatureType as TRawRepresentation>::from_raw(bytes)
            .map(|inner| Self {inner}).expect("Signature from array of SIGNATURE_LENGTH is always well-formed")
    }
}

#[cfg(test)]
mod test {
    use crate::api::instances::ecdsa_sig_ed25519::SignatureEd25519Sig;
    use crate::types::impls::sig_ecdsa_ed25519::SIGNATURE_LENGTH;

    #[test]
    fn check_empty_signature() {
        let default = SignatureEd25519Sig::default();
        assert!(default.is_empty());

        let zero_bytes = [0u8; SIGNATURE_LENGTH];
        let from_zero_bytes = SignatureEd25519Sig::from(zero_bytes);
        assert!(from_zero_bytes.is_empty());

        let from_zero_bytes_slice = SignatureEd25519Sig::try_from(zero_bytes.as_slice())
            .expect("Successful construction from slice of SIGNATURE_SIZE length");
        assert!(from_zero_bytes_slice.is_empty());

        let non_zero_bytes = [4u8; SIGNATURE_LENGTH];
        let from_non_zero_bytes = SignatureEd25519Sig::from(non_zero_bytes);
        assert!(!from_non_zero_bytes.is_empty());

        let from_non_zero_bytes_slice = SignatureEd25519Sig::try_from(non_zero_bytes.as_slice())
            .expect("Successful construction from slice of SIGNATURE_SIZE length");
        assert!(!from_non_zero_bytes_slice.is_empty());
    }

    #[test]
    fn check_reconstruction_from_slice() {
        let valid_bytes = [5u8; SIGNATURE_LENGTH];
        let from_bytes = SignatureEd25519Sig::try_from(valid_bytes.as_slice());
        assert!(from_bytes.is_ok(), "{:?}", from_bytes);

        let less_bytes = [5u8; SIGNATURE_LENGTH - 5];
        let result = SignatureEd25519Sig::try_from(less_bytes.as_slice());
        assert!(result.is_err());

        let more_bytes = [5u8; SIGNATURE_LENGTH + 5];
        let result = SignatureEd25519Sig::try_from(more_bytes.as_slice());
        assert!(result.is_err());
    }
}
