use crate::errors::DkgError;
use ed25519_dalek::Signature;

/// Length of the ED25519 signature.
pub const SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;

#[derive(Debug, Clone)]
pub struct DealingSignature {
    pub signature: Signature,
}

impl DealingSignature {
    pub fn to_vec(&self) -> Vec<u8> {
        self.signature.to_bytes().to_vec()
    }
}

impl TryFrom<&[u8]> for DealingSignature {
    type Error = DkgError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let value: [u8; SIGNATURE_LENGTH] = value.try_into().map_err(|_| DkgError::DeserializationError("DealingSignature bytes are not valid".into()))?;
        Ok(Self {
            signature: Signature::from(value),
        })
    }
}

