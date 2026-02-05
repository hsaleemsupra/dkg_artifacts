//! Defines singer data of the [UnsignedSmrTransaction]

use crate::sosmr_types::SmrError;
use serde::{Deserialize, Serialize};
use socrypto::{PublicKey, Signature};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};

/// Signer information of the [UnsignedSmrTransaction]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerData {
    /// PublicKey of the transaction sender and signer
    signer: PublicKey,
    /// Signature of the transaction by signer
    signature: Signature,
}

impl SignerData {
    pub fn new(signer: PublicKey, signature: Signature) -> Self {
        Self { signer, signature }
    }

    pub fn verify_on_message<M: AsRef<[u8]>>(&self, message: &M) -> Result<(), SmrError> {
        self.signature
            .verify(message, &self.signer)
            .map_err(SmrError::SupraCryptoError)
    }
}

pub trait TSignerData {
    fn signer_data(&self) -> &SignerData;

    fn signer(&self) -> &PublicKey {
        &self.signer_data().signer
    }

    fn signature(&self) -> &Signature {
        &self.signer_data().signature
    }
}
impl Display for SignerData {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
