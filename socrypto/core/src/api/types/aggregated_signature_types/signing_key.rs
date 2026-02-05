//! Defines common signing key concept for multi-party signature service based on the schema.
use super::{AggregateSignatureScheme, MultiSignatureScheme, ThresholdSignatureScheme};
use super::{PartialSignatureWrapper, PopWrapperAggSig, VerificationKeyWrapperAggSig};
use crate::types::ownable::Ownable;
use crate::types::serde::{TCryptoSerde, TRawRepresentation};
use serde::{Deserialize, Serialize};
use std::any::type_name;
use std::fmt::{Debug, Formatter};
use zeroize::ZeroizeOnDrop;

/// Wrapper struct representing signing (secret) for a multi-party signature scheme
#[derive(ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SigningKeyWrapperAggSig<T: AggregateSignatureScheme>(
    #[serde(with = "TCryptoSerde")] pub(crate) T::SigningKeyType,
);

impl<T: AggregateSignatureScheme> SigningKeyWrapperAggSig<T> {
    /// Generate a partial signature on message `msg` using associated verification key `vk`
    pub fn sign<M: AsRef<[u8]>>(
        &self,
        msg: &M,
        vk: &VerificationKeyWrapperAggSig<T>,
    ) -> PartialSignatureWrapper<T> {
        PartialSignatureWrapper::new(T::sign(msg, &self.0, vk.as_ref()))
    }

    /// Converts to raw representation of the enclosed data.
    pub fn to_bytes(
        &self,
    ) -> <<T as AggregateSignatureScheme>::SigningKeyType as TRawRepresentation>::Raw {
        self.0.to_raw()
    }
}

impl<T: MultiSignatureScheme> SigningKeyWrapperAggSig<T> {
    /// Choose a new random secret key.
    pub fn new() -> Self {
        SigningKeyWrapperAggSig(T::new_sk())
    }

    /// Compute verification key associated with self
    pub fn gen_vk(&self) -> VerificationKeyWrapperAggSig<T> {
        VerificationKeyWrapperAggSig::new(T::vk_from_sk(&self.0))
    }
}

impl<T: ThresholdSignatureScheme> SigningKeyWrapperAggSig<T> {}

// JG: Why do we need default here?
impl<T: MultiSignatureScheme> Default for SigningKeyWrapperAggSig<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: AggregateSignatureScheme> Clone for SigningKeyWrapperAggSig<T> {
    fn clone(&self) -> Self {
        Self(
            T::SigningKeyType::from_raw(self.0.to_raw())
                .expect("Cloning the key should not fail in scope of library"),
        )
    }
}

impl<T: AggregateSignatureScheme> Debug for SigningKeyWrapperAggSig<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::SigningKey", type_name::<T>())
    }
}

impl<T: AggregateSignatureScheme> SigningKeyWrapperAggSig<T>
where
    T::SigningKeyType: Ownable<PublicType = T::VerificationKeyType>,
    <T::SigningKeyType as Ownable>::PopType: TCryptoSerde,
{
    /// Generates proof of possession of the secret key associated with the input verification key.
    pub fn generate_proof_of_possession(
        &self,
        pk: &VerificationKeyWrapperAggSig<T>,
    ) -> PopWrapperAggSig<T> {
        PopWrapperAggSig::new(self.0.generate_proof_of_possession(pk.as_ref()))
    }
}
