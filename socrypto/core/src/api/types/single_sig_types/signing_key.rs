use super::{PopWrapperSig, SignatureScheme, SignatureWrapper, VerificationKeyWrapperSig};
use crate::types::ownable::Ownable;
use crate::types::serde::{TCryptoSerde, TRawRepresentation};
use crate::types::CryptoError;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use zeroize::ZeroizeOnDrop;

/// Wrapper struct representing signing (secret) for a single signer signature scheme.
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SigningKeyWrapperSig<T: SignatureScheme> {
    #[serde(with = "TCryptoSerde")]
    pub(crate) inner: T::SigningKeyType,
}

impl<T: SignatureScheme> SigningKeyWrapperSig<T> {
    /// Choose a new random secret key.
    pub fn new() -> Self {
        SigningKeyWrapperSig { inner: T::new_sk() }
    }
    /// Compute verification key associated with self.
    pub fn gen_vk(&self) -> VerificationKeyWrapperSig<T> {
        VerificationKeyWrapperSig::new(T::vk_from_sk(&self.inner))
    }
    /// Sign message `msg` using associated verification key `vk`.
    pub fn sign_with_vk<M: AsRef<[u8]>>(
        &self,
        msg: &M,
        vk: &VerificationKeyWrapperSig<T>,
    ) -> SignatureWrapper<T> {
        SignatureWrapper::new(T::sign(&self.inner, msg, &vk.inner))
    }
    /// Sign message `msg` without associated verification key `vk`.
    /// note in some cases may be less efficient than supplying vk when already known
    pub fn sign_no_vk<M: AsRef<[u8]>>(&self, msg: &M) -> SignatureWrapper<T> {
        SignatureWrapper::new(T::sign_no_vk(&self.inner, msg))
    }

    /// Converts to raw representation of the enclosed data.
    pub fn to_bytes(&self) -> <<T as SignatureScheme>::SigningKeyType as TRawRepresentation>::Raw {
        self.inner.to_raw()
    }
}

impl<T: SignatureScheme> Clone for SigningKeyWrapperSig<T> {
    fn clone(&self) -> Self {
        Self {
            inner: T::SigningKeyType::from_raw(self.inner.to_raw())
                .expect("Cloning the key should not fail in scope of library"),
        }
    }
}

impl<T: SignatureScheme> Default for SigningKeyWrapperSig<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: SignatureScheme> TryFrom<&[u8]> for SigningKeyWrapperSig<T> {
    type Error = CryptoError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <T::SigningKeyType as TRawRepresentation>::from(bytes)
            .and_then(T::SigningKeyType::from_raw)
            .map(|inner| Self { inner })
    }
}

impl<T: SignatureScheme> SigningKeyWrapperSig<T>
where
    T::SigningKeyType: Ownable<PublicType = T::VerificationKeyType>,
    <T::SigningKeyType as Ownable>::PopType: TCryptoSerde,
{
    /// Prove knowledge of self as secret key associated with verification key `vk`
    pub fn generate_proof_of_possession(
        &self,
        vk: &VerificationKeyWrapperSig<T>,
    ) -> PopWrapperSig<T> {
        PopWrapperSig::new(self.inner.generate_proof_of_possession(&vk.inner))
    }
}

impl<T: SignatureScheme> Debug for SigningKeyWrapperSig<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::Secret(...)", std::any::type_name::<T>())
    }
}

impl<T: SignatureScheme> Display for SigningKeyWrapperSig<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
