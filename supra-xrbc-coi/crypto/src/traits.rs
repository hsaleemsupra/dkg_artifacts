use primitives::{Origin, HASH32};

pub trait DistributedKeyPairInterface {
    type Error;
    type RawPublicKey;
    type Signature;
    type PartialShare;

    fn threshold(&self) -> usize;
    fn partial_signature(&self, message: &HASH32) -> Result<Self::PartialShare, Self::Error>;
    fn threshold_signature(
        &self,
        shares: Vec<Self::PartialShare>,
    ) -> Result<Self::Signature, Self::Error>;
    fn verify_partial_signature(
        &self,
        partial_share: &Self::PartialShare,
        message: &HASH32,
    ) -> Result<(), Self::Error>;
    fn verify_threshold_signature(
        &self,
        signature: &Self::Signature,
        message: &HASH32,
    ) -> Result<(), Self::Error>;
    fn public_key(&self) -> Self::RawPublicKey;
    fn verify_threshold_signature_for_key(
        public_key: &Self::RawPublicKey,
        signature: &Self::Signature,
        message: &HASH32,
    ) -> Result<(), Self::Error>;
}

pub trait NodeIdentityInterface {
    type Error;
    type RawPublicKey;
    type Signature;

    fn sign(&self, message: &[u8]) -> Result<Self::Signature, Self::Error>;
    fn verify(
        origin: &Self::RawPublicKey,
        signature: &Self::Signature,
        msg: &[u8],
    ) -> Result<(), Self::Error>;
    fn public_key(&self) -> Self::RawPublicKey;

    fn is_valid_public_key(origin: &Origin) -> Result<(), Self::Error>;
}
