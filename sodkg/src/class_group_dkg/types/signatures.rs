use crypto::errors::DkgError;
use nidkg_helper::{BlsSignature12381G2};

#[derive(Debug, Clone)]
pub struct BlsPartialSignature(pub BlsSignature12381G2);
pub type BlsMultiSignature = BlsPartialSignature;

impl TryFrom<&[u8]> for BlsPartialSignature {
    type Error = DkgError;

    fn try_from(pk: &[u8]) -> Result<Self, Self::Error> {
        let sig = BlsSignature12381G2::try_from(pk)?;
        Ok(BlsPartialSignature(sig))
    }
}