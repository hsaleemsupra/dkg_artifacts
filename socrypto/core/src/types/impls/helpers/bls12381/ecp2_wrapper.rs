use miracl_core_bls12381::bls12381::ecp2::ECP2;
use std::hash::{Hash, Hasher};

/// Wrapper for ECP which implements Eq (since ECP does not and VerificationKey must)
#[derive(Clone, Debug)]
pub struct Ecp2Wrapper(pub ECP2);

impl PartialEq for Ecp2Wrapper {
    fn eq(&self, other: &Ecp2Wrapper) -> bool {
        other.0.equals(&self.0)
    }
}

impl AsRef<ECP2> for Ecp2Wrapper {
    fn as_ref(&self) -> &ECP2 {
        &self.0
    }
}

impl Hash for Ecp2Wrapper {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        let mut b = [0u8; 96];
        self.0.tobytes(&mut b, true);
        state.write(&b);
        // let _ = state.finish();
    }
}

impl Eq for Ecp2Wrapper {}
