use miracl_core_bls12381::bls12381::ecp::ECP;
use std::hash::{Hash, Hasher};

/// Wrapper for ECP which implements Eq (since ECP does not and VerificationKey must)
#[derive(Clone, Debug)]
pub struct EcpWrapper(pub ECP);

impl PartialEq for EcpWrapper {
    fn eq(&self, other: &EcpWrapper) -> bool {
        other.0.equals(&self.0)
    }
}

impl AsRef<ECP> for EcpWrapper {
    fn as_ref(&self) -> &ECP {
        &self.0
    }
}

impl Hash for EcpWrapper {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        let mut b = [0u8; 48];
        self.0.tobytes(&mut b, true);
        state.write(&b);
        // let _ = state.finish(); // Remove finish call as it returns u64, not needed for void return
    }
}

impl Eq for EcpWrapper {}
