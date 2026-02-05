use super::SignatureScheme;
use crate::types::ownable::Ownable;
use crate::types::serde::TRawRepresentation;
use crate::types::{CryptoError, CryptoResult};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::OnceLock;
use zeroize::ZeroizeOnDrop;

#[derive(Default)]
pub(crate) struct MockSignatureSchema {
    pub(crate) sk_counter: AtomicU16,
    pub(crate) new_sk_called: AtomicBool,
    pub(crate) sign_called: AtomicBool,
    pub(crate) sign_no_vk_called: AtomicBool,
    pub(crate) verify_sig_called: AtomicBool,
    pub(crate) vk_from_sk_called: AtomicBool,
    pub(crate) to_raw_called: AtomicBool,
    pub(crate) prove_possession_called: AtomicBool,
    pub(crate) verify_possession_called: AtomicBool,
}

impl MockSignatureSchema {
    fn reset_flags(&self) {
        self.new_sk_called.store(false, Ordering::Relaxed);
        self.sign_called.store(false, Ordering::Relaxed);
        self.sign_no_vk_called.store(false, Ordering::Relaxed);
        self.vk_from_sk_called.store(false, Ordering::Relaxed);
        self.verify_sig_called.store(false, Ordering::Relaxed);
        self.to_raw_called.store(false, Ordering::Relaxed);
        self.prove_possession_called.store(false, Ordering::Relaxed);
        self.verify_possession_called
            .store(false, Ordering::Relaxed);
    }
}

pub(crate) static MSS: OnceLock<MockSignatureSchema> = OnceLock::<MockSignatureSchema>::new();

fn get_mss() -> &'static MockSignatureSchema {
    MSS.get_or_init(MockSignatureSchema::default)
}

#[derive(ZeroizeOnDrop)]
pub(crate) struct MockSk(u16);

impl Deref for MockSk {
    type Target = u16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SignatureScheme for MockSignatureSchema {
    type SigningKeyType = MockSk;
    type VerificationKeyType = u16;
    type SignatureType = u16;

    fn new_sk() -> Self::SigningKeyType {
        get_mss().new_sk_called.store(true, Ordering::Relaxed);
        let sk = get_mss().sk_counter.load(Ordering::Relaxed);
        get_mss().sk_counter.fetch_add(1, Ordering::Relaxed);
        MockSk(sk)
    }

    fn sign<M: AsRef<[u8]>>(
        sk: &Self::SigningKeyType,
        _msg: &M,
        _vk: &Self::VerificationKeyType,
    ) -> Self::SignatureType {
        get_mss().sign_called.store(true, Ordering::Relaxed);
        sk.deref() + 200
    }

    fn sign_no_vk<M: AsRef<[u8]>>(sk: &Self::SigningKeyType, _msg: &M) -> Self::SignatureType {
        get_mss().sign_no_vk_called.store(true, Ordering::Relaxed);
        sk.deref() + 200
    }

    fn verify_signature<M: AsRef<[u8]>>(
        _msg: &M,
        _vk: &Self::VerificationKeyType,
        _sig: &Self::SignatureType,
    ) -> CryptoResult<()> {
        get_mss().verify_sig_called.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn vk_from_sk(sk: &Self::SigningKeyType) -> Self::VerificationKeyType {
        get_mss().vk_from_sk_called.store(true, Ordering::Relaxed);
        sk.deref() + 100
    }
}

impl TRawRepresentation for MockSk {
    type Raw = [u8; 2];

    fn create() -> Self::Raw {
        [0; 2]
    }

    fn from_raw(src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized,
    {
        u16::from_raw(src).map(MockSk)
    }

    fn to_raw(&self) -> Self::Raw {
        get_mss().to_raw_called.store(true, Ordering::Relaxed);
        self.deref().to_raw()
    }
}
impl TRawRepresentation for u16 {
    type Raw = [u8; 2];

    fn create() -> Self::Raw {
        [0; 2]
    }

    fn from_raw(src: Self::Raw) -> CryptoResult<Self>
    where
        Self: Sized,
    {
        let value = u16::from_be_bytes(src);
        Ok(value)
    }

    fn to_raw(&self) -> Self::Raw {
        get_mss().to_raw_called.store(true, Ordering::Relaxed);
        self.to_be_bytes().to_vec().try_into().unwrap()
    }
}

impl Ownable for MockSk {
    type PublicType = u16;
    type PopType = u16;
    type Error = CryptoError;

    fn generate_proof_of_possession(&self, pk: &Self::PublicType) -> Self::PopType {
        get_mss()
            .prove_possession_called
            .store(true, Ordering::Relaxed);
        pk + 300
    }

    fn verify_possession(_pk: &Self::PublicType, _pop: &Self::PopType) -> CryptoResult<()> {
        get_mss()
            .verify_possession_called
            .store(true, Ordering::Relaxed);
        Ok(())
    }
}

mod tests {
    use crate::api::types::single_sig_types::mock_signature_schema::{
        get_mss, MockSignatureSchema, MSS,
    };
    use crate::api::types::single_sig_types::{
        PopWrapperSig, SignatureWrapper, SigningKeyWrapperSig, VerificationKeyWrapperSig,
    };
    use std::sync::atomic::Ordering;

    #[test]
    fn check_wrappers_api() {
        let _ = MSS.set(MockSignatureSchema::default());
        check_signing_key();
        get_mss().reset_flags();
        check_verifying_key();
        get_mss().reset_flags();
        check_signature();
        get_mss().reset_flags();
        check_pop();
        get_mss().reset_flags();
    }

    fn check_signature() {
        let sig = SignatureWrapper::<MockSignatureSchema>::new(5);
        let vk = VerificationKeyWrapperSig::<MockSignatureSchema>::new(6);
        let _ = sig.verify(b"test", &vk);
        assert!(get_mss().verify_sig_called.load(Ordering::Relaxed));

        let _ = sig.to_bytes();
        assert!(get_mss().to_raw_called.load(Ordering::Relaxed))
    }

    fn check_verifying_key() {
        let sig = SignatureWrapper::<MockSignatureSchema>::new(5);
        let vk = VerificationKeyWrapperSig::<MockSignatureSchema>::new(6);
        let _ = vk.verify(b"test", &sig);
        assert!(get_mss().verify_sig_called.load(Ordering::Relaxed));

        let _ = vk.to_bytes();
        assert!(get_mss().to_raw_called.load(Ordering::Relaxed));

        let pop = PopWrapperSig::<MockSignatureSchema>::new(7);
        let _ = vk.verify_possession(&pop);
        assert!(get_mss().verify_possession_called.load(Ordering::Relaxed));
    }

    fn check_pop() {
        let vk = VerificationKeyWrapperSig::<MockSignatureSchema>::new(6);

        let pop = PopWrapperSig::<MockSignatureSchema>::new(7);
        let _ = pop.verify_possession(&vk);
        assert!(get_mss().verify_possession_called.load(Ordering::Relaxed));

        let _ = pop.to_bytes();
        assert!(get_mss().to_raw_called.load(Ordering::Relaxed));
    }

    fn check_signing_key() {
        let sk = SigningKeyWrapperSig::<MockSignatureSchema>::new();
        assert!(get_mss().new_sk_called.load(Ordering::Relaxed));

        let vk = sk.gen_vk();
        assert!(get_mss().vk_from_sk_called.load(Ordering::Relaxed));

        let _ = sk.sign_with_vk(b"test", &vk);
        assert!(get_mss().sign_called.load(Ordering::Relaxed));
        assert!(!get_mss().sign_no_vk_called.load(Ordering::Relaxed));
        get_mss().reset_flags();

        let _ = sk.sign_no_vk(b"test");
        assert!(!get_mss().sign_called.load(Ordering::Relaxed));
        assert!(get_mss().sign_no_vk_called.load(Ordering::Relaxed));
        get_mss().reset_flags();

        let _ = SigningKeyWrapperSig::<MockSignatureSchema>::new();
        assert!(get_mss().new_sk_called.load(Ordering::Relaxed));
        get_mss().reset_flags();

        let _ = SigningKeyWrapperSig::<MockSignatureSchema>::default();
        assert!(get_mss().new_sk_called.load(Ordering::Relaxed));

        let _ = sk.to_bytes();
        assert!(get_mss().to_raw_called.load(Ordering::Relaxed));

        let _ = sk.generate_proof_of_possession(&vk);
        assert!(get_mss().prove_possession_called.load(Ordering::Relaxed));
    }
}
