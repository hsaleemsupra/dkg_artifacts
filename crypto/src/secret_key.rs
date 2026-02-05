use crate::dealing::{CGIndividualDealing, ShareCommitment};
use crate::dealing_signature::DealingSignature;
use crate::errors::DkgError;
use crate::serde_utils::{read_vector, write_vector};
use bicycl::b_i_c_y_c_l::{Mpz, RandGen};
use bicycl::cpp_std::VectorOfUchar;
use bicycl::{cpp_core, rust_vec_to_cpp, SecretKeyBox};
use rand::{thread_rng, Rng, RngCore};
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Formatter};
use zeroize::{Zeroize, ZeroizeOnDrop};
use base64::engine::general_purpose::URL_SAFE as BASE64_ENGINE;
use base64::Engine;
use ed25519_dalek::{
    Signer, SigningKey as SigningKeyDalek,
};
use rand::rngs::OsRng;
use blst::min_pk::{SecretKey as SecretKeyBlst, Signature as SignatureBlst};

pub type SecretKey = SigningKeyDalek;

/// Length of the ED25519 secret key.
pub const SECRET_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;
pub const DST_BLS_SIG_IN_G2_WITH_POP: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";


#[derive(Clone)]
pub struct CGSecretKey {
    decryption_key_bls12381: SecretKeyBox,
    signing_key: SecretKey,
    signing_key_bls: SecretKeyBlst,
}

impl Debug for CGSecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "CGSecretKey: [SECRET_KEY_REDACTED]")
    }
}

fn sign_message_blst(sk: &SecretKeyBlst, msg: &[u8]) -> SignatureBlst{
    sk.sign(msg, DST_BLS_SIG_IN_G2_WITH_POP,&[])
}

impl Zeroize for CGSecretKey {
    fn zeroize(&mut self) {
        unsafe { self.decryption_key_bls12381.0.clear() };
        // self.signing_key implements drop method which zeroizes it on drop, so explicit zeroize is not needed
        self.signing_key_bls.zeroize();
    }
}

impl Drop for CGSecretKey {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl ZeroizeOnDrop for CGSecretKey {}

unsafe impl Sync for CGSecretKey {}

unsafe impl Send for CGSecretKey {}

impl CGSecretKey {
    pub fn signing_key(&self) -> &SecretKey {
        &self.signing_key
    }

    pub fn signing_key_bls(&self) -> &SecretKeyBlst {
        &self.signing_key_bls
    }

    pub fn decryption_key_bls12381(&self) -> &SecretKeyBox {
        &self.decryption_key_bls12381
    }

    pub fn generate() -> Self {
        let seed = rand::thread_rng().gen::<[u8; 32]>();
        let seed_cpp = unsafe { rust_vec_to_cpp(seed.to_vec()) };
        let ref_seed: cpp_core::Ref<VectorOfUchar> =
            unsafe { cpp_core::Ref::from_raw_ref(&seed_cpp) };
        let seed_mpz = unsafe { Mpz::from_vector_of_uchar(ref_seed) };
        let ref_seed_mpz: cpp_core::Ref<Mpz> = unsafe { cpp_core::Ref::from_raw_ref(&seed_mpz) };
        let mut rng_cpp = unsafe { RandGen::new_1a(ref_seed_mpz) };

        let c_12381 = crate::bls12381::utils::get_cl();

        let rng_dalek = &mut OsRng;
        let signing_key = SecretKey::generate(rng_dalek);

        let mut thread_rng = thread_rng();
        let mut ikm = [0u8; 32];
        thread_rng.fill_bytes(&mut ikm);
        let signing_key_bls = SecretKeyBlst::key_gen(&ikm, &[]).unwrap();

        let (decryption_key, _encryption_key, _pop) =
            crate::bls12381::cg_encryption::keygen(&c_12381, &mut rng_cpp, &vec![]);

        CGSecretKey {
            decryption_key_bls12381: decryption_key,
            signing_key,
            signing_key_bls
        }
    }

    pub fn sign_commitment(&self, dealing: &CGIndividualDealing) -> DealingSignature {
        let commitment = ShareCommitment::from(dealing.clone());
        let commitment_ser = commitment.to_vec();
        let signature = self.signing_key.sign(commitment_ser.as_slice());
        DealingSignature { signature }
    }

    pub fn sign_bls(&self, data: &Vec<u8>) -> SignatureBlst {
        sign_message_blst(&self.signing_key_bls, data.as_slice())
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let decryption_bls12381_bytes = unsafe { self.decryption_key_bls12381.to_bytes() };
        let signing_bytes = self.signing_key.to_bytes().to_vec();
        let signing_bls_bytes = self.signing_key_bls.to_bytes().to_vec();
        let mut final_bytes = vec![];
        write_vector(&mut final_bytes, decryption_bls12381_bytes);
        write_vector(&mut final_bytes, signing_bytes);
        write_vector(&mut final_bytes, signing_bls_bytes);
        final_bytes
    }

    pub fn encode_base64(&self) -> String {
        let raw_data = self.to_vec();
        BASE64_ENGINE.encode(raw_data)
    }

    pub fn decode_base64(input: String) -> Result<Self, DkgError> {
        BASE64_ENGINE
            .decode(input)
            .map_err(|e| {
                DkgError::DeserializationError(format!(
                    "Failed to deserialize from base64 string: {e}"
                ))
            })
            .and_then(|raw_data| Self::try_from(raw_data.as_slice()))
    }
}

impl TryFrom<&[u8]> for CGSecretKey {
    type Error = DkgError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = std::io::Cursor::new(bytes); // Clone the byte slice
        let decryption_bls12381_key_bytes = read_vector(&mut cursor)?;
        let signing_key_bytes = read_vector(&mut cursor)?;
        let signing_key_bls_bytes = read_vector(&mut cursor)?;

        // Attempt to convert the Vec<u8> into [u8; 32]
        let signing_key_array: [u8; SECRET_KEY_LENGTH] = signing_key_bytes
            .try_into().map_err(|_| DkgError::DeserializationError(
            "Input array too small or not valid for signing key".to_owned(),
        ))?;

        Ok(CGSecretKey {
            decryption_key_bls12381: unsafe {
                SecretKeyBox::from_bytes(
                    &decryption_bls12381_key_bytes,
                    &crate::bls12381::utils::get_cl(),
                )
                    .ok_or(DkgError::DeserializationError(
                        "Input array too small or not valid for decryption key".to_owned(),
                    ))?
            },
            signing_key: SecretKey::from(signing_key_array),
            signing_key_bls: SecretKeyBlst::from_bytes(signing_key_bls_bytes.as_slice()).map_err(|e|{
                DkgError::DeserializationError(format!("Error while deserializing signing_key_bls: {:?}", e))})?
        })
    }
}

impl PartialEq for CGSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_vec() == other.to_vec()
    }
}

impl Serialize for CGSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.to_vec()))
    }
}

impl<'de> Deserialize<'de> for CGSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(|e| D::Error::custom(e.to_string()))?;
        let value =
            CGSecretKey::try_from(bytes.as_slice()).map_err(|e| D::Error::custom(e.to_string()))?;
        Ok(value)
    }
}
