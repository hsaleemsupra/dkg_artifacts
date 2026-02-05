use crate::secret_key::{CGSecretKey, DST_BLS_SIG_IN_G2_WITH_POP};
use crate::dealing_signature::DealingSignature;
use crate::errors::DkgError;
use crate::serde_utils::{read_vector, write_vector};
use bicycl::b_i_c_y_c_l::{Mpz, RandGen};
use bicycl::cpp_std::VectorOfUchar;
use bicycl::{cpp_core, rust_vec_to_cpp, MpzBox, PublicKeyBox, QFIBox};
use crate::bls12381::key_pop_zk::verify_pop_zk as verify_pop_zk_12381;
use crate::bls12381::key_pop_zk::{
    create_pop_zk as create_pop_zk_bls12381, PopZk as BLS12381PopZk,
    PopZkInstance as BLS12381PopZkInstance,
};
use rand::Rng;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Display, Formatter};
use blst::BLST_ERROR;
use ed25519_dalek::{Verifier, VerifyingKey as PublicKey};
use blst::min_pk::{PublicKey as PublicKeyBlst, Signature as SignatureBlst};

/// Class group Encryption key for BLS 12381 domain data
#[derive(Clone, Debug)]
pub struct CGEncryptionKeyBls12381 {
    pub key: PublicKeyBox,
    pub pop: BLS12381PopZk,
}

impl CGEncryptionKeyBls12381 {
    pub fn key(&self) -> &PublicKeyBox {
        &self.key
    }

    pub fn pop(&self) -> &BLS12381PopZk {
        &self.pop
    }
}

impl CGEncryptionKeyBls12381 {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];

        let encryption_key_bytes = unsafe { self.key.to_bytes() };
        let response_bytes = unsafe { self.pop.response.to_bytes() };
        let challenge_bytes = unsafe { self.pop.challenge.to_bytes() };
        let pop_key_box = unsafe { self.pop.pop_key.to_bytes() };

        // appending bytes for final result for bls12381
        write_vector(&mut final_bytes, encryption_key_bytes);
        write_vector(&mut final_bytes, pop_key_box);
        write_vector(&mut final_bytes, challenge_bytes);
        write_vector(&mut final_bytes, response_bytes);

        final_bytes
    }
}

impl TryFrom<&[u8]> for CGEncryptionKeyBls12381 {
    type Error = DkgError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = std::io::Cursor::new(bytes);
        let encryption_key_bytes = read_vector(&mut cursor)?;
        let pop_key_box = read_vector(&mut cursor)?;
        let challenge_bytes = read_vector(&mut cursor)?;
        let response_bytes = read_vector(&mut cursor)?;

        Ok(CGEncryptionKeyBls12381 {
            key: unsafe {
                PublicKeyBox::from_bytes(&encryption_key_bytes, &crate::bls12381::utils::get_cl())
                    .ok_or(DkgError::DeserializationError(
                        "Input array too small or not invalid for encryption key for bls12381 pk"
                            .to_owned(),
                    ))?
            },
            pop: unsafe {
                BLS12381PopZk {
                    pop_key: PublicKeyBox::from_bytes(&pop_key_box, &crate::bls12381::utils::get_cl())
                        .ok_or(DkgError::DeserializationError(
                            "Input array too small or not invalid for pop key for bls12381 pk"
                                .to_owned(),
                        ))?,
                    challenge: MpzBox::from_bytes(&challenge_bytes)
                        .ok_or(DkgError::DeserializationError(
                            "Input array too small or not invalid for pop challenge for bls12381 pk"
                                .to_owned(),
                        ))?,
                    response: MpzBox::from_bytes(&response_bytes).ok_or(
                        DkgError::DeserializationError(
                            "Input array too small or not invalid for pop response for bls12381 pk"
                                .to_owned(),
                        ),
                    )?,
                }
            },
        })
    }
}


/// Class Group public key containing
///  - ed25519 verification key for the signed dealing
///  - bls verification key for signed verified dealer set
///  - and encryption keys for BLS 12381 and BN 254 domain data
#[derive(Clone)]
pub struct CGPublicKey {
    pub verification_key: PublicKey,
    pub verification_key_bls: PublicKeyBlst,
    pub encryption_key_bls12381: CGEncryptionKeyBls12381,
}

pub fn verify_signature(pk: &PublicKeyBlst, msg: &[u8], sig: &SignatureBlst) -> bool{
    let result = sig.verify(true, msg, DST_BLS_SIG_IN_G2_WITH_POP, &[], pk, false);
    if result == BLST_ERROR::BLST_SUCCESS {
        true
    } else {
        false
    }
}


unsafe impl Sync for CGPublicKey {}

impl Display for CGPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            hex::encode(self.verification_key.to_bytes().to_vec())
        )
    }
}

impl Debug for CGPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl Serialize for CGPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex_string())
    }
}

impl<'de> Deserialize<'de> for CGPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(|e| D::Error::custom(e.to_string()))?;
        let value =
            CGPublicKey::try_from(bytes.as_slice()).map_err(|e| D::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl CGPublicKey {
    pub fn verification_key(&self) -> &PublicKey {
        &self.verification_key
    }

    pub fn verification_key_bls(&self) -> &PublicKeyBlst {
        &self.verification_key_bls
    }

    pub fn encryption_key_bls12381(&self) -> &CGEncryptionKeyBls12381 {
        &self.encryption_key_bls12381
    }

    pub fn validate(&self) -> Result<(), DkgError> {
        let ffi_gen_h_12381 = unsafe {
            bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
                cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(
                    crate::bls12381::utils::get_cl().h(),
                )
                    .as_raw_ptr(),
            )
        };
        let gen_h_12381 = unsafe { cpp_core::CppBox::from_raw(ffi_gen_h_12381) }.ok_or(
            DkgError::ClassGroupTypeError("Attempted to construct a null CppBox: Bls12381"),
        )?;

        let instance12381 = crate::bls12381::key_pop_zk::PopZkInstance {
            gen: QFIBox(gen_h_12381),
            public_key: self.encryption_key_bls12381().key().clone(),
            associated_data: vec![],
        };
        verify_pop_zk_12381(
            &instance12381,
            self.encryption_key_bls12381().pop(),
            &crate::bls12381::utils::get_cl(),
        )
            .map_err(DkgError::PopZkError12381)
    }

    pub fn to_hex_string(&self) -> String {
        hex::encode(self.to_vec())
    }
}

impl PartialEq for CGPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_vec() == other.to_vec()
    }
}

impl Eq for CGPublicKey {}

impl CGPublicKey {
    pub fn verify_commitment_signature(&self, msg: &Vec<u8>, signature: &DealingSignature) -> bool {
        self.verification_key.verify(msg, &signature.signature).is_ok()
    }

    pub fn verify_signature_bls(&self, msg: &Vec<u8>, signature: &SignatureBlst) -> bool {
        verify_signature(self.verification_key_bls(), msg, signature)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut final_bytes = vec![];
        let verification_key_bytes = self.verification_key.to_bytes().to_vec();
        let verification_key_bls_bytes = self.verification_key_bls.to_bytes().to_vec();
        let bls12381_bytes = self.encryption_key_bls12381.to_vec();
        write_vector(&mut final_bytes, verification_key_bytes);
        write_vector(&mut final_bytes, verification_key_bls_bytes);
        write_vector(&mut final_bytes, bls12381_bytes);

        final_bytes
    }
}

impl TryFrom<&CGSecretKey> for CGPublicKey {
    type Error = DkgError;

    fn try_from(cg_sk: &CGSecretKey) -> Result<Self, Self::Error> {
        let seed = rand::thread_rng().gen::<[u8; 32]>();
        let seed_cpp = unsafe { rust_vec_to_cpp(seed.to_vec()) };
        let ref_seed: cpp_core::Ref<VectorOfUchar> =
            unsafe { cpp_core::Ref::from_raw_ref(&seed_cpp) };
        let seed_mpz = unsafe { Mpz::from_vector_of_uchar(ref_seed) };
        let ref_seed_mpz: cpp_core::Ref<Mpz> = unsafe { cpp_core::Ref::from_raw_ref(&seed_mpz) };
        let mut rng_cpp = unsafe { RandGen::new_1a(ref_seed_mpz) };

        let c_12381 = crate::bls12381::utils::get_cl();

        let mut bls_12381_sk = cg_sk.decryption_key_bls12381().clone();

        // For BLS12381
        let bls12381_pk =
            unsafe { c_12381.keygen_c_l_h_s_m_secret_key_of_c_l_h_s_mqk(&bls_12381_sk.0) };
        let sk_mpz = unsafe { bls_12381_sk.0.get_mpz() };

        let ffi_gen_h = unsafe {
            bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
                cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(
                    c_12381.h(),
                )
                    .as_raw_ptr(),
            )
        };
        let gen_h = unsafe { cpp_core::CppBox::from_raw(ffi_gen_h) }
            .expect("attempted to construct a null CppBox");

        let bls12381_instance = BLS12381PopZkInstance {
            gen: QFIBox(gen_h),
            public_key: PublicKeyBox(bls12381_pk),
            associated_data: vec![],
        };
        let pop_bls12381 =
            create_pop_zk_bls12381(&bls12381_instance, &sk_mpz, &c_12381, &mut rng_cpp)
                .map_err(|e| DkgError::GeneralError(format!("{:?}", e)))?;
        let verification_key = cg_sk.signing_key().verifying_key();

        let verification_key_bls12381 = cg_sk.signing_key_bls().sk_to_pk();

        Ok(CGPublicKey {
            verification_key,
            verification_key_bls: verification_key_bls12381,
            encryption_key_bls12381: CGEncryptionKeyBls12381 {
                key: bls12381_instance.public_key,
                pop: pop_bls12381,
            },
        })
    }
}

impl TryFrom<&[u8]> for CGPublicKey {
    type Error = DkgError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = std::io::Cursor::new(bytes);
        let verification_key_bytes = read_vector(&mut cursor)?;
        let verification_key_bls_bytes = read_vector(&mut cursor)?;
        let bls12381_pk_bytes = read_vector(&mut cursor)?;

        Ok(CGPublicKey {
            verification_key: PublicKey::try_from(verification_key_bytes.as_slice())
                .map_err(|_| DkgError::DeserializationError("Verification Key has invalid length".to_string()))?,
            verification_key_bls:  PublicKeyBlst::from_bytes(verification_key_bls_bytes.as_slice())
                .map_err(|e| DkgError::DeserializationError(format!("Error while deserializing verification_key_bls: {:?}", e)))?,
            encryption_key_bls12381: CGEncryptionKeyBls12381::try_from(
                bls12381_pk_bytes.as_slice(),
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::public_key::CGPublicKey;
    use crate::secret_key::CGSecretKey;
    use std::time::Instant;

    #[test]
    fn check_public_key_serde_interface() {
        let sk_gen_time = Instant::now();
        let secret = CGSecretKey::generate();
        println!(
            "SK Generate Time: {} s",
            sk_gen_time.elapsed().as_secs_f32()
        );
        let raw_secret = secret.to_vec();
        let sk_from_bytes = CGSecretKey::try_from(raw_secret.as_slice()).expect("Valid sk");
        let sk_ser_time = Instant::now();
        let sk_ser_bytes =
            bincode::serialize(&secret).expect("Successful CGSecretKey Serialization");
        println!(
            "SK Serialization Time: {} s",
            sk_ser_time.elapsed().as_secs_f32()
        );

        let sk_deser_time = Instant::now();
        let sk_deser: CGSecretKey = bincode::deserialize(sk_ser_bytes.as_slice())
            .expect("Successful CGSecretKey de-serialization");
        println!(
            "SK Deserialization Time: {} s",
            sk_deser_time.elapsed().as_secs_f32()
        );
        assert_eq!(sk_from_bytes, sk_deser);

        let pk_from_sk_time = Instant::now();
        let pk = CGPublicKey::try_from(&secret).expect("Valid CGPublicKey from secret key");
        println!(
            "PK from SK Time: {} s",
            pk_from_sk_time.elapsed().as_secs_f32()
        );

        let raw_pk = pk.to_vec();
        let pk_from_bytes = CGPublicKey::try_from(raw_pk.as_slice()).expect("Valid pk");
        let pk_ser_time = Instant::now();
        let pk_ser_bytes = bincode::serialize(&pk).expect("Successful CGPublicKey Serialization");
        println!(
            "PK Serialization Time: {} s",
            pk_ser_time.elapsed().as_secs_f32()
        );

        let pk_deser_time = Instant::now();
        let pk_deser: CGPublicKey = bincode::deserialize(pk_ser_bytes.as_slice())
            .expect("Successful CGPublicKey de-serialization");
        println!(
            "PK Deserialization Time: {} s",
            pk_deser_time.elapsed().as_secs_f32()
        );
        assert_eq!(pk_from_bytes, pk_deser);
    }
}
