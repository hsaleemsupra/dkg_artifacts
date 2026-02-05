use crate::bls12381::{
    context::{Context, DomainSeparationContext},
    rng::RAND_ChaCha20,
};
use bicycl::cpp_vec_to_rust;
use bicycl::{CiphertextBox, PublicKeyBox, QFIBox};
use blsttc::{group::ff::Field, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use cpp_std::VectorOfUchar;
use miracl_core_bls12381::hash256::HASH256;
use std::collections::BTreeMap;
use std::ops::Deref;

const DOMAIN_RO_INT: &str = "crypto-random-oracle-integer";
const DOMAIN_RO_STRING: &str = "crypto-random-oracle-string";
const DOMAIN_RO_BYTE_ARRAY: &str = "crypto-random-oracle-byte-array";
const DOMAIN_RO_MAP: &str = "crypto-random-oracle-map";
const DOMAIN_RO_VECTOR: &str = "crypto-random-oracle-vector";
const DOMAIN_RO_QFI: &str = "crypto-random-oracle-qfi";
const DOMAIN_RO_PUBLIC_KEY: &str = "crypto-random-oracle-public-key";
const DOMAIN_RO_CIPHERTEXT: &str = "crypto-random-oracle-ciphertext";

const DOMAIN_RO_FR: &str = "crypto-random-oracle-blsttc-fr";
const DOMAIN_RO_G1_BLSTTC: &str = "crypto-random-oracle-blsttc-g1";
const DOMAIN_RO_G2_BLSTTC: &str = "crypto-random-oracle-blsttc-g2";

/// Hashes the unique encoding of some structured data. Each data type uses a
/// distinct domain separator.
pub trait UniqueHash {
    fn unique_hash(&self) -> [u8; 32];
}

/// Computes the unique digest of a string.
///
/// The digest is the hash of the domain separator appended with the UTF-8
/// encoding of a string.
impl UniqueHash for String {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_STRING);
        hasher.process_array(self.as_bytes());
        hasher.hash()
    }
}

/// Computes the unique digest of an integer.
///
/// The digest is the hash of the domain separator appended with the big-endian
/// encoding of the byte representation of the integer.
impl UniqueHash for usize {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_INT);
        hasher.process_array(&self.to_be_bytes());
        hasher.hash()
    }
}

/// Computes the unique digest of a byte vector.
///
/// The digest is the hash of the domain separator appended with the bytes in
/// the vector.
impl UniqueHash for Vec<u8> {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_BYTE_ARRAY);
        hasher.process_array(self);
        hasher.hash()
    }
}

impl UniqueHash for Fr {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_FR);
        let buffer = self.to_bytes_be();
        hasher.process_array(&buffer);
        hasher.hash()
    }
}
// NOTE G1Affine and G1Projective both serialize the same way and use the same domain string so they will get the same hash
// this is INTENTIONAL so that we can hash in either form without needing to congert unnecessarily
impl UniqueHash for G1Affine {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_G1_BLSTTC);
        let buffer = self.to_compressed();
        hasher.process_array(&buffer);
        hasher.hash()
    }
}
impl UniqueHash for G1Projective {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_G1_BLSTTC);
        let buffer = self.to_compressed();
        hasher.process_array(&buffer);
        hasher.hash()
    }
}
// NOTE G2Affine and G2Projective both serialize the same way and use the same domain string so they will get the same hash
// this is INTENTIONAL so that we can hash in either form without needing to congert unnecessarily
impl UniqueHash for G2Affine {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_G2_BLSTTC);
        let buffer = self.to_compressed();
        hasher.process_array(&buffer);
        hasher.hash()
    }
}

impl UniqueHash for G2Projective {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_G2_BLSTTC);
        let buffer = self.to_compressed();
        hasher.process_array(&buffer);
        hasher.hash()
    }
}

/// Computes the unique digest of a qfi element.
///
/// The digest is the hash of the domain separator appended with the
impl UniqueHash for QFIBox {
    fn unique_hash(&self) -> [u8; 32] {
        let mut a_bytes = unsafe { VectorOfUchar::new() };
        let mut b_bytes = unsafe { VectorOfUchar::new() };
        let mut c_bytes = unsafe { VectorOfUchar::new() };

        let mutref_a_bytes: cpp_core::MutRef<VectorOfUchar> =
            unsafe { cpp_core::MutRef::from_raw_ref(&mut a_bytes) };
        let mutref_b_bytes: cpp_core::MutRef<VectorOfUchar> =
            unsafe { cpp_core::MutRef::from_raw_ref(&mut b_bytes) };
        let mutref_c_bytes: cpp_core::MutRef<VectorOfUchar> =
            unsafe { cpp_core::MutRef::from_raw_ref(&mut c_bytes) };

        unsafe { self.0.a().mpz_to_vector(mutref_a_bytes) };
        unsafe { self.0.b().mpz_to_vector(mutref_b_bytes) };
        unsafe { self.0.c().mpz_to_vector(mutref_c_bytes) };

        let a_bytes_rust = unsafe { cpp_vec_to_rust(mutref_a_bytes.deref()) };
        let b_bytes_rust = unsafe { cpp_vec_to_rust(mutref_b_bytes.deref()) };
        let c_bytes_rust = unsafe { cpp_vec_to_rust(mutref_c_bytes.deref()) };

        let mut hasher = new_hasher_with_domain(DOMAIN_RO_QFI);

        hasher.process_array(&a_bytes_rust);
        hasher.process_array(&b_bytes_rust);
        hasher.process_array(&c_bytes_rust);
        hasher.hash()
    }
}

/// Computes the unique digest of a public key qfi element.
///
/// The digest is the hash of the domain separator appended with the
impl UniqueHash for PublicKeyBox {
    fn unique_hash(&self) -> [u8; 32] {
        let ffi_pk = unsafe {
            bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
                cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(
                    self.0.elt(),
                )
                .as_raw_ptr(),
            )
        };
        let pk_qfi = unsafe { cpp_core::CppBox::from_raw(ffi_pk) }
            .expect("attempted to construct a null CppBox");

        let mut hasher = new_hasher_with_domain(DOMAIN_RO_PUBLIC_KEY);
        hasher.process_array(&QFIBox(pk_qfi).unique_hash());

        hasher.hash()
    }
}

/// Computes the unique digest of a qfi element.
///
/// The digest is the hash of the domain separator appended with the
impl UniqueHash for CiphertextBox {
    fn unique_hash(&self) -> [u8; 32] {
        let ffi_c1 = unsafe {
            bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
                cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(
                    self.0.c1(),
                )
                .as_raw_ptr(),
            )
        };
        let c1_qfi = unsafe { cpp_core::CppBox::from_raw(ffi_c1) }
            .expect("attempted to construct a null CppBox");

        let ffi_c2 = unsafe {
            bicycl::__ffi::ctr_bicycl_ffi_BICYCL_QFI_QFI2(
                cpp_core::CastInto::<cpp_core::Ref<bicycl::b_i_c_y_c_l::QFI>>::cast_into(
                    self.0.c2(),
                )
                .as_raw_ptr(),
            )
        };
        let c2_qfi = unsafe { cpp_core::CppBox::from_raw(ffi_c2) }
            .expect("attempted to construct a null CppBox");

        let mut hasher = new_hasher_with_domain(DOMAIN_RO_CIPHERTEXT);
        hasher.process_array(&QFIBox(c1_qfi).unique_hash());
        hasher.process_array(&QFIBox(c2_qfi).unique_hash());

        hasher.hash()
    }
}

impl UniqueHash for Box<dyn UniqueHash> {
    fn unique_hash(&self) -> [u8; 32] {
        (**self).unique_hash()
    }
}

/// Computes the unique digest of a vector.
///
/// The digest is the hash of the domain separator concatenated with the unique
/// digests of the entries in the vector.
impl<T: UniqueHash> UniqueHash for Vec<T> {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_VECTOR);
        for item in self.iter() {
            hasher.process_array(&item.unique_hash())
        }
        hasher.hash()
    }
}

/// Computes the unique digest of a vector with entries of different types.
impl UniqueHash for Vec<&dyn UniqueHash> {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_VECTOR);
        for item in self.iter() {
            hasher.process_array(&item.unique_hash())
        }
        hasher.hash()
    }
}

/// Ordered map storing the unique digests of values using unique digests as the
/// keys.
///
/// It is used to store the digests of key-value pairs of an HashableMap.
pub struct HashedMap(pub BTreeMap<[u8; 32], [u8; 32]>);

impl Default for HashedMap {
    fn default() -> Self {
        Self::new()
    }
}

impl HashedMap {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Inserts the digest of `value` using the digest of `key` as the key.
    ///
    /// If the digest of the key is not in the map, it returns None.
    /// Otherwise, it updates the hashed value and returns the old digest.
    pub fn insert_hashed<S: ToString, T: UniqueHash>(
        &mut self,
        key: S,
        value: &T,
    ) -> Option<[u8; 32]> {
        self.0
            .insert(key.to_string().unique_hash(), value.unique_hash())
    }
}

/// Computes the domain separated hash of an HashedMap.
///
/// The digest is the hash of the domain separator concatenated with the sorted
/// key-value pairs. Note: keys and values in an HashedMap are digests.
impl UniqueHash for HashedMap {
    fn unique_hash(&self) -> [u8; 32] {
        let mut hasher = new_hasher_with_domain(DOMAIN_RO_MAP);
        // This iterates over the entries of a map sorted by key.
        for (hashed_key, hashed_value) in self.0.iter() {
            hasher.process_array(hashed_key);
            hasher.process_array(hashed_value)
        }
        hasher.hash()
    }
}

/// Initializes an hasher with a DomainSeparationContext string.
fn new_hasher_with_domain(domain: &str) -> HASH256 {
    let mut state = HASH256::new();
    state.process_array(&DomainSeparationContext::new(domain).as_bytes());
    state
}

/// Computes the hash of a struct using an hash function that can be modelled as
/// a random oracle.
///
/// The digest is the hash of `domain` appended with the unique digest of
/// `data`. A distinct `domain` should be used for each purpose of the random
/// oracle.
pub fn random_oracle(domain: &str, data: &dyn UniqueHash) -> [u8; 32] {
    let mut hasher = new_hasher_with_domain(domain);
    hasher.process_array(&data.unique_hash());
    hasher.hash()
}

pub fn random_oracle_to_fr(domain: &str, data: &dyn UniqueHash) -> Fr {
    let hash = random_oracle(domain, data);
    let mut rng = &mut RAND_ChaCha20::new(hash);
    Fr::random(&mut rng)
}
pub fn random_oracle_to_g1_blsttc(domain: &str, data: &dyn UniqueHash) -> G1Projective {
    G1Projective::hash_to_curve(&data.unique_hash(), domain.as_bytes(), b"")
}
pub fn random_oracle_to_g2_blsttc(domain: &str, data: &dyn UniqueHash) -> G2Projective {
    G2Projective::hash_to_curve(&data.unique_hash(), domain.as_bytes(), b"")
}
