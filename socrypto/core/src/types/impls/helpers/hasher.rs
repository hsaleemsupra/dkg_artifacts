use sha3::Digest;
use std::ops::{Deref, DerefMut};

/// Helper interface for common crypto hasher types allowing chained operations
pub struct HasherBuilder<Hasher: Digest>(Hasher);
impl<Hasher: Digest> HasherBuilder<Hasher> {
    /// Returns hasher with already prefixed POP identity domain info.
    pub fn get_hasher() -> Self {
        Self(Hasher::new())
    }

    /// Appends data to hasher.
    pub fn append<T: AsRef<[u8]>>(mut self, prefix: &T) -> Self {
        self.0.update(prefix);
        self
    }

    /// Calculates the hash and returns 32 bytes version of it.
    pub fn hash(self) -> [u8; 32] {
        let mut hash = [0; 32];
        hash.copy_from_slice(&self.0.finalize()[0..32]);
        hash
    }
}

impl<Hasher: Digest> Deref for HasherBuilder<Hasher> {
    type Target = Hasher;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Hasher: Digest> DerefMut for HasherBuilder<Hasher> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Returns hasher builder with prefixed message
pub fn get_hasher_with_prefix<Hasher: Digest, T: AsRef<[u8]>>(prefix: &T) -> HasherBuilder<Hasher> {
    HasherBuilder::<Hasher>::get_hasher().append(prefix)
}

#[cfg(test)]
mod tests {
    use crate::types::impls::helpers::hasher::{get_hasher_with_prefix, HasherBuilder};
    use sha3::Sha3_256;

    #[test]
    fn check_prefixed_api() {
        let msg = b"test";
        let hash_32_prefixed = get_hasher_with_prefix::<Sha3_256, _>(msg).hash();
        let hash_32 = HasherBuilder::<Sha3_256>::get_hasher().append(msg).hash();
        assert_eq!(hash_32, hash_32_prefixed);

        let msg2 = b"with extra data";
        let hash_32_prefixed = get_hasher_with_prefix::<Sha3_256, _>(msg)
            .append(msg2)
            .hash();
        let hash_32 = HasherBuilder::<Sha3_256>::get_hasher()
            .append(msg)
            .append(msg2)
            .hash();
        assert_eq!(hash_32, hash_32_prefixed);
    }
}
