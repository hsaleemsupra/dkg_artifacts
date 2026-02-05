use crypto::bls12381::rng::RAND_ChaCha20;
use rand::random;
use rand::rngs::OsRng;

/// Returns static array representation of u32 in byte-array.
pub(crate) fn u32_to_u8_array(seed: u32) -> [u8; 32] {
    (0u32..8)
        .flat_map(|_| seed.to_be_bytes())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

// CRYPTO_TODO:  production vs non-production randomness for Dalek
/// Random Generator from Dalek library
pub fn rng_for_dalek() -> OsRng {
    OsRng
}

#[cfg(any(test, not(feature = "prod_rand")))]
mod non_prod_rand {
    use crate::types::impls::helpers::rand::u32_to_u8_array;
    use crypto::bls12381::rng::RAND_ChaCha20;
    use rand::RngCore;
    use std::sync::atomic::{AtomicU32, Ordering};

    static CONSTANT_SEED: AtomicU32 = AtomicU32::new(0);
    /// Generate randomness using constant seed (for testing).
    pub fn rng_from_constant_seed() -> RAND_ChaCha20 {
        // CRYPTO_TODO maybe separate "constant seed" for testing internal functions where we want replayabilitiy
        // versus "low entropy seed" when we still want each invocation to give unique seed
        let seed = CONSTANT_SEED.fetch_add(1, Ordering::Relaxed);
        let seed = u32_to_u8_array(seed);
        RAND_ChaCha20::new(seed)
    }

    #[test]
    fn check_randomness() {
        let mut rnd1 = rng_from_constant_seed();
        let mut rnd2 = rng_from_constant_seed();
        let rnd1_u32 = rnd1.next_u32();
        let rnd2_u32 = rnd2.next_u32();
        assert_ne!(rnd1_u32, rnd2_u32);
    }
}

#[cfg(not(feature = "prod_rand"))]
pub use non_prod_rand::rng_from_constant_seed as rng_from_seed;

#[cfg(feature = "prod_rand")]
/// Generate randomness with production level random seed.
pub fn rng_from_seed() -> RAND_ChaCha20 {
    let seed = random::<[u8; 32]>();
    RAND_ChaCha20::new(seed)
}
