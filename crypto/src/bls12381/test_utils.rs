use blsttc::group::ff::Field;
use blsttc::Fr;
use proptest::prelude::*;
use crate::bls12381::polynomial::Polynomial;
use crate::bls12381::rng::RAND_ChaCha20;

pub fn arbitrary_fr() -> impl Strategy<Value=Fr> {
    any::<[u8; 32]>()
        .prop_map(RAND_ChaCha20::new)
        .prop_map(|mut rng| Fr::random(&mut rng))
}

pub fn arbitrary_poly() -> impl Strategy<Value=Polynomial> {
    any::<([u8; 32], u8)>().prop_map(|(seed, length)| {
        let mut rng = RAND_ChaCha20::new(seed);
        Polynomial::random(length as usize, &mut rng)
    })
}

pub fn uints_to_polynomial(integer_coefficients: &[u32]) -> Polynomial {
    Polynomial {
        coefficients: integer_coefficients
            .iter()
            .cloned()
            .map(|x| Fr::from(x as u64))
            .collect(),
    }
}

/// Polynomial evaluation for small polynomials; this will overflow and panic if
/// used for large values.
pub fn evaluate_integer_polynomial(x: u32, polynomial: &[u32]) -> u32 {
    let mut ans = 0u32;
    let mut power = 1u32;
    for coefficient in polynomial {
        ans += power * coefficient;
        power *= x;
    }
    ans
}

mod test {
    use super::*;

    fn test_integer_polynomial_evaluation_is_correct(x: u32, polynomial: &[u32], y: u32) {
        assert_eq!(
            evaluate_integer_polynomial(x, polynomial),
            y,
            "Expected f({:?})={:?} for polynomial with coefficients {:?}",
            x,
            y,
            polynomial
        );
    }

    #[test]
    fn integer_polynomial_evaluation_is_correct() {
        test_integer_polynomial_evaluation_is_correct(0, &[], 0);
        test_integer_polynomial_evaluation_is_correct(1, &[], 0);
        test_integer_polynomial_evaluation_is_correct(0, &[0, 1, 2], 0);
        test_integer_polynomial_evaluation_is_correct(1, &[0, 1, 2], 3);
        test_integer_polynomial_evaluation_is_correct(2, &[0, 1, 2], 10);
        test_integer_polynomial_evaluation_is_correct(0, &[1, 3, 5], 1);
    }
}
