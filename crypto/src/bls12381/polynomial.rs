use std::borrow::Borrow;
use std::{iter, ops};
use std::fmt::{Debug};
use blsttc::group::ff::Field;
use blsttc::Fr;
use rand::RngCore;

/// A univariate polynomial
/// Note: The polynomial terms are: coefficients[i] * x^i
///       E.g. 3 + 2x + x^2 - x^4 is encoded as:
///       Polynomial{ coefficients: [3,2,1,0,-1] }
#[derive(Clone, Debug)]
pub struct Polynomial {
    pub coefficients: Vec<Fr>,
}

impl PartialEq<Self> for Polynomial {
    fn eq(&self, other: &Self) -> bool {
        if self.coefficients.len() != other.coefficients.len() {
            return false;
        }
        self.coefficients.iter()
            .zip(&other.coefficients)
            .all(|(x, y)| {
                x == y
            })
    }
}

/// Creates a new `Polynomial` instance from a vector of prime field elements
/// representing the coefficients of the polynomial.
impl From<Vec<Fr>> for Polynomial {
    fn from(coefficients: Vec<Fr>) -> Self {
        let mut ans = Polynomial { coefficients };
        ans.remove_zeros();
        ans
    }
}

impl<B: Borrow<Polynomial>> ops::Add<B> for Polynomial {
    type Output = Polynomial;

    fn add(mut self, rhs: B) -> Polynomial {
        self += rhs;
        self
    }
}

impl<B: Borrow<Polynomial>> ops::AddAssign<B> for Polynomial {
    fn add_assign(&mut self, rhs: B) {
        let len = self.coefficients.len();
        let rhs_len = rhs.borrow().coefficients.len();
        if rhs_len > len {
            self.coefficients.resize(rhs_len, Fr::zero());
        }
        for (self_c, rhs_c) in self.coefficients.iter_mut().zip(&rhs.borrow().coefficients) {
            *self_c += rhs_c;
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Polynomial>> ops::Mul<B> for &'a Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: B) -> Self::Output {
        let rhs = rhs.borrow();
        if rhs.is_zero() || self.is_zero() {
            return Polynomial::zero();
        }
        let n_coeffs = self.coefficients.len() + rhs.coefficients.len() - 1;
        let mut coeffs = vec![Fr::zero(); n_coeffs];
        for (i, ca) in self.coefficients.iter().enumerate() {
            for (j, cb) in rhs.coefficients.iter().enumerate() {
                let tmp = ca * cb;
                coeffs[i + j] += tmp;
            }
        }
        Polynomial::from(coeffs)
    }
}

impl<B: Borrow<Polynomial>> ops::Mul<B> for Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: B) -> Self::Output {
        &self * rhs
    }
}

impl<B: Borrow<Self>> ops::MulAssign<B> for Polynomial {
    fn mul_assign(&mut self, rhs: B) {
        *self = &*self * rhs;
    }
}

impl ops::MulAssign<Fr> for Polynomial {
    fn mul_assign(&mut self, rhs: Fr) {
        if rhs.is_zero().into() {
            // self.zeroize();
            self.coefficients.clear();
        } else {
            for c in &mut self.coefficients {
                *c *= rhs;
            }
        }
    }
}

impl<'a> ops::Mul<&'a Fr> for Polynomial {
    type Output = Polynomial;

    fn mul(mut self, rhs: &Fr) -> Self::Output {
        if rhs.is_zero().into() {
            // self.zeroize();
            self.coefficients.clear();
        } else {
            self.coefficients.iter_mut()
                .for_each(|c| {
                    *c *= rhs;
                });
        }
        self
    }
}

impl ops::Mul<Fr> for Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: Fr) -> Self::Output {
        let rhs = &rhs;
        self * rhs
    }
}

impl<'a> ops::Mul<Fr> for &'a Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: Fr) -> Self::Output {
        (*self).clone() * rhs
    }
}

impl Polynomial {
    /// Returns the polynomial with constant value `0`.
    pub fn zero() -> Self {
        Polynomial {
            coefficients: vec![],
        }
    }

    /// Creates a random polynomial.
    // FUNCTIONAL CHANGE, RngCore instead of RAND
    pub fn random(number_of_coefficients: usize, rng: &mut impl RngCore) -> Self {
        let coefficients: Vec<_> = iter::repeat(())
            .map(|()| Fr::random(&mut *rng))
            .take(number_of_coefficients)
            .collect();
        Polynomial::from(coefficients)
    }

    pub fn constant(c: Fr) -> Self {
        Polynomial::from(vec![c])
    }

    /// Remove trailing zeros; this should be applied by internal constructors
    /// to get the canonical representation of each polynomial.
    pub fn remove_zeros(&mut self) {
        let zeros = self
            .coefficients
            .iter()
            .rev()
            .take_while(|c| c.is_zero().into())
            .count();
        let len = self.coefficients.len() - zeros;
        self.coefficients.truncate(len)
    }

    /// Returns `true` if the polynomial is the constant value `0`.
    pub fn is_zero(&self) -> bool {
        self.coefficients
            .iter()
            .all(|coefficient| coefficient.is_zero().into())
    }

    /// Evaluate the polynomial at x
    /// Note: This uses Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
    pub fn evaluate_at(&self, x: &Fr) -> Fr {
        let mut coefficients = self.coefficients.iter().rev();
        let first = coefficients.next();
        match first {
            None => Fr::zero(), // David: in MIRACL, a new Fr is initialized as zero.
            Some(ans) => {
                let mut ans: Fr = ans.clone();
                for coeff in coefficients {
                    ans *= x;
                    ans += coeff;
                }
                ans
            }
        }
    }

    pub fn interpolate(samples: &[(Fr, Fr)]) -> Self {
        if samples.is_empty() {
            return Polynomial::zero();
        }
        // Interpolates on the first `i` samples.
        let mut poly = Polynomial::constant(samples[0].1);

        let minus_s0 = -samples[0].0;
        // Is zero on the first `i` samples.
        let mut base = Polynomial::from(vec![minus_s0, Fr::one()]);

        // We update `base` so that it is always zero on all previous samples, and
        // `poly` so that it has the correct values on the previous samples.
        for (ref x, ref y) in &samples[1..] {
            // Scale `base` so that its value at `x` is the difference between `y` and
            // `poly`'s current value at `x`: Adding it to `poly` will then make
            // it correct for `x`.
            let mut diff = y - poly.evaluate_at(x);
            let inv = base.evaluate_at(x).invert().into_option();

            if inv.is_some() {
                let base_inv = inv.unwrap();
                diff *= base_inv;
                base *= diff;
                poly += &base;

                // Finally, multiply `base` by X - x, so that it is zero at `x`, too, now.
                let minus_x = -x;
                base *= Polynomial::from(vec![minus_x, Fr::one()]);
            }
        }
        poly
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;
    use blsttc::Fr;
    use crate::bls12381::test_utils::{arbitrary_fr, arbitrary_poly, evaluate_integer_polynomial, uints_to_polynomial};
    use super::*;

    struct AdditionTestVector {
        value: Vec<u32>,
        addend: Vec<u32>,
        sum: Vec<u32>,
        name: String,
    }

    fn addition_test_vectors() -> Vec<AdditionTestVector> {
        vec![
            AdditionTestVector {
                value: vec![],
                addend: vec![],
                sum: vec![],
                name: "Empty vector summation".to_string(),
            },
            AdditionTestVector {
                value: vec![1],
                addend: vec![],
                sum: vec![1],
                name: "Adding the identity".to_string(),
            },
            AdditionTestVector {
                value: vec![],
                addend: vec![2],
                sum: vec![2],
                name: "Adding to the identity".to_string(),
            },
            AdditionTestVector {
                value: vec![1, 2, 3],
                addend: vec![4, 5, 6],
                sum: vec![5, 7, 9],
                name: "Adding a polynomial of the same order".to_string(),
            },
            AdditionTestVector {
                value: vec![1, 2],
                addend: vec![4, 5, 6],
                sum: vec![5, 7, 6],
                name: "Adding a polynomial of greater order".to_string(),
            },
            AdditionTestVector {
                value: vec![1, 2, 3],
                addend: vec![4, 5],
                sum: vec![5, 7, 3],
                name: "Adding a polynomial of lesser order".to_string(),
            },
        ]
    }

    #[test]
    fn test_polynomial_add() {
        for test_vector in addition_test_vectors() {
            let value =
                uints_to_polynomial(&test_vector.value) + &uints_to_polynomial(&test_vector.addend);
            let expected = uints_to_polynomial(&test_vector.sum);
            assert_eq!(expected, value, "Test vector failed: {}", test_vector.name);
        }
    }

    struct MultiplicationTestVector {
        value: Vec<u32>,
        factor: Vec<u32>,
        product: Vec<u32>,
        name: String,
    }

    fn multiplication_test_vectors() -> Vec<MultiplicationTestVector> {
        vec![
            MultiplicationTestVector {
                value: vec![],
                factor: vec![],
                product: vec![],
                name: "Empty vector multiplication".to_string(),
            },
            MultiplicationTestVector {
                value: vec![1],
                factor: vec![],
                product: vec![],
                name: "Right multiply by zero".to_string(),
            },
            MultiplicationTestVector {
                value: vec![],
                factor: vec![2],
                product: vec![],
                name: "Left multiply by zero".to_string(),
            },
            MultiplicationTestVector {
                value: vec![1],
                factor: vec![1, 3, 6],
                product: vec![1, 3, 6],
                name: "Left multiply by one".to_string(),
            },
            MultiplicationTestVector {
                value: vec![4, 8, 1],
                factor: vec![1],
                product: vec![4, 8, 1],
                name: "Right multiply by one".to_string(),
            },
            MultiplicationTestVector {
                value: vec![1, 1],
                factor: vec![2, 4, 5],
                product: vec![2, 6, 9, 5],
                name: "Normal mutiplication".to_string(),
            },
        ]
    }

    #[test]
    fn test_polynomial_multiplication() {
        for test_vector in multiplication_test_vectors() {
            let value =
                uints_to_polynomial(&test_vector.value) * uints_to_polynomial(&test_vector.factor);
            let expected = uints_to_polynomial(&test_vector.product);
            assert_eq!(expected, value, "Test vector failed: {}", test_vector.name);
        }
    }

    fn constant_multiplication_test_vectors() -> Vec<(Vec<u32>, u32, Vec<u32>, String)> {
        vec![
            (vec![], 0, vec![], "All zero".to_string()),
            (vec![], 9, vec![], "Empty vector".to_string()),
            (vec![1, 2, 4], 0, vec![], "Factor zero".to_string()),
            (
                vec![1, 0, 9],
                3,
                vec![3, 0, 27],
                "Normal factor".to_string(),
            ),
        ]
    }

    #[test]
    fn test_constant_multiplication() {
        for (int_value, int_factor, combined_int, test_vector_name) in
        constant_multiplication_test_vectors()
        {
            let value = &uints_to_polynomial(&int_value) * Fr::from(int_factor as u64);
            let expected = uints_to_polynomial(&combined_int);
            assert_eq!(expected, value, "Test vector failed: {}", test_vector_name);
        }
    }

    /// Given a polynomial, verify that keys are generated correctly
    fn test_key_is_correct(x: u32, integer_coefficients: &[u32]) {
        let polynomial = uints_to_polynomial(integer_coefficients);
        let secret_key = polynomial.evaluate_at(&Fr::from(x as u64));
        let y = evaluate_integer_polynomial(x, integer_coefficients);
        assert!(secret_key == Fr::from(y as u64));
    }

    #[test]
    fn key_is_correct() {
        test_key_is_correct(3, &[1, 2, 3, 4, 5]);
        test_key_is_correct(9, &[5, 0, 7, 11]);
        test_key_is_correct(9, &[]);
    }

    #[test]
    fn test_polynomial_summation_is_correct() {
        assert_eq!(
            uints_to_polynomial(&[1, 3, 5]) + uints_to_polynomial(&[10, 20, 30]),
            uints_to_polynomial(&[11, 23, 35])
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 4,
            .. ProptestConfig::default()
        })]

        // Shamir's Secret Sharing Scheme
        #[test]
        fn shamir_secret_sharing_scheme(
            secret in arbitrary_fr(),
            mut poly in arbitrary_poly()
               .prop_filter("poly must have at least one coefficient", |p| !p.coefficients.is_empty()),
            shareholders in proptest::collection::vec(arbitrary_fr(), 1..300)
        ) {
            poly.coefficients[0] = secret;
            let shares: Vec<(Fr,Fr)> = shareholders.iter().map(|x| (*x, poly.evaluate_at(x))).collect();
            if shares.len() >= poly.coefficients.len() {
                assert!(Polynomial::interpolate(&shares[0..poly.coefficients.len()]).coefficients[0] == secret);
            } else {
                assert!(Polynomial::interpolate(&shares).coefficients[0] != secret);
            }
        }
    }
}