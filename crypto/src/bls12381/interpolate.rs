use blsttc::group::ff::Field;
use blsttc::{Fr, G1Projective, G2Projective};
use blsttc::group::Group;

/// Interpolation failed because of duplicate x-coordinates.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InterpolationError {
    DuplicateX,
    InsufficientPoints
}

fn contains_duplicates(scalars: &[Fr]) -> bool {
    let mut set = std::collections::HashSet::new();

    for scalar in scalars {
        if !set.insert(scalar.to_bytes_be()) {
            return true;
        }
    }
    false
}

/// Yields the polynomial-evaluation point `x` given the `index` of the
/// corresponding share.
///
/// The polynomial `f(x)` is computed at a value `x` for every share of a
/// threshold key. Shares are ordered and numbered `0...N`.
pub fn x_for_index(index: u32) -> Fr {
    // It is important that this is never zero and that values are unique.
    Fr::from(index as u64 + 1)
}

/// Compute the Lagrange coefficients at x=0.
///
/// # Arguments
/// * `samples` is a list of values x_0, x_1, ...x_n.
/// # Result
/// * `[lagrange_0, lagrange_1, ..., lagrange_n]` where:
///    * lagrange_i = numerator_i/denominator_i
///    * numerator_i = x_0 * x_1 * ... * x_(i-1) * x_(i+1) * ... * x_n
///    * denominator_i = (x_0 - x_i) * (x_1 - x_i) * ... * (x_(i-1) - x_i) *
///      (x_(i+1) - x_i) * ... * (x_n - x_i)
/// # Errors
/// `ThresholdSignatureError::DuplicateX`: in case the interpolation points `samples` are not all distinct.
pub fn lagrange_coefficients_at_zero(samples: &[Fr]) -> Result<Vec<Fr>, InterpolationError> {
    let len = samples.len();
    if len == 0 {
        return Ok(Vec::new());
    }
    if len == 1 {
        return Ok(vec![Fr::one()]);
    }

    if contains_duplicates(samples) {
        return Err(InterpolationError::DuplicateX);
    }

    // The j'th numerator is the product of all `x_prod[i]` for `i!=j`.
    // Note: The usual subtractions can be omitted as we are computing the Lagrange
    // coefficient at zero.
    let mut x_prod: Vec<Fr> = Vec::with_capacity(len);
    let mut tmp = Fr::one();
    x_prod.push(tmp);
    for x in samples.iter().take(len - 1) {
        tmp *= x;
        x_prod.push(tmp);
    }
    tmp = Fr::one();
    for (i, x) in samples[1..].iter().enumerate().rev() {
        tmp *= x;
        x_prod[i] *= tmp;
    }

    for (i, (lagrange_0, x_i)) in x_prod.iter_mut().zip(samples).enumerate() {
        // Compute the value at 0 of the Lagrange polynomial that is `0` at the other
        // data points but `1` at `x`.
        let mut denom = Fr::one();
        for (_, x_j) in samples.iter().enumerate().filter(|(j, _)| *j != i) {
            let diff = x_j - x_i;
            denom *= diff;
        }

        if let Some(inv) = denom.invert().into_option() {
            *lagrange_0 *= inv;
        } else {
            return Err(InterpolationError::DuplicateX);
        }
    }
    Ok(x_prod)
}

/// Compute the Lagrange coefficients at a specific point `x`.
fn lagrange_coefficients_at_point(xs: &[Fr], x: &Fr) -> Result<Vec<Fr>, InterpolationError> {
    let k = xs.len();
    let mut coeffs = Vec::with_capacity(k);

    for i in 0..k {
        let mut num = Fr::one(); // Numerator
        let mut denom = Fr::one(); // Denominator

        for j in 0..k {
            if i != j {
                let x_j = &xs[j];
                let x_i = &xs[i];

                // Compute (x - x_j)
                let num_term = x - x_j;
                num *= num_term;

                // Compute (x_i - x_j)
                let denom_term = x_i - x_j;
                denom *= &denom_term;
            }
        }

        // Compute lambda_i = num / denom
        if let Some(denom_inv) = denom.invert().into_option() {
            num *= &denom_inv;
            coeffs.push(num);
        } else {
            return Err(InterpolationError::DuplicateX);
        }
    }

    Ok(coeffs)
}

/// Given a list of samples `(x, f(x) * g)` for a polynomial `f` in the scalar field, and a generator g of G1 returns
/// `f(0) * g`.
/// See: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach
/// # Arguments:
/// * `samples` contains the list of `(x, y)` points to be used in the interpolation, where `x` is an element in the scalar field, and the `y` is an element of G1.
/// # Returns
/// The generator `g` of G1 multiplied by to the constant term of the interpolated polynomial `f(x)`. If `samples` contains multiple entries for the same scalar `x`, only the first sample contributes toward the interpolation and the subsequent entries are discarded.
pub fn interpolate_g1(samples: &[(Fr, G1Projective)]) -> Result<G1Projective, InterpolationError> {
    let all_x: Vec<_> = samples.iter().map(|(x, _)| *x).collect();
    let coefficients = lagrange_coefficients_at_zero(&all_x)?;
    let mut result = G1Projective::identity();
    for (coefficient, sample) in coefficients.iter().zip(samples.iter().map(|(_, y)| y)) {
        result += sample * coefficient;
    }
    Ok(result)
}

pub fn interpolate_g1_at_x(samples: &[(Fr, G1Projective)], x: &Fr) -> Result<G1Projective, InterpolationError> {

    let xs: Vec<_> = samples.iter().map(|(x, _)| *x).collect();
    // Compute Lagrange coefficients at point x
    let lagrange_coeffs = lagrange_coefficients_at_point(&xs, x)?;

    // Interpolate in the exponent to compute g^{f(x)}
    let mut result = G1Projective::identity();
    for (lambda_i, eval_i) in lagrange_coeffs.iter().zip(samples.iter().map(|(_, y)| y)) {
        let term = eval_i * lambda_i;
        result += term;
    }
    Ok(result)
}

/// Given a list of samples `(x, f(x) * g)` for a polynomial `f` in the scalar field, and a generator g of G2 returns
/// `f(0) * g`.
/// See: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach
/// # Arguments:
/// * `samples` contains the list of `(x, y)` points to be used in the interpolation, where `x` is an element in the scalar field, and the `y` is an element of G2.
/// # Returns
/// The generator `g` of G2 multiplied by to the constant term of the interpolated polynomial `f(x)`, i.e. `f(0)`. If `samples` contains multiple entries for the same scalar `x`, only the first sample contributes toward the interpolation and the subsequent entries are discarded.
pub fn interpolate_g2(samples: &[(Fr, G2Projective)]) -> Result<G2Projective, InterpolationError> {
    let all_x: Vec<_> = samples.iter().map(|(x, _)| *x).collect();
    let coefficients = lagrange_coefficients_at_zero(&all_x)?;
    let mut result = G2Projective::identity();
    for (coefficient, sample) in coefficients.iter().zip(samples.iter().map(|(_, y)| y)) {
        result += sample * coefficient;
    }
    Ok(result)
}

#[cfg(test)]
mod test {
    use crate::bls12381::polynomial::Polynomial;
    use crate::bls12381::test_utils::evaluate_integer_polynomial;
    use super::*;
    use blsttc::IntoFr;
    use crate::bls12381::rng::RAND_ChaCha20;

    /// Verify that x_for_index(i) == i+1 (in the field).
    #[test]
    fn x_for_index_is_correct() {
        // First N values:
        let mut x = Fr::one();
        for i in 0..100 {
            assert!(x_for_index(i) == x);
            x += Fr::one();
        }
        // Binary 0, 1, 11, 111, ... all the way up to the maximum NodeIndex.
        // The corresponding x values are binary 1, 10, 100, ... and the last value is
        // one greater than the maximum NodeIndex.
        let mut x = Fr::one();
        let mut i = 0;
        loop {
            assert!(x_for_index(i) == x);
            if i == u32::MAX {
                break;
            }
            i = i * 2 + 1;
            x += x;
        }
    }

    fn uint_to_g2(num: u32) -> G2Projective {
        G2Projective::generator() * Fr::from(num as u64)
    }

    fn uint_to_g1(num: u32) -> G1Projective {
        G1Projective::generator() * Fr::from(num as u64)
    }

    #[test]
    fn test_lagrange_coefficients_are_correct() {
        let x_values = [1, 3, 4, 7];
        let x_values_as_fr: Vec<_> = x_values.iter().map(|x| Fr::from(*x)).collect();
        let lagrange_coefficients: Vec<_> = {
            // The lagrange coefficient numerators and denominators:
            // need to cast as i64 to compile
            let as_integers: [(i32, i32); 4] = [
                (3 * 4 * 7, (3 - 1) * (4 - 1) * (7 - 1)),
                (1 * 4 * 7, (1 - 3) * (4 - 3) * (7 - 3)),
                (1 * 3 * 7, (1 - 4) * (3 - 4) * (7 - 4)),
                (1 * 3 * 4, (1 - 7) * (3 - 7) * (4 - 7)),
            ];
            let as_fr: Vec<_> = as_integers
                .iter()
                .map(|(numerator, denominator)| {
                    (numerator.into_fr(), denominator.into_fr())
                })
                .collect();
            let divided: Vec<_> = as_fr
                .iter()
                .map(|(numerator, denominator)| {
                    let mut ans: Fr = numerator.clone();
                    let inv = denominator.invert().expect("No inverse");
                    ans *= inv;
                    ans
                })
                .collect();
            divided
        };
        let observed = lagrange_coefficients_at_zero(&x_values_as_fr)
            .expect("Cannot fail because all the x values are distinct");

        lagrange_coefficients.iter()
            .zip(observed)
            .for_each(|(x, y)| {
                assert!(*x == y);
            });
    }

    #[test]
    fn test_lagrange_coefficients_at_zero_rejects_duplicate_points() {
        let seed = [4u8; 32];
        let mut rng = &mut RAND_ChaCha20::new(seed);

        for num_coefficients in 1..50 {
            let mut inputs = vec![];

            let dup_r = Fr::random(&mut rng);

            inputs.push(dup_r);

            for _i in 0..=num_coefficients {
                let r = Fr::random(&mut rng);
                inputs.push(r);
            }
            inputs.push(dup_r);

            assert!(lagrange_coefficients_at_zero(&inputs).is_err());
            assert!(lagrange_coefficients_at_zero(&inputs[1..]).is_ok());
        }
    }

    #[test]
    fn test_interpolation_is_resilient_to_duplicate_points() {
        let seed = [4u8; 32];
        let mut rng = &mut RAND_ChaCha20::new(seed);

        for num_coefficients in 1..50 {
            let poly = Polynomial::random(num_coefficients, &mut rng);

            let mut samples = vec![];

            let dup_r = Fr::random(&mut rng);
            let dup_p_r = poly.evaluate_at(&dup_r);

            for _i in 0..=num_coefficients {
                samples.push((dup_r, dup_p_r));
            }

            for _i in 0..=num_coefficients {
                let r = Fr::random(&mut rng);
                let p_r = poly.evaluate_at(&r);
                samples.push((r, p_r));
                samples.push((dup_r, dup_p_r));
            }

            let interp = Polynomial::interpolate(&samples);

            assert_eq!(poly, interp);
        }
    }


    #[test]
    fn test_public_interpolation_is_correct() {
        let polynomial = [2, 4, 9];
        let x_5 = (
            Fr::from(5),
            uint_to_g2(evaluate_integer_polynomial(5, &polynomial)),
        );
        let x_3 = (
            Fr::from(3),
            uint_to_g2(evaluate_integer_polynomial(3, &polynomial)),
        );
        let x_8 = (
            Fr::from(8),
            uint_to_g2(evaluate_integer_polynomial(8, &polynomial)),
        );

        let random_points = [x_5, x_3, x_8];
        let interpolated_polynomial_at_0 = interpolate_g2(&random_points).expect("Failed to interpolate");
        assert!(interpolated_polynomial_at_0.eq(&uint_to_g2(2)));
    }

    #[test]
    fn test_g1_interpolation_is_correct() {
        let polynomial = [2, 4, 9];
        let x_5 = (
            Fr::from(5),
            uint_to_g1(evaluate_integer_polynomial(5, &polynomial)),
        );
        let x_3 = (
            Fr::from(3),
            uint_to_g1(evaluate_integer_polynomial(3, &polynomial)),
        );
        let x_8 = (
            Fr::from(8),
            uint_to_g1(evaluate_integer_polynomial(8, &polynomial)),
        );

        let random_points = [x_5, x_3, x_8];
        let interpolated_polynomial_at_0 = interpolate_g1(&random_points).expect("Failed to interpolate");
        assert!(interpolated_polynomial_at_0.eq(&uint_to_g1(2)));
    }
}