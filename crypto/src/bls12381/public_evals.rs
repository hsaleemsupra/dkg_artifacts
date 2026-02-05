use std::borrow::Borrow;
use std::ops;
use blsttc::{group::{ff::Field, Group}, poly::Poly, Fr, G1Projective};
use rand::Rng;
use crate::bls12381::rng::RAND_ChaCha20;
use crate::dealing::DkgConfig;
use rayon::prelude::*;

/// Given a polynomial with secret evaluations <a0, ..., an> at points <0,1,2,..,n> the public
/// evaluations are the public points <A0, ..., An> corresponding to those secret evaluations.
#[derive(Clone, Debug)]
pub struct PublicEvals {
    pub g: G1Projective,
    pub evals: Vec<G1Projective>,
}

impl PartialEq<Self> for PublicEvals {
    fn eq(&self, other: &Self) -> bool {
        if !self.g.eq(&other.g) {
            return false;
        }
        if self.evals.len() != other.evals.len() {
            return false;
        }
        self.evals.iter()
            .zip(&other.evals)
            .all(|(x, y)| {
                x.eq(y)
            })
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl<B: Borrow<PublicEvals>> ops::AddAssign<B> for PublicEvals {
    fn add_assign(&mut self, rhs: B) {
        assert!(self.g.eq(&rhs.borrow().g));
        let len = self.evals.len();
        let rhs_len = rhs.borrow().evals.len();
        assert!(rhs_len == len);
        for (self_c, rhs_c) in self.evals.iter_mut().zip(&rhs.borrow().evals) {
            *self_c += rhs_c;
        }
    }
}

impl<B: Borrow<PublicEvals>> ops::Add<B> for PublicEvals {
    type Output = Self;

    fn add(mut self, rhs: B) -> Self {
        self += rhs;
        self
    }
}

impl PublicEvals {
    pub fn from_evals(evals: &Vec<Fr>, g: &G1Projective) -> Self {
        PublicEvals {
            g: g.clone(),
            evals: evals
                .iter()
                .map(|x| (g * x).into())
                .collect(),
        }
    }

    pub fn from_evals_parallelized(evals: &Vec<Fr>, g: &G1Projective) -> Self {
        PublicEvals {
            g: g.clone(),
            evals: evals
                .par_iter()
                .map(|x| (g * x).into())
                .collect(),
        }
    }

    pub fn perform_low_degree_test(&self, config: DkgConfig) -> bool{
        let evals = self.evals[1..].to_vec().clone();
        if config.t == config.n{
            return true;
        }

        let n = config.n as usize;
        let degree = (config.t - 1) as usize;

        // Generate the dual code word
        let vf = PublicEvals::get_dual_codeword(degree, n);

        // Ensure lengths match
        if evals.len() != vf.len() {
            return false;
        }

        // Compute the inner product
        let ip = G1Projective::multi_exp(evals.as_slice(), vf.as_slice());

        // Check if the inner product is the identity element
        ip.is_identity().into()
    }

    pub fn perform_low_degree_test_with_precomputation(&self, config: DkgConfig, dual_codeword: &Vec<Fr>) -> bool{
        let evals = self.evals[1..].to_vec().clone();
        if config.t == config.n{
            return true;
        }

        let vf = dual_codeword.clone();

        // Ensure lengths match
        if evals.len() != vf.len() {
            return false;
        }

        // Compute the inner product
        let ip = G1Projective::multi_exp(evals.as_slice(), vf.as_slice());

        // Check if the inner product is the identity element
        ip.is_identity().into()
    }

    pub fn get_dual_codeword(degree: usize, n: usize) -> Vec<Fr> {

        let dual_degree = n - degree - 2;

        let seed = rand::thread_rng().gen::<[u8; 32]>();
        let rng = &mut RAND_ChaCha20::new(seed);
        let f_poly = Poly::random(dual_degree, rng);

        let evaluations: Vec<Fr> = (0..n)
            .map(|i| f_poly.evaluate(i as u64))
            .collect();

        let denominators = PublicEvals::all_lagrange_denominators(n);

        let vf: Vec<Fr> = evaluations
            .iter()
            .zip(denominators.iter())
            .map(|(f_i, denom_i)| {
                let denom_inv = denom_i.invert().unwrap_or(Fr::zero());
                f_i * denom_inv
            })
            .collect();

        vf
    }

    fn all_lagrange_denominators(n: usize) -> Vec<Fr> {

        let mut denominators = Vec::with_capacity(n);
        for i in 0..n {
            let mut denom = Fr::one();
            let x_i = Fr::from(i as u64);

            for j in 0..n {
                if i != j {
                    let x_j = Fr::from(j as u64);
                    let diff = x_i - x_j;
                    denom *= diff
                }
            }

            denominators.push(denom);
        }

        denominators
    }
}

#[cfg(test)]
mod tests {
    use crate::bls12381::polynomial::Polynomial;
    use crate::dealing::DkgConfig;
    use super::*;
    #[test]
    fn test_low_deg_test() {
        // Setup
        let g = G1Projective::generator();
        let config = DkgConfig { n: 5, t: 3 };

        // Create a random polynomial of degree t - 1 (degree 2)
        let seed = rand::thread_rng().gen::<[u8; 32]>();
        let rng = &mut RAND_ChaCha20::new(seed);

        let poly = Polynomial::random(config.t as usize, rng);
        let evals: Vec<Fr> = (0..config.n+1)
            .map(|i| poly.evaluate_at(&Fr::from(i as u64)))
            .collect();

        let public_evals = PublicEvals::from_evals(&evals, &g);

        // Test
        assert!(public_evals.perform_low_degree_test(config.clone()));

        // Now create a polynomial of higher degree
        let poly_high_deg = Polynomial::random((config.t + 1) as usize, rng);
        let evals_high_deg: Vec<Fr> = (0..config.n)
            .map(|i| poly_high_deg.evaluate_at(&Fr::from(i as u64)))
            .collect();

        let public_evals_high_deg = PublicEvals::from_evals(&evals_high_deg, &g);

        // Test
        assert!(!public_evals_high_deg.perform_low_degree_test(config));
    }
}
