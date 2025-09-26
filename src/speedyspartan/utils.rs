use std::ops::Mul;

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;

use crate::{
    kzh_fold::generic_linear_combination,
    polynomial::{
        eq_poly::eq_poly::EqPolynomial, multilinear_poly::multilinear_poly::MultilinearPolynomial,
    },
};

pub fn combine_eq_polys<F: PrimeField + Absorb>(
    eq_polys: &[EqPolynomial<F>],
    polys: &[MultilinearPolynomial<F>],
    sigma: &F,
) -> Vec<MultilinearPolynomial<F>> {
    let eq_polys_as_mpoly: Vec<MultilinearPolynomial<F>> = eq_polys
        .iter()
        .map(|poly| MultilinearPolynomial::new(poly.evals()))
        .collect();
    let sigma_powers: Vec<F> = (0..eq_polys.len())
        .into_iter()
        .map(|idx| sigma.pow(&[idx as u64]))
        .collect();

    eq_polys
        .iter()
        .zip(polys)
        .enumerate()
        .map(|(idx, (eq, poly))| {
            let combine_fn = |poly_a, poly_b| -> F { poly_a * poly_b * sigma_powers[idx] };
            let evals = generic_linear_combination(
                &eq.evals(),
                &poly.evaluation_over_boolean_hypercube,
                combine_fn,
            );
            MultilinearPolynomial::new(evals)
        })
        .collect()
}
