use std::marker::PhantomData;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::{
    commitment::Commitment, constant_for_curves::ScalarField,
    polynomial::multilinear_poly::multilinear_poly::MultilinearPolynomial,
};

pub mod addr;
pub mod plonkish;

#[derive(Clone, Debug)]
pub struct FoldedObject<G: CurveGroup<ScalarField = F>, F: PrimeField + Absorb, C: Commitment<G>> {
    pub(crate) challenge: F,
    pub(crate) claim: F,
    pub(crate) random_point: Vec<F>,
    pub(crate) commitment: C,
    pub(crate) polynomial: MultilinearPolynomial<F>,
    pub(crate) _marker: PhantomData<G>,
}
