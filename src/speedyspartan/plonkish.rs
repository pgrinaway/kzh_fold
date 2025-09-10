use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::commitment::Commitment;
use crate::polynomial::multilinear_poly::multilinear_poly::MultilinearPolynomial;
use core::marker::PhantomData;

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlonkishShape<F: PrimeField> {
    pub q_l: MultilinearPolynomial<F>,
    pub q_r: MultilinearPolynomial<F>,
    pub q_m: MultilinearPolynomial<F>,
    pub q_o: MultilinearPolynomial<F>,
    pub q_c: MultilinearPolynomial<F>,
    pub A: Vec<usize>,
    pub B: Vec<usize>,
    pub C: Vec<usize>,
    pub addr_A: Vec<MultilinearPolynomial<F>>,
    pub addr_B: Vec<MultilinearPolynomial<F>>,
    pub addr_C: Vec<MultilinearPolynomial<F>>,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlonkishWitness<F: PrimeField> {
    pub witness_data: Vec<F>,
    pub witness_polynomial: MultilinearPolynomial<F>,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlonkishCommitments<G: CurveGroup, C: Commitment<G>> {
    pub q_l: C,
    pub q_r: C,
    pub q_m: C,
    pub q_o: C,
    pub q_c: C,
    pub addr_A: Vec<C>,
    pub addr_B: Vec<C>,
    pub addr_C: Vec<C>,
    pub(crate) _marker: PhantomData<G>,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlonkishInstance<F: PrimeField, G: CurveGroup, C: Commitment<G>> {
    pub instance: Vec<F>,
    pub commitments: PlonkishCommitments<G, C>,
}
