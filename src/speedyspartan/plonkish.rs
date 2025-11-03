use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::commitment::Commitment;
use crate::polynomial::multilinear_poly::multilinear_poly::MultilinearPolynomial;
use crate::speedyspartan::utils::vec_to_mle;
use crate::transcript::transcript::Transcript;
use core::marker::PhantomData;
use std::ops::Mul;
pub const ADDR_DIM: usize = 3;

#[derive(Clone, Debug)]
pub struct PlonkishZs<F: PrimeField> {
    pub z: Vec<F>,
    pub z_a: Vec<F>,
    pub z_b: Vec<F>,
    pub z_c: Vec<F>,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlonkishShape<F: PrimeField + Absorb> {
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

impl<F: PrimeField + Absorb> PlonkishShape<F> {
    pub fn new(
        q_l: MultilinearPolynomial<F>,
        q_r: MultilinearPolynomial<F>,
        q_m: MultilinearPolynomial<F>,
        q_o: MultilinearPolynomial<F>,
        q_c: MultilinearPolynomial<F>,
        A: Vec<usize>,
        B: Vec<usize>,
        C: Vec<usize>,
    ) -> Self {
        let addr_A = Self::one_hot_addr_mles(&A, ADDR_DIM);
        let addr_B = Self::one_hot_addr_mles(&B, ADDR_DIM);
        let addr_C = Self::one_hot_addr_mles(&C, ADDR_DIM);
        Self {
            q_l,
            q_r,
            q_m,
            q_o,
            q_c,
            A,
            B,
            C,
            addr_A,
            addr_B,
            addr_C,
        }
    }

    pub fn z<G, C>(
        &self,
        witness: &PlonkishWitness<F>,
        instance: &PlonkishInstance<F, G, C>,
    ) -> PlonkishZs<F>
    where
        G: CurveGroup<ScalarField = F>,
        C: Commitment<G>,
    {
        let z_vec: Vec<F> = [
            witness.witness_data.as_slice(),
            instance.instance.as_slice(),
        ]
        .concat();

        let z_a: Vec<F> = self.A.iter().map(|index| z_vec[*index]).collect();
        let z_b: Vec<F> = self.B.iter().map(|index| z_vec[*index]).collect();
        let z_c: Vec<F> = self.C.iter().map(|index| z_vec[*index]).collect();

        PlonkishZs {
            z: z_vec,
            z_a,
            z_b,
            z_c,
        }
    }

    /// Return `addr_dim` multilinear‐polynomials that are the d-dimensional
    /// one-hot encoding of the `indices` vector.
    ///
    /// Each address `idx` (< K) is split into `addr_dim` base-N “digits” where  
    /// N = next_pow2(root_ceil(K, d)).  
    /// For dimension `i` we build a length `rows_pow2 * N` vector that is 1 at  
    /// position `row * N + digit_i` and 0 elsewhere, then extend it multilinearly.
    fn one_hot_addr_mles(indices: &[usize], addr_dim: usize) -> Vec<MultilinearPolynomial<F>> {
        assert!(addr_dim > 0 && !indices.is_empty());

        // ---------- choose a power-of-two base N so that N^d ≥ K ----------
        let k = *indices.iter().max().unwrap_or(&0) + 1;
        let mut n = 1usize;
        while n.pow(addr_dim as u32) < k {
            n <<= 1; // multiply by 2 until condition holds
        }

        // ---------- allocate zero-filled vectors, padded to a power of two ----------
        let rows_pow2 = indices.len().next_power_of_two();
        let vec_len = rows_pow2 * n; // = 2^{⌈log T⌉+⌈log N⌉}
        let mut per_dim = vec![vec![F::ZERO; vec_len]; addr_dim];

        // ---------- populate the one-hot entries ----------
        for (row, &idx) in indices.iter().enumerate() {
            let mut rem = idx;
            for dim in 0..addr_dim {
                let digit = rem & (n - 1); // because n is a power of two
                rem >>= n.trailing_zeros(); // divide by n
                per_dim[dim][row * n + digit] = F::ONE;
            }
        }
        // ---------- convert to multilinear polynomials ----------
        per_dim.into_iter().map(|v| vec_to_mle::<F>(&v)).collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlonkishWitness<F: PrimeField> {
    pub witness_data: Vec<F>,
    pub witness_polynomial: MultilinearPolynomial<F>,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlonkishCommitments<
    F: PrimeField + Absorb,
    G: CurveGroup<ScalarField = F>,
    C: Commitment<G>,
> {
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

impl<F: PrimeField + Absorb, G: CurveGroup<ScalarField = F>, C: Commitment<G>>
    PlonkishCommitments<F, G, C>
{
    pub fn absorb_in_transcript(&self, transcript: &mut Transcript<F>) {
        todo!()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PlonkishInstance<
    F: PrimeField + Absorb,
    G: CurveGroup<ScalarField = F>,
    C: Commitment<G>,
> {
    pub instance: Vec<F>,
    pub commitments: PlonkishCommitments<F, G, C>,
}
