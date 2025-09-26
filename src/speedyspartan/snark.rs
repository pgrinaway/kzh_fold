use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::commitment::Commitment;
use crate::polynomial::eq_poly::eq_poly;
use crate::polynomial::multilinear_poly::multilinear_poly::MultilinearPolynomial;
use crate::speedyspartan::plonkish::{
    PlonkishCommitments, PlonkishInstance, PlonkishShape, PlonkishWitness,
};
use crate::speedyspartan::sumchecks::addr_sumcheck::prove_addr_sumcheck;
use crate::speedyspartan::sumchecks::plonkish_sumcheck::prove_plonkish_sumcheck;
use crate::speedyspartan::sumchecks::utils::scalar_rlc;
use crate::speedyspartan::{folding, ADDR_DIM};
use crate::transcript::transcript::Transcript;
use core::marker::PhantomData;

pub fn prove_speedyspartan_fragment<G, C, F>(
    incoming_shape: &PlonkishShape<G::ScalarField>,
    incoming_witness: &PlonkishWitness<G::ScalarField>,
    incoming_instance: &PlonkishInstance<G, C>,
    incoming_commitments: &PlonkishCommitments<G, C>,
) where
    G: CurveGroup<ScalarField = F>,
    C: Commitment<G>,
    F: Absorb + PrimeField,
{
    let mut transcript: Transcript<F> = Transcript::new(b"speedyspartan");
    let witness_length = incoming_witness.witness_data.len();
    let instance_length = incoming_instance.instance.len();

    let random_challenge: Vec<G::ScalarField> = (0..witness_length + instance_length)
        .into_iter()
        .map(|_idx| transcript.challenge_scalar(b"plonkish_challenge"))
        .collect();

    let mut eq_poly = eq_poly::EqPolynomial::new(random_challenge);

    let mut incoming_shape_cloned = incoming_shape.clone();

    let plonkish_sumcheck_result = prove_plonkish_sumcheck(
        &F::ZERO,
        &mut incoming_shape_cloned.q_l,
        &mut incoming_shape_cloned.q_r,
        &mut incoming_shape_cloned.q_o,
        &mut incoming_shape_cloned.q_m,
        &mut incoming_shape_cloned.q_c,
        z_a,
        z_b,
        z_c,
        &mut eq_poly,
        &mut transcript,
    );

    let folded_plonkish = folding::plonkish::fold(
        &plonkish_sumcheck_result,
        &mut transcript,
        &incoming_shape,
        &incoming_commitments,
    );

    let rho = transcript.challenge_scalar(b"addr challenge");
    let addr_claim = scalar_rlc(
        &[
            plonkish_sumcheck_result.v_a,
            plonkish_sumcheck_result.v_b,
            plonkish_sumcheck_result.v_c,
        ],
        &rho,
    );

    let addr_sumcheck_result = prove_addr_sumcheck(
        ADDR_DIM,
        &addr_claim,
        &rho,
        eq_poly,
        &mut incoming_shape_cloned.addr_A,
        &mut incoming_shape_cloned.addr_B,
        &mut incoming_shape_cloned.addr_C,
        &mut z,
        transcript,
    );

    todo!()
}
