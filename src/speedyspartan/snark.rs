use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::commitment::Commitment;
use crate::polynomial::eq_poly::eq_poly;
use crate::polynomial::multilinear_poly::multilinear_poly::MultilinearPolynomial;
use crate::speedyspartan::folding::FoldedObject;
use crate::speedyspartan::plonkish::{
    PlonkishCommitments, PlonkishInstance, PlonkishShape, PlonkishWitness,
};
use crate::speedyspartan::rerandomization::{rerandomize_fold, RerandomizationOutput};
use crate::speedyspartan::sumchecks::addr_sumcheck::{prove_addr_sumcheck, AddrMSumcheckResult};
use crate::speedyspartan::sumchecks::plonkish_sumcheck::{
    prove_plonkish_sumcheck, PlonkishSumcheckResult,
};
use crate::speedyspartan::sumchecks::utils::scalar_rlc;
use crate::speedyspartan::utils::vec_to_mle;
use crate::speedyspartan::{folding, ADDR_DIM};
use crate::transcript::transcript::Transcript;
use core::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct SpeedySpartanFragment<
    G: CurveGroup<ScalarField = F>,
    F: PrimeField + Absorb,
    C: Commitment<G>,
> {
    pub(crate) plonkish_sumcheck: PlonkishSumcheckResult<F>,
    pub(crate) addr_sumcheck: AddrMSumcheckResult<F>,
    pub(crate) plonkish_fold: FoldedObject<G, F, C>,
    pub(crate) addr_fold: FoldedObject<G, F, C>,
    pub(crate) rerand_fold: RerandomizationOutput<G, F, C>,
}

pub fn prove_speedyspartan_fragment<G, C, F>(
    incoming_shape: &PlonkishShape<G::ScalarField>,
    incoming_witness: &PlonkishWitness<G::ScalarField>,
    incoming_instance: &PlonkishInstance<F, G, C>,
    incoming_commitments: &PlonkishCommitments<F, G, C>,
) -> SpeedySpartanFragment<G, F, C>
where
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

    let eq_poly = eq_poly::EqPolynomial::new(random_challenge);
    let mut eq_poly_mle = MultilinearPolynomial::new(eq_poly.evals());

    let mut incoming_shape_cloned = incoming_shape.clone();

    let plonkish_zs = incoming_shape.z(&incoming_witness, &incoming_instance);
    let mut z_a = vec_to_mle(&plonkish_zs.z_a);
    let mut z_b = vec_to_mle(&plonkish_zs.z_b);
    let mut z_c = vec_to_mle(&plonkish_zs.z_c);
    let mut z_mle = vec_to_mle(&plonkish_zs.z);

    let plonkish_sumcheck_result = prove_plonkish_sumcheck(
        &F::ZERO,
        &mut incoming_shape_cloned.q_l,
        &mut incoming_shape_cloned.q_r,
        &mut incoming_shape_cloned.q_o,
        &mut incoming_shape_cloned.q_m,
        &mut incoming_shape_cloned.q_c,
        &mut z_a,
        &mut z_b,
        &mut z_c,
        &mut eq_poly_mle,
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

    let mut eq_poly_mle_addr = MultilinearPolynomial::new(eq_poly.evals());

    let addr_sumcheck_result = prove_addr_sumcheck(
        ADDR_DIM,
        &addr_claim,
        &rho,
        &mut eq_poly_mle_addr,
        &mut incoming_shape_cloned.addr_A,
        &mut incoming_shape_cloned.addr_B,
        &mut incoming_shape_cloned.addr_C,
        &mut z_mle,
        &incoming_witness.witness_polynomial,
        &mut transcript,
    );

    let gamma = transcript.challenge_scalar(b"addr fold challenge");

    let folded_addr = folding::addr::fold_addr(
        &addr_sumcheck_result,
        &incoming_shape,
        &incoming_commitments,
        &gamma,
    );

    let rerand_fold = rerandomize_fold(
        &[folded_plonkish.clone(), folded_addr.clone()],
        &mut transcript,
    );

    SpeedySpartanFragment {
        plonkish_sumcheck: plonkish_sumcheck_result,
        addr_sumcheck: addr_sumcheck_result,
        plonkish_fold: folded_plonkish,
        addr_fold: folded_addr,
        rerand_fold,
    }
}
