use crate::commitment::Commitment;
use crate::speedyspartan::folding::FoldedObject;
use crate::speedyspartan::sumchecks::plonkish_sumcheck::PlonkishSumcheckResult;
use std::marker::PhantomData;
use std::ops::Mul;

use crate::math::Math;
use crate::nexus_spartan::unipoly::unipoly::UniPoly;
use crate::polynomial::multilinear_poly::multilinear_poly::MultilinearPolynomial;
use crate::speedyspartan::plonkish::{PlonkishCommitments, PlonkishShape};
use crate::speedyspartan::sumchecks::utils::{self, point_rlc, polynomial_rlc, scalar_rlc};
use crate::transcript::transcript::{AppendToTranscript, Transcript};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

pub fn fold<G: CurveGroup<ScalarField = F>, C: Commitment<G>, F: PrimeField + Absorb>(
    sumcheck_result: &PlonkishSumcheckResult<F>,
    transcript: &mut Transcript<F>,
    incoming_shape: &PlonkishShape<F>,
    incoming_commitments: &PlonkishCommitments<G, C>,
) -> FoldedObject<G, F, C> {
    let gamma = transcript.challenge_scalar(b"plonkish rlc gamma");
    let claims = [
        sumcheck_result.v_l,
        sumcheck_result.v_r,
        sumcheck_result.v_o,
        sumcheck_result.v_m,
        sumcheck_result.v_c,
        sumcheck_result.v_a,
        sumcheck_result.v_b,
        sumcheck_result.v_c,
        sumcheck_result.eq,
    ];
    let folded_claim = scalar_rlc(&claims, &gamma);
    //TODO: za, zb, zc, eq
    let polynomials = [
        incoming_shape.q_l.clone(),
        incoming_shape.q_r.clone(),
        incoming_shape.q_o.clone(),
        incoming_shape.q_m.clone(),
        incoming_shape.q_c.clone(),
    ];
    let folded_poly = polynomial_rlc(&polynomials, &gamma);
    let commitments_to_combine: [G::Affine; 5] = [
        incoming_commitments.q_l.into_affine(),
        incoming_commitments.q_r.into_affine(),
        incoming_commitments.q_o.into_affine(),
        incoming_commitments.q_m.into_affine(),
        incoming_commitments.q_c.into_affine(),
    ];
    let folded_commitment_point = point_rlc(&commitments_to_combine, &gamma);
    let folded_commitment = C::from(folded_commitment_point);

    FoldedObject {
        challenge: gamma.clone(),
        claim: folded_claim,
        random_point: sumcheck_result.challenge_points.clone(),
        commitment: folded_commitment,
        polynomial: folded_poly,
        _marker: PhantomData,
    }
}
