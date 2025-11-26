use crate::commitment::Commitment;
use crate::speedyspartan::folding::{addr, FoldedObject};
use crate::speedyspartan::sumchecks::addr_sumcheck::AddrMSumcheckResult;
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

pub fn fold_addr<G: CurveGroup<ScalarField = F>, F: PrimeField + Absorb, C: Commitment<G>>(
    addr_sumcheck_result: &AddrMSumcheckResult<F>,
    incoming_shape: &PlonkishShape<F>,
    incoming_commitments: &PlonkishCommitments<F, G, C>,
    gamma: &F,
) -> FoldedObject<G, F, C> {
    let mut addr_claims: Vec<F> = [
        addr_sumcheck_result.addr_a_evals.clone(),
        addr_sumcheck_result.addr_b_evals.clone(),
        addr_sumcheck_result.addr_c_evals.clone(),
    ]
    .iter()
    .flatten()
    .cloned()
    .collect();
    addr_claims.push(addr_sumcheck_result.w_eval);
    let folded_claim = scalar_rlc(&addr_claims, gamma);

    let polys_to_compress: Vec<MultilinearPolynomial<F>> = [
        incoming_shape.addr_A.clone(),
        incoming_shape.addr_B.clone(),
        incoming_shape.addr_C.clone(),
    ]
    .iter()
    .flatten()
    .cloned()
    .collect();

    let folded_poly = polynomial_rlc(&polys_to_compress, gamma);

    let commitments_to_compress: Vec<G::Affine> = [
        incoming_commitments.addr_A.clone(),
        incoming_commitments.addr_B.clone(),
        incoming_commitments.addr_C.clone(),
    ]
    .iter()
    .flatten()
    .cloned()
    .map(|commitment| commitment.into_affine())
    .collect();

    let folded_commitment_point = point_rlc(&commitments_to_compress, gamma);
    let folded_commitment = C::from(folded_commitment_point);
    FoldedObject {
        challenge: gamma.clone(),
        claim: folded_claim,
        random_point: addr_sumcheck_result.challenge_points.clone(),
        commitment: folded_commitment,
        polynomial: folded_poly,
        _marker: PhantomData,
    }
}
