use std::ops::Mul;

use crate::math::Math;
use crate::nexus_spartan::unipoly::unipoly::UniPoly;
use crate::polynomial::multilinear_poly::multilinear_poly::MultilinearPolynomial;
use crate::speedyspartan::plonkish::{PlonkishCommitments, PlonkishShape};
use crate::speedyspartan::sumchecks::utils::{self, polynomial_rlc, scalar_rlc};
use crate::transcript::transcript::{AppendToTranscript, Transcript};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;

#[derive(Debug, Clone)]
pub struct PlonkishSumcheckResult<F: PrimeField + Absorb> {
    pub(crate) polys: Vec<UniPoly<F>>,
    pub(crate) claims_per_round: Vec<F>,
    pub(crate) challenge_points: Vec<F>,
    pub(crate) v_l: F,
    pub(crate) v_r: F,
    pub(crate) v_o: F,
    pub(crate) v_m: F,
    pub(crate) v_c: F,
    pub(crate) v_a: F,
    pub(crate) v_b: F,
    pub(crate) v_zc: F,
    pub(crate) eq: F,
}

impl<F: PrimeField + Absorb> PlonkishSumcheckResult<F> {
    pub fn fold(&self, transcript: &mut Transcript<F>, incoming_shape: &PlonkishShape<F>) {
        let gamma = transcript.challenge_scalar(b"plonkish rlc gamma");
        let claims = [
            self.v_l, self.v_r, self.v_o, self.v_m, self.v_c, self.v_a, self.v_b, self.v_c, self.eq,
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
    }

    pub fn final_claim(&self) -> F {
        todo!()
    }
}

pub fn prove_plonkish_sumcheck<F: PrimeField + Absorb>(
    claim: &F,
    q_l: &mut MultilinearPolynomial<F>,
    q_r: &mut MultilinearPolynomial<F>,
    q_o: &mut MultilinearPolynomial<F>,
    q_m: &mut MultilinearPolynomial<F>,
    q_c: &mut MultilinearPolynomial<F>,
    z_a: &mut MultilinearPolynomial<F>,
    z_b: &mut MultilinearPolynomial<F>,
    z_c: &mut MultilinearPolynomial<F>,
    eq_poly: &mut MultilinearPolynomial<F>,
    transcript: &mut Transcript<F>,
) -> PlonkishSumcheckResult<F> {
    let num_rounds = z_a.len().log_2();
    let mut r: Vec<F> = Vec::new();
    let mut polys: Vec<UniPoly<F>> = Vec::new();
    let mut claim_per_round = *claim;
    let mut claims_per_round: Vec<F> = vec![];
    claims_per_round.push(claim_per_round);
    for _ in 0..num_rounds {
        let comb_func = |poly_evals: &[F]| -> F {
            poly_evals[8]
                * (poly_evals[0] * poly_evals[5]
                    + poly_evals[1] * poly_evals[6]
                    + poly_evals[2] * poly_evals[7]
                    + poly_evals[3] * poly_evals[5] * poly_evals[6]
                    + poly_evals[4])
        };
        let evals = utils::compute_eval_points_degree_d(
            &[
                q_l.clone(),
                q_r.clone(),
                q_o.clone(),
                q_m.clone(),
                q_c.clone(),
                z_a.clone(),
                z_b.clone(),
                z_c.clone(),
                eq_poly.clone(),
            ],
            4,
            &comb_func,
        );
        let poly = UniPoly::from_evals(&evals);

        // append the prover's message to the transcript
        <UniPoly<F> as AppendToTranscript<F>>::append_to_transcript(&poly, b"poly", transcript);

        //derive the verifier's challenge for the next round
        let r_i = Transcript::challenge_scalar(transcript, b"challenge_nextround");
        r.push(r_i);
        polys.push(poly.clone());

        claim_per_round = poly.evaluate(&r_i);
        claims_per_round.push(claim_per_round);

        q_l.bound_poly_var_top(&r_i);
        q_r.bound_poly_var_top(&r_i);
        q_o.bound_poly_var_top(&r_i);
        q_m.bound_poly_var_top(&r_i);
        q_c.bound_poly_var_top(&r_i);
        z_a.bound_poly_var_top(&r_i);
        z_b.bound_poly_var_top(&r_i);
        z_c.bound_poly_var_top(&r_i);
        eq_poly.bound_poly_var_top(&r_i);
    }
    PlonkishSumcheckResult {
        polys,
        claims_per_round,
        challenge_points: r,
        v_l: q_l[0],
        v_r: q_r[0],
        v_o: q_o[0],
        v_m: q_m[0],
        v_c: q_c[0],
        v_a: z_a[0],
        v_b: z_b[0],
        v_zc: z_c[0],
        eq: eq_poly[0],
    }
}
