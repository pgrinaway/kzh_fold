use crate::math::Math;
use crate::nexus_spartan::unipoly::unipoly::UniPoly;
use crate::polynomial::multilinear_poly::multilinear_poly::MultilinearPolynomial;
use crate::speedyspartan::sumchecks::utils;
use crate::transcript::transcript::{AppendToTranscript, Transcript};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};

pub struct RerandomizationEvaluationResult<F: PrimeField + Absorb> {
    pub(crate) polys: Vec<UniPoly<F>>,
    pub(crate) claims_per_round: Vec<F>,
    pub(crate) challenge_points: Vec<F>,
    pub(crate) prev_poly_v: F,
    pub(crate) plonk_poly_v: F,
    pub(crate) addr_poly_v: F,
}

pub fn prove_rerandomization_sumcheck<F: PrimeField + Absorb>(
    claim: &F,
    eq_polys: &mut [MultilinearPolynomial<F>],
    prev_poly: &mut MultilinearPolynomial<F>,
    plonkish_poly: &mut MultilinearPolynomial<F>,
    addr_poly: &mut MultilinearPolynomial<F>,
    z_poly: &mut MultilinearPolynomial<F>,
    sigma: &F,
    transcript: &mut Transcript<F>,
) -> RerandomizationEvaluationResult<F> {
    let num_rounds = prev_poly.len().log_2();
    let mut r: Vec<F> = Vec::new();
    let mut polys: Vec<UniPoly<F>> = Vec::new();
    let mut claim_per_round = *claim;

    let mut claims_per_round: Vec<F> = vec![];
    claims_per_round.push(claim_per_round);
    for _ in 0..num_rounds {
        let mut polys_to_eval: Vec<MultilinearPolynomial<F>> =
            Vec::with_capacity(eq_polys.len() + 4);
        polys_to_eval.extend_from_slice(&eq_polys);
        polys_to_eval.push(prev_poly.clone());
        polys_to_eval.push(plonkish_poly.clone());
        polys_to_eval.push(addr_poly.clone());
        polys_to_eval.push(z_poly.clone());
        let comb_func = |poly_evals: &[F]| -> F {
            let mut output = F::ZERO;
            for idx in 0..4 {
                output += poly_evals[idx] * poly_evals[idx + 4] * sigma.pow(&[idx as u64]);
            }
            output
        };
        let evals = utils::compute_eval_points_degree_d(&polys_to_eval, 2, &comb_func);
        let poly = UniPoly::from_evals(&evals);
        // append the prover's message to the transcript
        <UniPoly<F> as AppendToTranscript<F>>::append_to_transcript(&poly, b"poly", transcript);

        //derive the verifier's challenge for the next round
        let r_i = Transcript::challenge_scalar(transcript, b"challenge_nextround");
        r.push(r_i);
        polys.push(poly.clone());

        claim_per_round = poly.evaluate(&r_i);
        claims_per_round.push(claim_per_round);

        eq_polys
            .par_iter_mut()
            .for_each(|p| p.bound_poly_var_top(&r_i));
        prev_poly.bound_poly_var_top(&r_i);
        plonkish_poly.bound_poly_var_top(&r_i);
        addr_poly.bound_poly_var_top(&r_i);
        z_poly.bound_poly_var_top(&r_i);
    }
    RerandomizationEvaluationResult {
        polys,
        claims_per_round,
        challenge_points: r,
        prev_poly_v: prev_poly[0],
        plonk_poly_v: plonkish_poly[0],
        addr_poly_v: addr_poly[0],
    }
}

#[derive(Debug, Clone)]
pub struct RerandSumcheckEvaluationResult<F: PrimeField + Absorb> {
    /// prover messages (degree-2 univariates) per round
    pub polys: Vec<UniPoly<F>>,
    /// claimed value for the running combination at start (index 0) and after each round
    pub claims_per_round: Vec<F>,
    /// verifier challenges r_1, ..., r_{num_rounds}
    pub challenge_points: Vec<F>,
    /// final single-value evaluations of each input polynomial after all bindings
    /// (same order as inputs: first all eq_polys, then all polys)
    pub final_poly_values: Vec<F>,

    pub sigma: F,
}

impl<F: PrimeField + Absorb> RerandSumcheckEvaluationResult<F> {
    pub fn final_claim(&self) -> F {
        todo!()
    }
}

/// Proves that `claim == sum_i sigma^i * eq_i * poly_i` at the current binding point,
/// via standard sumcheck over `n` variables (assumes all polynomials share the same arity).
pub fn prove_random_combination_sumcheck<F: PrimeField + Absorb>(
    claim: &F,
    eq_polys: &mut [MultilinearPolynomial<F>],
    polys: &mut [MultilinearPolynomial<F>],
    sigma: &F,
    transcript: &mut Transcript<F>,
) -> RerandSumcheckEvaluationResult<F> {
    assert!(
        !eq_polys.is_empty() && !polys.is_empty(),
        "need at least one eq poly and one target poly"
    );
    assert_eq!(
        eq_polys.len(),
        polys.len(),
        "eq_polys and polys must have the same length"
    );

    // sanity: all polynomials must have identical length (same #variables => same 2^n length)
    let len0 = eq_polys[0].len();
    for p in eq_polys.iter() {
        assert_eq!(p.len(), len0, "all eq_polys must have same length");
    }
    for p in polys.iter() {
        assert_eq!(p.len(), len0, "all polys must have same length as eq_polys");
    }
    // n = log2(length)
    let num_rounds = len0.log_2();

    let mut r: Vec<F> = Vec::with_capacity(num_rounds);
    let mut unis: Vec<UniPoly<F>> = Vec::with_capacity(num_rounds);
    let mut claim_per_round = *claim;

    let mut claims_per_round: Vec<F> = Vec::with_capacity(num_rounds + 1);
    claims_per_round.push(claim_per_round);

    // We’ll reuse a buffer that concatenates current eq_polys and polys for evals
    // Layout: [eq_0, ..., eq_{m-1}, poly_0, ..., poly_{m-1}]
    let m = eq_polys.len();

    for _round in 0..num_rounds {
        // Build the list to evaluate at {0,1} for the current top variable
        let mut to_eval: Vec<MultilinearPolynomial<F>> =
            Vec::with_capacity(eq_polys.len() + polys.len());
        to_eval.extend(eq_polys.iter().cloned());
        to_eval.extend(polys.iter().cloned());

        // Combines per the RLC: sum_i sigma^i * eq_i * poly_i
        let comb_func = |evals: &[F]| -> F {
            debug_assert_eq!(evals.len(), 2 * m);
            let (eq_evals, poly_evals) = evals.split_at(m);
            let mut acc = F::ZERO;
            // You can precompute powers if you want; sigma.pow(&[i as u64]) is fine here.
            for i in 0..m {
                acc += eq_evals[i] * poly_evals[i] * sigma.pow(&[i as u64]);
            }
            acc
        };

        // Degree is 2 (product of two multilinears in the current reduced variable)
        let evals = utils::compute_eval_points_degree_d(&to_eval, 2, &comb_func);
        let uni = UniPoly::from_evals(&evals);

        // append prover message
        <UniPoly<F> as AppendToTranscript<F>>::append_to_transcript(&uni, b"poly", transcript);

        // derive verifier challenge r_i
        let r_i = Transcript::challenge_scalar(transcript, b"challenge_nextround");
        r.push(r_i);
        unis.push(uni.clone());

        // update running claim
        claim_per_round = uni.evaluate(&r_i);
        claims_per_round.push(claim_per_round);

        // bind all polys on the top variable to r_i
        eq_polys
            .par_iter_mut()
            .for_each(|p| p.bound_poly_var_top(&r_i));
        polys
            .par_iter_mut()
            .for_each(|p| p.bound_poly_var_top(&r_i));
    }

    // After all rounds, each poly has length 1; collect their final scalar values.
    let mut final_vals = Vec::with_capacity(eq_polys.len() + polys.len());
    final_vals.extend(eq_polys.iter().map(|p| p[0]));
    final_vals.extend(polys.iter().map(|p| p[0]));

    RerandSumcheckEvaluationResult {
        polys: unis,
        claims_per_round,
        challenge_points: r,
        final_poly_values: final_vals,
        sigma: sigma.clone(),
    }
}
