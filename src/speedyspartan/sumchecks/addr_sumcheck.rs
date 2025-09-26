use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};

use crate::{
    math::Math,
    nexus_spartan::unipoly::unipoly::UniPoly,
    polynomial::multilinear_poly::multilinear_poly::MultilinearPolynomial,
    speedyspartan::sumchecks::utils,
    transcript::transcript::{AppendToTranscript, Transcript},
};

pub struct AddrMSumcheckResult<F: PrimeField + Absorb> {
    pub(crate) polys: Vec<UniPoly<F>>,
    pub(crate) claims_per_round: Vec<F>,
    pub(crate) challenge_points: Vec<F>,
    pub(crate) addr_a_evals: Vec<F>,
    pub(crate) addr_b_evals: Vec<F>,
    pub(crate) addr_c_evals: Vec<F>,
    pub(crate) z_eval: F,
}

pub fn prove_addr_sumcheck<F: PrimeField + Absorb>(
    dimension: usize,
    claim: &F,
    rho: &F,
    eq_poly: &mut MultilinearPolynomial<F>,
    addr_a: &mut [MultilinearPolynomial<F>],
    addr_b: &mut [MultilinearPolynomial<F>],
    addr_c: &mut [MultilinearPolynomial<F>],
    padded_z: &mut MultilinearPolynomial<F>,
    transcript: &mut Transcript<F>,
) -> AddrMSumcheckResult<F> {
    let num_rounds = addr_a[0].len().log_2();

    let mut r: Vec<F> = Vec::new();
    let mut polys: Vec<UniPoly<F>> = Vec::new();
    let mut claim_per_round = *claim;
    let z_unbound = padded_z.clone();
    let mut claims_per_round: Vec<F> = vec![];
    claims_per_round.push(claim_per_round);
    for _ in 0..num_rounds {
        let poly = {
            let mut eval_polys: Vec<MultilinearPolynomial<F>> =
                Vec::with_capacity((addr_a.len() * 3) + 2);
            eval_polys.extend_from_slice(&addr_a);
            eval_polys.extend_from_slice(&addr_b);
            eval_polys.extend_from_slice(&addr_c);
            eval_polys.push(padded_z.clone());
            eval_polys.push(eq_poly.clone());

            let comb_func = |poly_evals: &[F]| -> F {
                let addr_a_evals: F = poly_evals[0..dimension].iter().product();
                let addr_b_evals: F = poly_evals[dimension..dimension * 2].iter().product();
                let addr_c_evals: F = poly_evals[dimension * 2..dimension * 3].iter().product();
                let z_eval = poly_evals[dimension * 3];
                let eq_eval = poly_evals[dimension * 3 + 1];

                z_eval * eq_eval * (addr_a_evals + *rho * addr_b_evals + *rho * *rho * addr_c_evals)
            };
            let evaluations =
                utils::compute_eval_points_degree_d(&eval_polys, dimension + 2, &comb_func);

            UniPoly::from_evals(&evaluations)
        };
        // append the prover's message to the transcript
        <UniPoly<F> as AppendToTranscript<F>>::append_to_transcript(&poly, b"poly", transcript);

        //derive the verifier's challenge for the next round
        let r_i = Transcript::challenge_scalar(transcript, b"challenge_nextround");
        r.push(r_i);
        polys.push(poly.clone());
        //println!("Got here");
        // Set up next round
        claim_per_round = poly.evaluate(&r_i);
        // challenge r_i already squeezed
        addr_a
            .par_iter_mut()
            .for_each(|p| p.bound_poly_var_top(&r_i));
        addr_b
            .par_iter_mut()
            .for_each(|p| p.bound_poly_var_top(&r_i));
        addr_c
            .par_iter_mut()
            .for_each(|p| p.bound_poly_var_top(&r_i));

        eq_poly.bound_poly_var_top(&r_i);
        padded_z.bound_poly_var_top(&r_i);
        claims_per_round.push(claim_per_round);
    }

    // NEW: also evaluate z at (1, r')
    // Assumes the selector bit is the *first* variable bound by bind_poly_var_top.
    let mut z_at_one = z_unbound.clone();
    for (i, ri) in r.iter().enumerate() {
        let val = if i == 0 { F::ONE } else { *ri };
        z_at_one.bound_poly_var_top(&val);
    }
    let z_eval_at_one = z_at_one[0]; // this is z(1, r')
                                     // Existing evals at (alpha, r')
    AddrMSumcheckResult {
        polys,
        claims_per_round,
        challenge_points: r,
        addr_a_evals: addr_a.iter().map(|p| p[0]).collect(),
        addr_b_evals: addr_b.iter().map(|p| p[0]).collect(),
        addr_c_evals: addr_c.iter().map(|p| p[0]).collect(),
        z_eval: padded_z[0],
    }
}
