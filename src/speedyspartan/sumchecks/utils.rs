use crate::{
    commitment::Commitment, constant_for_curves::ScalarField,
    polynomial::multilinear_poly::multilinear_poly::MultilinearPolynomial,
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
// ---------------------------------------------------------------------------
//  little utility reused everywhere
// ---------------------------------------------------------------------------

/// Return (low , high) of `poly` for global row `i` in a table of length
/// `len_max` (= the largest table that participates in *this* round).
///
/// When `poly` is *smaller* than `len_max` it means it does **not** depend on
/// the variable currently being folded, therefore `low == high`.
#[inline(always)]
fn low_high<F: PrimeField>(poly: &MultilinearPolynomial<F>, i: usize, len_max: usize) -> (F, F) {
    match poly.len() {
        1 => (poly[0], poly[0]), // constant
        l if l == len_max => {
            let half = l / 2;
            (poly[i], poly[half + i])
        }
        l => {
            // replicate along the missing dimension
            let half = l / 2;
            let local = i % half;
            (poly[local], poly[half + local])
        }
    }
}

/// P(0)…P(d)  for one polynomial at global index `i`.
#[inline(always)]
fn eval_points_for_poly<F: PrimeField>(
    poly: &MultilinearPolynomial<F>,
    i: usize,
    len_max: usize,
    d: usize,
) -> Vec<F> {
    let (low, high) = low_high(poly, i, len_max);
    let delta = high - low;

    // P(k) = low + k·delta   (incrementally)
    let mut res = Vec::with_capacity(d + 1);
    let mut cur = low;
    res.push(cur); // k = 0

    let mut k = F::ONE;
    for _ in 1..=d {
        cur += delta; // ++k
        res.push(cur);
        k += F::ONE;
    }
    res
}

/// Fold *one Boolean variable* of **N** multilinear polynomials at once and
/// return the `d + 1` evaluation points of the combined polynomial:
///
/// ```text
///    G(X) = comb_func(  P₀(X), P₁(X), …, P_{N-1}(X)  ) ,   X ∈ {0,…,d}
/// ```
///
/// * `polys`      – slice of multilinear polynomials (table representation).
/// * `d`          – folding degree (often the *number* of polynomials).
/// * `comb_func`  – user supplied function that takes  **one value per
///                  polynomial** (all evaluated in the same point) and
///                  returns a single field element.
///
/// It is **thread-safe** and runs in parallel with **rayon**.
///
/// The result vector has length `d + 1`; entry *k* is  ∑₍i∈rows₎  Gᵢ(k).
///
/// ```none
///   use crate::{compute_eval_points_degree_d};
///
///   let evals = compute_eval_points_degree_d(&[a, b, c], 3, &|vals| {
///       // for example, a simple product of all values
///       vals.iter().copied().product()
///   });
/// ```
///
/// ## Constraints
/// * All table lengths must be powers of two (standard for multilinears).
/// * A polynomial that is *shorter* than the largest one is assumed **not**
///   to depend on the extra variables; it is implicitly replicated along
///   those dimensions.
pub fn compute_eval_points_degree_d<F: PrimeField, Comb>(
    polys: &[MultilinearPolynomial<F>],
    d: usize,
    comb_func: &Comb,
) -> Vec<F>
where
    Comb: Fn(&[F]) -> F + Sync,
{
    assert!(!polys.is_empty(), "need at least one polynomial");

    // longest table = number of rows of the “current” variable’s HIGH half

    let len_max = polys
        .iter()
        .map(MultilinearPolynomial::len)
        .fold(0usize, std::cmp::max);

    assert!(len_max.is_power_of_two(), "tables must be 2^n long");
    let half_max = len_max / 2;

    // parallel over the *rows* of the current split
    (0..half_max)
        .into_par_iter()
        .map(|row| {
            // ---------- evaluate every polynomial in this row -------------
            let per_poly_pts: Vec<Vec<F>> = polys
                .iter()
                .map(|p| eval_points_for_poly(p, row, len_max, d))
                .collect();

            // -------- combine coordinate-wise with the user function -------
            let mut combined = Vec::with_capacity(d + 1);
            for k in 0..=d {
                // collect P₀(k), P₁(k), …
                let mut tmp = Vec::with_capacity(per_poly_pts.len());
                for poly_pts in &per_poly_pts {
                    tmp.push(poly_pts[k]);
                }
                combined.push(comb_func(&tmp));
            }
            combined
        })
        // ------------ ∑ over all rows (element-wise) -----------------------
        .reduce(
            || vec![F::ZERO; d + 1],
            |mut acc, v| {
                for (acc_k, v_k) in acc.iter_mut().zip(v) {
                    *acc_k += v_k;
                }
                acc
            },
        )
}

pub fn polynomial_rlc<F: PrimeField>(
    polynomials: &[MultilinearPolynomial<F>],
    coeff: &F,
) -> MultilinearPolynomial<F> {
    let mut polys_to_add: Vec<MultilinearPolynomial<F>> = Vec::with_capacity(polynomials.len());
    for (index, poly) in polynomials.iter().enumerate() {
        let scalar_coeff = coeff.pow(&[index as u64]);
        let mut poly_times_scalar = poly.clone();
        poly_times_scalar.scalar_mul(&scalar_coeff);
        polys_to_add.push(poly_times_scalar);
    }
    let mut sum = polys_to_add[0].clone();
    for poly in polys_to_add.iter().skip(1) {
        sum = sum + poly.clone();
    }
    sum
}

pub fn scalar_rlc<F: PrimeField>(claims: &[F], coeff: &F) -> F {
    let mut sum = claims[0];
    for (idx, claim) in claims.iter().skip(1).enumerate() {
        sum += *claim * coeff.pow(&[idx as u64]);
    }
    sum
}

pub fn point_rlc<G: CurveGroup<ScalarField = F>, F: PrimeField>(
    points: &[G::Affine],
    coeff: &F,
) -> G {
    let coeffs: Vec<F> = (0u64..(points.len() as u64))
        .into_iter()
        .map(|idx| coeff.pow(&[idx]))
        .collect();
    <G as VariableBaseMSM>::msm(points, &coeffs).expect("lengths match")
}

pub fn commitment_rlc<G: CurveGroup<ScalarField = F>, F: PrimeField + Absorb, C: Commitment<G>>(
    commitments: &[C],
    coeff: &F,
) -> C {
    let points: Vec<G::Affine> = commitments.iter().map(|comm| comm.into_affine()).collect();
    let result_point = point_rlc(&points, coeff);
    C::from(result_point)
}
