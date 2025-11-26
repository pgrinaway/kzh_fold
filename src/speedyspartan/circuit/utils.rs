use ark_ff::PrimeField;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;

/// Compute claim for MLE of z = [w_vec || x_vec] at point r,
/// given:
/// - r: point in F^{k+1}, r[0] = t, r[1..] = r_rest
/// - w_claim = \tilde{w}(r_rest)
/// - x: full vector for x, but only x[0..4) are non-zero.
///
/// Returns: z_claim = \tilde{z}(r) = (1 - t) * w_claim + t * \tilde{x}(r_rest).
pub fn concat_mle_claim<F: PrimeField>(
    r: &[FpVar<F>],
    w_claim: &FpVar<F>,
    x: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    assert!(r.len() >= 3, "Need at least k+1 >= 3 coords (k>=2)");
    assert!(x.len() >= 4, "x must have at least 4 entries");

    // r_z = (t, r_rest)
    let t = r[0].clone();
    let r_rest = &r[1..]; // length k

    // a = r1, b = r2 (these correspond to the low 2 bits)
    let a = r_rest[0].clone();
    let b = r_rest[1].clone();

    // tail = ∏_{j=2}^{k-1} (1 - r_rest[j])
    let mut tail = FpVar::<F>::one();
    for rj in &r_rest[2..] {
        tail *= FpVar::<F>::one() - rj;
    }

    // Basis polynomials for indices 0..3

    // chi_0 = (1-a)(1-b) * tail
    let chi0 = (FpVar::<F>::one() - &a) * (FpVar::<F>::one() - &b) * &tail;

    // chi_1 = a(1-b) * tail
    let chi1 = a.clone() * (FpVar::<F>::one() - &b) * &tail;

    // chi_2 = (1-a)b * tail
    let chi2 = (FpVar::<F>::one() - &a) * b.clone() * &tail;

    // chi_3 = a b * tail
    let chi3 = a * b * tail;

    // MLE of x at r_rest using only first 4 entries
    let x0 = x[0].clone();
    let x1 = x[1].clone();
    let x2 = x[2].clone();
    let x3 = x[3].clone();

    let x_eval = x0 * chi0 + x1 * chi1 + x2 * chi2 + x3 * chi3;

    // Now combine with the existing claim w_claim:
    // z(r) = (1 - t) * w(r_rest) + t * x(r_rest)
    let one = FpVar::<F>::one();
    let z_claim = (one - &t) * w_claim + t * x_eval;

    Ok(z_claim)
}
