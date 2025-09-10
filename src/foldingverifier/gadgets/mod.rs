use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;

/// Computes a scalar linear combination of `inputs` using `coefficient`.
///
/// The returned variable enforces that
/// `inputs[0] + coefficient * inputs[1] + coefficient^2 * inputs[2] + ...` holds.
/// Each successive power of the coefficient is derived via multiplication,
/// introducing a separate constraint per power.
pub fn scalar_linear_combination<F: PrimeField>(
    coefficient: &FpVar<F>,
    inputs: &[FpVar<F>],
) -> FpVar<F> {
    let mut result = FpVar::<F>::zero();
    let mut power = FpVar::<F>::one();
    for input in inputs {
        result += &power * input;
        power *= coefficient;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::{PrimeField, UniformRand};
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::ns;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{test_rng, One, Zero};

    #[test]
    fn test_scalar_linear_combination() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rng = test_rng();

        let coeff = Fr::rand(&mut rng);
        let inputs_vals: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();

        let coeff_var = FpVar::new_witness(ns!(cs, "coeff"), || Ok(coeff)).unwrap();
        let input_vars = inputs_vals
            .iter()
            .map(|v| FpVar::new_witness(ns!(cs, "input"), || Ok(*v)).unwrap())
            .collect::<Vec<_>>();

        let rlc_var = scalar_linear_combination(&coeff_var, &input_vars);

        // compute expected value
        let mut expected = Fr::zero();
        let mut pow = Fr::one();
        for val in inputs_vals {
            expected += pow * val;
            pow *= coeff;
        }

        assert_eq!(rlc_var.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }
}
