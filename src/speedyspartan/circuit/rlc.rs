use std::marker::PhantomData;

use crate::constant_for_curves::ScalarField;
use crate::nexus_spartan::sumcheck_circuit::sumcheck_circuit::SumcheckCircuit;
use crate::nexus_spartan::unipoly::unipoly_var::{CompressedUniPolyVar, UniPolyVar};
use crate::transcript::transcript_var::{AppendToTranscriptVar, TranscriptVar};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace, SynthesisError};

#[derive(Clone, Debug)]
pub struct ScalarRLCVar<G, F>
where
    F: PrimeField + Absorb,
    G: SWCurveConfig<ScalarField = F> + Clone,
{
    rlc: FpVar<F>,
}

impl<F: PrimeField + Absorb, G: SWCurveConfig<ScalarField = F> + Clone> ScalarRLCVar<G, F> {
    pub fn new(
        cs: &mut ConstraintSystem<F>,
        eval_claim_values: Vec<FpVar<F>>,
        challenge: FpVar<F>,
    ) -> Self {
        let eval_claim_0 = eval_claim_values[0].clone();
        let challenge_powers: Vec<FpVar<F>> = (1..eval_claim_values.len())
            .into_iter()
            .map(|pow| challenge.pow_by_constant(&[pow as u64]).unwrap())
            .collect();

        let challenge_powers_sum: FpVar<F> = eval_claim_values
            .iter()
            .skip(1)
            .zip(challenge_powers)
            .map(|(eval, challenge)| eval * challenge)
            .reduce(|a, b| a + b)
            .unwrap();

        let rlc = eval_claim_0 + challenge_powers_sum;

        Self { rlc }
    }
}

#[derive(Clone, Debug)]
pub struct PointRLCVar<F1, F2, G, GV>
where
    F1: PrimeField + Absorb,
    F2: PrimeField + Absorb,
    G: CurveGroup<ScalarField = F1, BaseField = F2>,
    GV: CurveVar<G, F1> + Clone,
{
    rlc: GV,
    _g: PhantomData<G>,
    _f: PhantomData<F1>,
}

impl<
        F1: PrimeField + Absorb,
        F2: PrimeField + Absorb,
        G: CurveGroup,
        GV: CurveVar<G, F2> + Clone,
    > PointRLCVar<F1, F2, G, GV>
{
    pub fn new(
        cs: &mut ConstraintSystem<F1>,
        poly_commitments: &[GV],
        challenge: &FpVar<G::ScalarField>,
    ) -> Self {
        let mut acc = GV::zero();
        let mut power = FpVar::<G::ScalarField>::one();

        for point in poly_commitments {
            let bits = power.to_bits_le().unwrap();
            acc += point.scalar_mul_le(bits.iter()).unwrap();
            power *= challenge;
        }
        Self { rlc: acc }
    }
}
