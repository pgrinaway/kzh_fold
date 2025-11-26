use std::alloc::alloc;

use crate::constant_for_curves::ScalarField;
use crate::nexus_spartan::sumcheck_circuit::sumcheck_circuit::SumcheckCircuit;
use crate::nexus_spartan::sumcheck_circuit::sumcheck_circuit_var::SumcheckCircuitVar;
use crate::nexus_spartan::unipoly::unipoly::CompressedUniPoly;
use crate::nexus_spartan::unipoly::unipoly_var::{CompressedUniPolyVar, UniPolyVar};
use crate::polynomial::eq_poly::eq_poly::EqPolynomial;
use crate::polynomial::eq_poly::eq_poly_var::EqPolynomialVar;
use crate::speedyspartan::circuit::rlc::ScalarRLCVar;
use crate::speedyspartan::circuit::ss_verifier::SSFragmentVar;
use crate::speedyspartan::snark::SpeedySpartanFragment;
use crate::speedyspartan::sumchecks::addr_sumcheck::AddrMSumcheckResult;
use crate::speedyspartan::sumchecks::plonkish_sumcheck::{self, PlonkishSumcheckResult};
use crate::speedyspartan::sumchecks::rerandomization_sumcheck::{
    RerandSumcheckEvaluationResult, RerandomizationEvaluationResult,
};
use crate::speedyspartan::{
    ADDR_DEGREE, ADDR_N_ROUNDS, PLONKISH_DEGREE, PLONKISH_N_ROUNDS, RERAND_DEGREE,
};
use crate::transcript::transcript_var::{AppendToTranscriptVar, TranscriptVar};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::{R1CSVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace, SynthesisError};
use digest::KeyInit;
use sha3::CShake128Core;

pub fn squeeze_challenge<F: PrimeField + Absorb>(
    cs: impl Into<Namespace<F>>,
    transcript: &mut TranscriptVar<F>,
    n_bits: usize,
    label: 'a &[u8],
) -> FpVar<F> {
    let mut ns = cs.into();
    let initial_challenge = transcript.challenge_scalar('a label);
    let initial_challenge_bits = initial_challenge.to_bits_le().unwrap();

    let mut acc = FpVar::new_variable(ns.clone(), || Ok(F::ZERO), AllocationMode::Witness).unwrap();
    let mut coeff =
        FpVar::new_variable(ns.clone(), || Ok(F::ONE), AllocationMode::Witness).unwrap();
    for i in (0..n_bits) {
        acc += initial_challenge_bits[i]
            .select(&coeff.clone(), &FpVar::Constant(F::ZERO))
            .unwrap();

        coeff += coeff.clone();
    }
    acc
}
