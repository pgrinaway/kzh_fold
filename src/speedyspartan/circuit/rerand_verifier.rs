use crate::constant_for_curves::ScalarField;
use crate::nexus_spartan::sumcheck_circuit::sumcheck_circuit::SumcheckCircuit;
use crate::nexus_spartan::sumcheck_circuit::sumcheck_circuit_var::SumcheckCircuitVar;
use crate::nexus_spartan::unipoly::unipoly::CompressedUniPoly;
use crate::nexus_spartan::unipoly::unipoly_var::{CompressedUniPolyVar, UniPolyVar};
use crate::polynomial::eq_poly::eq_poly::EqPolynomial;
use crate::polynomial::eq_poly::eq_poly_var::EqPolynomialVar;
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
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace, SynthesisError};
use digest::KeyInit;
use sha3::CShake128Core;

/*
rerand result:
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
}



*/

pub struct RerandSumcheck<F: PrimeField + Absorb> {
    final_claim: FpVar<F>,
    rerand_sumcheck: SumcheckCircuitVar<F>,
}

impl<F: PrimeField + Absorb> RerandSumcheck<F> {
    pub fn new(
        cs: impl Into<Namespace<F>>,
        rerand_result: &RerandSumcheckEvaluationResult<F>,
        eqs: Vec<EqPolynomialVar<F>>,
        sigma_challenge: FpVar<F>,
        transcript: &mut TranscriptVar<F>,
    ) -> Self {
        let compressed_uni_polys: Vec<CompressedUniPoly<F>> = rerand_result
            .polys
            .iter()
            .map(|poly| poly.compress())
            .collect();
        let len_polys = compressed_uni_polys.len();
        let sumcheck_circuit: SumcheckCircuit<F> = SumcheckCircuit {
            compressed_polys: compressed_uni_polys,
            claim: rerand_result.final_claim(),
            num_rounds: rerand_result.polys.len(),
            degree_bound: RERAND_DEGREE,
        };
        let ns = cs.into();
        let sumcheck = SumcheckCircuitVar::new_variable(
            ns.clone(),
            || Ok(sumcheck_circuit),
            AllocationMode::Witness,
        )
        .unwrap();

        let (claim, challenge_rho) = sumcheck.verify(transcript);
        // let challenge_rho =

        // Compute the claim, an RLC of eq*claim:
        let sigma_powers: Vec<FpVar<F>> = (0..len_polys)
            .map(|power| sigma_challenge.pow_by_constant(&[power as u64]).unwrap())
            .collect();

        let final_claim: FpVar<F> = eqs
            .iter()
            .zip(rerand_result.final_poly_values.clone())
            .map(|(eq, claim)| eq.evaluate(&challenge_rho) * claim)
            .reduce(|a, b| a + b)
            .unwrap();

        sumcheck.claim.enforce_equal(&final_claim);
        Self {
            final_claim,
            rerand_sumcheck: sumcheck,
        }
    }
}
