use std::marker::PhantomData;

use crate::commitment::Commitment;
use crate::constant_for_curves::{BaseField, ScalarField};
use crate::nexus_spartan::sumcheck_circuit::sumcheck_circuit::SumcheckCircuit;
use crate::nexus_spartan::sumcheck_circuit::sumcheck_circuit_var::SumcheckCircuitVar;
use crate::nexus_spartan::unipoly::unipoly_var::{CompressedUniPolyVar, UniPolyVar};
use crate::polynomial::eq_poly::eq_poly::EqPolynomial;
use crate::polynomial::eq_poly::eq_poly_var::EqPolynomialVar;
use crate::speedyspartan::circuit::rerand_verifier::RerandSumcheck;
use crate::speedyspartan::circuit::rlc::{SSCCommitmentVar, ScalarRLCVar};
use crate::speedyspartan::circuit::utils::concat_mle_claim;
use crate::speedyspartan::circuit::{INSTANCE_SIZE, SELF_HASH};
use crate::speedyspartan::plonkish::{PlonkishCommitments, PlonkishInstance};
use crate::speedyspartan::snark::SpeedySpartanFragment;
use crate::speedyspartan::sumchecks::addr_sumcheck::AddrMSumcheckResult;
use crate::speedyspartan::sumchecks::plonkish_sumcheck::{self, PlonkishSumcheckResult};
use crate::speedyspartan::{ADDR_DEGREE, ADDR_N_ROUNDS, PLONKISH_DEGREE, PLONKISH_N_ROUNDS};
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
use digest::KeyInit;
use sha3::CShake128Core;

#[derive(Clone, Debug)]
pub struct PlonkishClaim<F: PrimeField + Absorb> {
    v_a: FpVar<F>,
    v_b: FpVar<F>,
    v_zc: FpVar<F>,
    v_o: FpVar<F>,
    v_m: FpVar<F>,
    v_l: FpVar<F>,
    v_r: FpVar<F>,
    v_c: FpVar<F>,
    final_claim: FpVar<F>,
    challenge_point_var: Vec<FpVar<F>>,
}

impl<F: PrimeField + Absorb> PlonkishClaim<F> {
    pub fn new(
        cs: impl Into<Namespace<F>>,
        plonkish_sumcheck: &PlonkishSumcheckResult<F>,
        eq_poly: EqPolynomial<F>,
    ) -> Self {
        let ns = cs.into();
        let v_a = FpVar::new_variable(
            ns.clone(),
            || Ok(plonkish_sumcheck.v_a),
            AllocationMode::Witness,
        )
        .unwrap();
        let v_b = FpVar::new_variable(
            ns.clone(),
            || Ok(plonkish_sumcheck.v_b),
            AllocationMode::Witness,
        )
        .unwrap();
        let v_zc = FpVar::new_variable(
            ns.clone(),
            || Ok(plonkish_sumcheck.v_zc),
            AllocationMode::Witness,
        )
        .unwrap();
        let v_o = FpVar::new_variable(
            ns.clone(),
            || Ok(plonkish_sumcheck.v_o),
            AllocationMode::Witness,
        )
        .unwrap();
        let v_m = FpVar::new_variable(
            ns.clone(),
            || Ok(plonkish_sumcheck.v_m),
            AllocationMode::Witness,
        )
        .unwrap();
        let v_l = FpVar::new_variable(
            ns.clone(),
            || Ok(plonkish_sumcheck.v_l),
            AllocationMode::Witness,
        )
        .unwrap();
        let v_r = FpVar::new_variable(
            ns.clone(),
            || Ok(plonkish_sumcheck.v_r),
            AllocationMode::Witness,
        )
        .unwrap();
        let v_c = FpVar::new_variable(
            ns.clone(),
            || Ok(plonkish_sumcheck.v_c),
            AllocationMode::Witness,
        )
        .unwrap();
        let eq = EqPolynomialVar::new_variable(ns.clone(), || Ok(eq_poly), AllocationMode::Witness)
            .unwrap();

        let challenge_point_var: Vec<FpVar<F>> = plonkish_sumcheck
            .challenge_points
            .iter()
            .map(|point| FpVar::new_variable(ns.clone(), || Ok(point), AllocationMode::Witness))
            .map(Result::unwrap)
            .collect();
        let final_claim = eq.evaluate(&challenge_point_var);

        Self {
            v_a,
            v_b,
            v_zc,
            v_o,
            v_m,
            v_l,
            v_r,
            v_c,
            final_claim,
            challenge_point_var,
        }
    }

    pub fn claim_as_vec(&self) -> Vec<FpVar<F>> {
        vec![
            self.v_a.clone(),
            self.v_b.clone(),
            self.v_zc.clone(),
            self.v_o.clone(),
            self.v_m.clone(),
            self.v_l.clone(),
            self.v_r.clone(),
            self.v_c.clone(),
        ]
    }

    pub fn compute_final_claim_noeq(&self) -> FpVar<F> {
        self.v_l.clone() * self.v_a.clone()
            + self.v_r.clone() * self.v_b.clone()
            + self.v_zc.clone() * self.v_o.clone()
            + self.v_m.clone() * self.v_a.clone() * self.v_b.clone()
            + self.v_c.clone()
    }
}

pub struct PlonkishSumcheckVar<F>
where
    F: PrimeField + Absorb,
{
    sumcheck: SumcheckCircuitVar<F>,
    plonkish_claim: PlonkishClaim<F>,
}

impl<F: PrimeField + Absorb> PlonkishSumcheckVar<F> {
    pub fn new(
        cs: impl Into<Namespace<F>>,
        plonkish_sumcheck: &PlonkishSumcheckResult<F>,
        transcript: &mut TranscriptVar<F>,
    ) -> Self {
        let compressed_uni_polys = plonkish_sumcheck
            .polys
            .iter()
            .map(|poly| poly.compress())
            .collect();
        let sumcheck_circuit: SumcheckCircuit<F> = SumcheckCircuit {
            compressed_polys: compressed_uni_polys,
            claim: plonkish_sumcheck.final_claim(),
            num_rounds: PLONKISH_N_ROUNDS,
            degree_bound: PLONKISH_DEGREE,
        };
        let ns = cs.into();
        let sumcheck = SumcheckCircuitVar::new_variable(
            ns.clone(),
            || Ok(sumcheck_circuit),
            AllocationMode::Witness,
        )
        .unwrap();

        sumcheck.verify(transcript);

        let eq_poly = EqPolynomial::new(plonkish_sumcheck.challenge_points.clone());

        let plonkish_claim_var = PlonkishClaim::new(ns.clone(), plonkish_sumcheck, eq_poly);
        sumcheck
            .claim
            .enforce_equal(&plonkish_claim_var.final_claim);

        Self {
            sumcheck,
            plonkish_claim: plonkish_claim_var,
        }
    }
}
/*

#[derive(Debug, Clone)]
pub struct AddrMSumcheckResult<F: PrimeField + Absorb> {
    pub(crate) polys: Vec<UniPoly<F>>,
    pub(crate) claims_per_round: Vec<F>,
    pub(crate) challenge_points: Vec<F>,
    pub(crate) addr_a_evals: Vec<F>,
    pub(crate) addr_b_evals: Vec<F>,
    pub(crate) addr_c_evals: Vec<F>,
    pub(crate) z_eval: F,
}

*/
pub struct AddrClaim<F: PrimeField + Absorb> {
    addr_a_prod: FpVar<F>,
    addr_b_prod: FpVar<F>,
    addr_c_prod: FpVar<F>,
    z_eval: FpVar<F>,
    w_eval: FpVar<F>,
    final_claim: FpVar<F>,
}

impl<F: PrimeField + Absorb> AddrClaim<F> {
    pub fn new(
        cs: impl Into<Namespace<F>>,
        addr_sumcheck: &AddrMSumcheckResult<F>,
        challenge_rho: &FpVar<F>,
        eq_polynomial: EqPolynomial<F>,
    ) -> Self {
        let ns = cs.into();
        let addr_a_evals_prod: FpVar<F> = addr_sumcheck
            .addr_a_evals
            .iter()
            .map(|eval| {
                FpVar::new_variable(ns.clone(), || Ok(eval), AllocationMode::Witness).unwrap()
            })
            .reduce(|acc, eval| acc * eval)
            .unwrap();
        let addr_b_evals_prod: FpVar<F> = addr_sumcheck
            .addr_b_evals
            .iter()
            .map(|eval| {
                FpVar::new_variable(ns.clone(), || Ok(eval), AllocationMode::Witness).unwrap()
            })
            .reduce(|acc, eval| acc * eval)
            .unwrap();
        let addr_c_evals_prod: FpVar<F> = addr_sumcheck
            .addr_c_evals
            .iter()
            .map(|eval| {
                FpVar::new_variable(ns.clone(), || Ok(eval), AllocationMode::Witness).unwrap()
            })
            .reduce(|acc, eval| acc * eval)
            .unwrap();

        let z_eval = FpVar::new_variable(
            ns.clone(),
            || Ok(addr_sumcheck.z_eval),
            AllocationMode::Witness,
        )
        .unwrap();

        let w_eval = FpVar::new_variable(
            ns.clone(),
            || Ok(addr_sumcheck.w_eval),
            AllocationMode::Witness,
        )
        .unwrap();

        let eq_var = EqPolynomialVar::new_variable(
            ns.clone(),
            || Ok(eq_polynomial),
            AllocationMode::Witness,
        )
        .unwrap();

        let challenge_point: Vec<FpVar<F>> = addr_sumcheck
            .challenge_points
            .iter()
            .map(|point| FpVar::new_variable(ns.clone(), || Ok(point), AllocationMode::Witness))
            .map(Result::unwrap)
            .collect();

        let eq_eval = eq_var.evaluate(&challenge_point);

        let final_claim_g = (addr_a_evals_prod.clone()
            + addr_b_evals_prod.clone() * challenge_rho
            + addr_c_evals_prod.clone() * challenge_rho.square().unwrap())
            * w_eval.clone();
        let final_claim = eq_eval * final_claim_g;

        Self {
            addr_a_prod: addr_a_evals_prod,
            addr_b_prod: addr_b_evals_prod,
            addr_c_prod: addr_c_evals_prod,
            z_eval,
            final_claim,
            w_eval,
        }
    }
}

pub struct AddrSumcheckVar<F: PrimeField + Absorb> {
    sumcheck: SumcheckCircuitVar<F>,
    addr_claim: AddrClaim<F>,
    final_claim: FpVar<F>,
    challenge: Vec<FpVar<F>>,
}

impl<F: PrimeField + Absorb> AddrSumcheckVar<F> {
    pub fn new(
        cs: impl Into<Namespace<F>>,
        addr_sumcheck: &AddrMSumcheckResult<F>,
        addr_claim: AddrClaim<F>,
        eq_poly: EqPolynomial<F>,
        challenge_rho: &FpVar<F>,
        transcript: &mut TranscriptVar<F>,
    ) -> Self {
        let compressed_uni_polys = addr_sumcheck
            .polys
            .iter()
            .map(|poly| poly.compress())
            .collect();
        let sumcheck_circuit: SumcheckCircuit<F> = SumcheckCircuit {
            compressed_polys: compressed_uni_polys,
            claim: addr_sumcheck.final_claim(),
            num_rounds: ADDR_N_ROUNDS,
            degree_bound: ADDR_DEGREE,
        };
        let ns = cs.into();
        let sumcheck = SumcheckCircuitVar::new_variable(
            ns.clone(),
            || Ok(sumcheck_circuit),
            AllocationMode::Witness,
        )
        .unwrap();

        let (final_claim, challenge) = sumcheck.verify(transcript);

        let addr_claim_var = AddrClaim::new(ns.clone(), addr_sumcheck, challenge_rho, eq_poly);
        sumcheck.claim.enforce_equal(&addr_claim_var.final_claim);

        Self {
            sumcheck,
            addr_claim: addr_claim_var,
            final_claim,
            challenge,
        }
    }
}

pub struct SSFragmentVar<
    F: PrimeField + Absorb,
    F2: PrimeField + Absorb,
    G: CurveGroup<ScalarField = F, BaseField = F2>,
> {
    plonkish_sumcheck: PlonkishSumcheckVar<F>,
    addr_sumcheck: AddrSumcheckVar<F>,
    plonkish_rlc: ScalarRLCVar<F>,
    circuit_comm: SSCCommitmentVar<F, F2>,
    circuit_hash: FpVar<F>,
    instance: Vec<FpVar<F>>,
    _g: PhantomData<G>,
}

impl<
        F: PrimeField + Absorb,
        F2: PrimeField + Absorb,
        G: CurveGroup<ScalarField = F, BaseField = F2>,
    > SSFragmentVar<F, F2, G>
{
    pub fn new<C: Commitment<G>>(
        cs: &mut ConstraintSystemRef<F>,
        ssfragment: SpeedySpartanFragment<G, F, C>,
        plonkish_result: &PlonkishSumcheckResult<F>,
        addr_result: &AddrMSumcheckResult<F>,
        plonkish_commitments: &PlonkishCommitments<F, G, C>,
        instance: &PlonkishInstance<F, G, C>,
        transcript: &mut TranscriptVar<F>,
    ) -> Self {
        let ns = cs.into();
        // Get the instance into a variable:
        let instance_var: Vec<FpVar<F>> = instance
            .instance
            .iter()
            .take(INSTANCE_SIZE)
            .map(|instance_felt| FpVar::new_input(cs, || Ok(instance_felt)).unwrap())
            .collect();

        // Allocate the commitments; not native here, just used for hashing:
        //TODO: Commit witness!
        let n_rounds_tau = plonkish_result.claims_per_round.len();
        let comms_nn = SSCCommitmentVar::new(ns.clone(), plonkish_commitments);
        let commitment_hash = comms_nn.hash(cs.into());

        // bind the first variable of the instance to the self hash:
        instance_var[SELF_HASH].enforce_equal(&commitment_hash);
        let tau: Vec<FpVar<F>> = (0..n_rounds_tau)
            .into_iter()
            .map(|_idx| transcript.challenge_scalar(b"tau"))
            .collect();
        // Verify the plonkish sumcheck
        let plonkish_sumcheck_var =
            PlonkishSumcheckVar::new(ns.clone(), plonkish_result, transcript);

        let plonkish_challenge = transcript.challenge_scalar(b"plonkish challenge");
        let plonkish_rlc = ScalarRLCVar::new(
            cs,
            plonkish_sumcheck_var.plonkish_claim.claim_as_vec(),
            plonkish_challenge,
        );

        // Enforce that the final claim of the plonkish sumcheck is comprised correctly of the multilinear evals
        let eq_poly_plonkish = EqPolynomialVar::new(tau);
        let plonkish_no_eq = plonkish_sumcheck_var
            .plonkish_claim
            .compute_final_claim_noeq();
        let eq_eval =
            eq_poly_plonkish.evaluate(&plonkish_sumcheck_var.plonkish_claim.challenge_point_var);
        let plonkish_claim = eq_eval * plonkish_no_eq;
        plonkish_claim.enforce_equal(&plonkish_sumcheck_var.plonkish_claim.final_claim);

        // Move on to ADDR phase:
        // Draw challenge for combining claims
        let challenge_rho_addr = transcript.challenge_scalar(b"addr challenge");

        // Need to make an eq poly from plonkish:
        let eq_poly_plonkish_nonvar = EqPolynomial::new(plonkish_result.challenge_points.clone());

        // Form the compressed addr claim
        let addr_claim = AddrClaim::new(
            ns.clone(),
            addr_result,
            &challenge_rho_addr,
            eq_poly_plonkish_nonvar.clone(),
        );

        // Verify the addr sumcheck
        let addr_sumcheck_var = AddrSumcheckVar::new(
            ns.clone(),
            addr_result,
            addr_claim,
            eq_poly_plonkish_nonvar.clone(),
            &challenge_rho_addr,
            transcript,
        );

        let z_claim_reconstructed = concat_mle_claim(
            addr_sumcheck_var.challenge,
            addr_claim.w_eval,
            &instance_var,
        )
        .unwrap();
        z_claim_reconstructed.enforce_equal(addr_claim.z_eval);

        let sigma_rerand = transcript.challenge_scalar(b"sigma_fold");
        let eq_plonkish =
            EqPolynomialVar::new(plonkish_sumcheck_var.plonkish_claim.challenge_point_var);
        let eq_addr = EqPolynomialVar::new(addr_sumcheck_var.challenge);
        let eqs = vec![eq_plonkish, eq_addr];
        // Now need to verify the rerandomization sumcheck
        let rerand_verifier = RerandSumcheck::new(
            cs.into(),
            &ssfragment.rerand_fold.sumcheck.clone(),
            eqs,
            sigma_rerand,
            transcript,
        );
        Self {
            plonkish_sumcheck: plonkish_sumcheck_var,
            addr_sumcheck: addr_sumcheck_var,
            plonkish_rlc,
            circuit_comm: comms_nn,
            _g: PhantomData,
            circuit_hash: commitment_hash,
            instance: instance_var,
        }
    }
}
