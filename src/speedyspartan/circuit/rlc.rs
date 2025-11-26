use std::marker::PhantomData;

use crate::commitment::Commitment;
use crate::constant_for_curves::{BaseField, ScalarField};
use crate::hash::poseidon::PoseidonHashVar;
use crate::nexus_spartan::sumcheck_circuit::sumcheck_circuit::SumcheckCircuit;
use crate::nexus_spartan::unipoly::unipoly_var::{CompressedUniPolyVar, UniPolyVar};
use crate::speedyspartan::plonkish::PlonkishCommitments;
use crate::transcript::transcript_var::{AppendToTranscriptVar, TranscriptVar};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::nonnative::{AllocatedNonNativeFieldVar, NonNativeFieldVar};
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::{R1CSVar, ToBitsGadget, ToConstraintFieldGadget};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, Namespace, SynthesisError};

#[derive(Clone, Debug)]
pub struct ScalarRLCVar<F>
where
    F: PrimeField + Absorb,
{
    rlc: FpVar<F>,
}

impl<F: PrimeField + Absorb> ScalarRLCVar<F> {
    pub fn new(
        cs: &mut ConstraintSystemRef<F>,
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
/*
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
        Self {
            rlc: acc,
            _g: PhantomData,
            _f: PhantomData,
        }
    }
}*/

#[derive(Debug, Clone)]
pub struct ForeignPoint<F1: PrimeField + Absorb, F2: PrimeField + Absorb> {
    x: NonNativeFieldVar<F2, F1>,
    y: NonNativeFieldVar<F2, F1>,
}
impl<F1: PrimeField + Absorb, F2: PrimeField + Absorb> ForeignPoint<F1, F2> {
    pub fn underlying_elements(&self) -> Vec<FpVar<F1>> {
        let mut underlying: Vec<FpVar<F1>> = vec![];

        underlying.extend_from_slice(&self.x.to_constraint_field().unwrap());
        underlying.extend_from_slice(&self.y.to_constraint_field().unwrap());

        underlying
    }

    pub fn new_public(cs: &mut ConstraintSystemRef<F1>, point_x: F2, point_y: F2) -> Self {
        let x = NonNativeFieldVar::new_variable(cs.clone(), || Ok(point_x), AllocationMode::Input)
            .unwrap();
        let y = NonNativeFieldVar::new_variable(cs.clone(), || Ok(point_y), AllocationMode::Input)
            .unwrap();
        Self { x, y }
    }

    pub fn new_witness(cs: impl Into<Namespace<F1>>, point_x: F2, point_y: F2) -> Self {
        let ns = cs.into();
        let x =
            NonNativeFieldVar::new_variable(ns.clone(), || Ok(point_x), AllocationMode::Witness)
                .unwrap();
        let y =
            NonNativeFieldVar::new_variable(ns.clone(), || Ok(point_y), AllocationMode::Witness)
                .unwrap();
        Self { x, y }
    }
}

// Container for the circuit commitments (not witness)
#[derive(Debug, Clone)]
pub struct SSCCommitmentVar<F1: PrimeField + Absorb, F2: PrimeField + Absorb> {
    q_l: ForeignPoint<F1, F2>,
    q_r: ForeignPoint<F1, F2>,
    q_o: ForeignPoint<F1, F2>,
    q_m: ForeignPoint<F1, F2>,
    q_c: ForeignPoint<F1, F2>,
    addr_A: Vec<ForeignPoint<F1, F2>>,
    addr_B: Vec<ForeignPoint<F1, F2>>,
    addr_C: Vec<ForeignPoint<F1, F2>>,
}

impl<F1: PrimeField + Absorb, F2: PrimeField + Absorb> SSCCommitmentVar<F1, F2> {
    pub fn hash(&self, cs: impl Into<Namespace<F1>>) -> FpVar<F1> {
        let ns = cs.into();
        let mut hasher = PoseidonHashVar::new(ns.clone());
        let mut elts_for_hashing: Vec<FpVar<F1>> = vec![];
        // Absorb each foreign point into the hash:
        hasher.update_sponge(self.q_l.underlying_elements());
        hasher.update_sponge(self.q_r.underlying_elements());
        hasher.update_sponge(self.q_o.underlying_elements());
        hasher.update_sponge(self.q_m.underlying_elements());
        hasher.update_sponge(self.q_c.underlying_elements());
        for addr_pts in [
            self.addr_A.clone(),
            self.addr_B.clone(),
            self.addr_C.clone(),
        ]
        .iter()
        {
            for point in addr_pts {
                hasher.update_sponge(point.underlying_elements());
            }
        }
        hasher.output()
    }

    pub fn commitment_to_foreign<
        G: CurveGroup<ScalarField = F1, BaseField = F2>,
        C: Commitment<G>,
    >(
        cs: impl Into<Namespace<F1>>,
        commitment: &C,
    ) -> ForeignPoint<F1, F2> {
        let point = commitment.into_affine();
        let x = point.x().unwrap();
        let y = point.y().unwrap();
        ForeignPoint::new_witness(cs.into(), x, y)
    }

    pub fn new<G: CurveGroup<ScalarField = F1, BaseField = F2>, C: Commitment<G>>(
        cs: impl Into<Namespace<F1>>,
        plonkish_commitment: &PlonkishCommitments<F1, G, C>,
    ) -> Self {
        let ns = cs.into();
        let q_l = Self::commitment_to_foreign(ns.clone(), &plonkish_commitment.q_l);
        let q_r = Self::commitment_to_foreign(ns.clone(), &plonkish_commitment.q_r);
        let q_o = Self::commitment_to_foreign(ns.clone(), &plonkish_commitment.q_o);
        let q_m = Self::commitment_to_foreign(ns.clone(), &plonkish_commitment.q_m);
        let q_c = Self::commitment_to_foreign(ns.clone(), &plonkish_commitment.q_c);

        let addr_A: Vec<ForeignPoint<F1, F2>> = plonkish_commitment
            .addr_A
            .iter()
            .map(|c| Self::commitment_to_foreign(ns.clone(), c))
            .collect();

        let addr_B: Vec<ForeignPoint<F1, F2>> = plonkish_commitment
            .addr_B
            .iter()
            .map(|c| Self::commitment_to_foreign(ns.clone(), c))
            .collect();

        let addr_C: Vec<ForeignPoint<F1, F2>> = plonkish_commitment
            .addr_C
            .iter()
            .map(|c| Self::commitment_to_foreign(ns.clone(), c))
            .collect();

        Self {
            q_l,
            q_r,
            q_o,
            q_m,
            q_c,
            addr_A,
            addr_B,
            addr_C,
        }
    }
}
