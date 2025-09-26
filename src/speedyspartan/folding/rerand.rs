use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::commitment::Commitment;

pub fn fold_rerand<G: CurveGroup<ScalarField = F>, F: PrimeField + Absorb, C: Commitment<G>>() {
    todo!()
}
