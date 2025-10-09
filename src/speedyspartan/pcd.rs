use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::{
    commitment::Commitment,
    speedyspartan::{
        folding::FoldedObject,
        rerandomization::{rerandomize_fold, RerandomizationOutput},
    },
    transcript::transcript::Transcript,
};

pub fn fold_two_running<
    G: CurveGroup<ScalarField = F>,
    F: PrimeField + Absorb,
    C: Commitment<G>,
>(
    running_a: &FoldedObject<G, F, C>,
    running_b: &FoldedObject<G, F, C>,
    transcript: &mut Transcript<F>,
) -> FoldedObject<G, F, C> {
    rerandomize_fold(&[running_a.clone(), running_b.clone()], transcript);
    todo!()
}
