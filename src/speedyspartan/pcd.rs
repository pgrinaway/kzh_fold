use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::{
    commitment::Commitment,
    speedyspartan::{
        folding::FoldedObject,
        rerandomization::{rerandomize_fold, RerandomizationOutput},
        snark::SpeedySpartanFragment,
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
    let rerand_fold = rerandomize_fold(&[running_a.clone(), running_b.clone()], transcript);
    // TODO: verifier circuit
    todo!()
}

pub fn fold_two_fragments<
    G: CurveGroup<ScalarField = F>,
    F: PrimeField + Absorb,
    C: Commitment<G>,
>(
    fragment_a: &SpeedySpartanFragment<G, F, C>,
    fragment_b: &SpeedySpartanFragment<G, F, C>,
    transcript: &mut Transcript<F>,
) {
    let folded_rerandomization = rerandomize_fold(
        &[
            fragment_a.plonkish_fold.clone(),
            fragment_a.addr_fold.clone(),
            fragment_b.plonkish_fold.clone(),
            fragment_b.addr_fold.clone(),
        ],
        transcript,
    );
    //TODO: Verifier circuit
    todo!()
}
