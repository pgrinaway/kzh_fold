use crate::commitment::Commitment;
use crate::math::Math;
use crate::nexus_spartan::unipoly::unipoly::UniPoly;
use crate::polynomial::eq_poly::eq_poly::EqPolynomial;
use crate::polynomial::multilinear_poly::multilinear_poly::MultilinearPolynomial;
use crate::speedyspartan::folding::FoldedObject;
use crate::speedyspartan::sumchecks::rerandomization_sumcheck::{
    prove_random_combination_sumcheck, RerandSumcheckEvaluationResult,
};
use crate::speedyspartan::sumchecks::utils::{
    self, commitment_rlc, point_rlc, polynomial_rlc, scalar_rlc,
};
use crate::speedyspartan::utils::combine_eq_polys;
use crate::transcript::transcript::{AppendToTranscript, Transcript};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use digest::typenum::Abs;
use itertools::fold;
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};

#[derive(Debug, Clone)]
pub struct RerandomizationOutput<
    G: CurveGroup<ScalarField = F>,
    F: PrimeField + Absorb,
    C: Commitment<G>,
> {
    pub(crate) sumcheck: RerandSumcheckEvaluationResult<F>,
    pub(crate) folded_object: FoldedObject<G, F, C>,
}

pub fn rerandomize_fold<
    G: CurveGroup<ScalarField = F>,
    F: PrimeField + Absorb,
    C: Commitment<G>,
>(
    folded_objects: &[FoldedObject<G, F, C>],
    transcript: &mut Transcript<F>,
) -> RerandomizationOutput<G, F, C> {
    let eq_polys: Vec<EqPolynomial<F>> = folded_objects
        .iter()
        .map(|folded| folded.random_point.clone())
        .map(|challenge_point| EqPolynomial::new(challenge_point))
        .collect();

    let mut eq_polys_as_poly: Vec<MultilinearPolynomial<F>> = eq_polys
        .iter()
        .map(|poly| MultilinearPolynomial::new(poly.evals()))
        .collect();

    let sigma = transcript.challenge_scalar(b"rerandomization sumcheck rlc");

    let mut polys: Vec<MultilinearPolynomial<F>> = folded_objects
        .iter()
        .map(|folded| folded.polynomial.clone())
        .collect();

    let polys_to_fold = combine_eq_polys(&eq_polys, &polys, &sigma);
    let witness_folded_poly = polynomial_rlc(&polys_to_fold, &sigma);
    let scalar_claims: Vec<F> = folded_objects.iter().map(|folded| folded.claim).collect();
    let eq_claims: Vec<F> = eq_polys
        .iter()
        .zip(folded_objects)
        .map(|(poly, folded)| poly.evaluate(&folded.random_point))
        .collect();

    let claim_products: Vec<F> = scalar_claims
        .iter()
        .zip(eq_claims)
        .map(|(scalar, eq)| *scalar * eq)
        .collect();
    let claim = scalar_rlc(&claim_products, &sigma);

    let rerand_result = prove_random_combination_sumcheck(
        &claim,
        &mut eq_polys_as_poly,
        &mut polys,
        &sigma,
        transcript,
    );
    let commitments_to_combine: Vec<C> = folded_objects
        .iter()
        .map(|folded| folded.commitment)
        .collect();

    let commitment_rlc = commitment_rlc(&commitments_to_combine, &sigma);

    let folded_object = FoldedObject {
        challenge: sigma,
        claim,
        random_point: rerand_result.challenge_points.clone(),
        commitment: commitment_rlc,
        polynomial: witness_folded_poly,
        _marker: std::marker::PhantomData,
    };
    RerandomizationOutput {
        sumcheck: rerand_result,
        folded_object,
    }
}
