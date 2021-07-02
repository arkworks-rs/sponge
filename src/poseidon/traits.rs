use crate::poseidon::PoseidonParameters;
use ark_ff::{fields::models::*, FpParameters, PrimeField};
use ark_relations::r1cs::OptimizationGoal;

/// A trait for default Poseidon parameters associated with a prime field
pub trait PoseidonDefaultParameters: FpParameters {
    /// An array of the parameters optimized for constraints
    /// (rate, alpha, full_rounds, partial_rounds)
    /// for rate = 2, 3, 4, 5, 6, 7, 8
    const PARAMS_OPT_FOR_CONSTRAINTS: [[usize; 4]; 7];
    /* example
    ```
    [
        [2, 3, 8, 31],
        [3, 3, 8, 31],
        [4, 3, 8, 31],
        [5, 3, 8, 31],
        [6, 3, 8, 31],
        [7, 3, 8, 31],
        [8, 3, 8, 31],
    ]
    ```
    */

    /// An array of the parameters optimized for weights
    /// (rate, alpha, full_rounds, partial_rounds)
    /// for rate = 2, 3, 4, 5, 6, 7, 8
    const PARAMS_OPT_FOR_WEIGHTS: [[usize; 4]; 7];

    /// A Grain PRNG seed that has been tested to generate
    /// good matrices for all the cases above
    const GRAIN_PRNG_SEED: [u8; 10];
}

/// A field with Poseidon parameters associated
pub trait PoseidonDefaultParametersField: PrimeField {
    /// Obtain the default Poseidon parameters for this rate and for this prime field,
    /// with a specific optimization goal.
    fn default_poseidon_parameters(
        rate: u64,
        optimization_goal: OptimizationGoal,
    ) -> PoseidonParameters<Self>;
}

macro_rules! impl_poseidon_default_parameters_field {
    ($field: ident, $params: ident) => {
        impl<P: $params + PoseidonDefaultParameters> PoseidonDefaultParametersField for $field<P> {
            fn default_poseidon_parameters(
                _rate: u64,
                _optimization_goal: OptimizationGoal,
            ) -> PoseidonParameters<Self> {
                unimplemented!()
            }
        }
    };
}

impl_poseidon_default_parameters_field!(Fp64, Fp64Parameters);
impl_poseidon_default_parameters_field!(Fp256, Fp256Parameters);
impl_poseidon_default_parameters_field!(Fp320, Fp320Parameters);
impl_poseidon_default_parameters_field!(Fp384, Fp384Parameters);
impl_poseidon_default_parameters_field!(Fp448, Fp448Parameters);
impl_poseidon_default_parameters_field!(Fp768, Fp768Parameters);
impl_poseidon_default_parameters_field!(Fp832, Fp832Parameters);
