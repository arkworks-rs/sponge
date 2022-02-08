//! Define the permute logic for Poseidon hash function.

use ark_std::fmt::Debug;
use ark_std::marker::PhantomData;
use ark_ff::PrimeField;
use crate::poseidon::PoseidonParameters;

pub trait PoseidonPermute<F: PrimeField>: Clone + Debug {
    fn permute(state: &mut [F], parameters: &PoseidonParameters<F>);
}

/// `Permute` without any optimization.
#[derive(Clone, Debug)]
pub struct CorrectPermute<F: PrimeField> {
    _field: PhantomData<F>
}

impl<F: PrimeField> CorrectPermute<F> {
    fn apply_s_box(parameters: &PoseidonParameters<F>, state: &mut [F], is_full_round: bool) {
        // Full rounds apply the S Box (x^alpha) to every element of state
        if is_full_round {
            for elem in state {
                *elem = elem.pow(&[parameters.alpha]);
            }
        }
        // Partial rounds apply the S Box (x^alpha) to just the first element of state
        else {
            state[0] = state[0].pow(&[parameters.alpha]);
        }
    }

    fn apply_ark(parameters: &PoseidonParameters<F>,  state: &mut [F], round_number: usize) {
        for (i, state_elem) in state.iter_mut().enumerate() {
            state_elem.add_assign(&parameters.ark[round_number][i]);
        }
    }

    fn apply_mds(parameters: &PoseidonParameters<F>,  state: &mut [F]) {
        let mut new_state = Vec::new();
        for i in 0..state.len() {
            let mut cur = F::zero();
            for (j, state_elem) in state.iter().enumerate() {
                let term = state_elem.mul(&parameters.mds[i][j]);
                cur.add_assign(&term);
            }
            new_state.push(cur);
        }
        state.clone_from_slice(&new_state[..state.len()])
    }
}

impl<F: PrimeField> PoseidonPermute<F> for CorrectPermute<F> {

    fn permute(state: &mut [F], parameters: &PoseidonParameters<F>) {
        let full_rounds_over_2 = parameters.full_rounds / 2;
        let mut state_cloned = state.to_vec();
        for i in 0..full_rounds_over_2 {
            Self::apply_ark(parameters, &mut state_cloned, i);
            Self::apply_s_box(parameters, &mut state_cloned, true);
            Self::apply_mds(parameters, &mut state_cloned);
        }

        for i in full_rounds_over_2..(full_rounds_over_2 + parameters.partial_rounds) {
            Self::apply_ark(parameters, &mut state_cloned, i);
            Self::apply_s_box(parameters, &mut state_cloned, false);
            Self::apply_mds(parameters, &mut state_cloned);
        }

        for i in (full_rounds_over_2 + parameters.partial_rounds)
            ..(parameters.partial_rounds + parameters.full_rounds)
        {
            Self::apply_ark(parameters, &mut state_cloned, i);
            Self::apply_s_box(parameters, &mut state_cloned, true);
            Self::apply_mds(parameters, &mut state_cloned);
        }
        state.clone_from_slice(&state_cloned);
    }
}

