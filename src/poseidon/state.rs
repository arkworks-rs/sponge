use ark_ff::PrimeField;
use std::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
};

use super::Parameters;

#[derive(Clone)]
/// A raw Poseidon state, with direct access to the permutation.
///
/// This is a lower-level API than
/// [`poseidon::Sponge`](crate::poseidon::Sponge), which builds a duplex
/// construction.
///
/// A new state is constructed from a [`Parameters`] instance using [`From`] or
/// [`Into`].  The state itself can be accessed and updated using [`Index`] and
/// [`IndexMut`] or [`AsRef`] and [`AsMut`].
pub struct State<F: PrimeField> {
    // Use a Box<[F]> rather than Vec<F> because the state is not resizable.
    state: Box<[F]>,
    parameters: Parameters<F>,
}

impl<F: PrimeField> From<Parameters<F>> for State<F> {
    fn from(parameters: Parameters<F>) -> Self {
        let state = vec![F::zero(); parameters.capacity + parameters.rate].into_boxed_slice();
        Self { state, parameters }
    }
}

impl<F, I> Index<I> for State<F>
where
    F: PrimeField,
    I: SliceIndex<[F]>,
{
    type Output = <I as SliceIndex<[F]>>::Output;
    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        self.state.index(index)
    }
}

impl<F, I> IndexMut<I> for State<F>
where
    F: PrimeField,
    I: SliceIndex<[F]>,
{
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        self.state.index_mut(index)
    }
}

impl<F: PrimeField> AsRef<[F]> for State<F> {
    #[inline]
    fn as_ref(&self) -> &[F] {
        self.state.as_ref()
    }
}

impl<F: PrimeField> AsMut<[F]> for State<F> {
    #[inline]
    fn as_mut(&mut self) -> &mut [F] {
        self.state.as_mut()
    }
}

impl<F: PrimeField> State<F> {
    fn apply_s_box(&mut self, is_full_round: bool) {
        // Full rounds apply the S Box (x^alpha) to every element of state
        if is_full_round {
            for elem in self.state.iter_mut() {
                *elem = elem.pow(&[self.parameters.alpha]);
            }
        }
        // Partial rounds apply the S Box (x^alpha) to just the first element of state
        else {
            self.state[0] = self.state[0].pow(&[self.parameters.alpha]);
        }
    }

    fn apply_ark(&mut self, round_number: usize) {
        for (i, state_elem) in self.state.iter_mut().enumerate() {
            state_elem.add_assign(&self.parameters.ark[round_number][i]);
        }
    }

    fn apply_mds(&mut self) {
        let mut new_state = Vec::with_capacity(self.state.len());
        for i in 0..self.state.len() {
            let mut cur = F::zero();
            for (j, state_elem) in self.state.iter().enumerate() {
                let term = state_elem.mul(&self.parameters.mds[i][j]);
                cur.add_assign(&term);
            }
            new_state.push(cur);
        }
        self.state = new_state.into_boxed_slice();
    }

    /// Runs the permutation, updating the state.
    pub fn permute(&mut self) {
        let full_rounds_over_2 = self.parameters.full_rounds / 2;
        for i in 0..full_rounds_over_2 {
            self.apply_ark(i);
            self.apply_s_box(true);
            self.apply_mds();
        }

        for i in full_rounds_over_2..(full_rounds_over_2 + self.parameters.partial_rounds) {
            self.apply_ark(i);
            self.apply_s_box(false);
            self.apply_mds();
        }

        for i in (full_rounds_over_2 + self.parameters.partial_rounds)
            ..(self.parameters.partial_rounds + self.parameters.full_rounds)
        {
            self.apply_ark(i);
            self.apply_s_box(true);
            self.apply_mds();
        }
    }

    /// Returns the rate of the permutation.
    pub fn rate(&self) -> usize {
        self.parameters.rate
    }

    /// Returns the capacity of the permutation.
    pub fn capacity(&self) -> usize {
        self.parameters.capacity
    }
}
