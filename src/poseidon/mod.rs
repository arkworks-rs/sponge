use crate::{Absorbable, CryptographicSponge, SpongeExt};
use ark_ff::{BigInteger, FpParameters, PrimeField};
use ark_std::vec;
use ark_std::vec::Vec;
use rand_core::SeedableRng;

/// constraints for Poseidon
#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Clone)]
enum PoseidonSpongeMode {
    Absorbing { next_absorb_index: usize },
    Squeezing { next_squeeze_index: usize },
}

#[derive(Clone)]
/// the sponge for Poseidon
///
/// This implementation of Poseidon is entirely from Fractal's implementation in [COS20][cos]
/// with small syntax changes.
///
/// [cos]: https://eprint.iacr.org/2019/1076
pub struct PoseidonSponge<F: PrimeField> {
    /// number of rounds in a full-round operation
    full_rounds: u32,
    /// number of rounds in a partial-round operation
    partial_rounds: u32,
    /// Exponent used in S-boxes
    alpha: u64,
    /// Additive Round keys. These are added before each MDS matrix application to make it an affine shift.
    /// They are indexed by `ark[round_num][state_element_index]`
    ark: Vec<Vec<F>>,
    /// Maximally Distance Separating Matrix.
    mds: Vec<Vec<F>>,

    /// the sponge's state
    state: Vec<F>,
    /// the rate
    rate: usize,
    /// the capacity
    capacity: usize,
    /// the mode
    mode: PoseidonSpongeMode,
}

impl<F: PrimeField> PoseidonSponge<F> {
    fn apply_s_box(&self, state: &mut [F], is_full_round: bool) {
        // Full rounds apply the S Box (x^alpha) to every element of state
        if is_full_round {
            for elem in state {
                *elem = elem.pow(&[self.alpha]);
            }
        }
        // Partial rounds apply the S Box (x^alpha) to just the final element of state
        else {
            state[state.len() - 1] = state[state.len() - 1].pow(&[self.alpha]);
        }
    }

    fn apply_ark(&self, state: &mut [F], round_number: usize) {
        for (i, state_elem) in state.iter_mut().enumerate() {
            state_elem.add_assign(&self.ark[round_number][i]);
        }
    }

    fn apply_mds(&self, state: &mut [F]) {
        let mut new_state = Vec::new();
        for i in 0..state.len() {
            let mut cur = F::zero();
            for (j, state_elem) in state.iter().enumerate() {
                let term = state_elem.mul(&self.mds[i][j]);
                cur.add_assign(&term);
            }
            new_state.push(cur);
        }
        state.clone_from_slice(&new_state[..state.len()])
    }

    fn permute(&mut self) {
        let full_rounds_over_2 = self.full_rounds / 2;
        let mut state = self.state.clone();
        for i in 0..full_rounds_over_2 {
            self.apply_ark(&mut state, i as usize);
            self.apply_s_box(&mut state, true);
            self.apply_mds(&mut state);
        }

        for i in full_rounds_over_2..(full_rounds_over_2 + self.partial_rounds) {
            self.apply_ark(&mut state, i as usize);
            self.apply_s_box(&mut state, false);
            self.apply_mds(&mut state);
        }

        for i in
            (full_rounds_over_2 + self.partial_rounds)..(self.partial_rounds + self.full_rounds)
        {
            self.apply_ark(&mut state, i as usize);
            self.apply_s_box(&mut state, true);
            self.apply_mds(&mut state);
        }
        self.state = state;
    }

    // Absorbs everything in elements, this does not end in an absorbtion.
    fn absorb_internal(&mut self, rate_start_index: usize, elements: &[F]) {
        // if we can finish in this call
        if rate_start_index + elements.len() <= self.rate {
            for (i, element) in elements.iter().enumerate() {
                self.state[i + rate_start_index] += element;
            }
            self.mode = PoseidonSpongeMode::Absorbing {
                next_absorb_index: rate_start_index + elements.len(),
            };

            return;
        }
        // otherwise absorb (rate - rate_start_index) elements
        let num_elements_absorbed = self.rate - rate_start_index;
        for (i, element) in elements.iter().enumerate().take(num_elements_absorbed) {
            self.state[i + rate_start_index] += element;
        }
        self.permute();
        // Tail recurse, with the input elements being truncated by num elements absorbed
        self.absorb_internal(0, &elements[num_elements_absorbed..]);
    }

    // Squeeze |output| many elements. This does not end in a squeeze
    fn squeeze_internal(&mut self, rate_start_index: usize, output: &mut [F]) {
        // if we can finish in this call
        if rate_start_index + output.len() <= self.rate {
            output
                .clone_from_slice(&self.state[rate_start_index..(output.len() + rate_start_index)]);
            self.mode = PoseidonSpongeMode::Squeezing {
                next_squeeze_index: rate_start_index + output.len(),
            };
            return;
        }
        // otherwise squeeze (rate - rate_start_index) elements
        let num_elements_squeezed = self.rate - rate_start_index;
        output[..num_elements_squeezed].clone_from_slice(
            &self.state[rate_start_index..(num_elements_squeezed + rate_start_index)],
        );

        // Unless we are done with squeezing in this call, permute.
        if output.len() != self.rate {
            self.permute();
        }
        // Tail recurse, with the correct change to indices in output happening due to changing the slice
        self.squeeze_internal(0, &mut output[num_elements_squeezed..]);
    }
}

impl<F: PrimeField> CryptographicSponge<F> for PoseidonSponge<F> {
    fn new() -> Self {
        // Requires F to be Alt_Bn128Fr
        let full_rounds = 8;
        let partial_rounds = 31;
        let alpha = 17;

        let mds = vec![
            vec![F::one(), F::zero(), F::one()],
            vec![F::one(), F::one(), F::zero()],
            vec![F::zero(), F::one(), F::one()],
        ];

        let mut ark = Vec::new();
        let mut ark_rng = rand_chacha::ChaChaRng::seed_from_u64(123456789u64);

        for _ in 0..(full_rounds + partial_rounds) {
            let mut res = Vec::new();

            for _ in 0..3 {
                res.push(F::rand(&mut ark_rng));
            }
            ark.push(res);
        }

        let rate = 2;
        let capacity = 1;
        let state = vec![F::zero(); rate + capacity];
        let mode = PoseidonSpongeMode::Absorbing {
            next_absorb_index: 0,
        };

        Self {
            full_rounds,
            partial_rounds,
            alpha,
            ark,
            mds,

            state,
            rate,
            capacity,
            mode,
        }
    }

    fn absorb(&mut self, input: &impl Absorbable<F>) {
        let elems = input.to_sponge_field_elements();
        if elems.is_empty() {
            return;
        }

        match self.mode {
            PoseidonSpongeMode::Absorbing { next_absorb_index } => {
                let mut absorb_index = next_absorb_index;
                if absorb_index == self.rate {
                    self.permute();
                    absorb_index = 0;
                }
                self.absorb_internal(absorb_index, elems.as_slice());
            }
            PoseidonSpongeMode::Squeezing {
                next_squeeze_index: _,
            } => {
                self.permute();
                self.absorb_internal(0, elems.as_slice());
            }
        };
    }

    fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        let usable_bytes = (F::Params::CAPACITY / 8) as usize;

        let num_elements = (num_bytes + usable_bytes - 1) / usable_bytes;
        let src_elements = self.squeeze_field_elements(num_elements);

        let mut bytes: Vec<u8> = Vec::with_capacity(usable_bytes * num_elements);
        for elem in &src_elements {
            let elem_bytes = elem.into_repr().to_bytes_le();
            bytes.extend_from_slice(&elem_bytes[..usable_bytes]);
        }

        bytes.truncate(num_bytes);
        bytes
    }

    fn squeeze_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let usable_bits = F::Params::CAPACITY as usize;

        let num_elements = (num_bits + usable_bits - 1) / usable_bits;
        let src_elements = self.squeeze_field_elements(num_elements);

        let mut bits: Vec<bool> = Vec::with_capacity(usable_bits * num_elements);
        for elem in &src_elements {
            let elem_bits = elem.into_repr().to_bits_le();
            bits.extend_from_slice(&elem_bits[..usable_bits]);
        }

        bits.truncate(num_bits);
        bits
    }

    fn squeeze_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        let mut squeezed_elems = vec![F::zero(); num_elements];
        match self.mode {
            PoseidonSpongeMode::Absorbing {
                next_absorb_index: _,
            } => {
                self.permute();
                self.squeeze_internal(0, &mut squeezed_elems);
            }
            PoseidonSpongeMode::Squeezing { next_squeeze_index } => {
                let mut squeeze_index = next_squeeze_index;
                if squeeze_index == self.rate {
                    self.permute();
                    squeeze_index = 0;
                }
                self.squeeze_internal(squeeze_index, &mut squeezed_elems);
            }
        };

        squeezed_elems
    }
}

#[derive(Clone)]
/// Stores the state of a Poseidon Sponge. Does not store any parameter.
pub struct PoseidonSpongeState<F: PrimeField> {
    state: Vec<F>,
    mode: PoseidonSpongeMode,
}

impl<CF: PrimeField> SpongeExt<CF> for PoseidonSponge<CF> {
    type State = PoseidonSpongeState<CF>;

    fn from_state(state: Self::State) -> Self {
        let mut sponge = Self::new();
        sponge.mode = state.mode;
        sponge.state = state.state;
        sponge
    }

    fn into_state(self) -> Self::State {
        Self::State {
            state: self.state,
            mode: self.mode,
        }
    }
}
