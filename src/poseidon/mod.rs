use crate::{
    batch_field_cast, squeeze_field_elements_with_sizes_default_impl, Absorb, CryptographicSponge,
    FieldBasedCryptographicSponge, FieldElementSize, SpongeExt,
};
use ark_ff::{BigInteger, FpParameters, PrimeField};
use ark_std::any::TypeId;
use ark_std::rand::Rng;
use ark_std::vec;
use ark_std::vec::Vec;

/// constraints for Poseidon
#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(test)]
mod tests;

#[derive(Clone)]
enum PoseidonSpongeMode {
    Absorbing { next_absorb_index: usize },
    Squeezing { next_squeeze_index: usize },
}

#[derive(Clone)]
/// A duplex sponge based using the Poseidon permutation.
///
/// This implementation of Poseidon is entirely from Fractal's implementation in [COS20][cos]
/// with small syntax changes.
///
/// [cos]: https://eprint.iacr.org/2019/1076
pub struct PoseidonSponge<F: PrimeField> {
    // Sponge Parameters
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
    /// the rate (in terms of number of field elements)
    rate: usize,
    /// the capacity (in terms of number of field elements)
    capacity: usize,

    // Sponge State
    /// current sponge's state (current elements in the permutation block)
    state: Vec<F>,
    /// current mode (whether its absorbing or squeezing)
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
    fn absorb_internal(&mut self, mut rate_start_index: usize, elements: &[F]) {
        let mut remaining_elements = elements;

        loop {
            // if we can finish in this call
            if rate_start_index + remaining_elements.len() <= self.rate {
                for (i, element) in remaining_elements.iter().enumerate() {
                    self.state[i + rate_start_index] += element;
                }
                self.mode = PoseidonSpongeMode::Absorbing {
                    next_absorb_index: rate_start_index + remaining_elements.len(),
                };

                return;
            }
            // otherwise absorb (rate - rate_start_index) elements
            let num_elements_absorbed = self.rate - rate_start_index;
            for (i, element) in remaining_elements
                .iter()
                .enumerate()
                .take(num_elements_absorbed)
            {
                self.state[i + rate_start_index] += element;
            }
            self.permute();
            // the input elements got truncated by num elements absorbed
            remaining_elements = &remaining_elements[num_elements_absorbed..];
            rate_start_index = 0;
        }
    }

    // Squeeze |output| many elements. This does not end in a squeeze
    fn squeeze_internal(&mut self, mut rate_start_index: usize, output: &mut [F]) {
        let mut output_remaining = output;
        loop {
            // if we can finish in this call
            if rate_start_index + output_remaining.len() <= self.rate {
                output_remaining.clone_from_slice(
                    &self.state[rate_start_index..(output_remaining.len() + rate_start_index)],
                );
                self.mode = PoseidonSpongeMode::Squeezing {
                    next_squeeze_index: rate_start_index + output_remaining.len(),
                };
                return;
            }
            // otherwise squeeze (rate - rate_start_index) elements
            let num_elements_squeezed = self.rate - rate_start_index;
            output_remaining[..num_elements_squeezed].clone_from_slice(
                &self.state[rate_start_index..(num_elements_squeezed + rate_start_index)],
            );

            // Unless we are done with squeezing in this call, permute.
            if output_remaining.len() != self.rate {
                self.permute();
            }
            // Repeat with updated output slices
            output_remaining = &mut output_remaining[num_elements_squeezed..];
            rate_start_index = 0;
        }
    }
}

/// Parameters and RNG used
#[derive(Clone, Debug)]
pub struct PoseidonParameters<F: PrimeField> {
    full_rounds: u32,
    partial_rounds: u32,
    alpha: u64,
    mds: Vec<Vec<F>>,
    ark: Vec<Vec<F>>,
}

impl<F: PrimeField> PoseidonParameters<F> {
    /// Initialize the parameter for Poseidon Sponge.
    pub fn new(
        full_rounds: u32,
        partial_rounds: u32,
        alpha: u64,
        mds: Vec<Vec<F>>,
        ark: Vec<Vec<F>>,
    ) -> Self {
        // shape check
        assert_eq!(ark.len() as u32, full_rounds + partial_rounds);
        for item in &ark {
            assert_eq!(item.len(), 3);
        }
        Self {
            full_rounds,
            partial_rounds,
            alpha,
            mds,
            ark,
        }
    }

    /// Return a random round constant.
    pub fn random_ark<R: Rng>(full_rounds: u32, partial_rounds: u32, rng: &mut R) -> Vec<Vec<F>> {
        let mut ark = Vec::new();

        for _ in 0..full_rounds + partial_rounds {
            let mut res = Vec::new();

            for _ in 0..3 {
                res.push(F::rand(rng));
            }
            ark.push(res);
        }

        ark
    }
}

impl<F: PrimeField> CryptographicSponge for PoseidonSponge<F> {
    type Parameters = PoseidonParameters<F>;

    fn new(params: &Self::Parameters) -> Self {
        // Requires F to be Alt_Bn128Fr
        let full_rounds = params.full_rounds;
        let partial_rounds = params.partial_rounds;
        let alpha = params.alpha;

        let mds = params.mds.clone();

        let ark = params.ark.to_vec();

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

    fn absorb(&mut self, input: &impl Absorb) {
        let elems = input.to_sponge_field_elements_as_vec::<F>();
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
        let src_elements = self.squeeze_native_field_elements(num_elements);

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
        let src_elements = self.squeeze_native_field_elements(num_elements);

        let mut bits: Vec<bool> = Vec::with_capacity(usable_bits * num_elements);
        for elem in &src_elements {
            let elem_bits = elem.into_repr().to_bits_le();
            bits.extend_from_slice(&elem_bits[..usable_bits]);
        }

        bits.truncate(num_bits);
        bits
    }

    fn squeeze_field_elements_with_sizes<F2: PrimeField>(
        &mut self,
        sizes: &[FieldElementSize],
    ) -> Vec<F2> {
        if F::characteristic() == F2::characteristic() {
            // native case
            let mut buf = Vec::with_capacity(sizes.len());
            batch_field_cast(
                &self.squeeze_native_field_elements_with_sizes(sizes),
                &mut buf,
            )
            .unwrap();
            buf
        } else {
            squeeze_field_elements_with_sizes_default_impl(self, sizes)
        }
    }

    fn squeeze_field_elements<F2: PrimeField>(&mut self, num_elements: usize) -> Vec<F2> {
        if TypeId::of::<F>() == TypeId::of::<F2>() {
            let result = self.squeeze_native_field_elements(num_elements);
            let mut cast = Vec::with_capacity(result.len());
            batch_field_cast(&result, &mut cast).unwrap();
            cast
        } else {
            self.squeeze_field_elements_with_sizes::<F2>(
                vec![FieldElementSize::Full; num_elements].as_slice(),
            )
        }
    }
}

impl<F: PrimeField> FieldBasedCryptographicSponge<F> for PoseidonSponge<F> {
    fn squeeze_native_field_elements(&mut self, num_elements: usize) -> Vec<F> {
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

impl<CF: PrimeField> SpongeExt for PoseidonSponge<CF> {
    type State = PoseidonSpongeState<CF>;

    fn from_state(state: Self::State, params: &Self::Parameters) -> Self {
        let mut sponge = Self::new(params);
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
