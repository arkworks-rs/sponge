/*
 * credit:
 *      This implementation of Rescue is based on the Sage scripts in
 *      https://github.com/KULeuven-COSIC/Marvellous
 */

use crate::{Absorbable, CryptographicSponge, FieldElementSize, Vec, DuplexSpongeMode};
use ark_ff::{BigInteger, FpParameters, PrimeField};

/// Constraints for Rescue.
#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Clone, Debug)]
/// The sponge parameters for Rescue.
pub struct RescueSpongeParameters<F: PrimeField> {
    /// Number of rounds (each round has two steps).
    rounds: u32,

    /// Exponent used in S-boxes.
    alpha: Vec<u64>,

    /// 1/alpha.
    /// Note: not -alpha.
    invalpha: Vec<u64>,

    /// Initial constants.
    initial_constant: Vec<F>,

    /// Constants matrix for generating the round keys.
    constants_matrix: Vec<Vec<F>>,

    /// Constants constant for generating the round keys.
    constants_constant: Vec<F>,

    /// Maximally Distance Separating Matrix.
    mds: Vec<Vec<F>>,

    /// The rate.
    rate: usize,

    /// the capacity.
    capacity: usize,
}

#[derive(Clone)]
/// The sponge for Rescue.
pub struct RescueSponge<F: PrimeField> {
    /// The sponge parameters.
    pub params: RescueSpongeParameters<F>,

    /// The sponge's state.
    pub state: Vec<F>,

    /// The mode.
    pub mode: DuplexSpongeMode,
}

impl<F: PrimeField> RescueSponge<F> {
    fn permute(&mut self) {
        let mut key_injection = self.params.initial_constant.clone();
        let mut key_state = self.params.initial_constant.clone();

        let state_len = self.params.rate + self.params.capacity;

        for i in 0..state_len {
            self.state[i] += key_state[i];
        }

        for r in 0..2 * self.params.rounds{
            if r % 2 == 0 {
                for i in 0..state_len {
                    key_state[i] = key_state[i].pow(&self.params.invalpha);
                    self.state[i] = self.state[i].pow(&self.params.invalpha);
                }
            } else {
                for i in 0..state_len {
                    key_state[i] = key_state[i].pow(&self.params.alpha);
                    self.state[i] = self.state[i].pow(&self.params.alpha);
                }
            }

            // key_injection <= constants_matrix * key_injection + constants_constant
            let key_injection_old = key_injection.clone();
            for i in 0..state_len {
                key_injection[i] = F::zero();
                for j in 0..state_len {
                    key_injection[i] += self.params.constants_matrix[i][j] * key_injection_old[j];
                }
                key_injection[i] += self.params.constants_constant[i];
            }

            // key_state <= MDS * key_state + key_injection
            let key_state_old = key_state.clone();
            for i in 0..state_len {
                key_state[i] = F::zero();
                for j in 0..state_len {
                    key_state[i] += self.params.mds[i][j] * key_state_old[j];
                }
                key_state[i] += key_injection[i];
            }

            // state <= MDS * state + key_state
            let state_old = self.state.clone();
            for i in 0..state_len {
                self.state[i] = F::zero();
                for j in 0..state_len {
                    self.state[i] += self.params.mds[i][j] * state_old[j];
                }
                self.state[i] += key_state[i];
            }
        }
    }

    // Absorbs everything in elements, this does not end in an absorption.
    fn absorb_internal(&mut self, rate_start_index: usize, elements: &[F]) {
        // if we can finish in this call
        if rate_start_index + elements.len() <= self.params.rate {
            for (i, element) in elements.iter().enumerate() {
                self.state[i + rate_start_index] += element;
            }
            self.mode = DuplexSpongeMode::Absorbing {
                next_absorb_index: rate_start_index + elements.len(),
            };

            return;
        }
        // otherwise absorb (rate - rate_start_index) elements
        let num_elements_absorbed = self.params.rate - rate_start_index;
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
        if rate_start_index + output.len() <= self.params.rate {
            output
                .clone_from_slice(&self.state[rate_start_index..(output.len() + rate_start_index)]);
            self.mode = DuplexSpongeMode::Squeezing {
                next_squeeze_index: rate_start_index + output.len(),
            };
            return;
        }
        // otherwise squeeze (rate - rate_start_index) elements
        let num_elements_squeezed = self.params.rate - rate_start_index;
        output[..num_elements_squeezed].clone_from_slice(
            &self.state[rate_start_index..(num_elements_squeezed + rate_start_index)],
        );

        // Unless we are done with squeezing in this call, permute.
        if output.len() != self.params.rate {
            self.permute();
        }
        // Tail recurse, with the correct change to indices in output happening due to changing the slice
        self.squeeze_internal(0, &mut output[num_elements_squeezed..]);
    }
}

impl<F: PrimeField> CryptographicSponge<F> for RescueSponge<F> {
    type Parameters = RescueSpongeParameters<F>;

    fn new(params: &Self::Parameters) -> Self {
        Self {
            params: params.clone(),
            state: vec![F::zero(); params.rate + params.capacity],
                mode: DuplexSpongeMode::Absorbing {
                next_absorb_index: 0,
            },
        }
    }

    fn absorb(&mut self, input: &impl Absorbable<F>) {
        let elems = input.to_sponge_field_elements();
        if elems.is_empty() {
            return;
        }

        match self.mode {
            DuplexSpongeMode::Absorbing { next_absorb_index } => {
                let mut absorb_index = next_absorb_index;
                if absorb_index == self.params.rate {
                    self.permute();
                    absorb_index = 0;
                }
                self.absorb_internal(absorb_index, elems.as_slice());
            }
            DuplexSpongeMode::Squeezing {
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

    fn squeeze_field_elements_with_sizes(&mut self, _sizes: &[FieldElementSize]) -> Vec<F> {
        unimplemented!()
    }

    fn squeeze_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        let mut squeezed_elems = vec![F::zero(); num_elements];
        match self.mode {
            DuplexSpongeMode::Absorbing {
                next_absorb_index: _,
            } => {
                self.permute();
                self.squeeze_internal(0, &mut squeezed_elems);
            }
            DuplexSpongeMode::Squeezing { next_squeeze_index } => {
                let mut squeeze_index = next_squeeze_index;
                if squeeze_index == self.params.rate {
                    self.permute();
                    squeeze_index = 0;
                }
                self.squeeze_internal(squeeze_index, &mut squeezed_elems);
            }
        };

        squeezed_elems
    }
}
