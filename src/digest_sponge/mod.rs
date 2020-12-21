use crate::{Absorbable, CryptographicSponge, FieldElementSize};
use ark_ff::{PrimeField, ToConstraintField};
use ark_std::{marker::PhantomData, vec, vec::Vec};
use digest::consts::U64;
use digest::Digest;

#[derive(Eq, PartialEq)]
pub enum SpongeOperationState {
    Absorbing,
    Squeezing,
}

pub struct DigestSponge<F: PrimeField, D: Digest<OutputSize = U64>> {
    state: Vec<u8>,
    rate: usize,
    capacity: usize,

    operation_state: SpongeOperationState,
    next_byte: usize,

    _field_phantom: PhantomData<F>,
    _digest_phantom: PhantomData<D>,
}

impl<F: PrimeField, D: Digest<OutputSize = U64>> DigestSponge<F, D> {
    fn get_rate_byte(&mut self, index: usize) -> u8 {
        assert!(index < self.rate);
        self.state[index]
    }

    fn xor_rate_byte(&mut self, index: usize, byte: u8) {
        assert!(index < self.rate);
        self.state[index] ^= byte;
    }

    fn transition_state(&mut self) {
        self.state = D::digest(self.state.as_slice()).to_vec();
        assert_eq!(self.capacity + self.rate, self.state.len());
        self.next_byte = 0;
    }

    fn set_operation(&mut self, operation: SpongeOperationState) {
        if self.operation_state == operation {
            return;
        }

        // Changing operation state
        self.transition_state();
        self.operation_state = if self.operation_state == SpongeOperationState::Squeezing {
            SpongeOperationState::Absorbing
        } else {
            SpongeOperationState::Squeezing
        }
    }

    fn absorb_bytes(&mut self, input: &[u8]) {
        self.set_operation(SpongeOperationState::Absorbing);
        for i in 0..(input.len()) {
            if self.next_byte >= self.rate {
                self.transition_state();
            }
            self.xor_rate_byte(self.next_byte, input[i]);
            self.next_byte += 1;
        }
    }

    fn squeeze_bytes(&mut self, output: &mut [u8]) {
        self.set_operation(SpongeOperationState::Squeezing);
        for i in 0..(output.len()) {
            if self.next_byte >= self.rate {
                self.transition_state();
            }
            output[i] = self.get_rate_byte(self.next_byte);
            self.next_byte += 1;
        }
    }
}

impl<F: PrimeField, D: Digest<OutputSize = U64>> CryptographicSponge<F> for DigestSponge<F, D> {
    fn new() -> Self {
        let (rate, capacity) = (32usize, 32usize);
        Self {
            state: vec![0u8; rate + capacity],
            rate,
            capacity,

            operation_state: SpongeOperationState::Absorbing,
            next_byte: 0usize,

            _field_phantom: PhantomData,
            _digest_phantom: PhantomData,
        }
    }

    fn absorb(&mut self, input: &impl Absorbable<F>) {
        self.absorb_bytes(input.to_sponge_bytes().as_slice());
    }

    fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(num_bytes);
        self.squeeze_bytes(output.as_mut_slice());
        output
    }

    fn squeeze_field_elements_with_sizes(&mut self, sizes: &[FieldElementSize]) -> Vec<F> {
        let mut output = Vec::with_capacity(sizes.len());
        let max_bits = F::size_in_bits();
        for size in sizes {
            let num_bits = if let FieldElementSize::Truncated { num_bits } = size {
                if *num_bits > max_bits {
                    max_bits
                } else {
                    *num_bits
                }
            } else {
                max_bits
            };

            let extra_bits = num_bits % 8;
            let num_bytes = num_bits / 8 + if extra_bits > 0 { 1 } else { 0 };

            let mut output_bytes = vec![0u8; num_bytes];
            self.squeeze_bytes(output_bytes.as_mut_slice());

            if extra_bits > 0 {
                let bitmask = (1 << extra_bits) - 1;
                output_bytes[num_bytes - 1] &= bitmask;
            }

            output.push(output_bytes.to_field_elements().unwrap()[0]);
        }

        output
    }
}
