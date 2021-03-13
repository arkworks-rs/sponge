use crate::constraints::AbsorbableGadget;
use crate::constraints::CryptographicSpongeVar;
use crate::poseidon::{PoseidonSponge, PoseidonSpongeParameters};
use crate::DuplexSpongeMode;
use ark_ff::{FpParameters, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::{vec, vec::Vec};

#[derive(Clone, Debug)]
/// the gadget for Poseidon sponge
///
/// This implementation of Poseidon is entirely from Fractal's implementation in [COS20][cos]
/// with small syntax changes.
///
/// [cos]: https://eprint.iacr.org/2019/1076
pub struct PoseidonSpongeVar<F: PrimeField> {
    /// Constraint system reference
    pub cs: ConstraintSystemRef<F>,
    /// Poseidon parameters
    pub params: PoseidonSpongeParameters<F>,
    /// the sponge's state
    pub state: Vec<FpVar<F>>,
    /// the mode
    pub mode: DuplexSpongeMode,
}

impl<F: PrimeField> PoseidonSpongeVar<F> {
    #[tracing::instrument(target = "r1cs", skip(self))]
    fn apply_s_box(
        &self,
        state: &mut [FpVar<F>],
        is_full_round: bool,
    ) -> Result<(), SynthesisError> {
        // Full rounds apply the S Box (x^alpha) to every element of state
        if is_full_round {
            for state_item in state.iter_mut() {
                *state_item = state_item.pow_by_constant(&[self.params.alpha])?;
            }
        }
        // Partial rounds apply the S Box (x^alpha) to just the final element of state
        else {
            state[state.len() - 1] =
                state[state.len() - 1].pow_by_constant(&[self.params.alpha])?;
        }

        Ok(())
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn apply_ark(&self, state: &mut [FpVar<F>], round_number: usize) -> Result<(), SynthesisError> {
        for (i, state_elem) in state.iter_mut().enumerate() {
            *state_elem += self.params.ark[round_number][i];
        }
        Ok(())
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn apply_mds(&self, state: &mut [FpVar<F>]) -> Result<(), SynthesisError> {
        let mut new_state = Vec::new();
        let zero = FpVar::<F>::zero();
        for i in 0..state.len() {
            let mut cur = zero.clone();
            for (j, state_elem) in state.iter().enumerate() {
                let term = state_elem * self.params.mds[i][j];
                cur += &term;
            }
            new_state.push(cur);
        }
        state.clone_from_slice(&new_state[..state.len()]);
        Ok(())
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn permute(&mut self) -> Result<(), SynthesisError> {
        let full_rounds_over_2 = self.params.full_rounds / 2;
        let mut state = self.state.clone();
        for i in 0..full_rounds_over_2 {
            self.apply_ark(&mut state, i as usize)?;
            self.apply_s_box(&mut state, true)?;
            self.apply_mds(&mut state)?;
        }
        for i in full_rounds_over_2..(full_rounds_over_2 + self.params.partial_rounds) {
            self.apply_ark(&mut state, i as usize)?;
            self.apply_s_box(&mut state, false)?;
            self.apply_mds(&mut state)?;
        }

        for i in (full_rounds_over_2 + self.params.partial_rounds)
            ..(self.params.partial_rounds + self.params.full_rounds)
        {
            self.apply_ark(&mut state, i as usize)?;
            self.apply_s_box(&mut state, true)?;
            self.apply_mds(&mut state)?;
        }

        self.state = state;
        Ok(())
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn absorb_internal(
        &mut self,
        rate_start_index: usize,
        elements: &[FpVar<F>],
    ) -> Result<(), SynthesisError> {
        // if we can finish in this call
        if rate_start_index + elements.len() <= self.params.rate {
            for (i, element) in elements.iter().enumerate() {
                self.state[i + rate_start_index] += element;
            }
            self.mode = DuplexSpongeMode::Absorbing {
                next_absorb_index: rate_start_index + elements.len(),
            };

            return Ok(());
        }
        // otherwise absorb (rate - rate_start_index) elements
        let num_elements_absorbed = self.params.rate - rate_start_index;
        for (i, element) in elements.iter().enumerate().take(num_elements_absorbed) {
            self.state[i + rate_start_index] += element;
        }
        self.permute()?;
        // Tail recurse, with the input elements being truncated by num elements absorbed
        self.absorb_internal(0, &elements[num_elements_absorbed..])
    }

    // Squeeze |output| many elements. This does not end in a squeeze
    #[tracing::instrument(target = "r1cs", skip(self))]
    fn squeeze_internal(
        &mut self,
        rate_start_index: usize,
        output: &mut [FpVar<F>],
    ) -> Result<(), SynthesisError> {
        // if we can finish in this call
        if rate_start_index + output.len() <= self.params.rate {
            output
                .clone_from_slice(&self.state[rate_start_index..(output.len() + rate_start_index)]);
            self.mode = DuplexSpongeMode::Squeezing {
                next_squeeze_index: rate_start_index + output.len(),
            };
            return Ok(());
        }
        // otherwise squeeze (rate - rate_start_index) elements
        let num_elements_squeezed = self.params.rate - rate_start_index;
        output[..num_elements_squeezed].clone_from_slice(
            &self.state[rate_start_index..(num_elements_squeezed + rate_start_index)],
        );

        // Unless we are done with squeezing in this call, permute.
        if output.len() != self.params.rate {
            self.permute()?;
        }
        // Tail recurse, with the correct change to indices in output happening due to changing the slice
        self.squeeze_internal(0, &mut output[num_elements_squeezed..])
    }
}

impl<F: PrimeField> CryptographicSpongeVar<F, PoseidonSponge<F>> for PoseidonSpongeVar<F> {
    #[tracing::instrument(target = "r1cs", skip(cs))]
    fn new(cs: ConstraintSystemRef<F>, params: &PoseidonSpongeParameters<F>) -> Self {
        Self {
            cs: cs,
            params: params.clone(),
            state: vec![FpVar::<F>::zero(); params.rate + params.capacity],
            mode: DuplexSpongeMode::Absorbing {
                next_absorb_index: 0,
            },
        }
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn cs(&self) -> ConstraintSystemRef<F> {
        self.cs.clone()
    }

    #[tracing::instrument(target = "r1cs", skip(self, input))]
    fn absorb(&mut self, input: &impl AbsorbableGadget<F>) -> Result<(), SynthesisError> {
        let input = input.to_sponge_field_elements()?;
        if input.is_empty() {
            return Ok(());
        }

        match self.mode {
            DuplexSpongeMode::Absorbing { next_absorb_index } => {
                let mut absorb_index = next_absorb_index;
                if absorb_index == self.params.rate {
                    self.permute()?;
                    absorb_index = 0;
                }
                self.absorb_internal(absorb_index, input.as_slice())?;
            }
            DuplexSpongeMode::Squeezing {
                next_squeeze_index: _,
            } => {
                self.permute()?;
                self.absorb_internal(0, input.as_slice())?;
            }
        };

        Ok(())
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn squeeze_bytes(&mut self, num_bytes: usize) -> Result<Vec<UInt8<F>>, SynthesisError> {
        let usable_bytes = (F::Params::CAPACITY / 8) as usize;

        let num_elements = (num_bytes + usable_bytes - 1) / usable_bytes;
        let src_elements = self.squeeze_field_elements(num_elements)?;

        let mut bytes: Vec<UInt8<F>> = Vec::with_capacity(usable_bytes * num_elements);
        for elem in &src_elements {
            bytes.extend_from_slice(&elem.to_bytes()?[..usable_bytes]);
        }

        bytes.truncate(num_bytes);
        Ok(bytes)
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn squeeze_bits(&mut self, num_bits: usize) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let usable_bits = F::Params::CAPACITY as usize;

        let num_elements = (num_bits + usable_bits - 1) / usable_bits;
        let src_elements = self.squeeze_field_elements(num_elements)?;

        let mut bits: Vec<Boolean<F>> = Vec::with_capacity(usable_bits * num_elements);
        for elem in &src_elements {
            bits.extend_from_slice(&elem.to_bits_le()?[..usable_bits]);
        }

        bits.truncate(num_bits);
        Ok(bits)
    }

    #[tracing::instrument(target = "r1cs", skip(self))]
    fn squeeze_field_elements(
        &mut self,
        num_elements: usize,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let zero = FpVar::zero();
        let mut squeezed_elems = vec![zero; num_elements];
        match self.mode {
            DuplexSpongeMode::Absorbing {
                next_absorb_index: _,
            } => {
                self.permute()?;
                self.squeeze_internal(0, &mut squeezed_elems)?;
            }
            DuplexSpongeMode::Squeezing { next_squeeze_index } => {
                let mut squeeze_index = next_squeeze_index;
                if squeeze_index == self.params.rate {
                    self.permute()?;
                    squeeze_index = 0;
                }
                self.squeeze_internal(squeeze_index, &mut squeezed_elems)?;
            }
        };

        Ok(squeezed_elems.to_vec())
    }
}
