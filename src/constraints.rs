use ark_ff::PrimeField;
use ark_r1cs_std::bits::boolean::Boolean;
use ark_r1cs_std::bits::uint8::UInt8;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

// TODO: Work in progress. Redesign API later

/// The interface for a cryptographic sponge.
/// A sponge can `absorb` or take in inputs and later `squeeze` or output bytes or field elements.
/// The outputs are dependent on previous `absorb` and `squeeze` calls.
pub trait CryptographicSpongeVar<F: PrimeField> {
    /// Initialize a new instance of the sponge.
    fn new(cs: ConstraintSystemRef<F>) -> Self;

    fn cs(&self) -> ConstraintSystemRef<F>;

    /// Absorb an input into the sponge.
    fn absorb(&mut self, input: &[FpVar<F>]) -> Result<(), SynthesisError>;

    /// Squeeze `num_bytes` bytes from the sponge.
    fn squeeze_byte_vars(&mut self, num_bytes: usize) -> Result<Vec<UInt8<F>>, SynthesisError>;

    /// Squeeze `num_elements` field elements from the sponge.
    fn squeeze_field_element_vars(
        &mut self,
        num_elements: usize,
    ) -> Result<Vec<FpVar<F>>, SynthesisError>;
}
