#![cfg_attr(not(feature = "std"), no_std)]

//! A crate for the cryptographic sponge trait.
#![deny(
    const_err,
    future_incompatible,
    missing_docs,
    non_shorthand_field_patterns,
    renamed_and_removed_lints,
    rust_2018_idioms,
    stable_features,
    trivial_casts,
    trivial_numeric_casts,
    unused,
    variant_size_differences,
    warnings
)]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc as std;

use ark_ff::Field;
use std::vec::Vec;

/// An interface for objects that can be absorbed by a `CryptographicSponge`.
pub trait Absorbable<F: Field> {
    /// Converts the object into a list of bytes that can be absorbed by a `CryptographicSponge`.
    fn to_sponge_bytes(&self) -> Vec<u8>;

    /// Converts the object into field elements that can be absorbed by a `CryptographicSponge`.
    fn to_sponge_field_elements(&self) -> Vec<F>;
}

/// An enum for specifying the output field element size.
#[derive(Clone)]
pub enum FieldElementSize {
    /// Sample field elements from the entire field.
    Full,

    /// Sample field elements from a subset of the field.
    Truncated {
        /// The maximum size of the subset is 2^num_bits.
        num_bits: usize,
    },
}

/// The interface for a cryptographic sponge.
/// A sponge can `absorb` or take in inputs and later `squeeze` or output bytes or field elements.
/// The outputs are dependent on previous `absorb` and `squeeze` calls.
pub trait CryptographicSponge<F: Field> {
    /// Initialize a new instance of the sponge.
    fn new() -> Self;

    /// Absorb an input into the sponge.
    fn absorb(&mut self, input: &impl Absorbable<F>);

    /// Squeeze `num_bytes` bytes from the sponge.
    fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8>;

    /// Squeeze `sizes.len()` field elements from the sponge, where the `i`-th element of
    /// the output has size `sizes[i]`.
    fn squeeze_field_elements_with_sizes(&mut self, sizes: &[FieldElementSize]) -> Vec<F>;

    /// Squeeze `num_elements` field elements from the sponge.
    fn squeeze_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        self.squeeze_field_elements_with_sizes(
            vec![FieldElementSize::Full; num_elements].as_slice(),
        )
    }
}
