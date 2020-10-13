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
extern crate std;

#[cfg(not(feature = "std"))]
extern crate alloc as std;

use ark_ff::Field;
use std::vec::Vec;

/// An enum for specifying an output size.
pub enum OutputSize {
    /// Sample outputs from the entire output set.
    Full,

    /// Sample outputs from a subset of the output set.
    Truncated {
        /// The maximum size of the subset is 2^num_bits.
        num_bits: usize,
    },
}

/// An interface for objects that can be absorbed by a `CryptographicSponge`.
pub trait Absorbable<F: Field> {
    /// Converts the object into a list of bytes that can be absorbed by a `CryptographicSponge`.
    fn to_sponge_bytes(&self) -> Vec<u8>;

    /// Converts the object into field elements that can be absorbed by a `CryptographicSponge`.
    fn to_sponge_field_elements(&self) -> Vec<F>;
}

/// The interface for a cryptographic sponge.
/// A sponge can `absorb` or take in inputs and later `squeeze` or output bytes or field elements.
/// The outputs are dependent on previous `absorb` and `squeeze` calls, and the set of possible
/// outputs is implementation-dependent.
pub trait CryptographicSponge<F: Field> {
    /// Initialize a new instance of the sponge.
    fn new() -> Self;

    /// Absorb an input.
    fn absorb(&mut self, input: &impl Absorbable<F>);

    /// Output a list of bytes from the entire bytes output set.
    fn squeeze_bytes(&mut self) -> Vec<u8> {
        self.squeeze_bytes_with_size(OutputSize::Full)
    }

    /// Output a list of bytes from a subset of the bytes output set.
    fn squeeze_bytes_with_size(&mut self, size: OutputSize) -> Vec<u8>;

    /// Output a list of field elements from the entire field elements output set.
    fn squeeze_field_elements(&mut self) -> Vec<F> {
        self.squeeze_field_elements_with_size(OutputSize::Full)
    }

    /// Output a list of field elements from a subset of the field elements output set.
    fn squeeze_field_elements_with_size(&mut self, size: OutputSize) -> Vec<F>;
}
