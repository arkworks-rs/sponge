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

    /// Converts the object into a field element that can be absorbed by a `CryptographicSponge`.
    fn to_sponge_field_element(&self) -> F;
}

/// The interface for a sponge.
/// A sponge can `absorb` or take in inputs and later `squeeze` or output bytes or field elements.
/// The output depends on previous `absorb` and `squeeze` calls.
pub trait CryptographicSponge<F: Field> {
    /// Initialize a new instance of the sponge.
    fn new() -> Self;

    /// Absorb an input.
    fn absorb(&mut self, input: &impl Absorbable<F>);

    /// Output a list of bytes of full length.
    /// The full length is implementation-dependent and the output is byte-aligned.
    /// Depends on previous `absorb` and `squeeze` calls.
    fn squeeze_bytes(&mut self) -> Vec<u8> {
        self.squeeze_bytes_with_size(OutputSize::Full)
    }

    /// Output a list of bytes with a specified maximum length.
    /// The output is byte-aligned.
    /// Depends on previous `absorb` and `squeeze` calls.
    fn squeeze_bytes_with_size(&mut self, size: OutputSize) -> Vec<u8>;

    /// Output a field element from the entire field.
    /// Depends on previous `absorb` and `squeeze` calls.
    fn squeeze_field_element(&mut self) -> F {
        self.squeeze_field_element_with_size(OutputSize::Full)
    }

    /// Output a field element from a subset of the field.
    /// Depends on previous `absorb` and `squeeze` calls.
    fn squeeze_field_element_with_size(&mut self, size: OutputSize) -> F;
}
