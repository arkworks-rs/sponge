#![cfg_attr(not(feature = "std"), no_std)]

//! A crate for the sponge trait.
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

use ark_ff::Field;

/// An enum for specifying the output size.
pub enum OutputSize {
    /// Sample outputs from the entire field.
    Full,

    /// Sample outputs from a subset of the field.
    Truncated {
        /// The maximum size of the subset is 2^num_bits.
        num_bits: usize,
    },
}

/// An interface for objects that can be absorbed into a specified `FiatShamirSponge`.
pub trait Absorbable<F: Field, S: FiatShamirSponge<F>> {
    /// Converts the object into the input of the specified `FiatShamirSponge`.
    fn to_sponge_input(&self) -> S::Input;
}

/// The interface for a sponge.
/// A sponge can `absorb` or take in inputs and later `squeeze` or output field elements.
/// The output depends on previous `absorb` and `squeeze` calls.
pub trait FiatShamirSponge<F: Field> {
    /// The input type.
    type Input;

    /// Initialize a new instance of the sponge.
    fn new() -> Self;

    /// Absorb an input.
    fn absorb(&mut self, input: &impl Absorbable<F, Self>)
    where
        Self: Sized;

    /// Output a field element from the entire field.
    /// Depends on previous `absorb` and `squeeze` calls.
    fn squeeze(&mut self) -> F {
        self.squeeze_with_size(OutputSize::Full)
    }

    /// Output a field element from a subset of the field.
    /// Depends on previous `absorb` and `squeeze` calls.
    fn squeeze_with_size(&mut self, size: OutputSize) -> F;
}
