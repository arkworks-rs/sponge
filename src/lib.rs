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

use ark_ff::models::{
    Fp256, Fp256Parameters, Fp320, Fp320Parameters, Fp384, Fp384Parameters, Fp768, Fp768Parameters,
    Fp832, Fp832Parameters,
};
use ark_ff::{to_bytes, PrimeField, ToConstraintField};
use std::vec::Vec;

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
pub trait CryptographicSponge<F: PrimeField> {
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

/// An interface for objects that can be absorbed by a `CryptographicSponge`.
pub trait Absorbable<F: PrimeField> {
    /// Converts the object into a list of bytes that can be absorbed by a `CryptographicSponge`.
    fn to_sponge_bytes(&self) -> Vec<u8>;

    /// Converts the object into field elements that can be absorbed by a `CryptographicSponge`.
    fn to_sponge_field_elements(&self) -> Vec<F>;
}

impl<F: PrimeField> Absorbable<F> for u8 {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        vec![*self]
    }

    fn to_sponge_field_elements(&self) -> Vec<F> {
        vec![F::from(*self)]
    }
}

impl<F: PrimeField> Absorbable<F> for Vec<u8> {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        self.clone()
    }

    fn to_sponge_field_elements(&self) -> Vec<F> {
        self.as_slice().to_sponge_field_elements()
    }
}

impl<F: PrimeField> Absorbable<F> for [u8] {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }

    fn to_sponge_field_elements(&self) -> Vec<F> {
        self.to_field_elements().unwrap()
    }
}

macro_rules! impl_absorbable_field {
    ($field:ident, $params:ident) => {
        impl<P: $params> Absorbable<$field<P>> for $field<P> {
            fn to_sponge_bytes(&self) -> Vec<u8> {
                to_bytes![self].unwrap()
            }

            fn to_sponge_field_elements(&self) -> Vec<$field<P>> {
                vec![*self]
            }
        }

        impl<P: $params> Absorbable<$field<P>> for Vec<$field<P>> {
            fn to_sponge_bytes(&self) -> Vec<u8> {
                self.as_slice().to_sponge_bytes()
            }

            fn to_sponge_field_elements(&self) -> Vec<$field<P>> {
                self.clone()
            }
        }

        impl<P: $params> Absorbable<$field<P>> for [$field<P>] {
            fn to_sponge_bytes(&self) -> Vec<u8> {
                to_bytes![self].unwrap()
            }

            fn to_sponge_field_elements(&self) -> Vec<$field<P>> {
                self.to_vec()
            }
        }
    };
}

impl_absorbable_field!(Fp256, Fp256Parameters);
impl_absorbable_field!(Fp320, Fp320Parameters);
impl_absorbable_field!(Fp384, Fp384Parameters);
impl_absorbable_field!(Fp768, Fp768Parameters);
impl_absorbable_field!(Fp832, Fp832Parameters);

macro_rules! impl_absorbable_unsigned {
    ($t:ident) => {
        impl<F: PrimeField> Absorbable<F> for $t {
            fn to_sponge_bytes(&self) -> Vec<u8> {
                self.to_le_bytes().to_vec()
            }

            fn to_sponge_field_elements(&self) -> Vec<F> {
                vec![F::from(*self)]
            }
        }
    };
}

impl_absorbable_unsigned!(u16);
impl_absorbable_unsigned!(u32);
impl_absorbable_unsigned!(u64);
impl_absorbable_unsigned!(u128);

macro_rules! impl_absorbable_signed {
    ($signed:ident, $unsigned:ident) => {
        impl<F: PrimeField> Absorbable<F> for $signed {
            fn to_sponge_bytes(&self) -> Vec<u8> {
                self.to_le_bytes().to_vec()
            }

            fn to_sponge_field_elements(&self) -> Vec<F> {
                let mut elem = F::from(self.abs() as $unsigned);
                if *self < 0 {
                    elem = -elem;
                }
                vec![elem]
            }
        }
    };
}

impl_absorbable_signed!(i8, u8);
impl_absorbable_signed!(i16, u16);
impl_absorbable_signed!(i32, u32);
impl_absorbable_signed!(i64, u64);
impl_absorbable_signed!(i128, u128);

macro_rules! impl_absorbable_size {
    ($t:ident) => {
        impl<F: PrimeField> Absorbable<F> for $t {
            fn to_sponge_bytes(&self) -> Vec<u8> {
                Absorbable::<F>::to_sponge_bytes(&(*self as u64))
            }

            fn to_sponge_field_elements(&self) -> Vec<F> {
                (*self as u64).to_sponge_field_elements()
            }
        }
    };
}

impl_absorbable_size!(usize);
impl_absorbable_size!(isize);

impl<F: PrimeField> Absorbable<F> for bool {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        vec![(*self as u8)]
    }

    fn to_sponge_field_elements(&self) -> Vec<F> {
        vec![F::from(*self)]
    }
}

impl<F: PrimeField, A: Absorbable<F>> Absorbable<F> for Option<A> {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        let mut output = vec![self.is_some() as u8];
        if let Some(absorbable) = self {
            output.extend(absorbable.to_sponge_bytes());
        };
        output
    }

    fn to_sponge_field_elements(&self) -> Vec<F> {
        let mut output = vec![F::from(self.is_some())];
        if let Some(absorbable) = self {
            output.extend(absorbable.to_sponge_field_elements());
        };
        output
    }
}

impl<F: PrimeField, A: Absorbable<F>> Absorbable<F> for &A {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        (*self).to_sponge_bytes()
    }

    fn to_sponge_field_elements(&self) -> Vec<F> {
        (*self).to_sponge_field_elements()
    }
}

/// Individually absorbs each element in a comma-separated list of absorbables into a sponge.
/// Format is `absorb_all!(s, a_0, a_1, ..., a_n)`, where `s` is a mutable reference to a sponge
/// and `a_n` implements Absorbable.
#[macro_export]
macro_rules! absorb_all {
    ($sponge:expr, $($absorbable:expr),+ ) => {
        $(
            CryptographicSponge::absorb($sponge, &$absorbable);
        )+
    };
}
