#![cfg_attr(not(feature = "std"), no_std)]

//! A crate for the cryptographic sponge trait.
#![warn(
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
extern crate ark_std as std;

#[macro_use]
extern crate derivative;

use ark_ff::models::{
    Fp256, Fp256Parameters, Fp320, Fp320Parameters, Fp384, Fp384Parameters, Fp768, Fp768Parameters,
    Fp832, Fp832Parameters,
};
use ark_ff::{to_bytes, FpParameters, PrimeField, ToConstraintField};
use std::cmp::Ordering;
use std::marker::PhantomData;
use std::{vec, vec::Vec};

#[cfg(feature = "r1cs")]
pub mod constraints;

mod absorbable;
pub use absorbable::*;

pub mod poseidon;

pub mod domain_separated;

/// An enum for specifying the output field element size.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum FieldElementSize {
    /// Sample field elements from the entire field.
    Full,

    /// Sample field elements from a subset of the field, specified by the maximum number of bits.
    Truncated(usize),
}

impl FieldElementSize {
    pub(crate) fn num_bits<F: PrimeField>(&self) -> usize {
        if let FieldElementSize::Truncated(num_bits) = self {
            *num_bits.min(&(F::Params::CAPACITY as usize))
        } else {
            F::Params::CAPACITY as usize
        }
    }
}

/// The interface for a cryptographic sponge.
/// A sponge can `absorb` or take in inputs and later `squeeze` or output bytes or field elements.
/// The outputs are dependent on previous `absorb` and `squeeze` calls.
pub trait CryptographicSponge<CF: PrimeField>: Clone {
    /// Initialize a new instance of the sponge.
    fn new() -> Self;

    /// Absorb an input into the sponge.
    fn absorb(&mut self, input: &impl Absorbable<CF>);

    /// Squeeze `num_bytes` bytes from the sponge.
    fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8>;

    /// Squeeze `num_bits` bits from the sponge.
    fn squeeze_bits(&mut self, num_bits: usize) -> Vec<bool>;

    /// Squeeze `num_elements` field elements from the sponge.
    fn squeeze_field_elements(&mut self, num_elements: usize) -> Vec<CF>;

    /// Squeeze `sizes.len()` field elements from the sponge, where the `i`-th element of
    /// the output has size `sizes[i]`.
    fn squeeze_field_elements_with_sizes(&mut self, sizes: &[FieldElementSize]) -> Vec<CF> {
        let mut all_full_sizes = true;
        for size in sizes {
            if *size != FieldElementSize::Full {
                all_full_sizes = false;
                break;
            }
        }

        if all_full_sizes {
            self.squeeze_field_elements(sizes.len())
        } else {
            self.squeeze_nonnative_field_elements_with_sizes::<CF>(sizes)
        }
    }

    /// Squeeze `sizes.len()` nonnative field elements from the sponge, where the `i`-th element of
    /// the output has size `sizes[i]`.
    fn squeeze_nonnative_field_elements_with_sizes<F: PrimeField>(
        &mut self,
        sizes: &[FieldElementSize],
    ) -> Vec<F> {
        if sizes.len() == 0 {
            return Vec::new();
        }

        let mut max_nonnative_bits = 0usize;
        let mut total_bits = 0usize;
        for size in sizes {
            let bits = size.num_bits::<F>();
            if max_nonnative_bits < bits {
                max_nonnative_bits = bits
            }

            total_bits += bits;
        }

        let bits = self.squeeze_bits(total_bits);
        let mut bits_window = bits.as_slice();

        let mut output = Vec::with_capacity(sizes.len());
        for size in sizes {
            let num_bits = size.num_bits::<F>();
            let mut nonnative_bits_le: Vec<bool> = bits_window[..num_bits].to_vec();
            bits_window = &bits_window[num_bits..];

            let nonnative_bytes = nonnative_bits_le
                .chunks(8)
                .map(|bits| {
                    let mut byte = 0u8;
                    for (i, &bit) in bits.into_iter().enumerate() {
                        if bit {
                            byte += 1 << i;
                        }
                    }
                    byte
                })
                .collect::<Vec<_>>();

            output.push(F::from_random_bytes(nonnative_bytes.as_slice()).unwrap());
        }

        output
    }

    /// Squeeze `num_elements` nonnative field elements from the sponge.
    fn squeeze_nonnative_field_elements<F: PrimeField>(&mut self, num_elements: usize) -> Vec<F> {
        self.squeeze_nonnative_field_elements_with_sizes::<F>(
            vec![FieldElementSize::Full; num_elements].as_slice(),
        )
    }

    /// Applies domain separation to a sponge
    fn fork(&mut self, domain: &[u8]) -> &mut Self {
        let mut input = Absorbable::<CF>::to_sponge_bytes(&domain.len());
        input.extend_from_slice(domain);
        self.absorb(&input);
        self
    }

    /// Applies domain separation to a new sponge.
    fn new_fork(&self, domain: &[u8]) -> Self {
        let mut new_sponge = self.clone();
        new_sponge.fork(domain);
        new_sponge
    }
}

#[cfg(test)]
pub mod tests {
    use crate::collect_sponge_bytes;
    use crate::collect_sponge_field_elements;
    use crate::constraints::CryptographicSpongeVar;
    use crate::poseidon::constraints::PoseidonSpongeVar;
    use crate::poseidon::PoseidonSponge;
    use crate::Absorbable;
    use crate::{CryptographicSponge, FieldElementSize};
    use ark_ed_on_bls12_381::{Fq, Fr};
    use ark_ff::{One, ToConstraintField};
    use ark_ff::{PrimeField, Zero};
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::fields::FieldVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    type F = Fr;
    type CF = Fq;

    pub struct Test<F: PrimeField> {
        a: Vec<u8>,
        b: u128,
        c: F,
    }

    impl<F: PrimeField> Absorbable<F> for Test<F>
    where
        F: Absorbable<F>,
    {
        fn to_sponge_bytes(&self) -> Vec<u8> {
            collect_sponge_bytes!(F, self.a, self.b, self.c)
        }

        fn to_sponge_field_elements(&self) -> Vec<F> {
            collect_sponge_field_elements!(F, self.a, self.b, self.c)
        }
    }

    #[test]
    fn test_ae() {
        let a = Test {
            a: vec![],
            b: 0,
            c: Fr::zero(),
        };
        let mut s = PoseidonSponge::<Fr>::new();
        s.absorb(&a);
        s.absorb(vec![0u8].as_slice())
    }

    /*
    #[test]
    fn test_a() {
        let a = vec![0u8, 5, 6, 2, 3, 7, 2];
        let mut s = PoseidonSponge::<CF>::new();
        s.absorb(&a);
    }

    #[test]
    fn test_squeeze_nonnative_field_elements() {
        let cs = ConstraintSystem::<CF>::new_ref();
        let mut s = PoseidonSponge::<CF>::new();
        s.absorb(&CF::one());

        let mut s_var = PoseidonSpongeVar::<CF>::new(cs.clone());
        s_var.absorb(&[FpVar::<CF>::one()]);

        let out: Vec<F> = s.squeeze_nonnative_field_elements_with_sizes::<F>(&[
            FieldElementSize::Truncated { num_bits: 128 },
            FieldElementSize::Truncated { num_bits: 180 },
            FieldElementSize::Full,
            FieldElementSize::Truncated { num_bits: 128 },
        ]);
        let out_var = s_var
            .squeeze_nonnative_field_elements_with_sizes::<F>(&[
                FieldElementSize::Truncated { num_bits: 128 },
                FieldElementSize::Truncated { num_bits: 180 },
                FieldElementSize::Full,
                FieldElementSize::Truncated { num_bits: 128 },
            ])
            .unwrap();

        println!("{:?}", out);
        println!("{:?}", out_var.0.value().unwrap());

        /*
        let out = s
            .squeeze_nonnative_field_elements::<F>(&[
                FieldElementSize::Truncated { num_bits: 128 },
                FieldElementSize::Truncated { num_bits: 128 },
            ])
            .unwrap();
        println!("{:?}", out.0.value().unwrap());

         */
    }*/
}
