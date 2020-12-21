use crate::Vec;
use crate::{Absorbable, CryptographicSponge, FieldElementSize};
use ark_ff::PrimeField;

pub struct DummySponge {}

impl<F: PrimeField> CryptographicSponge<F> for DummySponge {
    fn new() -> Self {
        Self {}
    }

    fn absorb(&mut self, _input: &impl Absorbable<F>) {}

    fn squeeze_bytes(&mut self, _num_bytes: usize) -> Vec<u8> {
        unimplemented!()
    }

    fn squeeze_field_elements_with_sizes(&mut self, _sizes: &[FieldElementSize]) -> Vec<F> {
        unimplemented!()
    }

    fn squeeze_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        let two = F::one() + F::one();
        vec![two; num_elements]
    }
}
