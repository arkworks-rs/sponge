use crate::{Absorb, CryptographicSponge, FieldBasedCryptographicSponge, FieldElementSize};
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use ark_std::vec::Vec;

/// The constraints version of the [`DomainSeparatedSponge`].
#[cfg(feature = "r1cs")]
pub mod constraints;

/// Specifies the domain of a [`DomainSeparatedSponge`].
pub trait DomainSeparator {
    /// Returns the domain
    fn domain() -> Vec<u8>;
}

/// A sponge that offers backwards compatibility for implementations that do not accept sponge
/// objects but require domain separation. Operates in the same way as fork.
/// TODO: Remove `doamin_separated` module eventually, and use `fork`.
#[derive(Derivative)]
#[derivative(Clone(bound = "D: DomainSeparator"))]
pub struct DomainSeparatedSponge<S: CryptographicSponge, D: DomainSeparator> {
    sponge: S,
    _domain_phantom: PhantomData<D>,
}

impl<S: CryptographicSponge, D: DomainSeparator> CryptographicSponge
    for DomainSeparatedSponge<S, D>
{
    fn new() -> Self {
        let mut sponge = S::new();

        let mut domain = D::domain();
        let mut input = Absorb::to_sponge_bytes_as_vec(&domain.len());
        input.append(&mut domain);
        sponge.absorb(&input);

        Self {
            sponge,
            _domain_phantom: PhantomData,
        }
    }

    fn absorb(&mut self, input: &impl Absorb) {
        self.sponge.absorb(input);
    }

    fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        self.sponge.squeeze_bytes(num_bytes)
    }

    fn squeeze_bits(&mut self, num_bits: usize) -> Vec<bool> {
        self.sponge.squeeze_bits(num_bits)
    }

    fn squeeze_field_elements_with_sizes<F: PrimeField>(
        &mut self,
        sizes: &[FieldElementSize],
    ) -> Vec<F> {
        self.sponge.squeeze_field_elements_with_sizes(sizes)
    }

    fn squeeze_nonnative_field_elements<F: PrimeField>(&mut self, num_elements: usize) -> Vec<F> {
        self.sponge.squeeze_nonnative_field_elements(num_elements)
    }
}

impl<S: FieldBasedCryptographicSponge, D: DomainSeparator> FieldBasedCryptographicSponge
    for DomainSeparatedSponge<S, D>
{
    type CF = S::CF;

    fn squeeze_native_field_elements(&mut self, num_elements: usize) -> Vec<Self::CF> {
        self.sponge.squeeze_native_field_elements(num_elements)
    }

    fn squeeze_native_field_elements_with_sizes(
        &mut self,
        sizes: &[FieldElementSize],
    ) -> Vec<Self::CF> {
        self.sponge.squeeze_native_field_elements_with_sizes(sizes)
    }
}
