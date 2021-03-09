use crate::constraints::AbsorbableGadget;
use crate::constraints::CryptographicSpongeVar;
use crate::domain_separated::{DomainSeparatedSponge, DomainSeparator};
use crate::{Absorbable, CryptographicSponge, FieldElementSize};
use ark_ff::PrimeField;
use ark_nonnative_field::NonNativeFieldVar;
use ark_r1cs_std::bits::boolean::Boolean;
use ark_r1cs_std::bits::uint8::UInt8;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::marker::PhantomData;

/// Sponge that offers backwards compatibility for implementations that do not accept sponge objects
/// but require domain separation. Operates in the same way as fork.
#[derive(Derivative)]
#[derivative(Clone(bound = "D: DomainSeparator"))]
pub struct DomainSeparatedSpongeVar<
    CF: PrimeField,
    S: CryptographicSponge<CF>,
    SV: CryptographicSpongeVar<CF, S>,
    D: DomainSeparator,
> {
    sponge: SV,
    domain_separated: bool,

    _affine_phantom: PhantomData<CF>,
    _sponge_phantom: PhantomData<S>,
    _domain_separator_phantom: PhantomData<D>,
}

impl<CF, S, SV, D> DomainSeparatedSpongeVar<CF, S, SV, D>
where
    CF: PrimeField,
    S: CryptographicSponge<CF>,
    SV: CryptographicSpongeVar<CF, S>,
    D: DomainSeparator,
{
    fn try_separate_domain(&mut self) -> Result<(), SynthesisError> {
        if !self.domain_separated {
            let mut domain = D::domain();
            let mut input = Absorbable::<CF>::to_sponge_bytes(&domain.len());
            input.append(&mut domain);

            let elems: Vec<CF> = input.to_sponge_field_elements();
            let elem_vars = elems
                .into_iter()
                .map(|elem| FpVar::Constant(elem))
                .collect::<Vec<_>>();

            self.sponge.absorb(&elem_vars)?;

            self.domain_separated = true;
        }
        Ok(())
    }
}

impl<CF, S, SV, D> CryptographicSpongeVar<CF, DomainSeparatedSponge<CF, S, D>>
    for DomainSeparatedSpongeVar<CF, S, SV, D>
where
    CF: PrimeField,
    S: CryptographicSponge<CF>,
    SV: CryptographicSpongeVar<CF, S>,
    D: DomainSeparator,
{
    fn new(cs: ConstraintSystemRef<CF>) -> Self {
        Self {
            sponge: SV::new(cs),
            domain_separated: false,
            _affine_phantom: PhantomData,
            _sponge_phantom: PhantomData,
            _domain_separator_phantom: PhantomData,
        }
    }

    fn cs(&self) -> ConstraintSystemRef<CF> {
        self.sponge.cs()
    }

    fn absorb(&mut self, input: &impl AbsorbableGadget<CF>) -> Result<(), SynthesisError> {
        self.try_separate_domain()?;
        self.sponge.absorb(input)
    }

    fn squeeze_bytes(&mut self, num_bytes: usize) -> Result<Vec<UInt8<CF>>, SynthesisError> {
        self.try_separate_domain()?;
        self.sponge.squeeze_bytes(num_bytes)
    }

    fn squeeze_bits(&mut self, num_bits: usize) -> Result<Vec<Boolean<CF>>, SynthesisError> {
        self.try_separate_domain()?;
        self.sponge.squeeze_bits(num_bits)
    }

    fn squeeze_field_elements(
        &mut self,
        num_elements: usize,
    ) -> Result<Vec<FpVar<CF>>, SynthesisError> {
        self.try_separate_domain()?;
        self.sponge.squeeze_field_elements(num_elements)
    }

    fn squeeze_nonnative_field_elements_with_sizes<F: PrimeField>(
        &mut self,
        sizes: &[FieldElementSize],
    ) -> Result<(Vec<NonNativeFieldVar<F, CF>>, Vec<Vec<Boolean<CF>>>), SynthesisError> {
        self.try_separate_domain()?;
        self.sponge
            .squeeze_nonnative_field_elements_with_sizes(sizes)
    }
}
