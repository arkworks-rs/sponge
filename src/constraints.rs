use crate::FieldElementSize;
use ark_ff::PrimeField;
use ark_nonnative_field::params::get_params;
use ark_nonnative_field::{AllocatedNonNativeFieldVar, NonNativeFieldVar};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::bits::boolean::Boolean;
use ark_r1cs_std::bits::uint8::UInt8;
use ark_r1cs_std::fields::fp::{AllocatedFp, FpVar};
use ark_r1cs_std::R1CSVar;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError};
use ark_std::vec::Vec;

// TODO: Work in progress. Redesign API later

/// The interface for a cryptographic sponge.
/// A sponge can `absorb` or take in inputs and later `squeeze` or output bytes or field elements.
/// The outputs are dependent on previous `absorb` and `squeeze` calls.
pub trait CryptographicSpongeVar<CF: PrimeField> {
    /// Initialize a new instance of the sponge.
    fn new(cs: ConstraintSystemRef<CF>) -> Self;

    fn cs(&self) -> ConstraintSystemRef<CF>;

    /// Absorb an input into the sponge.
    fn absorb(&mut self, input: &[FpVar<CF>]) -> Result<(), SynthesisError>;

    /// Squeeze `num_bytes` bytes from the sponge.
    fn squeeze_bytes(&mut self, num_bytes: usize) -> Result<Vec<UInt8<CF>>, SynthesisError>;

    /// Squeeze `num_bit` bits from the sponge.
    fn squeeze_bits(&mut self, num_bits: usize) -> Result<Vec<Boolean<CF>>, SynthesisError>;

    /// Squeeze `num_elements` field elements from the sponge.
    fn squeeze_field_elements(
        &mut self,
        num_elements: usize,
    ) -> Result<Vec<FpVar<CF>>, SynthesisError>;

    fn squeeze_nonnative_field_elements_with_sizes<F: PrimeField>(
        &mut self,
        sizes: &[FieldElementSize],
    ) -> Result<(Vec<NonNativeFieldVar<F, CF>>, Vec<Vec<Boolean<CF>>>), SynthesisError> {
        if sizes.len() == 0 {
            return Ok((Vec::new(), Vec::new()));
        }

        let cs = self.cs();
        let params = get_params(F::size_in_bits(), CF::size_in_bits());

        let mut max_nonnative_bits = 0usize;
        let mut total_bits = 0usize;
        for size in sizes {
            let bits = size.num_bits::<F>();
            if max_nonnative_bits < bits {
                max_nonnative_bits = bits
            }

            total_bits += bits;
        }

        let bits = self.squeeze_bits(total_bits)?;

        let mut lookup_table = Vec::<Vec<CF>>::new();
        let mut cur = F::one();
        for _ in 0..max_nonnative_bits {
            let repr = AllocatedNonNativeFieldVar::<F, CF>::get_limbs_representations(&cur)?;
            lookup_table.push(repr);
            cur.double_in_place();
        }

        let mut dest_gadgets = Vec::<NonNativeFieldVar<F, CF>>::new();
        let mut dest_bits = Vec::<Vec<Boolean<CF>>>::new();

        let mut bits_window = bits.as_slice();
        for size in sizes {
            let num_bits = size.num_bits::<F>();

            let nonnative_bits_le = bits_window[..num_bits].to_vec();
            bits_window = &bits_window[num_bits..];

            let mut val = vec![CF::zero(); params.num_limbs];
            let mut lc = vec![LinearCombination::<CF>::zero(); params.num_limbs];

            for (j, bit) in nonnative_bits_le.iter().enumerate() {
                if bit.value().unwrap_or_default() {
                    for (k, val) in val.iter_mut().enumerate().take(params.num_limbs) {
                        *val += &lookup_table[j][k];
                    }
                }

                #[allow(clippy::needless_range_loop)]
                for k in 0..params.num_limbs {
                    lc[k] = &lc[k] + bit.lc() * lookup_table[j][k];
                }
            }

            let mut limbs = Vec::new();
            for k in 0..params.num_limbs {
                let gadget =
                    AllocatedFp::new_witness(ark_relations::ns!(cs, "alloc"), || Ok(val[k]))
                        .unwrap();
                lc[k] = lc[k].clone() - (CF::one(), gadget.variable);
                cs.enforce_constraint(lc!(), lc!(), lc[k].clone()).unwrap();
                limbs.push(FpVar::<CF>::from(gadget));
            }

            dest_bits.push(nonnative_bits_le);
            dest_gadgets.push(NonNativeFieldVar::<F, CF>::Var(
                AllocatedNonNativeFieldVar::<F, CF> {
                    limbs,
                    num_of_additions_over_normal_form: CF::zero(),
                    is_in_the_normal_form: true,
                    target_phantom: Default::default(),
                },
            ));
        }

        Ok((dest_gadgets, dest_bits))
    }

    fn squeeze_nonnative_field_elements<F: PrimeField>(
        &mut self,
        num_elements: usize,
    ) -> Result<(Vec<NonNativeFieldVar<F, CF>>, Vec<Vec<Boolean<CF>>>), SynthesisError> {
        self.squeeze_nonnative_field_elements_with_sizes::<F>(
            vec![FieldElementSize::Full; num_elements].as_slice(),
        )
    }
}

#[cfg(test)]
pub mod tests {
    use crate::constraints::CryptographicSpongeVar;
    use crate::poseidon::constraints::PoseidonSpongeVar;
    use crate::poseidon::PoseidonSponge;
    use crate::{CryptographicSponge, FieldElementSize};
    use ark_ed_on_bls12_381::{Fq, Fr};
    use ark_ff::{One, ToConstraintField};
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::fields::FieldVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    type F = Fr;
    type CF = Fq;

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
    }
}
