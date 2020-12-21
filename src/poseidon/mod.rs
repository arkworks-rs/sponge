use crate::Vec;
use crate::{Absorbable, CryptographicSponge, FieldElementSize};
use ark_ff::PrimeField;
use ark_marlin::fiat_shamir::poseidon::PoseidonSponge;
use ark_marlin::fiat_shamir::{FiatShamirAlgebraicSpongeRng, FiatShamirRng};

pub struct PoseidonSpongeWrapper<F: PrimeField, CF: PrimeField> {
    sponge: FiatShamirAlgebraicSpongeRng<F, CF, PoseidonSponge<CF>>,
}

impl<F: PrimeField, CF: PrimeField> CryptographicSponge<F> for PoseidonSpongeWrapper<F, CF> {
    fn new() -> Self {
        let sponge = FiatShamirAlgebraicSpongeRng::<F, CF, PoseidonSponge<CF>>::new();
        Self { sponge }
    }

    fn absorb(&mut self, input: &impl Absorbable<F>) {
        let input_bytes = input.to_sponge_bytes();
        self.sponge.absorb_bytes(input_bytes.as_slice());
    }

    fn squeeze_bytes(&mut self, _num_bytes: usize) -> Vec<u8> {
        unimplemented!()
    }

    fn squeeze_field_elements_with_sizes(&mut self, _sizes: &[FieldElementSize]) -> Vec<F> {
        unimplemented!()
    }

    fn squeeze_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        self.sponge.squeeze_nonnative_field_elements(num_elements)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::poseidon::PoseidonSpongeWrapper;
    use crate::CryptographicSponge;
    use ark_ed_on_bls12_381::constraints::EdwardsVar;
    use ark_ed_on_bls12_381::{EdwardsAffine, Fq, Fr};
    use ark_ff::{Field, One, UniformRand};
    use ark_marlin::fiat_shamir::constraints::{FiatShamirAlgebraicSpongeRngVar, FiatShamirRngVar};
    use ark_marlin::fiat_shamir::poseidon::constraints::PoseidonSpongeVar;
    use ark_marlin::fiat_shamir::poseidon::PoseidonSponge;
    use ark_nonnative_field::NonNativeFieldVar;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::fields::FieldVar;
    use ark_r1cs_std::{R1CSVar, ToBytesGadget, ToBitsGadget};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    type G = EdwardsAffine;
    type C = EdwardsVar;
    type F = Fr;
    type ConstraintF = Fq;

    type Sponge = FiatShamirAlgebraicSpongeRngVar<
        F,
        ConstraintF,
        PoseidonSponge<ConstraintF>,
        PoseidonSpongeVar<ConstraintF>,
    >;

    type NNFieldVar = NonNativeFieldVar<F, ConstraintF>;

    #[test]
    fn tests() {
        let _rng = test_rng();
        let mut sponge = PoseidonSpongeWrapper::<F, ConstraintF>::new();
        sponge.absorb(&F::one());

        /*
        let elem = G::rand(&mut rng);
        sponge.absorb(&to_bytes![elem].unwrap());

         */

        let cs = ConstraintSystem::<ConstraintF>::new_ref();
        let _sponge_var = Sponge::new(cs.clone());

        let f_var = NNFieldVar::new_input(cs.clone(), || Ok(F::one())).unwrap();
        println!("Input: {:?}", f_var.to_bytes().unwrap().value().unwrap());

        let f_constant = NNFieldVar::new_constant(cs.clone(), F::one()).unwrap();
        println!("Constant: {:?}", f_constant.to_bytes().unwrap().value().unwrap());

        let f_witness = NNFieldVar::new_witness(cs.clone(), || Ok(F::one())).unwrap();
        //println!("Witness: {:?}", f_witness.to_bytes().unwrap().value().unwrap());

        let _bits = f_witness.to_bits_le().unwrap();
        //println!("Constant bits: {:?}", bits.value().unwrap());
        //println!("{:}", bits.len());

        assert!(false);
        /*
        sponge_var.absorb_bytes(&f_var.to_bytes().unwrap());

        /*
        let elem_var = C::new_input(cs.clone(), || Ok(elem)).unwrap();
        sponge_var.absorb_bytes(&elem_var.to_bytes().unwrap());
         */

        let squeeze = sponge.squeeze_field_elements(1).pop().unwrap();
        let squeeze_var = sponge_var.squeeze_field_elements(1).unwrap().pop().unwrap();

        assert_eq!(squeeze, squeeze_var.value().unwrap());

         */
    }
}
