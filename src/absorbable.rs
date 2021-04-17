#![allow(unused)]
use ark_ec::models::short_weierstrass_jacobian::GroupAffine as SWAffine;
use ark_ec::models::twisted_edwards_extended::GroupAffine as TEAffine;
use ark_ec::models::{SWModelParameters, TEModelParameters};
use ark_ff::models::{
    Fp256, Fp256Parameters, Fp320, Fp320Parameters, Fp384, Fp384Parameters, Fp768, Fp768Parameters,
    Fp832, Fp832Parameters,
};
use ark_ff::{to_bytes, PrimeField, ToBytes, ToConstraintField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::any::TypeId;
use ark_std::ops::Deref;
use ark_std::vec;
use ark_std::vec::Vec;

/// An interface for objects that can be absorbed by a `CryptographicSponge`.
pub trait Absorb {
    /// Converts the object into a list of bytes that can be absorbed by a `CryptographicSponge`.
    /// Append the list to `dest`.
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>);

    /// Converts the object into a list of bytes that can be absorbed by a `CryptographicSponge`.
    /// Return the list as `Vec`.
    fn to_sponge_bytes_as_vec(&self) -> Vec<u8> {
        let mut result = Vec::new();
        self.to_sponge_bytes(&mut result);
        result
    }

    /// Converts the object into field elements that can be absorbed by a `CryptographicSponge`.
    /// Append the list to `dest`
    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>);

    /// Converts the object into field elements that can be absorbed by a `CryptographicSponge`.
    /// Return the list as `Vec`
    fn to_sponge_field_elements_as_vec<F: PrimeField>(&self) -> Vec<F> {
        let mut result = Vec::new();
        self.to_sponge_field_elements(&mut result);
        result
    }

    /// Specifies the conversion into a list of bytes for a batch. Append the list to `dest`.
    fn batch_to_sponge_bytes(batch: &[Self], dest: &mut Vec<u8>)
    where
        Self: Sized,
    {
        for absorbable in batch {
            absorbable.to_sponge_bytes(dest)
        }
    }

    /// Specifies the conversion into a list of bytes for a batch. Return the list as `Vec`.
    fn batch_to_sponge_bytes_as_vec(batch: &[Self]) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut result = Vec::new();
        Self::batch_to_sponge_bytes(batch, &mut result);
        result
    }

    /// Specifies the conversion into a list of field elements for a batch. Append the list to `dest`.
    fn batch_to_sponge_field_elements<F: PrimeField>(batch: &[Self], dest: &mut Vec<F>)
    where
        Self: Sized,
    {
        for absorbable in batch {
            absorbable.to_sponge_field_elements(dest)
        }
    }

    /// Specifies the conversion into a list of field elements for a batch. Append the list to `dest`.
    fn batch_to_sponge_field_elements_as_vec<F: PrimeField>(batch: &[Self]) -> Vec<F>
    where
        Self: Sized,
    {
        let mut result = Vec::new();
        for absorbable in batch {
            absorbable.to_sponge_field_elements(&mut result)
        }
        result
    }
}

/// If `F1` equals to `F2`, return `x` as `F2`, otherwise panics.
/// ## Panics
/// This function will panic if `F1` is not equal to `F2`.
fn field_cast<F1: PrimeField, F2: PrimeField>(input: F1) -> F2 {
    if TypeId::of::<F1>() != TypeId::of::<F2>() {
        panic!("Try to absorb non-native field elements.")
    } else {
        let mut buf = Vec::new();
        input.serialize_unchecked(&mut buf).unwrap();
        F2::deserialize_unchecked(&buf[..]).unwrap()
    }
}

/// If `F1` equals to `F2`, add all elements of x as `F2` to `dest`, otherwise panics.
/// ## Panics
/// This function will panic if `F1` is not equal to `F2`.
fn batch_field_cast<F1: PrimeField, F2: PrimeField>(x: &[F1], dest: &mut Vec<F2>) {
    if TypeId::of::<F1>() != TypeId::of::<F2>() {
        panic!("Try to absorb non-native field elements.")
    } else {
        let mut buf = Vec::new();
        x.serialize_unchecked(&mut buf).unwrap();
        dest.extend(Vec::<F2>::deserialize_unchecked(&buf[..]).unwrap())
    }
}

impl Absorb for u8 {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        self.write(dest).unwrap()
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        dest.push(F::from(*self))
    }

    fn batch_to_sponge_bytes(batch: &[Self], dest: &mut Vec<u8>) {
        dest.extend_from_slice(batch)
    }

    fn batch_to_sponge_field_elements<F: PrimeField>(batch: &[Self], dest: &mut Vec<F>) {
        let mut bytes = (batch.len() as u64).to_le_bytes().to_vec();
        bytes.extend_from_slice(batch);
        dest.extend_from_slice(&bytes.to_field_elements().unwrap()[..])
    }
}

impl Absorb for bool {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        dest.push(*self as u8)
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        dest.push(F::from(*self))
    }
}

macro_rules! impl_absorbable_field {
    ($field:ident, $params:ident) => {
        impl<P: $params> Absorb for $field<P> {
            fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
                self.write(dest).unwrap()
            }

            fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
                dest.push(field_cast(*self))
            }

            fn batch_to_sponge_field_elements<F: PrimeField>(batch: &[Self], dest: &mut Vec<F>)
            where
                Self: Sized,
            {
                batch_field_cast(batch, dest)
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
        impl Absorb for $t {
            fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
                dest.extend_from_slice(&self.to_le_bytes()[..])
            }

            fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
                dest.push(F::from(*self))
            }
        }
    };
}
//
impl_absorbable_unsigned!(u16);
impl_absorbable_unsigned!(u32);
impl_absorbable_unsigned!(u64);
impl_absorbable_unsigned!(u128);

macro_rules! impl_absorbable_signed {
    ($signed:ident, $unsigned:ident) => {
        impl Absorb for $signed {
            fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
                dest.extend_from_slice(&self.to_le_bytes()[..])
            }

            fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
                let mut elem = F::from(self.abs() as $unsigned);
                if *self < 0 {
                    elem = -elem;
                }
                dest.push(elem)
            }
        }
    };
}

impl_absorbable_signed!(i8, u8);
impl_absorbable_signed!(i16, u16);
impl_absorbable_signed!(i32, u32);
impl_absorbable_signed!(i64, u64);
impl_absorbable_signed!(i128, u128);

impl Absorb for usize {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(&self.to_le_bytes()[..])
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        (*self as u64).to_sponge_field_elements(dest)
    }
}

impl Absorb for isize {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        dest.extend_from_slice(&self.to_le_bytes()[..])
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        (*self as i64).to_sponge_field_elements(dest)
    }
}

// TODO: I will implement absorb for those later.
// impl<P: TEModelParameters> Absorb for TEAffine<P> {
//     fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
//         self.write(dest).unwrap()
//     }
//
//     fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
//         dest.extend(self.to_field_elements().unwrap())
//     }
// }
//
// impl<P: SWModelParameters> Absorb for SWAffine<P> {
//     fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
//         self.write(dest).unwrap()
//     }
//
//     fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
//         dest.extend(self.to_field_elements().unwrap())
//     }
// }

impl<A: Absorb> Absorb for &[A] {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        A::batch_to_sponge_bytes(self, dest)
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        A::batch_to_sponge_field_elements(self, dest)
    }
}

impl<A: Absorb> Absorb for Vec<A> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        self.as_slice().to_sponge_bytes(dest)
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.as_slice().to_sponge_field_elements(dest)
    }
}

impl<A: Absorb> Absorb for Option<A> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        self.is_some().to_sponge_bytes(dest);
        if let Some(item) = self {
            item.to_sponge_bytes(dest)
        }
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.is_some().to_sponge_field_elements(dest);
        if let Some(item) = self {
            item.to_sponge_field_elements(dest)
        }
    }
}

impl<A: Absorb> Absorb for &A {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        (*self).to_sponge_bytes(dest)
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        (*self).to_sponge_field_elements(dest)
    }
}

/// Individually absorbs each element in a comma-separated list of absorbables into a sponge.
/// Format is `absorb!(s, a_0, a_1, ..., a_n)`, where `s` is a mutable reference to a sponge
/// and each `a_i` implements `Absorb`.
#[macro_export]
macro_rules! absorb {
    ($sponge:expr, $($absorbable:expr),+ ) => {
        $(
            CryptographicSponge::absorb($sponge, &$absorbable);
        )+
    };
}

/// Quickly convert a list of different [`Absorb`]s into sponge bytes.
#[macro_export]
macro_rules! collect_sponge_bytes {
    ($head:expr $(, $tail:expr)* ) => {
        {
            let mut output = Absorb::to_sponge_bytes_as_vec(&$head);
            $(
                Absorb::to_sponge_bytes(&$tail, output);
            )*
            output
        }
    };
}

/// Quickly convert a list of different [`Absorb`]s into sponge field elements.
#[macro_export]
macro_rules! collect_sponge_field_elements {
    ($head:expr $(, $tail:expr)* ) => {
        {
            let mut output = Absorb::to_sponge_field_elements_as_vec(&$head);
            $(
               Absorb::to_sponge_field_elements(&$tail, output);
            )*
            output
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::Absorb;
    use ark_ff::{One, PrimeField, UniformRand};
    use ark_std::any::TypeId;
    use ark_std::test_rng;
    use ark_test_curves::bls12_381::Fr;
    use ark_test_curves::mnt4_753::Fr as MntFr;

    fn assert_different_encodings<F: PrimeField, A: Absorb>(a: &A, b: &A) {
        let bytes1 = a.to_sponge_bytes_as_vec();
        let bytes2 = b.to_sponge_bytes_as_vec();

        let field1 = a.to_sponge_field_elements_as_vec::<F>();
        let field2 = b.to_sponge_field_elements_as_vec::<F>();

        assert_ne!(bytes1, bytes2);
        assert_ne!(field1, field2);
    }

    #[test]
    fn single_field_element() {
        let mut rng = test_rng();
        let elem1 = Fr::rand(&mut rng);
        let elem2 = elem1 + Fr::one();

        assert_different_encodings::<Fr, _>(&elem1, &elem2)
    }

    #[test]
    fn list_with_constant_size_element() {
        let mut rng = test_rng();
        let lst1: Vec<_> = (0..1024 * 8).map(|_| Fr::rand(&mut rng)).collect();
        let mut lst2 = lst1.to_vec();
        lst2[3] += Fr::one();

        assert_different_encodings::<Fr, _>(&lst1, &lst2)
    }

    // struct VariableSizeList(Vec<u8>);
    //
    // impl<F: PrimeField> Absorb<F> for VariableSizeList {
    //     fn to_sponge_bytes(&self) -> Vec<u8> {
    //         <Vec<u8> as AbsorbWithLength<F>>::to_sponge_bytes_with_length(&self.0)
    //     }
    //
    //     fn to_sponge_field_elements(&self) -> Vec<F> {
    //         <Vec<u8> as AbsorbWithLength<F>>::to_sponge_field_elements_with_length(&self.0)
    //     }
    // }
    //
    // #[test]
    // fn list_with_nonconstant_size_element() {
    //     let lst1 = vec![
    //         VariableSizeList(vec![1u8, 2, 3, 4]),
    //         VariableSizeList(vec![5, 6]),
    //     ];
    //     let lst2 = vec![
    //         VariableSizeList(vec![1u8, 2]),
    //         VariableSizeList(vec![3, 4, 5, 6]),
    //     ];
    //
    //     assert_different_encodings::<Fr, _>(&lst1, &lst2);
    // }
    //
    // fn is_type_equal<F1: PrimeField, F2: PrimeField>() -> bool {
    //     TypeId::of::<F1>() == TypeId::of::<F2>()
    // }
    //
    // #[test]
    // fn test_type_equality() {
    //     assert!(is_type_equal::<Fr, Fr>());
    //     assert!(!is_type_equal::<Fr, MntFr>())
    // }
}
