use ark_ec::models::short_weierstrass_jacobian::GroupAffine as SWAffine;
use ark_ec::models::twisted_edwards_extended::GroupAffine as TEAffine;
use ark_ec::models::{SWModelParameters, TEModelParameters};
use ark_ff::models::{
    Fp256, Fp256Parameters, Fp320, Fp320Parameters, Fp384, Fp384Parameters, Fp768, Fp768Parameters,
    Fp832, Fp832Parameters,
};
use ark_ff::{to_bytes, PrimeField, ToConstraintField};
use ark_std::vec;
use ark_std::vec::Vec;

/// An interface for objects that can be absorbed by a `CryptographicSponge`.
pub trait Absorb<F: PrimeField> {
    /// Converts the object into a list of bytes that can be absorbed by a `CryptographicSponge`.
    fn to_sponge_bytes(&self) -> Vec<u8>;

    /// Converts the object into field elements that can be absorbed by a `CryptographicSponge`.
    fn to_sponge_field_elements(&self) -> Vec<F>;

    /// Specifies the conversion into a list of bytes for a batch.
    fn batch_to_sponge_bytes(batch: &[Self]) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut output = Vec::new();
        for absorbable in batch {
            output.append(&mut absorbable.to_sponge_bytes());
        }

        output
    }

    /// Specifies the conversion into a list of bytes for a batch along with its length information.
    fn batch_to_sponge_bytes_with_length(batch: &[Self]) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut output = Vec::new();
        output.append(&mut <u64 as Absorb<F>>::to_sponge_bytes(
            &(batch.len() as u64),
        ));
        for absorbable in batch {
            output.append(&mut absorbable.to_sponge_bytes());
        }

        output
    }

    /// Specifies the conversion into a list of field elements for a batch.
    fn batch_to_sponge_field_elements(batch: &[Self]) -> Vec<F>
    where
        Self: Sized,
    {
        let mut output = Vec::new();
        for absorbable in batch {
            output.append(&mut absorbable.to_sponge_field_elements());
        }

        output
    }

    /// Specifies the conversion into a list of field elements for a batch along with its length information.
    fn batch_to_sponge_field_elements_with_length(batch: &[Self]) -> Vec<F>
    where
        Self: Sized,
    {
        let mut output = Vec::new();
        output.append(&mut <u64 as Absorb<F>>::to_sponge_field_elements(
            &(batch.len() as u64),
        ));
        for absorbable in batch {
            output.append(&mut absorbable.to_sponge_field_elements());
        }

        output
    }
}

/// An extension to `Absorb` interface that allows an option for sponge to absorb length information.
/// This extended interface should be used in cases when the length of `self` is list-like and
pub trait AbsorbWithLength<F: PrimeField>: Absorb<F> {
    /// Converts the object and its length information into a list of bytes that
    /// can be absorbed by a `CryptographicSponge`.
    fn to_sponge_bytes_with_length(&self) -> Vec<u8>;

    /// Converts the object and its length information into field elements that can be absorbed by a `CryptographicSponge`.
    fn to_sponge_field_elements_with_length(&self) -> Vec<F>;
}

impl<F: PrimeField> Absorb<F> for u8 {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        vec![*self]
    }

    fn to_sponge_field_elements(&self) -> Vec<F> {
        vec![F::from(*self)]
    }

    fn batch_to_sponge_bytes(batch: &[Self]) -> Vec<u8> {
        batch.to_vec()
    }

    fn batch_to_sponge_field_elements(batch: &[Self]) -> Vec<F> {
        let mut bytes = (batch.len() as u64).to_le_bytes().to_vec();
        bytes.extend_from_slice(batch);
        bytes.to_field_elements().unwrap()
    }
}

impl<F: PrimeField> Absorb<F> for bool {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        vec![(*self as u8)]
    }

    fn to_sponge_field_elements(&self) -> Vec<F> {
        vec![F::from(*self)]
    }
}

macro_rules! impl_absorbable_field {
    ($field:ident, $params:ident) => {
        impl<P: $params> Absorb<$field<P>> for $field<P> {
            fn to_sponge_bytes(&self) -> Vec<u8> {
                to_bytes![self].unwrap()
            }

            fn to_sponge_field_elements(&self) -> Vec<$field<P>> {
                vec![*self]
            }

            fn batch_to_sponge_field_elements(batch: &[Self]) -> Vec<$field<P>> {
                batch.to_vec()
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
        impl<F: PrimeField> Absorb<F> for $t {
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
        impl<F: PrimeField> Absorb<F> for $signed {
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
        impl<F: PrimeField> Absorb<F> for $t {
            fn to_sponge_bytes(&self) -> Vec<u8> {
                Absorb::<F>::to_sponge_bytes(&(*self as u64))
            }

            fn to_sponge_field_elements(&self) -> Vec<F> {
                (*self as u64).to_sponge_field_elements()
            }
        }
    };
}

impl_absorbable_size!(usize);
impl_absorbable_size!(isize);

macro_rules! impl_absorbable_group {
    ($group:ident, $params:ident) => {
        impl<P: $params, F: PrimeField> Absorb<F> for $group<P>
        where
            P::BaseField: ToConstraintField<F>,
        {
            fn to_sponge_bytes(&self) -> Vec<u8> {
                Absorb::<F>::to_sponge_bytes(&to_bytes!(self).unwrap())
            }

            fn to_sponge_field_elements(&self) -> Vec<F> {
                self.to_field_elements().unwrap()
            }
        }
    };
}

impl_absorbable_group!(TEAffine, TEModelParameters);
impl_absorbable_group!(SWAffine, SWModelParameters);

impl<F: PrimeField, A: Absorb<F>> Absorb<F> for &[A] {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        A::batch_to_sponge_bytes(self)
    }

    fn to_sponge_field_elements(&self) -> Vec<F> {
        A::batch_to_sponge_field_elements(self)
    }
}

impl<F: PrimeField, A: Absorb<F>> AbsorbWithLength<F> for &[A] {
    fn to_sponge_bytes_with_length(&self) -> Vec<u8> {
        A::batch_to_sponge_bytes_with_length(self)
    }

    fn to_sponge_field_elements_with_length(&self) -> Vec<F> {
        A::batch_to_sponge_field_elements_with_length(self)
    }
}

impl<F: PrimeField, A: Absorb<F>> Absorb<F> for Vec<A> {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        self.as_slice().to_sponge_bytes()
    }

    fn to_sponge_field_elements(&self) -> Vec<F> {
        self.as_slice().to_sponge_field_elements()
    }
}

impl<F: PrimeField, A: Absorb<F>> AbsorbWithLength<F> for Vec<A> {
    fn to_sponge_bytes_with_length(&self) -> Vec<u8> {
        self.as_slice().to_sponge_bytes_with_length()
    }

    fn to_sponge_field_elements_with_length(&self) -> Vec<F> {
        self.as_slice().to_sponge_field_elements_with_length()
    }
}

impl<F: PrimeField, A: Absorb<F>> Absorb<F> for Option<A> {
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

impl<F: PrimeField, A: Absorb<F>> Absorb<F> for &A {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        (*self).to_sponge_bytes()
    }

    fn to_sponge_field_elements(&self) -> Vec<F> {
        (*self).to_sponge_field_elements()
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
    ($type:ident, $head:expr $(, $tail:expr)* ) => {
        {
            let mut output = Absorbable::<$type>::to_sponge_bytes(&$head);
            $(
                output.append(&mut Absorbable::<$type>::to_sponge_bytes(&$tail));
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
            let mut output = Absorb::to_sponge_field_elements(&$head);
            $(
                output.append(&mut Absorb::to_sponge_field_elements(&$tail));
            )*
            output
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::{Absorb, AbsorbWithLength};
    use ark_ff::{One, PrimeField, UniformRand};
    use ark_std::test_rng;
    use ark_test_curves::bls12_381::Fr;

    fn assert_different_encodings<F: PrimeField, A: Absorb<F>>(a: &A, b: &A) {
        let bytes1 = a.to_sponge_bytes();
        let bytes2 = b.to_sponge_bytes();

        let field1 = a.to_sponge_field_elements();
        let field2 = b.to_sponge_field_elements();

        assert_ne!(bytes1, bytes2);
        assert_ne!(field1, field2);
    }

    #[test]
    fn single_field_element() {
        let mut rng = test_rng();
        let elem1 = Fr::rand(&mut rng);
        let elem2 = elem1 + Fr::one();

        assert_different_encodings(&elem1, &elem2)
    }

    #[test]
    fn list_with_constant_size_element() {
        let lst1 = vec![1u8, 2, 3, 4, 5, 6];
        let lst2 = vec![2u8, 3, 4, 5, 6, 7];

        assert_different_encodings::<Fr, _>(&lst1, &lst2)
    }

    struct VariableSizeList(Vec<u8>);

    impl<F: PrimeField> Absorb<F> for VariableSizeList {
        fn to_sponge_bytes(&self) -> Vec<u8> {
            <Vec<u8> as AbsorbWithLength<F>>::to_sponge_bytes_with_length(&self.0)
        }

        fn to_sponge_field_elements(&self) -> Vec<F> {
            <Vec<u8> as AbsorbWithLength<F>>::to_sponge_field_elements_with_length(&self.0)
        }
    }

    #[test]
    fn list_with_nonconstant_size_element() {
        let lst1 = vec![
            VariableSizeList(vec![1u8, 2, 3, 4]),
            VariableSizeList(vec![5, 6]),
        ];
        let lst2 = vec![
            VariableSizeList(vec![1u8, 2]),
            VariableSizeList(vec![3, 4, 5, 6]),
        ];

        assert_different_encodings::<Fr, _>(&lst1, &lst2);
    }
}
