use ark_ff::{PrimeField, ToConstraintField, to_bytes};
use ark_ff::models::{
    Fp256, Fp256Parameters, Fp320, Fp320Parameters, Fp384, Fp384Parameters, Fp768, Fp768Parameters,
    Fp832, Fp832Parameters,
};

/// An interface for objects that can be absorbed by a `CryptographicSponge`.
pub trait Absorbable<F: PrimeField> {
    /// Converts the object into a list of bytes that can be absorbed by a `CryptographicSponge`.
    fn to_sponge_bytes(&self) -> Vec<u8>;

    /// Converts the object into field elements that can be absorbed by a `CryptographicSponge`.
    fn to_sponge_field_elements(&self) -> Vec<F>;

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
}

impl<F: PrimeField> Absorbable<F> for u8 {
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
        //let mut bytes = (batch.len() as u64).to_le_bytes().to_vec();
        //bytes.extend_from_slice(batch);
        //bytes.to_field_elements().unwrap()
        batch.to_field_elements().unwrap()
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

impl<F: PrimeField, A: Absorbable<F>> Absorbable<F> for &[A] {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        A::batch_to_sponge_bytes(self)
    }

    fn to_sponge_field_elements(&self) -> Vec<F> {
        A::batch_to_sponge_field_elements(self)
    }
}

impl<F: PrimeField, A: Absorbable<F>> Absorbable<F> for Vec<A> {
    fn to_sponge_bytes(&self) -> Vec<u8> {
        self.as_slice().to_sponge_bytes()
    }

    fn to_sponge_field_elements(&self) -> Vec<F> {
        self.as_slice().to_sponge_field_elements()
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
/// Format is `absorb!(s, a_0, a_1, ..., a_n)`, where `s` is a mutable reference to a sponge
/// and each `a_i` implements `Absorbable`.
#[macro_export]
macro_rules! absorb {
    ($sponge:expr, $($absorbable:expr),+ ) => {
        $(
            CryptographicSponge::absorb($sponge, &$absorbable);
        )+
    };
}
