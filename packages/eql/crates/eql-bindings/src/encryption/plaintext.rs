//! Scalar plaintexts for the v4 number and boolean types.
//!
//! A Stack Encrypt target encrypts a plaintext through Vitamin C's
//! `Encrypt` and `Decrypt` traits, and vitaminc 0.5 implements
//! `Encrypt` for `String` but not for `i32`, `i64`, `bool`, `f32` or `f64`.
//! These newtypes fill that gap for the storage-only EQL v4 types: [`Int32`]
//! for `Integer`, [`Int64`] for `Bigint`, [`Bool`] for `Boolean`, and
//! [`Float32`] / [`Float64`] for `Real` and `Double`.
//!
//! Each seals as vitaminc's tagged leaf, `[tag] ++ payload` from the frozen
//! table in `vitaminc_aead_value::tags`, which is exactly what the value enum
//! (`FfiValue`) seals for the same value. So a value written through these
//! types and one written by the Go SDK as a plain `int32` field open each
//! other.
//!
//! None of them derives an equality term. `IntegerEq` and `BigintEq` are held
//! back until vitaminc 0.6, whose integer equality term uses one PRF domain
//! for every width; a term derived here under vitaminc 0.5's per-width
//! domains would stop matching after that upgrade.
//!
//! ```rust,ignore
//! use eql_bindings::encryption::plaintext::Int32;
//! use eql_bindings::v4::integer::Integer;
//!
//! let stored: Integer = keyset.encrypt_as(&Int32(42), column).await?;
//! let opened: Int32 = cipher.decrypt_as(stored, expected).await?;
//! ```
//!
//! None of them implements `Debug`, so a plaintext does not reach a log by
//! accident.

use stack_encrypt::{Cipher, Decipher, Decrypt, Encrypt, IntoAad, Unspecified};
use vitaminc_aead::DecipherVisitor;
use vitaminc_aead_value::tagged::{
    TaggedBoolFalse, TaggedBoolTrue, TaggedFloat32, TaggedFloat64, TaggedInt32, TaggedInt64,
};
use vitaminc_aead_value::tags;
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

/// Reads one tagged scalar leaf back, refusing any other tag or width: a
/// value sealed as one kind never opens as another.
struct LeafVisitor<T> {
    tag: u8,
    parse: fn(&[u8]) -> Option<T>,
}

impl<'c, T: Send> DecipherVisitor<'c> for LeafVisitor<T> {
    type Value = T;

    fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<T, Unspecified> {
        match data.risky_ref().split_first() {
            Some((&tag, payload)) if tag == self.tag => (self.parse)(payload).ok_or(Unspecified),
            _ => Err(Unspecified),
        }
    }
}

/// Bytes a [`LeafVisitor`] reads back: one tag, then exactly `N` payload
/// bytes. Anything else is not this kind.
fn leaf_payload<const N: usize>(payload: &[u8]) -> Option<[u8; N]> {
    payload.try_into().ok()
}

macro_rules! fixed_scalar {
    ($(#[$doc:meta])* $name:ident($inner:ty), $tagged:ty, $tag:expr, $width:literal, |$bytes:ident| $decode:expr, |$a:ident, $b:ident| $eq:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Zeroize)]
        pub struct $name(pub $inner);

        /// Equal when the sealed payloads would be: by value for an integer,
        /// by bit pattern for a float, so `-0.0 != 0.0` and a NaN equals
        /// itself. That is the equality a round trip preserves.
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                let ($a, $b) = (self.0, other.0);
                $eq
            }
        }

        impl Eq for $name {}

        impl From<$inner> for $name {
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $inner {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl Encrypt for $name {
            fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
            where
                C: Cipher,
                A: IntoAad<'a>,
            {
                <$tagged>::from(self.0).encrypt_with_aad(cipher, aad)
            }
        }

        impl<'c> Decrypt<'c> for $name {
            fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
            where
                D: Decipher<'c>,
                A: IntoAad<'a>,
            {
                decipher.decrypt_any(Self::visitor(), aad)
            }
        }

        impl $name {
            /// The reader [`Decrypt`] opens this type's leaf with.
            fn visitor() -> LeafVisitor<Self> {
                LeafVisitor {
                    tag: $tag,
                    parse: |payload| {
                        let $bytes = leaf_payload::<$width>(payload)?;
                        Some($name($decode))
                    },
                }
            }
        }
    };
}

fixed_scalar!(
    /// The plaintext of `Integer`: a 32-bit signed integer.
    Int32(i32), TaggedInt32, tags::INT32, 4, |b| i32::from_le_bytes(b), |a, b| a == b
);
fixed_scalar!(
    /// The plaintext of `Bigint`: a 64-bit signed integer.
    Int64(i64), TaggedInt64, tags::INT64, 8, |b| i64::from_le_bytes(b), |a, b| a == b
);
fixed_scalar!(
    /// The plaintext of `Real`: a 32-bit float, sealed by its bit pattern, so
    /// `-0.0` and a NaN's payload survive a round trip.
    Float32(f32), TaggedFloat32, tags::FLOAT32, 4, |b| f32::from_bits(u32::from_le_bytes(b)),
    |a, b| a.to_bits() == b.to_bits()
);
fixed_scalar!(
    /// The plaintext of `Double`: a 64-bit float, sealed by its bit pattern.
    Float64(f64), TaggedFloat64, tags::FLOAT64, 8, |b| f64::from_bits(u64::from_le_bytes(b)),
    |a, b| a.to_bits() == b.to_bits()
);

/// The plaintext of `Boolean`. A boolean is the tag itself: no payload.
#[derive(Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct Bool(pub bool);

impl From<bool> for Bool {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

impl From<Bool> for bool {
    fn from(value: Bool) -> Self {
        value.0
    }
}

impl Encrypt for Bool {
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        if self.0 {
            TaggedBoolTrue::tag_only().encrypt_with_aad(cipher, aad)
        } else {
            TaggedBoolFalse::tag_only().encrypt_with_aad(cipher, aad)
        }
    }
}

/// Opens either boolean tag, and nothing else.
struct BoolVisitor;

impl<'c> DecipherVisitor<'c> for BoolVisitor {
    type Value = Bool;

    fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<Bool, Unspecified> {
        match data.risky_ref().as_slice() {
            [tags::BOOL_TRUE] => Ok(Bool(true)),
            [tags::BOOL_FALSE] => Ok(Bool(false)),
            _ => Err(Unspecified),
        }
    }
}

impl<'c> Decrypt<'c> for Bool {
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>,
    {
        decipher.decrypt_any(BoolVisitor, aad)
    }
}

#[cfg(test)]
mod tests {
    //! The leaf each type reads back, byte for byte. Sealing goes through
    //! vitaminc's own `Tagged*` types; what is hand-written here is the
    //! reading, so these pin its tag, width and byte order. The round trip
    //! against the value enum (`FfiValue`) is in the encryption test crate
    //! (`tests/encryption/tests/v4_types.rs`).
    use super::*;

    fn leaf(tag: u8, payload: &[u8]) -> Protected<Vec<u8>> {
        let mut bytes = vec![tag];
        bytes.extend_from_slice(payload);
        Protected::new(bytes)
    }

    fn read<'c, V: DecipherVisitor<'c>>(visitor: V, bytes: Protected<Vec<u8>>) -> Option<V::Value> {
        visitor.visit_bytes_vec(bytes).ok()
    }

    #[test]
    fn integers_read_their_own_little_endian_leaf() {
        let (int32, int64) = (Int32::visitor, Int64::visitor);
        for v in [0, 1, -1, 42, i32::MIN, i32::MAX] {
            assert!(read(int32(), leaf(tags::INT32, &v.to_le_bytes())) == Some(Int32(v)));
        }
        for v in [0, -1, 42, i64::MIN, i64::MAX] {
            assert!(read(int64(), leaf(tags::INT64, &v.to_le_bytes())) == Some(Int64(v)));
        }
        // Little-endian, not big: 1 is 01 00 00 00.
        assert!(read(int32(), leaf(tags::INT32, &[1, 0, 0, 0])) == Some(Int32(1)));
    }

    #[test]
    fn a_leaf_of_another_tag_or_width_is_refused() {
        let (int32, int64) = (Int32::visitor, Int64::visitor);
        // An Int64 leaf is not an Int32, even when its value would fit.
        assert!(read(int32(), leaf(tags::INT64, &1i64.to_le_bytes())).is_none());
        assert!(read(int64(), leaf(tags::INT32, &1i32.to_le_bytes())).is_none());
        // The right tag with the wrong width.
        assert!(read(int32(), leaf(tags::INT32, &1i64.to_le_bytes())).is_none());
        assert!(read(int32(), leaf(tags::INT32, &[1, 0, 0])).is_none());
        assert!(read(int64(), leaf(tags::INT64, &1i32.to_le_bytes())).is_none());
        // No tag at all.
        assert!(read(int32(), Protected::new(Vec::new())).is_none());
        // A float's leaf is not an integer's.
        assert!(read(int32(), leaf(tags::FLOAT32, &1f32.to_le_bytes())).is_none());
    }

    #[test]
    fn floats_read_their_bit_pattern() {
        let (f32s, f64s) = (Float32::visitor, Float64::visitor);
        let nan32 = f32::from_bits(0x7fc0_1234);
        for v in [0.0, -0.0, 1.5, f32::INFINITY, f32::NEG_INFINITY, nan32] {
            let opened = read(f32s(), leaf(tags::FLOAT32, &v.to_bits().to_le_bytes())).unwrap();
            assert_eq!(opened.0.to_bits(), v.to_bits());
        }
        let nan64 = f64::from_bits(0x7ff8_0000_0000_beef);
        for v in [0.0, -0.0, 1.5, f64::INFINITY, nan64] {
            let opened = read(f64s(), leaf(tags::FLOAT64, &v.to_bits().to_le_bytes())).unwrap();
            assert_eq!(opened.0.to_bits(), v.to_bits());
        }
        assert!(read(f64s(), leaf(tags::FLOAT32, &1f32.to_le_bytes())).is_none());
        assert!(read(f32s(), leaf(tags::FLOAT32, &1f64.to_le_bytes())).is_none());
    }

    #[test]
    fn booleans_are_the_tag_alone() {
        assert!(read(BoolVisitor, Protected::new(vec![tags::BOOL_TRUE])) == Some(Bool(true)));
        assert!(read(BoolVisitor, Protected::new(vec![tags::BOOL_FALSE])) == Some(Bool(false)));
        // A payload after the tag, or another tag, is not a boolean.
        assert!(read(BoolVisitor, Protected::new(vec![tags::BOOL_TRUE, 0])).is_none());
        assert!(read(BoolVisitor, leaf(tags::INT32, &1i32.to_le_bytes())).is_none());
        assert!(read(BoolVisitor, Protected::new(Vec::new())).is_none());
    }

    #[test]
    fn float_equality_is_by_bit_pattern() {
        assert!(Float32(-0.0) != Float32(0.0));
        assert!(Float64(-0.0) != Float64(0.0));
        assert!(Float32(f32::NAN) == Float32(f32::NAN));
        assert!(Float64(f64::NAN) == Float64(f64::NAN));
        assert!(Float64(f64::from_bits(0x7ff8_0000_0000_0001)) != Float64(f64::NAN));
        assert!(Int32(7) == Int32(7) && Int64(7) != Int64(8));
    }
}
