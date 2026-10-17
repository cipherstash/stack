//! Scalar plaintexts for the v4 number and boolean types.
//!
//! A Stack Encrypt target encrypts a plaintext through Vitamin C's
//! `Encrypt` and reads it back through `Decrypt`. These newtypes name the
//! plaintext of each number and boolean EQL v4 type: [`Int32`] for `Integer`
//! and `IntegerEq`, [`Int64`] for `Bigint` and `BigintEq`, [`Bool`] for
//! `Boolean`, and [`Float32`] / [`Float64`] for `Real`, `RealEq`, `Double`
//! and `DoubleEq`.
//!
//! Each describes itself as the primitive it wraps, so it seals the leaf
//! vitaminc seals for that primitive, which is the leaf a data plan's field of
//! the same type seals. So a value written through these types and one
//! written by the Go SDK as a plain `int32` field open each other.
//!
//! Each reads back only its own width. vitaminc's primitive targets convert
//! an integer of any width that fits, and widen an `f32` to an `f64`; these
//! refuse a leaf of another width, so a column's type is the one it was
//! written with.
//!
//! The equality types store the engine's equality term beside the
//! ciphertext, derived over ADR-0002's semantic baseline: one integer of
//! either width has one term, and a float's `-0.0` and every NaN fold to one
//! value each, as Postgres's `float8 =` treats them. The ciphertext keeps the
//! value exactly, so `-0.0` still opens as `-0.0`.
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

use stack_encrypt::Encrypt;
use vitaminc_aead::{Float, FromScalar, Int, Logical, Physical, Sink};
use zeroize::Zeroize;

macro_rules! fixed_scalar {
    ($(#[$doc:meta])* $name:ident($inner:ty), $read:pat => $value:expr, |$a:ident, $b:ident| $eq:expr) => {
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

        /// Describes itself as the primitive it wraps.
        impl Encrypt for $name {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                self.0.visit(sink)
            }
        }

        /// Reads back a leaf of exactly this kind and width, and nothing
        /// else: a value sealed as one kind never opens as another.
        impl FromScalar for $name {
            const EXPECTED: &'static str = stringify!($inner);
            fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
                match (ty, value) {
                    (None, $read) => Some($name($value)),
                    _ => None,
                }
            }
        }
    };
}

fixed_scalar!(
    /// The plaintext of `Integer`: a 32-bit signed integer.
    Int32(i32), Physical::Int(Int::I32(v)) => v, |a, b| a == b
);
fixed_scalar!(
    /// The plaintext of `Bigint`: a 64-bit signed integer.
    Int64(i64), Physical::Int(Int::I64(v)) => v, |a, b| a == b
);
fixed_scalar!(
    /// The plaintext of `Real`: a 32-bit float, sealed by its bit pattern, so
    /// `-0.0` and a NaN's payload survive a round trip.
    Float32(f32), Physical::Float(Float::F32(v)) => v, |a, b| a.to_bits() == b.to_bits()
);
fixed_scalar!(
    /// The plaintext of `Double`: a 64-bit float, sealed by its bit pattern.
    Float64(f64), Physical::Float(Float::F64(v)) => v, |a, b| a.to_bits() == b.to_bits()
);

/// The plaintext of `Boolean`.
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

/// Describes itself as a `bool`.
impl Encrypt for Bool {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.0.visit(sink)
    }
}

/// Reads back a boolean leaf, and nothing else.
impl FromScalar for Bool {
    const EXPECTED: &'static str = "bool";
    fn from_scalar(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
        match (ty, value) {
            (None, Physical::Bool(b)) => Some(Bool(b)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    //! What each type reads back. Sealing is the primitive's own; what is
    //! written here is the reading, so these pin that each type takes only
    //! its own kind and width. The round trip against the value enum
    //! (`FfiValue`) is in the encryption test crate
    //! (`tests/encryption/tests/v4_types.rs`).
    use super::*;

    fn read<T: FromScalar>(value: Physical<'_>) -> Option<T> {
        T::from_scalar(None, value)
    }

    #[test]
    fn integers_read_their_own_width() {
        for v in [0, 1, -1, 42, i32::MIN, i32::MAX] {
            assert!(read::<Int32>(Physical::Int(Int::I32(v))) == Some(Int32(v)));
        }
        for v in [0, -1, 42, i64::MIN, i64::MAX] {
            assert!(read::<Int64>(Physical::Int(Int::I64(v))) == Some(Int64(v)));
        }
    }

    #[test]
    fn a_scalar_of_another_kind_or_width_is_refused() {
        // An Int64 leaf is not an Int32, even when its value would fit.
        assert!(read::<Int32>(Physical::Int(Int::I64(1))).is_none());
        assert!(read::<Int64>(Physical::Int(Int::I32(1))).is_none());
        assert!(read::<Int32>(Physical::Int(Int::U32(1))).is_none());
        // A float's leaf is not an integer's, nor a boolean's.
        assert!(read::<Int32>(Physical::Float(Float::F32(1.0))).is_none());
        assert!(read::<Bool>(Physical::Int(Int::I32(1))).is_none());
        // An f32 leaf is not an f64, though it would widen exactly.
        assert!(read::<Float64>(Physical::Float(Float::F32(1.0))).is_none());
        assert!(read::<Float32>(Physical::Float(Float::F64(1.0))).is_none());
        // A logical type on the leaf is not the bare scalar.
        assert!(Int32::from_scalar(Some(Logical::Date), Physical::Int(Int::I32(1))).is_none());
    }

    #[test]
    fn floats_read_their_bit_pattern() {
        let nan32 = f32::from_bits(0x7fc0_1234);
        for v in [0.0, -0.0, 1.5, f32::INFINITY, f32::NEG_INFINITY, nan32] {
            let opened = read::<Float32>(Physical::Float(Float::F32(v))).unwrap();
            assert_eq!(opened.0.to_bits(), v.to_bits());
        }
        let nan64 = f64::from_bits(0x7ff8_0000_0000_beef);
        for v in [0.0, -0.0, 1.5, f64::INFINITY, nan64] {
            let opened = read::<Float64>(Physical::Float(Float::F64(v))).unwrap();
            assert_eq!(opened.0.to_bits(), v.to_bits());
        }
    }

    #[test]
    fn booleans_read_both_values() {
        assert!(read::<Bool>(Physical::Bool(true)) == Some(Bool(true)));
        assert!(read::<Bool>(Physical::Bool(false)) == Some(Bool(false)));
        assert!(read::<Bool>(Physical::Null).is_none());
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
