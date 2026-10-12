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

macro_rules! fixed_scalar {
    ($(#[$doc:meta])* $name:ident($inner:ty), $tagged:ty, $tag:expr, $width:literal, |$bytes:ident| $decode:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Zeroize)]
        pub struct $name(pub $inner);

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
                decipher.decrypt_any(
                    LeafVisitor {
                        tag: $tag,
                        parse: |payload| {
                            let $bytes: [u8; $width] = payload.try_into().ok()?;
                            Some($name($decode))
                        },
                    },
                    aad,
                )
            }
        }
    };
}

fixed_scalar!(
    /// The plaintext of `Integer`: a 32-bit signed integer.
    Int32(i32), TaggedInt32, tags::INT32, 4, |b| i32::from_le_bytes(b)
);
fixed_scalar!(
    /// The plaintext of `Bigint`: a 64-bit signed integer.
    Int64(i64), TaggedInt64, tags::INT64, 8, |b| i64::from_le_bytes(b)
);
fixed_scalar!(
    /// The plaintext of `Real`: a 32-bit float, sealed by its bit pattern, so
    /// `-0.0` and a NaN's payload survive a round trip.
    Float32(f32), TaggedFloat32, tags::FLOAT32, 4, |b| f32::from_bits(u32::from_le_bytes(b))
);
fixed_scalar!(
    /// The plaintext of `Double`: a 64-bit float, sealed by its bit pattern.
    Float64(f64), TaggedFloat64, tags::FLOAT64, 8, |b| f64::from_bits(u64::from_le_bytes(b))
);

/// The plaintext of `Boolean`. A boolean is the tag itself: no payload.
#[derive(Clone, Copy, PartialEq, Zeroize)]
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
