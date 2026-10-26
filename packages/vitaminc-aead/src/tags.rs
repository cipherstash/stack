//! Leaf type tags: the cross-language wire commitment.
//!
//! Every scalar seals as `[tag] ++ payload` **inside** the AEAD envelope, so
//! the tag is authenticated: flipping a value's type requires forging the
//! AEAD authentication tag. Containers (sequences, maps) are structural;
//! they use the ciphertext tree's shape and carry no tag.
//!
//! Each tag is read as shorthand for a physical kind plus a logical type:
//! `UINT32` is a plain int with a 32-bit width hint, `DATE` is
//! [`Logical::Date`](crate::Logical) over an int, and so on. A logical type
//! with no tag of its own travels in the [`LOGICAL`] envelope. See
//! [`leaf`](crate::leaf).
//!
//! # ⚠️ Frozen wire format
//!
//! These constants and their payload encodings are shared by every language
//! binding and are pinned byte-for-byte by known-answer tests. Changing one
//! breaks decryption of existing ciphertexts everywhere. New types must be
//! assigned **new** tags; tags are never reused or renumbered.

/// Null (JS `null`, Python `None`, Go `nil`). No payload.
pub const NULL: u8 = 0x00;
/// JavaScript `undefined`. No payload. Languages without an analog decode
/// this to their null value and never encode it.
pub const UNDEFINED: u8 = 0x01;
/// Boolean `false`. No payload — the value is the tag.
pub const BOOL_FALSE: u8 = 0x02;
/// Boolean `true`. No payload.
pub const BOOL_TRUE: u8 = 0x03;
/// 32-bit signed integer: 4 bytes, two's-complement, little-endian. Exists
/// for schema fidelity with Postgres `int4` at the EQL layer (not byte
/// savings) — integer-typed languages keep 16/32-bit values distinct from
/// [`INT64`].
pub const INT32: u8 = 0x04;
/// 64-bit signed integer: 8 bytes, two's-complement, little-endian.
/// Distinct from [`FLOAT64`] so integer-typed languages (Python, Go)
/// round-trip integers as integers.
pub const INT64: u8 = 0x05;
/// 32-bit unsigned integer: 4 bytes, little-endian. Exists for schema
/// fidelity with Postgres unsigned/`int4`-range values at the EQL layer.
pub const UINT32: u8 = 0x06;
/// 64-bit unsigned integer: 8 bytes, little-endian. Distinct from
/// [`INT64`] so unsigned values above `i64::MAX` (which [`INT64`] cannot
/// represent) round-trip losslessly without widening to [`UINT128`].
pub const UINT64: u8 = 0x07;
/// 32-bit floating-point number: 4 bytes, IEEE-754 binary32 bit pattern,
/// little-endian. Raw bits (not a numeric encoding) so `NaN` payloads and
/// `-0.0` survive round trips. Exists for schema fidelity with Postgres
/// `float4` at the EQL layer.
pub const FLOAT32: u8 = 0x08;
/// 64-bit floating-point number: 8 bytes, IEEE-754 binary64 bit pattern,
/// little-endian. Raw bits (not a numeric encoding) so `NaN` payloads and
/// `-0.0` survive round trips. This is the tag a JavaScript `number` maps
/// to.
pub const FLOAT64: u8 = 0x09;
/// String: UTF-8 bytes. Validated on decrypt.
pub const STRING: u8 = 0x0A;
/// Binary data: raw bytes.
pub const BYTES: u8 = 0x0B;

/// 8-bit signed integer: 1 byte, little-endian (two's complement).
pub const INT8: u8 = 0x0C;
/// 8-bit unsigned integer: 1 byte, little-endian.
pub const UINT8: u8 = 0x0D;
/// 16-bit signed integer: 2 bytes, little-endian (two's complement).
pub const INT16: u8 = 0x0E;
/// 16-bit unsigned integer: 2 bytes, little-endian.
pub const UINT16: u8 = 0x0F;
/// 128-bit signed integer: 16 bytes, little-endian (two's complement).
pub const INT128: u8 = 0x10;
/// 128-bit unsigned integer: 16 bytes, little-endian.
pub const UINT128: u8 = 0x11;
/// Date: `i32` days from CE (0001-01-01 is day 1), little-endian. Read as
/// [`Logical::Date`](crate::Logical) over an int holding days since
/// 1970-01-01.
pub const DATE: u8 = 0x12;
/// UTC timestamp: `i64` Unix seconds, then `u32` nanoseconds, little-endian.
/// The nanoseconds are below 2,000,000,000; values of 1,000,000,000 and
/// above were chrono's leap-second representation, which the `Value` codec
/// wrote and read before ADR 0001; this codec reads this tag as
/// [`Logical::Timestamp`](crate::Logical) in nanoseconds and refuses a leap
/// second, which has no count in any unit (see [`crate::leaf`]).
pub const TIMESTAMP: u8 = 0x13;
/// Decimal: rust_decimal's 16-byte `serialize()` layout, preserving scale.
/// Little-endian flags (sign bit 31, scale in bits 16–23, at most 28), then
/// low, middle and high `u32` words of the 96-bit mantissa. Other flag bits
/// must be zero. This finite format has no NaN or infinity. The sign bit
/// may be set on a zero mantissa. `vitaminc-aead`'s codec reads this tag as
/// [`Logical::Decimal`](crate::Logical) over an int holding the mantissa,
/// so a negative zero reads as zero (see [`crate::leaf`]).
pub const DECIMAL: u8 = 0x14;
/// Typed null: an absent value of a fixed-width type, padded to the length
/// of that type's leaf so a sealed absence cannot be told from a sealed
/// value by its length. `TYPED_NULL`, then the header a value of the type
/// starts with (its own tag, or the [`LOGICAL`] envelope's `LOGICAL, id,
/// param, tag`), then zero bytes for all but one byte of its payload. A
/// null date is `[TYPED_NULL, DATE, 0, 0, 0]`, five bytes like
/// `[DATE, d0, d1, d2, d3]`.
///
/// Only an int or a float, plain or under a logical type, and a uuid have a
/// typed null (see [`FixedType`](crate::FixedType)). A bool's leaf is the
/// tag alone, already as short as [`NULL`]; other text and bytes are
/// variable width. A uuid's typed null has no length before its padding,
/// even in a frame: its type fixes the length. A
/// reader refuses a typed null of any other tag, an envelope where a
/// shorthand tag exists, and padding that is not zero, so every absence
/// has one encoding. [`NULL`] stays a valid absence of any type.
pub const TYPED_NULL: u8 = 0x15;

/// The generic logical-type envelope: `LOGICAL, id, param`, then the plain
/// physical scalar. Carries any logical type that has no tag of its own.
/// An envelope is refused where a shorthand tag exists, so every value has
/// one encoding. Sits next to the transport frame's container tags
/// (`0xF0`–`0xF2`).
pub const LOGICAL: u8 = 0xF3;
/// Reserved for a logical-type envelope with a length-prefixed parameter,
/// should a logical type ever need more than one byte of parameter. Not
/// written, and refused on read.
pub const LOGICAL_LONG: u8 = 0xF4;

/// Reserved for the storage profile of `vitaminc-aead-frame`, which marks
/// an `Option`'s `Some` with it: `STORAGE_SOME`, then the node the `Some`
/// holds. Never a leaf tag or a transport frame tag, so a frame never holds
/// one and [`Frame::parse`](crate::Frame::parse) refuses it.
pub const STORAGE_SOME: u8 = 0xF5;
/// Reserved for the storage profile of `vitaminc-aead-frame`, which writes
/// a serde map with it: `STORAGE_MAP`, a `u32` count, then a key node and a
/// value node for each entry. Never a leaf tag or a transport frame tag.
pub const STORAGE_MAP: u8 = 0xF6;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{ARRAY, OBJECT, PASSTHROUGH};

    /// Every byte that starts a leaf, a frame node or a storage node means
    /// one thing: a new tag must take a byte no other tag holds.
    #[test]
    fn every_tag_is_its_own_byte() {
        let all = [
            NULL,
            UNDEFINED,
            BOOL_FALSE,
            BOOL_TRUE,
            INT32,
            INT64,
            UINT32,
            UINT64,
            FLOAT32,
            FLOAT64,
            STRING,
            BYTES,
            INT8,
            UINT8,
            INT16,
            UINT16,
            INT128,
            UINT128,
            DATE,
            TIMESTAMP,
            DECIMAL,
            TYPED_NULL,
            ARRAY,
            OBJECT,
            PASSTHROUGH,
            LOGICAL,
            LOGICAL_LONG,
            STORAGE_SOME,
            STORAGE_MAP,
        ];
        let mut seen = std::collections::HashSet::new();
        for tag in all {
            assert!(seen.insert(tag), "{tag:#04x} is taken twice");
        }
    }
}
