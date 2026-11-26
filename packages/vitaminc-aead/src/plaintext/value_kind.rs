//! A value's kind, named without a value, with its text name.
//!
//! [`Physical`] and [`Logical`] describe one value as it is sealed. A
//! schema needs the kind alone: "this column holds `int32`s". [`ValueKind`]
//! is that kind. It names every scalar a plan can declare, the two
//! container shapes and a JSON document, and it has the text name a schema
//! spells it with.

use core::fmt;
use core::str::FromStr;

use super::kinds::{FixedType, Float, Int, Logical, Physical, TimeUnit, Width};

/// What a value is, without the value: a boolean, an integer of one width
/// and sign, a float of one width, a decimal, a date, a timestamp, text,
/// bytes, an array, an object or a JSON document. What a schema declares a
/// column holds.
///
/// [`Kind`](super::Kind) is a different thing: the physical storage of one
/// scalar leaf (null, bool, int, float, text or bytes), with no width and
/// no logical type. An `int32`, a `uint8`, a date and a decimal are four
/// `ValueKind`s and one `Kind` ([`Kind::Int`](super::Kind::Int)), and an
/// array or an object has a `ValueKind` and no `Kind`.
///
/// [`of`](Self::of) gives the kind of a scalar, and
/// [`sealed_null`](Self::sealed_null) says how an absent value of the kind
/// is sealed.
///
/// A null, JavaScript's `undefined` and a passthrough have no kind. Each
/// null is a kind with one value, so declaring a column as one says
/// nothing, and a passthrough is a choice of how a value travels, not a
/// kind.
///
/// # Names are wire format
///
/// [`name`](Self::name), which is also the [`Display`](fmt::Display) and
/// [`FromStr`] form, is how a schema spells a kind in every language. The
/// names never change. Parsing matches them exactly and is case-sensitive.
///
/// The enum is exhaustive on purpose: a new kind is a new name every
/// language has to be taught, and a match that stops compiling is how a
/// binding's author learns of it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ValueKind {
    /// `"bool"`.
    Bool,
    /// `"int8"`.
    Int8,
    /// `"int16"`.
    Int16,
    /// `"int32"`.
    Int32,
    /// `"int64"`.
    Int64,
    /// `"int128"`.
    Int128,
    /// `"uint8"`.
    UInt8,
    /// `"uint16"`.
    UInt16,
    /// `"uint32"`.
    UInt32,
    /// `"uint64"`.
    UInt64,
    /// `"uint128"`.
    UInt128,
    /// `"float32"`.
    Float32,
    /// `"float64"`.
    Float64,
    /// `"decimal"`: [`Logical::Decimal`] of any scale.
    Decimal,
    /// `"date"`: [`Logical::Date`].
    Date,
    /// `"timestamp"`: [`Logical::Timestamp`] of any unit.
    Timestamp,
    /// `"string"`: UTF-8 text.
    String,
    /// `"bytes"`.
    Bytes,
    /// `"array"`. Says nothing about the elements' kinds.
    Array,
    /// `"object"`. Says nothing about the entries' kinds.
    Object,
    /// `"json"`: a JSON document, carried as UTF-8 JSON text in a text or
    /// bytes leaf. A column declares it; a scalar is never of this kind
    /// ([`of`](Self::of) says [`String`](Self::String) or
    /// [`Bytes`](Self::Bytes)), and [`holds`](Self::holds) takes either.
    /// The kind only names the document: the rules it is parsed by belong
    /// to whoever reads it. A document's `null` is the text `null`, not a
    /// null leaf.
    Json,
}

/// How an absent value of a [`ValueKind`] is sealed so that it is as long
/// as a present one. See [`ValueKind::sealed_null`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SealedNull {
    /// The plain null leaf, which is already as long as a value: a boolean's
    /// leaf is its tag alone, one byte, as the plain null's is.
    Plain,
    /// A typed null of this type
    /// ([`Sink::typed_null`](crate::plaintext::Sink::typed_null)), padded
    /// to the length of the type's leaf.
    Typed(FixedType),
}

impl ValueKind {
    /// Every kind, in declaration order.
    pub const ALL: [ValueKind; 21] = [
        ValueKind::Bool,
        ValueKind::Int8,
        ValueKind::Int16,
        ValueKind::Int32,
        ValueKind::Int64,
        ValueKind::Int128,
        ValueKind::UInt8,
        ValueKind::UInt16,
        ValueKind::UInt32,
        ValueKind::UInt64,
        ValueKind::UInt128,
        ValueKind::Float32,
        ValueKind::Float64,
        ValueKind::Decimal,
        ValueKind::Date,
        ValueKind::Timestamp,
        ValueKind::String,
        ValueKind::Bytes,
        ValueKind::Array,
        ValueKind::Object,
        ValueKind::Json,
    ];

    /// How a schema spells this kind: `"bool"`, `"int8"`, `"int16"`,
    /// `"int32"`, `"int64"`, `"int128"`, `"uint8"`, `"uint16"`, `"uint32"`,
    /// `"uint64"`, `"uint128"`, `"float32"`, `"float64"`, `"decimal"`,
    /// `"date"`, `"timestamp"`, `"string"`, `"bytes"`, `"array"`,
    /// `"object"` or `"json"`. These names never change.
    pub const fn name(self) -> &'static str {
        match self {
            ValueKind::Bool => "bool",
            ValueKind::Int8 => "int8",
            ValueKind::Int16 => "int16",
            ValueKind::Int32 => "int32",
            ValueKind::Int64 => "int64",
            ValueKind::Int128 => "int128",
            ValueKind::UInt8 => "uint8",
            ValueKind::UInt16 => "uint16",
            ValueKind::UInt32 => "uint32",
            ValueKind::UInt64 => "uint64",
            ValueKind::UInt128 => "uint128",
            ValueKind::Float32 => "float32",
            ValueKind::Float64 => "float64",
            ValueKind::Decimal => "decimal",
            ValueKind::Date => "date",
            ValueKind::Timestamp => "timestamp",
            ValueKind::String => "string",
            ValueKind::Bytes => "bytes",
            ValueKind::Array => "array",
            ValueKind::Object => "object",
            ValueKind::Json => "json",
        }
    }

    /// The kind of the scalar `value` under `ty`, or `None` for a scalar of
    /// no kind: a null (plain, or JavaScript's `undefined`), a value its
    /// logical type does not admit ([`Logical::admits`]), and a logical
    /// type no `ValueKind` names (a uuid, or one this build does not know).
    ///
    /// An integer's width and sign, and a float's width, are part of its
    /// kind. A decimal of any scale and a timestamp of any unit are one
    /// kind each.
    ///
    /// ```
    /// use vitaminc_aead::plaintext::{Int, Logical, Physical, ValueKind};
    ///
    /// assert_eq!(ValueKind::of(None, &Physical::Int(Int::U8(7))), Some(ValueKind::UInt8));
    /// assert_eq!(
    ///     ValueKind::of(Some(Logical::Date), &Physical::Int(Int::I32(19_782))),
    ///     Some(ValueKind::Date),
    /// );
    /// assert_eq!(ValueKind::of(None, &Physical::Null), None);
    /// ```
    pub fn of(ty: Option<Logical>, value: &Physical<'_>) -> Option<Self> {
        let Some(logical) = ty else {
            return Some(match *value {
                Physical::Null => return None,
                Physical::Bool(_) => ValueKind::Bool,
                Physical::Int(int) => match int {
                    Int::I8(_) => ValueKind::Int8,
                    Int::I16(_) => ValueKind::Int16,
                    Int::I32(_) => ValueKind::Int32,
                    Int::I64(_) => ValueKind::Int64,
                    Int::I128(_) => ValueKind::Int128,
                    Int::U8(_) => ValueKind::UInt8,
                    Int::U16(_) => ValueKind::UInt16,
                    Int::U32(_) => ValueKind::UInt32,
                    Int::U64(_) => ValueKind::UInt64,
                    Int::U128(_) => ValueKind::UInt128,
                },
                Physical::Float(Float::F32(_)) => ValueKind::Float32,
                Physical::Float(Float::F64(_)) => ValueKind::Float64,
                Physical::Text(_) => ValueKind::String,
                Physical::Bytes(_) => ValueKind::Bytes,
            });
        };
        if !logical.admits(value) {
            return None;
        }
        match logical {
            Logical::Date => Some(ValueKind::Date),
            Logical::Timestamp(_) => Some(ValueKind::Timestamp),
            Logical::Decimal { .. } => Some(ValueKind::Decimal),
            Logical::Undefined | Logical::Uuid | Logical::Unknown(_) => None,
        }
    }

    /// A scalar of this kind, with its logical type, or `None` for an
    /// array, an object or a JSON document. For asking a rule stated over values about the kind:
    /// every value of a kind is treated alike by a rule that looks only at
    /// its kind.
    ///
    /// The scalar is zero, `false`, empty text or empty bytes. An integer
    /// or float has the kind's width. A decimal is at scale 0 and a
    /// timestamp in nanoseconds, each as a 128-bit integer, and a date is a
    /// 32-bit day count: the forms they are sealed in.
    pub const fn zero(self) -> Option<(Option<Logical>, Physical<'static>)> {
        Some(match self {
            ValueKind::Bool => (None, Physical::Bool(false)),
            ValueKind::String => (None, Physical::Text("")),
            ValueKind::Bytes => (None, Physical::Bytes(&[])),
            // An array, an object and a document have no fixed type either.
            _ => match self.fixed_type() {
                Some(fixed) => (fixed.logical(), fixed.width().zero()),
                None => return None,
            },
        })
    }

    /// How an absent value of this kind is sealed so that it is as long as
    /// a present one, or `None` for a kind of no fixed length (text, bytes,
    /// an array, an object, a JSON document), whose absence no padding can hide.
    ///
    /// AES-GCM keeps the plaintext's length, so a null sealed as the plain
    /// null leaf (one byte) beside dates (five bytes) shows which rows have
    /// no date. A null of a type with a fixed length is sealed as a typed
    /// null of that length instead.
    ///
    /// Use the kind the column declares, not a type the null arrived with:
    /// a null whose own type disagreed with the column's would be padded to
    /// the wrong length, and show that it is a null.
    ///
    /// ```
    /// use vitaminc_aead::plaintext::{SealedNull, ValueKind};
    ///
    /// assert_eq!(ValueKind::Bool.sealed_null(), Some(SealedNull::Plain));
    /// assert!(matches!(ValueKind::Date.sealed_null(), Some(SealedNull::Typed(_))));
    /// assert_eq!(ValueKind::String.sealed_null(), None);
    /// ```
    pub const fn sealed_null(self) -> Option<SealedNull> {
        match self {
            ValueKind::Bool => Some(SealedNull::Plain),
            _ => match self.fixed_type() {
                Some(fixed) => Some(SealedNull::Typed(fixed)),
                None => None,
            },
        }
    }

    /// Whether a value of kind `found` is a value of this declared kind:
    /// the same kind, or for [`Json`](Self::Json), the text or bytes a
    /// document crosses as. `None`, a value with no kind (a null, an
    /// undefined, a passthrough), is a value of no kind.
    pub const fn holds(self, found: Option<ValueKind>) -> bool {
        match (self, found) {
            (ValueKind::Json, Some(ValueKind::String | ValueKind::Bytes)) => true,
            (declared, Some(found)) => declared as u8 == found as u8,
            (_, None) => false,
        }
    }

    /// The fixed-width type a value of this kind is sealed as, or `None`
    /// for a boolean (whose leaf has no payload) and a kind of no fixed
    /// length.
    const fn fixed_type(self) -> Option<FixedType> {
        let plain = FixedType::plain;
        match self {
            ValueKind::Int8 => plain(Width::I8),
            ValueKind::Int16 => plain(Width::I16),
            ValueKind::Int32 => plain(Width::I32),
            ValueKind::Int64 => plain(Width::I64),
            ValueKind::Int128 => plain(Width::I128),
            ValueKind::UInt8 => plain(Width::U8),
            ValueKind::UInt16 => plain(Width::U16),
            ValueKind::UInt32 => plain(Width::U32),
            ValueKind::UInt64 => plain(Width::U64),
            ValueKind::UInt128 => plain(Width::U128),
            ValueKind::Float32 => plain(Width::F32),
            ValueKind::Float64 => plain(Width::F64),
            ValueKind::Decimal => FixedType::new(Some(Logical::Decimal { scale: 0 }), Width::I128),
            ValueKind::Date => FixedType::new(Some(Logical::Date), Width::I32),
            ValueKind::Timestamp => {
                FixedType::new(Some(Logical::Timestamp(TimeUnit::Nanos)), Width::I128)
            }
            ValueKind::Bool
            | ValueKind::String
            | ValueKind::Bytes
            | ValueKind::Array
            | ValueKind::Object
            | ValueKind::Json => None,
        }
    }
}

impl fmt::Display for ValueKind {
    /// Writes [`name`](Self::name).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for ValueKind {
    type Err = ParseValueKindError;

    /// Parses a [`name`](Self::name), exactly: `"uint64"`, not `"UInt64"`,
    /// `"u64"` or `" uint64"`. `"null"` and `"undefined"` are not kinds.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        ValueKind::ALL
            .into_iter()
            .find(|ty| ty.name() == name)
            .ok_or(ParseValueKindError)
    }
}

/// The error from parsing a string that is not a [`ValueKind::name`].
/// Carries no detail: the caller holds the string it tried to parse.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("not a value kind")]
pub struct ParseValueKindError;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::leaf::{max_len, sealed_null_type, typed_null_len, write_leaf};
    use crate::plaintext::UnknownLogical;

    #[test]
    fn names_parse_back_exactly() {
        let names: Vec<&str> = ValueKind::ALL.iter().map(|ty| ty.name()).collect();
        assert_eq!(
            names,
            [
                "bool",
                "int8",
                "int16",
                "int32",
                "int64",
                "int128",
                "uint8",
                "uint16",
                "uint32",
                "uint64",
                "uint128",
                "float32",
                "float64",
                "decimal",
                "date",
                "timestamp",
                "string",
                "bytes",
                "array",
                "object",
                "json",
            ],
            "the names never change"
        );
        for ty in ValueKind::ALL {
            assert_eq!(ty.name().parse::<ValueKind>(), Ok(ty));
            assert_eq!(ty.to_string(), ty.name());
        }
        for refused in ["UInt64", "u64", " uint64", "null", "undefined", "Json", ""] {
            assert_eq!(
                refused.parse::<ValueKind>(),
                Err(ParseValueKindError),
                "{refused:?}"
            );
        }
        assert_eq!(ParseValueKindError.to_string(), "not a value kind");
    }

    /// Every scalar type is the type of its own zero, and a container has
    /// none.
    #[test]
    fn every_scalar_type_is_the_type_of_its_zero() {
        for ty in ValueKind::ALL {
            match ty.zero() {
                Some((logical, value)) => assert_eq!(ValueKind::of(logical, &value), Some(ty)),
                None => assert!(
                    matches!(ty, ValueKind::Array | ValueKind::Object | ValueKind::Json),
                    "{ty}"
                ),
            }
        }
    }

    #[test]
    fn of_names_each_physical_width() {
        let cases = [
            (Physical::Bool(true), ValueKind::Bool),
            (Physical::Int(Int::I8(1)), ValueKind::Int8),
            (Physical::Int(Int::I16(1)), ValueKind::Int16),
            (Physical::Int(Int::I32(1)), ValueKind::Int32),
            (Physical::Int(Int::I64(1)), ValueKind::Int64),
            (Physical::Int(Int::I128(1)), ValueKind::Int128),
            (Physical::Int(Int::U8(1)), ValueKind::UInt8),
            (Physical::Int(Int::U16(1)), ValueKind::UInt16),
            (Physical::Int(Int::U32(1)), ValueKind::UInt32),
            (Physical::Int(Int::U64(1)), ValueKind::UInt64),
            (Physical::Int(Int::U128(1)), ValueKind::UInt128),
            (Physical::Float(Float::F32(1.0)), ValueKind::Float32),
            (Physical::Float(Float::F64(1.0)), ValueKind::Float64),
            (Physical::Text("a"), ValueKind::String),
            (Physical::Bytes(b"a"), ValueKind::Bytes),
        ];
        for (value, ty) in cases {
            assert_eq!(ValueKind::of(None, &value), Some(ty), "{ty}");
        }
        assert_eq!(ValueKind::of(None, &Physical::Null), None);
    }

    /// A logical type gives its own type at any parameter, and only for a
    /// value it admits. One no `ValueKind` names gives none.
    #[test]
    fn of_reads_a_logical_type_only_over_a_value_it_admits() {
        let int = |v| Physical::Int(Int::I64(v));
        assert_eq!(
            ValueKind::of(Some(Logical::Date), &int(1)),
            Some(ValueKind::Date)
        );
        for unit in [
            TimeUnit::Seconds,
            TimeUnit::Millis,
            TimeUnit::Micros,
            TimeUnit::Nanos,
        ] {
            assert_eq!(
                ValueKind::of(Some(Logical::Timestamp(unit)), &int(1)),
                Some(ValueKind::Timestamp),
                "{unit:?}"
            );
        }
        for scale in [0, 2, 28] {
            assert_eq!(
                ValueKind::of(Some(Logical::Decimal { scale }), &int(150)),
                Some(ValueKind::Decimal),
                "{scale}"
            );
        }
        // Not admitted: a date over text, a date out of range, a scale
        // above 28.
        assert_eq!(
            ValueKind::of(Some(Logical::Date), &Physical::Text("1")),
            None
        );
        assert_eq!(ValueKind::of(Some(Logical::Date), &int(i64::MAX)), None);
        assert_eq!(
            ValueKind::of(Some(Logical::Decimal { scale: 29 }), &int(1)),
            None
        );
        // Named by no `ValueKind`.
        assert_eq!(
            ValueKind::of(Some(Logical::Undefined), &Physical::Null),
            None
        );
        assert_eq!(
            ValueKind::of(Some(Logical::Uuid), &Physical::Bytes(&[0; 16])),
            None
        );
        let unknown = Logical::from_wire(200, 0).expect("an unknown id");
        assert!(matches!(unknown, Logical::Unknown(UnknownLogical { .. })));
        assert_eq!(ValueKind::of(Some(unknown), &int(1)), None);
    }

    /// `json` holds text and bytes besides itself, and has no zero and no
    /// sealed null: a document has no fixed length. Every other kind holds
    /// itself alone, and no kind holds a value with none. (No value is of
    /// kind `json`, since `of` never gives it, so `json` holding itself
    /// is never reached by a value.)
    #[test]
    fn json_holds_text_and_bytes_and_has_no_fixed_length() {
        assert_eq!(ValueKind::Json.name(), "json");
        assert_eq!(ValueKind::Json.zero(), None);
        assert_eq!(ValueKind::Json.sealed_null(), None);
        assert!(ValueKind::Json.holds(Some(ValueKind::String)));
        assert!(ValueKind::Json.holds(Some(ValueKind::Bytes)));
        assert!(!ValueKind::Json.holds(Some(ValueKind::Object)));
        assert!(!ValueKind::String.holds(Some(ValueKind::Bytes)));
        for declared in ValueKind::ALL {
            assert!(!declared.holds(None), "{declared}");
            for found in ValueKind::ALL {
                let text = matches!(found, ValueKind::String | ValueKind::Bytes);
                let held = declared == found || (declared == ValueKind::Json && text);
                assert_eq!(
                    declared.holds(Some(found)),
                    held,
                    "{declared} holds {found}"
                );
            }
        }
    }

    /// The widths, spelled out: these are the lengths stored nulls already
    /// have, so a change here changes stored bytes.
    #[test]
    fn sealed_null_widths() {
        let plain = |width| Some(SealedNull::Typed(FixedType::plain(width).expect("fixed")));
        let cases = [
            (ValueKind::Bool, Some(SealedNull::Plain)),
            (ValueKind::Int8, plain(Width::I8)),
            (ValueKind::Int16, plain(Width::I16)),
            (ValueKind::Int32, plain(Width::I32)),
            (ValueKind::Int64, plain(Width::I64)),
            (ValueKind::Int128, plain(Width::I128)),
            (ValueKind::UInt8, plain(Width::U8)),
            (ValueKind::UInt16, plain(Width::U16)),
            (ValueKind::UInt32, plain(Width::U32)),
            (ValueKind::UInt64, plain(Width::U64)),
            (ValueKind::UInt128, plain(Width::U128)),
            (ValueKind::Float32, plain(Width::F32)),
            (ValueKind::Float64, plain(Width::F64)),
            (
                ValueKind::Decimal,
                FixedType::new(Some(Logical::Decimal { scale: 0 }), Width::I128)
                    .map(SealedNull::Typed),
            ),
            (
                ValueKind::Date,
                FixedType::new(Some(Logical::Date), Width::I32).map(SealedNull::Typed),
            ),
            (
                ValueKind::Timestamp,
                FixedType::new(Some(Logical::Timestamp(TimeUnit::Nanos)), Width::I128)
                    .map(SealedNull::Typed),
            ),
            (ValueKind::String, None),
            (ValueKind::Bytes, None),
            (ValueKind::Array, None),
            (ValueKind::Object, None),
            (ValueKind::Json, None),
        ];
        for (ty, want) in cases {
            assert_eq!(ty.sealed_null(), want, "{ty}");
        }
    }

    /// A typed null is the length of the leaf of a value of its type, so a
    /// sealed null and a sealed value cannot be told apart by length.
    #[test]
    fn a_typed_null_is_as_long_as_its_zero() {
        for ty in ValueKind::ALL {
            let Some(SealedNull::Typed(fixed)) = ty.sealed_null() else {
                continue;
            };
            let (logical, value) = ty.zero().expect("a fixed type has a zero");
            let mut leaf = Vec::with_capacity(max_len(&value));
            write_leaf(logical, value, &mut leaf).expect("a zero writes");
            assert_eq!(typed_null_len(sealed_null_type(fixed)), leaf.len(), "{ty}");
        }
    }
}
