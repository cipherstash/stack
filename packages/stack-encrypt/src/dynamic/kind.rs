//! What a plan's declared field type means to the engine.
//!
//! A typed host knows what `34` is: a Rust `u32`, a Go `int64`. A dynamically
//! typed host (JavaScript, PHP, Ruby) does not, and index semantics depend on
//! it: an ORE term of the integer `34` and of the float `34.0` differ, a
//! JavaScript number is a float, and match is defined over text alone. So a
//! plan field may say what its values are, in its `"type"` key.
//!
//! The vocabulary is [`ValueKind`], whose
//! [`name`](ValueKind::name)s (`"uint64"`, `"string"`, …, `"array"`,
//! `"object"`) are frozen wire format; [`ValueFrame::kind`] says which kind
//! a value is. Beside it, this module adds two rules:
//!
//! - [`admits`]: which indexes a kind is defined for, so a plan asking for
//!   match on an integer or equality on a boolean is refused when it is
//!   built;
//! - [`read`]: how a query value is read as a field's kind, converting a
//!   number only when the conversion is exact.
//!
//! The engine then uses a declared kind three times:
//!
//! - **encrypt** admits only the indexes the kind is defined for (when the
//!   plan is built), and refuses a value of any other kind (when it runs),
//!   so the term bytes are the declared kind's and no binding is trusted to
//!   have tagged the value right;
//! - **query** is meant to read the query value *as* the field's kind
//!   ([`read`]): `34` against a `uint64` field is the `u64` term, whatever
//!   number type the host handed over. The engine does not do this for the
//!   caller yet; see [`read`];
//! - **decrypt** refuses an opened value of any other kind, so a host with no
//!   types of its own can rely on the declaration for what it gets back (an
//!   integer, not a float; bytes, not a string).
//!
//! Every field with a term output declares its kind; a plan whose indexed
//! field has none is refused when it is built
//! ([`Error::UntypedIndex`], naming the field). A field that only seals, or
//! only carries its value through, may leave it out: no term derives from it.
use std::fmt;
use std::str::FromStr;

use vitaminc_aead::plaintext::{FixedType, Float, Int, Logical, Physical, Raw, TimeUnit, Width};
use vitaminc_aead::Encrypt;

use super::term::OneScalar;
use super::ValueFrame;

use super::{Error, Reason};
use crate::target::IndexSpec;

/// Whether the scheme defines an `index` term for values of `kind`.
///
/// The table [`IndexSpec::defines`] reads for a value, stated over kinds
/// instead, so a plan can be refused when it is built rather than when its
/// first value arrives. Equality is vitaminc's: every kind
/// `vitaminc-normalize` gives an equality domain, which is every integer
/// of every width, both floats, a decimal, a date, a timestamp, text and
/// bytes, and not a boolean. The rest are this crate's: match over text
/// alone, and ORE, OPE and block ORE over the integers of 16 bits and
/// wider, both floats, text, bytes, a decimal, a date and a timestamp. A
/// boolean and an 8-bit integer have no order term: over so small a domain
/// it would reveal which rows are `true`, or each row's rank among 256
/// values. A composite (`array`, `object`) has no term. Only the index's
/// kind matters: a match index's options do not change what it applies to.
///
/// ```
/// use stack_encrypt::dynamic::{admits, ValueKind};
/// use stack_encrypt::target::IndexSpec;
///
/// assert!(admits(ValueKind::UInt64, &IndexSpec::Equality));
/// assert!(admits(ValueKind::Int16, &IndexSpec::Ore));
/// assert!(admits(ValueKind::Int8, &IndexSpec::Equality));
/// assert!(!admits(ValueKind::Int8, &IndexSpec::Ore));
/// assert!(admits(ValueKind::Date, &IndexSpec::Equality));
/// assert!(admits(ValueKind::Date, &IndexSpec::Ore));
/// assert!(!admits(ValueKind::Bool, &IndexSpec::Equality));
/// assert!(!admits(ValueKind::Bool, &IndexSpec::Ore));
/// assert!(!admits(ValueKind::Object, &IndexSpec::Ore));
/// ```
pub fn admits(kind: ValueKind, index: &IndexSpec) -> bool {
    scalar_of(kind).is_some_and(|(ty, scalar)| index.takes(ty, &scalar))
}

/// Why `kind` does not admit `index`, or `None` when it does: the reason a
/// plan that declares the pair is refused with,
/// [`Reason::IndexNotAdmitted`] for every pair [`admits`] refuses.
///
/// ```
/// use stack_encrypt::dynamic::{not_admitted, Reason, ValueKind};
/// use stack_encrypt::target::IndexSpec;
///
/// assert_eq!(not_admitted(ValueKind::Bool, &IndexSpec::Ore), Some(Reason::IndexNotAdmitted));
/// assert_eq!(not_admitted(ValueKind::Timestamp, &IndexSpec::Ope), None);
/// ```
pub fn not_admitted(kind: ValueKind, index: &IndexSpec) -> Option<Reason> {
    if admits(kind, index) {
        return None;
    }
    Some(if matches!(index, IndexSpec::Json(_)) {
        Reason::JsonIndexPending
    } else {
        Reason::IndexNotAdmitted
    })
}

/// A scalar of `kind`, with its logical type, for asking the table about
/// the kind: any value of a kind is taken by an index exactly when every
/// other is. `None` for a composite, which is no scalar.
fn scalar_of(kind: ValueKind) -> Option<(Option<Logical>, Physical<'static>)> {
    let int = |int| (None, Physical::Int(int));
    Some(match kind {
        ValueKind::Bool => (None, Physical::Bool(false)),
        ValueKind::Int8 => int(Int::I8(0)),
        ValueKind::Int16 => int(Int::I16(0)),
        ValueKind::Int32 => int(Int::I32(0)),
        ValueKind::Int64 => int(Int::I64(0)),
        ValueKind::Int128 => int(Int::I128(0)),
        ValueKind::UInt8 => int(Int::U8(0)),
        ValueKind::UInt16 => int(Int::U16(0)),
        ValueKind::UInt32 => int(Int::U32(0)),
        ValueKind::UInt64 => int(Int::U64(0)),
        ValueKind::UInt128 => int(Int::U128(0)),
        ValueKind::Float32 => (None, Physical::Float(Float::F32(0.0))),
        ValueKind::Float64 => (None, Physical::Float(Float::F64(0.0))),
        ValueKind::Decimal => (
            Some(Logical::Decimal { scale: 0 }),
            Physical::Int(Int::I128(0)),
        ),
        ValueKind::Date => (Some(Logical::Date), Physical::Int(Int::I32(0))),
        ValueKind::Timestamp => (
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I128(0)),
        ),
        ValueKind::String => (None, Physical::Text("")),
        ValueKind::Bytes => (None, Physical::Bytes(&[])),
        ValueKind::Array | ValueKind::Object | ValueKind::Json => return None,
    })
}

/// Read a query value as `kind`.
///
/// A value already of this kind is returned as it is. A number of another
/// width or kind is converted when the conversion is exact: an integer in
/// range, or a float with no fractional part in range, for an integer kind
/// of any width (a JavaScript `34` arrives as a float); an integer or float
/// the target float kind represents exactly, for a float kind; an integer
/// whose magnitude fits 96 bits, for a decimal (at scale 0, so `34` reads as
/// the decimal `34`, which equals `34.00`). A NaN is never converted, in
/// either float direction: it equals nothing, so no conversion of it is
/// exact. A float is never read as a decimal, since most floats have no
/// short decimal form, and nothing converts to or from a date or a
/// timestamp. Nothing else converts: a string is never parsed as a number,
/// and a number never becomes a string.
///
/// The value is any source ([`Encrypt`]): a transport frame a binding was
/// handed, walked in place. What comes back is the value as the field's kind,
/// written into a [`ValueFrame`] in the engine's value model.
///
/// This is for a query: what a host hands over to search with. A value
/// being sealed is not converted; it must already be of the field's kind,
/// and is refused otherwise.
///
/// **The engine does not call this.** [`term`](super::term()) takes a
/// value and an [`IndexSpec`] and never sees the field's declared kind, so a binding deriving a query term for a typed field must
/// call `read` first, with [`FieldPlan::field_type`](super::FieldPlan::field_type).
/// One that skips it hands `Float64(34.0)` to a `uint64` field, derives a
/// float term where the stored one is the `u64` term, and matches nothing,
/// with no error. Wiring this into the plan's query path
/// (`query(v).using(&plan)`) is tracked in #1057.
///
/// ```
/// use stack_encrypt::dynamic::{read, ValueFrame, ValueKind};
///
/// // A JavaScript number is a float; against a `uint64` field it is 34.
/// let value = read(ValueKind::UInt64, 34.0f64)?;
/// assert_eq!(value.kind(), Some(ValueKind::UInt64));
/// assert_eq!(value.risky_ref(), ValueFrame::of(34u64)?.risky_ref());
/// assert!(read(ValueKind::UInt64, 34.5f64).is_err());
/// // Against an `int8` field, 34 is the 8-bit integer; 300 does not fit.
/// assert_eq!(read(ValueKind::Int8, 34i64)?.kind(), Some(ValueKind::Int8));
/// assert!(read(ValueKind::Int8, 300i64).is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// [`Error::Source`] ([`Reason::FieldType`]) if the value cannot be read as
/// `kind` exactly, or is not in the engine's value model. It names no
/// field: the caller that knows the field names it ([`Error::in_field`]).
pub fn read(kind: ValueKind, value: impl Encrypt) -> Result<ValueFrame, Error> {
    let refused = || Error::bad_source(Reason::FieldType);
    let value = ValueFrame::of(value).map_err(|_| refused())?;
    if kind.holds(value.kind()) {
        return Ok(value);
    }
    let number = (&value)
        .visit(OneScalar::new(
            |ty: Option<Logical>, value: Physical<'_>| Number::of(ty, value).ok_or(None),
        ))
        .map_err(|_| refused())?;
    let int = |int: Int| Raw(None, Physical::Int(int));
    let signed = || number.integer();
    let read = match kind {
        ValueKind::Int8 => signed()
            .and_then(|i| i8::try_from(i).ok())
            .map(|v| int(Int::I8(v))),
        ValueKind::Int16 => signed()
            .and_then(|i| i16::try_from(i).ok())
            .map(|v| int(Int::I16(v))),
        ValueKind::Int32 => signed()
            .and_then(|i| i32::try_from(i).ok())
            .map(|v| int(Int::I32(v))),
        ValueKind::Int64 => signed()
            .and_then(|i| i64::try_from(i).ok())
            .map(|v| int(Int::I64(v))),
        ValueKind::Int128 => signed().map(|v| int(Int::I128(v))),
        ValueKind::UInt8 => signed()
            .and_then(|i| u8::try_from(i).ok())
            .map(|v| int(Int::U8(v))),
        ValueKind::UInt16 => signed()
            .and_then(|i| u16::try_from(i).ok())
            .map(|v| int(Int::U16(v))),
        ValueKind::UInt32 => signed()
            .and_then(|i| u32::try_from(i).ok())
            .map(|v| int(Int::U32(v))),
        ValueKind::UInt64 => signed()
            .and_then(|i| u64::try_from(i).ok())
            .map(|v| int(Int::U64(v))),
        ValueKind::UInt128 => number.unsigned().map(|v| int(Int::U128(v))),
        ValueKind::Float64 => number
            .exact_f64()
            .map(|f| Raw(None, Physical::Float(Float::F64(f)))),
        ValueKind::Float32 => number
            .exact_f32()
            .map(|f| Raw(None, Physical::Float(Float::F32(f)))),
        ValueKind::Decimal => number.whole().map(|i| {
            Raw(
                Some(Logical::Decimal { scale: 0 }),
                Physical::Int(Int::I128(i)),
            )
        }),
        _ => None,
    };
    ValueFrame::of(read.ok_or_else(refused)?).map_err(|_| refused())
}

/// 2^127 as an `f64`, exactly: the first float past `i128::MAX`.
const TWO_127: f64 = 170_141_183_460_469_231_731_687_303_715_884_105_728.0;
/// 2^128 as an `f64`, exactly: the first float past `u128::MAX`.
const TWO_128: f64 = 340_282_366_920_938_463_463_374_607_431_768_211_456.0;

/// A numeric leaf, widened without loss: every integer but a `u128` above
/// `i128::MAX` fits an `i128`, which is `Unsigned`; an `f32` widens to an
/// `f64` exactly.
#[derive(Clone, Copy)]
enum Number {
    Integer(i128),
    Unsigned(u128),
    Float(f64),
}

impl Number {
    /// The number a scalar of the value model is, or `None` for anything
    /// that is not a number. A decimal, date or timestamp is not one.
    fn of(ty: Option<Logical>, value: Physical<'_>) -> Option<Self> {
        Some(match (ty, value) {
            (None, Physical::Int(int)) => match int.to_i128() {
                Some(v) => Number::Integer(v),
                None => Number::Unsigned(int.to_u128()?),
            },
            (None, Physical::Float(Float::F32(v))) => Number::Float(v.into()),
            (None, Physical::Float(Float::F64(v))) => Number::Float(v),
            _ => return None,
        })
    }

    /// The integer this number is exactly, if it is one that fits an
    /// `i128`. A float outside `i128` is not one: casting it would
    /// saturate to a different number.
    fn integer(self) -> Option<i128> {
        match self {
            Number::Integer(i) => Some(i),
            Number::Unsigned(_) => None,
            Number::Float(f) => {
                (f.fract() == 0.0 && (-TWO_127..TWO_127).contains(&f)).then_some(f as i128)
            }
        }
    }

    /// The integer this number is exactly, if it is a non-negative one
    /// that fits a `u128`.
    fn unsigned(self) -> Option<u128> {
        match self {
            Number::Integer(i) => u128::try_from(i).ok(),
            Number::Unsigned(u) => Some(u),
            Number::Float(f) => {
                (f.fract() == 0.0 && (0.0..TWO_128).contains(&f)).then_some(f as u128)
            }
        }
    }

    /// The integer this number is, if it is an integer and not a float: a
    /// decimal is read from an integer alone.
    fn whole(self) -> Option<i128> {
        match self {
            Number::Integer(i) => Some(i),
            Number::Unsigned(_) | Number::Float(_) => None,
        }
    }

    /// The `f64` this number is exactly, if it is one: an integer whose
    /// conversion does not round, or a float that is not a NaN. A NaN is
    /// never exact, because it does not equal itself.
    fn exact_f64(self) -> Option<f64> {
        match self {
            Number::Float(f) => (!f.is_nan()).then_some(f),
            Number::Integer(i) => {
                let f = i as f64;
                // `i128::MAX` rounds up to 2^127, which casts back to
                // `i128::MAX` by saturation: the range check refuses it.
                (f < TWO_127 && f as i128 == i).then_some(f)
            }
            Number::Unsigned(u) => {
                let f = u as f64;
                (f < TWO_128 && f as u128 == u).then_some(f)
            }
        }
    }

    /// The `f32` this number is exactly, if it is one. A NaN is refused by
    /// `exact_f64` before it gets here.
    fn exact_f32(self) -> Option<f32> {
        let f = self.exact_f64()?;
        let narrowed = f as f32;
        (f64::from(narrowed) == f).then_some(narrowed)
    }
}

/// The kind of a value: the type vocabulary a plan field declares in its
/// `"type"` key, and what [`ValueFrame::kind`] reports.
///
/// `Null`, `Undefined` and `Passthrough` have no kind: each null is a type
/// with one value, so declaring a field as one says nothing, and a
/// passthrough is a transport choice, not a type.
///
/// # Names are wire format
///
/// [`name`](Self::name) (also its [`Display`](fmt::Display) and [`FromStr`]
/// form) is how a binding spells a kind. The names are frozen: matched
/// exactly, case-sensitively, and never renamed.
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
    /// `"decimal"`: vitaminc's `Decimal` logical type, a mantissa and a
    /// scale.
    Decimal,
    /// `"date"`: vitaminc's `Date` logical type, a calendar date with no
    /// time or zone.
    Date,
    /// `"timestamp"`: vitaminc's `Timestamp` logical type, an instant in
    /// UTC, to the nanosecond.
    Timestamp,
    /// `"string"`.
    String,
    /// `"bytes"`.
    Bytes,
    /// `"array"`. Says nothing about the elements' kinds.
    Array,
    /// `"object"`. Says nothing about the entries' kinds.
    Object,
    /// `"json"`: a JSON document, carried as UTF-8 JSON text in a text or
    /// bytes leaf, which the engine parses by one set of rules
    /// ([`crate::json::parse_text`]) and opens back to as bytes. A value
    /// is never of this kind ([`ValueFrame::kind`] says `string` or
    /// `bytes`); a field declares it, and takes a target that stores a
    /// document (`JsonSearch`). A JSON document's `null` is the text
    /// `null`, not the frame's null.
    Json,
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

    /// How a declaration spells this kind: `"bool"`, `"int8"`, `"int16"`,
    /// `"int32"`, `"int64"`, `"int128"`, `"uint8"`, `"uint16"`, `"uint32"`,
    /// `"uint64"`, `"uint128"`, `"float32"`, `"float64"`, `"decimal"`,
    /// `"date"`, `"timestamp"`, `"string"`, `"bytes"`, `"array"`,
    /// `"object"` or `"json"`. Frozen wire format.
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

    /// How an absent value of this kind is sealed so that it is as long as
    /// a present one (a plan's `"null": "sealed"`, #1298): `Some(Some(ty))`
    /// for a kind of fixed width, sealed as a typed null of `ty` (vitaminc
    /// 0.8); `Some(None)` for a boolean, whose leaf is one byte, as the
    /// plain null is; `None` for a kind of no fixed width (text, bytes, a
    /// container), whose absence no padding can hide.
    pub(crate) const fn sealed_null(self) -> Option<Option<FixedType>> {
        let plain = FixedType::plain;
        Some(match self {
            ValueKind::Bool => None,
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
            // The widths the value model holds each logical type at.
            ValueKind::Decimal => FixedType::new(Some(Logical::Decimal { scale: 0 }), Width::I128),
            ValueKind::Date => FixedType::new(Some(Logical::Date), Width::I32),
            ValueKind::Timestamp => {
                FixedType::new(Some(Logical::Timestamp(TimeUnit::Nanos)), Width::I128)
            }
            ValueKind::String
            | ValueKind::Bytes
            | ValueKind::Array
            | ValueKind::Object
            | ValueKind::Json => return None,
        })
    }
}

impl ValueKind {
    /// Whether a value of kind `found` is a value of this declared kind:
    /// the same kind, or for [`Json`](Self::Json), the text or bytes the
    /// document crosses as. `None`, a value with no kind (a null, an
    /// undefined, a passthrough), is a value of no kind.
    pub const fn holds(self, found: Option<ValueKind>) -> bool {
        match (self, found) {
            (ValueKind::Json, Some(ValueKind::String | ValueKind::Bytes)) => true,
            (declared, Some(found)) => declared as u8 == found as u8,
            (_, None) => false,
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
            .find(|kind| kind.name() == name)
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
    use crate::dynamic::test_frame::Tree;
    use crate::sem::{MatchOptions, Tokenizer};
    use vitaminc_aead::plaintext::Raw;

    #[test]
    fn kind_names_parse_back_exactly() {
        let names: Vec<&str> = ValueKind::ALL.iter().map(|kind| kind.name()).collect();
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
                "json"
            ],
            "the frozen names"
        );
        for kind in ValueKind::ALL {
            assert_eq!(kind.name().parse::<ValueKind>(), Ok(kind));
            assert_eq!(kind.to_string(), kind.name());
        }
        assert_eq!("UInt64".parse::<ValueKind>(), Err(ParseValueKindError));
        assert_eq!("null".parse::<ValueKind>(), Err(ParseValueKindError));
    }

    // Beside the frozen names (above), these test the two rules this crate
    // adds over the vocabulary.

    /// A scalar as the engine holds it: its frame.
    fn scalar(ty: Option<Logical>, value: Physical<'_>) -> ValueFrame {
        ValueFrame::of(Raw(ty, value)).expect("in the value model")
    }

    fn int(int: Int) -> ValueFrame {
        scalar(None, Physical::Int(int))
    }

    fn tree(value: Tree) -> ValueFrame {
        ValueFrame::of(&value).expect("in the value model")
    }

    /// One value of every kind.
    fn sample(kind: ValueKind) -> ValueFrame {
        match kind {
            ValueKind::Bool => tree(Tree::Bool(true)),
            ValueKind::Int8 => int(Int::I8(-1)),
            ValueKind::Int16 => int(Int::I16(-2)),
            ValueKind::Int32 => tree(Tree::Int32(-3)),
            ValueKind::Int64 => tree(Tree::Int64(-4)),
            ValueKind::Int128 => int(Int::I128(i128::MIN)),
            ValueKind::UInt8 => int(Int::U8(32)),
            ValueKind::UInt16 => int(Int::U16(33)),
            ValueKind::UInt32 => tree(Tree::UInt32(34)),
            ValueKind::UInt64 => tree(Tree::UInt64(35)),
            ValueKind::UInt128 => int(Int::U128(u128::MAX)),
            ValueKind::Float32 => tree(Tree::Float32(1.5)),
            ValueKind::Float64 => tree(Tree::Float64(2.5)),
            ValueKind::Decimal => scalar(
                Some(Logical::Decimal { scale: 2 }),
                Physical::Int(Int::I64(150)),
            ),
            ValueKind::Date => scalar(Some(Logical::Date), Physical::Int(Int::I32(19_782))),
            ValueKind::Timestamp => scalar(
                Some(Logical::Timestamp(TimeUnit::Nanos)),
                Physical::Int(Int::I128(1_760_662_923_123_456_789)),
            ),
            ValueKind::String => tree(Tree::String("alice".into())),
            ValueKind::Bytes => tree(Tree::Bytes(b"ab".to_vec())),
            ValueKind::Array => tree(Tree::Array(vec![Tree::UInt32(1)])),
            ValueKind::Object => tree(Tree::Object(vec![("k".to_string(), Tree::UInt32(1))])),
            // A document crosses as its text: a value of kind string.
            ValueKind::Json => tree(Tree::String(r#"{"k": 1}"#.into())),
        }
    }

    /// Every kind whose values are of that kind: all but `json`, which a
    /// field declares and a value never is (it crosses as text or bytes).
    fn value_kinds() -> impl Iterator<Item = ValueKind> {
        ValueKind::ALL
            .into_iter()
            .filter(|kind| *kind != ValueKind::Json)
    }

    /// `json` admits no index (a document is indexed by the target that
    /// stores it), holds text and bytes and nothing else, and reads either
    /// as it is: the text is parsed where the document is sealed.
    #[test]
    fn json_holds_its_text_and_admits_no_index() {
        for index in indexes() {
            assert!(!admits(ValueKind::Json, &index), "{index}");
        }
        assert!(ValueKind::Json.holds(Some(ValueKind::String)));
        assert!(ValueKind::Json.holds(Some(ValueKind::Bytes)));
        for kind in value_kinds().filter(|k| !matches!(k, ValueKind::String | ValueKind::Bytes)) {
            assert!(!ValueKind::Json.holds(Some(kind)), "{kind}");
        }
        assert!(
            !ValueKind::Json.holds(None),
            "a frame null is not a document"
        );
        assert!(!ValueKind::String.holds(Some(ValueKind::Bytes)));
        for kind in value_kinds() {
            assert!(kind.holds(Some(kind)), "{kind}");
            assert!(!kind.holds(None), "{kind}");
        }
        let text = read_frame(ValueKind::Json, sample(ValueKind::Json)).expect("text");
        assert_eq!(text.kind(), Some(ValueKind::String));
        let bytes = read_frame(ValueKind::Json, Tree::Bytes(b"[1]".to_vec())).expect("bytes");
        assert_eq!(bytes.kind(), Some(ValueKind::Bytes));
        assert!(read_frame(ValueKind::Json, Tree::UInt32(1)).is_none());
        assert_eq!(
            ValueKind::Json.sealed_null(),
            None,
            "a document has no fixed width"
        );
    }

    fn indexes() -> [IndexSpec; 5] {
        [
            IndexSpec::Equality,
            IndexSpec::Match(MatchOptions::default()),
            IndexSpec::Ore,
            IndexSpec::Ope,
            IndexSpec::OreBlock,
        ]
    }

    /// `admits` is `IndexSpec::defines` stated over kinds: the two cannot
    /// disagree about a value of any kind, and a composite admits nothing.
    #[test]
    fn admits_agrees_with_defines_for_every_kind() {
        for kind in value_kinds() {
            for index in indexes() {
                assert_eq!(
                    admits(kind, &index),
                    index.defines(sample(kind)),
                    "{kind} and {index}"
                );
            }
        }
        // Spelled out, so the table reads without the cross-check.
        assert!(admits(ValueKind::UInt64, &IndexSpec::Equality));
        assert!(admits(ValueKind::Float64, &IndexSpec::Equality));
        assert!(admits(ValueKind::Bytes, &IndexSpec::Equality));
        assert!(!admits(ValueKind::Bool, &IndexSpec::Equality));
        assert!(admits(
            ValueKind::String,
            &IndexSpec::Match(MatchOptions::default())
        ));
        assert!(!admits(
            ValueKind::Bytes,
            &IndexSpec::Match(MatchOptions::default())
        ));
        assert!(admits(ValueKind::Float64, &IndexSpec::Ore));
        assert!(admits(ValueKind::String, &IndexSpec::Ope));
        assert!(!admits(ValueKind::Bool, &IndexSpec::Ore));
        assert!(!admits(ValueKind::Bool, &IndexSpec::Ope));
        assert!(!admits(ValueKind::Object, &IndexSpec::Ope));
        assert!(!admits(ValueKind::Array, &IndexSpec::Ore));
        assert!(admits(ValueKind::Int32, &IndexSpec::OreBlock));
        assert!(admits(ValueKind::String, &IndexSpec::OreBlock));
        assert!(!admits(ValueKind::Bool, &IndexSpec::OreBlock));
    }

    /// Equality is vitaminc's table: a kind admits it exactly when
    /// `vitaminc-normalize` gives the kind's values an equality domain.
    #[test]
    fn admits_equality_exactly_where_vitaminc_gives_a_domain() {
        for kind in value_kinds() {
            let has_domain = matches!(
                vitaminc_normalize::terms(sample(kind)).as_deref(),
                Ok([term]) if term.path.steps().is_empty()
            );
            assert_eq!(
                admits(kind, &IndexSpec::Equality),
                has_domain,
                "{kind} admits equality exactly when it has a domain"
            );
        }
    }

    /// A match index's options are not part of what it applies to: text
    /// admits it under any options, and nothing else does.
    #[test]
    fn admits_ignores_match_options() {
        let wide = IndexSpec::Match(MatchOptions {
            tokenizer: Tokenizer::Standard,
            downcase: false,
            short_words: false,
            k: 6,
            m: 1024,
        });
        for kind in ValueKind::ALL {
            assert_eq!(
                admits(kind, &wide),
                kind == ValueKind::String,
                "{kind} admits a non-default match exactly when it is text"
            );
        }
    }

    /// The new kinds' rows, spelled out: equality on every one, order on
    /// every integer width but 8 bits and on the decimal, date and
    /// timestamp, match on none.
    #[test]
    fn admits_the_new_kinds_where_their_terms_exist() {
        let integers = [
            ValueKind::Int16,
            ValueKind::Int128,
            ValueKind::UInt16,
            ValueKind::UInt128,
        ];
        let logical = [ValueKind::Decimal, ValueKind::Date, ValueKind::Timestamp];
        let matched = IndexSpec::Match(MatchOptions::default());
        for kind in integers {
            assert!(admits(kind, &IndexSpec::Equality), "{kind} equality");
            assert!(admits(kind, &IndexSpec::Ore), "{kind} ore");
            assert!(admits(kind, &IndexSpec::Ope), "{kind} ope");
            assert!(admits(kind, &IndexSpec::OreBlock), "{kind} ore_block");
            assert!(!admits(kind, &matched), "{kind} match");
        }
        // An 8-bit integer keeps its equality term and, like a boolean,
        // has no order term: 256 values are too few to rank.
        for kind in [ValueKind::Int8, ValueKind::UInt8] {
            assert!(admits(kind, &IndexSpec::Equality), "{kind} equality");
            assert!(!admits(kind, &IndexSpec::Ore), "{kind} ore");
            assert!(!admits(kind, &IndexSpec::Ope), "{kind} ope");
            assert!(!admits(kind, &matched), "{kind} match");
            assert_eq!(
                not_admitted(kind, &IndexSpec::Ore),
                Some(Reason::IndexNotAdmitted),
                "{kind} ore is refused as a boolean's is, not as pending"
            );
        }
        for kind in logical {
            assert!(admits(kind, &IndexSpec::Equality), "{kind} equality");
            assert!(admits(kind, &IndexSpec::Ore), "{kind} ore");
            assert!(admits(kind, &IndexSpec::Ope), "{kind} ope");
            assert!(admits(kind, &IndexSpec::OreBlock), "{kind} ore_block");
            assert!(!admits(kind, &matched), "{kind} match");
        }
    }

    /// `not_admitted` is `admits` with a reason: none for an admitted pair,
    /// and one reason for every refusal.
    #[test]
    fn not_admitted_is_admits_with_a_reason() {
        for kind in ValueKind::ALL {
            for index in indexes() {
                let reason = not_admitted(kind, &index);
                assert_eq!(reason.is_none(), admits(kind, &index), "{kind} and {index}");
                if reason.is_some() {
                    assert_eq!(reason, Some(Reason::IndexNotAdmitted), "{kind} and {index}");
                }
            }
        }
        assert_eq!(
            not_admitted(ValueKind::Bool, &IndexSpec::Ope),
            Some(Reason::IndexNotAdmitted)
        );
        assert_eq!(
            not_admitted(ValueKind::Date, &IndexSpec::Match(MatchOptions::default())),
            Some(Reason::IndexNotAdmitted)
        );
        for kind in [ValueKind::Decimal, ValueKind::Date, ValueKind::Timestamp] {
            for index in [IndexSpec::Ore, IndexSpec::Ope, IndexSpec::OreBlock] {
                assert_eq!(not_admitted(kind, &index), None, "{kind} and {index}");
            }
        }
        for index in [IndexSpec::Ore, IndexSpec::Ope, IndexSpec::OreBlock] {
            assert_eq!(
                not_admitted(ValueKind::Int8, &index),
                Some(Reason::IndexNotAdmitted),
                "an 8-bit integer is refused {index} as a boolean is"
            );
        }
    }

    /// Every integer width is a source and a target: a value in range
    /// converts exactly, one outside it is refused.
    #[test]
    fn read_converts_between_every_integer_width() {
        assert!(reads_as(
            ValueKind::Int8,
            Tree::Int64(-128),
            int(Int::I8(-128))
        ));
        assert!(read_frame(ValueKind::Int8, Tree::Int64(128)).is_none());
        assert!(reads_as(
            ValueKind::Int16,
            int(Int::U8(200)),
            int(Int::I16(200))
        ));
        assert!(read_frame(ValueKind::Int16, Tree::Int32(40_000)).is_none());
        assert!(reads_as(
            ValueKind::UInt8,
            int(Int::I16(255)),
            int(Int::U8(255))
        ));
        assert!(read_frame(ValueKind::UInt8, int(Int::I8(-1))).is_none());
        assert!(reads_as(
            ValueKind::UInt16,
            int(Int::U128(65_535)),
            int(Int::U16(65_535))
        ));
        assert!(read_frame(ValueKind::UInt16, Tree::UInt32(65_536)).is_none());
        assert!(reads_as(
            ValueKind::Int128,
            Tree::UInt64(u64::MAX),
            int(Int::I128(u64::MAX.into()))
        ));
        assert!(reads_as(
            ValueKind::Int128,
            int(Int::U128(i128::MAX as u128)),
            int(Int::I128(i128::MAX))
        ));
        // A `u128` above `i128::MAX` is no `i128`, nor any narrower width.
        assert!(read_frame(ValueKind::Int128, int(Int::U128(u128::MAX))).is_none());
        assert!(read_frame(ValueKind::UInt64, int(Int::U128(u128::MAX))).is_none());
        assert!(reads_as(
            ValueKind::UInt128,
            int(Int::I8(7)),
            int(Int::U128(7))
        ));
        assert!(read_frame(ValueKind::UInt128, int(Int::I128(-1))).is_none());
        assert!(reads_as(
            ValueKind::Int64,
            int(Int::I128(-5)),
            int(Int::I64(-5))
        ));
        assert!(reads_as(
            ValueKind::UInt32,
            int(Int::U16(9)),
            int(Int::U32(9))
        ));
        assert!(reads_as(
            ValueKind::Int32,
            int(Int::I8(-9)),
            int(Int::I32(-9))
        ));
    }

    /// The 128-bit edges: a float at 2^127 is past `i128` and one at 2^128
    /// past `u128`, though casting either would saturate to the maximum and
    /// derive the term of a different number. -2^127 is `i128::MIN`
    /// exactly. An integer the float kind would round is refused in the
    /// other direction too.
    #[test]
    fn read_refuses_a_number_past_the_128_bit_ranges() {
        let two_127 = 170_141_183_460_469_231_731_687_303_715_884_105_728.0_f64;
        let two_128 = 340_282_366_920_938_463_463_374_607_431_768_211_456.0_f64;
        assert!(read_frame(ValueKind::Int128, Tree::Float64(two_127)).is_none());
        assert!(reads_as(
            ValueKind::Int128,
            Tree::Float64(-two_127),
            int(Int::I128(i128::MIN))
        ));
        assert!(read_frame(ValueKind::UInt128, Tree::Float64(two_128)).is_none());
        assert!(reads_as(
            ValueKind::UInt128,
            Tree::Float64(two_127),
            int(Int::U128(1 << 127))
        ));
        assert!(read_frame(ValueKind::UInt128, Tree::Float64(-1.0)).is_none());
        assert!(read_frame(ValueKind::UInt128, Tree::Float64(0.5)).is_none());
        assert!(read_frame(ValueKind::UInt128, Tree::Float64(f64::NAN)).is_none());
        assert!(read_frame(ValueKind::Float64, int(Int::I128(i128::MAX))).is_none());
        assert!(read_frame(ValueKind::Float64, int(Int::U128(u128::MAX))).is_none());
        assert!(reads_as(
            ValueKind::Float64,
            int(Int::I128(i128::MIN)),
            tree(Tree::Float64(-two_127))
        ));
        assert!(reads_as(
            ValueKind::Float64,
            int(Int::U128(1 << 127)),
            tree(Tree::Float64(two_127))
        ));
        assert!(read_frame(ValueKind::Float32, int(Int::U128((1 << 24) + 1))).is_none());
    }

    /// An integer reads as a decimal at scale 0 when its magnitude fits 96
    /// bits; a float never does. Nothing converts to a date or a
    /// timestamp, and a decimal, date or timestamp converts to nothing.
    #[test]
    fn read_converts_an_integer_to_a_decimal_and_nothing_to_a_date() {
        let decimal = |mantissa: i128| {
            scalar(
                Some(Logical::Decimal { scale: 0 }),
                Physical::Int(Int::I128(mantissa)),
            )
        };
        assert!(reads_as(ValueKind::Decimal, Tree::Int64(-34), decimal(-34)));
        assert!(reads_as(ValueKind::Decimal, int(Int::U8(34)), decimal(34)));
        assert!(read_frame(ValueKind::Decimal, int(Int::I128(1 << 96))).is_none());
        assert!(read_frame(ValueKind::Decimal, int(Int::U128(u128::MAX))).is_none());
        assert!(read_frame(ValueKind::Decimal, Tree::Float64(1.0)).is_none());
        assert!(read_frame(ValueKind::Date, Tree::Int32(19_782)).is_none());
        assert!(read_frame(ValueKind::Timestamp, Tree::Int64(1)).is_none());
        for kind in [ValueKind::Decimal, ValueKind::Date, ValueKind::Timestamp] {
            for target in [ValueKind::Int128, ValueKind::Float64, ValueKind::String] {
                assert!(
                    read_frame(target, sample(kind)).is_none(),
                    "{kind} as {target}"
                );
            }
        }
    }

    /// `read`, with the frame it writes read back as a value tree to
    /// compare.
    fn read_ok(kind: ValueKind, value: Tree) -> Option<Tree> {
        let read = read(kind, value).ok()?;
        Some(Tree::from_frame(read.risky_ref()).expect("a value"))
    }

    /// `read` from any source, as the frame it writes, for the kinds a
    /// control-data tree cannot hold.
    fn read_frame(kind: ValueKind, value: impl Encrypt) -> Option<ValueFrame> {
        read(kind, value).ok()
    }

    /// Whether `read` gives exactly the frame of `want`.
    fn reads_as(kind: ValueKind, value: impl Encrypt, want: ValueFrame) -> bool {
        read_frame(kind, value).is_some_and(|read| read.risky_ref() == want.risky_ref())
    }

    #[test]
    fn read_returns_a_value_of_the_kind_as_it_is() {
        for kind in value_kinds() {
            let read = read_frame(kind, sample(kind)).expect("its own kind");
            assert_eq!(read.kind(), Some(kind));
            assert_eq!(
                read.risky_ref(),
                sample(kind).risky_ref(),
                "{kind} as it is"
            );
        }
        // Already of the kind: returned as it is, not converted, so a NaN
        // the host sent as the field's own float kind is not refused here.
        assert!(
            matches!(read_ok(ValueKind::Float32, Tree::Float32(f32::NAN)), Some(Tree::Float32(f)) if f.is_nan())
        );
        assert!(
            matches!(read_ok(ValueKind::Float64, Tree::Float64(f64::NAN)), Some(Tree::Float64(f)) if f.is_nan())
        );
    }

    #[test]
    fn read_converts_an_exact_number_to_an_integer_kind() {
        // Every numeric variant is a source, each read into another width.
        assert!(matches!(
            read_ok(ValueKind::Int64, Tree::Int32(-5)),
            Some(Tree::Int64(-5))
        ));
        assert!(matches!(
            read_ok(ValueKind::Int32, Tree::UInt64(5)),
            Some(Tree::Int32(5))
        ));
        assert!(
            matches!(read_ok(ValueKind::Float64, Tree::Int32(-5)), Some(Tree::Float64(f)) if f == -5.0)
        );
        // A JavaScript number is a float.
        assert!(matches!(
            read_ok(ValueKind::UInt64, Tree::Float64(34.0)),
            Some(Tree::UInt64(34))
        ));
        assert!(matches!(
            read_ok(ValueKind::Int32, Tree::Float32(-2.0)),
            Some(Tree::Int32(-2))
        ));
        assert!(matches!(
            read_ok(ValueKind::Int64, Tree::UInt32(7)),
            Some(Tree::Int64(7))
        ));
        assert!(matches!(
            read_ok(ValueKind::UInt32, Tree::Int64(7)),
            Some(Tree::UInt32(7))
        ));
        assert!(matches!(
            read_ok(ValueKind::Int64, Tree::Float64(-0.0)),
            Some(Tree::Int64(0))
        ));
        assert!(matches!(
            read_ok(ValueKind::UInt64, Tree::Int64(i64::MAX)),
            Some(Tree::UInt64(v)) if v == i64::MAX as u64
        ));
        assert!(matches!(
            read_ok(ValueKind::Int32, Tree::Int64(i32::MIN.into())),
            Some(Tree::Int32(i32::MIN))
        ));
        assert!(matches!(
            read_ok(ValueKind::UInt32, Tree::UInt64(u32::MAX.into())),
            Some(Tree::UInt32(u32::MAX))
        ));
    }

    #[test]
    fn read_refuses_an_inexact_or_out_of_range_integer() {
        let refused = [
            (ValueKind::UInt64, Tree::Float64(34.5)),
            (ValueKind::Int64, Tree::Float64(f64::NAN)),
            (ValueKind::Int64, Tree::Float64(f64::INFINITY)),
            (ValueKind::Int64, Tree::Float64(1e30)),
            (ValueKind::UInt64, Tree::Int64(-1)),
            (ValueKind::UInt32, Tree::UInt64(u64::from(u32::MAX) + 1)),
            (ValueKind::Int32, Tree::Int64(i64::from(i32::MAX) + 1)),
            (ValueKind::Int32, Tree::Int64(i64::from(i32::MIN) - 1)),
            (ValueKind::Int64, Tree::UInt64(u64::MAX)),
        ];
        for (at, (kind, value)) in refused.into_iter().enumerate() {
            assert!(
                matches!(read(kind, value), Err(Error::Source { .. })),
                "case {at}, as {kind}"
            );
        }
    }

    /// The first float past each integer range is refused, and the last
    /// one inside it converts exactly. A float cast straight to the integer
    /// type (`f as u64`) would saturate instead: a JavaScript 2^64 would
    /// read as `u64::MAX` and derive a term for a different number.
    #[test]
    fn read_refuses_a_float_at_the_first_value_past_an_integer_range() {
        let two_63 = 9_223_372_036_854_775_808.0_f64;
        let two_64 = 18_446_744_073_709_551_616.0_f64;
        assert!(read_ok(ValueKind::Int64, Tree::Float64(two_63)).is_none());
        assert!(matches!(
            read_ok(ValueKind::Int64, Tree::Float64(-two_63)),
            Some(Tree::Int64(i64::MIN))
        ));
        assert!(read_ok(ValueKind::UInt64, Tree::Float64(two_64)).is_none());
        assert!(matches!(
            read_ok(
                ValueKind::UInt64,
                Tree::Float64(18_446_744_073_709_549_568.0)
            ),
            Some(Tree::UInt64(18_446_744_073_709_549_568))
        ));
        assert!(read_ok(ValueKind::UInt32, Tree::Float64(4_294_967_296.0)).is_none());
        assert!(matches!(
            read_ok(ValueKind::UInt32, Tree::Float64(4_294_967_295.0)),
            Some(Tree::UInt32(u32::MAX))
        ));
    }

    #[test]
    fn read_converts_an_exactly_representable_number_to_a_float_kind() {
        assert!(
            matches!(read_ok(ValueKind::Float64, Tree::Int64(34)), Some(Tree::Float64(f)) if f == 34.0)
        );
        assert!(
            matches!(read_ok(ValueKind::Float64, Tree::Float32(1.5)), Some(Tree::Float64(f)) if f == 1.5)
        );
        assert!(
            matches!(read_ok(ValueKind::Float32, Tree::Float64(1.5)), Some(Tree::Float32(f)) if f == 1.5)
        );
        assert!(
            matches!(read_ok(ValueKind::Float32, Tree::UInt32(16_777_216)), Some(Tree::Float32(f)) if f == 16_777_216.0)
        );
        assert!(matches!(
            read_ok(ValueKind::Float64, Tree::UInt64(1 << 53)),
            Some(Tree::Float64(f)) if f == 9_007_199_254_740_992.0
        ));
    }

    #[test]
    fn read_refuses_a_number_a_float_kind_would_round() {
        let refused = [
            (ValueKind::Float64, Tree::UInt64((1 << 53) + 1)),
            (ValueKind::Float64, Tree::UInt64(u64::MAX)),
            (ValueKind::Float32, Tree::UInt32(16_777_217)),
            (ValueKind::Float32, Tree::Float64(0.1)),
        ];
        for (at, (kind, value)) in refused.into_iter().enumerate() {
            assert!(
                matches!(read(kind, value), Err(Error::Source { .. })),
                "case {at}, as {kind}"
            );
        }
    }

    /// A NaN converts in neither float direction: it equals nothing, so no
    /// conversion of it is exact, and a query for one could match nothing.
    #[test]
    fn read_refuses_a_nan_in_both_float_directions() {
        assert!(matches!(
            read(ValueKind::Float32, Tree::Float64(f64::NAN)),
            Err(Error::Source { .. })
        ));
        assert!(matches!(
            read(ValueKind::Float64, Tree::Float32(f32::NAN)),
            Err(Error::Source { .. })
        ));
    }

    #[test]
    fn read_never_converts_across_kinds() {
        let refused = [
            (ValueKind::UInt64, Tree::String("34".into())),
            (ValueKind::String, Tree::UInt64(34)),
            (ValueKind::Bool, Tree::UInt32(1)),
            (ValueKind::UInt32, Tree::Bool(true)),
            (ValueKind::Bytes, Tree::String("ab".into())),
            (ValueKind::String, Tree::Bytes(b"ab".to_vec())),
            (ValueKind::Array, Tree::Object(vec![])),
            (ValueKind::Object, Tree::Array(vec![])),
            (ValueKind::UInt32, Tree::Null),
            (ValueKind::Bool, Tree::Float64(1.0)),
        ];
        for (at, (kind, value)) in refused.into_iter().enumerate() {
            assert!(
                matches!(read(kind, value), Err(Error::Source { .. })),
                "case {at}, as {kind}"
            );
        }
    }
}
