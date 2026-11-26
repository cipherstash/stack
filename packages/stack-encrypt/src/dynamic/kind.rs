//! What a plan's declared field type means to the engine.
//!
//! A typed host knows what `34` is: a Rust `u32`, a Go `int64`. A dynamically
//! typed host (JavaScript, PHP, Ruby) does not, and index semantics depend on
//! it: an ORE term of the integer `34` and of the float `34.0` differ, a
//! JavaScript number is a float, and match is defined over text alone. So a
//! plan field may say what its values are, in its `"type"` key.
//!
//! The vocabulary is [`DeclaredType`]: vitaminc's [`ValueKind`], or `json`.
//! Their [`name`](DeclaredType::name)s (`"uint64"`, `"string"`, …,
//! `"array"`, `"object"`, `"json"`) are frozen wire format;
//! [`ValueFrame::kind`] says which [`ValueKind`] a value is. Beside it, this
//! module adds two rules:
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

use vitaminc_aead::plaintext::{
    Float, Int, Logical, ParseValueKindError, Physical, Raw, ValueKind,
};
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
/// wider, both floats, text, a decimal, a date and a timestamp. A
/// boolean and an 8-bit integer have no order term: over so small a domain
/// it would reveal which rows are `true`, or each row's rank among 256
/// values. A composite (`array`, `object`) has no term. Only the index's
/// kind matters: a match index's options do not change what it applies to.
///
/// Bytes have no order term: no ordering operator compares them, so no
/// query could use a stored term, and anyone who reads the rows could
/// still compare the terms. So a plan refuses an order index on bytes, as
/// [`IndexSpec::defines`] gives bytes no order term.
///
/// A plan therefore accepts an index on a kind only if one of the
/// index's operators accepts that kind. The typed interface has the same
/// rule: an order index needs [`Orderable`](crate::Orderable), which does
/// not cover bytes.
///
/// `json` admits no index here: a document is indexed by the target that
/// stores it.
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
/// assert!(admits(ValueKind::Bytes, &IndexSpec::Equality));
/// assert!(!admits(ValueKind::Bytes, &IndexSpec::Ore));
/// ```
pub fn admits(kind: impl Into<DeclaredType>, index: &IndexSpec) -> bool {
    kind.into()
        .value_kind()
        .and_then(ValueKind::zero)
        .is_some_and(|(ty, scalar)| index.takes(ty, &scalar))
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
pub fn not_admitted(kind: impl Into<DeclaredType>, index: &IndexSpec) -> Option<Reason> {
    if admits(kind, index) {
        return None;
    }
    Some(if matches!(index, IndexSpec::Json(_)) {
        Reason::JsonIndexPending
    } else {
        Reason::IndexNotAdmitted
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
/// **[`term`](super::term()) does not call this.** It takes a value and an
/// [`IndexSpec`] and never sees the field's declared kind, so a binding
/// deriving a query term with it for a typed field must call `read` first,
/// with [`FieldPlan::field_type`](super::FieldPlan::field_type). One that
/// skips it hands `Float64(34.0)` to a `uint64` field, derives a float term
/// where the stored one is the `u64` term, and matches nothing, with no
/// error. [`query_term`](super::query_term) does call it, for a non-null
/// input to any operator but a document's: a query named by operator reads
/// its input as the field's kind.
///
/// ```
/// use stack_encrypt::dynamic::{read, ValueFrame, ValueKind};
///
/// // A JavaScript number is a float; against a `uint64` field it is 34.
/// let value = read(ValueKind::UInt64, 34.0f64)?;
/// assert_eq!(value.kind(), Some(ValueKind::UInt64));
/// assert_eq!(value, ValueFrame::of(34u64)?);
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
pub fn read(kind: impl Into<DeclaredType>, value: impl Encrypt) -> Result<ValueFrame, Error> {
    let kind = kind.into();
    let refused = || Error::bad_source(Reason::FieldType);
    let value = ValueFrame::of(value).map_err(|_| refused())?;
    if kind.holds(value.kind()) {
        return Ok(value);
    }
    let Some(kind) = kind.value_kind() else {
        return Err(refused());
    };
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

/// The type a plan field declares in its `"type"` key: a [`ValueKind`], or
/// `json`.
///
/// A [`ValueKind`] is vitaminc's: a scalar of one type, an array or an
/// object, as it is sealed. `json` is the engine's own. A JSON document
/// crosses as UTF-8 JSON text in a text or bytes value, so no value is of
/// type `json` ([`ValueFrame::kind`] says `string` or `bytes`). A field
/// declares it to have its text parsed by one set of rules
/// ([`crate::json::parse_text`]) and stored by a target that stores a
/// document (`JsonSearch`), and it opens back as bytes. A JSON document's
/// `null` is the text `null`, not the frame's null.
///
/// # Names are wire format
///
/// [`name`](Self::name) (also its [`Display`](fmt::Display) and [`FromStr`]
/// form) is how a binding spells a type: [`ValueKind::name`], or `"json"`.
/// The names are frozen: matched exactly, case-sensitively, and never
/// renamed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DeclaredType {
    /// A value of this type.
    Value(ValueKind),
    /// `"json"`: a JSON document, as UTF-8 JSON text in a text or bytes
    /// value.
    Json,
}

impl DeclaredType {
    /// How a declaration spells this type: [`ValueKind::name`], or
    /// `"json"`. Frozen wire format.
    pub const fn name(self) -> &'static str {
        match self {
            DeclaredType::Value(ty) => ty.name(),
            DeclaredType::Json => "json",
        }
    }

    /// The type of the values a field of this type holds, or `None` for
    /// `json`, whose values are text or bytes.
    pub const fn value_kind(self) -> Option<ValueKind> {
        match self {
            DeclaredType::Value(ty) => Some(ty),
            DeclaredType::Json => None,
        }
    }

    /// Whether a value of type `found` is a value of this declared type:
    /// the same type, or for [`Json`](Self::Json), the text or bytes the
    /// document crosses as. `None`, a value with no type (a null, an
    /// undefined, a passthrough), is a value of no declared type.
    pub fn holds(self, found: Option<ValueKind>) -> bool {
        match (self, found) {
            (DeclaredType::Json, Some(ValueKind::String | ValueKind::Bytes)) => true,
            (DeclaredType::Value(declared), Some(found)) => declared == found,
            (_, _) => false,
        }
    }
}

impl From<ValueKind> for DeclaredType {
    fn from(ty: ValueKind) -> Self {
        DeclaredType::Value(ty)
    }
}

impl fmt::Display for DeclaredType {
    /// Writes [`name`](Self::name).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for DeclaredType {
    type Err = ParseValueKindError;

    /// Parses a [`name`](Self::name), exactly: `"uint64"`, not `"UInt64"`,
    /// `"u64"` or `" uint64"`. `"null"` and `"undefined"` are not types.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if name == DeclaredType::Json.name() {
            return Ok(DeclaredType::Json);
        }
        name.parse().map(DeclaredType::Value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::test_frame::Tree;
    use crate::sem::{MatchOptions, Tokenizer};
    use vitaminc_aead::plaintext::{Raw, TimeUnit};

    /// A declared type's names are its value type's, and `"json"`, each
    /// parsing back exactly.
    #[test]
    fn declared_type_names_parse_back_exactly() {
        let all = ValueKind::ALL
            .into_iter()
            .map(DeclaredType::Value)
            .chain([DeclaredType::Json]);
        for ty in all {
            assert_eq!(ty.name().parse::<DeclaredType>(), Ok(ty));
            assert_eq!(ty.to_string(), ty.name());
        }
        assert_eq!(DeclaredType::Json.name(), "json");
        for ty in ValueKind::ALL {
            assert_eq!(DeclaredType::from(ty).name(), ty.name());
            assert_eq!(DeclaredType::from(ty).value_kind(), Some(ty));
        }
        assert_eq!(DeclaredType::Json.value_kind(), None);
        for refused in ["UInt64", "Json", "null", "undefined", ""] {
            assert_eq!(
                refused.parse::<DeclaredType>(),
                Err(ParseValueKindError),
                "{refused:?}"
            );
        }
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
        }
    }

    /// Every value type.
    fn value_kinds() -> impl Iterator<Item = ValueKind> {
        ValueKind::ALL.into_iter()
    }

    /// `json` admits no index (a document is indexed by the target that
    /// stores it), holds text and bytes and nothing else, and reads either
    /// as it is: the text is parsed where the document is sealed.
    #[test]
    fn json_holds_its_text_and_admits_no_index() {
        for index in indexes() {
            assert!(!admits(DeclaredType::Json, &index), "{index}");
        }
        assert!(DeclaredType::Json.holds(Some(ValueKind::String)));
        assert!(DeclaredType::Json.holds(Some(ValueKind::Bytes)));
        for kind in value_kinds().filter(|k| !matches!(k, ValueKind::String | ValueKind::Bytes)) {
            assert!(!DeclaredType::Json.holds(Some(kind)), "{kind}");
        }
        assert!(
            !DeclaredType::Json.holds(None),
            "a frame null is not a document"
        );
        assert!(!DeclaredType::from(ValueKind::String).holds(Some(ValueKind::Bytes)));
        for kind in value_kinds() {
            assert!(DeclaredType::from(kind).holds(Some(kind)), "{kind}");
            assert!(!DeclaredType::from(kind).holds(None), "{kind}");
        }
        // A document crosses as its text: a value of type string.
        let text =
            read_frame(DeclaredType::Json, Tree::String(r#"{"k": 1}"#.into())).expect("text");
        assert_eq!(text.kind(), Some(ValueKind::String));
        let bytes = read_frame(DeclaredType::Json, Tree::Bytes(b"[1]".to_vec())).expect("bytes");
        assert_eq!(bytes.kind(), Some(ValueKind::Bytes));
        assert!(read_frame(DeclaredType::Json, Tree::UInt32(1)).is_none());
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
    /// Bytes have no order term, so a plan refuses an order index on them
    /// with `index_not_admitted`.
    #[test]
    fn admits_agrees_with_defines_for_every_kind() {
        for kind in value_kinds() {
            for index in indexes() {
                let order = matches!(index, IndexSpec::Ore | IndexSpec::Ope | IndexSpec::OreBlock);
                if kind == ValueKind::Bytes && order {
                    assert_eq!(
                        not_admitted(kind, &index),
                        Some(Reason::IndexNotAdmitted),
                        "bytes and {index}"
                    );
                }
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
        assert!(!admits(DeclaredType::Json, &wide));
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
        let all = ValueKind::ALL
            .into_iter()
            .map(DeclaredType::Value)
            .chain([DeclaredType::Json]);
        for kind in all {
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
    fn read_frame(kind: impl Into<DeclaredType>, value: impl Encrypt) -> Option<ValueFrame> {
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
