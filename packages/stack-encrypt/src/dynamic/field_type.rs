//! The type a plan declares for a field.
//!
//! A typed host knows what `34` is: a Rust `u32`, a Go `int64`. A dynamically
//! typed host (JavaScript, PHP, Ruby) does not, and index semantics depend on
//! it: an ORE term of the integer `34` and of the float `34.0` differ, a
//! JavaScript number is a float, and match is defined over text alone. So a
//! plan field may say what its values are, and the engine uses that three
//! times:
//!
//! - **encrypt** admits only the indexes the type is defined for (when the
//!   plan is built), and refuses a value of any other type (when it runs),
//!   so the term bytes are the declared type's and no binding is trusted to
//!   have tagged the value right;
//! - **query** reads the query value *as* the field's type
//!   ([`FieldType::read`]): `34` against a `uint64` field is the `u64` term,
//!   whatever number type the host handed over;
//! - **decrypt** refuses an opened value of any other type, so a host with no
//!   types of its own can rely on the declaration for what it gets back (an
//!   integer, not a float; bytes, not a string).
//!
//! The vocabulary is not new: it is vitaminc's frozen leaf-tag table
//! (`vitaminc_aead_value::tags`), one type per scalar tag, plus the two
//! composite kinds the transport frames (`array`, `object`). `null` and
//! `undefined` are tags but not field types: a type with one value says
//! nothing a field can be declared as.
use std::fmt;

use vitaminc_aead_value::{tags, FfiValue};

use super::Error;
use crate::target::IndexSpec;

/// The type of a plan field's values.
///
/// The [`name`](Self::name) strings are wire format, spelled by a binding in
/// a plan's `"type"` key, so this enum is exhaustive for the reason
/// [`IndexSpec`] is (see the [module docs](super#stability)).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum FieldType {
    /// `"bool"`: [`FfiValue::Bool`], tags `BOOL_FALSE` and `BOOL_TRUE`.
    Bool,
    /// `"int32"`: [`FfiValue::Int32`], tag `INT32`.
    Int32,
    /// `"int64"`: [`FfiValue::Int64`], tag `INT64`.
    Int64,
    /// `"uint32"`: [`FfiValue::UInt32`], tag `UINT32`.
    UInt32,
    /// `"uint64"`: [`FfiValue::UInt64`], tag `UINT64`.
    UInt64,
    /// `"float32"`: [`FfiValue::Float32`], tag `FLOAT32`.
    Float32,
    /// `"float64"`: [`FfiValue::Float64`], tag `FLOAT64`.
    Float64,
    /// `"string"`: [`FfiValue::String`], tag `STRING`.
    String,
    /// `"bytes"`: [`FfiValue::Bytes`], tag `BYTES`.
    Bytes,
    /// `"array"`: [`FfiValue::Array`], sealed in the cipher's sequence mode.
    /// Its elements are not typed by the declaration.
    Array,
    /// `"object"`: [`FfiValue::Object`], sealed in the cipher's map mode.
    /// Its entries are not typed by the declaration.
    Object,
}

/// Every field type, in declaration order.
const ALL: [FieldType; 11] = [
    FieldType::Bool,
    FieldType::Int32,
    FieldType::Int64,
    FieldType::UInt32,
    FieldType::UInt64,
    FieldType::Float32,
    FieldType::Float64,
    FieldType::String,
    FieldType::Bytes,
    FieldType::Array,
    FieldType::Object,
];

impl FieldType {
    /// Every field type.
    pub fn all() -> [FieldType; 11] {
        ALL
    }

    /// The type a plan's `"type"` names, or `None` for a name that is not
    /// one. Names are matched exactly: `"uint64"`, not `"UInt64"` or `"u64"`.
    pub fn parse(name: &str) -> Option<Self> {
        ALL.into_iter().find(|ty| ty.name() == name)
    }

    /// How a plan spells this type.
    pub fn name(self) -> &'static str {
        match self {
            FieldType::Bool => "bool",
            FieldType::Int32 => "int32",
            FieldType::Int64 => "int64",
            FieldType::UInt32 => "uint32",
            FieldType::UInt64 => "uint64",
            FieldType::Float32 => "float32",
            FieldType::Float64 => "float64",
            FieldType::String => "string",
            FieldType::Bytes => "bytes",
            FieldType::Array => "array",
            FieldType::Object => "object",
        }
    }

    /// The vitaminc leaf tags a value of this type seals under: one per
    /// scalar type (two for `bool`, whose value is its tag), none for a
    /// composite, which seals as structure.
    pub fn tags(self) -> &'static [u8] {
        match self {
            FieldType::Bool => &[tags::BOOL_FALSE, tags::BOOL_TRUE],
            FieldType::Int32 => &[tags::INT32],
            FieldType::Int64 => &[tags::INT64],
            FieldType::UInt32 => &[tags::UINT32],
            FieldType::UInt64 => &[tags::UINT64],
            FieldType::Float32 => &[tags::FLOAT32],
            FieldType::Float64 => &[tags::FLOAT64],
            FieldType::String => &[tags::STRING],
            FieldType::Bytes => &[tags::BYTES],
            FieldType::Array | FieldType::Object => &[],
        }
    }

    /// The type of a value, or `None` for one no field can be declared as:
    /// null, undefined or a passthrough.
    pub fn of(value: &FfiValue) -> Option<Self> {
        Some(match value {
            FfiValue::Bool(_) => FieldType::Bool,
            FfiValue::Int32(_) => FieldType::Int32,
            FfiValue::Int64(_) => FieldType::Int64,
            FfiValue::UInt32(_) => FieldType::UInt32,
            FfiValue::UInt64(_) => FieldType::UInt64,
            FfiValue::Float32(_) => FieldType::Float32,
            FfiValue::Float64(_) => FieldType::Float64,
            FfiValue::String(_) => FieldType::String,
            FfiValue::Bytes(_) => FieldType::Bytes,
            FfiValue::Array(_) => FieldType::Array,
            FfiValue::Object(_) => FieldType::Object,
            _ => return None,
        })
    }

    /// Whether `value` is of this type: what the engine checks of every
    /// value it seals into, and every value it opens from, a typed field.
    pub fn holds(self, value: &FfiValue) -> bool {
        Self::of(value) == Some(self)
    }

    /// Whether the scheme defines a `kind` term for values of this type.
    ///
    /// The same table as [`IndexSpec::supports`], stated over types instead
    /// of values, so a plan can be refused when it is built rather than when
    /// its first value arrives: equality over every integer, text and bytes
    /// (no floats, no booleans); match over text alone; ORE and OPE over
    /// every scalar. A composite has no term. Only the index's kind
    /// matters: a match index's options do not change what it applies to.
    pub fn admits(self, kind: &IndexSpec) -> bool {
        use FieldType::*;
        match kind {
            IndexSpec::Equality => matches!(self, Int32 | Int64 | UInt32 | UInt64 | String | Bytes),
            IndexSpec::Match(_) => self == String,
            IndexSpec::Ore | IndexSpec::Ope => !matches!(self, Array | Object),
        }
    }

    /// Read a query value as this type.
    ///
    /// A value already of this type is returned as it is. A number of
    /// another width or kind is converted when the conversion is exact: an
    /// integer in range, or a float with no fractional part in range, for an
    /// integer type (a JavaScript `34` arrives as a float); an integer or
    /// float the target float type represents exactly, for a float type.
    /// Nothing else converts: a string is never parsed as a number, and a
    /// number never becomes a string.
    ///
    /// This is for a query: what a host hands over to search with. A value
    /// being sealed is not converted; it must already be of the field's
    /// type, and is refused otherwise.
    ///
    /// # Errors
    ///
    /// [`Error::Source`] if the value cannot be read as this type exactly.
    pub fn read(self, value: FfiValue) -> Result<FfiValue, Error> {
        if self.holds(&value) {
            return Ok(value);
        }
        let number = Number::of(&value).ok_or(Error::Source)?;
        let read = match self {
            FieldType::Int32 => number
                .integer()
                .and_then(|i| i32::try_from(i).ok())
                .map(FfiValue::Int32),
            FieldType::Int64 => number
                .integer()
                .and_then(|i| i64::try_from(i).ok())
                .map(FfiValue::Int64),
            FieldType::UInt32 => number
                .integer()
                .and_then(|i| u32::try_from(i).ok())
                .map(FfiValue::UInt32),
            FieldType::UInt64 => number
                .integer()
                .and_then(|i| u64::try_from(i).ok())
                .map(FfiValue::UInt64),
            FieldType::Float64 => number.exact_f64().map(FfiValue::Float64),
            FieldType::Float32 => number.exact_f32().map(FfiValue::Float32),
            _ => None,
        };
        read.ok_or(Error::Source)
    }
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A numeric leaf, widened without loss: every integer variant fits an
/// `i128`, and an `f32` widens to an `f64` exactly.
#[derive(Clone, Copy)]
enum Number {
    Integer(i128),
    Float(f64),
}

impl Number {
    fn of(value: &FfiValue) -> Option<Self> {
        Some(match value {
            FfiValue::Int32(v) => Number::Integer((*v).into()),
            FfiValue::Int64(v) => Number::Integer((*v).into()),
            FfiValue::UInt32(v) => Number::Integer((*v).into()),
            FfiValue::UInt64(v) => Number::Integer((*v).into()),
            FfiValue::Float32(v) => Number::Float((*v).into()),
            FfiValue::Float64(v) => Number::Float(*v),
            _ => return None,
        })
    }

    /// The integer this number is exactly, if it is one. A float outside
    /// `i128` saturates, which no target integer type then accepts.
    fn integer(self) -> Option<i128> {
        match self {
            Number::Integer(i) => Some(i),
            Number::Float(f) if f.is_finite() && f.fract() == 0.0 => Some(f as i128),
            Number::Float(_) => None,
        }
    }

    /// The `f64` this number is exactly, if it is one: an integer whose
    /// conversion does not round.
    fn exact_f64(self) -> Option<f64> {
        match self {
            Number::Float(f) => Some(f),
            Number::Integer(i) => {
                let f = i as f64;
                (f as i128 == i).then_some(f)
            }
        }
    }

    /// The `f32` this number is exactly, if it is one. A NaN is never
    /// exact, because it does not equal itself.
    fn exact_f32(self) -> Option<f32> {
        let f = self.exact_f64()?;
        let narrowed = f as f32;
        (f64::from(narrowed) == f).then_some(narrowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::Scalar;
    use crate::sem::{MatchOptions, Tokenizer};
    use vitaminc_protected::Protected;

    /// One value of every field type.
    fn sample(ty: FieldType) -> FfiValue {
        match ty {
            FieldType::Bool => FfiValue::Bool(true),
            FieldType::Int32 => FfiValue::Int32(-3),
            FieldType::Int64 => FfiValue::Int64(-4),
            FieldType::UInt32 => FfiValue::UInt32(34),
            FieldType::UInt64 => FfiValue::UInt64(35),
            FieldType::Float32 => FfiValue::Float32(1.5),
            FieldType::Float64 => FfiValue::Float64(2.5),
            FieldType::String => FfiValue::String("alice".into()),
            FieldType::Bytes => FfiValue::Bytes(Protected::new(b"ab".to_vec())),
            FieldType::Array => FfiValue::Array(vec![FfiValue::UInt32(1)]),
            FieldType::Object => FfiValue::Object(vec![("k".to_string(), FfiValue::UInt32(1))]),
        }
    }

    fn kinds() -> [IndexSpec; 4] {
        [
            IndexSpec::Equality,
            IndexSpec::Match(MatchOptions::default()),
            IndexSpec::Ore,
            IndexSpec::Ope,
        ]
    }

    #[test]
    fn every_name_parses_back_to_its_type_and_nothing_else_parses() {
        let names: Vec<_> = FieldType::all().iter().map(|ty| ty.name()).collect();
        assert_eq!(
            names,
            [
                "bool", "int32", "int64", "uint32", "uint64", "float32", "float64", "string",
                "bytes", "array", "object"
            ],
            "the names are wire format"
        );
        for ty in FieldType::all() {
            assert_eq!(FieldType::parse(ty.name()), Some(ty));
            assert_eq!(ty.to_string(), ty.name());
        }
        for not_a_type in [
            "",
            "UInt64",
            "u64",
            "int",
            "number",
            "null",
            "undefined",
            "text",
        ] {
            assert_eq!(FieldType::parse(not_a_type), None, "{not_a_type:?}");
        }
    }

    /// The vocabulary is the tag table: every scalar tag but null and
    /// undefined belongs to exactly one type, and the composites to none.
    #[test]
    fn the_scalar_types_are_vitaminc_tag_table() {
        let mut claimed: Vec<u8> = FieldType::all()
            .iter()
            .flat_map(|ty| ty.tags().iter().copied())
            .collect();
        claimed.sort_unstable();
        assert_eq!(
            claimed,
            [
                tags::BOOL_FALSE,
                tags::BOOL_TRUE,
                tags::INT32,
                tags::INT64,
                tags::UINT32,
                tags::UINT64,
                tags::FLOAT32,
                tags::FLOAT64,
                tags::STRING,
                tags::BYTES
            ]
        );
        assert_eq!(FieldType::Bool.tags(), [tags::BOOL_FALSE, tags::BOOL_TRUE]);
        assert_eq!(FieldType::UInt64.tags(), [tags::UINT64]);
        assert_eq!(FieldType::Int64.tags(), [tags::INT64]);
        assert!(FieldType::Array.tags().is_empty());
        assert!(FieldType::Object.tags().is_empty());
    }

    #[test]
    fn a_value_is_of_exactly_one_type_and_held_by_it_alone() {
        for ty in FieldType::all() {
            let value = sample(ty);
            assert_eq!(FieldType::of(&value), Some(ty));
            for other in FieldType::all() {
                assert_eq!(other.holds(&value), other == ty, "{other} holds a {ty}?");
            }
        }
        for untyped in [
            FfiValue::Null,
            FfiValue::Undefined,
            FfiValue::Passthrough(Box::new(FfiValue::UInt32(1))),
        ] {
            assert_eq!(FieldType::of(&untyped), None);
            assert!(FieldType::all().iter().all(|ty| !ty.holds(&untyped)));
        }
    }

    /// `admits` is `IndexSpec::supports` stated over types: the two tables
    /// cannot disagree about any scalar, and a composite admits nothing.
    #[test]
    fn admits_agrees_with_supports_for_every_scalar_type() {
        for ty in FieldType::all() {
            for kind in kinds() {
                match Scalar::of(&sample(ty), &kind) {
                    Ok(scalar) => {
                        assert_eq!(ty.admits(&kind), kind.supports(&scalar), "{ty} and {kind}")
                    }
                    Err(_) => assert!(!ty.admits(&kind), "{ty} is not a scalar"),
                }
            }
        }
        // Spelled out, so the table reads without the cross-check.
        assert!(FieldType::UInt64.admits(&IndexSpec::Equality));
        assert!(!FieldType::Float64.admits(&IndexSpec::Equality));
        assert!(!FieldType::Bool.admits(&IndexSpec::Equality));
        assert!(FieldType::String.admits(&IndexSpec::Match(MatchOptions::default())));
        assert!(!FieldType::Bytes.admits(&IndexSpec::Match(MatchOptions::default())));
        assert!(FieldType::Float64.admits(&IndexSpec::Ore));
        assert!(!FieldType::Object.admits(&IndexSpec::Ope));
        assert!(!FieldType::Array.admits(&IndexSpec::Ore));
    }

    /// A match index's options are not part of what it applies to: text
    /// admits it under any options, and nothing else does.
    #[test]
    fn admits_ignores_match_options() {
        let wide = IndexSpec::Match(MatchOptions {
            tokenizer: Tokenizer::Standard,
            downcase: false,
            k: 6,
            m: 1024,
        });
        for ty in FieldType::all() {
            assert_eq!(
                ty.admits(&wide),
                ty == FieldType::String,
                "{ty} admits a non-default match exactly when it is text"
            );
        }
    }

    fn read(ty: FieldType, value: FfiValue) -> Option<FfiValue> {
        ty.read(value).ok()
    }

    #[test]
    fn read_returns_a_value_of_the_type_as_it_is() {
        for ty in FieldType::all() {
            let read = read(ty, sample(ty)).expect("its own type");
            assert!(ty.holds(&read));
        }
        assert!(
            matches!(read(FieldType::Float32, FfiValue::Float32(f32::NAN)), Some(FfiValue::Float32(f)) if f.is_nan())
        );
    }

    #[test]
    fn read_converts_an_exact_number_to_an_integer_type() {
        // Every numeric variant is a source, each read into another width.
        assert!(matches!(
            read(FieldType::Int64, FfiValue::Int32(-5)),
            Some(FfiValue::Int64(-5))
        ));
        assert!(matches!(
            read(FieldType::Int32, FfiValue::UInt64(5)),
            Some(FfiValue::Int32(5))
        ));
        assert!(
            matches!(read(FieldType::Float64, FfiValue::Int32(-5)), Some(FfiValue::Float64(f)) if f == -5.0)
        );
        // A JavaScript number is a float.
        assert!(matches!(
            read(FieldType::UInt64, FfiValue::Float64(34.0)),
            Some(FfiValue::UInt64(34))
        ));
        assert!(matches!(
            read(FieldType::Int32, FfiValue::Float32(-2.0)),
            Some(FfiValue::Int32(-2))
        ));
        assert!(matches!(
            read(FieldType::Int64, FfiValue::UInt32(7)),
            Some(FfiValue::Int64(7))
        ));
        assert!(matches!(
            read(FieldType::UInt32, FfiValue::Int64(7)),
            Some(FfiValue::UInt32(7))
        ));
        assert!(matches!(
            read(FieldType::Int64, FfiValue::Float64(-0.0)),
            Some(FfiValue::Int64(0))
        ));
        assert!(matches!(
            read(FieldType::UInt64, FfiValue::Int64(i64::MAX)),
            Some(FfiValue::UInt64(v)) if v == i64::MAX as u64
        ));
        assert!(matches!(
            read(FieldType::Int32, FfiValue::Int64(i32::MIN.into())),
            Some(FfiValue::Int32(i32::MIN))
        ));
        assert!(matches!(
            read(FieldType::UInt32, FfiValue::UInt64(u32::MAX.into())),
            Some(FfiValue::UInt32(u32::MAX))
        ));
    }

    #[test]
    fn read_refuses_an_inexact_or_out_of_range_integer() {
        let refused = [
            (FieldType::UInt64, FfiValue::Float64(34.5)),
            (FieldType::Int64, FfiValue::Float64(f64::NAN)),
            (FieldType::Int64, FfiValue::Float64(f64::INFINITY)),
            (FieldType::Int64, FfiValue::Float64(1e30)),
            (FieldType::UInt64, FfiValue::Int64(-1)),
            (FieldType::UInt32, FfiValue::UInt64(u64::from(u32::MAX) + 1)),
            (FieldType::Int32, FfiValue::Int64(i64::from(i32::MAX) + 1)),
            (FieldType::Int32, FfiValue::Int64(i64::from(i32::MIN) - 1)),
            (FieldType::Int64, FfiValue::UInt64(u64::MAX)),
        ];
        for (at, (ty, value)) in refused.into_iter().enumerate() {
            assert!(
                matches!(ty.read(value), Err(Error::Source)),
                "case {at}, as {ty}"
            );
        }
    }

    #[test]
    fn read_converts_an_exactly_representable_number_to_a_float_type() {
        assert!(
            matches!(read(FieldType::Float64, FfiValue::Int64(34)), Some(FfiValue::Float64(f)) if f == 34.0)
        );
        assert!(
            matches!(read(FieldType::Float64, FfiValue::Float32(1.5)), Some(FfiValue::Float64(f)) if f == 1.5)
        );
        assert!(
            matches!(read(FieldType::Float32, FfiValue::Float64(1.5)), Some(FfiValue::Float32(f)) if f == 1.5)
        );
        assert!(
            matches!(read(FieldType::Float32, FfiValue::UInt32(16_777_216)), Some(FfiValue::Float32(f)) if f == 16_777_216.0)
        );
        assert!(matches!(
            read(FieldType::Float64, FfiValue::UInt64(1 << 53)),
            Some(FfiValue::Float64(f)) if f == 9_007_199_254_740_992.0
        ));
    }

    #[test]
    fn read_refuses_a_number_a_float_type_would_round() {
        let refused = [
            (FieldType::Float64, FfiValue::UInt64((1 << 53) + 1)),
            (FieldType::Float64, FfiValue::UInt64(u64::MAX)),
            (FieldType::Float32, FfiValue::UInt32(16_777_217)),
            (FieldType::Float32, FfiValue::Float64(0.1)),
            (FieldType::Float32, FfiValue::Float64(f64::NAN)),
        ];
        for (at, (ty, value)) in refused.into_iter().enumerate() {
            assert!(
                matches!(ty.read(value), Err(Error::Source)),
                "case {at}, as {ty}"
            );
        }
    }

    #[test]
    fn read_never_converts_across_kinds() {
        let refused = [
            (FieldType::UInt64, FfiValue::String("34".into())),
            (FieldType::String, FfiValue::UInt64(34)),
            (FieldType::Bool, FfiValue::UInt32(1)),
            (FieldType::UInt32, FfiValue::Bool(true)),
            (FieldType::Bytes, FfiValue::String("ab".into())),
            (
                FieldType::String,
                FfiValue::Bytes(Protected::new(b"ab".to_vec())),
            ),
            (FieldType::Array, FfiValue::Object(vec![])),
            (FieldType::Object, FfiValue::Array(vec![])),
            (FieldType::UInt32, FfiValue::Null),
            (FieldType::Bool, FfiValue::Float64(1.0)),
        ];
        for (at, (ty, value)) in refused.into_iter().enumerate() {
            assert!(
                matches!(ty.read(value), Err(Error::Source)),
                "case {at}, as {ty}"
            );
        }
    }
}
