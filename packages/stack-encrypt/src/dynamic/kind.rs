//! What a plan's declared field type means to the engine.
//!
//! A typed host knows what `34` is: a Rust `u32`, a Go `int64`. A dynamically
//! typed host (JavaScript, PHP, Ruby) does not, and index semantics depend on
//! it: an ORE term of the integer `34` and of the float `34.0` differ, a
//! JavaScript number is a float, and match is defined over text alone. So a
//! plan field may say what its values are, in its `"type"` key.
//!
//! The vocabulary is vitaminc's, not this crate's: a declared type is a
//! [`ValueKind`] (`vitaminc_aead_value::ValueKind`, re-exported here), whose
//! [`name`](ValueKind::name)s (`"uint64"`, `"string"`, …, `"array"`,
//! `"object"`) are frozen wire format beside vitaminc's tag table, and whose
//! [`holds`](ValueKind::holds) and [`FfiValue::kind`] say whether a value is
//! of a kind. What vitaminc deliberately leaves to the declaring layer is the
//! two rules this module adds:
//!
//! - [`admits`]: which indexes a kind is defined for, so a plan asking for
//!   match on an integer or equality on a float is refused when it is built;
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
//! A field with no `"type"` is dispatched on each value's own tag. That is
//! transitional; see [`record::plan`](super::record::plan()).
use vitaminc_aead_value::{FfiValue, ValueKind};

use super::Error;
use crate::target::IndexSpec;

/// Whether the scheme defines an `index` term for values of `kind`.
///
/// The same table as [`IndexSpec::supports`], stated over kinds instead of
/// values, so a plan can be refused when it is built rather than when its
/// first value arrives: equality over every integer, text and bytes (no
/// floats, no booleans); match over text alone; ORE and OPE over every
/// scalar. A composite (`array`, `object`) has no term. Only the index's
/// kind matters: a match index's options do not change what it applies to.
///
/// ```
/// use stack_encrypt::dynamic::{admits, ValueKind};
/// use stack_encrypt::target::IndexSpec;
///
/// assert!(admits(ValueKind::UInt64, &IndexSpec::Equality));
/// assert!(!admits(ValueKind::Float64, &IndexSpec::Equality));
/// assert!(!admits(ValueKind::Object, &IndexSpec::Ore));
/// ```
pub fn admits(kind: ValueKind, index: &IndexSpec) -> bool {
    use ValueKind::*;
    match index {
        IndexSpec::Equality => matches!(kind, Int32 | Int64 | UInt32 | UInt64 | String | Bytes),
        IndexSpec::Match(_) => kind == String,
        IndexSpec::Ore | IndexSpec::Ope => !matches!(kind, Array | Object),
    }
}

/// Read a query value as `kind`.
///
/// A value already of this kind is returned as it is. A number of another
/// width or kind is converted when the conversion is exact: an integer in
/// range, or a float with no fractional part in range, for an integer kind
/// (a JavaScript `34` arrives as a float); an integer or float the target
/// float kind represents exactly, for a float kind. A NaN is never
/// converted, in either float direction: it equals nothing, so no
/// conversion of it is exact. Nothing else converts: a string is never
/// parsed as a number, and a number never becomes a string.
///
/// This is for a query: what a host hands over to search with. A value
/// being sealed is not converted; it must already be of the field's kind,
/// and is refused otherwise.
///
/// **The engine does not call this.** [`term`](super::term()) takes a
/// [`Scalar`](super::Scalar) and an [`IndexSpec`] and never sees the field's
/// declared kind, so a binding deriving a query term for a typed field must
/// call `read` first, with [`FieldPlan::field_type`](super::FieldPlan::field_type).
/// One that skips it hands `Float64(34.0)` to a `uint64` field, derives a
/// float term where the stored one is the `u64` term, and matches nothing,
/// with no error. Wiring this into the plan's query path
/// (`query(v).using(&plan)`) is tracked in #1057.
///
/// ```
/// use stack_encrypt::dynamic::{read, FfiValue, ValueKind};
///
/// // A JavaScript number is a float; against a `uint64` field it is 34.
/// let value = read(ValueKind::UInt64, FfiValue::Float64(34.0))?;
/// assert!(matches!(value, FfiValue::UInt64(34)));
/// assert!(read(ValueKind::UInt64, FfiValue::Float64(34.5)).is_err());
/// # Ok::<(), stack_encrypt::dynamic::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Source`] if the value cannot be read as `kind` exactly.
pub fn read(kind: ValueKind, value: FfiValue) -> Result<FfiValue, Error> {
    if kind.holds(&value) {
        return Ok(value);
    }
    let number = Number::of(&value).ok_or(Error::Source)?;
    let read = match kind {
        ValueKind::Int32 => number
            .integer()
            .and_then(|i| i32::try_from(i).ok())
            .map(FfiValue::Int32),
        ValueKind::Int64 => number
            .integer()
            .and_then(|i| i64::try_from(i).ok())
            .map(FfiValue::Int64),
        ValueKind::UInt32 => number
            .integer()
            .and_then(|i| u32::try_from(i).ok())
            .map(FfiValue::UInt32),
        ValueKind::UInt64 => number
            .integer()
            .and_then(|i| u64::try_from(i).ok())
            .map(FfiValue::UInt64),
        ValueKind::Float64 => number.exact_f64().map(FfiValue::Float64),
        ValueKind::Float32 => number.exact_f32().map(FfiValue::Float32),
        _ => None,
    };
    read.ok_or(Error::Source)
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
    /// conversion does not round, or a float that is not a NaN. A NaN is
    /// never exact, because it does not equal itself.
    fn exact_f64(self) -> Option<f64> {
        match self {
            Number::Float(f) => (!f.is_nan()).then_some(f),
            Number::Integer(i) => {
                let f = i as f64;
                (f as i128 == i).then_some(f)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::Scalar;
    use crate::sem::{MatchOptions, Tokenizer};
    use vitaminc_protected::Protected;

    // What a kind is, its name and its tags, and which values it holds are
    // vitaminc's to test (`ValueKind`). These test the two rules this crate
    // adds over the vocabulary.

    /// One value of every kind.
    fn sample(kind: ValueKind) -> FfiValue {
        match kind {
            ValueKind::Bool => FfiValue::Bool(true),
            ValueKind::Int32 => FfiValue::Int32(-3),
            ValueKind::Int64 => FfiValue::Int64(-4),
            ValueKind::UInt32 => FfiValue::UInt32(34),
            ValueKind::UInt64 => FfiValue::UInt64(35),
            ValueKind::Float32 => FfiValue::Float32(1.5),
            ValueKind::Float64 => FfiValue::Float64(2.5),
            ValueKind::String => FfiValue::String("alice".into()),
            ValueKind::Bytes => FfiValue::Bytes(Protected::new(b"ab".to_vec())),
            ValueKind::Array => FfiValue::Array(vec![FfiValue::UInt32(1)]),
            ValueKind::Object => FfiValue::Object(vec![("k".to_string(), FfiValue::UInt32(1))]),
        }
    }

    fn indexes() -> [IndexSpec; 4] {
        [
            IndexSpec::Equality,
            IndexSpec::Match(MatchOptions::default()),
            IndexSpec::Ore,
            IndexSpec::Ope,
        ]
    }

    /// `admits` is `IndexSpec::supports` stated over kinds: the two tables
    /// cannot disagree about any scalar, and a composite admits nothing.
    #[test]
    fn admits_agrees_with_supports_for_every_scalar_kind() {
        for kind in ValueKind::ALL {
            for index in indexes() {
                match Scalar::of(&sample(kind), &index) {
                    Ok(scalar) => {
                        assert_eq!(
                            admits(kind, &index),
                            index.supports(&scalar),
                            "{kind} and {index}"
                        )
                    }
                    Err(_) => assert!(!admits(kind, &index), "{kind} is not a scalar"),
                }
            }
        }
        // Spelled out, so the table reads without the cross-check.
        assert!(admits(ValueKind::UInt64, &IndexSpec::Equality));
        assert!(!admits(ValueKind::Float64, &IndexSpec::Equality));
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
        assert!(!admits(ValueKind::Object, &IndexSpec::Ope));
        assert!(!admits(ValueKind::Array, &IndexSpec::Ore));
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
        for kind in ValueKind::ALL {
            assert_eq!(
                admits(kind, &wide),
                kind == ValueKind::String,
                "{kind} admits a non-default match exactly when it is text"
            );
        }
    }

    fn read_ok(kind: ValueKind, value: FfiValue) -> Option<FfiValue> {
        read(kind, value).ok()
    }

    #[test]
    fn read_returns_a_value_of_the_kind_as_it_is() {
        for kind in ValueKind::ALL {
            let read = read_ok(kind, sample(kind)).expect("its own kind");
            assert!(kind.holds(&read));
        }
        // Already of the kind: returned as it is, not converted, so a NaN
        // the host sent as the field's own float kind is not refused here.
        assert!(
            matches!(read_ok(ValueKind::Float32, FfiValue::Float32(f32::NAN)), Some(FfiValue::Float32(f)) if f.is_nan())
        );
        assert!(
            matches!(read_ok(ValueKind::Float64, FfiValue::Float64(f64::NAN)), Some(FfiValue::Float64(f)) if f.is_nan())
        );
    }

    #[test]
    fn read_converts_an_exact_number_to_an_integer_kind() {
        // Every numeric variant is a source, each read into another width.
        assert!(matches!(
            read_ok(ValueKind::Int64, FfiValue::Int32(-5)),
            Some(FfiValue::Int64(-5))
        ));
        assert!(matches!(
            read_ok(ValueKind::Int32, FfiValue::UInt64(5)),
            Some(FfiValue::Int32(5))
        ));
        assert!(
            matches!(read_ok(ValueKind::Float64, FfiValue::Int32(-5)), Some(FfiValue::Float64(f)) if f == -5.0)
        );
        // A JavaScript number is a float.
        assert!(matches!(
            read_ok(ValueKind::UInt64, FfiValue::Float64(34.0)),
            Some(FfiValue::UInt64(34))
        ));
        assert!(matches!(
            read_ok(ValueKind::Int32, FfiValue::Float32(-2.0)),
            Some(FfiValue::Int32(-2))
        ));
        assert!(matches!(
            read_ok(ValueKind::Int64, FfiValue::UInt32(7)),
            Some(FfiValue::Int64(7))
        ));
        assert!(matches!(
            read_ok(ValueKind::UInt32, FfiValue::Int64(7)),
            Some(FfiValue::UInt32(7))
        ));
        assert!(matches!(
            read_ok(ValueKind::Int64, FfiValue::Float64(-0.0)),
            Some(FfiValue::Int64(0))
        ));
        assert!(matches!(
            read_ok(ValueKind::UInt64, FfiValue::Int64(i64::MAX)),
            Some(FfiValue::UInt64(v)) if v == i64::MAX as u64
        ));
        assert!(matches!(
            read_ok(ValueKind::Int32, FfiValue::Int64(i32::MIN.into())),
            Some(FfiValue::Int32(i32::MIN))
        ));
        assert!(matches!(
            read_ok(ValueKind::UInt32, FfiValue::UInt64(u32::MAX.into())),
            Some(FfiValue::UInt32(u32::MAX))
        ));
    }

    #[test]
    fn read_refuses_an_inexact_or_out_of_range_integer() {
        let refused = [
            (ValueKind::UInt64, FfiValue::Float64(34.5)),
            (ValueKind::Int64, FfiValue::Float64(f64::NAN)),
            (ValueKind::Int64, FfiValue::Float64(f64::INFINITY)),
            (ValueKind::Int64, FfiValue::Float64(1e30)),
            (ValueKind::UInt64, FfiValue::Int64(-1)),
            (ValueKind::UInt32, FfiValue::UInt64(u64::from(u32::MAX) + 1)),
            (ValueKind::Int32, FfiValue::Int64(i64::from(i32::MAX) + 1)),
            (ValueKind::Int32, FfiValue::Int64(i64::from(i32::MIN) - 1)),
            (ValueKind::Int64, FfiValue::UInt64(u64::MAX)),
        ];
        for (at, (kind, value)) in refused.into_iter().enumerate() {
            assert!(
                matches!(read(kind, value), Err(Error::Source)),
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
        assert!(read_ok(ValueKind::Int64, FfiValue::Float64(two_63)).is_none());
        assert!(matches!(
            read_ok(ValueKind::Int64, FfiValue::Float64(-two_63)),
            Some(FfiValue::Int64(i64::MIN))
        ));
        assert!(read_ok(ValueKind::UInt64, FfiValue::Float64(two_64)).is_none());
        assert!(matches!(
            read_ok(
                ValueKind::UInt64,
                FfiValue::Float64(18_446_744_073_709_549_568.0)
            ),
            Some(FfiValue::UInt64(18_446_744_073_709_549_568))
        ));
        assert!(read_ok(ValueKind::UInt32, FfiValue::Float64(4_294_967_296.0)).is_none());
        assert!(matches!(
            read_ok(ValueKind::UInt32, FfiValue::Float64(4_294_967_295.0)),
            Some(FfiValue::UInt32(u32::MAX))
        ));
    }

    #[test]
    fn read_converts_an_exactly_representable_number_to_a_float_kind() {
        assert!(
            matches!(read_ok(ValueKind::Float64, FfiValue::Int64(34)), Some(FfiValue::Float64(f)) if f == 34.0)
        );
        assert!(
            matches!(read_ok(ValueKind::Float64, FfiValue::Float32(1.5)), Some(FfiValue::Float64(f)) if f == 1.5)
        );
        assert!(
            matches!(read_ok(ValueKind::Float32, FfiValue::Float64(1.5)), Some(FfiValue::Float32(f)) if f == 1.5)
        );
        assert!(
            matches!(read_ok(ValueKind::Float32, FfiValue::UInt32(16_777_216)), Some(FfiValue::Float32(f)) if f == 16_777_216.0)
        );
        assert!(matches!(
            read_ok(ValueKind::Float64, FfiValue::UInt64(1 << 53)),
            Some(FfiValue::Float64(f)) if f == 9_007_199_254_740_992.0
        ));
    }

    #[test]
    fn read_refuses_a_number_a_float_kind_would_round() {
        let refused = [
            (ValueKind::Float64, FfiValue::UInt64((1 << 53) + 1)),
            (ValueKind::Float64, FfiValue::UInt64(u64::MAX)),
            (ValueKind::Float32, FfiValue::UInt32(16_777_217)),
            (ValueKind::Float32, FfiValue::Float64(0.1)),
        ];
        for (at, (kind, value)) in refused.into_iter().enumerate() {
            assert!(
                matches!(read(kind, value), Err(Error::Source)),
                "case {at}, as {kind}"
            );
        }
    }

    /// A NaN converts in neither float direction: it equals nothing, so no
    /// conversion of it is exact, and a query for one could match nothing.
    #[test]
    fn read_refuses_a_nan_in_both_float_directions() {
        assert!(matches!(
            read(ValueKind::Float32, FfiValue::Float64(f64::NAN)),
            Err(Error::Source)
        ));
        assert!(matches!(
            read(ValueKind::Float64, FfiValue::Float32(f32::NAN)),
            Err(Error::Source)
        ));
    }

    #[test]
    fn read_never_converts_across_kinds() {
        let refused = [
            (ValueKind::UInt64, FfiValue::String("34".into())),
            (ValueKind::String, FfiValue::UInt64(34)),
            (ValueKind::Bool, FfiValue::UInt32(1)),
            (ValueKind::UInt32, FfiValue::Bool(true)),
            (ValueKind::Bytes, FfiValue::String("ab".into())),
            (
                ValueKind::String,
                FfiValue::Bytes(Protected::new(b"ab".to_vec())),
            ),
            (ValueKind::Array, FfiValue::Object(vec![])),
            (ValueKind::Object, FfiValue::Array(vec![])),
            (ValueKind::UInt32, FfiValue::Null),
            (ValueKind::Bool, FfiValue::Float64(1.0)),
        ];
        for (at, (kind, value)) in refused.into_iter().enumerate() {
            assert!(
                matches!(read(kind, value), Err(Error::Source)),
                "case {at}, as {kind}"
            );
        }
    }
}
