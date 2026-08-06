use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use cipherstash_client::encryption::{Plaintext, TryFromPlaintext, TypeParseError};
use cipherstash_client::schema::ColumnType;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use vitaminc::protected::OpaqueDebug;

/// The single-key wire form a JS `bigint` crosses the FFI boundary in:
/// `{"__protect_ffi_bigint__": "<decimal string>"}`.
///
/// A JS `bigint` cannot cross either serde-based boundary natively:
///
/// - Neon extracts every options object with `neon::types::extract::Json`,
///   which runs `JSON.stringify` on the JS side — and `JSON.stringify`
///   throws a `TypeError` on any BigInt.
/// - serde-wasm-bindgen's `deserialize_any` visits BOTH a JS BigInt and a
///   safe-integer JS Number as `visit_i64`, so after `#[serde(untagged)]`
///   buffering the two are indistinguishable (and a plain `i64` variant
///   would shadow `Number`).
///
/// So the boundaries encode `typeof v === 'bigint'` values into this tagged
/// map before serde ever sees them (`src/index.cts` for Neon,
/// `encode_plaintext` in `wasm.rs` for wasm), and the [`bigint_wire`]
/// serde module below decodes exactly this shape into
/// [`JsPlaintext::BigInt`]. Both encoders bounds-check against `i64` first
/// and raise a clear error, so an out-of-range value never reaches serde
/// through the public API.
// Referenced by the wasm boundary encoder (`wasm.rs`) and tests; the Neon
// boundary builds the tagged form in TypeScript (`src/index.cts`), so the
// non-wasm cdylib itself never reads the const.
#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
pub(crate) const BIGINT_WIRE_KEY: &str = "__protect_ffi_bigint__";

#[derive(Deserialize, Serialize, OpaqueDebug, PartialEq)]
#[serde(untagged)]
pub(crate) enum JsPlaintext {
    // `String` is first so that RFC 3339 strings (as produced by
    // `Date.prototype.toJSON()` on the JS side) deserialize as strings, not
    // as `Date`. `to_plaintext_with_type` parses them into `Plaintext::Date` /
    // `Plaintext::Timestamp` when the column's `cast_as` requires it.
    String(String),
    Number(f64),
    Boolean(bool),
    // A JS `bigint`, carried on the wire as the tagged single-key map
    // documented on [`BIGINT_WIRE_KEY`]. Must precede `JsonB`, which
    // accepts any map. Bounds: full i64 — the boundary encoders reject
    // anything outside `i64::MIN..=i64::MAX` before serde runs. If the
    // tagged shape carries a non-i64 string anyway (only reachable by
    // bypassing the public wrappers), this variant fails to match and the
    // value falls through to `JsonB`, where `to_plaintext_with_type`
    // rejects it as a Json → numeric-column mismatch.
    BigInt(#[serde(with = "bigint_wire")] i64),
    // Produced only on the decrypt path from `Plaintext::NaiveDate` /
    // `Plaintext::Timestamp`. Serializes as a plain RFC 3339 string via
    // chrono's default impl, so the JS side receives a string and can call
    // `new Date(...)` if needed.
    Date(DateTime<Utc>),
    JsonB(serde_json::Value),
}

/// Serde (de)serialization of the [`BIGINT_WIRE_KEY`] tagged map form.
///
/// The value is a decimal *string*, not a JSON number: the Neon boundary
/// builds the map in JavaScript, where an i64-magnitude number literal
/// would already have lost precision beyond 2^53.
mod bigint_wire {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Tagged {
        #[serde(rename = "__protect_ffi_bigint__")]
        value: String,
    }

    pub(super) fn serialize<S: Serializer>(v: &i64, serializer: S) -> Result<S::Ok, S::Error> {
        Tagged {
            value: v.to_string(),
        }
        .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
        let tagged = Tagged::deserialize(deserializer)?;
        tagged.value.parse::<i64>().map_err(|_| {
            // Note: inside #[serde(untagged)] this error is swallowed and
            // the value falls through to the JsonB variant — see the
            // BigInt variant docs. The message still helps direct
            // (non-untagged) deserialization and tests.
            serde::de::Error::custom(
                "BigInt wire value is not a 64-bit signed integer \
                 (-9223372036854775808..=9223372036854775807)",
            )
        })
    }
}

impl From<JsPlaintext> for Plaintext {
    fn from(value: JsPlaintext) -> Self {
        match value {
            JsPlaintext::String(s) => Plaintext::Text(Some(s)),
            JsPlaintext::Number(n) => Plaintext::Float(Some(n)),
            JsPlaintext::Boolean(b) => Plaintext::Boolean(Some(b)),
            JsPlaintext::BigInt(v) => Plaintext::BigInt(Some(v)),
            JsPlaintext::JsonB(j) => Plaintext::Json(Some(j)),
            JsPlaintext::Date(dt) => Plaintext::Timestamp(Some(dt)),
        }
    }
}

impl TryFrom<Plaintext> for JsPlaintext {
    type Error = TypeParseError;

    fn try_from(value: Plaintext) -> Result<Self, Self::Error> {
        match value {
            v @ Plaintext::Text(Some(_)) => String::try_from_plaintext(v).map(JsPlaintext::String),
            v @ Plaintext::Json(Some(_)) => {
                serde_json::Value::try_from_plaintext(v).map(JsPlaintext::JsonB)
            }
            // BigInt decrypts to a JS `bigint` — ALWAYS, even for values
            // that would fit in a JS number. (Breaking change: prior
            // releases lowered to `Number(n as f64)`, silently losing
            // precision beyond Number.MAX_SAFE_INTEGER, 2^53 - 1.)
            Plaintext::BigInt(Some(n)) => Ok(JsPlaintext::BigInt(n)),
            Plaintext::Int(Some(n)) => Ok(JsPlaintext::Number(n as f64)),
            Plaintext::SmallInt(Some(n)) => Ok(JsPlaintext::Number(n as f64)),
            // Decimal → f64 carries the same caveat as BigInt above: values
            // beyond f64's exact range lose precision as a JS number.
            Plaintext::Decimal(Some(d)) => rust_decimal::prelude::ToPrimitive::to_f64(&d)
                .map(JsPlaintext::Number)
                .ok_or_else(|| TypeParseError("Decimal does not fit in an f64".to_string())),
            Plaintext::Float(Some(n)) => Ok(JsPlaintext::Number(n)),
            Plaintext::Boolean(Some(b)) => Ok(JsPlaintext::Boolean(b)),
            Plaintext::NaiveDate(Some(nd)) => {
                // Promote date-only to midnight UTC so the JS-visible form is a
                // full timestamp.
                let dt =
                    Utc.from_utc_datetime(&nd.and_hms_opt(0, 0, 0).expect("00:00:00 is valid"));
                Ok(JsPlaintext::Date(dt))
            }
            Plaintext::Timestamp(Some(ts)) => Ok(JsPlaintext::Date(ts)),
            _ => Err(TypeParseError("Unsupported type".to_string())),
        }
    }
}

impl JsPlaintext {
    /// Convert JsPlaintext to Plaintext based on a target ColumnType.
    ///
    /// The storage type is driven by `cast_as`, not by the input variant.
    /// A JS Date (arriving as an RFC 3339 string via `Date.prototype.toJSON()`
    /// or as a `JsPlaintext::Date` produced by a prior decrypt) can be stored
    /// as a day-only `Date`, a full `Timestamp`, or an ISO 8601 string.
    pub fn to_plaintext_with_type(
        &self,
        column_type: ColumnType,
    ) -> Result<Plaintext, TypeParseError> {
        match (self, column_type) {
            // String conversions - Text, Date, and Timestamp (the latter two parse).
            (JsPlaintext::String(s), ColumnType::Text) => Ok(Plaintext::Text(Some(s.clone()))),
            (JsPlaintext::String(s), ColumnType::Date) => parse_naive_date(s)
                .map(|d| Plaintext::NaiveDate(Some(d)))
                .map_err(|e| TypeParseError(format!("Cannot parse Date: {}", e))),
            (JsPlaintext::String(s), ColumnType::Timestamp) => parse_timestamp(s)
                .map(|t| Plaintext::Timestamp(Some(t)))
                .map_err(|e| TypeParseError(format!("Cannot parse Timestamp: {}", e))),

            // Number conversions. Float stores the f64 verbatim; every other
            // numeric target must represent the value exactly or error — a
            // lossy cast would silently corrupt the stored value and the
            // index terms derived from it.
            (JsPlaintext::Number(n), ColumnType::Float) => Ok(Plaintext::Float(Some(*n))),
            (JsPlaintext::Number(n), ColumnType::Decimal) => Decimal::try_from(*n)
                .map(|d| Plaintext::Decimal(Some(d)))
                .map_err(|e| TypeParseError(format!("Cannot convert number to Decimal: {}", e))),
            (JsPlaintext::Number(n), ColumnType::BigInt) => {
                f64_to_exact_int(*n, ColumnType::BigInt).map(|v| Plaintext::BigInt(Some(v)))
            }
            (JsPlaintext::Number(n), ColumnType::Int) => {
                f64_to_exact_int(*n, ColumnType::Int).map(|v| Plaintext::Int(Some(v)))
            }
            (JsPlaintext::Number(n), ColumnType::SmallInt) => {
                f64_to_exact_int(*n, ColumnType::SmallInt).map(|v| Plaintext::SmallInt(Some(v)))
            }
            (JsPlaintext::Number(n), ColumnType::BigUInt) => {
                if *n < 0.0 {
                    Err(TypeParseError(
                        "Cannot convert negative number to BigUInt".to_string(),
                    ))
                } else {
                    f64_to_exact_int(*n, ColumnType::BigUInt).map(|v| Plaintext::BigUInt(Some(v)))
                }
            }

            // BigInt conversions. The i64 arrives exact (the boundary
            // already enforced i64 bounds), so BigInt stores it verbatim;
            // the narrower integer targets and BigUInt are range-checked
            // and error instead of truncating (same policy as the Number
            // arms above); Decimal holds any i64 exactly. Float is NOT a
            // valid target — f64 loses precision beyond 2^53, and a lossy
            // cast would corrupt both the stored value and the index terms
            // derived from it. Errors deliberately do not echo the value:
            // it is plaintext being encrypted.
            (JsPlaintext::BigInt(v), ColumnType::BigInt) => Ok(Plaintext::BigInt(Some(*v))),
            (JsPlaintext::BigInt(v), ColumnType::Int) => i32::try_from(*v)
                .map(|v| Plaintext::Int(Some(v)))
                .map_err(|_| bigint_out_of_range(ColumnType::Int)),
            (JsPlaintext::BigInt(v), ColumnType::SmallInt) => i16::try_from(*v)
                .map(|v| Plaintext::SmallInt(Some(v)))
                .map_err(|_| bigint_out_of_range(ColumnType::SmallInt)),
            (JsPlaintext::BigInt(v), ColumnType::BigUInt) => u64::try_from(*v)
                .map(|v| Plaintext::BigUInt(Some(v)))
                .map_err(|_| {
                    TypeParseError("Cannot convert negative BigInt to BigUInt".to_string())
                }),
            (JsPlaintext::BigInt(v), ColumnType::Decimal) => {
                Ok(Plaintext::Decimal(Some(Decimal::from(*v))))
            }

            // Boolean conversions - only allow to Boolean
            (JsPlaintext::Boolean(b), ColumnType::Boolean) => Ok(Plaintext::Boolean(Some(*b))),

            // Json conversions - only allow to Json
            (JsPlaintext::JsonB(j), ColumnType::Json) => Ok(Plaintext::Json(Some(j.clone()))),

            // Date conversions: the value is a full UTC timestamp; cast_as picks
            // the storage form.
            (JsPlaintext::Date(dt), ColumnType::Date) => {
                Ok(Plaintext::NaiveDate(Some(dt.date_naive())))
            }
            (JsPlaintext::Date(dt), ColumnType::Timestamp) => Ok(Plaintext::Timestamp(Some(*dt))),
            (JsPlaintext::Date(dt), ColumnType::Text) => Ok(Plaintext::Text(Some(dt.to_rfc3339()))),

            // All other conversions are not allowed - provide helpful error message
            (js_type, col_type) => {
                let valid_targets = match js_type {
                    JsPlaintext::String(_) => {
                        "Text (string columns), Date, Timestamp (ISO 8601 strings)"
                    }
                    JsPlaintext::Number(_) => {
                        "Float, BigInt, Int, SmallInt, BigUInt, Decimal (numeric columns)"
                    }
                    JsPlaintext::BigInt(_) => {
                        "BigInt, Int, SmallInt, BigUInt, Decimal (integer columns; \
                         Float is excluded because f64 cannot represent every i64)"
                    }
                    JsPlaintext::Boolean(_) => "Boolean (boolean columns)",
                    JsPlaintext::JsonB(_) => "Json (json columns)",
                    JsPlaintext::Date(_) => {
                        "Date, Timestamp (date/timestamp columns), Text (ISO 8601 string)"
                    }
                };
                let type_name = js_plaintext_type_name(js_type);
                Err(TypeParseError(format!(
                    "Cannot convert {} to {:?}. {} values can only be used with: {}. \
                    Check your column's cast_as setting in the encrypt config.",
                    type_name, col_type, type_name, valid_targets
                )))
            }
        }
    }
}

/// Error for a BigInt that does not fit the (narrower) target column type.
/// Mirrors the `f64_to_exact_int` error style — names the target type,
/// never echoes the value (it is plaintext being encrypted).
fn bigint_out_of_range(column_type: ColumnType) -> TypeParseError {
    TypeParseError(format!(
        "Cannot convert BigInt to {:?}: value is out of range",
        column_type
    ))
}

/// Convert a JS number (f64) into an integer type exactly, or error.
///
/// JS has a single number type, so integer columns receive `f64` values. A
/// saturating `as` cast would silently corrupt out-of-range values (e.g.
/// 5_000_000_000 → i32::MAX), map NaN to 0, and drop fractional parts
/// (42.5 → 42) — and the hm/ob index terms would be computed over the
/// corrupted value. Instead, error unless the value is finite, has no
/// fractional component, and fits the target type. The error deliberately
/// does not echo the value: it is plaintext being encrypted.
fn f64_to_exact_int<T: TryFrom<i128>>(
    n: f64,
    column_type: ColumnType,
) -> Result<T, TypeParseError> {
    if !n.is_finite() {
        return Err(TypeParseError(format!(
            "Cannot convert number to {:?}: value must be finite (got NaN or Infinity)",
            column_type
        )));
    }
    if n.fract() != 0.0 {
        return Err(TypeParseError(format!(
            "Cannot convert number to {:?}: value has a fractional component",
            column_type
        )));
    }
    let out_of_range = || {
        TypeParseError(format!(
            "Cannot convert number to {:?}: value is out of range",
            column_type
        ))
    };
    // `n` is finite with no fractional part, so if it lies within i128's
    // range the `as` cast below is exact (every integer-valued f64 with
    // |n| < 2^127 is exactly representable in i128). Note `i128::MAX as f64`
    // rounds up to 2^127, which does NOT fit in i128, hence `>=`.
    if n < i128::MIN as f64 || n >= i128::MAX as f64 {
        return Err(out_of_range());
    }
    T::try_from(n as i128).map_err(|_| out_of_range())
}

/// Parse a string into a `NaiveDate`. Accepts full RFC 3339 timestamps (the
/// common case — JS `Date.prototype.toJSON()` always emits RFC 3339) and also
/// `YYYY-MM-DD` for callers who pass a bare date.
fn parse_naive_date(s: &str) -> Result<NaiveDate, String> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc).date_naive());
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|e| e.to_string())
}

/// Parse a string into a UTC `DateTime`. Accepts RFC 3339 (the format JS `Date`
/// objects produce via `toJSON()`).
fn parse_timestamp(s: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| e.to_string())
}

/// Helper function to get a readable type name for error messages
pub(crate) fn js_plaintext_type_name(js_plaintext: &JsPlaintext) -> &'static str {
    match js_plaintext {
        JsPlaintext::String(_) => "String",
        JsPlaintext::Number(_) => "Number",
        JsPlaintext::Boolean(_) => "Boolean",
        JsPlaintext::BigInt(_) => "BigInt",
        JsPlaintext::JsonB(_) => "Json",
        JsPlaintext::Date(_) => "Date",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js_plaintext::JsPlaintext;

    fn sample_dt() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2025-03-14T12:34:56.789Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    mod js_plaintext_to_plaintext {
        use super::*;

        #[quickcheck]
        fn test_string(s: String) {
            let js_string = JsPlaintext::String(s.clone());
            let plaintext_string: Plaintext = js_string.into();
            assert_eq!(plaintext_string, Plaintext::Text(Some(s)));
        }

        #[quickcheck]
        fn test_number(f: f64) {
            let js_number = JsPlaintext::Number(f);
            let plaintext_number: Plaintext = js_number.into();
            if let Plaintext::Float(Some(n)) = plaintext_number {
                assert_eq!(n.total_cmp(&f), std::cmp::Ordering::Equal);
            } else {
                panic!("Expected Plaintext::Float variant");
            }
        }

        #[quickcheck]
        fn test_boolean(b: bool) {
            let js_boolean = JsPlaintext::Boolean(b);
            let plaintext_boolean: Plaintext = js_boolean.into();
            assert_eq!(plaintext_boolean, Plaintext::Boolean(Some(b)));
        }

        #[test]
        fn test_jsonb() {
            let js_jsonb = JsPlaintext::JsonB(serde_json::json!({"key": "value"}));
            let plaintext_jsonb: Plaintext = js_jsonb.into();
            assert_eq!(
                plaintext_jsonb,
                Plaintext::Json(Some(serde_json::json!({"key": "value"})))
            );
        }

        #[test]
        fn test_date_to_timestamp_plaintext() {
            let t = sample_dt();
            let js = JsPlaintext::Date(t);
            let pt: Plaintext = js.into();
            assert_eq!(
                pt,
                Plaintext::Timestamp(Some(t)),
                "JsPlaintext::Date should map to Plaintext::Timestamp without column-type context"
            );
        }

        #[quickcheck]
        fn test_bigint(i: i64) {
            let pt: Plaintext = JsPlaintext::BigInt(i).into();
            assert_eq!(pt, Plaintext::BigInt(Some(i)));
        }
    }

    /// Deserialization discrimination for the `#[serde(untagged)]` enum. The
    /// variant order is load-bearing: `BigInt` must precede `JsonB` (which
    /// accepts any map), or the tagged bigint wire form would match `JsonB`
    /// first and a bigint plaintext would be silently mis-read as JSON. These
    /// pin the current behaviour so a future reorder fails loudly here.
    mod wire_deserialization {
        use super::*;

        #[test]
        fn tagged_map_deserializes_as_bigint_not_jsonb() {
            let wire = format!(r#"{{"{BIGINT_WIRE_KEY}":"42"}}"#);
            let js: JsPlaintext = serde_json::from_str(&wire).unwrap();
            assert_eq!(
                js,
                JsPlaintext::BigInt(42),
                "the tagged bigint map must match BigInt before the catch-all JsonB variant"
            );
        }

        #[test]
        fn tagged_map_deserializes_at_the_i64_extremes() {
            for v in [i64::MIN, i64::MAX] {
                let wire = format!(r#"{{"{BIGINT_WIRE_KEY}":"{v}"}}"#);
                let js: JsPlaintext = serde_json::from_str(&wire).unwrap();
                assert_eq!(js, JsPlaintext::BigInt(v));
            }
        }

        #[test]
        fn a_plain_object_deserializes_as_jsonb() {
            let js: JsPlaintext = serde_json::from_str(r#"{"key":"value"}"#).unwrap();
            assert_eq!(js, JsPlaintext::JsonB(serde_json::json!({"key": "value"})));
        }

        #[test]
        fn a_non_i64_tagged_value_falls_through_to_jsonb() {
            // The BigInt variant's own docs promise this: a tagged map whose
            // value isn't an i64 decimal string fails the BigInt match and
            // lands in JsonB (where `to_plaintext_with_type` later rejects it
            // as a Json -> numeric-column mismatch).
            let wire = format!(r#"{{"{BIGINT_WIRE_KEY}":"not-a-number"}}"#);
            let js: JsPlaintext = serde_json::from_str(&wire).unwrap();
            assert!(
                matches!(js, JsPlaintext::JsonB(_)),
                "a non-i64 tagged value must fall through to JsonB, got {js:?}"
            );
        }
    }

    mod plaintext_to_js_plaintext {
        use super::*;

        #[quickcheck]
        fn test_utf8str(s: String) {
            let plaintext_string = Plaintext::Text(Some(s.clone()));
            let js_string: JsPlaintext = plaintext_string.try_into().unwrap();
            assert_eq!(js_string, JsPlaintext::String(s));
        }

        #[quickcheck]
        fn test_float(f: f64) {
            let plaintext_number = Plaintext::Float(Some(f));
            let js_number: JsPlaintext = plaintext_number.try_into().unwrap();
            if let JsPlaintext::Number(n) = js_number {
                assert_eq!(n.total_cmp(&f), std::cmp::Ordering::Equal);
            } else {
                panic!("Expected JsPlaintext::Number variant");
            }
        }

        #[quickcheck]
        fn test_boolean(b: bool) {
            let plaintext_boolean = Plaintext::Boolean(Some(b));
            let js_boolean: JsPlaintext = plaintext_boolean.try_into().unwrap();
            assert_eq!(js_boolean, JsPlaintext::Boolean(b));
        }

        #[test]
        fn test_jsonb() {
            let plaintext_jsonb = Plaintext::Json(Some(serde_json::json!({"key": "value"})));
            let js_jsonb: JsPlaintext = plaintext_jsonb.try_into().unwrap();
            assert_eq!(
                js_jsonb,
                JsPlaintext::JsonB(serde_json::json!({"key": "value"}))
            );
        }

        #[quickcheck]
        fn test_bigint_becomes_bigint(i: i64) {
            // BREAKING: cast_as 'bigint' columns decrypt to a JS bigint now
            // (previously Number, which lost precision beyond 2^53).
            let plaintext_bigint = Plaintext::BigInt(Some(i));
            let js: JsPlaintext = plaintext_bigint.try_into().unwrap();
            assert_eq!(js, JsPlaintext::BigInt(i));
        }

        #[test]
        fn test_bigint_extremes_survive_decrypt_exactly() {
            for v in [i64::MIN, i64::MAX, 0, -1] {
                let js: JsPlaintext = Plaintext::BigInt(Some(v)).try_into().unwrap();
                assert_eq!(js, JsPlaintext::BigInt(v));
            }
        }

        #[test]
        fn test_naive_date_becomes_date_at_midnight_utc() {
            let d = NaiveDate::from_ymd_opt(2025, 3, 14).unwrap();
            let pt = Plaintext::NaiveDate(Some(d));
            let js: JsPlaintext = pt.try_into().unwrap();
            let expected = Utc.with_ymd_and_hms(2025, 3, 14, 0, 0, 0).unwrap();
            assert_eq!(
                js,
                JsPlaintext::Date(expected),
                "NaiveDate should promote to midnight UTC on the JS side"
            );
        }

        #[test]
        fn test_timestamp_becomes_date() {
            let t = sample_dt();
            let pt = Plaintext::Timestamp(Some(t));
            let js: JsPlaintext = pt.try_into().unwrap();
            assert_eq!(
                js,
                JsPlaintext::Date(t),
                "Plaintext::Timestamp should map to JsPlaintext::Date preserving the value"
            );
        }

        #[test]
        fn test_int_becomes_number() {
            // cast_as: 'int' stores Plaintext::Int; decrypt must surface it
            // as a JS number (the eql-v3 'count' round-trip).
            let js: JsPlaintext = Plaintext::Int(Some(42)).try_into().unwrap();
            assert_eq!(js, JsPlaintext::Number(42.0));
        }

        #[test]
        fn test_small_int_becomes_number() {
            let js: JsPlaintext = Plaintext::SmallInt(Some(7)).try_into().unwrap();
            assert_eq!(js, JsPlaintext::Number(7.0));
        }

        #[test]
        fn test_decimal_becomes_number() {
            let d = Decimal::try_from(19.99).unwrap();
            let js: JsPlaintext = Plaintext::Decimal(Some(d)).try_into().unwrap();
            assert_eq!(js, JsPlaintext::Number(19.99));
        }

        #[test]
        fn test_unsupported_type() {
            let result: Result<JsPlaintext, TypeParseError> =
                Plaintext::BigUInt(Some(42)).try_into();
            assert!(
                result.is_err(),
                "Plaintext::BigUInt has no JsPlaintext mapping and should fail"
            );
        }
    }

    mod js_plaintext_to_plaintext_with_type {
        use super::*;

        #[test]
        fn test_string_to_utf8str() {
            let js_string = JsPlaintext::String("hello".to_string());
            let result = js_string.to_plaintext_with_type(ColumnType::Text).unwrap();
            assert_eq!(result, Plaintext::Text(Some("hello".to_string())));
        }

        #[test]
        fn test_string_to_int_fails() {
            let js_string = JsPlaintext::String("123".to_string());
            let result = js_string.to_plaintext_with_type(ColumnType::Int);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Cannot convert"));
        }

        #[test]
        fn test_number_to_float() {
            let js_number = JsPlaintext::Number(3.78);
            let result = js_number.to_plaintext_with_type(ColumnType::Float).unwrap();
            assert_eq!(result, Plaintext::Float(Some(3.78)));
        }

        #[test]
        fn test_number_to_decimal() {
            let js_number = JsPlaintext::Number(3.78);
            let result = js_number
                .to_plaintext_with_type(ColumnType::Decimal)
                .unwrap();
            let expected_decimal = Decimal::try_from(3.78).unwrap();
            assert_eq!(result, Plaintext::Decimal(Some(expected_decimal)));
        }

        // A saturating `as` cast on the encrypt path silently corrupts the
        // stored value AND the hm/ob index terms derived from it, so queries
        // match wrong rows with no error. Policy: any JS number that cannot
        // be represented exactly in the target integer type must Err —
        // out-of-range, NaN, Infinity, and fractional values alike.

        /// Assert the conversion fails and the error names the target column
        /// type without echoing the offending value (which is plaintext being
        /// encrypted — a possible secret leak).
        fn assert_truncation_err(n: f64, column_type: ColumnType) {
            let err = JsPlaintext::Number(n)
                .to_plaintext_with_type(column_type)
                .expect_err(&format!(
                    "converting {} to {:?} must fail instead of truncating",
                    n, column_type
                ));
            assert!(
                err.0.contains(&format!("{:?}", column_type)),
                "error should name the target column type {:?}, got: {}",
                column_type,
                err.0
            );
        }

        #[test]
        fn test_in_range_whole_number_to_int() {
            let result = JsPlaintext::Number(42.0)
                .to_plaintext_with_type(ColumnType::Int)
                .unwrap();
            assert_eq!(result, Plaintext::Int(Some(42)));
        }

        #[test]
        fn test_int_boundaries_pass() {
            let max = JsPlaintext::Number(i32::MAX as f64)
                .to_plaintext_with_type(ColumnType::Int)
                .unwrap();
            assert_eq!(max, Plaintext::Int(Some(i32::MAX)));
            let min = JsPlaintext::Number(i32::MIN as f64)
                .to_plaintext_with_type(ColumnType::Int)
                .unwrap();
            assert_eq!(min, Plaintext::Int(Some(i32::MIN)));
        }

        #[test]
        fn test_out_of_range_number_to_int_fails() {
            // The review-comment repro: 5_000_000_000 would silently saturate
            // to i32::MAX (2147483647) with an `as` cast.
            assert_truncation_err(5_000_000_000.0, ColumnType::Int);
            assert_truncation_err((i32::MAX as f64) + 1.0, ColumnType::Int);
            assert_truncation_err((i32::MIN as f64) - 1.0, ColumnType::Int);
        }

        #[test]
        fn test_nan_to_int_fails() {
            // `as` would turn NaN into 0.
            assert_truncation_err(f64::NAN, ColumnType::Int);
        }

        #[test]
        fn test_infinity_to_int_fails() {
            assert_truncation_err(f64::INFINITY, ColumnType::Int);
            assert_truncation_err(f64::NEG_INFINITY, ColumnType::Int);
        }

        #[test]
        fn test_fractional_number_to_int_fails() {
            // 42.5 as i32 == 42 — that is also silent truncation.
            assert_truncation_err(42.5, ColumnType::Int);
        }

        #[test]
        fn test_in_range_whole_number_to_smallint() {
            let result = JsPlaintext::Number(42.0)
                .to_plaintext_with_type(ColumnType::SmallInt)
                .unwrap();
            assert_eq!(result, Plaintext::SmallInt(Some(42)));
        }

        #[test]
        fn test_smallint_boundaries_pass() {
            let max = JsPlaintext::Number(i16::MAX as f64)
                .to_plaintext_with_type(ColumnType::SmallInt)
                .unwrap();
            assert_eq!(max, Plaintext::SmallInt(Some(i16::MAX)));
            let min = JsPlaintext::Number(i16::MIN as f64)
                .to_plaintext_with_type(ColumnType::SmallInt)
                .unwrap();
            assert_eq!(min, Plaintext::SmallInt(Some(i16::MIN)));
        }

        #[test]
        fn test_out_of_range_number_to_smallint_fails() {
            assert_truncation_err(40_000.0, ColumnType::SmallInt);
            assert_truncation_err(-40_000.0, ColumnType::SmallInt);
        }

        #[test]
        fn test_nan_to_smallint_fails() {
            assert_truncation_err(f64::NAN, ColumnType::SmallInt);
        }

        #[test]
        fn test_infinity_to_smallint_fails() {
            assert_truncation_err(f64::INFINITY, ColumnType::SmallInt);
            assert_truncation_err(f64::NEG_INFINITY, ColumnType::SmallInt);
        }

        #[test]
        fn test_fractional_number_to_smallint_fails() {
            assert_truncation_err(42.5, ColumnType::SmallInt);
        }

        #[test]
        fn test_in_range_whole_number_to_bigint() {
            // 2^53 — the largest f64 range where every integer is exact.
            let result = JsPlaintext::Number(9_007_199_254_740_992.0)
                .to_plaintext_with_type(ColumnType::BigInt)
                .unwrap();
            assert_eq!(result, Plaintext::BigInt(Some(9_007_199_254_740_992)));
        }

        #[test]
        fn test_out_of_range_number_to_bigint_fails() {
            // 2^63 is representable as f64 but exceeds i64::MAX; `as` would
            // saturate to i64::MAX. Same for anything larger, e.g. 1e19.
            assert_truncation_err(9_223_372_036_854_775_808.0, ColumnType::BigInt);
            assert_truncation_err(1e19, ColumnType::BigInt);
            assert_truncation_err(-1e19, ColumnType::BigInt);
        }

        #[test]
        fn test_nan_to_bigint_fails() {
            assert_truncation_err(f64::NAN, ColumnType::BigInt);
        }

        #[test]
        fn test_infinity_to_bigint_fails() {
            assert_truncation_err(f64::INFINITY, ColumnType::BigInt);
            assert_truncation_err(f64::NEG_INFINITY, ColumnType::BigInt);
        }

        #[test]
        fn test_fractional_number_to_bigint_fails() {
            assert_truncation_err(42.5, ColumnType::BigInt);
        }

        #[test]
        fn test_number_to_biguint() {
            let js_number = JsPlaintext::Number(42.0);
            let result = js_number
                .to_plaintext_with_type(ColumnType::BigUInt)
                .unwrap();
            assert_eq!(result, Plaintext::BigUInt(Some(42)));
        }

        #[test]
        fn test_negative_number_to_biguint_fails() {
            let js_number = JsPlaintext::Number(-42.0);
            let result = js_number.to_plaintext_with_type(ColumnType::BigUInt);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("negative"));
        }

        #[test]
        fn test_out_of_range_number_to_biguint_fails() {
            // 2^64 is representable as f64 but exceeds u64::MAX; `as` would
            // saturate to u64::MAX.
            assert_truncation_err(18_446_744_073_709_551_616.0, ColumnType::BigUInt);
        }

        #[test]
        fn test_nan_to_biguint_fails() {
            // NaN is not < 0.0, so it sails past the negative guard and `as`
            // would turn it into 0.
            assert_truncation_err(f64::NAN, ColumnType::BigUInt);
        }

        #[test]
        fn test_infinity_to_biguint_fails() {
            assert_truncation_err(f64::INFINITY, ColumnType::BigUInt);
        }

        #[test]
        fn test_fractional_number_to_biguint_fails() {
            assert_truncation_err(42.5, ColumnType::BigUInt);
        }

        #[test]
        fn test_nan_and_infinity_pass_through_to_float() {
            // Float stores the f64 verbatim — no truncation is possible, so
            // the strict-integer policy does not apply.
            let nan = JsPlaintext::Number(f64::NAN)
                .to_plaintext_with_type(ColumnType::Float)
                .unwrap();
            assert!(matches!(nan, Plaintext::Float(Some(n)) if n.is_nan()));
            let inf = JsPlaintext::Number(f64::INFINITY)
                .to_plaintext_with_type(ColumnType::Float)
                .unwrap();
            assert_eq!(inf, Plaintext::Float(Some(f64::INFINITY)));
        }

        #[test]
        fn test_nan_to_decimal_fails() {
            // Decimal::try_from rejects non-finite values — verify rather
            // than assume.
            let result = JsPlaintext::Number(f64::NAN).to_plaintext_with_type(ColumnType::Decimal);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Decimal"));
        }

        #[test]
        fn test_infinity_to_decimal_fails() {
            let result =
                JsPlaintext::Number(f64::INFINITY).to_plaintext_with_type(ColumnType::Decimal);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Decimal"));
        }

        #[test]
        fn test_truncation_errors_do_not_echo_the_value() {
            // Values on the encrypt path are plaintext secrets; errors must
            // not leak them (same convention as the date parsing errors).
            let err = JsPlaintext::Number(5_000_000_001.0)
                .to_plaintext_with_type(ColumnType::Int)
                .unwrap_err();
            assert!(
                !err.0.contains("5000000001") && !err.0.contains("5_000_000_001"),
                "error must not echo the plaintext value, got: {}",
                err.0
            );
        }

        #[test]
        fn test_boolean_to_boolean() {
            let js_bool = JsPlaintext::Boolean(true);
            let result = js_bool.to_plaintext_with_type(ColumnType::Boolean).unwrap();
            assert_eq!(result, Plaintext::Boolean(Some(true)));
        }

        #[test]
        fn test_boolean_to_string_fails() {
            let js_bool = JsPlaintext::Boolean(true);
            let result = js_bool.to_plaintext_with_type(ColumnType::Text);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Cannot convert"));
        }

        #[test]
        fn test_jsonb_to_jsonb() {
            let json_value = serde_json::json!({"key": "value"});
            let js_jsonb = JsPlaintext::JsonB(json_value.clone());
            let result = js_jsonb.to_plaintext_with_type(ColumnType::Json).unwrap();
            assert_eq!(result, Plaintext::Json(Some(json_value)));
        }

        #[test]
        fn test_jsonb_to_string_fails() {
            let json_value = serde_json::json!({"key": "value"});
            let js_jsonb = JsPlaintext::JsonB(json_value);
            let result = js_jsonb.to_plaintext_with_type(ColumnType::Text);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Cannot convert"));
        }

        #[test]
        fn test_number_to_boolean_fails() {
            let js_number = JsPlaintext::Number(1.0);
            let result = js_number.to_plaintext_with_type(ColumnType::Boolean);
            assert!(result.is_err());
            assert!(result.unwrap_err().0.contains("Cannot convert"));
        }

        #[test]
        fn test_iso_date_string_to_date() {
            let js_string = JsPlaintext::String("2025-03-14".to_string());
            let result = js_string.to_plaintext_with_type(ColumnType::Date).unwrap();
            assert_eq!(
                result,
                Plaintext::NaiveDate(Some(NaiveDate::from_ymd_opt(2025, 3, 14).unwrap()))
            );
        }

        #[test]
        fn test_rfc3339_string_to_date_truncates_time() {
            let js_string = JsPlaintext::String("2025-03-14T12:34:56.789Z".to_string());
            let result = js_string.to_plaintext_with_type(ColumnType::Date).unwrap();
            assert_eq!(
                result,
                Plaintext::NaiveDate(Some(NaiveDate::from_ymd_opt(2025, 3, 14).unwrap()))
            );
        }

        #[test]
        fn test_rfc3339_string_to_timestamp() {
            let js_string = JsPlaintext::String("2025-03-14T12:34:56.789Z".to_string());
            let result = js_string
                .to_plaintext_with_type(ColumnType::Timestamp)
                .unwrap();
            assert_eq!(result, Plaintext::Timestamp(Some(sample_dt())));
        }

        #[test]
        fn test_invalid_date_string_fails() {
            let js_string = JsPlaintext::String("not a date".to_string());
            let result = js_string.to_plaintext_with_type(ColumnType::Date);
            let err = result.expect_err("unparseable input must fail");
            assert!(
                err.0.contains("Cannot parse Date"),
                "error should name the failing target type, got: {}",
                err.0
            );
            assert!(
                !err.0.contains("not a date"),
                "error must not echo the user's input (possible secret leak), got: {}",
                err.0
            );
        }

        #[test]
        fn test_invalid_timestamp_string_fails() {
            let js_string = JsPlaintext::String("2025-03-14".to_string()); // date-only, not rfc3339
            let result = js_string.to_plaintext_with_type(ColumnType::Timestamp);
            let err =
                result.expect_err("date-only string must fail as Timestamp (requires RFC 3339)");
            assert!(
                err.0.contains("Cannot parse Timestamp"),
                "error should name the failing target type, got: {}",
                err.0
            );
            assert!(
                !err.0.contains("2025-03-14"),
                "error must not echo the user's input (possible secret leak), got: {}",
                err.0
            );
        }

        #[test]
        fn test_date_value_to_timestamp_column() {
            let t = sample_dt();
            let js = JsPlaintext::Date(t);
            let result = js.to_plaintext_with_type(ColumnType::Timestamp).unwrap();
            assert_eq!(result, Plaintext::Timestamp(Some(t)));
        }

        #[test]
        fn test_date_value_to_date_column_truncates() {
            let t = sample_dt();
            let js = JsPlaintext::Date(t);
            let result = js.to_plaintext_with_type(ColumnType::Date).unwrap();
            assert_eq!(
                result,
                Plaintext::NaiveDate(Some(NaiveDate::from_ymd_opt(2025, 3, 14).unwrap()))
            );
        }

        #[test]
        fn test_date_value_to_string_column_serializes_rfc3339() {
            let t = sample_dt();
            let js = JsPlaintext::Date(t);
            let result = js.to_plaintext_with_type(ColumnType::Text).unwrap();
            if let Plaintext::Text(Some(ref s)) = result {
                let parsed = DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);
                assert_eq!(parsed, t);
            } else {
                panic!("Expected Plaintext::Text");
            }
        }

        #[test]
        fn test_date_value_to_bigint_fails() {
            let t = sample_dt();
            let js = JsPlaintext::Date(t);
            let result = js.to_plaintext_with_type(ColumnType::BigInt);
            assert!(
                result.is_err(),
                "Date should not coerce into a numeric column"
            );
        }

        #[test]
        fn test_date_serializes_as_rfc3339_string() {
            let t = sample_dt();
            let js = JsPlaintext::Date(t);
            let s = serde_json::to_string(&js).unwrap();
            assert_eq!(
                s, r#""2025-03-14T12:34:56.789Z""#,
                "Date must serialize as a plain RFC 3339 string so JS callers can build a Date from it"
            );
        }

        #[test]
        fn test_rfc3339_string_deserializes_as_string_not_date() {
            // `String` precedes `Date` in the untagged enum order, which is load-bearing:
            // user-supplied strings must never be silently reinterpreted as dates; date
            // parsing only happens in `to_plaintext_with_type` when the column demands it.
            let parsed: JsPlaintext =
                serde_json::from_str(r#""2025-03-14T12:34:56.789Z""#).unwrap();
            assert!(
                matches!(parsed, JsPlaintext::String(_)),
                "RFC 3339 strings must deserialize as JsPlaintext::String, not JsPlaintext::Date"
            );
        }

        #[test]
        fn test_type_coercion_error_shows_valid_alternatives() {
            // Test that error messages show what types are valid for each JS type
            let js_string = JsPlaintext::String("hello".to_string());
            let result = js_string.to_plaintext_with_type(ColumnType::Int);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().0;
            // Should mention valid targets for String
            assert!(
                err_msg.contains("Text"),
                "Error should mention valid target Text: {}",
                err_msg
            );
            // Should mention cast_as setting
            assert!(
                err_msg.contains("cast_as"),
                "Error should mention cast_as setting: {}",
                err_msg
            );

            // Test Number type shows its valid targets
            let js_number = JsPlaintext::Number(42.0);
            let result = js_number.to_plaintext_with_type(ColumnType::Boolean);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().0;
            // Should mention valid targets for Number
            assert!(
                err_msg.contains("Float") || err_msg.contains("BigInt"),
                "Error should mention valid numeric targets: {}",
                err_msg
            );

            // Test Boolean shows its valid target
            let js_bool = JsPlaintext::Boolean(true);
            let result = js_bool.to_plaintext_with_type(ColumnType::Int);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().0;
            assert!(
                err_msg.contains("Boolean"),
                "Error should mention valid target Boolean: {}",
                err_msg
            );

            // Test JsonB shows its valid target
            let js_json = JsPlaintext::JsonB(serde_json::json!({"a": 1}));
            let result = js_json.to_plaintext_with_type(ColumnType::Int);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().0;
            assert!(
                err_msg.contains("Json"),
                "Error should mention valid target Json: {}",
                err_msg
            );
        }
    }

    mod bigint_to_plaintext_with_type {
        use super::*;

        #[test]
        fn bigint_to_bigint_is_exact_across_the_full_i64_range() {
            for v in [i64::MIN, -1, 0, 42, i64::MAX] {
                let result = JsPlaintext::BigInt(v)
                    .to_plaintext_with_type(ColumnType::BigInt)
                    .unwrap();
                assert_eq!(result, Plaintext::BigInt(Some(v)));
            }
        }

        /// Assert the conversion fails, names the target column type, and
        /// does not echo the value (plaintext being encrypted).
        fn assert_range_err(v: i64, column_type: ColumnType) {
            let err = JsPlaintext::BigInt(v)
                .to_plaintext_with_type(column_type)
                .expect_err(&format!(
                    "converting {}n to {:?} must fail instead of truncating",
                    v, column_type
                ));
            assert!(
                err.0.contains(&format!("{:?}", column_type)),
                "error should name the target column type {:?}, got: {}",
                column_type,
                err.0
            );
            assert!(
                !err.0
                    .contains(&v.to_string().trim_start_matches('-').to_string()),
                "error must not echo the plaintext value, got: {}",
                err.0
            );
        }

        #[test]
        fn bigint_to_int_boundaries_pass() {
            let max = JsPlaintext::BigInt(i32::MAX as i64)
                .to_plaintext_with_type(ColumnType::Int)
                .unwrap();
            assert_eq!(max, Plaintext::Int(Some(i32::MAX)));
            let min = JsPlaintext::BigInt(i32::MIN as i64)
                .to_plaintext_with_type(ColumnType::Int)
                .unwrap();
            assert_eq!(min, Plaintext::Int(Some(i32::MIN)));
        }

        #[test]
        fn bigint_to_int_overflow_fails() {
            assert_range_err(i32::MAX as i64 + 1, ColumnType::Int);
            assert_range_err(i32::MIN as i64 - 1, ColumnType::Int);
            assert_range_err(5_000_000_000, ColumnType::Int);
        }

        #[test]
        fn bigint_to_smallint_boundaries_pass() {
            let max = JsPlaintext::BigInt(i16::MAX as i64)
                .to_plaintext_with_type(ColumnType::SmallInt)
                .unwrap();
            assert_eq!(max, Plaintext::SmallInt(Some(i16::MAX)));
            let min = JsPlaintext::BigInt(i16::MIN as i64)
                .to_plaintext_with_type(ColumnType::SmallInt)
                .unwrap();
            assert_eq!(min, Plaintext::SmallInt(Some(i16::MIN)));
        }

        #[test]
        fn bigint_to_smallint_overflow_fails() {
            assert_range_err(40_000, ColumnType::SmallInt);
            assert_range_err(-40_000, ColumnType::SmallInt);
        }

        #[test]
        fn bigint_to_biguint_accepts_non_negative() {
            let result = JsPlaintext::BigInt(i64::MAX)
                .to_plaintext_with_type(ColumnType::BigUInt)
                .unwrap();
            assert_eq!(result, Plaintext::BigUInt(Some(i64::MAX as u64)));
        }

        #[test]
        fn negative_bigint_to_biguint_fails() {
            let err = JsPlaintext::BigInt(-1)
                .to_plaintext_with_type(ColumnType::BigUInt)
                .unwrap_err();
            assert!(
                err.0.contains("negative"),
                "error should mention the negative direction: {}",
                err.0
            );
        }

        #[test]
        fn bigint_to_decimal_is_exact() {
            // rust_decimal's 96-bit mantissa holds any i64 exactly.
            let result = JsPlaintext::BigInt(i64::MAX)
                .to_plaintext_with_type(ColumnType::Decimal)
                .unwrap();
            assert_eq!(result, Plaintext::Decimal(Some(Decimal::from(i64::MAX))));
        }

        #[test]
        fn bigint_to_float_fails() {
            // f64 cannot represent every i64 — a lossy cast would corrupt
            // the stored value and its index terms, so this is rejected.
            let err = JsPlaintext::BigInt(42)
                .to_plaintext_with_type(ColumnType::Float)
                .unwrap_err();
            assert!(err.0.contains("Cannot convert"), "got: {}", err.0);
            assert!(
                err.0.contains("cast_as"),
                "error should point at the cast_as setting: {}",
                err.0
            );
        }

        #[test]
        fn bigint_to_text_boolean_json_date_fail() {
            for column_type in [
                ColumnType::Text,
                ColumnType::Boolean,
                ColumnType::Json,
                ColumnType::Date,
                ColumnType::Timestamp,
            ] {
                let err = JsPlaintext::BigInt(42)
                    .to_plaintext_with_type(column_type)
                    .expect_err(&format!("BigInt must not coerce to {:?}", column_type));
                assert!(
                    err.0.contains("BigInt values can only be used with"),
                    "error should list the valid BigInt targets: {}",
                    err.0
                );
            }
        }

        #[test]
        fn number_to_bigint_guard_is_unchanged() {
            // The existing f64 path still applies to JS numbers: exact
            // integers pass, anything beyond exact-f64 territory fails.
            let ok = JsPlaintext::Number(9_007_199_254_740_992.0) // 2^53
                .to_plaintext_with_type(ColumnType::BigInt)
                .unwrap();
            assert_eq!(ok, Plaintext::BigInt(Some(9_007_199_254_740_992)));
            let err = JsPlaintext::Number(9_223_372_036_854_775_808.0) // 2^63
                .to_plaintext_with_type(ColumnType::BigInt);
            assert!(err.is_err(), "2^63 exceeds i64::MAX and must fail");
        }
    }

    mod bigint_wire_form {
        use super::*;

        #[test]
        fn tagged_map_deserializes_to_bigint() {
            let parsed: JsPlaintext =
                serde_json::from_str(r#"{"__protect_ffi_bigint__": "9223372036854775807"}"#)
                    .unwrap();
            assert_eq!(parsed, JsPlaintext::BigInt(i64::MAX));

            let parsed: JsPlaintext =
                serde_json::from_str(r#"{"__protect_ffi_bigint__": "-9223372036854775808"}"#)
                    .unwrap();
            assert_eq!(parsed, JsPlaintext::BigInt(i64::MIN));
        }

        #[test]
        fn bigint_serializes_to_the_tagged_map() {
            // Pins the serde rename to BIGINT_WIRE_KEY (the literal is
            // duplicated in the serde attribute, which cannot reference a
            // const).
            let s = serde_json::to_string(&JsPlaintext::BigInt(42)).unwrap();
            assert_eq!(s, format!(r#"{{"{}":"42"}}"#, BIGINT_WIRE_KEY));
        }

        #[test]
        fn wire_round_trip_is_exact_at_the_extremes() {
            for v in [i64::MIN, i64::MAX, 0, -1] {
                let s = serde_json::to_string(&JsPlaintext::BigInt(v)).unwrap();
                let parsed: JsPlaintext = serde_json::from_str(&s).unwrap();
                assert_eq!(parsed, JsPlaintext::BigInt(v));
            }
        }

        #[test]
        fn out_of_i64_range_tagged_value_falls_through_to_jsonb() {
            // Only reachable by bypassing the public wrappers (which
            // bounds-check first): the BigInt variant fails to match and
            // untagged deserialization falls through to JsonB, which the
            // column conversion then rejects. Pin that behavior so a
            // future serde change is noticed.
            let parsed: JsPlaintext =
                serde_json::from_str(r#"{"__protect_ffi_bigint__": "9223372036854775808"}"#)
                    .unwrap();
            assert!(
                matches!(parsed, JsPlaintext::JsonB(_)),
                "out-of-range tagged value should fall through to JsonB"
            );
            let err = parsed
                .to_plaintext_with_type(ColumnType::BigInt)
                .expect_err("JsonB must not convert to a BigInt column");
            assert!(err.0.contains("Cannot convert"), "got: {}", err.0);
        }

        #[test]
        fn json_objects_with_extra_keys_stay_jsonb() {
            // deny_unknown_fields on the wire struct: a user JSON object
            // that merely CONTAINS the magic key alongside other keys is
            // still a JsonB value.
            let parsed: JsPlaintext =
                serde_json::from_str(r#"{"__protect_ffi_bigint__": "42", "other": true}"#).unwrap();
            assert!(matches!(parsed, JsPlaintext::JsonB(_)));

            // Nested occurrences of the magic key are also untouched.
            let parsed: JsPlaintext =
                serde_json::from_str(r#"{"nested": {"__protect_ffi_bigint__": "42"}}"#).unwrap();
            assert!(matches!(parsed, JsPlaintext::JsonB(_)));
        }

        #[test]
        fn plain_numbers_still_deserialize_as_number() {
            // The BigInt variant must not shadow Number: integers arriving
            // as JSON numbers keep the existing Number semantics.
            let parsed: JsPlaintext = serde_json::from_str("42").unwrap();
            assert_eq!(parsed, JsPlaintext::Number(42.0));
            let parsed: JsPlaintext = serde_json::from_str("42.5").unwrap();
            assert_eq!(parsed, JsPlaintext::Number(42.5));
        }
    }
}
