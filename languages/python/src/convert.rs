//! The only place a Python object becomes an `FfiValue`, and the only place
//! one becomes a Python object again.
//!
//! Width lives here on purpose. A Python `int` is arbitrary precision, so
//! `34` says nothing about `int64` versus `int32`, and the engine derives a
//! different ORE term for each. The declared kind arrives with the value and
//! is checked before the value crosses, which is the earliest stage this
//! language allows (principle G3).
//!
//! The conversion is deliberately **exact**. `stack_encrypt::dynamic::read`
//! will convert a number of another width when the conversion is lossless,
//! and that is right for a *query* value whose caller wrote a literal. It is
//! wrong here: `34` and `34.0` derive different ORE terms, so accepting a
//! float for a declared integer field would store terms a later query cannot
//! match. A field's declared kind is the one kind it takes.

use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString};
use stack_encrypt::dynamic::{FfiValue, ValueKind};
// `risky_ref` is a `Controlled` method, not an inherent one, on both
// `Protected<Vec<u8>>` and `Utf8String`. The name is vitaminc's warning
// label: it borrows plaintext out of a wiped-on-drop wrapper.
use vitaminc_protected::Controlled;

use crate::errors::ConvertError;

/// The `ValueKind` a plan's `"type"` string names.
///
/// `ValueKind: FromStr` over `ValueKind::name`'s lowercase vocabulary, which
/// is what `dynamic::record::plan_with` itself parses the key with. Using
/// the same parser is the point: a name this accepts and the engine refuses,
/// or the reverse, would be two spellings of one declaration.
pub fn kind(name: &str) -> Result<ValueKind, ConvertError> {
    name.parse().map_err(|_| ConvertError::UnknownKind {
        name: name.to_owned(),
    })
}

/// One Python value as an `FfiValue`, checked against `declared`.
pub fn to_ffi(
    value: &Bound<'_, PyAny>,
    declared: Option<ValueKind>,
) -> Result<FfiValue, ConvertError> {
    let produced = encode(value, declared)?;
    if let Some(declared) = declared {
        // `holds` is vitaminc's own check, so the shell cannot disagree with
        // the engine about what a kind accepts.
        if !declared.holds(&produced) {
            return Err(ConvertError::Kind {
                declared: declared.name(),
                got: describe(&produced),
            });
        }
    }
    Ok(produced)
}

/// The Python type to an `FfiValue`, before the kind check.
fn encode(value: &Bound<'_, PyAny>, declared: Option<ValueKind>) -> Result<FfiValue, ConvertError> {
    // `None` first: it is a legal `FfiValue` (`Null`), so it must reach the
    // kind check rather than fall through to "no encoding".
    if value.is_none() {
        return Ok(FfiValue::Null);
    }
    // `isinstance(True, int)` is true in Python, so bool comes before int or
    // every bool reaches an integer field.
    if value.is_instance_of::<PyBool>() {
        return Ok(FfiValue::Bool(value.extract::<bool>().map_err(|_| {
            ConvertError::Kind {
                declared: declared.map_or("no kind", ValueKind::name),
                got: "bool".to_owned(),
            }
        })?));
    }
    if value.is_instance_of::<PyInt>() {
        return integer(value, declared);
    }
    if value.is_instance_of::<PyFloat>() {
        return float(value, declared);
    }
    if value.is_instance_of::<PyString>() {
        let text = value
            .extract::<String>()
            .map_err(|_| ConvertError::Unsupported {
                got: "str".to_owned(),
            })?;
        // `Utf8String: From<String>` validates UTF-8 at construction and
        // holds the bytes in `Protected`, so the copy is wiped on drop.
        return Ok(FfiValue::String(text.into()));
    }
    if value.is_instance_of::<PyBytes>() {
        let bytes = value
            .extract::<Vec<u8>>()
            .map_err(|_| ConvertError::Unsupported {
                got: "bytes".to_owned(),
            })?;
        return Ok(FfiValue::Bytes(bytes.into()));
    }
    Err(ConvertError::Unsupported {
        got: type_name(value),
    })
}

/// A Python integer narrowed to the declared kind, or refused.
///
/// With no declared kind the value takes `int64`. That is reachable only for
/// a passthrough or ciphertext-only field: the data plan requires `"type"`
/// on every field with a term output, so an indexed field always arrives
/// with one.
fn integer(
    value: &Bound<'_, PyAny>,
    declared: Option<ValueKind>,
) -> Result<FfiValue, ConvertError> {
    let declared = declared.unwrap_or(ValueKind::Int64);
    let name = declared.name();
    let out_of_range = || ConvertError::Range { declared: name };
    match declared {
        ValueKind::Int32 => value.extract::<i32>().map(FfiValue::Int32),
        ValueKind::Int64 => value.extract::<i64>().map(FfiValue::Int64),
        ValueKind::UInt32 => value.extract::<u32>().map(FfiValue::UInt32),
        ValueKind::UInt64 => value.extract::<u64>().map(FfiValue::UInt64),
        // An integer where a float, string or bytes field is declared. Not
        // a range failure — no width would accept it — so it is a kind
        // refusal, raised here rather than by `holds` so the message names
        // what arrived as an integer rather than as its narrowed tag.
        _ => {
            return Err(ConvertError::Kind {
                declared: name,
                got: "int64".to_owned(),
            })
        }
    }
    .map_err(|_| out_of_range())
}

/// A Python float, which is always an IEEE-754 double.
fn float(value: &Bound<'_, PyAny>, declared: Option<ValueKind>) -> Result<FfiValue, ConvertError> {
    let double = value
        .extract::<f64>()
        .map_err(|_| ConvertError::Unsupported {
            got: "float".to_owned(),
        })?;
    match declared {
        // `float32` is in the kind vocabulary for schema fidelity with
        // `float4`. Narrowing is lossy in general, so it is refused rather
        // than rounded: a stored term and a query term that disagree in the
        // last bits match nothing.
        Some(ValueKind::Float32) => Err(ConvertError::Kind {
            declared: "float32",
            got: "float64".to_owned(),
        }),
        _ => Ok(FfiValue::Float64(double)),
    }
}

/// An `FfiValue` as a Python object.
///
/// The declared kind is what decides the Python type, which is why a field
/// with a term output must declare one: a host with no static type to infer
/// from cannot otherwise tell an integer from a float, or bytes from a
/// string.
pub fn from_ffi(py: Python<'_>, value: FfiValue) -> PyResult<Py<PyAny>> {
    Ok(match value {
        FfiValue::Null | FfiValue::Undefined => py.None(),
        FfiValue::Bool(inner) => inner.into_pyobject(py)?.to_owned().into_any().unbind(),
        FfiValue::Int32(inner) => inner.into_pyobject(py)?.into_any().unbind(),
        FfiValue::Int64(inner) => inner.into_pyobject(py)?.into_any().unbind(),
        FfiValue::UInt32(inner) => inner.into_pyobject(py)?.into_any().unbind(),
        FfiValue::UInt64(inner) => inner.into_pyobject(py)?.into_any().unbind(),
        FfiValue::Float32(inner) => inner.into_pyobject(py)?.into_any().unbind(),
        FfiValue::Float64(inner) => inner.into_pyobject(py)?.into_any().unbind(),
        FfiValue::String(text) => {
            // `risky_ref` is the borrow out of `Protected`. It is named that
            // way because the bytes are plaintext; they go straight into a
            // Python str and nowhere else.
            let bytes = text.risky_ref().to_vec();
            let decoded = String::from_utf8(bytes).map_err(|_| {
                // Unreachable through `Utf8String`, which validates at
                // construction. An error rather than a lossy decode, so a
                // future path that builds one another way is loud.
                crate::errors::EngineError::new_err("a string leaf held invalid UTF-8")
            })?;
            decoded.into_pyobject(py)?.into_any().unbind()
        }
        FfiValue::Bytes(bytes) => PyBytes::new(py, bytes.risky_ref()).into_any().unbind(),
        // Containers, recursively. An opened row is an `Object` of field name
        // to value, and a plan's context may be an `Array`; both are plain
        // Python structures on the way out.
        FfiValue::Object(pairs) => {
            let dict = PyDict::new(py);
            for (key, inner) in pairs {
                dict.set_item(key, from_ffi(py, inner)?)?;
            }
            dict.into_any().unbind()
        }
        FfiValue::Array(items) => {
            let list = PyList::empty(py);
            for inner in items {
                list.append(from_ffi(py, inner)?)?;
            }
            list.into_any().unbind()
        }
        other => {
            return Err(ConvertError::NoPythonMapping {
                got: describe(&other),
            }
            .into())
        }
    })
}

/// A value's kind, for a message. `FfiValue::kind` is `None` for `Null` and
/// `Undefined`, which have no `ValueKind` — they are the absence of one.
fn describe(value: &FfiValue) -> String {
    value
        .kind()
        .map_or_else(|| "null".to_owned(), |kind| kind.name().to_owned())
}

fn type_name(value: &Bound<'_, PyAny>) -> String {
    value
        .get_type()
        .name()
        .map(|name| name.to_string())
        .unwrap_or_else(|_| "?".to_owned())
}
