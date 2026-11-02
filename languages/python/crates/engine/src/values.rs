//! Python values at the boundary: a model's attribute read by exact type
//! into a core [`Value`], and an opened core [`Scalar`] back into a Python
//! object.
//!
//! The type check is exact, `type(v) is T`: a `bool` is not an `int`, and a
//! `datetime` is not a `date` (the spec in #1341, "Values"). The extension
//! never changes a value: nothing here converts, only reads.

use std::borrow::Cow;
use zeroize::Zeroize;

use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyBool, PyBytes, PyFloat, PyInt, PyString, PyTuple, PyType};
use stackencrypt_core::refusal::Refusal;
use stackencrypt_core::values::{Kind, Scalar, Value};

/// The Python type a field's value must have, exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PyKind {
    Str,
    Int,
    Float,
    Bool,
    Bytes,
    Date,
    DateTime,
    Decimal,
}

impl PyKind {
    /// The Python type of a marker's kind: the `_KIND_TYPES` table in
    /// `_declaration.py`, checked there at the class statement.
    pub fn of_kind(kind: Kind) -> Self {
        match kind {
            Kind::String => Self::Str,
            Kind::Int16 | Kind::Int32 | Kind::Int64 => Self::Int,
            Kind::Float32 | Kind::Float64 => Self::Float,
            Kind::Bool => Self::Bool,
            Kind::Decimal => Self::Decimal,
            Kind::Date => Self::Date,
            Kind::Timestamp => Self::DateTime,
        }
    }

    /// The kind of a declared type object, or `None` for a type the SDK
    /// does not carry. The decorator refuses those at the class statement.
    pub fn of_type(py: Python<'_>, declared: &Bound<'_, PyType>) -> PyResult<Option<Self>> {
        for kind in [
            Self::Str,
            Self::Int,
            Self::Float,
            Self::Bool,
            Self::Bytes,
            Self::Date,
            Self::DateTime,
            Self::Decimal,
        ] {
            if kind.type_object(py)?.is(declared) {
                return Ok(Some(kind));
            }
        }
        Ok(None)
    }

    fn type_object<'py>(self, py: Python<'py>) -> PyResult<&'py Bound<'py, PyType>> {
        static DATE: PyOnceLock<Py<PyType>> = PyOnceLock::new();
        static DATETIME: PyOnceLock<Py<PyType>> = PyOnceLock::new();
        static DECIMAL: PyOnceLock<Py<PyType>> = PyOnceLock::new();
        static STR: PyOnceLock<Py<PyType>> = PyOnceLock::new();
        static INT: PyOnceLock<Py<PyType>> = PyOnceLock::new();
        static FLOAT: PyOnceLock<Py<PyType>> = PyOnceLock::new();
        static BOOL: PyOnceLock<Py<PyType>> = PyOnceLock::new();
        static BYTES: PyOnceLock<Py<PyType>> = PyOnceLock::new();
        let imported = |module: &str, name: &str| -> PyResult<Py<PyType>> {
            Ok(py
                .import(module)?
                .getattr(name)?
                .cast_into::<PyType>()?
                .unbind())
        };
        let cell = match self {
            Self::Str => {
                STR.get_or_try_init(py, || PyResult::Ok(py.get_type::<PyString>().unbind()))?
            }
            Self::Int => {
                INT.get_or_try_init(py, || PyResult::Ok(py.get_type::<PyInt>().unbind()))?
            }
            Self::Float => {
                FLOAT.get_or_try_init(py, || PyResult::Ok(py.get_type::<PyFloat>().unbind()))?
            }
            Self::Bool => {
                BOOL.get_or_try_init(py, || PyResult::Ok(py.get_type::<PyBool>().unbind()))?
            }
            Self::Bytes => {
                BYTES.get_or_try_init(py, || PyResult::Ok(py.get_type::<PyBytes>().unbind()))?
            }
            Self::Date => DATE.get_or_try_init(py, || imported("datetime", "date"))?,
            Self::DateTime => DATETIME.get_or_try_init(py, || imported("datetime", "datetime"))?,
            Self::Decimal => DECIMAL.get_or_try_init(py, || imported("decimal", "Decimal"))?,
        };
        Ok(cell.bind(py))
    }

    fn name(self) -> &'static str {
        match self {
            Self::Str => "str",
            Self::Int => "int",
            Self::Float => "float",
            Self::Bool => "bool",
            Self::Bytes => "bytes",
            Self::Date => "date",
            Self::DateTime => "datetime",
            Self::Decimal => "Decimal",
        }
    }
}

/// A field's value as read from its attribute. Text and bytes borrow from
/// the attribute object where they can, so the plaintext is not copied
/// before the engine writes it into the protected frame.
///
/// Under `abi3-py39`, pyo3 cannot borrow a `str`'s UTF-8, so `Text` is an
/// owned copy on every Python version. That copy is the extension's own, and
/// is wiped when the `Read` is dropped (`src/heap_hygiene.rs` checks it).
pub enum Read<'a> {
    Text(Cow<'a, str>),
    Bytes(&'a [u8]),
    Other(Value<'static>),
}

impl Drop for Read<'_> {
    fn drop(&mut self) {
        if let Self::Text(Cow::Owned(text)) = self {
            text.zeroize();
        }
    }
}

impl Read<'_> {
    /// The value, as the core rules take it.
    pub fn value(&self) -> Value<'_> {
        match self {
            Self::Text(text) => Value::Text(text),
            Self::Bytes(bytes) => Value::Bytes(bytes),
            Self::Other(value) => *value,
        }
    }
}

/// Read `value` as a field of `kind`, by exact type.
///
/// # Errors
///
/// `value_none` for `None`, `value_wrong_type` for another type,
/// `value_naive_datetime` for a datetime with no `tzinfo`, and the range
/// refusals for an `int` or `Decimal` the engine cannot hold. `field` is
/// not set: the caller names it.
pub fn read<'a>(
    value: &'a Bound<'_, PyAny>,
    kind: PyKind,
    reason: &'static str,
) -> PyResult<Result<Read<'a>, Refusal>> {
    let py = value.py();
    if value.is_none() {
        return Ok(Err(refusal("value_none", "is None", reason)));
    }
    if !value.get_type().is(kind.type_object(py)?) {
        return Ok(Err(refusal(
            "value_wrong_type",
            &format!(
                "is {} and the field takes {}",
                type_name(value),
                kind.name()
            ),
            reason,
        )));
    }
    let other = |value: Value<'static>| Ok(Ok(Read::Other(value)));
    match kind {
        PyKind::Str => Ok(Ok(Read::Text(value.cast::<PyString>()?.to_cow()?))),
        PyKind::Bytes => Ok(Ok(Read::Bytes(value.cast::<PyBytes>()?.as_bytes()))),
        PyKind::Int => match value.extract::<i128>() {
            Ok(i) => other(Value::Int(i)),
            Err(_) => Ok(Err(refusal(
                "value_out_of_range",
                "does not fit 128 bits",
                reason,
            ))),
        },
        PyKind::Float => other(Value::Float(value.extract::<f64>()?)),
        PyKind::Bool => other(Value::Bool(value.extract::<bool>()?)),
        PyKind::Date => {
            // Python's ordinal counts from 0001-01-01; the engine's day
            // count from 1970-01-01, ordinal 719163.
            let ordinal: i64 = value.call_method0("toordinal")?.extract()?;
            other(Value::Date(ordinal - 719_163))
        }
        PyKind::DateTime => {
            if value.getattr("tzinfo")?.is_none() {
                return Ok(Err(refusal(
                    "value_naive_datetime",
                    "is a naive datetime. Give it a tzinfo, such as timezone.utc",
                    reason,
                )));
            }
            // Exact arithmetic in Python: the timedelta since the epoch, in
            // days, seconds and microseconds. `timestamp()` is a float and
            // would round.
            let delta = value.sub(epoch(py)?)?;
            let days: i128 = delta.getattr("days")?.extract()?;
            let seconds: i128 = delta.getattr("seconds")?.extract()?;
            let micros: i128 = delta.getattr("microseconds")?.extract()?;
            other(Value::Timestamp(
                ((days * 86_400 + seconds) * 1_000_000 + micros) * 1_000,
            ))
        }
        PyKind::Decimal => Ok(decimal(value, reason)?.map(Read::Other)),
    }
}

fn epoch(py: Python<'_>) -> PyResult<&Bound<'_, PyAny>> {
    static EPOCH: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
    let epoch = EPOCH.get_or_try_init(py, || -> PyResult<Py<PyAny>> {
        let datetime = py.import("datetime")?;
        let utc = datetime.getattr("timezone")?.getattr("utc")?;
        Ok(datetime
            .getattr("datetime")?
            .call1((1970, 1, 1, 0, 0, 0, 0, utc))?
            .unbind())
    })?;
    Ok(epoch.bind(py))
}

/// A `Decimal` as its mantissa and scale, from `as_tuple()`: the sign, the
/// digits, and the exponent. A NaN or an infinity has a letter for an
/// exponent, and no mantissa.
fn decimal(
    value: &Bound<'_, PyAny>,
    reason: &'static str,
) -> PyResult<Result<Value<'static>, Refusal>> {
    let parts = value.call_method0("as_tuple")?;
    let sign: u8 = parts.getattr("sign")?.extract()?;
    let digits: Vec<u8> = parts.getattr("digits")?.extract()?;
    let Ok(exponent) = parts.getattr("exponent")?.extract::<i64>() else {
        return Ok(Err(refusal(
            "value_not_representable",
            "is not a finite number",
            reason,
        )));
    };
    let not_representable = || {
        refusal(
            "value_not_representable",
            "has more than 96 bits of digits",
            reason,
        )
    };
    let mut mantissa: i128 = 0;
    for digit in digits {
        mantissa = match mantissa
            .checked_mul(10)
            .and_then(|m| m.checked_add(i128::from(digit)))
        {
            Some(m) => m,
            None => return Ok(Err(not_representable())),
        };
    }
    // A zero with a positive exponent is zero at scale 0, as a nonzero one
    // is multiplied out below. The loop would otherwise run once per unit of
    // a huge exponent with the GIL held: Decimal("0E+999999999999999999").
    // A negative exponent keeps its scale, so Decimal("0.00") stays 0.00.
    if mantissa == 0 && exponent > 0 {
        return Ok(Ok(Value::Decimal {
            mantissa: 0,
            scale: 0,
        }));
    }
    // Past 38 the mantissa overflows i128 whatever its digits, so refuse it
    // before the loop rather than after a long one.
    if exponent > 38 {
        return Ok(Err(not_representable()));
    }
    let scale = if exponent < 0 {
        match u32::try_from(-exponent) {
            Ok(scale) => scale,
            Err(_) => return Ok(Err(not_representable())),
        }
    } else {
        for _ in 0..exponent {
            mantissa = match mantissa.checked_mul(10) {
                Some(m) => m,
                None => return Ok(Err(not_representable())),
            };
        }
        0
    };
    if sign == 1 {
        mantissa = -mantissa;
    }
    Ok(Ok(Value::Decimal { mantissa, scale }))
}

fn refusal(code: &str, what: &str, reason: &'static str) -> Refusal {
    Refusal {
        code: code.to_owned(),
        message: format!("the value {what}."),
        field: None,
        reason: Some(reason.to_owned()),
    }
}

fn type_name(value: &Bound<'_, PyAny>) -> String {
    value
        .get_type()
        .name()
        .map_or_else(|_| "an unknown type".to_owned(), |name| name.to_string())
}

/// An opened scalar as a Python object, of the type the field declares.
pub fn to_python(py: Python<'_>, scalar: Scalar) -> PyResult<Py<PyAny>> {
    Ok(match scalar {
        Scalar::Null => py.None(),
        Scalar::Text(text) => PyString::new(py, &text).into_any().unbind(),
        Scalar::Int(i) => i.into_pyobject(py)?.into_any().unbind(),
        Scalar::Float(f) => PyFloat::new(py, f).into_any().unbind(),
        Scalar::Bool(b) => PyBool::new(py, b).to_owned().into_any().unbind(),
        Scalar::Bytes(bytes) => PyBytes::new(py, &bytes).into_any().unbind(),
        Scalar::Date(days) => PyKind::Date
            .type_object(py)?
            .call_method1("fromordinal", (i64::from(days) + 719_163,))?
            .unbind(),
        Scalar::Timestamp(nanos) => {
            // Python's datetime keeps microseconds; the engine's timestamp
            // is in nanoseconds, so the last three digits are dropped. An
            // encrypted datetime had none: Python wrote it.
            let micros = nanos.div_euclid(1_000);
            let seconds = micros.div_euclid(1_000_000);
            let micros = micros.rem_euclid(1_000_000);
            let delta = py
                .import("datetime")?
                .getattr("timedelta")?
                .call1((0, seconds, micros))?;
            epoch(py)?.add(delta)?.unbind()
        }
        Scalar::Decimal { mantissa, scale } => {
            // Decimal((sign, digits, exponent)), so that the scale is kept:
            // Decimal("1.50") is not Decimal("1.5") to Python.
            let sign = u8::from(mantissa < 0);
            let digits: Vec<u8> = mantissa
                .unsigned_abs()
                .to_string()
                .bytes()
                .map(|b| b - b'0')
                .collect();
            // A tuple of ints: pyo3 converts a Vec<u8> to bytes, which
            // Decimal refuses.
            let digits = PyTuple::new(py, digits)?;
            PyKind::Decimal
                .type_object(py)?
                .call1(((sign, digits, -i64::from(scale)),))?
                .unbind()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_opened_decimal_is_a_decimal_with_its_scale() {
        Python::initialize();
        Python::attach(|py| {
            let decimal = py.import("decimal").unwrap().getattr("Decimal").unwrap();
            for (mantissa, scale, text) in [(1_995, 2, "19.95"), (-150, 2, "-1.50"), (0, 2, "0.00")]
            {
                let opened = to_python(py, Scalar::Decimal { mantissa, scale }).unwrap();
                let opened = opened.bind(py);
                assert!(opened.get_type().is(&decimal), "{text}");
                assert_eq!(opened.str().unwrap().to_string(), text);
            }
        });
    }

    #[test]
    fn a_zero_with_a_huge_exponent_reads_at_once() {
        Python::initialize();
        Python::attach(|py| {
            let decimal = py.import("decimal").unwrap().getattr("Decimal").unwrap();
            let zero = decimal.call1(("0E+999999999999999999",)).unwrap();
            assert!(matches!(
                decimal_of(&zero),
                Ok(Value::Decimal {
                    mantissa: 0,
                    scale: 0
                })
            ));
            let small_zero = decimal.call1(("0.00",)).unwrap();
            assert!(matches!(
                decimal_of(&small_zero),
                Ok(Value::Decimal {
                    mantissa: 0,
                    scale: 2
                })
            ));
            let big = decimal.call1(("1E+39",)).unwrap();
            assert_eq!(
                decimal_of(&big).unwrap_err().code,
                "value_not_representable"
            );
        });
    }

    fn decimal_of(value: &Bound<'_, PyAny>) -> Result<Value<'static>, Refusal> {
        decimal(value, "decimal").unwrap()
    }
}
