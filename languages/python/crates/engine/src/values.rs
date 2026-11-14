//! Python values at the boundary: a model's attribute read by exact type
//! into a core [`Value`], and an opened core [`Scalar`] back into a Python
//! object.
//!
//! The type check is exact, `type(v) is T`: a `bool` is not an `int`, and a
//! `datetime` is not a `date` (the spec in #1341, "Values"). The extension
//! never changes a value: nothing here converts, only reads.

use std::borrow::Cow;
use zeroize::{Zeroize, Zeroizing};

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
/// `value_naive_datetime` for a datetime with no UTC offset, and the range
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
            // Naive as Python defines it: no tzinfo, or a tzinfo whose
            // utcoffset() is None. The subtraction below needs an offset.
            if value.call_method0("utcoffset")?.is_none() {
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
    // The digits are plaintext: wiped when dropped.
    let digits = Zeroizing::new(parts.getattr("digits")?.extract::<Vec<u8>>()?);
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
    for &digit in digits.iter() {
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

/// Why an opened date or timestamp has no Python object. The Go SDK can
/// store both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unfit {
    /// `datetime` keeps microseconds, and rounding would change the value.
    Nanoseconds,
    /// `datetime` holds the years 1 to 9999.
    Year,
}

impl Unfit {
    /// The cause, for a message.
    pub fn cause(self) -> &'static str {
        match self {
            Self::Nanoseconds => {
                "it has nanoseconds, and Python's datetime keeps only microseconds"
            }
            Self::Year => "its year is outside 1 to 9999, the years Python's datetime holds",
        }
    }
}

/// `datetime`'s refusal of a value out of its range as [`Unfit::Year`].
/// `fromordinal` raises `ValueError` for it, and `timedelta` and the
/// addition raise `OverflowError`. Any other error is Python's own.
fn in_range<T>(py: Python<'_>, result: PyResult<T>) -> PyResult<Result<T, Unfit>> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(error)
            if error.is_instance_of::<pyo3::exceptions::PyValueError>(py)
                || error.is_instance_of::<pyo3::exceptions::PyOverflowError>(py) =>
        {
            Ok(Err(Unfit::Year))
        }
        Err(error) => Err(error),
    }
}

/// An opened scalar as a Python object, of the type the field declares.
///
/// The scalar is borrowed and copied into the Python object. It wipes its
/// own copy when dropped, so the caller drops it where it lies: a scalar
/// moved out of a row's buffer leaves its bytes behind in the buffer.
///
/// # Errors
///
/// The outer error is Python's own. The inner one is a date or timestamp
/// that `datetime` cannot hold, with the reason.
pub fn to_python(py: Python<'_>, scalar: &Scalar) -> PyResult<Result<Py<PyAny>, Unfit>> {
    Ok(Ok(match scalar {
        Scalar::Null => py.None(),
        Scalar::Text(text) => PyString::new(py, text).into_any().unbind(),
        Scalar::Int(i) => i.into_pyobject(py)?.into_any().unbind(),
        Scalar::Float(f) => PyFloat::new(py, *f).into_any().unbind(),
        Scalar::Bool(b) => PyBool::new(py, *b).to_owned().into_any().unbind(),
        Scalar::Bytes(bytes) => PyBytes::new(py, bytes).into_any().unbind(),
        Scalar::Date(days) => {
            let date = PyKind::Date.type_object(py)?;
            let opened = date.call_method1("fromordinal", (i64::from(*days) + 719_163,));
            match in_range(py, opened)? {
                Ok(date) => date.unbind(),
                Err(unfit) => return Ok(Err(unfit)),
            }
        }
        &Scalar::Timestamp(nanos) => {
            if nanos.rem_euclid(1_000) != 0 {
                return Ok(Err(Unfit::Nanoseconds));
            }
            let micros = nanos.div_euclid(1_000);
            let seconds = micros.div_euclid(1_000_000);
            let micros = micros.rem_euclid(1_000_000);
            let timedelta = py.import("datetime")?.getattr("timedelta")?;
            let epoch = epoch(py)?;
            let opened = timedelta
                .call1((0, seconds, micros))
                .and_then(|delta| epoch.add(delta));
            match in_range(py, opened)? {
                Ok(timestamp) => timestamp.unbind(),
                Err(unfit) => return Ok(Err(unfit)),
            }
        }
        &Scalar::Decimal { mantissa, scale } => {
            // Decimal((sign, digits, exponent)), so that the scale is kept:
            // Decimal("1.50") is not Decimal("1.5") to Python. The digits
            // are plaintext, and both copies are wiped when dropped.
            let sign = u8::from(mantissa < 0);
            let text = Zeroizing::new(mantissa.unsigned_abs().to_string());
            let digits = Zeroizing::new(text.bytes().map(|b| b - b'0').collect::<Vec<u8>>());
            // A tuple of ints: pyo3 converts a Vec<u8> to bytes, which
            // Decimal refuses.
            let digits = PyTuple::new(py, digits.iter())?;
            PyKind::Decimal
                .type_object(py)?
                .call1(((sign, digits, -i64::from(scale)),))?
                .unbind()
        }
    }))
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
                let opened = to_python(py, &Scalar::Decimal { mantissa, scale })
                    .unwrap()
                    .unwrap();
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

    /// A positive exponent multiplies the mantissa, and the sign applies to
    /// it. A wrong sign or power would encrypt another number with no error.
    #[test]
    fn a_decimal_reads_as_its_exact_mantissa_and_scale() {
        Python::initialize();
        Python::attach(|py| {
            let decimal = py.import("decimal").unwrap().getattr("Decimal").unwrap();
            for (text, expected_mantissa, expected_scale) in [
                ("1.2E+3", 1_200, 0),
                ("-0.05", -5, 2),
                ("-7", -7, 0),
                ("1E+28", 10_i128.pow(28), 0),
            ] {
                match decimal_of(&decimal.call1((text,)).unwrap()) {
                    Ok(Value::Decimal { mantissa, scale }) => {
                        assert_eq!(
                            (mantissa, scale),
                            (expected_mantissa, expected_scale),
                            "{text}"
                        );
                    }
                    other => panic!("{text}: {other:?}"),
                }
            }
        });
    }

    /// A date is days from 1970-01-01, and a datetime nanoseconds from the
    /// epoch, in UTC. Both are checked against known numbers, before the
    /// epoch and with a non-UTC offset, and read back as equal values.
    #[test]
    fn a_date_and_a_datetime_read_as_the_engines_numbers_and_back() {
        Python::initialize();
        Python::attach(|py| {
            let datetime = py.import("datetime").unwrap();
            let utc = datetime
                .getattr("timezone")
                .unwrap()
                .getattr("utc")
                .unwrap();
            let ten_hours = datetime
                .getattr("timezone")
                .unwrap()
                .call1((datetime
                    .getattr("timedelta")
                    .unwrap()
                    .call1((0, 36_000))
                    .unwrap(),))
                .unwrap();
            let day_before = datetime
                .getattr("date")
                .unwrap()
                .call1((1969, 12, 31))
                .unwrap();
            let cases = [
                (day_before, PyKind::Date, Scalar::Date(-1)),
                (
                    // 1970-01-01T00:00:00.123456Z, written ten hours ahead.
                    datetime
                        .getattr("datetime")
                        .unwrap()
                        .call1((1970, 1, 1, 10, 0, 0, 123_456, &ten_hours))
                        .unwrap(),
                    PyKind::DateTime,
                    Scalar::Timestamp(123_456_000),
                ),
                (
                    datetime
                        .getattr("datetime")
                        .unwrap()
                        .call1((1969, 12, 31, 23, 59, 59, 999_999, &utc))
                        .unwrap(),
                    PyKind::DateTime,
                    Scalar::Timestamp(-1_000),
                ),
            ];
            for (value, kind, scalar) in cases {
                let read = read(&value, kind, "test").unwrap().unwrap();
                let got = match read.value() {
                    Value::Date(days) => Scalar::Date(i32::try_from(days).unwrap()),
                    Value::Timestamp(nanos) => Scalar::Timestamp(nanos),
                    other => panic!("{value}: read as {other:?}"),
                };
                assert_eq!(got, scalar, "{value}");
                let opened = to_python(py, &scalar).unwrap().unwrap();
                assert!(
                    opened.bind(py).eq(&value).unwrap(),
                    "{value} came back as {opened}"
                );
            }
        });
    }
}
