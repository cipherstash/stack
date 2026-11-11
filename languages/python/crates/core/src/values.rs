//! The value rules: a host value into the engine's scalar, and an opened
//! scalar back out.
//!
//! The kind comes from the field's marker, never from the value. The
//! extension reads a Python value by exact type and hands it over as a
//! [`Value`]; this module writes it as the engine's physical value under the
//! kind's logical type, and refuses what does not fit (the spec in #1341,
//! "Values"). A passthrough has no kind: it is carried as it is. An opened
//! passthrough comes back as a [`Scalar`], read from its frame here, so the
//! extension never walks a frame itself.
//!
//! The exact-type check (`bool` is not an `int`) is the extension's: it is
//! a check on Python types. What is here is everything after it.

use stack_encrypt::dynamic::frame::Frame;
use stack_encrypt::dynamic::plaintext::{
    kinds, Error as SinkError, FixedType, Float, Int, Logical, MapSink, Physical, SeqSink, Sink,
    SourceError, TimeUnit,
};
use zeroize::Zeroize;

use std::convert::Infallible;
use std::marker::PhantomData;

use stack_encrypt::Encrypt;

use crate::refusal::Refusal;

/// A marker's kind, as the catalog names it: the `plaintext` attribute of
/// the generated marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    String,
    Int16,
    Int32,
    Int64,
    Float32,
    Float64,
    Bool,
    Decimal,
    Date,
    Timestamp,
}

impl Kind {
    /// The kind of this name, or `None` for a kind no Python type exists
    /// for, such as `json`. The decorator refuses those first.
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "string" => Self::String,
            "int16" => Self::Int16,
            "int32" => Self::Int32,
            "int64" => Self::Int64,
            "float32" => Self::Float32,
            "float64" => Self::Float64,
            "bool" => Self::Bool,
            "decimal" => Self::Decimal,
            "date" => Self::Date,
            "timestamp" => Self::Timestamp,
            _ => return None,
        })
    }

    /// The catalog's name, the `reason` of a value refusal.
    pub fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Int16 => "int16",
            Self::Int32 => "int32",
            Self::Int64 => "int64",
            Self::Float32 => "float32",
            Self::Float64 => "float64",
            Self::Bool => "bool",
            Self::Decimal => "decimal",
            Self::Date => "date",
            Self::Timestamp => "timestamp",
        }
    }
}

/// A host value, already read by exact type, as the engine takes it.
#[derive(Clone, Copy, Debug)]
pub enum Value<'a> {
    /// A missing value: Python's `None`, for a field declared `Optional`.
    /// The frame carries it as a null. A nullable EQL field stores nothing
    /// for it, so its column holds SQL `NULL` (`"null": "sql"`).
    Null,
    Text(&'a str),
    /// Any Python `int` that fits; one that does not is refused by the
    /// extension as out of range before it gets here.
    Int(i128),
    Float(f64),
    Bool(bool),
    Bytes(&'a [u8]),
    /// Days since 1970-01-01.
    Date(i64),
    /// Nanoseconds since the Unix epoch, UTC. A naive datetime never gets
    /// here: the extension refuses it.
    Timestamp(i128),
    /// `mantissa × 10^-scale`.
    Decimal {
        mantissa: i128,
        scale: u32,
    },
}

/// Why a value does not fit its kind. The extension turns it into the
/// `InvalidValueError` with the field's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Misfit {
    /// An integer outside the kind's width, or a date or timestamp outside
    /// the engine's range: `value_out_of_range`.
    OutOfRange,
    /// A float the kind's width does not round-trip, or a decimal outside
    /// the engine's bounds: `value_not_representable`.
    NotRepresentable,
}

impl Misfit {
    /// The SDK's error code.
    pub fn code(self) -> &'static str {
        match self {
            Self::OutOfRange => "value_out_of_range",
            Self::NotRepresentable => "value_not_representable",
        }
    }
}

/// Write `value` into `sink` as the scalar of `kind`, or as it is for a
/// passthrough (`None`).
///
/// # Errors
///
/// [`Misfit`] when the value does not fit the kind. A value of the wrong
/// shape for the kind, such as text for an integer kind, is a bug in the
/// extension's type check and is reported as out of range.
pub fn write<S: Sink>(sink: S, kind: Option<Kind>, value: Value<'_>) -> Result<S::Ok, S::Error> {
    let (logical, physical) =
        scalar(kind, value).map_err(|misfit| S::Error::source(SourceError::new(misfit)))?;
    sink.scalar(logical, physical)
}

/// `value` as the engine's input on its own: [`write`] of it as `kind`, or
/// as it is for a passthrough (`None`). A query's value, a stored
/// passthrough, and the tests' and fuzz target's frames are written
/// through this.
#[derive(Clone, Copy, Debug)]
pub struct Typed<'a>(pub Option<Kind>, pub Value<'a>);

impl Encrypt for Typed<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        write(sink, self.0, self.1)
    }
}

/// The engine's scalar for `value` under `kind`.
///
/// # Errors
///
/// As [`write`].
pub fn scalar(
    kind: Option<Kind>,
    value: Value<'_>,
) -> Result<(Option<Logical>, Physical<'_>), Misfit> {
    let int = |i: i128, width: fn(i128) -> Option<Int>| {
        width(i).map(Physical::Int).ok_or(Misfit::OutOfRange)
    };
    Ok(match (kind, value) {
        (_, Value::Null) => (None, Physical::Null),
        (Some(Kind::String), Value::Text(s)) | (None, Value::Text(s)) => (None, Physical::Text(s)),
        (Some(Kind::Int16), Value::Int(i)) => {
            (None, int(i, |i| i16::try_from(i).ok().map(Int::I16))?)
        }
        (Some(Kind::Int32), Value::Int(i)) => {
            (None, int(i, |i| i32::try_from(i).ok().map(Int::I32))?)
        }
        (Some(Kind::Int64), Value::Int(i)) => {
            (None, int(i, |i| i64::try_from(i).ok().map(Int::I64))?)
        }
        // A passthrough integer keeps the narrowest signed width that holds
        // it, as a Go `int` would.
        (None, Value::Int(i)) => (
            None,
            Physical::Int(i64::try_from(i).map(Int::I64).unwrap_or(Int::I128(i))),
        ),
        (Some(Kind::Float32), Value::Float(f)) => {
            let narrowed = f as f32;
            if f64::from(narrowed) != f && !f.is_nan() {
                return Err(Misfit::NotRepresentable);
            }
            (None, Physical::Float(Float::F32(narrowed)))
        }
        (Some(Kind::Float64), Value::Float(f)) | (None, Value::Float(f)) => {
            (None, Physical::Float(Float::F64(f)))
        }
        (Some(Kind::Bool), Value::Bool(b)) | (None, Value::Bool(b)) => (None, Physical::Bool(b)),
        (None, Value::Bytes(b)) => (None, Physical::Bytes(b)),
        (Some(Kind::Date), Value::Date(days)) | (None, Value::Date(days)) => {
            let days = i32::try_from(days).map_err(|_| Misfit::OutOfRange)?;
            let physical = Physical::Int(Int::I32(days));
            if !Logical::Date.admits(&physical) {
                return Err(Misfit::OutOfRange);
            }
            (Some(Logical::Date), physical)
        }
        (Some(Kind::Timestamp), Value::Timestamp(nanos)) | (None, Value::Timestamp(nanos)) => {
            let physical = Physical::Int(Int::I128(nanos));
            if !Logical::Timestamp(TimeUnit::Nanos).admits(&physical) {
                return Err(Misfit::OutOfRange);
            }
            (Some(Logical::Timestamp(TimeUnit::Nanos)), physical)
        }
        (Some(Kind::Decimal), Value::Decimal { mantissa, scale })
        | (None, Value::Decimal { mantissa, scale }) => {
            let scale = u8::try_from(scale).map_err(|_| Misfit::NotRepresentable)?;
            let logical = Logical::Decimal { scale };
            let physical = Physical::Int(Int::I128(mantissa));
            if !logical.admits(&physical) {
                return Err(Misfit::NotRepresentable);
            }
            (Some(logical), physical)
        }
        // The extension checks the Python type before this, so a value of
        // another shape than its kind is its bug, not the user's.
        _ => return Err(Misfit::OutOfRange),
    })
}

impl std::fmt::Display for Misfit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Misfit {}

/// An opened scalar, as a host value. What a passthrough comes back as.
#[derive(Clone, Debug, PartialEq)]
pub enum Scalar {
    Null,
    Text(String),
    Int(i128),
    Float(f64),
    Bool(bool),
    Bytes(Vec<u8>),
    /// Days since 1970-01-01.
    Date(i32),
    /// Nanoseconds since the Unix epoch, UTC.
    Timestamp(i128),
    /// `mantissa × 10^-scale`.
    Decimal {
        mantissa: i128,
        scale: u8,
    },
}

/// An opened value is plaintext, and the SDK's own copy of it: it is wiped
/// when dropped, the inline numbers in a row's buffer as well as the text
/// and bytes on the heap. The extension copies it into a Python object
/// first (`src/heap_hygiene.rs` in the engine crate checks the drop).
impl Drop for Scalar {
    fn drop(&mut self) {
        match self {
            Self::Null => {}
            Self::Text(text) => text.zeroize(),
            Self::Bytes(bytes) => bytes.zeroize(),
            Self::Int(int) | Self::Timestamp(int) => int.zeroize(),
            Self::Float(float) => float.zeroize(),
            Self::Bool(bool) => bool.zeroize(),
            Self::Date(days) => days.zeroize(),
            Self::Decimal { mantissa, scale } => {
                mantissa.zeroize();
                scale.zeroize();
            }
        }
    }
}

impl Scalar {
    /// The scalar as the value the SDK writes, or `None` for a null, which
    /// the SDK never writes.
    pub fn value(&self) -> Option<Value<'_>> {
        Some(match self {
            Self::Null => return None,
            Self::Text(s) => Value::Text(s),
            Self::Int(i) => Value::Int(*i),
            Self::Float(f) => Value::Float(*f),
            Self::Bool(b) => Value::Bool(*b),
            Self::Bytes(b) => Value::Bytes(b),
            Self::Date(d) => Value::Date(i64::from(*d)),
            Self::Timestamp(t) => Value::Timestamp(*t),
            Self::Decimal { mantissa, scale } => Value::Decimal {
                mantissa: *mantissa,
                scale: u32::from(*scale),
            },
        })
    }
}

/// Read the one scalar a passthrough frame holds.
///
/// # Errors
///
/// A refusal when the bytes are not a frame of one scalar in the value
/// model. The engine wrote them, so that is an engine fault.
pub fn read(bytes: &[u8]) -> Result<Scalar, Refusal> {
    let frame = Frame::parse(bytes).map_err(|_| malformed("not a frame"))?;
    frame
        .visit(Reader)
        .map_err(|ReadError(what)| malformed(what))
}

/// An opened scalar as a host value.
///
/// # Errors
///
/// What the value is, when the SDK has no host value for it: an integer
/// wider than 128 bits, a date or timestamp outside the range, or a logical
/// type the SDK does not read.
pub fn scalar_of(ty: Option<Logical>, value: Physical<'_>) -> Result<Scalar, &'static str> {
    Ok(match (ty, value) {
        (None, Physical::Null) => Scalar::Null,
        (None, Physical::Bool(b)) => Scalar::Bool(b),
        (None, Physical::Int(i)) => Scalar::Int(i.to_i128().ok_or("an integer too wide")?),
        (None, Physical::Float(Float::F32(f))) => Scalar::Float(f64::from(f)),
        (None, Physical::Float(Float::F64(f))) => Scalar::Float(f),
        (None, Physical::Text(s)) => Scalar::Text(s.to_owned()),
        (None, Physical::Bytes(b)) => Scalar::Bytes(b.to_vec()),
        (Some(Logical::Date), Physical::Int(days)) => Scalar::Date(
            days.to_i128()
                .and_then(|d| i32::try_from(d).ok())
                .ok_or("a date outside the range")?,
        ),
        (Some(Logical::Timestamp(unit)), Physical::Int(count)) => Scalar::Timestamp(
            kinds::timestamp_nanos(unit, count).ok_or("a timestamp outside the range")?,
        ),
        (Some(Logical::Decimal { scale }), Physical::Int(mantissa)) => Scalar::Decimal {
            mantissa: mantissa.to_i128().ok_or("a decimal too wide")?,
            scale,
        },
        _ => return Err("a logical type the SDK does not read"),
    })
}

fn malformed(what: &str) -> Refusal {
    Refusal {
        code: "stack_encrypt_unknown".to_owned(),
        message: format!("the engine returned a passthrough that is not one scalar: {what}"),
        field: None,
        reason: None,
    }
}

/// Why a frame the engine returned could not be read: what was found.
#[derive(Debug)]
pub(crate) struct ReadError(pub(crate) &'static str);

impl SinkError for ReadError {
    fn source(_: SourceError) -> Self {
        ReadError("the frame could not be walked")
    }
}

struct Reader;

impl Sink for Reader {
    type Ok = Scalar;
    type Error = ReadError;
    type Seq = Never<Scalar, Reader>;
    type Map = Never<Scalar, Reader>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<Scalar, ReadError> {
        scalar_of(ty, value).map_err(ReadError)
    }

    fn typed_null(self, _: FixedType) -> Result<Scalar, ReadError> {
        Ok(Scalar::Null)
    }

    fn seq(self, _: Option<usize>) -> Result<Never<Scalar, Reader>, ReadError> {
        Err(ReadError("a sequence"))
    }

    fn map(self, _: Option<usize>) -> Result<Never<Scalar, Reader>, ReadError> {
        Err(ReadError("a map"))
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<Scalar, ReadError> {
        Err(ReadError("a nested passthrough"))
    }
}

/// A container sink that is never built, for a sink that refuses
/// containers: `O` is its `Ok`, `E` the sink of its elements and entries.
pub(crate) enum Never<O, E> {
    #[allow(dead_code)]
    Void(Infallible, PhantomData<fn() -> (O, E)>),
}

impl<O, E: Sink<Error = ReadError>> SeqSink for Never<O, E> {
    type Ok = O;
    type Error = ReadError;
    type Element<'s>
        = E
    where
        Self: 's;

    fn element(&mut self) -> Result<E, ReadError> {
        match self {
            Self::Void(never, _) => match *never {},
        }
    }

    fn end(self) -> Result<O, ReadError> {
        match self {
            Self::Void(never, _) => match never {},
        }
    }
}

impl<O, E: Sink<Error = ReadError>> MapSink for Never<O, E> {
    type Ok = O;
    type Error = ReadError;
    type Entry<'s>
        = E
    where
        Self: 's;

    fn entry(&mut self, _: &str) -> Result<E, ReadError> {
        match self {
            Self::Void(never, _) => match *never {},
        }
    }

    fn end(self) -> Result<O, ReadError> {
        match self {
            Self::Void(never, _) => match never {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stack_encrypt::dynamic::ValueFrame;

    #[test]
    fn every_kind_has_one_name() {
        for name in [
            "string",
            "int16",
            "int32",
            "int64",
            "float32",
            "float64",
            "bool",
            "decimal",
            "date",
            "timestamp",
        ] {
            assert_eq!(Kind::parse(name).map(Kind::name), Some(name));
        }
        assert_eq!(Kind::parse("json"), None);
    }

    #[test]
    fn an_integer_is_refused_outside_its_kinds_width() {
        assert!(scalar(Some(Kind::Int16), Value::Int(32_768)).is_err());
        assert!(scalar(Some(Kind::Int16), Value::Int(32_767)).is_ok());
        assert!(scalar(Some(Kind::Int32), Value::Int(i128::from(i32::MIN) - 1)).is_err());
        assert!(scalar(Some(Kind::Int64), Value::Int(i128::from(i64::MAX))).is_ok());
        assert_eq!(
            scalar(Some(Kind::Int64), Value::Int(i128::from(i64::MAX) + 1)),
            Err(Misfit::OutOfRange)
        );
    }

    #[test]
    fn a_float_that_does_not_round_trip_through_float32_is_refused() {
        assert!(scalar(Some(Kind::Float32), Value::Float(0.5)).is_ok());
        assert_eq!(
            scalar(Some(Kind::Float32), Value::Float(0.1)),
            Err(Misfit::NotRepresentable)
        );
        assert!(scalar(Some(Kind::Float64), Value::Float(0.1)).is_ok());
    }

    #[test]
    fn a_decimal_is_refused_outside_the_engines_bounds() {
        assert!(scalar(
            Some(Kind::Decimal),
            Value::Decimal {
                mantissa: 12_345,
                scale: 2
            }
        )
        .is_ok());
        assert_eq!(
            scalar(
                Some(Kind::Decimal),
                Value::Decimal {
                    mantissa: 1,
                    scale: 29
                }
            ),
            Err(Misfit::NotRepresentable)
        );
        assert_eq!(
            scalar(
                Some(Kind::Decimal),
                Value::Decimal {
                    mantissa: 1 << 96,
                    scale: 0
                }
            ),
            Err(Misfit::NotRepresentable)
        );
    }

    #[test]
    fn a_scalar_written_as_a_passthrough_reads_back() {
        for (kind, value, expected) in [
            (None, Value::Text("ada"), Scalar::Text("ada".to_owned())),
            (None, Value::Int(42), Scalar::Int(42)),
            (None, Value::Float(1.5), Scalar::Float(1.5)),
            (None, Value::Bool(true), Scalar::Bool(true)),
            (None, Value::Bytes(b"\x00\x01"), Scalar::Bytes(vec![0, 1])),
            (None, Value::Date(-25_567), Scalar::Date(-25_567)),
            (
                None,
                Value::Timestamp(1_000_000_000),
                Scalar::Timestamp(1_000_000_000),
            ),
            (
                None,
                Value::Decimal {
                    mantissa: 1_995,
                    scale: 2,
                },
                Scalar::Decimal {
                    mantissa: 1_995,
                    scale: 2,
                },
            ),
        ] {
            let frame = ValueFrame::of(Typed(kind, value)).unwrap();
            assert_eq!(read(frame.risky_ref()).unwrap(), expected, "{value:?}");
        }
    }

    #[test]
    fn a_frame_that_is_not_one_scalar_is_refused() {
        assert!(read(b"not a frame").is_err());
        let seq = ValueFrame::of(vec!["a", "b"]).unwrap();
        assert!(read(seq.risky_ref()).is_err());
    }
}
