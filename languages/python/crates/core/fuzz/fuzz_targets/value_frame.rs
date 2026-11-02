#![no_main]

// Fuzz the Python SDK's value conversion, both ways.
//
// Write: an arbitrary kind and host value go through `values::scalar`, the
// check `encrypt` and `query` run. A value it refuses is fine. A value it
// accepts must frame with no error, and must read back through
// `values::read` as the same value, narrowed to its kind. For a kind with a
// plain Rust type, the frame must also be the bytes `ValueFrame::of` gives
// that type: an independent writer, so a conversion that writes and reads
// symmetrically wrong is still caught.
//
// Read: arbitrary bytes go through `values::read`, as a passthrough the
// engine returns does. It must never panic. A scalar it accepts that the
// write check also accepts must write back as a passthrough and read as
// itself.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use stack_encrypt::dynamic::ValueFrame;
use stackencrypt_core::values::{self, Kind, Scalar, Typed, Value};

#[derive(Arbitrary, Debug)]
enum Input {
    Write(MirrorKind, Host),
    Read(Vec<u8>),
}

/// `Option<Kind>`: `Passthrough` is `None`.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum MirrorKind {
    Passthrough,
    String,
    Int16,
    Int32,
    Int64,
    Float32,
    Float64,
    Bool,
    Date,
    Timestamp,
    Decimal,
}

impl MirrorKind {
    fn kind(self) -> Option<Kind> {
        Some(match self {
            Self::Passthrough => return None,
            Self::String => Kind::String,
            Self::Int16 => Kind::Int16,
            Self::Int32 => Kind::Int32,
            Self::Int64 => Kind::Int64,
            Self::Float32 => Kind::Float32,
            Self::Float64 => Kind::Float64,
            Self::Bool => Kind::Bool,
            Self::Date => Kind::Date,
            Self::Timestamp => Kind::Timestamp,
            Self::Decimal => Kind::Decimal,
        })
    }
}

/// `Value`, owned.
#[derive(Arbitrary, Debug)]
enum Host {
    Text(String),
    Int(i128),
    Float(f64),
    Bool(bool),
    Bytes(Vec<u8>),
    Date(i64),
    Timestamp(i128),
    Decimal { mantissa: i128, scale: u32 },
}

impl Host {
    fn value(&self) -> Value<'_> {
        match self {
            Self::Text(s) => Value::Text(s),
            Self::Int(i) => Value::Int(*i),
            Self::Float(f) => Value::Float(*f),
            Self::Bool(b) => Value::Bool(*b),
            Self::Bytes(b) => Value::Bytes(b),
            Self::Date(d) => Value::Date(*d),
            Self::Timestamp(t) => Value::Timestamp(*t),
            Self::Decimal { mantissa, scale } => Value::Decimal {
                mantissa: *mantissa,
                scale: *scale,
            },
        }
    }
}

/// The scalar an accepted value reads back as: the value, narrowed to its
/// kind.
fn expected(kind: Option<Kind>, value: Value<'_>) -> Scalar {
    match (kind, value) {
        (_, Value::Text(s)) => Scalar::Text(s.to_owned()),
        (_, Value::Int(i)) => Scalar::Int(i),
        (Some(Kind::Float32), Value::Float(f)) => Scalar::Float(f64::from(f as f32)),
        (_, Value::Float(f)) => Scalar::Float(f),
        (_, Value::Bool(b)) => Scalar::Bool(b),
        (_, Value::Bytes(b)) => Scalar::Bytes(b.to_vec()),
        (_, Value::Date(d)) => Scalar::Date(i32::try_from(d).expect("an accepted date")),
        (_, Value::Timestamp(t)) => Scalar::Timestamp(t),
        (_, Value::Decimal { mantissa, scale }) => Scalar::Decimal {
            mantissa,
            scale: u8::try_from(scale).expect("an accepted scale"),
        },
    }
}

/// The frame of the plain Rust type for `kind`, where there is one.
fn independent(kind: Option<Kind>, value: Value<'_>) -> Option<ValueFrame> {
    Some(
        match (kind, value) {
            (Some(Kind::String), Value::Text(s)) => ValueFrame::of(s),
            (Some(Kind::Int16), Value::Int(i)) => ValueFrame::of(i16::try_from(i).ok()?),
            (Some(Kind::Int32), Value::Int(i)) => ValueFrame::of(i32::try_from(i).ok()?),
            (Some(Kind::Int64), Value::Int(i)) => ValueFrame::of(i64::try_from(i).ok()?),
            (Some(Kind::Float32), Value::Float(f)) => ValueFrame::of(f as f32),
            (Some(Kind::Float64), Value::Float(f)) => ValueFrame::of(f),
            (Some(Kind::Bool), Value::Bool(b)) => ValueFrame::of(b),
            _ => return None,
        }
        .expect("a plain Rust value frames"),
    )
}

/// Equal, with a NaN equal to a NaN: the value model keeps NaN.
fn same(a: &Scalar, b: &Scalar) -> bool {
    match (a, b) {
        (Scalar::Float(a), Scalar::Float(b)) => {
            a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan())
        }
        _ => a == b,
    }
}

fuzz_target!(|input: Input| {
    match input {
        Input::Write(kind, host) => {
            let (kind, value) = (kind.kind(), host.value());
            if values::scalar(kind, value).is_err() {
                return;
            }
            let frame = ValueFrame::of(Typed(kind, value)).expect("an accepted value frames");
            let read = values::read(frame.risky_ref()).expect("a written frame reads");
            assert!(
                same(&read, &expected(kind, value)),
                "{read:?} for {kind:?} {value:?}"
            );
            if let Some(plain) = independent(kind, value) {
                assert_eq!(frame.risky_ref(), plain.risky_ref(), "{kind:?} {value:?}");
            }
        }
        Input::Read(bytes) => {
            let Ok(read) = values::read(&bytes) else {
                return;
            };
            let Some(value) = read.value() else {
                return;
            };
            // `values::read` range-checks a timestamp, but not a date or a
            // decimal: it reads any `i32` day count, and any scale and
            // mantissa. `values::scalar` refuses a date outside the engine's
            // range, a scale over 28, and a mantissa over 96 bits. The engine
            // only returns a passthrough the SDK wrote, so read accepting
            // more than write is not a defect.
            if values::scalar(None, value).is_err() {
                return;
            }
            let frame = ValueFrame::of(Typed(None, value)).expect("a read scalar writes back");
            let again = values::read(frame.risky_ref()).expect("a written frame reads");
            assert!(same(&again, &read), "{again:?} after {read:?}");
        }
    }
});
