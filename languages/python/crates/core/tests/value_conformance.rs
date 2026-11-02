//! vitaminc's shared value corpus against the SDK's value conversion.
//!
//! The corpus (`testdata/value-conformance.json`, see `testdata/README.md`)
//! gives each vector a host value, its kind, and the exact bytes of its
//! frame. For every kind the SDK writes, the value written through
//! [`values::write`] must give those bytes, and the bytes read through
//! [`values::read`] must give the value back. Every malformed vector must
//! be refused, and every normalized vector must read as its canonical
//! value.
//!
//! A vector of a kind the SDK does not write is skipped by name, so a new
//! vector in the corpus fails here until it is handled or listed.

use serde_json::Value as Json;
use stack_encrypt::dynamic::ValueFrame;
use stackencrypt_core::values::{self, Kind, Scalar, Typed};

const CORPUS: &str = include_str!("../testdata/value-conformance.json");

/// The vectors whose kind the SDK never writes: no Python type maps to it
/// (`int8`, the unsigned and 128-bit integers, `uuid`), it is not a scalar
/// (`array`, `object`), or it is a timestamp in a unit other than the
/// nanoseconds the SDK writes.
const NOT_WRITTEN: &[&str] = &[
    "null",
    "undefined",
    "int8",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "int128",
    "uint128",
    "empty-array",
    "empty-object",
    "uuid",
    "timestamp-millis",
    "timestamp-seconds",
    "timestamp-micros",
    "unknown-logical",
];

fn corpus() -> Json {
    serde_json::from_str(CORPUS).expect("the corpus is JSON")
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

/// The SDK's kind for a vector, its value, and the scalar it reads back as.
/// `None` for a vector the SDK does not write.
fn host(vector: &Json, text: &mut String, bytes: &mut Vec<u8>) -> Option<(Option<Kind>, Scalar)> {
    let value = &vector["value"];
    let int = || {
        value
            .as_str()
            .expect("an integer as text")
            .parse::<i128>()
            .expect("an integer")
    };
    Some(match vector["kind"].as_str().expect("a kind") {
        "bool" => (
            Some(Kind::Bool),
            Scalar::Bool(value.as_bool().expect("a bool")),
        ),
        "int16" => (Some(Kind::Int16), Scalar::Int(int())),
        "int32" => (Some(Kind::Int32), Scalar::Int(int())),
        "int64" => (Some(Kind::Int64), Scalar::Int(int())),
        "float32" => (
            Some(Kind::Float32),
            Scalar::Float(value.as_f64().expect("a float")),
        ),
        "float64" => (
            Some(Kind::Float64),
            Scalar::Float(value.as_f64().expect("a float")),
        ),
        "string" => {
            *text = value.as_str().expect("text").to_owned();
            (Some(Kind::String), Scalar::Text(text.clone()))
        }
        // A Python `bytes` field is a passthrough: no EQL type takes bytes.
        "bytes" => {
            *bytes = unhex(value.as_str().expect("hex"));
            (None, Scalar::Bytes(bytes.clone()))
        }
        "date" => (
            Some(Kind::Date),
            Scalar::Date(days(value.as_str().expect("a date"))),
        ),
        "timestamp" if vector.get("unit").is_none() => (
            Some(Kind::Timestamp),
            Scalar::Timestamp(nanos(value.as_str().expect("a timestamp"))),
        ),
        "decimal" => {
            let (mantissa, scale) = decimal(value.as_str().expect("a decimal"));
            (Some(Kind::Decimal), Scalar::Decimal { mantissa, scale })
        }
        _ => return None,
    })
}

/// Days since 1970-01-01 of a proleptic Gregorian date, `[+-]YYYY-MM-DD`.
fn days(date: &str) -> i32 {
    let (sign, date) = match date.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, date.strip_prefix('+').unwrap_or(date)),
    };
    let mut parts = date.split('-');
    let mut next = || {
        parts
            .next()
            .expect("a date part")
            .parse::<i64>()
            .expect("a number")
    };
    let (year, month, day) = (sign * next(), next(), next());
    // Howard Hinnant's days_from_civil.
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let of_era = year - era * 400;
    let of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let of_era_days = of_era * 365 + of_era / 4 - of_era / 100 + of_year;
    i32::try_from(era * 146_097 + of_era_days - 719_468).expect("a date in range")
}

/// Nanoseconds since the Unix epoch of `[+-]YYYY-MM-DDTHH:MM:SS[.fraction]Z`.
fn nanos(timestamp: &str) -> i128 {
    let (date, time) = timestamp.split_once('T').expect("a T");
    let time = time.strip_suffix('Z').expect("a Z");
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    let mut parts = clock
        .split(':')
        .map(|part| part.parse::<i128>().expect("a number"));
    let mut next = || parts.next().expect("a clock part");
    let seconds = next() * 3600 + next() * 60 + next();
    let fraction = format!("{fraction:0<9}")
        .parse::<i128>()
        .expect("a fraction");
    (i128::from(days(date)) * 86_400 + seconds) * 1_000_000_000 + fraction
}

/// The mantissa and scale of decimal text, such as `-1.50`.
fn decimal(text: &str) -> (i128, u8) {
    let scale = text
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len());
    let mantissa = text.replace('.', "").parse::<i128>().expect("a mantissa");
    (mantissa, u8::try_from(scale).expect("a scale"))
}

#[test]
fn every_vector_the_sdk_writes_gives_its_bytes_and_reads_back() {
    let corpus = corpus();
    let mut written = 0;
    for vector in corpus["vectors"].as_array().expect("vectors") {
        let name = vector["name"].as_str().expect("a name");
        let (mut text, mut bytes) = (String::new(), Vec::new());
        let Some((kind, expected)) = host(vector, &mut text, &mut bytes) else {
            assert!(
                NOT_WRITTEN.contains(&name),
                "{name}: a new kind, not handled"
            );
            continue;
        };
        assert!(
            !NOT_WRITTEN.contains(&name),
            "{name}: listed as not written"
        );
        let transport = unhex(vector["transport"].as_str().expect("transport"));

        let frame = ValueFrame::of(Typed(kind, expected.value().expect("not a null")))
            .unwrap_or_else(|error| panic!("{name}: refused: {error}"));

        assert_eq!(
            frame.risky_ref(),
            &transport[..],
            "{name}: the written bytes"
        );
        assert_eq!(
            values::read(&transport).unwrap(),
            expected,
            "{name}: the read value"
        );
        written += 1;
    }
    // Every scalar kind the SDK has, from the corpus at this commit.
    assert_eq!(written, 19);
}

#[test]
fn every_malformed_vector_is_refused() {
    let corpus = corpus();
    for vector in corpus["malformed"].as_array().expect("malformed") {
        let name = vector["name"].as_str().expect("a name");
        let transport = unhex(vector["transport"].as_str().expect("transport"));
        assert!(values::read(&transport).is_err(), "{name}: read");
    }
}

#[test]
fn every_normalized_vector_reads_as_its_canonical_value() {
    let corpus = corpus();
    let mut written = 0;
    for vector in corpus["normalized"].as_array().expect("normalized") {
        let name = vector["name"].as_str().expect("a name");
        let transport = unhex(vector["transport"].as_str().expect("transport"));
        let reencode = unhex(vector["reencode"].as_str().expect("reencode"));
        assert_ne!(
            transport, reencode,
            "{name}: a vector that normalizes nothing"
        );
        // The canonical value, as the corpus states it, read as a vector.
        let canonical = serde_json::json!({
            "kind": vector["kind"],
            "value": vector["reencode_value"],
        });
        let (mut text, mut bytes) = (String::new(), Vec::new());
        let expected = match vector["kind"].as_str() {
            // A typed null is a null leaf padded to its type's length: it
            // reads as a plain null.
            Some("null") => None,
            _ => Some(host(&canonical, &mut text, &mut bytes).expect("a kind the SDK writes")),
        };

        let read =
            values::read(&transport).unwrap_or_else(|error| panic!("{name}: refused: {error:?}"));

        match expected {
            None => assert_eq!(read, Scalar::Null, "{name}"),
            Some((kind, expected)) => {
                assert_eq!(read, expected, "{name}: the read value");
                // Written back, the canonical value is the canonical bytes.
                let frame =
                    ValueFrame::of(Typed(kind, read.value().expect("not a null"))).expect("frames");
                assert_eq!(
                    frame.risky_ref(),
                    &reencode[..],
                    "{name}: the written bytes"
                );
                written += 1;
            }
        }
    }
    // decimal-negative-zero, at this commit.
    assert_eq!(written, 1);
}
