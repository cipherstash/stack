//! The shared binding corpus against the frame: every vector parses as one
//! frame and writes back byte for byte from its own walk, and from a scalar
//! built independently with std, chrono and rust_decimal, so a bug that
//! reads and writes symmetrically wrong cannot pass. Every malformed vector
//! is refused.
//!
//! Two vectors carry transitional fields until #414 rewrites the corpus to
//! ADR 0001's rules: `frame: refused` (a leap second, which has no count)
//! and `frame_reencode` (a decimal negative zero, which reads as zero).

use std::collections::BTreeMap;

use vitaminc_aead::plaintext::kinds::chrono as conv;
use vitaminc_aead::{Float, Int, Logical, Physical, Plaintext, Raw, TimeUnit};
use vitaminc_aead_frame::{to_frame, Frame};
use vitaminc_protected::Controlled;

fn unhex(text: &str) -> Vec<u8> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    assert!(rest.is_empty(), "odd-length hex: {text}");
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16).expect("hex"))
        .collect()
}

fn framed<P: Plaintext>(p: P) -> Vec<u8> {
    to_frame(p).expect("frames").risky_ref().clone()
}

fn scalar(ty: Option<Logical>, v: Physical<'_>) -> Vec<u8> {
    framed(Raw(ty, v))
}

/// The frame of the value a vector's `kind` and `value` fields describe,
/// built without the frame reader.
fn expected(kind: &str, value: &serde_json::Value) -> Vec<u8> {
    fn int<T: std::str::FromStr>(value: &serde_json::Value) -> T {
        let text = value.as_str().expect("integers are JSON strings");
        text.parse()
            .unwrap_or_else(|_| panic!("{text} is out of range"))
    }
    let text = || value.as_str().expect("JSON string");
    let plain = |v: Physical<'_>| scalar(None, v);
    match kind {
        "null" => plain(Physical::Null),
        "undefined" => scalar(Some(Logical::Undefined), Physical::Null),
        "bool" => plain(Physical::Bool(value.as_bool().expect("JSON bool"))),
        "int8" => plain(Physical::Int(Int::I8(int(value)))),
        "uint8" => plain(Physical::Int(Int::U8(int(value)))),
        "int16" => plain(Physical::Int(Int::I16(int(value)))),
        "uint16" => plain(Physical::Int(Int::U16(int(value)))),
        "int32" => plain(Physical::Int(Int::I32(int(value)))),
        "uint32" => plain(Physical::Int(Int::U32(int(value)))),
        "int64" => plain(Physical::Int(Int::I64(int(value)))),
        "uint64" => plain(Physical::Int(Int::U64(int(value)))),
        "int128" => plain(Physical::Int(Int::I128(int(value)))),
        "uint128" => plain(Physical::Int(Int::U128(int(value)))),
        "float32" => plain(Physical::Float(Float::F32(
            value.as_f64().expect("JSON number") as f32,
        ))),
        "float64" => plain(Physical::Float(Float::F64(
            value.as_f64().expect("JSON number"),
        ))),
        "string" => plain(Physical::Text(text())),
        "bytes" => plain(Physical::Bytes(&unhex(text()))),
        "date" => {
            let date = chrono::NaiveDate::parse_from_str(text(), "%Y-%m-%d").expect("valid date");
            scalar(
                Some(Logical::Date),
                Physical::Int(Int::I32(conv::date_days(date))),
            )
        }
        "timestamp" => {
            let instant: chrono::DateTime<chrono::Utc> = text().parse().expect("valid timestamp");
            let nanos = conv::timestamp_nanos(instant).expect("not a leap second");
            scalar(
                Some(Logical::Timestamp(TimeUnit::Nanos)),
                Physical::Int(Int::I128(nanos)),
            )
        }
        "decimal" => {
            // A negative zero parses as zero, which is what the leaf codec
            // writes (ADR 0001 section 3).
            let decimal = rust_decimal::Decimal::from_str_exact(text()).expect("valid decimal");
            scalar(
                Some(Logical::Decimal {
                    scale: decimal.scale() as u8,
                }),
                Physical::Int(Int::I128(decimal.mantissa())),
            )
        }
        "array" if value.as_array().is_some_and(Vec::is_empty) => framed(Vec::<bool>::new()),
        "object" if value.as_object().is_some_and(|map| map.is_empty()) => {
            framed(BTreeMap::<String, bool>::new())
        }
        _ => panic!("teach expected() the {kind} vector {value}"),
    }
}

#[test]
fn shared_binding_corpus_covers_every_tag() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../testdata/value-conformance.json"))
            .expect("corpus JSON");
    let mut tags = Vec::new();
    for row in corpus["vectors"].as_array().expect("vectors") {
        let name = &row["name"];
        let bytes = unhex(row["transport"].as_str().expect("transport"));
        tags.push(bytes[0]);
        if row["frame"] == "refused" {
            assert!(
                Frame::parse(&bytes).is_err(),
                "{name}: the frame refuses it"
            );
            continue;
        }
        let want = row["frame_reencode"]
            .as_str()
            .map_or_else(|| bytes.clone(), unhex);
        let frame = Frame::parse(&bytes).expect("valid vector");
        assert_eq!(framed(frame), want, "{name}: written from its own walk");
        assert_eq!(
            expected(row["kind"].as_str().expect("kind"), &row["value"]),
            want,
            "{name}: written from an independently built value"
        );
    }
    for tag in 0x00..=0x14 {
        assert!(tags.contains(&tag), "missing scalar tag {tag:02x}");
    }
    for row in corpus["malformed"].as_array().expect("malformed") {
        let bytes = unhex(row["transport"].as_str().expect("transport"));
        assert!(Frame::parse(&bytes).is_err(), "{}", row["name"]);
    }
}
