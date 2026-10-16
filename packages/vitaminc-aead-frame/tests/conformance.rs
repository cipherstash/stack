//! The shared binding corpus against the frame and the ciphertext codec:
//! every vector parses as one frame and writes back byte for byte, from its
//! own walk and from a scalar built independently with std, chrono and
//! rust_decimal, so a bug that reads and writes symmetrically wrong cannot
//! pass. Every malformed vector is refused, every normalized vector reads
//! and writes back as its canonical bytes, every malformed ciphertext is
//! refused by the ciphertext codec, and every leaf-type AAD vector has the
//! context bytes it pins.
//!
//! ADR 0001 section 3 decides the cases the corpus carries beyond the
//! original tag table: the `0xF3` envelope, no `CT_NONE`, a leap second
//! refused, a decimal negative zero read as zero, and `LeafTypeAad` under
//! its new label. Each such vector states its rule.

use std::collections::BTreeMap;

use vitaminc_aead::plaintext::kinds::chrono as conv;
use vitaminc_aead::{
    Float, Int, IntoAad, Kind, KnownLogical, LeafTypeAad, Logical, Physical, Plaintext, Raw,
    TimeUnit, UnknownLogicalId,
};
use vitaminc_aead_frame::{decode_ciphertext, to_frame, Frame};
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

fn int<T: std::str::FromStr>(value: &serde_json::Value) -> T {
    let text = value.as_str().expect("integers are JSON strings");
    text.parse()
        .unwrap_or_else(|_| panic!("{text} is out of range"))
}

/// A physical scalar from a vector's `kind` and `value`, for the kinds that
/// are physical, written through `f` so the borrow it needs lives here.
fn physical(
    kind: &str,
    value: &serde_json::Value,
    f: impl FnOnce(Physical<'_>) -> Vec<u8>,
) -> Vec<u8> {
    let text = || value.as_str().expect("JSON string");
    match kind {
        "null" => f(Physical::Null),
        "bool" => f(Physical::Bool(value.as_bool().expect("JSON bool"))),
        "int8" => f(Physical::Int(Int::I8(int(value)))),
        "uint8" => f(Physical::Int(Int::U8(int(value)))),
        "int16" => f(Physical::Int(Int::I16(int(value)))),
        "uint16" => f(Physical::Int(Int::U16(int(value)))),
        "int32" => f(Physical::Int(Int::I32(int(value)))),
        "uint32" => f(Physical::Int(Int::U32(int(value)))),
        "int64" => f(Physical::Int(Int::I64(int(value)))),
        "uint64" => f(Physical::Int(Int::U64(int(value)))),
        "int128" => f(Physical::Int(Int::I128(int(value)))),
        "uint128" => f(Physical::Int(Int::U128(int(value)))),
        "float32" => f(Physical::Float(Float::F32(
            value.as_f64().expect("JSON number") as f32,
        ))),
        "float64" => f(Physical::Float(Float::F64(
            value.as_f64().expect("JSON number"),
        ))),
        "string" => f(Physical::Text(text())),
        "bytes" => f(Physical::Bytes(&unhex(text()))),
        _ => panic!("{kind} is not a physical kind"),
    }
}

/// The frame of the value a vector's `kind` and `value` fields describe,
/// built without the frame reader.
fn expected(row: &serde_json::Value) -> Vec<u8> {
    let kind = row["kind"].as_str().expect("kind");
    let value = &row["value"];
    let text = || value.as_str().expect("JSON string");
    match kind {
        "undefined" => scalar(Some(Logical::Undefined), Physical::Null),
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
            let unit = match row["unit"].as_str() {
                None | Some("nanos") => TimeUnit::Nanos,
                Some("micros") => TimeUnit::Micros,
                Some("millis") => TimeUnit::Millis,
                Some("seconds") => TimeUnit::Seconds,
                Some(other) => panic!("unknown unit {other}"),
            };
            let count = conv::timestamp_count(unit, nanos).expect("exact in its unit");
            // The narrowest int the count fits, as a host would write it.
            let count = match i64::try_from(count) {
                Ok(v) => Int::I64(v),
                Err(_) => Int::I128(count),
            };
            scalar(Some(Logical::Timestamp(unit)), Physical::Int(count))
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
        "uuid" => {
            let bytes = unhex(&text().replace('-', ""));
            scalar(Some(Logical::Uuid), Physical::Bytes(&bytes))
        }
        "unknown" => {
            let byte = |field: &str| {
                let n = value[field].as_u64().expect(field);
                u8::try_from(n).unwrap_or_else(|_| panic!("{field} {n} is not one byte"))
            };
            let id = byte("id");
            let param = byte("param");
            let ty = Logical::from_wire(id, param).expect("an unknown id");
            assert!(matches!(ty, Logical::Unknown(_)), "{id} is a known id");
            physical(
                value["kind"].as_str().expect("physical kind"),
                &value["value"],
                |v| scalar(Some(ty), v),
            )
        }
        "array" if value.as_array().is_some_and(Vec::is_empty) => framed(Vec::<bool>::new()),
        "object" if value.as_object().is_some_and(|map| map.is_empty()) => {
            framed(BTreeMap::<String, bool>::new())
        }
        _ => physical(kind, value, |v| scalar(None, v)),
    }
}

fn corpus() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../testdata/value-conformance.json"))
        .expect("corpus JSON")
}

#[test]
fn every_vector_round_trips_through_the_frame() {
    let corpus = corpus();
    let mut tags = Vec::new();
    for row in corpus["vectors"].as_array().expect("vectors") {
        let name = &row["name"];
        let bytes = unhex(row["transport"].as_str().expect("transport"));
        tags.push(bytes[0]);
        let frame = Frame::parse(&bytes).expect("valid vector");
        assert_eq!(framed(frame), bytes, "{name}: written from its own walk");
        assert_eq!(
            expected(row),
            bytes,
            "{name}: written from an independently built value"
        );
    }
    for tag in (0x00..=0x14).chain([0xF3]) {
        assert!(tags.contains(&tag), "missing scalar tag {tag:02x}");
    }
}

#[test]
fn every_normalized_vector_reads_and_writes_as_its_canonical_bytes() {
    let corpus = corpus();
    let rows = corpus["normalized"].as_array().expect("normalized");
    assert!(!rows.is_empty());
    for row in rows {
        let name = &row["name"];
        assert!(row["rule"].is_string(), "{name}: states its rule");
        let bytes = unhex(row["transport"].as_str().expect("transport"));
        let canonical = unhex(row["reencode"].as_str().expect("reencode"));
        assert_ne!(
            bytes, canonical,
            "{name}: the vector is not already canonical"
        );
        let frame = Frame::parse(&bytes).expect("reads");
        assert_eq!(
            framed(frame),
            canonical,
            "{name}: written from its own walk"
        );
        // Both spellings build the canonical bytes.
        assert_eq!(expected(row), canonical, "{name}: from `value`");
        let mut canonical_row = row.clone();
        canonical_row["value"] = row["reencode_value"].clone();
        assert_eq!(
            expected(&canonical_row),
            canonical,
            "{name}: from `reencode_value`"
        );
    }
}

#[test]
fn every_malformed_vector_is_refused() {
    let corpus = corpus();
    for row in corpus["malformed"].as_array().expect("malformed") {
        let bytes = unhex(row["transport"].as_str().expect("transport"));
        assert!(Frame::parse(&bytes).is_err(), "{}", row["name"]);
    }
}

#[test]
fn every_malformed_ciphertext_is_refused() {
    let corpus = corpus();
    let rows = corpus["ciphertext_malformed"]
        .as_array()
        .expect("ciphertext_malformed");
    assert!(!rows.is_empty());
    for row in rows {
        let bytes = unhex(row["transport"].as_str().expect("transport"));
        assert!(
            decode_ciphertext::<Vec<u8>>(&bytes).is_err(),
            "{}",
            row["name"]
        );
    }
}

#[test]
fn every_leaf_type_aad_vector_has_its_context_bytes() {
    let corpus = corpus();
    let section = &corpus["leaf_type_aad"];
    assert!(section["rule"].is_string());
    let rows = section["vectors"].as_array().expect("vectors");
    assert!(rows.len() >= 2, "with and without a logical id");
    let mut seen_without = false;
    let mut seen_kinds = std::collections::BTreeSet::new();
    // (base, kind, id) -> context: the parameter is not bound, so two
    // vectors that differ only in it must share one context.
    let mut by_binding: BTreeMap<(String, String, u64), (Vec<u8>, u64)> = BTreeMap::new();
    // Bindings shared by two vectors with different parameters.
    let mut shared_across_params = 0;
    for row in rows {
        let name = &row["name"];
        let base = row["base"].as_str().expect("base");
        let kind = match row["kind"].as_str().expect("kind") {
            "null" => Kind::Null,
            "bool" => Kind::Bool,
            "int" => Kind::Int,
            "float" => Kind::Float,
            "text" => Kind::Text,
            "bytes" => Kind::Bytes,
            other => panic!("{name}: unknown kind {other}"),
        };
        // The context binds the logical id and not its parameter, so the
        // row's `param` plays no part here (see the rule on each row).
        let id = row["logical"]["id"]
            .as_u64()
            .map(|id| u8::try_from(id).expect("a one-byte id"));
        seen_without |= id.is_none();
        let context = match id {
            None => LeafTypeAad::physical(base, kind),
            Some(id) => match KnownLogical::from_id(id) {
                Some(known) => {
                    assert_eq!(known.kind(), kind, "{name}: a known id over the wrong kind");
                    LeafTypeAad::logical(base, known)
                }
                None => {
                    let unknown = UnknownLogicalId::new(id)
                        .unwrap_or_else(|| panic!("{name}: {id} is a known id"));
                    LeafTypeAad::unknown(base, kind, unknown)
                }
            },
        }
        .into_aad();
        let expected = unhex(row["context"].as_str().expect("context"));
        assert_eq!(context.as_bytes(), expected, "{name}");
        seen_kinds.insert(row["kind"].as_str().expect("kind").to_owned());
        let id = row["logical"]["id"].as_u64().unwrap_or(0);
        let binding = (
            base.to_owned(),
            row["kind"].as_str().expect("kind").to_owned(),
            id,
        );
        let param = row["logical"]["param"].as_u64().unwrap_or(0);
        if let Some((other, other_param)) = by_binding.insert(binding, (expected.clone(), param)) {
            assert_eq!(
                other, expected,
                "{name}: the parameter must not change the context"
            );
            if other_param != param {
                shared_across_params += 1;
            }
        }
    }
    assert!(seen_without);
    // Every kind byte of the cross-language commitment is pinned.
    assert_eq!(
        seen_kinds.into_iter().collect::<Vec<_>>(),
        ["bool", "bytes", "float", "int", "null", "text"]
    );
    assert!(
        shared_across_params >= 1,
        "at least one pair of vectors that differ only in the parameter"
    );
}
