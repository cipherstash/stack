//! The value-kinds fixture: one field of each kind a binding gained with
//! #1144 (`int8`, `int16`, `uint8`, `uint16`, `int128`, `uint128`, `date`,
//! `timestamp`, `decimal`), sealed by the data-plan lowering under a
//! deterministic key source, with each value's transport frame, each term,
//! and the equality queries vitaminc-normalize folds onto a stored term.
//!
//! `tests/fixtures/value_kinds.json` is what the Go SDK's `encrypt` tests
//! read: a generated Go type with the same context and identities opens the
//! sealed record, writes each value as the same frame, and derives the same
//! terms through the deterministic guest. Here the record path, the data
//! query path and the typed path are held to the same bytes.
//!
//! Regenerate with `STACK_ENCRYPT_UPDATE_FIXTURES=1 cargo test -p
//! stack-encrypt --all-features --test value_kinds`. Only the sealed bytes
//! change between runs (every leaf carries a fresh nonce); the frames and the
//! terms must not, and the test fails if they do. The schema is in the
//! README beside the fixture.
#![cfg(feature = "dynamic")]

mod common;

use std::path::PathBuf;

use common::frames::{frame as value_of, object, payload};
use common::{deterministic_cipher, DeterministicSource};
use serde_json::{json, Map, Value as Json};
use stack_encrypt::dynamic::record::{self, Plan as DataPlan};
use stack_encrypt::dynamic::{
    context, query_term, NoTargets, OpSpec, Operand, Reason, Scope, ValueFrame, ValueKind,
};
use stack_encrypt::target::IndexSpec;
use stack_encrypt::{CipherText, KeysetCipher, SealedValue, StackCipher, StackCipherText};
use vitaminc_aead::plaintext::{Int, Logical, Physical, Raw, TimeUnit};
use vitaminc_aead::plaintext::{MapSink, Sink};
use vitaminc_aead::{Encrypt, FrameWriter};

const SEED: [u8; 32] = *b"stack-encrypt value kinds v1    ";

/// The table both languages share: one field per kind, its outputs, the
/// value in the text a Go test parses, and the value as the engine holds
/// it.
struct Kind {
    field: &'static str,
    kind: ValueKind,
    outputs: &'static [&'static str],
    text: &'static str,
    value: Raw<'static>,
}

fn int(int: Int) -> Raw<'static> {
    Raw(None, Physical::Int(int))
}

fn date(days: i32) -> Raw<'static> {
    Raw(Some(Logical::Date), Physical::Int(Int::I32(days)))
}

fn instant(nanos: i128) -> Raw<'static> {
    Raw(
        Some(Logical::Timestamp(TimeUnit::Nanos)),
        Physical::Int(Int::I128(nanos)),
    )
}

fn decimal(mantissa: i128, scale: u8) -> Raw<'static> {
    Raw(
        Some(Logical::Decimal { scale }),
        Physical::Int(Int::I128(mantissa)),
    )
}

/// A value as the engine holds it: its frame.
fn value(raw: Raw<'_>) -> ValueFrame {
    ValueFrame::of(raw).expect("in the value model")
}

/// 2026-10-17T01:02:03.123456789Z, in nanoseconds since the epoch.
const AT: i128 = 1_792_198_923_123_456_789;

fn kinds() -> Vec<Kind> {
    vec![
        Kind {
            field: "i8",
            kind: ValueKind::Int8,
            outputs: &["c", "eq"],
            text: "-8",
            value: int(Int::I8(-8)),
        },
        Kind {
            field: "i16",
            kind: ValueKind::Int16,
            outputs: &["c", "eq", "ore"],
            text: "-300",
            value: int(Int::I16(-300)),
        },
        Kind {
            field: "u8",
            kind: ValueKind::UInt8,
            outputs: &["c", "eq"],
            text: "200",
            value: int(Int::U8(200)),
        },
        Kind {
            field: "u16",
            kind: ValueKind::UInt16,
            outputs: &["c", "eq", "ope"],
            text: "60000",
            value: int(Int::U16(60_000)),
        },
        Kind {
            field: "i128",
            kind: ValueKind::Int128,
            outputs: &["c", "eq", "ore"],
            text: "-170141183460469231731687303715884105728",
            value: int(Int::I128(i128::MIN)),
        },
        Kind {
            field: "u128",
            kind: ValueKind::UInt128,
            outputs: &["c", "eq", "ope"],
            text: "340282366920938463463374607431768211455",
            value: int(Int::U128(u128::MAX)),
        },
        Kind {
            field: "date",
            kind: ValueKind::Date,
            outputs: &["c", "eq", "ore"],
            text: "2024-02-29",
            value: date(19_782),
        },
        Kind {
            field: "at",
            kind: ValueKind::Timestamp,
            outputs: &["c", "eq", "ope"],
            text: "2026-10-17T01:02:03.123456789Z",
            value: instant(AT),
        },
        Kind {
            field: "amount",
            kind: ValueKind::Decimal,
            outputs: &["c", "eq", "ore"],
            text: "-1234.5600",
            value: decimal(-12_345_600, 4),
        },
    ]
}

/// Queries whose input differs from the stored value and whose terms are
/// the stored ones: vitaminc's equality and order encodings both drop a
/// decimal's trailing zeros and a timestamp's nanoseconds below the
/// microsecond.
fn folded_queries() -> Vec<(&'static str, &'static str, Raw<'static>)> {
    vec![
        ("amount", "-1234.56", decimal(-123_456, 2)),
        ("at", "2026-10-17T01:02:03.123456Z", instant(AT - 789)),
    ]
}

fn data_plan_json() -> Json {
    let mut plan = Map::new();
    for kind in kinds() {
        let _ = plan.insert(
            kind.field.into(),
            json!({
                "context": ["value_kinds", kind.field],
                "outputs": kind.outputs,
                "type": kind.kind.name(),
            }),
        );
    }
    Json::Object(plan)
}

fn data_plan() -> DataPlan {
    let fields = kinds()
        .into_iter()
        .map(|kind| {
            (
                kind.field,
                object(vec![
                    ("context", value_of(vec!["value_kinds", kind.field])),
                    ("outputs", value_of(kind.outputs.to_vec())),
                    ("type", value_of(kind.kind.name())),
                ]),
            )
        })
        .collect();
    record::plan(object(fields).risky_ref()).expect("the data plan parses")
}

/// The source as a binding hands it over: one frame, a map of the fields in
/// plan order.
fn source() -> ValueFrame {
    let mut bytes = Vec::new();
    {
        let kinds = kinds();
        let mut map = FrameWriter::new(&mut bytes)
            .map(Some(kinds.len()))
            .expect("a map");
        for kind in kinds {
            kind.value
                .visit(map.entry(kind.field).expect("an entry"))
                .expect("written");
        }
        map.end().expect("ended");
    }
    ValueFrame::from_bytes(&bytes).expect("in the value model")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn frame(raw: Raw<'_>) -> String {
    hex(value(raw).risky_ref())
}

fn term_bytes(node: StackCipherText) -> Vec<u8> {
    let CipherText::Passthrough(payload) = node else {
        panic!("a term rides as a passthrough");
    };
    vitaminc_aead_frame::serde::from_slice::<&[u8]>(&payload.0)
        .expect("a term is bytes")
        .to_vec()
}

/// A stored record as JSON: `"c"` is the leaf's frozen bytes and a term its
/// bytes, both hex.
fn json_of_record(tree: StackCipherText) -> Json {
    let CipherText::Map(fields) = tree else {
        panic!("a record is a map of fields");
    };
    let mut out = Map::new();
    for (name, node) in fields {
        let CipherText::Map(outputs) = node else {
            panic!("a field is a map of outputs");
        };
        let mut field = Map::new();
        for (key, node) in outputs {
            let value = match node {
                CipherText::Single(leaf) => json!(hex(&leaf.to_bytes())),
                term => json!(hex(&term_bytes(term))),
            };
            let _ = field.insert(key, value);
        }
        let _ = out.insert(name, Json::Object(field));
    }
    Json::Object(out)
}

fn record_of_json(record: &Json) -> StackCipherText {
    CipherText::Map(
        record
            .as_object()
            .expect("an object")
            .iter()
            .map(|(name, outputs)| {
                let nodes = outputs
                    .as_object()
                    .expect("an object")
                    .iter()
                    .map(|(key, value)| {
                        let bytes = unhex(value.as_str().expect("hex"));
                        let node = if key == "c" {
                            CipherText::Single(SealedValue::from_bytes(&bytes).expect("a leaf"))
                        } else {
                            CipherText::Passthrough(stack_encrypt::PassthroughFrame(payload(bytes)))
                        };
                        (key.clone(), node)
                    })
                    .collect();
                (name.clone(), CipherText::Map(nodes))
            })
            .collect(),
    )
}

/// Every term of a record by `field/key`, so two records compare on their
/// terms whatever their nonces.
fn terms_of(record: &Json) -> Map<String, Json> {
    let mut terms = Map::new();
    for (name, outputs) in record.as_object().expect("an object") {
        for (key, value) in outputs.as_object().expect("an object") {
            if key != "c" {
                let _ = terms.insert(format!("{name}/{key}"), value.clone());
            }
        }
    }
    terms
}

async fn seal(cipher: &StackCipher<DeterministicSource>, plan: &DataPlan) -> StackCipherText {
    record::encrypt(&cipher.default_keyset(), source(), plan)
        .expect("the source fits")
        .await
        .expect("the lowering seals")
}

/// The opened record's frame, hex, which is the source's frame byte for
/// byte when every value opens exactly as it was sealed: a decimal's scale
/// and a timestamp's nanoseconds count.
async fn open(
    cipher: &StackCipher<DeterministicSource>,
    tree: StackCipherText,
    plan: &DataPlan,
) -> String {
    hex(record::decrypt(Scope::Client(cipher), tree, plan, None)
        .expect("the record fits")
        .await
        .expect("the lowering opens it")
        .risky_ref())
}

fn expected_frames() -> String {
    hex(source().risky_ref())
}

async fn query(
    keyset: &KeysetCipher<'_, DeterministicSource>,
    plan: &DataPlan,
    field: &str,
    operator: OpSpec,
    input: Raw<'_>,
) -> Vec<u8> {
    let term = query_term(keyset, plan, field, operator, input, &NoTargets)
        .expect("the query fits")
        .await
        .expect("the term derives");
    match term.operand() {
        Operand::One(bytes) => bytes.clone(),
        Operand::Range { .. } => panic!("one term"),
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/value_kinds.json")
}

/// The record path, the data query path and the typed path derive one term
/// for each value, and the record opens to exactly what was sealed.
#[tokio::test]
async fn every_new_kind_seals_opens_and_queries_as_the_typed_path() {
    let cipher = deterministic_cipher(SEED).await;
    let keyset = cipher.default_keyset();
    let plan = data_plan();
    let sealed = json_of_record(seal(&cipher, &plan).await);
    assert_eq!(
        open(&cipher, record_of_json(&sealed), &plan).await,
        expected_frames(),
        "each value opens exactly as it was sealed"
    );
    for kind in kinds() {
        let stored = |key: &str| unhex(sealed[kind.field][key].as_str().expect("a term"));
        let eq = query(&keyset, &plan, kind.field, OpSpec::Eq, kind.value).await;
        assert_eq!(
            eq,
            stored("eq"),
            "{} eq: the query is the stored term",
            kind.field
        );
        let ctx = context(
            &vitaminc_aead_frame::serde::to_vec(&("value_kinds", kind.field)).expect("frames"),
        )
        .expect("context");
        let typed_eq = keyset
            .equality_term(kind.value, ctx.clone())
            .await
            .expect("the typed path derives");
        assert_eq!(
            eq,
            typed_eq.into_bytes().to_vec(),
            "{} eq: the typed path's term",
            kind.field
        );
        for (key, index) in [("ore", IndexSpec::Ore), ("ope", IndexSpec::Ope)] {
            if kind.outputs.contains(&key) {
                let lt = query(&keyset, &plan, kind.field, OpSpec::Lt, kind.value).await;
                assert_eq!(lt, stored(key), "{} {key}", kind.field);
                let probe = stack_encrypt::dynamic::term(&keyset, kind.value, &index, ctx.clone())
                    .await
                    .expect("derives");
                assert_eq!(probe, stored(key), "{} {key} probe", kind.field);
            }
        }
    }
    for (field, _, input) in folded_queries() {
        let stored = unhex(sealed[field]["eq"].as_str().expect("a term"));
        assert_eq!(
            query(&keyset, &plan, field, OpSpec::Eq, input).await,
            stored,
            "{field}: vitaminc-normalize folds the query onto the stored term"
        );
        let order = ["ore", "ope"]
            .into_iter()
            .find(|key| sealed[field].get(*key).is_some())
            .expect("each folded field has an order term");
        assert_eq!(
            query(&keyset, &plan, field, OpSpec::Lt, input).await,
            unhex(sealed[field][order].as_str().expect("a term")),
            "{field}: vitaminc-ore folds the query onto the stored {order} term"
        );
    }
}

/// A value of another width is not of the field's kind: sealing refuses
/// it, naming the field, where a query reads it as the field's kind.
#[tokio::test]
async fn a_value_of_another_width_is_refused_when_sealed() {
    let cipher = deterministic_cipher(SEED).await;
    let plan = data_plan();
    // The source with the `int8` field's value sent at 32 bits.
    let mut bytes = Vec::new();
    {
        let kinds = kinds();
        let mut map = FrameWriter::new(&mut bytes)
            .map(Some(kinds.len()))
            .expect("a map");
        for kind in kinds {
            let entry = map.entry(kind.field).expect("an entry");
            match kind.field {
                "i8" => int(Int::I32(-8)).visit(entry),
                _ => kind.value.visit(entry),
            }
            .expect("written");
        }
        map.end().expect("ended");
    }
    let keyset = cipher.default_keyset();
    let source = vitaminc_aead::Frame::parse(&bytes).expect("a frame");
    let refused = record::encrypt(&keyset, source, &plan);
    assert!(
        matches!(&refused, Err(error) if error.field() == Some("i8") && error.reason() == Some(Reason::FieldType)),
        "an int32 is not an int8: {:?}",
        refused.err()
    );
}

/// The committed fixture: the record sealed in an earlier run opens now, its
/// terms and frames are today's, and each folded query lands on its stored
/// term. With `STACK_ENCRYPT_UPDATE_FIXTURES=1` the record is sealed afresh
/// and the file written.
#[tokio::test]
async fn the_committed_fixture_opens_and_its_terms_are_todays() {
    let cipher = deterministic_cipher(SEED).await;
    let keyset = cipher.default_keyset();
    let plan = data_plan();
    let path = fixture_path();
    let values = || -> Json {
        kinds()
            .into_iter()
            .map(|kind| {
                json!({
                    "field": kind.field,
                    "type": kind.kind.name(),
                    "text": kind.text,
                    "frame": frame(kind.value),
                })
            })
            .collect()
    };

    if std::env::var_os("STACK_ENCRYPT_UPDATE_FIXTURES").is_some() {
        let record = json_of_record(seal(&cipher, &plan).await);
        let mut queries = Vec::new();
        for (field, text, input) in folded_queries() {
            let term = query(&keyset, &plan, field, OpSpec::Eq, input).await;
            queries.push(json!({
                "field": field,
                "operator": "eq",
                "text": text,
                "frame": frame(input),
                "term": hex(&term),
            }));
        }
        let fixture = json!({
            "_comment": "One field of each value kind added in #1144, sealed by the data-plan lowering under a deterministic key source, with each value's transport frame and the equality queries vitaminc-normalize folds onto a stored term. Read by tests/value_kinds.rs and the Go SDK's encrypt tests; the schema is in README.md beside this file. Regenerate with STACK_ENCRYPT_UPDATE_FIXTURES=1; do not edit by hand.",
            "key_source": { "kind": "deterministic-sha256", "seed": hex(&SEED) },
            "keyset_id": keyset.keyset_id().to_string(),
            "plan": data_plan_json(),
            "values": values(),
            "record": record,
            "queries": queries,
        });
        let mut text = serde_json::to_string_pretty(&fixture).expect("serialise");
        text.push('\n');
        std::fs::write(&path, text).expect("write the fixture");
    }

    let fixture: Json =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the fixture is committed"))
            .expect("the fixture is JSON");
    assert_eq!(fixture["key_source"]["seed"], json!(hex(&SEED)));
    assert_eq!(fixture["keyset_id"], json!(keyset.keyset_id().to_string()));
    assert_eq!(
        fixture["plan"],
        data_plan_json(),
        "the declaration is this one"
    );
    assert_eq!(fixture["values"], values(), "each value frames as it did");

    let record = &fixture["record"];
    let now = json_of_record(seal(&cipher, &plan).await);
    assert_eq!(terms_of(record), terms_of(&now), "the terms are today's");
    assert_eq!(
        open(&cipher, record_of_json(record), &plan).await,
        expected_frames(),
        "the committed record opens to the values"
    );
    let queries = fixture["queries"].as_array().expect("a list");
    assert_eq!(queries.len(), folded_queries().len());
    for (entry, (field, text, input)) in queries.iter().zip(folded_queries()) {
        assert_eq!(entry["field"], json!(field));
        assert_eq!(entry["text"], json!(text));
        assert_eq!(entry["frame"], json!(frame(input)));
        assert_eq!(entry["term"], record[field]["eq"], "{field}: folded");
        let term = query(&keyset, &plan, field, OpSpec::Eq, input).await;
        assert_eq!(json!(hex(&term)), entry["term"], "{field}: today's");
    }
}
