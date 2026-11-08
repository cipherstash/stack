//! The shared value-kind boundary profile: every kind the engine names, at
//! its edges, through the record path, with native data-key observations.
//! See conformance/stack-encrypt/values-contract.md.
#![cfg(feature = "dynamic")]
mod common;

use common::{
    conformance::{canonical_float, refusal, value, Input},
    frames::{frame, object},
    hex,
};
use serde::Deserialize;
use serde_json::json;
use stack_encrypt::dynamic::{self, record, NoTargets, OpSpec, Operand, Scope, ValueFrame};
use stack_encrypt::{AsProtectedRef as _, CipherText, StackCipherText};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::Ordering,
};

const KINDS: [&str; 19] = [
    "bool",
    "int8",
    "int16",
    "int32",
    "int64",
    "int128",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "uint128",
    "float32",
    "float64",
    "decimal",
    "date",
    "timestamp",
    "string",
    "bytes",
    "null",
];

/// The host constructions the Go runner knows how to make and the engine
/// never sees. A name outside this list is a corpus error in both runners.
const HOST_CONSTRUCTIONS: [&str; 6] = [
    "zero_date",
    "decimal_scale_29",
    "timestamp_year_300000",
    "complex128",
    "map_int_key",
    "channel",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    version: u32,
    profile: String,
    required_capabilities: Vec<String>,
    cases: Vec<Case>,
    host_conversions: Vec<HostCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    kind: String,
    null: String,
    outputs: Vec<String>,
    input: Input,
    /// The input's frozen typed transport frame, hex. Required unless the
    /// input is null.
    frame: Option<String>,
    /// A value of the kind sealed in a second row: with a sealed null, the
    /// row whose ciphertext length the null's must equal.
    companion: Option<Input>,
    /// Another spelling whose equality query must derive the stored term.
    equal_query: Option<Input>,
    /// Stored indexes no query operator answers for this kind: the term is
    /// stored, and a query of it is refused as `operator_not_answered`.
    #[serde(default)]
    unanswered: Vec<String>,
    expected_error: Option<ExpectedError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostCase {
    id: String,
    language: String,
    kind: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedError {
    code: String,
    reason: String,
    field: String,
}

/// A stored row's outputs for `value`: the ciphertext leaf's length and the
/// term bytes under each index key, or `None` when nothing is stored.
fn stored(row: &StackCipherText) -> Option<(usize, BTreeMap<String, Vec<u8>>)> {
    let CipherText::Map(fields) = row else {
        panic!("record")
    };
    assert!(fields.iter().all(|(name, _)| name == "value"));
    let (_, node) = fields.first()?;
    let CipherText::Map(outputs) = node else {
        panic!("outputs")
    };
    let mut length = None;
    let mut terms = BTreeMap::new();
    for (key, output) in outputs {
        match (key.as_str(), output) {
            ("c", CipherText::Single(leaf)) => length = Some(leaf.to_bytes().len()),
            ("c", _) => panic!("ciphertext is not one leaf"),
            (index, CipherText::Passthrough(term)) => {
                let bytes: &[u8] = vitaminc_aead_frame::serde::from_slice(&term.0).unwrap();
                terms.insert(index.to_owned(), bytes.to_vec());
            }
            (key, _) => panic!("{key}: not a term"),
        }
    }
    Some((length.expect("ciphertext stored"), terms))
}

fn row(input: &Input) -> ValueFrame {
    object(vec![("value", value(input))])
}

#[tokio::test]
async fn shared_record_value_profile() {
    let corpus: Corpus = serde_json::from_str(include_str!(
        "../../../conformance/stack-encrypt/v1/record-values-v1.cases.json"
    ))
    .unwrap();
    assert_eq!(corpus.version, 1);
    assert_eq!(corpus.profile, "record-values-v1");
    assert_eq!(
        corpus.required_capabilities,
        ["records", "equality", "value-kinds", "null-policies"]
    );
    assert!(!corpus.cases.is_empty() && !corpus.host_conversions.is_empty());
    let mut ids = BTreeSet::new();
    // Host conversions are refused by a binding's host before the engine
    // sees a value. Native Rust has no such layer: the corpus is checked
    // for shape here and executed by the language each case names.
    for case in &corpus.host_conversions {
        assert!(!case.id.is_empty() && ids.insert(case.id.clone()));
        assert_eq!(case.language, "go", "{}: unknown runner", case.id);
        assert!(KINDS.contains(&case.kind.as_str()), "{}", case.id);
        assert!(
            HOST_CONSTRUCTIONS.contains(&case.value.as_str()),
            "{}: unknown host construction {}",
            case.id,
            case.value
        );
    }
    let (cipher, generates, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let mut failures = Vec::new();
    for case in &corpus.cases {
        assert!(!case.id.is_empty() && ids.insert(case.id.clone()));
        eprintln!("value conformance: {}", case.id);
        assert!(["", "sql", "sealed"].contains(&case.null.as_str()));
        assert!(KINDS[..18].contains(&case.kind.as_str()), "{}", case.id);
        assert!(KINDS.contains(&case.input.kind.as_str()), "{}", case.id);
        assert!(!case.outputs.is_empty() && case.outputs[0] == "c");
        let is_null = case.input.kind == "null";
        assert_eq!(case.frame.is_none(), is_null, "{}: frame", case.id);
        let mut spec = json!({"context": ["conformance", "value"], "outputs": case.outputs, "type": case.kind});
        if !case.null.is_empty() {
            spec["null"] = json!(case.null);
        }
        let plan = record::plan(
            vitaminc_aead_frame::serde::to_vec(&json!({"value": spec}))
                .unwrap()
                .as_protected_ref(),
        )
        .unwrap();
        generates.store(0, Ordering::SeqCst);
        retrieves.store(0, Ordering::SeqCst);
        let input = value(&case.input);
        if let Some(frozen) = &case.frame {
            let actual = hex(input.risky_ref());
            if &actual != frozen {
                failures.push(format!("{}: frame {actual}, frozen {frozen}", case.id));
            }
        }
        if let Some(expected) = &case.expected_error {
            assert!(case.companion.is_none() && case.equal_query.is_none());
            let error = record::encrypt(&keyset, frame(vec![row(&case.input)]), &plan)
                .err()
                .expect("refused before any pending operation");
            refusal(&error, &expected.code, &expected.reason, &expected.field);
            assert_eq!(generates.load(Ordering::SeqCst), 0, "{}", case.id);
            assert_eq!(retrieves.load(Ordering::SeqCst), 0, "{}", case.id);
            continue;
        }
        let mut rows = vec![row(&case.input)];
        rows.extend(case.companion.iter().map(row));
        let sealed = record::encrypt(&keyset, frame(rows), &plan)
            .unwrap()
            .await
            .unwrap();
        let CipherText::Sequence(batch) = &sealed else {
            panic!("batch")
        };
        let outputs: Vec<_> = batch.iter().map(stored).collect();
        let omitted = is_null && case.null == "sql";
        assert_eq!(outputs[0].is_none(), omitted, "{}: storage", case.id);
        let stores = outputs.iter().any(Option::is_some);
        assert_eq!(
            generates.load(Ordering::SeqCst),
            usize::from(stores),
            "{}: one batched generation",
            case.id
        );
        for (index, (_, terms)) in outputs.iter().flatten().enumerate() {
            let keys: BTreeSet<_> = terms.keys().map(String::as_str).collect();
            let declared: BTreeSet<_> = case.outputs[1..].iter().map(String::as_str).collect();
            assert_eq!(
                keys, declared,
                "{}: row {index} stores every index",
                case.id
            );
        }
        if let Some((null_length, _)) = &outputs[0] {
            if let Some(Some((companion_length, _))) = outputs.get(1) {
                assert_eq!(
                    null_length, companion_length,
                    "{}: a sealed null is as long as a value",
                    case.id
                );
            }
        }
        // Every stored term is the term a query of the value derives.
        let mut queried = Vec::new();
        for (target, output) in [(&case.input, 0usize)]
            .into_iter()
            .chain(case.companion.iter().map(|c| (c, 1usize)))
        {
            let Some((_, terms)) = &outputs[output] else {
                continue;
            };
            for (index, term) in terms {
                let operator = match index.as_str() {
                    "eq" => OpSpec::Eq,
                    "ore" | "ope" => OpSpec::Lt,
                    other => panic!("{other}"),
                };
                if case.unanswered.contains(index) {
                    let error = dynamic::query_term(
                        &keyset,
                        &plan,
                        "value",
                        operator,
                        value(target),
                        &NoTargets,
                    )
                    .err()
                    .expect("an unanswered index is refused before any term");
                    refusal(
                        &error,
                        "stack_encrypt::dynamic_source",
                        "operator_not_answered",
                        "value",
                    );
                    continue;
                }
                queried.push((target.clone(), operator, term.clone()));
            }
            if output == 0 {
                if let Some(other) = &case.equal_query {
                    queried.push((other.clone(), OpSpec::Eq, terms["eq"].clone()));
                }
            }
        }
        for (target, operator, stored_term) in queried {
            let term = dynamic::query_term(
                &keyset,
                &plan,
                "value",
                operator,
                value(&target),
                &NoTargets,
            )
            .unwrap()
            .await
            .unwrap();
            if term.operand() != &Operand::One(stored_term) {
                failures.push(format!(
                    "{}: {operator:?} of {target:?} is not the stored term",
                    case.id
                ));
            }
        }
        assert_eq!(generates.load(Ordering::SeqCst), usize::from(stores));
        assert_eq!(
            retrieves.load(Ordering::SeqCst),
            0,
            "queries retrieve nothing"
        );
        let opened = record::decrypt(Scope::Keyset(keyset.clone()), sealed, &plan, None)
            .unwrap()
            .await
            .unwrap();
        let mut expected = vec![row(&case.input)];
        expected.extend(case.companion.iter().map(row));
        if opened.risky_ref() != frame(expected).risky_ref() {
            failures.push(format!("{}: typed round trip differs", case.id));
        }
        assert_eq!(
            retrieves.load(Ordering::SeqCst),
            usize::from(stores),
            "{}: one batched retrieval",
            case.id
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The corpus spells dates, instants and decimals as text, and the shared
/// helper parses them without a calendar library: hold it to the frames the
/// value-kinds fixture froze for the same spellings.
#[test]
fn the_shared_text_forms_frame_as_the_value_kinds_fixture() {
    let framed = |kind: &str, text: &str| {
        hex(value(&Input {
            kind: kind.into(),
            text: text.into(),
        })
        .risky_ref())
    };
    assert_eq!(framed("date", "2024-02-29"), "1281460b00");
    assert_eq!(
        framed("timestamp", "2026-10-17T01:02:03.123456789Z"),
        "130bc9d26a0000000015cd5b07"
    );
    assert_eq!(
        framed("decimal", "-1234.5600"),
        "14000004800061bc000000000000000000"
    );
    assert_eq!(framed("int8", "-8"), "0cf8");
    assert_eq!(
        framed("uint128", "340282366920938463463374607431768211455"),
        "11ffffffffffffffffffffffffffffffff"
    );
}

/// A float spelling with more digits than its value's shortest is rounded
/// by the parse: the helper refuses it instead of sealing another value.
#[test]
#[should_panic(expected = "not the shortest spelling")]
fn a_rounded_float_spelling_is_a_corpus_error() {
    value(&Input {
        kind: "float64".into(),
        text: "0.1000000000000000001".into(),
    });
}

/// A float spelling with more zeros than its shortest is refused too, though
/// it names the value exactly.
#[test]
#[should_panic(expected = "not the shortest spelling")]
fn a_float_with_trailing_zeros_is_a_corpus_error() {
    value(&Input {
        kind: "float64".into(),
        text: "1.00".into(),
    });
}

/// Spellings the float reader accepts, as `(bits, text)`; Go's
/// `TestConformanceFloatSpelling` holds its reader to the same lists.
const CANONICAL_FLOATS: &[(u32, &str)] = &[
    (64, "100"),
    (64, "12000"),
    (64, "1e3"),
    (64, "34"),
    (64, "-0"),
    (64, "1.5"),
    (64, "0.5"),
    (64, "1e-3"),
    (64, "9007199254740992"),
    (64, "1.7976931348623157e308"),
    (64, "5e-324"),
    (64, "inf"),
    (64, "-inf"),
    (32, "1e-45"),
    (32, "3.4028235e38"),
];

/// Spellings that parse to a float but are not its canonical spelling.
const NON_CANONICAL_FLOATS: &[(u32, &str)] = &[
    (64, "1.00"),
    (64, "1.0"),
    (64, "1e0"),
    (64, "1.5e0"),
    (64, "1000"),
    (64, "1e2"),
    (64, "1e+3"),
    (64, "1E3"),
    (64, "10e2"),
    (64, "01"),
    (64, "+1"),
    (64, ".5"),
    (64, "5."),
    (64, "-0.0"),
    (64, "0.001"),
    (64, "0.1000000000000000001"),
    (64, "Inf"),
    (64, "infinity"),
    (64, "NaN"),
    (32, "1.4e-45"),
    (32, "3.4028234664e38"),
];

/// The float reader accepts exactly the canonical spelling: the shorter of
/// the positional and scientific forms of the shortest round-trip digits.
#[test]
fn the_float_reader_accepts_only_the_canonical_spelling() {
    fn canonical(bits: u32, text: &str) -> Option<String> {
        match bits {
            32 => text.parse::<f32>().ok().and_then(canonical_float),
            64 => text.parse::<f64>().ok().and_then(canonical_float),
            _ => unreachable!(),
        }
    }
    for &(bits, text) in CANONICAL_FLOATS {
        assert_eq!(canonical(bits, text).as_deref(), Some(text), "float{bits}");
    }
    for &(bits, text) in NON_CANONICAL_FLOATS {
        assert!(text.parse::<f64>().is_ok(), "{text} parses");
        assert_ne!(canonical(bits, text).as_deref(), Some(text), "float{bits}");
    }
}

/// A day the month does not have is a corpus error, as it is in Go.
#[test]
#[should_panic(expected = "not a calendar date")]
fn a_day_the_month_lacks_is_a_corpus_error() {
    value(&Input {
        kind: "date".into(),
        text: "2023-02-29".into(),
    });
}
