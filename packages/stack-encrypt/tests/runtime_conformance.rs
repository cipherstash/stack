//! Shared runtime semantics, with native data-key call observations.
#![cfg(feature = "dynamic")]
mod common;

use common::{
    conformance::{value, Input},
    frames::{frame, object},
};
use miette::Diagnostic;
use serde::Deserialize;
use serde_json::json;
use stack_encrypt::dynamic::{self, record, NoTargets, OpSpec, Operand, Scope, ValueFrame};
use stack_encrypt::{CipherText, StackCipherText};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::Ordering,
};

type Row = BTreeMap<String, Input>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    version: u32,
    profile: String,
    required_capabilities: Vec<String>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    kind: String,
    null: String,
    #[serde(flatten)]
    operation: Operation,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Seal {
        rows: Vec<Row>,
        expected_rows: Option<Vec<Row>>,
        expected_stored: Option<Vec<bool>>,
        #[serde(default)]
        equal_lengths: bool,
        expected_error: Option<ExpectedError>,
    },
    Query {
        input: Input,
        expected_value: Option<Input>,
        expected_error: Option<ExpectedError>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedError {
    // Go can refuse record shape before entering the guest.
    #[serde(rename = "go_message")]
    _go_message: Option<String>,
    code: String,
    reason: String,
    field: String,
}

fn refusal(error: dynamic::Error, expected: &ExpectedError) {
    assert_eq!(error.code().unwrap().to_string(), expected.code);
    assert_eq!(error.reason().unwrap().as_str(), expected.reason);
    assert_eq!(error.field(), Some(expected.field.as_str()));
}

fn rows(input: &[Row]) -> ValueFrame {
    frame(
        input
            .iter()
            .map(|row| object(row.iter().map(|(key, input)| (key, value(input))).collect()))
            .collect::<Vec<_>>(),
    )
}

// Return the actual bytes and length, rather than deriving storage from input.
fn outputs(tree: &StackCipherText) -> Option<(Vec<u8>, usize)> {
    let CipherText::Map(fields) = tree else {
        panic!("record map")
    };
    if fields.is_empty() {
        return None;
    }
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].0, "value");
    let CipherText::Map(outputs) = &fields[0].1 else {
        panic!("output map")
    };
    assert_eq!(outputs.len(), 2);
    let CipherText::Single(leaf) = &outputs.iter().find(|(k, _)| k == "c").unwrap().1 else {
        panic!("ciphertext")
    };
    let CipherText::Passthrough(term) = &outputs.iter().find(|(k, _)| k == "eq").unwrap().1 else {
        panic!("term")
    };
    Some((
        vitaminc_aead_frame::serde::from_slice::<&[u8]>(&term.0)
            .unwrap()
            .to_vec(),
        leaf.to_bytes().len(),
    ))
}

#[tokio::test]
async fn shared_record_runtime_profile() {
    let corpus: Corpus = serde_json::from_str(include_str!(
        "../../../conformance/stack-encrypt/v1/runtime.json"
    ))
    .unwrap();
    assert_eq!(corpus.version, 1);
    assert_eq!(corpus.profile, "record-runtime-v1");
    assert_eq!(
        corpus.required_capabilities,
        [
            "records",
            "equality",
            "null-policies",
            "lossless-query-conversion"
        ]
    );
    assert!(!corpus.cases.is_empty());
    let mut ids = BTreeSet::new();
    for case in corpus.cases {
        assert!(!case.id.is_empty() && ids.insert(case.id.clone()));
        eprintln!("runtime conformance: {}", case.id);
        assert!(["", "sql", "sealed"].contains(&case.null.as_str()));
        let mut spec =
            json!({"context":["conformance", "value"], "outputs":["c", "eq"], "type":case.kind});
        if !case.null.is_empty() {
            spec["null"] = json!(case.null);
        }
        let plan =
            record::plan(&vitaminc_aead_frame::serde::to_vec(&json!({"value":spec})).unwrap())
                .unwrap();
        let (cipher, generates, retrieves) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        match case.operation {
            Operation::Seal {
                rows: input,
                expected_rows,
                expected_stored,
                equal_lengths,
                expected_error,
            } => {
                let result = record::encrypt(&keyset, rows(&input), &plan);
                if let Some(expected) = expected_error {
                    assert!(expected_rows.is_none() && expected_stored.is_none() && !equal_lengths);
                    refusal(result.err().expect("preflight refusal"), &expected);
                    assert_eq!(generates.load(Ordering::SeqCst), 0);
                    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
                    continue;
                }
                let expected_rows = expected_rows.expect("opened rows");
                let expected_stored = expected_stored.expect("storage presence");
                assert_eq!(input.len(), expected_rows.len());
                assert_eq!(input.len(), expected_stored.len());
                let sealed = result.unwrap().await.unwrap();
                let CipherText::Sequence(batch) = &sealed else {
                    panic!("batch")
                };
                assert_eq!(batch.len(), input.len());
                let stored: Vec<_> = batch.iter().map(outputs).collect();
                assert_eq!(
                    stored.iter().map(Option::is_some).collect::<Vec<_>>(),
                    expected_stored
                );
                let calls = usize::from(expected_stored.iter().any(|&present| present));
                assert_eq!(
                    generates.load(Ordering::SeqCst),
                    calls,
                    "batch generation calls"
                );
                assert_eq!(retrieves.load(Ordering::SeqCst), 0);
                if equal_lengths {
                    let lengths: BTreeSet<_> = stored
                        .iter()
                        .map(|v| v.as_ref().expect("stored field").1)
                        .collect();
                    assert_eq!(lengths.len(), 1, "null and value ciphertext lengths");
                }
                for (expected, stored) in expected_rows.iter().zip(&stored) {
                    if let Some((bytes, _)) = stored {
                        let term = dynamic::query_term(
                            &keyset,
                            &plan,
                            "value",
                            OpSpec::Eq,
                            value(&expected["value"]),
                            &NoTargets,
                        )
                        .unwrap()
                        .await
                        .unwrap();
                        assert_eq!(term.operand(), &Operand::One(bytes.clone()));
                    }
                }
                assert_eq!(
                    generates.load(Ordering::SeqCst),
                    calls,
                    "queries generate no data keys"
                );
                assert_eq!(
                    retrieves.load(Ordering::SeqCst),
                    0,
                    "queries retrieve no data keys"
                );
                let opened = record::decrypt(Scope::Keyset(keyset.clone()), sealed, &plan, None)
                    .unwrap()
                    .await
                    .unwrap();
                assert_eq!(
                    opened.risky_ref(),
                    rows(&expected_rows).risky_ref(),
                    "typed ordered roundtrip"
                );
                assert_eq!(
                    retrieves.load(Ordering::SeqCst),
                    calls,
                    "batch retrieval calls"
                );
                assert_eq!(
                    generates.load(Ordering::SeqCst),
                    calls,
                    "opening generates no data keys"
                );
            }
            Operation::Query {
                input,
                expected_value,
                expected_error,
            } => {
                let result = dynamic::query_term(
                    &keyset,
                    &plan,
                    "value",
                    OpSpec::Eq,
                    value(&input),
                    &NoTargets,
                );
                if let Some(expected) = expected_error {
                    assert!(expected_value.is_none());
                    refusal(result.err().expect("preflight refusal"), &expected);
                } else {
                    let term = result.unwrap().await.unwrap();
                    assert_eq!(generates.load(Ordering::SeqCst), 0);
                    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
                    let expected = expected_value.expect("normalized value");
                    let sealed =
                        record::encrypt(&keyset, object(vec![("value", value(&expected))]), &plan)
                            .unwrap()
                            .await
                            .unwrap();
                    assert_eq!(term.operand(), &Operand::One(outputs(&sealed).unwrap().0));
                    // This generation belongs to the independent stored-value oracle.
                    assert_eq!(generates.load(Ordering::SeqCst), 1);
                    continue;
                }
                assert_eq!(generates.load(Ordering::SeqCst), 0);
                assert_eq!(retrieves.load(Ordering::SeqCst), 0);
            }
        }
    }
}
