//! Stored-shape, authenticated-type and context preflight conformance.
#![cfg(feature = "dynamic")]
mod common;

use common::{
    conformance::{value, Input},
    frames::{frame, object},
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use stack_encrypt::dynamic::{record, Scope, ValueFrame};
use stack_encrypt::{CipherText, ErrorPayload, Label, StackCipherText};
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
#[serde(deny_unknown_fields)]
struct Declaration {
    kind: String,
    null: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    write: Declaration,
    read: Declaration,
    context_field: bool,
    rows: Vec<Row>,
    mutation: Mutation,
    expected_context: Option<String>,
    check_error: Option<Refusal>,
    expected: Expected,
    // Go additionally runs representable cases through its normal record adapter.
    #[serde(rename = "adapter")]
    _adapter: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mutation {
    kind: String,
    row: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Refusal {
    code: String,
    fields: Map<String, Value>,
}
#[derive(Deserialize, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Success,
    Shape,
    Preflight,
    Authenticated,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    stage: Stage,
    retrievals: usize,
    error: Option<Refusal>,
    rows: Option<Vec<Row>>,
}

fn refusal(error: &impl ErrorPayload, want: &Refusal) {
    assert_eq!(error.code().unwrap().to_string(), want.code);
    assert_eq!(error.payload(), want.fields);
}
fn plan(decl: &Declaration, context_field: bool) -> record::Plan {
    assert!(["", "sql", "sealed"].contains(&decl.null.as_str()));
    let context = if context_field {
        vec!["value"]
    } else {
        vec!["conformance", "value"]
    };
    let mut spec = json!({"context":context,"outputs":["c","eq"],"type":decl.kind});
    if !decl.null.is_empty() {
        spec["null"] = json!(decl.null);
    }
    let mut plan = json!({"value":spec});
    if context_field {
        plan["context_field"] = json!("tenant");
        plan["tenant"] = json!({"context":["tenant"],"outputs":["passthrough"],"type":"string"});
    }
    record::plan(&vitaminc_aead_frame::serde::to_vec(&plan).unwrap()).unwrap()
}
fn rows(input: &[Row]) -> ValueFrame {
    frame(
        input
            .iter()
            .map(|row| object(row.iter().map(|(k, v)| (k, value(v))).collect()))
            .collect::<Vec<_>>(),
    )
}
fn map(tree: &mut StackCipherText) -> &mut Vec<(String, StackCipherText)> {
    let CipherText::Map(fields) = tree else {
        panic!("map")
    };
    fields
}
fn slot<'a>(fields: &'a mut [(String, StackCipherText)], key: &str) -> &'a mut StackCipherText {
    &mut fields.iter_mut().find(|(k, _)| k == key).unwrap().1
}
fn plain() -> StackCipherText {
    CipherText::Passthrough(common::passthrough(34_i32))
}
// Ciphertext deliberately has no Clone implementation. Copy public test storage.
fn copy_tree(tree: &StackCipherText) -> StackCipherText {
    use stack_encrypt::{PassthroughFrame, SealedValue};
    let leaf = |v: &SealedValue| SealedValue::from_bytes(&v.to_bytes()).unwrap();
    match tree {
        CipherText::Single(v) => CipherText::Single(leaf(v)),
        CipherText::EmptySequence(v) => CipherText::EmptySequence(leaf(v)),
        CipherText::EmptyMap(v) => CipherText::EmptyMap(leaf(v)),
        CipherText::Sequence(v) => CipherText::Sequence(v.iter().map(copy_tree).collect()),
        CipherText::Map(v) => {
            CipherText::Map(v.iter().map(|(k, v)| (k.clone(), copy_tree(v))).collect())
        }
        CipherText::Passthrough(v) => CipherText::Passthrough(PassthroughFrame(v.0.clone())),
    }
}

fn mutate(tree: &mut StackCipherText, mutation: &Mutation) {
    let CipherText::Sequence(batch) = tree else {
        panic!("batch")
    };
    let row = &mut batch[mutation.row];
    if mutation.kind == "row_plain" {
        *row = plain();
        return;
    }
    let fields = map(row);
    match mutation.kind.as_str() {
        "none" => {}
        "drop_value" => fields.retain(|(k, _)| k != "value"),
        "field_plain" => *slot(fields, "value") = plain(),
        "extra_field" => fields.push(("extra".into(), plain())),
        "drop_tenant" => fields.retain(|(k, _)| k != "tenant"),
        "tenant_no_payload" => map(slot(fields, "tenant")).clear(),
        "tenant_number" => *slot(map(slot(fields, "tenant")), "passthrough") = plain(),
        kind => {
            let outputs = map(slot(fields, "value"));
            match kind {
                "drop_c" => outputs.retain(|(k, _)| k != "c"),
                "drop_eq" => outputs.retain(|(k, _)| k != "eq"),
                "c_plain" => *slot(outputs, "c") = plain(),
                "extra_output" => outputs.push(("extra".into(), plain())),
                other => panic!("unknown mutation {other}"),
            }
        }
    }
}

#[tokio::test]
async fn shared_record_read_profile() {
    let corpus: Corpus = serde_json::from_str(include_str!(
        "../../../conformance/stack-encrypt/v1/reads.json"
    ))
    .unwrap();
    assert_eq!(corpus.version, 1);
    assert_eq!(corpus.profile, "record-reads-v1");
    assert_eq!(
        corpus.required_capabilities,
        [
            "records",
            "read-shapes",
            "authenticated-types",
            "context-preflight"
        ]
    );
    assert!(!corpus.cases.is_empty());
    let mut ids = BTreeSet::new();
    for case in corpus.cases {
        assert!(!case.id.is_empty() && ids.insert(case.id.clone()));
        eprintln!("read conformance: {}", case.id);
        let write = plan(&case.write, case.context_field);
        let read = plan(&case.read, case.context_field);
        let expected = case
            .expected_context
            .as_deref()
            .map(|s| Label::parse(s).unwrap());
        let (cipher, generates, retrieves) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let mut stored = record::encrypt(&keyset, rows(&case.rows), &write)
            .unwrap()
            .await
            .unwrap();
        generates.store(0, Ordering::SeqCst);
        retrieves.store(0, Ordering::SeqCst);
        mutate(&mut stored, &case.mutation);
        let checked = record::check_record(copy_tree(&stored), &read, expected.as_ref());
        if let Some(want) = &case.check_error {
            refusal(&checked.unwrap_err(), want);
        } else {
            checked.unwrap();
        }
        let result = record::decrypt(Scope::Keyset(keyset), stored, &read, expected);
        match case.expected.stage {
            Stage::Shape => {
                assert!(case.expected.rows.is_none());
                refusal(
                    &result.err().expect("shape rejection before pending"),
                    case.expected.error.as_ref().unwrap(),
                );
            }
            Stage::Success => {
                assert!(case.expected.error.is_none());
                let opened = result.unwrap().await.unwrap();
                assert_eq!(
                    opened.risky_ref(),
                    rows(case.expected.rows.as_ref().unwrap()).risky_ref()
                );
            }
            Stage::Preflight | Stage::Authenticated => {
                assert!(case.expected.rows.is_none());
                let err = result.unwrap().await.unwrap_err();
                refusal(&err, case.expected.error.as_ref().unwrap());
                assert_eq!(
                    case.expected.retrievals,
                    usize::from(case.expected.stage == Stage::Authenticated)
                );
            }
        }
        assert_eq!(
            generates.load(Ordering::SeqCst),
            0,
            "reads never generate data keys"
        );
        assert_eq!(
            retrieves.load(Ordering::SeqCst),
            case.expected.retrievals,
            "retrieval stage"
        );
    }
}
