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
    #[serde(default)]
    context_field_name: String,
    rows: Vec<Row>,
    mutation: Mutation,
    #[serde(default, deserialize_with = "deserialize_expected_context")]
    expected_context: Option<String>,
    check_error: Option<Refusal>,
    expected: Expected,
    // Go additionally runs representable cases through its normal record adapter.
    #[serde(rename = "adapter")]
    _adapter: bool,
}

// Only omission means unrestricted. Deserialize a supplied value as a label,
// rather than letting Option treat an explicit null as absence.
fn deserialize_expected_context<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let context = String::deserialize(deserializer)?;
    Label::parse(&context).map_err(serde::de::Error::custom)?;
    Ok(Some(context))
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
fn plan(decl: &Declaration, context_field: bool, context_name: &str) -> record::Plan {
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
    // Match Go Plan.Wire's declaration order explicitly, regardless of the
    // serde_json map backend or the context field's lexical position.
    let framed = |v: &Value| {
        ValueFrame::from_bytes(&vitaminc_aead_frame::serde::to_vec(v).unwrap()).unwrap()
    };
    let mut fields = Vec::new();
    if context_field {
        fields.push(("context_field", frame(context_name.to_owned())));
        fields.push((
            context_name,
            framed(&json!({"context":[context_name],"outputs":["passthrough"],"type":"string"})),
        ));
    }
    fields.push(("value", framed(&spec)));
    record::plan(object(fields).risky_ref()).unwrap()
}
fn rows(input: &[Row], context_name: Option<&str>) -> ValueFrame {
    frame(
        input
            .iter()
            .map(|row| {
                let mut entries: Vec<_> = row.iter().collect();
                entries
                    .sort_by_key(|(name, _)| (Some(name.as_str()) != context_name, name.as_str()));
                object(entries.into_iter().map(|(k, v)| (k, value(v))).collect())
            })
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

fn mutate(tree: &mut StackCipherText, mutation: &Mutation, context_name: &str) {
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
        "drop_tenant" => fields.retain(|(k, _)| k != context_name),
        "tenant_no_payload" => map(slot(fields, context_name)).clear(),
        "tenant_number" => *slot(map(slot(fields, context_name)), "passthrough") = plain(),
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

#[test]
fn shared_record_read_profile() {
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
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut failures = Vec::new();
    let mut ids = BTreeSet::new();
    for case in corpus.cases {
        assert!(!case.id.is_empty() && ids.insert(case.id.clone()));
        eprintln!("read conformance: {}", case.id);
        let id = case.id.clone();
        if let Err(error) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(check_case(case))
        })) {
            let message = error
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| error.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic");
            failures.push(format!("{id}: {message}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

async fn check_case(case: Case) {
    let context_name = if case.context_field_name.is_empty() {
        "tenant"
    } else {
        assert!(case.context_field);
        Label::new([case.context_field_name.as_str()]).unwrap();
        &case.context_field_name
    };
    match case.expected.stage {
        Stage::Success => {
            assert!(
                case.check_error.is_none()
                    && case.expected.error.is_none()
                    && case.expected.rows.is_some()
            );
            assert!(case.expected.retrievals <= 1);
        }
        Stage::Authenticated => {
            assert!(case.check_error.is_none());
            assert_eq!(case.expected.retrievals, 1);
        }
        Stage::Shape | Stage::Preflight => {
            assert!(case.check_error.is_some());
            assert_eq!(case.expected.retrievals, 0);
        }
    }
    let write = plan(&case.write, case.context_field, context_name);
    let read = plan(&case.read, case.context_field, context_name);
    let expected = case
        .expected_context
        .as_deref()
        .map(|s| Label::parse(s).unwrap());
    let (cipher, generates, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let mut stored = record::encrypt(
        &keyset,
        rows(&case.rows, case.context_field.then_some(context_name)),
        &write,
    )
    .unwrap()
    .await
    .unwrap();
    generates.store(0, Ordering::SeqCst);
    retrieves.store(0, Ordering::SeqCst);
    mutate(&mut stored, &case.mutation, context_name);
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
                rows(
                    case.expected.rows.as_ref().unwrap(),
                    case.context_field.then_some(context_name)
                )
                .risky_ref()
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

#[test]
fn expected_context_must_be_a_nonempty_label_when_present() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../conformance/stack-encrypt/v1/reads.json"
    ))
    .unwrap();
    let mut case = corpus["cases"][0].clone();
    case.as_object_mut().unwrap().remove("expected_context");
    assert!(serde_json::from_value::<Case>(case.clone())
        .unwrap()
        .expected_context
        .is_none());
    case["expected_context"] = json!("tenants/acme");
    assert_eq!(
        serde_json::from_value::<Case>(case.clone())
            .unwrap()
            .expected_context
            .as_deref(),
        Some("tenants/acme")
    );
    for invalid in [Value::Null, json!(""), json!(42), json!([]), json!({})] {
        case["expected_context"] = invalid.clone();
        assert!(
            serde_json::from_value::<Case>(case.clone()).is_err(),
            "accepted expected_context: {invalid}"
        );
    }
}
