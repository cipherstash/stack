//! Executable acceptance and normalization contract for record declarations.
#![cfg(feature = "dynamic")]

use std::collections::BTreeSet;
use std::path::PathBuf;

use miette::Diagnostic;
use serde::Deserialize;
use serde_json::{json, Value};
use stack_encrypt::dynamic::record::{self, NullMode, Output};
use stack_encrypt::{ContextPiece, ErrorPayload};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    version: u32,
    profile: String,
    resolver: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    input: Input,
    accepted: bool,
    expected_error: Option<ExpectedError>,
    boundary_error: Option<ExpectedError>,
    normalized: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Input {
    Json(Value),
    FrameHex(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedError {
    code: String,
    fields: serde_json::Map<String, Value>,
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.is_ascii() && text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn extension(piece: &ContextPiece<'_>) -> Value {
    let (kind, text) = match piece {
        ContextPiece::Text(text) => ("string", text.to_string()),
        ContextPiece::Bytes(bytes) => ("bytes", bytes.iter().map(|b| format!("{b:02x}")).collect()),
        ContextPiece::I32(n) => ("int32", n.to_string()),
        ContextPiece::I64(n) => ("int64", n.to_string()),
        ContextPiece::U32(n) => ("uint32", n.to_string()),
        ContextPiece::U64(n) => ("uint64", n.to_string()),
        other => panic!("unexpected extension {other:?}"),
    };
    json!({"type": kind, "text": text})
}

// An observation of the parsed engine plan, not a second declaration parser.
// No sorting: field/output order is observable and must survive parsing.
fn normalized(plan: &record::Plan) -> Value {
    let fields: Vec<_> = plan.fields().iter().map(|field| {
        let outputs: Vec<_> = field.outputs().iter().map(|output| match output {
            Output::Ciphertext => json!("c"),
            Output::Passthrough => json!("passthrough"),
            Output::Term(index) => serde_json::to_value(index).unwrap(),
        }).collect();
        json!({
            "name": field.name(),
            "label": field.label().segments().collect::<Vec<_>>(),
            "type": field.field_type().map(|kind| kind.name()),
            "null": field.null().map(|mode| match mode { NullMode::Sql => "sql", NullMode::Sealed => "sealed" }),
            "outputs": outputs,
        })
    }).collect();
    json!({
        "label": plan.label().map(|label| label.segments().collect::<Vec<_>>()),
        "context_field": plan.context_field(),
        "extension": plan.extension().iter().map(extension).collect::<Vec<_>>(),
        "fields": fields,
    })
}

#[test]
fn shared_declaration_grammar() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/stack-encrypt/v1/declarations.json");
    let corpus: Corpus = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(corpus.version, 1);
    assert_eq!(corpus.profile, "record-declarations-v1");
    assert_eq!(corpus.resolver, "none");
    assert!(!corpus.cases.is_empty());
    let mut ids = BTreeSet::new();
    let mut failures = Vec::new();
    for case in corpus.cases {
        assert!(
            !case.id.is_empty() && ids.insert(case.id.clone()),
            "duplicate/empty ID"
        );
        assert_eq!(
            case.accepted,
            case.expected_error.is_none(),
            "{}: contradictory outcome",
            case.id
        );
        assert!(
            case.accepted || case.normalized.is_none(),
            "{}: rejected normalization",
            case.id
        );
        let frame = match case.input {
            Input::Json(value) => vitaminc_aead_frame::serde::to_vec(&value).unwrap(),
            Input::FrameHex(text) => unhex(&text),
        };
        if let Some(boundary) = case.boundary_error {
            assert!(!case.accepted);
            assert!(
                vitaminc_aead::Frame::parse(&frame).is_err(),
                "{}: boundary refusal requires a malformed frame",
                case.id
            );
            assert_eq!(boundary.code, "stack_guest_abi::malformed_input");
            assert!(boundary.fields.is_empty());
        }
        // No cipher/key source exists: declaration checking cannot do key I/O.
        match (record::plan(&frame), case.expected_error) {
            (Ok(plan), None) => {
                if let Some(expected) = case.normalized {
                    let actual = normalized(&plan);
                    if actual != expected {
                        failures.push(format!(
                            "{}: normalized {actual}, expected {expected}",
                            case.id
                        ));
                    }
                }
            }
            (Err(error), Some(expected)) => {
                let code = error.code().unwrap().to_string();
                let fields = error.payload();
                if code != expected.code || fields != expected.fields {
                    failures.push(format!(
                        "{}: {code} {fields:?}, expected {} {:?}",
                        case.id, expected.code, expected.fields
                    ));
                }
            }
            (actual, expected) => failures.push(format!(
                "{}: accepted={}, expected accepted={}; error={:?}",
                case.id,
                actual.is_ok(),
                expected.is_none(),
                actual.err()
            )),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
