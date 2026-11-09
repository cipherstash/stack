//! Bindings in the dynamic record grammar, shared with Go (#1487).
//!
//! A binding is in the stored context, after the scopes, and in no query
//! context. So a record bound to its row is found by a query under the
//! scopes alone, opens only under the same binding, and a query that carries
//! a binding is refused. The vectors pin the stored context's descriptor,
//! the equality term, one ciphertext, and the contexts text, so Go can open
//! what Rust sealed and check that it prints the same contexts.
#![cfg(feature = "dynamic")]
mod common;

use common::conformance::{value, Input};
use common::frames::{frame, object};
use common::{hex, unhex};
use serde::{Deserialize, Serialize};
use stack_encrypt::dynamic::{self, record, Scope, ValueFrame};
use stack_encrypt::AsProtectedRef as _;
use stack_encrypt::{CipherText, Descriptor, Label, SealedValue, StackCipherText};
use std::collections::{BTreeMap, BTreeSet};

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
struct Case {
    id: String,
    label: String,
    scopes: Vec<Input>,
    bind: Vec<Input>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    /// The descriptor of the stored context: the label and field, the
    /// scopes, then the bindings.
    descriptor: String,
    /// The equality term, derived under the query context: no binding.
    equality: String,
    /// One ciphertext sealed under the stored context.
    ciphertext: String,
    /// `Plan::contexts()` of the plan: the query context and the stored
    /// context, as Rust and Go print them.
    contexts: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    version: u32,
    profile: String,
    producer: String,
    cases: BTreeMap<String, Vector>,
}

fn part(input: &Input) -> ValueFrame {
    if input.kind == "bytes" {
        frame(unhex(&input.text))
    } else {
        assert!(["string", "int32", "int64", "uint64"].contains(&input.kind.as_str()));
        value(input)
    }
}
fn nest(head: ValueFrame, parts: &[Input]) -> ValueFrame {
    parts
        .iter()
        .fold(head, |head, p| frame(vec![head, part(p)]))
}
/// The field's context frame: the label and field, extended by the scopes.
fn context(case: &Case) -> ValueFrame {
    let mut label = case.label.split('/').map(str::to_owned).collect::<Vec<_>>();
    label.push("text".into());
    nest(frame(label), &case.scopes)
}
/// The plan: the one field, and the bindings under the plan-level `bind`
/// key when the case has any.
fn plan(case: &Case, with_bind: bool) -> record::Plan {
    let mut fields = vec![];
    if with_bind && !case.bind.is_empty() {
        fields.push((
            "bind",
            frame(case.bind.iter().map(part).collect::<Vec<_>>()),
        ));
    }
    fields.push((
        "text",
        object(vec![
            ("context", context(case)),
            ("outputs", frame(vec!["c", "eq"])),
            ("type", frame("string")),
        ]),
    ));
    record::plan(object(fields).as_protected_ref()).unwrap()
}
/// The bytes a passthrough frame holds: a stored term.
fn passthrough_bytes(payload: &stack_encrypt::PassthroughFrame) -> Vec<u8> {
    use vitaminc_aead::Decrypt;
    let frame = payload.parse().expect("one frame");
    vitaminc_aead::Encrypt::visit(frame, Vec::<u8>::sink()).expect("bytes")
}
fn source() -> ValueFrame {
    object(vec![("text", frame("hello"))])
}
fn ciphertext(tree: StackCipherText) -> Vec<u8> {
    let CipherText::Map(fields) = tree else {
        panic!("record")
    };
    let (_, CipherText::Map(outputs)) = fields.into_iter().find(|(k, _)| k == "text").unwrap()
    else {
        panic!("outputs")
    };
    let (_, CipherText::Single(leaf)) = outputs.into_iter().find(|(k, _)| k == "c").unwrap() else {
        panic!("leaf")
    };
    leaf.to_bytes()
}
fn stored(vector: &Vector) -> StackCipherText {
    CipherText::Map(vec![(
        "text".into(),
        CipherText::Map(vec![
            (
                "c".into(),
                CipherText::Single(SealedValue::from_bytes(&unhex(&vector.ciphertext)).unwrap()),
            ),
            (
                "eq".into(),
                CipherText::Passthrough(common::passthrough(unhex(&vector.equality))),
            ),
        ]),
    )])
}

#[tokio::test]
async fn binding_conformance() {
    let update = common::fixture_updates_requested_or_panic();
    let corpus: Corpus = serde_json::from_str(include_str!(
        "../../../conformance/stack-encrypt/v1/record-bindings-v1.cases.json"
    ))
    .unwrap();
    assert_eq!(corpus.version, 1);
    assert_eq!(corpus.profile, "record-bindings-v1");
    assert_eq!(
        corpus.required_capabilities,
        ["composition", "typed-extensions", "bindings", "frozen-open"]
    );
    assert!(!corpus.cases.is_empty());
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/stack-encrypt/v1/record-bindings-v1.expected.rust-native.json");
    let baseline: BTreeMap<String, Vector> = if update {
        BTreeMap::new()
    } else {
        let expected: Expected = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(expected.version, 1);
        assert_eq!(expected.profile, "record-bindings-v1");
        assert!(!expected.producer.is_empty());
        expected.cases
    };
    let mut vectors = BTreeMap::new();
    let mut ids = BTreeSet::new();
    let cipher = common::deterministic_cipher([0; 32]).await;
    let keyset = cipher.default_keyset();
    for case in corpus.cases {
        assert!(!case.id.is_empty() && ids.insert(case.id.clone()));
        assert!(!case.bind.is_empty(), "a binding case has a binding");
        Label::parse(&case.label).unwrap();
        eprintln!("binding conformance: {}", case.id);
        let bound = plan(&case, true);
        let unbound = plan(&case, false);

        // The record seals under the stored context, and its term derives
        // under the query context: the term of the plan with no binding.
        let fresh = record::encrypt(&keyset, source(), &bound)
            .unwrap()
            .await
            .unwrap();
        let free = record::encrypt(&keyset, source(), &unbound)
            .unwrap()
            .await
            .unwrap();
        let term = |tree: &StackCipherText| {
            let CipherText::Map(fields) = tree else {
                panic!("record")
            };
            let (_, CipherText::Map(outputs)) = fields.iter().find(|(k, _)| k == "text").unwrap()
            else {
                panic!("outputs")
            };
            let (_, CipherText::Passthrough(term)) =
                outputs.iter().find(|(k, _)| k == "eq").unwrap()
            else {
                panic!("term")
            };
            passthrough_bytes(term)
        };
        assert_eq!(
            term(&fresh),
            term(&free),
            "a binding is not in the query context"
        );

        // The key is requested under the stored context's descriptor.
        let (recording, sent) = common::recording_cipher().await;
        record::encrypt(&recording.default_keyset(), source(), &bound)
            .unwrap()
            .await
            .unwrap();
        let descriptors = sent.lock().unwrap().generated();
        assert_eq!(descriptors.len(), 1);
        let stored_context = {
            let field = frame(vec![context(&case)]);
            let _ = field;
            let ctx = dynamic::context(context(&case).as_protected_ref()).unwrap();
            let mut piece = ctx.into_inner();
            for binding in &case.bind {
                let part = dynamic::context(part(binding).as_protected_ref())
                    .map(|p| p.into_inner())
                    .unwrap_or_else(|_| {
                        // An empty part is not a nonempty context on its own.
                        panic!("a binding part is nonempty in this corpus")
                    });
                piece = stack_encrypt::ContextPiece::List(vec![piece, part]);
            }
            piece
        };
        assert_eq!(
            descriptors[0],
            Descriptor::from_piece(&stored_context).as_str()
        );

        // A query through the bound plan is refused before any key is used.
        let refused = dynamic::query_term(
            &keyset,
            &bound,
            "text",
            dynamic::OpSpec::Eq,
            "hello",
            &dynamic::NoTargets,
        );
        assert!(
            matches!(refused.as_ref().err(), Some(dynamic::Error::Plan { .. })),
            "a query takes no binding"
        );
        // The same query through the unbound plan matches the stored term.
        let query = dynamic::query_term(
            &keyset,
            &unbound,
            "text",
            dynamic::OpSpec::Eq,
            "hello",
            &dynamic::NoTargets,
        )
        .unwrap()
        .await
        .unwrap();
        let dynamic::Operand::One(bytes) = query.operand() else {
            panic!("one term")
        };
        assert_eq!(bytes, term(&fresh).as_slice());

        let vector = Vector {
            descriptor: descriptors[0].clone(),
            equality: hex(&term(&fresh)),
            ciphertext: hex(&ciphertext(fresh)),
            contexts: bound.contexts().unwrap().to_string(),
        };
        let expected = if update { &vector } else { &baseline[&case.id] };
        assert_eq!(vector.descriptor, expected.descriptor);
        assert_eq!(vector.equality, expected.equality);
        assert_eq!(vector.contexts, expected.contexts);

        // The frozen record opens under its binding, and under no other.
        let opened = record::decrypt(
            Scope::Keyset(keyset.clone()),
            stored(expected),
            &bound,
            None,
        )
        .unwrap()
        .await
        .unwrap();
        assert_eq!(opened.risky_ref(), source().risky_ref());
        let other = {
            let tampered = vec![
                (
                    "bind",
                    frame(
                        case.bind
                            .iter()
                            .map(|_| frame("tampered"))
                            .collect::<Vec<_>>(),
                    ),
                ),
                (
                    "text",
                    object(vec![
                        ("context", context(&case)),
                        ("outputs", frame(vec!["c", "eq"])),
                        ("type", frame("string")),
                    ]),
                ),
            ];
            record::plan(object(tampered).as_protected_ref()).unwrap()
        };
        assert!(
            record::decrypt(
                Scope::Keyset(keyset.clone()),
                stored(expected),
                &other,
                None
            )
            .unwrap()
            .await
            .is_err(),
            "a tampered binding opens nothing"
        );
        assert!(
            record::decrypt(
                Scope::Keyset(keyset.clone()),
                stored(expected),
                &unbound,
                None
            )
            .unwrap()
            .await
            .is_err(),
            "a binding left out opens nothing"
        );
        vectors.insert(case.id, vector);
    }
    if update {
        let expected = Expected {
            version: 1,
            profile: "record-bindings-v1".into(),
            producer: "rust-native".into(),
            cases: vectors,
        };
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&expected).unwrap() + "\n",
        )
        .unwrap();
    }
}
