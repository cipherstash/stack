//! Shared context composition, typed chains and dynamic lowering.
#![cfg(feature = "dynamic")]
mod common;

use common::conformance::{value, Input};
use common::frames::{frame, object};
use common::{hex, unhex};
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use stack_encrypt::dynamic::{self, record, Scope, ValueFrame};
use stack_encrypt::plan::pick;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DeclaredContext, Encrypted};
use stack_encrypt::AsProtectedRef as _;
use stack_encrypt::{
    CipherText, Descriptor, Equality, IntoAad, IntoPrfContext, Label, NonEmpty, Plan, SealedValue,
    StackCipherText,
};
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
    base: String,
    label: String,
    parts: Vec<Input>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    context_frame: String,
    plan_context_frame: String,
    descriptor: String,
    aad: String,
    prf: String,
    ciphertext: String,
    equality: String,
    /// `Plan::contexts()` of the data plan: what Rust and Go print for the
    /// declaration, with the extension applied.
    contexts: String,
}
/// The `record-contexts-v1` outputs of one producer, keyed by case ID.
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
fn extension(input: &Input) -> DeclaredContext {
    // An empty scalar is a valid extension of an already nonempty label.
    // CallerContext's constructors enforce nonemptiness on each part, so
    // the empty-part case is exercised through lowering only.
    match input.kind.as_str() {
        "string" => DeclaredContext::from(NonEmpty::new(input.text.clone()).unwrap()),
        "bytes" => DeclaredContext::from(NonEmpty::new(unhex(&input.text)).unwrap()),
        "int32" => input.text.parse::<i32>().unwrap().into(),
        "int64" => input.text.parse::<i64>().unwrap().into(),
        "uint64" => input.text.parse::<u64>().unwrap().into(),
        _ => panic!("unsupported context part"),
    }
}
fn nest(head: ValueFrame, parts: &[Input]) -> ValueFrame {
    parts
        .iter()
        .fold(head, |head, p| frame(vec![head, part(p)]))
}

fn context(case: &Case, field_only: bool) -> ValueFrame {
    let mut label = if field_only {
        vec![]
    } else {
        case.label.split('/').map(str::to_owned).collect::<Vec<_>>()
    };
    label.push("text".into());
    nest(frame(label), &case.parts)
}
fn plan(case: &Case) -> record::Plan {
    let mut fields = vec![];
    if case.base == "field" {
        fields.push(("context_field", frame("tenant")));
        fields.push((
            "tenant",
            object(vec![
                ("context", nest(frame(vec!["tenant"]), &case.parts)),
                ("outputs", frame(vec!["passthrough"])),
                ("type", frame("string")),
            ]),
        ));
    }
    fields.push((
        "text",
        object(vec![
            ("context", context(case, case.base == "field")),
            ("outputs", frame(vec!["c", "eq"])),
            ("type", frame("string")),
        ]),
    ));
    record::plan(object(fields).as_protected_ref()).unwrap()
}
fn source(case: &Case) -> ValueFrame {
    let mut fields = vec![];
    if case.base == "field" {
        fields.push(("tenant", frame(case.label.clone())));
    }
    fields.push(("text", frame("hello")));
    object(fields)
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
fn stored(case: &Case, vector: &Vector) -> StackCipherText {
    let mut fields = vec![];
    if case.base == "field" {
        fields.push((
            "tenant".into(),
            CipherText::Map(vec![(
                "passthrough".into(),
                CipherText::Passthrough(common::passthrough(case.label.clone())),
            )]),
        ));
    }
    fields.push((
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
    ));
    CipherText::Map(fields)
}
struct Note {
    tenant: String,
    text: String,
}

#[tokio::test]
async fn shared_context_composition() {
    let update = common::fixture_updates_requested_or_panic();
    let corpus: Corpus = serde_json::from_str(include_str!(
        "../../../conformance/stack-encrypt/v1/record-contexts-v1.cases.json"
    ))
    .unwrap();
    assert_eq!(corpus.version, 1);
    assert_eq!(corpus.profile, "record-contexts-v1");
    assert_eq!(
        corpus.required_capabilities,
        [
            "composition",
            "typed-extensions",
            "context-fields",
            "frozen-open"
        ]
    );
    assert!(!corpus.cases.is_empty());
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/stack-encrypt/v1/record-contexts-v1.expected.rust-native.json");
    let baseline: BTreeMap<String, Vector> = if update {
        BTreeMap::new()
    } else {
        let expected: Expected = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(expected.version, 1);
        assert_eq!(expected.profile, "record-contexts-v1");
        assert!(!expected.producer.is_empty());
        expected.cases
    };
    let mut vectors = BTreeMap::new();
    let mut ids = BTreeSet::new();
    let cipher = common::deterministic_cipher([0; 32]).await;
    let keyset = cipher.default_keyset();
    for case in corpus.cases {
        assert!(!case.id.is_empty() && ids.insert(case.id.clone()));
        assert!(["literal", "field"].contains(&case.base.as_str()));
        Label::parse(&case.label).unwrap();
        eprintln!("context conformance: {}", case.id);
        let context_frame = context(&case, false);
        let ctx = dynamic::context(context_frame.as_protected_ref()).unwrap();
        let descriptor = Descriptor::of(ctx.clone()).as_str().to_owned();
        let aad = hex(ctx.clone().into_aad().as_bytes());
        let prf = hex(ctx.clone().into_prf_context().as_bytes());
        let term = keyset.equality_term("hello", ctx.clone()).await.unwrap();
        let plan = plan(&case);
        let fresh = record::encrypt(&keyset, source(&case), &plan)
            .unwrap()
            .await
            .unwrap();
        let vector = Vector {
            context_frame: hex(context_frame.risky_ref()),
            plan_context_frame: hex(context(&case, case.base == "field").risky_ref()),
            descriptor,
            aad,
            prf,
            ciphertext: hex(&ciphertext(fresh)),
            equality: hex(&term.to_bytes()),
            contexts: plan.contexts().unwrap().to_string(),
        };
        let (recording, sent) = common::recording_cipher().await;
        record::encrypt(&recording.default_keyset(), source(&case), &plan)
            .unwrap()
            .await
            .unwrap();
        assert_eq!(
            sent.lock().unwrap().generated(),
            std::slice::from_ref(&vector.descriptor)
        );
        let query_plan = record::plan(
            object(vec![(
                "text",
                object(vec![
                    ("context", context_frame.clone()),
                    ("outputs", frame(vec!["c", "eq"])),
                    ("type", frame("string")),
                ]),
            )])
            .as_protected_ref(),
        )
        .unwrap();
        let query = dynamic::query_term(
            &keyset,
            &query_plan,
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
        assert_eq!(hex(bytes), vector.equality);
        if case.base == "field" {
            assert!(
                dynamic::query_term(
                    &keyset,
                    &plan,
                    "text",
                    dynamic::OpSpec::Eq,
                    "hello",
                    &dynamic::NoTargets
                )
                .is_err(),
                "field query requires a context"
            );
        }
        let expected = if update { &vector } else { &baseline[&case.id] };
        assert_eq!(vector.context_frame, expected.context_frame);
        assert_eq!(vector.plan_context_frame, expected.plan_context_frame);
        assert_eq!(vector.descriptor, expected.descriptor);
        assert_eq!(vector.aad, expected.aad);
        assert_eq!(vector.prf, expected.prf);
        assert_eq!(vector.equality, expected.equality);
        assert_eq!(vector.contexts, expected.contexts);
        let opened = record::decrypt(
            Scope::Keyset(keyset.clone()),
            stored(&case, expected),
            &plan,
            None,
        )
        .unwrap()
        .await
        .unwrap();
        assert_eq!(opened.risky_ref(), source(&case).risky_ref());
        let plain: String = cipher
            .decrypt(
                CipherText::Single(SealedValue::from_bytes(&unhex(&expected.ciphertext)).unwrap()),
                ctx,
            )
            .await
            .unwrap();
        assert_eq!(plain, "hello");

        // Native public chains: repeated calls, not one preassembled extension.
        if case.parts.iter().any(|p| p.text.is_empty()) {
            assert!(
                NonEmpty::new(String::new()).is_err(),
                "typed empty extension must refuse"
            );
        } else {
            let note = Note {
                tenant: case.label.clone(),
                text: "hello".into(),
            };
            let fields = if case.base == "field" {
                Plan::fields().context_field(pick("tenant", |n: &Note| &n.tenant))
            } else {
                Plan::context(case.label.as_str()).fields()
            };
            let typed = fields
                .encrypt_index(pick("text", |n: &Note| &n.text), Equality)
                .build()
                .unwrap();
            let mut chain = cipher.encrypt(&note).using(&typed);
            for p in &case.parts {
                chain = chain.extend(extension(p));
            }
            // A no-op extension must not clear earlier calls.
            let mut row = chain.extend(()).await.unwrap();
            let field_plan = typed.field("text").unwrap();
            let mut query = cipher.query(stack_encrypt::op::Eq, "hello");
            if case.base == "field" {
                query = query.context(case.label.as_str());
            }
            let mut query = query.on(&field_plan);
            for p in &case.parts {
                query = query.extend(extension(p));
            }
            let query: EqualityTerm = query.extend(()).await.unwrap();
            assert_eq!(hex(&query.to_bytes()), expected.equality);
            let field: Encrypted<EqualityTerm> = row.take("text").unwrap();
            assert_eq!(hex(&field.terms.to_bytes()), expected.equality);
            row.insert("text", field);
            let mut open = cipher.open(row).using(&typed);
            for p in &case.parts {
                open = open.extend(extension(p));
            }
            let mut opened = open.extend(()).await.unwrap();
            assert_eq!(opened.take::<String>("text").unwrap(), "hello");
        }
        vectors.insert(case.id, vector);
    }
    if update {
        let expected = Expected {
            version: 1,
            profile: "record-contexts-v1".into(),
            producer: format!("rust-native/stack-encrypt-{}", env!("CARGO_PKG_VERSION")),
            cases: vectors,
        };
        std::fs::write(
            path,
            serde_json::to_string_pretty(&expected).unwrap() + "\n",
        )
        .unwrap();
    } else {
        assert_eq!(
            baseline.keys().collect::<Vec<_>>(),
            vectors.keys().collect::<Vec<_>>()
        );
    }
}

#[test]
fn grouped_extensions_preserve_their_shape() {
    let own = || NonEmpty::from(Label::parse("users/age").unwrap());
    let separate = DeclaredContext::default()
        .with(7u64)
        .with(NonEmpty::new("eu").unwrap())
        .under(own());
    let grouped = DeclaredContext::from(NonEmpty::from(7u64).with("eu")).under(own());
    assert_eq!(
        Descriptor::of(separate.clone()).as_str(),
        "((users/age)/7u64)/eu"
    );
    assert_eq!(
        Descriptor::of(grouped.clone()).as_str(),
        "(users/age)/(7u64/eu)"
    );
    assert_ne!(
        separate.into_aad().as_bytes(),
        grouped.into_aad().as_bytes()
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Boundaries {
    version: u32,
    profile: String,
    cases: Vec<Boundary>,
    queries: Vec<QueryBoundary>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Boundary {
    id: String,
    tenants: Vec<String>,
    expected: String,
    mutation: String,
    outcome: String,
    native_retrievals: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryBoundary {
    id: String,
    context: String,
    outcome: String,
    matches: bool,
}

#[tokio::test]
async fn shared_context_boundaries() {
    use std::sync::atomic::Ordering;
    let corpus: Boundaries = serde_json::from_str(include_str!(
        "../../../conformance/stack-encrypt/v1/record-context-boundaries-v1.cases.json"
    ))
    .unwrap();
    assert_eq!(corpus.version, 1);
    assert_eq!(corpus.profile, "record-context-boundaries-v1");
    assert!(!corpus.cases.is_empty());
    let mut ids = BTreeSet::new();
    let case = Case {
        id: "boundary".into(),
        base: "field".into(),
        label: "tenants/acme".into(),
        parts: vec![],
    };
    let plan = plan(&case);
    for case in corpus.cases {
        assert!(!case.id.is_empty() && ids.insert(case.id.clone()));
        eprintln!("context boundary: {}", case.id);
        let (cipher, generates, retrieves) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let rows = frame(
            case.tenants
                .iter()
                .map(|tenant| {
                    object(vec![
                        ("tenant", frame(tenant.clone())),
                        ("text", frame("hello")),
                    ])
                })
                .collect::<Vec<_>>(),
        );
        let mut stored = record::encrypt(&keyset, rows.clone(), &plan)
            .unwrap()
            .await
            .unwrap();
        let CipherText::Sequence(batch) = &mut stored else {
            panic!("batch")
        };
        match case.mutation.as_str() {
            "none" => {}
            "ciphertext" => {
                let CipherText::Map(fields) = batch.last_mut().unwrap() else {
                    panic!("row")
                };
                let CipherText::Map(outputs) =
                    &mut fields.iter_mut().find(|(k, _)| k == "text").unwrap().1
                else {
                    panic!("outputs")
                };
                let node = &mut outputs.iter_mut().find(|(k, _)| k == "c").unwrap().1;
                let CipherText::Single(leaf) = node else {
                    panic!("leaf")
                };
                let mut bytes = leaf.to_bytes();
                *bytes.last_mut().unwrap() ^= 1;
                *node = CipherText::Single(SealedValue::from_bytes(&bytes).unwrap());
            }
            "tamper" | "empty" | "missing" => {
                let CipherText::Map(fields) = batch.last_mut().expect("mutation requires a row")
                else {
                    panic!("row")
                };
                if case.mutation == "missing" {
                    fields.retain(|(k, _)| k != "tenant");
                } else {
                    let tenant = &mut fields.iter_mut().find(|(k, _)| k == "tenant").unwrap().1;
                    let text = if case.mutation == "tamper" {
                        "tenants/globex"
                    } else {
                        ""
                    };
                    *tenant = CipherText::Map(vec![(
                        "passthrough".into(),
                        CipherText::Passthrough(common::passthrough(text)),
                    )]);
                }
            }
            _ => panic!("unknown mutation"),
        }
        let typed_rows = batch
            .iter()
            .map(|row| {
                let CipherText::Map(fields) = row else {
                    panic!("row")
                };
                let mut values = stack_encrypt::plan::FieldValues::new();
                for (name, node) in fields {
                    let CipherText::Map(outputs) = node else {
                        panic!("outputs")
                    };
                    for (output, node) in outputs {
                        match (output.as_str(), node) {
                            ("passthrough", CipherText::Passthrough(payload)) => {
                                values.insert(
                                    name,
                                    vitaminc_aead_frame::serde::from_slice::<String>(&payload.0)
                                        .unwrap(),
                                );
                            }
                            ("c", CipherText::Single(leaf)) => {
                                values.insert(
                                    name,
                                    StackCipherText::Single(
                                        SealedValue::from_bytes(&leaf.to_bytes()).unwrap(),
                                    ),
                                );
                            }
                            _ => {}
                        }
                    }
                }
                values
            })
            .collect::<Vec<_>>();
        let typed = Plan::fields()
            .context_field(pick("tenant", |n: &Note| &n.tenant))
            .encrypt_index(pick("text", |n: &Note| &n.text), Equality)
            .build()
            .unwrap();
        retrieves.store(0, Ordering::SeqCst);
        let mut open = cipher.open(typed_rows);
        if !case.expected.is_empty() {
            open = open.context(case.expected.as_str());
        }
        let typed_result = open.using(&typed).await;
        assert_eq!(
            typed_result.is_ok(),
            case.outcome == "success",
            "typed {}",
            case.id
        );
        if let Ok(opened) = typed_result {
            assert_eq!(opened.len(), case.tenants.len());
            for (row, tenant) in opened.iter().zip(&case.tenants) {
                assert_eq!(row.get::<String>("text").unwrap(), "hello");
                assert_eq!(row.get::<String>("tenant").unwrap(), tenant);
            }
        }
        assert_eq!(
            retrieves.load(Ordering::SeqCst),
            case.native_retrievals,
            "typed {}",
            case.id
        );
        generates.store(0, Ordering::SeqCst);
        retrieves.store(0, Ordering::SeqCst);
        let expected = if case.expected.is_empty() {
            None
        } else {
            Some(Label::parse(&case.expected).unwrap())
        };
        let result = match record::decrypt(Scope::Keyset(keyset.clone()), stored, &plan, expected) {
            Ok(pending) => pending.await.map_err(|e| e.code().unwrap().to_string()),
            Err(error) => Err(error.code().unwrap().to_string()),
        };
        match case.outcome.as_str() {
            "success" => assert_eq!(result.unwrap().risky_ref(), rows.risky_ref()),
            "mismatch" => assert_eq!(result.unwrap_err(), "stack_encrypt::context_mismatch"),
            "authentication" | "aead" => assert_eq!(result.unwrap_err(), "stack_encrypt::aead"),
            "shape" => {
                let code = if case.mutation == "missing" {
                    "stack_encrypt::dynamic_record"
                } else {
                    "stack_encrypt::plan_context_label"
                };
                assert_eq!(result.unwrap_err(), code);
            }
            _ => panic!("unknown outcome"),
        }
        assert_eq!(
            retrieves.load(Ordering::SeqCst),
            case.native_retrievals,
            "{}",
            case.id
        );
        assert_eq!(generates.load(Ordering::SeqCst), 0);
    }
    assert!(!corpus.queries.is_empty());
    for query in corpus.queries {
        assert!(!query.id.is_empty() && ids.insert(query.id.clone()));
        let (cipher, generates, retrieves) = common::counting_cipher().await;
        let typed = Plan::fields()
            .context_field(pick("tenant", |n: &Note| &n.tenant))
            .encrypt_index(pick("text", |n: &Note| &n.text), Equality)
            .build()
            .unwrap();
        let note = Note {
            tenant: "tenants/acme".into(),
            text: "hello".into(),
        };
        let mut stored = cipher.encrypt(&note).using(&typed).await.unwrap();
        let field: Encrypted<EqualityTerm> = stored.take("text").unwrap();
        generates.store(0, Ordering::SeqCst);
        let field_plan = typed.field("text").unwrap();
        let mut call = cipher.query(stack_encrypt::op::Eq, "hello");
        if !query.context.is_empty() {
            call = call.context(query.context.as_str());
        }
        let result: Result<EqualityTerm, _> = call.on(&field_plan).await;
        match query.outcome.as_str() {
            "refused" => {
                assert!(result.is_err());
                assert!(!query.matches);
            }
            "success" => assert_eq!(result.unwrap() == field.terms, query.matches),
            _ => panic!("unknown query outcome"),
        }
        assert_eq!(generates.load(Ordering::SeqCst), 0);
        assert_eq!(retrieves.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn a_grouped_extension_remains_one_part_when_appended() {
    let (cipher, sent) = common::recording_cipher().await;
    let plan = Plan::context("users/age")
        .with::<u32, _>(Equality)
        .build()
        .unwrap();
    let grouped = || NonEmpty::from(7u64).with("eu");
    let out = cipher
        .encrypt(&34u32)
        .using(&plan)
        .extend(grouped())
        .extend(9u64)
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["((users/age)/(7u64/eu))/9u64"]
    );
    let query = cipher
        .query(stack_encrypt::op::Eq, &34u32)
        .on(&plan)
        .extend(grouped())
        .extend(9u64)
        .await
        .unwrap();
    assert_eq!(out.terms, query);
    let back: u32 = cipher
        .open(out)
        .using(&plan)
        .extend(grouped())
        .extend(9u64)
        .await
        .unwrap();
    assert_eq!(back, 34);
    // The record lowering accepts scalar extension parts, not this native-only group.
    let grouped_context = frame(vec![
        frame(vec!["users", "age"]),
        frame(vec![frame(7u64), frame("eu")]),
    ]);
    let declaration = object(vec![(
        "age",
        object(vec![
            ("context", grouped_context),
            ("outputs", frame(vec!["c"])),
        ]),
    )]);
    assert!(record::plan(declaration.as_protected_ref()).is_err());
}

#[tokio::test]
async fn replacement_context_records_keep_their_original_read_and_query_context() {
    let cipher = common::deterministic_cipher([0; 32]).await;
    let plan = Plan::context("users/age")
        .with::<u32, _>(Equality)
        .build()
        .unwrap();
    // The old chain discarded the first extension before sealing. Writing with
    // its surviving part exactly reproduces that context without an old API.
    let old = cipher
        .encrypt(&34u32)
        .using(&plan)
        .extend(7u64)
        .await
        .unwrap();
    let old_term = old.terms.clone();
    let current = cipher
        .query(stack_encrypt::op::Eq, &34u32)
        .on(&plan)
        .extend(1u64)
        .extend(7u64)
        .await
        .unwrap();
    assert_ne!(
        current, old_term,
        "the changed query succeeds but silently misses old rows"
    );
    let compatible = cipher
        .query(stack_encrypt::op::Eq, &34u32)
        .on(&plan)
        .extend(7u64)
        .await
        .unwrap();
    assert_eq!(compatible, old_term);
    let value: u32 = cipher.open(old).using(&plan).extend(7u64).await.unwrap();
    assert_eq!(value, 34);
}
