//! Shared context composition: the data-plan lowering, and the combinators
//! of `stack_encrypt::target` composed by hand.
//!
//! The lowering runs every case of the shared corpora. The combinators run
//! what they can state: a field sealed and indexed under a label, extended
//! one part at a time, the term a query derives under the same context, and
//! the opening under it. They compare no stored context with an expected
//! one and check no record's shape. Those checks are a plan's, so the cases
//! that need them run through the lowering alone.
#![cfg(feature = "dynamic")]
mod common;

use common::conformance::{value, Input};
use common::frames::{frame, object};
use common::{hex, unhex};
use miette::Diagnostic;
use serde::{Deserialize, Serialize};
use stack_encrypt::dynamic::{self, record, ValueFrame};
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{
    equality, indexed, open, Borrowed, CallerContext, DeclaredContext, Decryption, Encrypted,
};
use stack_encrypt::AsProtectedRef as _;
use stack_encrypt::{
    CipherText, Descriptor, Equality, IntoAad, IntoPrfContext, Label, NonEmpty, SealedValue,
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
/// One part of an extension, as the combinators take it.
fn extension(input: &Input) -> CallerContext {
    // An empty scalar is a valid extension of an already nonempty label.
    // CallerContext's constructors enforce nonemptiness on each part, so
    // the empty-part case is exercised through lowering only.
    match input.kind.as_str() {
        "string" => CallerContext::from(NonEmpty::new(input.text.clone()).unwrap()),
        "bytes" => CallerContext::from(NonEmpty::new(unhex(&input.text)).unwrap()),
        "int32" => input.text.parse::<i32>().unwrap().into(),
        "int64" => input.text.parse::<i64>().unwrap().into(),
        "uint64" => input.text.parse::<u64>().unwrap().into(),
        _ => panic!("unsupported context part"),
    }
}
/// The parts of an extension, added one at a time, in order.
fn extended(parts: &[Input]) -> DeclaredContext {
    parts
        .iter()
        .fold(DeclaredContext::default(), |context, part| {
            context.with(extension(part))
        })
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
/// The outputs of the field `text` of one stored row.
fn text_outputs(row: &StackCipherText) -> &[(String, StackCipherText)] {
    let CipherText::Map(fields) = row else {
        panic!("record")
    };
    let (_, CipherText::Map(outputs)) = fields.iter().find(|(k, _)| k == "text").unwrap() else {
        panic!("outputs")
    };
    outputs
}
/// The equality term a stored row holds for `text`.
fn equality_term(row: &StackCipherText) -> Vec<u8> {
    let (_, CipherText::Passthrough(term)) =
        text_outputs(row).iter().find(|(k, _)| k == "eq").unwrap()
    else {
        panic!("term")
    };
    vitaminc_aead_frame::serde::from_slice::<&[u8]>(&term.0)
        .unwrap()
        .to_vec()
}
/// The context a stored row names and its sealed `text`, as the
/// combinators open it: under `<tenant>/text`.
fn opening(row: &StackCipherText) -> Decryption<String, common::CountingSource> {
    let CipherText::Map(fields) = row else {
        panic!("record")
    };
    let (_, CipherText::Map(tenant)) = fields.iter().find(|(k, _)| k == "tenant").unwrap() else {
        panic!("tenant")
    };
    let (_, CipherText::Passthrough(tenant)) =
        tenant.iter().find(|(k, _)| k == "passthrough").unwrap()
    else {
        panic!("passthrough")
    };
    let tenant: String = vitaminc_aead_frame::serde::from_slice(&tenant.0).unwrap();
    let (_, CipherText::Single(leaf)) = text_outputs(row).iter().find(|(k, _)| k == "c").unwrap()
    else {
        panic!("leaf")
    };
    open(
        CipherText::Single(SealedValue::from_bytes(&leaf.to_bytes()).unwrap()),
        NonEmpty::from(Label::parse(&format!("{tenant}/text")).unwrap()),
    )
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
            dynamic::Op::Eq,
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
                    dynamic::Op::Eq,
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
        let opened = record::decrypt(keyset.clone(), stored(&case, expected), &plan, None)
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

        // The combinators, composed by hand: one `with` for each part, not
        // one preassembled extension. The label is `<label>/text` for both
        // bases. Where a label comes from is the plan's concern.
        if case.parts.iter().any(|p| p.text.is_empty()) {
            assert!(
                NonEmpty::new(String::new()).is_err(),
                "typed empty extension must refuse"
            );
        } else {
            let label = || NonEmpty::from(Label::parse(&format!("{}/text", case.label)).unwrap());
            let text = String::from("hello");
            let query: EqualityTerm = keyset
                .run(
                    equality::<String, _, Borrowed>().under(label()),
                    &text,
                    extended(&case.parts),
                )
                .await
                .unwrap();
            assert_eq!(hex(&query.to_bytes()), expected.equality);
            let field: Encrypted<EqualityTerm> = keyset
                .run(
                    indexed::<String, _, Borrowed, _>(Equality).under(label()),
                    &text,
                    extended(&case.parts),
                )
                .await
                .unwrap();
            assert_eq!(hex(&field.terms.to_bytes()), expected.equality);
            let opened: String = cipher
                .run_decryption(open(field.ciphertext, extended(&case.parts).under(label())))
                .await
                .unwrap();
            assert_eq!(opened, "hello");
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
        Descriptor::of(separate.stored()).as_str(),
        "((users/age)/7u64)/eu"
    );
    assert_eq!(
        Descriptor::of(grouped.stored()).as_str(),
        "(users/age)/(7u64/eu)"
    );
    assert_ne!(
        separate.stored().into_aad().as_bytes(),
        grouped.stored().into_aad().as_bytes()
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
        // The combinators open each row under the context it stores, all
        // in one request. They hold no expected context and read no shape,
        // so they run the cases with no expectation whose rows all store a
        // label.
        if case.expected.is_empty()
            && ["none", "tamper", "ciphertext"].contains(&case.mutation.as_str())
        {
            retrieves.store(0, Ordering::SeqCst);
            let opened = cipher
                .run_decryption(Decryption::all(batch.iter().map(opening)))
                .await;
            assert_eq!(
                opened.is_ok(),
                case.outcome == "success",
                "combinators {}",
                case.id
            );
            if let Ok(opened) = opened {
                assert_eq!(opened, vec!["hello"; case.tenants.len()]);
            }
            assert_eq!(
                retrieves.load(Ordering::SeqCst),
                case.native_retrievals,
                "combinators {}",
                case.id
            );
        }
        generates.store(0, Ordering::SeqCst);
        retrieves.store(0, Ordering::SeqCst);
        let expected = if case.expected.is_empty() {
            None
        } else {
            Some(Label::parse(&case.expected).unwrap())
        };
        let result = match record::decrypt(keyset.clone(), stored, &plan, expected) {
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
    // A plan that reads its context from the record has none for a query,
    // so a query names it: the plan under that label, with no context
    // field, as a binding sends it.
    assert!(!corpus.queries.is_empty());
    for query in corpus.queries {
        assert!(!query.id.is_empty() && ids.insert(query.id.clone()));
        eprintln!("context boundary: {}", query.id);
        let (cipher, generates, retrieves) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let row = object(vec![
            ("tenant", frame("tenants/acme")),
            ("text", frame("hello")),
        ]);
        let stored = record::encrypt(&keyset, row, &plan).unwrap().await.unwrap();
        generates.store(0, Ordering::SeqCst);
        let named = if query.context.is_empty() {
            Ok(plan.clone())
        } else {
            let mut label = query
                .context
                .split('/')
                .map(str::to_owned)
                .collect::<Vec<_>>();
            label.push("text".into());
            record::plan(
                object(vec![(
                    "text",
                    object(vec![
                        ("context", frame(label)),
                        ("outputs", frame(vec!["c", "eq"])),
                        ("type", frame("string")),
                    ]),
                )])
                .as_protected_ref(),
            )
        };
        let pending = named.and_then(|named| {
            dynamic::query_term(
                &keyset,
                &named,
                "text",
                dynamic::Op::Eq,
                "hello",
                &dynamic::NoTargets,
            )
        });
        match query.outcome.as_str() {
            "refused" => {
                assert!(pending.is_err(), "{}", query.id);
                assert!(!query.matches);
            }
            "success" => {
                let term = pending.unwrap().await.unwrap();
                let dynamic::Operand::One(bytes) = term.operand() else {
                    panic!("one term")
                };
                assert_eq!(
                    bytes == equality_term(&stored).as_slice(),
                    query.matches,
                    "{}",
                    query.id
                );
            }
            _ => panic!("unknown query outcome"),
        }
        assert_eq!(generates.load(Ordering::SeqCst), 0);
        assert_eq!(retrieves.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn a_grouped_extension_remains_one_part_when_appended() {
    let (cipher, sent) = common::recording_cipher().await;
    let keyset = cipher.default_keyset();
    let label = || NonEmpty::from(Label::parse("users/age").unwrap());
    let grouped = || NonEmpty::from(7u64).with("eu");
    let extended = || DeclaredContext::default().with(grouped()).with(9u64);
    let out: Encrypted<EqualityTerm> = keyset
        .run(
            indexed::<u32, _, Borrowed, _>(Equality).under(label()),
            &34u32,
            extended(),
        )
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["((users/age)/(7u64/eu))/9u64"]
    );
    let query: EqualityTerm = keyset
        .run(
            equality::<u32, _, Borrowed>().under(label()),
            &34u32,
            extended(),
        )
        .await
        .unwrap();
    assert_eq!(out.terms, query);
    let back: u32 = cipher
        .run_decryption(open(out.ciphertext, extended().under(label())))
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
    let keyset = cipher.default_keyset();
    let label = || NonEmpty::from(Label::parse("users/age").unwrap());
    let query = |extension: DeclaredContext| {
        keyset.run(
            equality::<u32, _, Borrowed>().under(label()),
            &34u32,
            extension,
        )
    };
    // The removed chain of an earlier release replaced its extension on each
    // `extend`, so only the last part reached the seal. Writing with that
    // surviving part reproduces the context of the records it stored.
    let old: Encrypted<EqualityTerm> = keyset
        .run(
            indexed::<u32, _, Borrowed, _>(Equality).under(label()),
            &34u32,
            DeclaredContext::from(7u64),
        )
        .await
        .unwrap();
    let current = query(DeclaredContext::from(1u64).with(7u64)).await.unwrap();
    assert_ne!(
        current, old.terms,
        "the changed query succeeds but silently misses old rows"
    );
    let compatible = query(DeclaredContext::from(7u64)).await.unwrap();
    assert_eq!(compatible, old.terms);
    let value: u32 = cipher
        .run_decryption(open(
            old.ciphertext,
            DeclaredContext::from(7u64).under(label()),
        ))
        .await
        .unwrap();
    assert_eq!(value, 34);
}
