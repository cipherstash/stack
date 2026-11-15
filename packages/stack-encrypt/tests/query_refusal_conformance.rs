//! The shared query-refusal profile: what a query is refused for before any
//! term exists, through the binding's check, the binding's derivation and,
//! where a field marker of a derived record can spell the same query, the
//! typed query from that marker. See
//! conformance/stack-encrypt/query-refusals-contract.md.
#![cfg(feature = "dynamic")]
mod common;

use common::{
    conformance::{value, Input},
    frames::frame,
    CountingSource,
};
use miette::Diagnostic;
use serde::Deserialize;
use serde_json::json;
use stack_encrypt::dynamic::{self, record, Error, NoTargets, Op, ValueFrame};
use stack_encrypt::sem::{EqualityTerm, MatchTerms, OpeTerm, OreBlockTerm, OreTerm};
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::{AsProtectedRef as _, Encrypted, KeysetCipher, StackCipher};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicUsize, Ordering},
    sync::Arc,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    version: u32,
    profile: String,
    required_capabilities: Vec<String>,
    fields: BTreeMap<String, FieldSpec>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldSpec {
    kind: String,
    outputs: Vec<String>,
    #[serde(default)]
    null: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    field: String,
    operator: String,
    input: QueryInput,
    accepted: bool,
    expected_error: Option<ExpectedError>,
    /// How the typed query answers the same query, for the queries a field
    /// marker can spell: refused before a keyset is asked for anything, or
    /// not refused. The corpus has a third value, for a refusal after the
    /// keyset was loaded. A marker query runs through a keyset the caller
    /// already holds, so it cannot be refused at that stage.
    typed: Option<Typed>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum QueryInput {
    Scalar(Input),
    List {
        #[serde(rename = "type")]
        _kind: ListTag,
        items: Vec<Input>,
    },
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum ListTag {
    List,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedError {
    class: Class,
    code: String,
    reason: Option<String>,
    field: Option<String>,
}

#[derive(Deserialize, Debug, PartialEq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Class {
    /// `Error::Source`: the input is not one the field takes.
    Source,
    /// `Error::Plan`: the plan has no such field, or cannot be queried.
    Plan,
    /// `Error::Cipher(Error::Term(..))`: the index refuses the value.
    Term,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Typed {
    refusal: Refusal,
}

#[derive(Deserialize, Debug, PartialEq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Refusal {
    BeforeKeyset,
    AfterKeyset,
    None,
}

fn input(query: &QueryInput) -> ValueFrame {
    match query {
        QueryInput::Scalar(scalar) => value(scalar),
        QueryInput::List { items, .. } => frame(items.iter().map(value).collect::<Vec<_>>()),
    }
}

fn class_of(error: &Error) -> Class {
    match error {
        Error::Source { .. } => Class::Source,
        Error::Plan { .. } => Class::Plan,
        Error::Cipher(stack_encrypt::Error::Term(_)) => Class::Term,
        other => panic!("not a query refusal class: {other:?}"),
    }
}

fn check(id: &str, path: &str, result: Result<(), Error>, expected: Option<&ExpectedError>) {
    match (result, expected) {
        (Ok(()), None) => {}
        (Err(error), Some(want)) => {
            assert_eq!(class_of(&error), want.class, "{id} {path}: {error:?}");
            assert_eq!(error.code().unwrap().to_string(), want.code, "{id} {path}");
            assert_eq!(
                error.reason().map(|reason| reason.as_str().to_owned()),
                want.reason,
                "{id} {path}"
            );
            assert_eq!(
                error.field().map(str::to_owned),
                want.field,
                "{id} {path}: field"
            );
        }
        (result, _) => panic!("{id} {path}: {result:?}, accepted={}", expected.is_none()),
    }
}

/// The fields of the corpus plan that a typed query can name, each with
/// the plaintext type the corpus declares for it.
#[derive(Clone, zeroize::Zeroize)]
struct Conformance {
    email: String,
    name: String,
    nickname: String,
    title: String,
    age: u32,
    big: i128,
}

/// The same fields as a derived record, each under `conformance/<field>`
/// with the indexes the corpus plan declares. Only its field markers are
/// used: no record is sealed, so no field is read.
#[derive(EncryptTarget)]
#[allow(dead_code)]
#[stash(struct = Conformance, scope = "conformance")]
struct Fields {
    email: Encrypted<EqualityTerm>,
    name: Encrypted<MatchTerms>,
    nickname: Encrypted<OreTerm<String>>,
    title: Encrypted<OreBlockTerm<String>>,
    age: Encrypted<(EqualityTerm, OreTerm<u32>)>,
    big: Encrypted<(EqualityTerm, OpeTerm<i128>)>,
}

/// The typed query's answer: a `stack_encrypt::Error` code, or none. The
/// query starts from the marker of `field`.
async fn typed(
    keyset: &KeysetCipher<'_, CountingSource>,
    field: &str,
    operator: Op,
    query: &QueryInput,
) -> Option<String> {
    let text = |query: &QueryInput| match query {
        QueryInput::Scalar(Input { kind, text }) if kind == "string" => text.clone(),
        other => panic!("{field}: not text: {other:?}"),
    };
    let pair = |query: &QueryInput| match query {
        QueryInput::List { items, .. } if items.len() == 2 => (items[0].clone(), items[1].clone()),
        other => panic!("{field}: not a pair: {other:?}"),
    };
    let texts = |query: &QueryInput| {
        let (lo, hi) = pair(query);
        assert!(lo.kind == "string" && hi.kind == "string");
        (lo.text, hi.text)
    };
    let u32s = |query: &QueryInput| {
        let (lo, hi) = pair(query);
        assert!(lo.kind == "uint32" && hi.kind == "uint32");
        (
            lo.text.parse::<u32>().unwrap(),
            hi.text.parse::<u32>().unwrap(),
        )
    };
    let i128s = |query: &QueryInput| {
        let (lo, hi) = pair(query);
        assert!(lo.kind == "int128" && hi.kind == "int128");
        (
            lo.text.parse::<i128>().unwrap(),
            hi.text.parse::<i128>().unwrap(),
        )
    };
    // The marker's label is the context the corpus plan gives the field,
    // so the typed query and the binding's query are the same query.
    macro_rules! run {
        ($marker:expr, $query:expr) => {{
            assert_eq!(
                $marker.label().to_string(),
                format!("conformance/{field}"),
                "{field}: the marker's label"
            );
            $query
                .encrypt(keyset)
                .await
                .err()
                .map(|error| error.code().expect("a code").to_string())
        }};
    }
    match (field, operator) {
        ("email", Op::Eq) => run!(Fields::EMAIL, Fields::EMAIL.eq(text(query))),
        ("name", Op::Matches) => run!(Fields::NAME, Fields::NAME.matches(text(query))),
        ("nickname", Op::Lt) => run!(Fields::NICKNAME, Fields::NICKNAME.lt(text(query))),
        ("nickname", Op::Between) => {
            let (lo, hi) = texts(query);
            run!(Fields::NICKNAME, Fields::NICKNAME.between(lo, hi))
        }
        ("title", Op::Lt) => run!(Fields::TITLE, Fields::TITLE.lt(text(query))),
        ("title", Op::Gt) => run!(Fields::TITLE, Fields::TITLE.gt(text(query))),
        ("title", Op::Between) => {
            let (lo, hi) = texts(query);
            run!(Fields::TITLE, Fields::TITLE.between(lo, hi))
        }
        ("age", Op::Between) => {
            let (lo, hi) = u32s(query);
            run!(Fields::AGE, Fields::AGE.between(lo, hi))
        }
        ("big", Op::Between) => {
            let (lo, hi) = i128s(query);
            run!(Fields::BIG, Fields::BIG.between(lo, hi))
        }
        other => panic!("{field}: no typed query is spelled for {other:?}"),
    }
}

async fn cipher() -> (StackCipher<CountingSource>, [Arc<AtomicUsize>; 3]) {
    let source = CountingSource::new();
    let loads = source.loads();
    let (generates, retrieves) = source.counters();
    let cipher = StackCipher::builder()
        .kms(source)
        .init()
        .await
        .expect("build cipher");
    loads.store(0, Ordering::SeqCst);
    (cipher, [loads, generates, retrieves])
}

#[tokio::test]
async fn shared_query_refusal_profile() {
    let corpus: Corpus = serde_json::from_str(include_str!(
        "../../../conformance/stack-encrypt/v1/record-query-refusals-v1.cases.json"
    ))
    .unwrap();
    assert_eq!(corpus.version, 1);
    assert_eq!(corpus.profile, "record-query-refusals-v1");
    assert_eq!(
        corpus.required_capabilities,
        ["records", "query-errors", "term-errors"]
    );
    assert!(!corpus.cases.is_empty());
    let mut declaration = serde_json::Map::new();
    for (name, spec) in &corpus.fields {
        let mut field = json!({
            "context": ["conformance", name], "outputs": spec.outputs, "type": spec.kind,
        });
        if !spec.null.is_empty() {
            field["null"] = json!(spec.null);
        }
        declaration.insert(name.clone(), field);
    }
    let plan = record::plan(
        vitaminc_aead_frame::serde::to_vec(&declaration)
            .unwrap()
            .as_protected_ref(),
    )
    .unwrap();
    let (cipher, counters) = cipher().await;
    let keyset = cipher.default_keyset();
    let mut ids = BTreeSet::new();
    for case in &corpus.cases {
        assert!(!case.id.is_empty() && ids.insert(case.id.clone()));
        eprintln!("query refusal conformance: {}", case.id);
        assert_eq!(case.accepted, case.expected_error.is_none(), "{}", case.id);
        let expected = case.expected_error.as_ref();
        if let Some(want) = expected {
            assert_eq!(want.reason.is_none(), want.class == Class::Term);
            assert_eq!(want.field.is_none(), want.class == Class::Term);
        }
        for counter in &counters {
            counter.store(0, Ordering::SeqCst);
        }
        let Some(operator) = Op::parse(&case.operator) else {
            // The engine's operator vocabulary is closed: a name it does not
            // parse never reaches a query here. The binding, which takes the
            // name as text, is where the refusal is observed.
            let want = expected.expect("an unknown operator is refused");
            assert_eq!(want.reason.as_deref(), Some("unknown_operator"));
            assert_eq!(want.class, Class::Source);
            continue;
        };
        let value = input(&case.input);
        let field = corpus.fields.get(&case.field);
        check(
            &case.id,
            "check_query",
            dynamic::check_query(&plan, &case.field, operator, &value, &NoTargets),
            expected,
        );
        let derived =
            match dynamic::query_term(&keyset, &plan, &case.field, operator, &value, &NoTargets) {
                Ok(pending) => {
                    assert!(case.accepted, "{}: refused only after pending", case.id);
                    pending.await.map(drop).map_err(Error::Cipher)
                }
                Err(error) => Err(error),
            };
        check(&case.id, "query_term", derived, expected);
        if operator == Op::Matches {
            let verified = dynamic::verify(
                &plan,
                &case.field,
                operator,
                &value,
                Vec::<ValueFrame>::new(),
                &NoTargets,
            )
            .map(|matched| assert!(matched.is_empty()));
            check(&case.id, "verify", verified, expected);
        }
        for (name, counter) in ["loads", "generates", "retrieves"].iter().zip(&counters) {
            assert_eq!(
                counter.load(Ordering::SeqCst),
                0,
                "{}: the binding path made a {name} call",
                case.id
            );
        }
        let Some(want) = &case.typed else {
            continue;
        };
        assert!(field.is_some(), "{}: a declared field", case.id);
        // A marker query runs through a keyset the caller holds, here the
        // default one, so it has no keyset to load. The observation is that
        // it asks the key source for nothing, refused or not.
        let code = typed(&keyset, &case.field, operator, &case.input).await;
        match want.refusal {
            Refusal::None => {
                assert!(
                    case.accepted && code.is_none(),
                    "{}: typed {code:?}",
                    case.id
                );
            }
            Refusal::BeforeKeyset => {
                let expected = expected.expect("a refusal");
                assert_eq!(expected.class, Class::Term, "{}: typed", case.id);
                assert_eq!(code.as_deref(), Some(expected.code.as_str()), "{}", case.id);
            }
            Refusal::AfterKeyset => panic!(
                "{}: a marker query is prepared before its keyset is asked for anything",
                case.id
            ),
        }
        assert_eq!(
            counters[0].load(Ordering::SeqCst),
            0,
            "{}: typed keyset lookup",
            case.id
        );
        assert_eq!(
            counters[1].load(Ordering::SeqCst),
            0,
            "{}: typed generate",
            case.id
        );
        assert_eq!(
            counters[2].load(Ordering::SeqCst),
            0,
            "{}: typed retrieve",
            case.id
        );
    }
}
