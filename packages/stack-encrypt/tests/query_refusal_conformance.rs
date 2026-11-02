//! The shared query-refusal profile: what a query is refused for before any
//! term exists, through the binding's check, the binding's derivation and,
//! where the typed chain can spell the same query, the typed chain. See
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
use stack_encrypt::dynamic::{self, record, Error, NoTargets, OpSpec, ValueFrame};
use stack_encrypt::sem::DefaultMatch;
use stack_encrypt::{op, Equality, Match, Ope, Ore, OreBlock, Plan, StackCipher};
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
    /// How the typed Rust chain answers the same query, for the queries it
    /// can spell: refused before the named keyset is loaded, after it, or
    /// not refused.
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

/// The typed chain's answer: a `stack_encrypt::Error` code, or none.
async fn typed(
    cipher: &StackCipher<CountingSource>,
    keyset: &str,
    field: &str,
    kind: &str,
    outputs: &[String],
    operator: OpSpec,
    query: &QueryInput,
) -> Option<String> {
    let context = format!("conformance/{field}");
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
    // The index that answers the operator, as the plan declares it: the
    // equality, match or order index, whichever the operator reads.
    let answers: &[&str] = match operator {
        OpSpec::Eq => &["eq"],
        OpSpec::Matches => &["match"],
        _ => &["ore", "ore_block", "ope"],
    };
    let index = outputs
        .iter()
        .map(String::as_str)
        .find(|output| answers.contains(output))
        .expect("an index that answers the operator");
    macro_rules! run {
        ($plan:expr, $op:expr, $value:expr) => {
            run!($plan, $op, $value, Ore)
        };
        ($plan:expr, $op:expr, $value:expr, $via:expr) => {
            cipher
                .query($op, $value)
                .via($via)
                .on(&$plan)
                .keyset(keyset)
                .await
                .err()
                .map(|error| error.code().expect("a code").to_string())
        };
    }
    match (kind, index, operator) {
        ("string", "eq", OpSpec::Eq) => {
            let plan = Plan::context(context)
                .with::<String, _>(Equality)
                .build()
                .unwrap();
            run!(plan, op::Eq, &text(query), Equality)
        }
        ("string", "match", OpSpec::Matches) => {
            let plan = Plan::context(context)
                .with::<String, _>(Match::<DefaultMatch>::default())
                .build()
                .unwrap();
            run!(
                plan,
                op::Matches,
                &text(query),
                Match::<DefaultMatch>::default()
            )
        }
        ("string", "ore", OpSpec::Lt) => {
            let plan = Plan::context(context)
                .with::<String, _>(Ore)
                .build()
                .unwrap();
            run!(plan, op::Lt, &text(query))
        }
        ("string", "ore", OpSpec::Between) => {
            let plan = Plan::context(context)
                .with::<String, _>(Ore)
                .build()
                .unwrap();
            run!(plan, op::Between, &texts(query))
        }
        ("string", "ore_block", OpSpec::Lt) => {
            let plan = Plan::context(context)
                .with::<String, _>(OreBlock)
                .build()
                .unwrap();
            run!(plan, op::Lt, &text(query), OreBlock)
        }
        ("string", "ore_block", OpSpec::Gt) => {
            let plan = Plan::context(context)
                .with::<String, _>(OreBlock)
                .build()
                .unwrap();
            run!(plan, op::Gt, &text(query), OreBlock)
        }
        ("string", "ore_block", OpSpec::Between) => {
            let plan = Plan::context(context)
                .with::<String, _>(OreBlock)
                .build()
                .unwrap();
            run!(plan, op::Between, &texts(query), OreBlock)
        }
        ("uint32", "ore", OpSpec::Between) => {
            let plan = Plan::context(context).with::<u32, _>(Ore).build().unwrap();
            run!(plan, op::Between, &u32s(query))
        }
        ("int128", "ope", OpSpec::Between) => {
            let plan = Plan::context(context).with::<i128, _>(Ope).build().unwrap();
            run!(plan, op::Between, &i128s(query), Ope)
        }
        other => panic!("{field}: the typed chain is not spelled for {other:?}"),
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
        "../../../conformance/stack-encrypt/v1/query-refusals.json"
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
    let plan = record::plan(&vitaminc_aead_frame::serde::to_vec(&declaration).unwrap()).unwrap();
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
        let Some(operator) = OpSpec::parse(&case.operator) else {
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
        if operator == OpSpec::Matches {
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
        let spec = field.expect("a declared field");
        // A named keyset is loaded once and cached, so each typed query
        // names its own: the load is the observation.
        let code = typed(
            &cipher,
            &format!("keyset-{}", case.id),
            &case.field,
            &spec.kind,
            &spec.outputs,
            operator,
            &case.input,
        )
        .await;
        let loads = counters[0].swap(0, Ordering::SeqCst);
        match want.refusal {
            Refusal::None => {
                assert!(
                    case.accepted && code.is_none(),
                    "{}: typed {code:?}",
                    case.id
                );
                assert_eq!(loads, 1, "{}: the typed chain loaded its keyset", case.id);
            }
            Refusal::BeforeKeyset | Refusal::AfterKeyset => {
                let expected = expected.expect("a refusal");
                assert_eq!(expected.class, Class::Term, "{}: typed", case.id);
                assert_eq!(code.as_deref(), Some(expected.code.as_str()), "{}", case.id);
                assert_eq!(
                    loads,
                    usize::from(want.refusal == Refusal::AfterKeyset),
                    "{}: typed refusal stage",
                    case.id
                );
            }
        }
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
