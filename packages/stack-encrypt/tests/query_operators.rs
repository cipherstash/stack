//! The query fixture: a query a binding names by operator derives the term
//! the typed query chain derives, and a probabilistic term's two questions
//! answer as the typed `MatchQuery` answers them (ADR-0009; ADR-0007,
//! amended 2026-10-16). `tests/fixtures/query_operators.json` records each
//! query's term, a page of verified values and a few fetch limits, so the
//! Go SDK's tests can hold the guest's `se_query_term`, `se_verify` and
//! `se_target_limit` exports to the same results; its README gives the
//! schema.
//!
//! Every query derives under the deterministic key source the record
//! fixture uses, whose index key is `FakeDataKeySource`'s, so nothing in the
//! file depends on a nonce: a run that derives other bytes fails, and
//! `STACK_ENCRYPT_UPDATE_FIXTURES=1 cargo test --test query_operators
//! --all-features` rewrites the file when a derivation changes on purpose.
#![cfg(feature = "dynamic")]

mod common;

use std::path::PathBuf;

use common::{deterministic_cipher, DeterministicSource};
use serde_json::{json, Value as Json};
use stack_encrypt::dynamic::{self, record, FfiValue, NoTargets, OpSpec, Operand, QueryTerm};
use stack_encrypt::op::{self, Limit, Probabilistic, Stats};
use stack_encrypt::{Equality, KeysetCipher, Match, Ore, Plan, StackCipher};

const SEED: [u8; 32] = *b"stack-encrypt record fixture v1 ";

/// The declaration every query runs on, in the data grammar.
fn plan_json() -> Json {
    json!({
        "email": { "context": ["users", "email"], "outputs": ["c", "eq"], "type": "string" },
        "age": { "context": ["users", "age"], "outputs": ["c", "eq", "ore"], "type": "uint32" },
        "name": { "context": ["users", "name"], "outputs": ["c", "match"], "type": "string" }
    })
}

/// Each query: a field, an operator and its input, as a binding sends them.
fn queries() -> Vec<(&'static str, OpSpec, Json)> {
    vec![
        ("email", OpSpec::Eq, json!("bob@example.com")),
        ("age", OpSpec::Eq, json!(34)),
        ("age", OpSpec::Lt, json!(40)),
        ("age", OpSpec::Lte, json!(40)),
        ("age", OpSpec::Gt, json!(18)),
        ("age", OpSpec::Gte, json!(18)),
        ("age", OpSpec::Between, json!([18, 65])),
        ("name", OpSpec::Matches, json!("alice")),
        ("name", OpSpec::Matches, json!("ali")),
    ]
}

/// The page `verify` answers for `matches "alice"` on `name`.
fn page() -> Json {
    json!(["Alice Smith", "alicia", "Bob", "malice", "ALICE", null])
}

/// The statistics each recorded limit is sized under.
fn stats_cases() -> Vec<(Json, Stats)> {
    vec![
        (
            json!({ "rows": 1_000_000, "histogram": [[40, 500_000], [120, 500_000]] }),
            Stats::measured(1_000_000, [(40, 500_000), (120, 500_000)]),
        ),
        (
            json!({ "rows": 1_000_000, "histogram": [[40, 1_000_000]], "confidence": 0.5 }),
            Stats::measured(1_000_000, [(40, 1_000_000)]).with_confidence(0.5),
        ),
        (json!({ "rows": 1_000_000 }), Stats::declared(1_000_000)),
    ]
}

fn ffi_of_json(value: &Json) -> FfiValue {
    match value {
        Json::Null => FfiValue::Null,
        Json::String(s) => FfiValue::String(s.as_str().into()),
        Json::Array(items) => FfiValue::Array(items.iter().map(ffi_of_json).collect()),
        Json::Object(entries) => FfiValue::Object(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), ffi_of_json(v)))
                .collect(),
        ),
        Json::Number(n) => match n.as_u64() {
            Some(n) => FfiValue::UInt64(n),
            None => FfiValue::Float64(n.as_f64().expect("a number")),
        },
        Json::Bool(b) => FfiValue::Bool(*b),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A query term as the fixture holds it: the wire form's keys, the bytes in
/// hex.
fn json_of_term(term: &QueryTerm) -> Json {
    json!({
        "operator": term.operator().name(),
        "fidelity": term.fidelity().name(),
        "index": term.index().key(),
        "domain": term.domain(),
        "term": match term.operand() {
            Operand::One(bytes) => json!(hex(bytes)),
            Operand::Range { lo, hi } => json!([hex(lo), hex(hi)]),
        },
    })
}

fn limit_json(limit: Limit) -> Json {
    limit.rows().map_or(Json::Null, |rows| json!(rows))
}

/// The typed chain's term for the same query, as the operand's bytes: the
/// proof that the data path derives what a Rust caller does.
async fn typed_operand(
    cipher: &StackCipher<DeterministicSource>,
    field: &str,
    operator: OpSpec,
    input: &Json,
) -> Operand {
    let int = |value: &Json| u32::try_from(value.as_u64().expect("an integer")).expect("a u32");
    let text = |value: &Json| value.as_str().expect("text").to_owned();
    let age = Plan::context("users/age")
        .with::<u32, _>((Equality, Ore))
        .build()
        .expect("plan");
    let one = Operand::One;
    match (field, operator) {
        ("email", OpSpec::Eq) => {
            let plan = Plan::context("users/email")
                .with::<String, _>(Equality)
                .build()
                .expect("plan");
            one(cipher
                .query(op::Eq, &text(input))
                .on(&plan)
                .await
                .expect("eq")
                .to_bytes())
        }
        ("age", OpSpec::Eq) => one(cipher
            .query(op::Eq, &int(input))
            .on(&age)
            .await
            .expect("eq")
            .to_bytes()),
        ("age", OpSpec::Lt) => one(cipher
            .query(op::Lt, &int(input))
            .on(&age)
            .await
            .expect("lt")
            .to_bytes()),
        ("age", OpSpec::Lte) => one(cipher
            .query(op::Lte, &int(input))
            .on(&age)
            .await
            .expect("lte")
            .to_bytes()),
        ("age", OpSpec::Gt) => one(cipher
            .query(op::Gt, &int(input))
            .on(&age)
            .await
            .expect("gt")
            .to_bytes()),
        ("age", OpSpec::Gte) => one(cipher
            .query(op::Gte, &int(input))
            .on(&age)
            .await
            .expect("gte")
            .to_bytes()),
        ("age", OpSpec::Between) => {
            let range = cipher
                .query(op::Between, &(int(&input[0]), int(&input[1])))
                .on(&age)
                .await
                .expect("between");
            Operand::Range {
                lo: range.lo().to_bytes(),
                hi: range.hi().to_bytes(),
            }
        }
        ("name", OpSpec::Matches) => one(typed_match(cipher, &text(input)).await.to_bytes()),
        other => panic!("no typed query for {other:?}"),
    }
}

async fn typed_match(
    cipher: &StackCipher<DeterministicSource>,
    input: &str,
) -> stack_encrypt::sem::MatchQuery {
    let plan = Plan::context("users/name")
        .with::<String, _>(Match::default())
        .build()
        .expect("plan");
    cipher
        .query(op::Matches, input)
        .on(&plan)
        .await
        .expect("matches")
}

async fn data_term(
    keyset: &KeysetCipher<'_, DeterministicSource>,
    plan: &record::Plan,
    field: &str,
    operator: OpSpec,
    input: &Json,
) -> QueryTerm {
    dynamic::query_term(
        keyset,
        plan,
        field,
        operator,
        ffi_of_json(input),
        &NoTargets,
    )
    .expect("the query is answered")
    .await
    .expect("the term derives")
}

/// The fixture as this run derives it, checked against the typed path as
/// it is built.
async fn derived() -> Json {
    let cipher = deterministic_cipher(SEED).await;
    let keyset = cipher.default_keyset();
    let plan = record::plan(ffi_of_json(&plan_json())).expect("the plan parses");

    let mut terms = Vec::new();
    for (field, operator, input) in queries() {
        let term = data_term(&keyset, &plan, field, operator, &input).await;
        assert_eq!(
            term.operand(),
            &typed_operand(&cipher, field, operator, &input).await,
            "{operator} on {field}: the data path derives the typed chain's term"
        );
        terms.push(json!({
            "field": field,
            "operator": operator.name(),
            "input": input,
            "term": json_of_term(&term),
        }));
    }

    let typed = typed_match(&cipher, "alice").await;
    let values: Vec<FfiValue> = page()
        .as_array()
        .expect("a list")
        .iter()
        .map(ffi_of_json)
        .collect();
    let verified = dynamic::verify(
        &plan,
        "name",
        OpSpec::Matches,
        ffi_of_json(&json!("alice")),
        &values,
        &NoTargets,
    )
    .expect("verify");
    let typed_verified: Vec<bool> = page()
        .as_array()
        .expect("a list")
        .iter()
        .map(|value| value.as_str().is_some_and(|text| typed.verify(text)))
        .collect();
    assert_eq!(verified, typed_verified, "verify is the typed MatchQuery's");

    let mut limits = Vec::new();
    for input in ["ali", "alice"] {
        let term = data_term(&keyset, &plan, "name", OpSpec::Matches, &json!(input)).await;
        let Operand::One(bytes) = term.operand() else {
            panic!("a match term is one term");
        };
        let typed = typed_match(&cipher, input).await;
        for (stats_json, stats) in stats_cases() {
            let read = Stats::from_value(&ffi_of_json(&stats_json)).expect("stats read");
            assert_eq!(read, stats, "the wire form reads as the typed stats");
            let limit =
                dynamic::target_limit(&plan, "name", OpSpec::Matches, bytes, 10, &read, &NoTargets)
                    .expect("a limit");
            assert_eq!(
                limit,
                typed.target_limit(10, &stats),
                "target_limit is the typed MatchQuery's"
            );
            limits.push(json!({
                "field": "name",
                "operator": "matches",
                "input": input,
                "term": hex(bytes),
                "want": 10,
                "stats": stats_json,
                "limit": limit_json(limit),
            }));
        }
    }

    json!({
        "_comment": "Query terms derived by operator through the data path (stack_encrypt::dynamic::query_term), each equal to the typed query chain's, with a verified page and fetch limits. Read by tests/query_operators.rs and the Go SDK's tests; the schema is in README.md beside this file. Regenerate with STACK_ENCRYPT_UPDATE_FIXTURES=1; do not edit by hand.",
        "key_source": { "kind": "deterministic-sha256", "seed": hex(&SEED) },
        "keyset_id": keyset.keyset_id().to_string(),
        "plan": plan_json(),
        "queries": terms,
        "verify": {
            "field": "name",
            "operator": "matches",
            "input": "alice",
            "values": page(),
            "verified": verified,
        },
        "target_limit": limits,
    })
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/query_operators.json")
}

/// The committed fixture is what this run derives. With
/// `STACK_ENCRYPT_UPDATE_FIXTURES=1` it is written first.
#[tokio::test]
async fn the_committed_query_fixture_is_what_the_engine_derives() {
    let now = derived().await;
    let path = fixture_path();
    if std::env::var_os("STACK_ENCRYPT_UPDATE_FIXTURES").is_some() {
        let mut text = serde_json::to_string_pretty(&now).expect("serialise");
        text.push('\n');
        std::fs::write(&path, text).expect("write the fixture");
    }
    let committed: Json =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the fixture is committed"))
            .expect("the fixture is JSON");
    assert_eq!(committed, now, "the committed query fixture is today's");
}

/// The fixture pins more than one answer of each kind: a verified page
/// with both outcomes, and limits both finite and unbounded.
#[tokio::test]
async fn the_fixture_pins_both_outcomes() {
    let now = derived().await;
    let verified = now["verify"]["verified"].as_array().expect("a list");
    assert!(verified.contains(&json!(true)) && verified.contains(&json!(false)));
    let limits: Vec<&Json> = now["target_limit"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|case| &case["limit"])
        .collect();
    assert!(limits.iter().any(|limit| limit.is_u64()));
    assert!(limits.iter().any(|limit| limit.is_null()));
}
