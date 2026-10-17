//! Rust queries an EQL v4 field through Stack Encrypt's typed query chain
//! (ADR-0009): `cipher.query(op::Eq, v).on(&plan)` on a plan for the type,
//! answered through the `op::Answers` impls eql-codegen writes, with the
//! type's query twin as the term.
//!
//! The typed path must agree with the data path a binding takes
//! (`stack_encrypt::dynamic::query_term`, which the Go SDK runs) on three
//! things: which operators each type answers, the bytes of each query, and
//! for `TextMatch`, how a decrypted row verifies and how many rows to fetch.

mod common;

use eql_bindings::encryption::plaintext::{Float32, Float64, Int32, Int64};
use eql_bindings::encryption::query::MatchTwin;
use eql_bindings::encryption::targets::{self as eql_targets, Target};
use eql_bindings::v4::targets::ANSWERS;
use eql_bindings::v4::text::{TextEq, TextMatch, TextMatchQuery};
use eql_bindings::v4::{bigint, double, integer, real, DomainType};
use eql_bindings::Identifier;
use serde::Serialize;
use stack_encrypt::dynamic::{
    self, record, FfiValue, OpSpec, Operand, TargetDescriptor, TargetError, TargetResolver,
};
use stack_encrypt::op::{self, Probabilistic, Stats};
use stack_encrypt::{Error, KeysetCipher, Label, Pending, Plan, StackCipher};

type Cipher = StackCipher<common::Observed>;

/// eql-bindings' table as the engine's resolver, as the Go guest installs
/// it (`languages/golang/encrypt/guest/src/targets.rs`).
struct Eql;

/// A table row as the engine's descriptor, with the match options of a type
/// that carries a match index, as the guest describes it.
fn describe(target: &Target) -> TargetDescriptor {
    let descriptor = TargetDescriptor::new(
        target.name,
        target.family,
        target.suffix,
        target.plaintext_kind(),
        target.sql_domain,
        target.indexes.iter().map(|key| (*key).to_owned()).collect(),
        target.query.map(str::to_owned),
        target.query_sql_domain.map(str::to_owned),
        target.producible,
        target.reason.map(str::to_owned),
    );
    match target.match_options() {
        Some(options) => descriptor.with_match_options(options),
        None => descriptor,
    }
}

fn convert(error: eql_targets::TargetError) -> TargetError {
    TargetError::Other(Box::new(error))
}

impl TargetResolver for Eql {
    fn targets(&self) -> Vec<TargetDescriptor> {
        eql_targets::targets().iter().map(describe).collect()
    }
    fn encrypt<'a, K: 'static>(
        &self,
        name: &str,
        keyset: &'a KeysetCipher<'_, K>,
        label: &Label,
        plaintext: FfiValue,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        eql_targets::encrypt(name, keyset, label, plaintext).map_err(convert)
    }
    fn decrypt<'a, K: 'static>(
        &self,
        name: &str,
        cipher: &'a StackCipher<K>,
        label: &Label,
        stored: &[u8],
    ) -> Result<Pending<'a, FfiValue, K>, TargetError> {
        eql_targets::decrypt(name, cipher, label, stored).map_err(convert)
    }
    fn query<'a, K: 'static>(
        &self,
        name: &str,
        keyset: &'a KeysetCipher<'_, K>,
        label: &Label,
        plaintext: FfiValue,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        eql_targets::query(name, keyset, label, plaintext).map_err(convert)
    }
}

/// A data plan with one field, `value`, under `users/<column>`, naming the
/// EQL type `name`.
fn data_plan(name: &str, column: &str) -> record::Plan {
    let text = |s: &str| FfiValue::String(s.into());
    record::plan_with(
        FfiValue::Object(vec![(
            "value".into(),
            FfiValue::Object(vec![
                (
                    "context".into(),
                    FfiValue::Array(vec![text("users"), text(column)]),
                ),
                ("target".into(), text(name)),
            ]),
        )]),
        &Eql,
    )
    .unwrap()
}

/// The data path's term for the query, and the domain it is cast to.
async fn data_term(
    cipher: &Cipher,
    name: &str,
    column: &str,
    operator: OpSpec,
    input: FfiValue,
) -> (Vec<u8>, String) {
    let keyset = cipher.default_keyset();
    let term = dynamic::query_term(
        &keyset,
        &data_plan(name, column),
        "value",
        operator,
        input,
        &Eql,
    )
    .unwrap()
    .await
    .unwrap();
    let Operand::One(bytes) = term.operand() else {
        panic!("{name}: a one-value query has one operand");
    };
    (bytes.clone(), term.domain().unwrap().to_owned())
}

/// The bytes a typed query term binds, and the query domain it names.
fn typed_bytes<Q: Serialize + DomainType>(query: &Q) -> (Vec<u8>, String) {
    (
        serde_json::to_vec(query).unwrap(),
        Q::sql_domain_static().to_owned(),
    )
}

/// A typed plan for the EQL type `$ty` over `$plaintext`, under
/// `users/<column>`, and the term of `cipher.query($op, $value)` on it.
macro_rules! typed {
    ($cipher:expr, $column:expr, $ty:ty, $plaintext:ty, $op:expr, $value:expr) => {{
        let plan = Plan::value::<$plaintext>()
            .context(format!("users/{}", $column))
            .encrypt_into::<$ty>()
            .build()
            .unwrap();
        $cipher.query($op, $value).on(&plan).await.unwrap()
    }};
}

/// The typed query for each operator a type answers, with the input the
/// data path is given for the same query: one arm per row of `ANSWERS`, so
/// a type that starts answering an operator fails here until it has one,
/// and an arm compiles only if the type implements `op::Answers` for it.
async fn typed_and_input(
    cipher: &Cipher,
    name: &str,
    operator: &str,
    column: &str,
) -> ((Vec<u8>, String), FfiValue) {
    match (name, operator) {
        ("TextEq", "eq") => (
            typed_bytes(&typed!(
                cipher,
                column,
                TextEq,
                String,
                op::Eq,
                "bob@example.com"
            )),
            FfiValue::String("bob@example.com".into()),
        ),
        ("IntegerEq", "eq") => (
            typed_bytes(&typed!(
                cipher,
                column,
                integer::IntegerEq,
                Int32,
                op::Eq,
                &Int32(-42)
            )),
            FfiValue::Int32(-42),
        ),
        ("BigintEq", "eq") => (
            typed_bytes(&typed!(
                cipher,
                column,
                bigint::BigintEq,
                Int64,
                op::Eq,
                &Int64(i64::MIN + 1)
            )),
            FfiValue::Int64(i64::MIN + 1),
        ),
        ("RealEq", "eq") => (
            typed_bytes(&typed!(
                cipher,
                column,
                real::RealEq,
                Float32,
                op::Eq,
                &Float32(-0.0)
            )),
            FfiValue::Float32(-0.0),
        ),
        ("DoubleEq", "eq") => (
            typed_bytes(&typed!(
                cipher,
                column,
                double::DoubleEq,
                Float64,
                op::Eq,
                &Float64(f64::NAN)
            )),
            FfiValue::Float64(f64::NAN),
        ),
        ("TextMatch", "matches") => {
            let query: MatchTwin<TextMatchQuery> =
                typed!(cipher, column, TextMatch, String, op::Matches, "alice");
            (typed_bytes(query.twin()), FfiValue::String("alice".into()))
        }
        _ => panic!(
            "{name} answers `{operator}` in the typed query chain: give it an arm here, with the \
             input the data path is given"
        ),
    }
}

/// The operators each type answers in the typed chain are exactly the ones
/// the data path answers for a field that names it, type by type, in order.
/// The typed impls and `ANSWERS` are generated from one rule, so this is
/// what holds that rule to the engine's.
#[test]
fn the_typed_chain_answers_what_the_data_path_answers() {
    for target in eql_targets::targets() {
        let data: Vec<&str> = describe(target)
            .operators()
            .into_iter()
            .map(OpSpec::name)
            .collect();
        let typed: Vec<&str> = ANSWERS
            .iter()
            .find(|(name, _)| *name == target.name)
            .map(|(_, ops)| ops.to_vec())
            .unwrap_or_default();
        assert_eq!(typed, data, "{}", target.name);
    }
    for (name, _) in ANSWERS {
        assert!(eql_targets::target(name).is_some(), "{name} is a target");
    }
    assert!(!ANSWERS.is_empty());
}

/// Every typed query binds the bytes the data path derives for the same
/// field, operator and value, under the same query domain. The float
/// values are the ones whose terms the semantic baseline folds (`-0.0`,
/// NaN).
#[tokio::test]
async fn every_typed_query_is_the_data_paths_query() {
    let (cipher, _) = common::cipher().await;
    for (name, operators) in ANSWERS {
        for operator in *operators {
            let column = "col";
            let (typed, input) = typed_and_input(&cipher, name, operator, column).await;
            let op = OpSpec::parse(operator).unwrap();
            let data = data_term(&cipher, name, column, op, input).await;
            assert_eq!(typed, data, "{name} {operator}");
            let json: serde_json::Value = serde_json::from_slice(&typed.0).unwrap();
            assert_eq!(json["v"], 4, "{name}");
            assert_eq!(json["i"], serde_json::json!({"t": "users", "c": column}));
        }
    }
}

/// The typed `TextEq` query is the stored value's term under the same
/// column, as the data path's is.
#[tokio::test]
async fn a_typed_eq_query_matches_the_stored_term() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let column = Identifier::for_column("users", "email").unwrap();
    let stored: TextEq = keyset
        .encrypt_as(&"bob@example.com".to_owned(), column)
        .await
        .unwrap();
    let query = typed!(cipher, "email", TextEq, String, op::Eq, "bob@example.com");
    assert_eq!(query.hm, stored.hm);
    assert_eq!(query.i, stored.i);
    let other = typed!(cipher, "email", TextEq, String, op::Eq, "alice@example.com");
    assert_ne!(other.hm, stored.hm);
}

/// `verify` and `target_limit` on the typed `TextMatch` query answer as
/// the data path's `verify` and `target_limit` do for the same query.
#[tokio::test]
async fn a_typed_match_query_verifies_and_sizes_as_the_data_path_does() {
    let (cipher, _) = common::cipher().await;
    let plan = data_plan("TextMatch", "name");
    for needle in ["alice", "ali", "ALICE SMITH"] {
        let query: MatchTwin<TextMatchQuery> =
            typed!(cipher, "name", TextMatch, String, op::Matches, needle);
        let input = FfiValue::String(needle.into());

        let page = ["Alice Smith", "alicia", "Bob", "malice", "ALICE", "al", ""];
        let values: Vec<FfiValue> = page.iter().map(|v| FfiValue::String((*v).into())).collect();
        let data = dynamic::verify(
            &plan,
            "value",
            OpSpec::Matches,
            input.clone(),
            &values,
            &Eql,
        )
        .unwrap();
        let typed: Vec<bool> = page.iter().map(|v| query.verify(v)).collect();
        assert_eq!(typed, data, "{needle}");
        assert!(query.verify("Alice Smith"), "{needle}");
        assert!(!query.verify("Bob"), "{needle}");

        let (term, _) = data_term(&cipher, "TextMatch", "name", OpSpec::Matches, input).await;
        assert_eq!(
            serde_json::to_vec(&query).unwrap(),
            term,
            "serializes as the twin"
        );
        for stats in [
            Stats::measured(1_000_000, [(40, 500_000), (120, 500_000)]),
            Stats::measured(1_000_000, [(40, 1_000_000)]).with_confidence(0.5),
            Stats::declared(1_000_000),
        ] {
            for want in [0, 1, 10, 1_000] {
                let data = dynamic::target_limit(
                    &plan,
                    "value",
                    OpSpec::Matches,
                    &term,
                    want,
                    &stats,
                    &Eql,
                )
                .unwrap();
                assert_eq!(query.target_limit(want, &stats), data, "{needle} {want}");
            }
        }
    }
}

/// The query's refusals are the data path's: match text that cuts no token
/// is refused before any term exists, and a label that names no column is
/// refused, since the twin stores the column. Both come before the named
/// keyset is loaded.
#[tokio::test]
async fn a_typed_query_refuses_what_the_data_path_refuses() {
    let (cipher, calls) = common::cipher().await;
    let plan = Plan::value::<String>()
        .context("users/name")
        .encrypt_into::<TextMatch>()
        .build()
        .unwrap();
    let short = cipher
        .query(op::Matches, "al")
        .keyset("tenant")
        .on(&plan)
        .await;
    assert!(
        matches!(
            short,
            Err(Error::Term(stack_encrypt::sem::TermError::EmptyTermText))
        ),
        "{short:?}"
    );

    for label in ["users", "public/users/email"] {
        let plan = Plan::value::<String>()
            .context(label)
            .encrypt_into::<TextEq>()
            .build()
            .unwrap();
        let refused = cipher.query(op::Eq, "bob").keyset("tenant").on(&plan).await;
        let Err(Error::Other(reason)) = &refused else {
            panic!("{label}: {refused:?}");
        };
        assert!(
            reason
                .to_string()
                .contains("is not an EQL column identifier"),
            "{label}: {reason}"
        );
    }
    assert_eq!(calls.lock().unwrap().loads, 0, "refused before any keyset");
}

/// A query extended with `.extend(..)` derives its terms under the column
/// and the extension, while the twin stores the column alone, so it could
/// match nothing: it is refused, before the named keyset is loaded, for an
/// exact type and for `TextMatch`.
#[tokio::test]
async fn an_extended_typed_query_is_refused_before_any_keyset() {
    let (cipher, calls) = common::cipher().await;
    let email = Plan::value::<String>()
        .context("users/email")
        .encrypt_into::<TextEq>()
        .build()
        .unwrap();
    let name = Plan::value::<String>()
        .context("users/name")
        .encrypt_into::<TextMatch>()
        .build()
        .unwrap();
    let refusals = [
        cipher
            .query(op::Eq, "bob")
            .extend(7i64)
            .keyset("tenant")
            .on(&email)
            .await
            .map(drop),
        cipher
            .query(op::Matches, "alice")
            .extend(7i64)
            .keyset("tenant")
            .on(&name)
            .await
            .map(drop),
    ];
    for refused in refusals {
        let Err(Error::Other(reason)) = &refused else {
            panic!("{refused:?}");
        };
        assert!(
            reason.to_string().contains("cannot be extended"),
            "{reason}"
        );
    }
    assert_eq!(calls.lock().unwrap().loads, 0, "refused before any keyset");

    // Unextended, the same query loads the keyset and runs.
    cipher
        .query(op::Eq, "bob")
        .keyset("tenant")
        .on(&email)
        .await
        .unwrap();
    assert_eq!(calls.lock().unwrap().loads, 1);
}
