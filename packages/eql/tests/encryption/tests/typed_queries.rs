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

use eql_bindings::encryption::query::{MatchTwin, QueryLabelError};
use eql_bindings::encryption::targets::{self as eql_targets, Target};
use eql_bindings::v4::answers::ANSWERS;
use eql_bindings::v4::plaintext::{Date, Decimal, Timestamp};
use eql_bindings::v4::text::{TextEq, TextMatch, TextMatchQuery};
use eql_bindings::v4::{
    bigint, date, double, integer, numeric, real, smallint, timestamp, DomainType,
};
use eql_bindings::Identifier;
use serde::Serialize;
use stack_encrypt::dynamic::{
    self, record, FieldPlan, OpSpec, Operand, TargetDescriptor, TargetError, TargetResolver,
    ValueFrame,
};
use stack_encrypt::op::{self, Probabilistic, Stats};
use stack_encrypt::{
    ContextPiece, Encrypt, Error, KeysetCipher, Label, NonEmpty, Pending, Plan, StackCipher,
};

type Cipher = StackCipher<common::Observed>;

/// A Rust value as the engine's runtime plaintext: its frame.
fn frame<T: Encrypt>(value: T) -> ValueFrame {
    ValueFrame::of(value).unwrap()
}

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
        plaintext: ValueFrame,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        eql_targets::encrypt(name, keyset, label, plaintext).map_err(convert)
    }
    fn decrypt<'a, K: 'static>(
        &self,
        name: &str,
        cipher: &'a StackCipher<K>,
        label: &Label,
        stored: &[u8],
    ) -> Result<Pending<'a, ValueFrame, K>, TargetError> {
        eql_targets::decrypt(name, cipher, label, stored).map_err(convert)
    }
    fn query<'a, K: 'static>(
        &self,
        name: &str,
        index: &stack_encrypt::target::IndexSpec,
        keyset: &'a KeysetCipher<'_, K>,
        label: &Label,
        plaintext: ValueFrame,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        eql_targets::query(name, index, keyset, label, plaintext).map_err(convert)
    }
}

/// A data plan with one field, `value`, under `users/<column>`, naming the
/// EQL type `name`.
fn data_plan(name: &str, column: &str) -> record::Plan {
    let context = NonEmpty::new(ContextPiece::List(vec![
        ContextPiece::Text("users".into()),
        ContextPiece::Text(column.to_owned().into()),
    ]))
    .unwrap();
    let field = FieldPlan::with_target("value", context, name).unwrap();
    record::Plan::new_with(vec![field], &Eql).unwrap()
}

/// The data path's term for the query, and the domain it is cast to.
async fn data_term(
    cipher: &Cipher,
    name: &str,
    column: &str,
    operator: OpSpec,
    input: ValueFrame,
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
) -> ((Vec<u8>, String), ValueFrame) {
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
            frame("bob@example.com"),
        ),
        ("IntegerEq", "eq") => (
            typed_bytes(&typed!(
                cipher,
                column,
                integer::IntegerEq,
                i32,
                op::Eq,
                &-42i32
            )),
            frame(-42i32),
        ),
        ("SmallintEq", "eq") => (
            typed_bytes(&typed!(
                cipher,
                column,
                smallint::SmallintEq,
                i16,
                op::Eq,
                &-7i16
            )),
            frame(-7i16),
        ),
        ("DateEq", "eq") => {
            let day = || Date::from_days_since_epoch(19_000).expect("a day in range");
            (
                typed_bytes(&typed!(cipher, column, date::DateEq, Date, op::Eq, &day())),
                frame(day()),
            )
        }
        ("TimestampEq", "eq") => {
            // Sub-microsecond nanoseconds: both paths truncate them alike.
            let instant =
                || Timestamp::new(1_700_000_000, 123_456_789).expect("an instant in range");
            (
                typed_bytes(&typed!(
                    cipher,
                    column,
                    timestamp::TimestampEq,
                    Timestamp,
                    op::Eq,
                    &instant()
                )),
                frame(instant()),
            )
        }
        ("NumericEq", "eq") => {
            let amount = || Decimal::new(-1_234_567, 4).expect("a decimal in range");
            (
                typed_bytes(&typed!(
                    cipher,
                    column,
                    numeric::NumericEq,
                    Decimal,
                    op::Eq,
                    &amount()
                )),
                frame(amount()),
            )
        }
        ("BigintEq", "eq") => (
            typed_bytes(&typed!(
                cipher,
                column,
                bigint::BigintEq,
                i64,
                op::Eq,
                &(i64::MIN + 1)
            )),
            frame(i64::MIN + 1),
        ),
        ("RealEq", "eq") => (
            typed_bytes(&typed!(cipher, column, real::RealEq, f32, op::Eq, &-0.0f32)),
            frame(-0.0f32),
        ),
        ("DoubleEq", "eq") => (
            typed_bytes(&typed!(
                cipher,
                column,
                double::DoubleEq,
                f64,
                op::Eq,
                &f64::NAN
            )),
            frame(f64::NAN),
        ),
        ("TextMatch", "matches") => {
            let query: MatchTwin<TextMatchQuery> =
                typed!(cipher, column, TextMatch, String, op::Matches, "alice");
            (typed_bytes(query.twin()), frame("alice"))
        }
        _ => panic!(
            "{name} answers `{operator}` in the typed query chain: give it an arm here, with the \
             input the data path is given"
        ),
    }
}

/// The operators each type answers in the typed chain are exactly the ones
/// the data path answers for a field that names it, type by type, in order,
/// for every type whose twin the chain assembles: one term, from an equality
/// or a match index. A producible type whose twin needs an order term, or
/// several terms, is the chain's one gap: the data path answers it and the
/// typed chain answers nothing, and this holds the gap to exactly those
/// types, so a type with an equality or match twin cannot drop out unseen.
/// The typed impls and `ANSWERS` are generated from one rule, so this is
/// what holds that rule to the engine's.
#[test]
fn the_typed_chain_answers_what_the_data_path_answers() {
    let mut gap = Vec::new();
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
        let one_term = target.indexes.len() <= 1
            && target
                .indexes
                .iter()
                .all(|index| matches!(*index, "eq" | "match"));
        if one_term {
            assert_eq!(typed, data, "{}", target.name);
        } else {
            assert!(
                typed.is_empty(),
                "{}: the typed chain answers nothing yet",
                target.name
            );
            if !data.is_empty() {
                gap.push(target.name);
            }
        }
    }
    // The gap today: every producible ordered type (OPE and block ORE), and
    // text search, whose twins carry an order term among their three. A type
    // leaves this list
    // when the typed chain assembles its twin, and its answers are then
    // held to the data path's above.
    assert_eq!(
        gap,
        [
            "IntegerOrdOre",
            "IntegerOrd",
            "IntegerOrdOpe",
            "SmallintOrdOre",
            "SmallintOrd",
            "SmallintOrdOpe",
            "BigintOrdOre",
            "BigintOrd",
            "BigintOrdOpe",
            "DateOrdOre",
            "DateOrd",
            "DateOrdOpe",
            "TimestampOrdOre",
            "TimestampOrd",
            "TimestampOrdOpe",
            "NumericOrdOre",
            "NumericOrd",
            "NumericOrdOpe",
            "TextOrdOre",
            "TextOrd",
            "TextOrdOpe",
            "TextSearchOre",
            "TextSearch",
            "RealOrdOre",
            "RealOrd",
            "RealOrdOpe",
            "DoubleOrdOre",
            "DoubleOrd",
            "DoubleOrdOpe",
        ]
    );
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
        let input = frame(needle);

        let page = ["Alice Smith", "alicia", "Bob", "malice", "ALICE", "al", ""];
        let data =
            dynamic::verify(&plan, "value", OpSpec::Matches, input.clone(), page, &Eql).unwrap();
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
        assert_eq!(
            reason.downcast_ref::<QueryLabelError>(),
            Some(&QueryLabelError::NotAColumn {
                label: label.to_owned()
            }),
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
        assert_eq!(
            reason.downcast_ref::<QueryLabelError>(),
            Some(&QueryLabelError::Extended),
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

/// A record field naming a storage-only EQL type may store a null as the
/// plan says (#1298), through the resolver the Go guest installs:
/// `"sealed"` stores an EQL value whose `c` is a typed null, as long as a
/// value's, and `"sql"` stores nothing for the field. Both open as a null.
#[tokio::test]
async fn a_record_stores_a_null_in_an_eql_field_as_its_plan_says() {
    use dynamic::{NullMode, Scope};
    use stack_encrypt::CipherText;
    use std::collections::BTreeMap;

    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let context = |column: &str| {
        NonEmpty::new(ContextPiece::List(vec![
            ContextPiece::Text("users".into()),
            ContextPiece::Text(column.to_owned().into()),
        ]))
        .unwrap()
    };
    let plan = record::Plan::new_with(
        vec![
            FieldPlan::with_target("a_dob", context("dob"), "Date")
                .unwrap()
                .with_null(NullMode::Sealed),
            FieldPlan::with_target("b_born", context("born"), "DateEq")
                .unwrap()
                .with_null(NullMode::Sql),
        ],
        &Eql,
    )
    .unwrap();
    let day = chrono::NaiveDate::from_ymd_opt(1990, 5, 17);
    let rows = |dob, born| BTreeMap::from([("a_dob", dob), ("b_born", born)]);
    let source = vec![rows(day, day), rows(None, None)];
    let sealed = record::encrypt_with(&keyset, frame(&source), &plan, &Eql)
        .unwrap()
        .await
        .unwrap();

    // The EQL value's size, as the stored record carries it.
    let eql_len = |row: &stack_encrypt::StackCipherText, field: &str| -> Option<usize> {
        let CipherText::Map(fields) = row else {
            panic!("a row is a map")
        };
        let (_, CipherText::Map(outputs)) = fields.iter().find(|(name, _)| name == field)? else {
            panic!("{field} is a map of outputs");
        };
        match outputs.iter().find(|(key, _)| key == "eql") {
            Some((_, CipherText::Passthrough(payload))) => Some(payload.0.len()),
            other => panic!("{field}'s EQL value is a passthrough: {other:?}"),
        }
    };
    let CipherText::Sequence(stored) = &sealed else {
        panic!("a batch is a sequence");
    };
    assert_eq!(
        eql_len(&stored[1], "a_dob"),
        eql_len(&stored[0], "a_dob"),
        "a sealed null is as long as a value"
    );
    assert!(eql_len(&stored[0], "b_born").is_some());
    assert_eq!(
        eql_len(&stored[1], "b_born"),
        None,
        "a sql null stores nothing"
    );

    let opened = record::decrypt_with(Scope::Client(&cipher), sealed, &plan, None, &Eql)
        .unwrap()
        .await
        .unwrap();
    assert_eq!(opened.risky_ref(), frame(&source).risky_ref());
}
