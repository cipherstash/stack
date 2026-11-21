//! Rust queries an EQL v4 field through its field reference on a derived
//! record: `EncryptedUser::EMAIL.eq(v).encrypt(&keyset)`, answered through
//! the `op::Answers` impls eql-codegen writes, with the type's query twin
//! as the term. A record that lists a scope takes it with `.scope(..)`.
//!
//! The typed path must agree with the data path a binding takes
//! (`stack_encrypt::dynamic::query_term`, which the Go SDK runs) on three
//! things: which operators each type answers, the bytes of each query, and
//! for `TextMatch`, how a decrypted row verifies and how many rows to fetch.
//! A field query must also be the term of the row its record stored,
//! under the same scope.

mod common;

use eql_bindings::encryption::query::MatchTwin;
use eql_bindings::encryption::targets as eql_targets;
use eql_bindings::encryption::EqlTargets;
use eql_bindings::v4::answers::ANSWERS;
use eql_bindings::v4::plaintext::{Date, Decimal, Timestamp};
use eql_bindings::v4::text::{TextEq, TextMatch, TextMatchQuery};
use eql_bindings::v4::{
    bigint, date, double, integer, numeric, real, smallint, timestamp, DomainType,
};
use eql_bindings::Identifier;
use serde::Serialize;
use stack_encrypt::dynamic::{self, record, FieldPlan, Op, Operand, TargetDescriptor, ValueFrame};
use stack_encrypt::op::{Probabilistic, Stats};
use stack_encrypt::target::Scope;
use stack_encrypt::{ContextPiece, Encrypt, Error, KeysetCipher, NonEmpty, StackCipher};
use stack_encrypt::{DecryptSource, EncryptInto, EncryptTarget};
use zeroize::Zeroize;

type Cipher = StackCipher<common::RecordingKeySource>;
type Keyset<'k> = KeysetCipher<'k, common::RecordingKeySource>;

/// A Rust value as the engine's runtime plaintext: its frame.
fn frame<T: Encrypt>(value: T) -> ValueFrame {
    ValueFrame::of(value).unwrap()
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
    record::Plan::new_with(vec![field], &EqlTargets).unwrap()
}

/// The data path's term for the query, and the domain it is cast to.
async fn data_term(
    cipher: &Cipher,
    name: &str,
    column: &str,
    operator: Op,
    input: ValueFrame,
) -> (Vec<u8>, String) {
    let keyset = cipher.default_keyset();
    let term = dynamic::query_term(
        &keyset,
        &data_plan(name, column),
        "value",
        operator,
        input,
        &EqlTargets,
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

/// One plaintext for each EQL type that answers an operator. Each field is
/// named after its type, and the name is its column.
#[derive(Zeroize)]
struct Columns {
    text_eq: String,
    integer_eq: i32,
    smallint_eq: i16,
    date_eq: Date,
    timestamp_eq: Timestamp,
    numeric_eq: Decimal,
    bigint_eq: i64,
    real_eq: f32,
    double_eq: f64,
    text_match: String,
}

/// A record with a field of each EQL type that answers an operator, in the
/// table `users`. Its field references are the typed queries under test.
#[derive(EncryptTarget)]
#[stash(struct = Columns, scope = "users")]
struct EncryptedColumns {
    text_eq: TextEq,
    integer_eq: integer::IntegerEq,
    smallint_eq: smallint::SmallintEq,
    date_eq: date::DateEq,
    timestamp_eq: timestamp::TimestampEq,
    numeric_eq: numeric::NumericEq,
    bigint_eq: bigint::BigintEq,
    real_eq: real::RealEq,
    double_eq: double::DoubleEq,
    text_match: TextMatch,
}

/// The row each query below asks for. The float values are the ones whose
/// terms the semantic baseline folds (`-0.0`, NaN), and the timestamp has
/// nanoseconds below a microsecond, which both paths truncate alike.
fn columns() -> Columns {
    Columns {
        text_eq: "bob@example.com".into(),
        integer_eq: -42,
        smallint_eq: -7,
        date_eq: common::date_of_days(19_000),
        timestamp_eq: common::timestamp_of(1_700_000_000, 123_456_789),
        numeric_eq: common::decimal_of(-1_234_567, 4),
        bigint_eq: i64::MIN + 1,
        real_eq: -0.0,
        double_eq: f64::NAN,
        text_match: "alice".into(),
    }
}

/// A field query for one operator, as what the tests compare: the bytes
/// it binds with its query domain, the column the field reference names, and the
/// input the data path is given for the same query.
struct Typed {
    bytes: (Vec<u8>, String),
    column: &'static str,
    input: ValueFrame,
}

/// The query `$field reference.$operator(value)` under `$keyset`, where
/// `value` is the row's `$field`, with the same value as the data path's
/// input. The row is built twice: a plaintext is not `Clone`.
macro_rules! typed {
    ($keyset:expr, $reference:expr, $operator:ident, $field:ident) => {{
        let reference = $reference;
        let query = reference
            .$operator(columns().$field)
            .encrypt($keyset)
            .await
            .unwrap();
        Typed {
            bytes: typed_bytes(&query),
            column: reference.name(),
            input: frame(columns().$field),
        }
    }};
}

/// The field query for each operator a type answers, for the value the
/// row `columns()` holds: one arm per row of `ANSWERS`, so a type that
/// starts answering an operator fails here until it has one, and an arm
/// compiles only if the type implements `op::Answers` for it.
async fn typed_and_input(keyset: &Keyset<'_>, name: &str, operator: &str) -> Typed {
    let row = columns();
    match (name, operator) {
        ("TextEq", "eq") => typed!(keyset, EncryptedColumns::TEXT_EQ, eq, text_eq),
        ("IntegerEq", "eq") => typed!(keyset, EncryptedColumns::INTEGER_EQ, eq, integer_eq),
        ("SmallintEq", "eq") => typed!(keyset, EncryptedColumns::SMALLINT_EQ, eq, smallint_eq),
        ("DateEq", "eq") => typed!(keyset, EncryptedColumns::DATE_EQ, eq, date_eq),
        ("TimestampEq", "eq") => {
            typed!(keyset, EncryptedColumns::TIMESTAMP_EQ, eq, timestamp_eq)
        }
        ("NumericEq", "eq") => typed!(keyset, EncryptedColumns::NUMERIC_EQ, eq, numeric_eq),
        ("BigintEq", "eq") => typed!(keyset, EncryptedColumns::BIGINT_EQ, eq, bigint_eq),
        ("RealEq", "eq") => typed!(keyset, EncryptedColumns::REAL_EQ, eq, real_eq),
        ("DoubleEq", "eq") => typed!(keyset, EncryptedColumns::DOUBLE_EQ, eq, double_eq),
        ("TextMatch", "matches") => {
            let reference = EncryptedColumns::TEXT_MATCH;
            let query: MatchTwin<TextMatchQuery> = reference
                .matches(row.text_match.clone())
                .encrypt(keyset)
                .await
                .unwrap();
            Typed {
                bytes: typed_bytes(query.twin()),
                column: reference.name(),
                input: frame(row.text_match),
            }
        }
        _ => panic!(
            "{name} answers `{operator}` from a field reference: give it a field in \
             `EncryptedColumns` and an arm here, with the input the data path is given"
        ),
    }
}

/// The operators each type answers from a field reference are exactly the
/// ones the data path answers for a field that names it, type by type, in
/// order, for every type whose twin a field query assembles: one term,
/// from an equality or a match index. A producible type whose twin needs
/// an order term, or several terms, is the one gap: the data path answers
/// it and a field reference answers nothing, and this holds the gap to exactly
/// those types, so a type with an equality or match twin cannot drop out
/// unseen. The typed impls and `ANSWERS` are generated from one rule, so
/// this is what holds that rule to the engine's.
#[test]
fn a_field_reference_answers_what_the_data_path_answers() {
    let mut gap = Vec::new();
    // A document's field reference answers through its JSON queries
    // (`JsonQueries`), not `Answers`: tests/json_tree_field_references.rs holds them
    // to the data path.
    for target in eql_targets::targets()
        .iter()
        .filter(|t| t.plaintext != Some("json"))
    {
        let data: Vec<&str> = TargetDescriptor::from(target)
            .operators()
            .into_iter()
            .map(Op::name)
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
                "{}: a field reference answers nothing yet",
                target.name
            );
            if !data.is_empty() {
                gap.push(target.name);
            }
        }
    }
    // The gap today: every producible ordered type (OPE and block ORE), and
    // text search, whose twins carry an order term among their three. A type
    // leaves this list when a field query assembles its twin, and its
    // answers are then held to the data path's above.
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

/// Every field query binds the bytes the data path derives for the same
/// column, operator and value, under the same query domain. The twin
/// names the column the field reference names: the record's scope, then the field.
#[tokio::test]
async fn every_field_query_is_the_data_paths_query() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for (name, operators) in ANSWERS {
        for operator in *operators {
            let typed = typed_and_input(&keyset, name, operator).await;
            let op = Op::parse(operator).unwrap();
            let data = data_term(&cipher, name, typed.column, op, typed.input).await;
            assert_eq!(typed.bytes, data, "{name} {operator}");
            let json: serde_json::Value = serde_json::from_slice(&typed.bytes.0).unwrap();
            assert_eq!(json["v"], 4, "{name}");
            assert_eq!(
                json["i"],
                serde_json::json!({"t": "users", "c": typed.column})
            );
        }
    }
}

/// Every field query carries the term of the row its record stored: the
/// `hm` of an exact type's field, and a filter the stored `bf` of a match
/// type's field contains.
#[tokio::test]
async fn every_field_query_is_the_term_of_the_row_its_record_stored() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let stored: EncryptedColumns = columns().encrypt_into(&keyset).await.unwrap();
    let field = |column: &str| {
        match column {
            "text_eq" => serde_json::to_value(&stored.text_eq),
            "integer_eq" => serde_json::to_value(&stored.integer_eq),
            "smallint_eq" => serde_json::to_value(&stored.smallint_eq),
            "date_eq" => serde_json::to_value(&stored.date_eq),
            "timestamp_eq" => serde_json::to_value(&stored.timestamp_eq),
            "numeric_eq" => serde_json::to_value(&stored.numeric_eq),
            "bigint_eq" => serde_json::to_value(&stored.bigint_eq),
            "real_eq" => serde_json::to_value(&stored.real_eq),
            "double_eq" => serde_json::to_value(&stored.double_eq),
            "text_match" => serde_json::to_value(&stored.text_match),
            other => panic!("`EncryptedColumns` has no field {other}"),
        }
        .unwrap()
    };
    for (name, operators) in ANSWERS {
        for operator in *operators {
            let typed = typed_and_input(&keyset, name, operator).await;
            let query: serde_json::Value = serde_json::from_slice(&typed.bytes.0).unwrap();
            let row = field(typed.column);
            assert_eq!(query["i"], row["i"], "{name}: the same column");
            match *operator {
                "eq" => assert_eq!(query["hm"], row["hm"], "{name}: the stored term"),
                "matches" => {
                    let stored = row["bf"].as_array().unwrap();
                    let asked = query["bf"].as_array().unwrap();
                    assert!(!asked.is_empty(), "{name}: the query sets a position");
                    assert!(
                        asked.iter().all(|position| stored.contains(position)),
                        "{name}: the stored filter contains the query's"
                    );
                }
                other => panic!("{name} answers `{other}`: say what its query finds here"),
            }
        }
    }
}

#[derive(Clone, Zeroize)]
struct User {
    email: String,
    name: String,
}

/// A record with an exact field and a match field, in the table `users`,
/// that lists no scope.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    email: TextEq,
    name: TextMatch,
}

/// The field reference's `TextEq` query is the term of a value the type stored on
/// its own under the same column, as the data path's is.
#[tokio::test]
async fn a_field_reference_eq_query_matches_the_stored_term() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let column = Identifier::for_column("users", "email").unwrap();
    let stored: TextEq = "bob@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, column)
        .await
        .unwrap();
    let query = EncryptedUser::EMAIL
        .eq("bob@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(query.hm, stored.hm);
    assert_eq!(query.i, stored.i);
    let other = EncryptedUser::EMAIL
        .eq("alice@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_ne!(other.hm, stored.hm);
}

/// `verify` and `target_limit` on the field reference's `TextMatch` query answer as
/// the data path's `verify` and `target_limit` do for the same query.
#[tokio::test]
async fn a_field_reference_match_query_verifies_and_sizes_as_the_data_path_does() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let plan = data_plan("TextMatch", "name");
    for needle in ["alice", "ali", "ALICE SMITH"] {
        let query: MatchTwin<TextMatchQuery> = EncryptedUser::NAME
            .matches(needle)
            .encrypt(&keyset)
            .await
            .unwrap();
        let input = frame(needle);

        let page = ["Alice Smith", "alicia", "Bob", "malice", "ALICE", "al", ""];
        let data = dynamic::verify(
            &plan,
            "value",
            Op::Matches,
            again(&input),
            page,
            &EqlTargets,
        )
        .unwrap();
        let typed: Vec<bool> = page.iter().map(|v| query.verify(v)).collect();
        assert_eq!(typed, data, "{needle}");
        assert!(query.verify("Alice Smith"), "{needle}");
        assert!(!query.verify("Bob"), "{needle}");

        let (term, _) = data_term(&cipher, "TextMatch", "name", Op::Matches, input).await;
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
                    Op::Matches,
                    &term,
                    want,
                    &stats,
                    &EqlTargets,
                )
                .unwrap();
                assert_eq!(query.target_limit(want, &stats), data, "{needle} {want}");
            }
        }
    }
}

/// A field query refuses what the data path refuses: match text that cuts
/// no token is no query, by either path.
///
/// A field reference's label is its record's scope and its field's name, so it
/// always names a column: the refusal of a label that names no column is
/// the data path's alone (tests/targets.rs).
#[tokio::test]
async fn a_field_query_refuses_what_the_data_path_refuses() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let short = EncryptedUser::NAME.matches("a").encrypt(&keyset).await;
    assert!(
        matches!(
            short,
            Err(Error::Term(stack_encrypt::sem::TermError::EmptyTermText))
        ),
        "{short:?}"
    );
    let data = dynamic::query_term(
        &keyset,
        &data_plan("TextMatch", "name"),
        "value",
        Op::Matches,
        frame("a"),
        &EqlTargets,
    );
    assert!(
        matches!(
            data,
            Err(dynamic::Error::Cipher(Error::Term(
                stack_encrypt::sem::TermError::EmptyTermText
            )))
        ),
        "the data path refuses the same text, before it derives a term"
    );
}

#[derive(Clone, Zeroize)]
struct Person {
    email: String,
    name: String,
}

/// A record whose caller supplies a tenant scope, with an exact field and a
/// match field. Each field stores its column, and not the tenant.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Person, scope = "users", scope(tenant: i64))]
struct EncryptedPerson {
    email: TextEq,
    name: TextMatch,
}

/// A field query given a scope with `.scope(..)` derives its term under
/// the column and the scope. A record stores its fields the same way under
/// a scope. So the scoped query is the term of the row stored under that
/// scope, and the twin stores the column alone, as the row does. For an
/// exact type and for `TextMatch`.
#[tokio::test]
async fn a_scoped_field_query_finds_a_value_stored_under_the_same_scope() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let stored: EncryptedPerson = Person {
        email: "bob@example.com".into(),
        name: "Bob Jones".into(),
    }
    .encrypt_into_with_context(&keyset, Scope::new(7i64))
    .await
    .unwrap();

    let query = EncryptedPerson::EMAIL
        .eq("bob@example.com")
        .scope(Scope::new(7i64))
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(query.i, stored.email.i, "the twin stores the column alone");
    assert_eq!(query.hm, stored.email.hm, "the term of the stored row");

    // Another scope, or none, gives another term. The query with no scope
    // is from the field reference of a record that lists none, for the same column.
    let other = EncryptedPerson::EMAIL
        .eq("bob@example.com")
        .scope(Scope::new(8i64))
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_ne!(other.hm, stored.email.hm);
    let unscoped = EncryptedUser::EMAIL
        .eq("bob@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(unscoped.i, stored.email.i);
    assert_ne!(unscoped.hm, stored.email.hm);

    let query = EncryptedPerson::NAME
        .matches("jones")
        .scope(Scope::new(7i64))
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(query.twin().i, stored.name.i);
    // Every position the query sets is set in the stored filter.
    assert!(
        query
            .twin()
            .bf
            .0
            .iter()
            .all(|position| stored.name.bf.0.contains(position)),
        "the stored filter contains the query's"
    );
    let other = EncryptedPerson::NAME
        .matches("jones")
        .scope(Scope::new(8i64))
        .encrypt(&keyset)
        .await
        .unwrap();
    assert!(
        !other
            .twin()
            .bf
            .0
            .iter()
            .all(|position| stored.name.bf.0.contains(position)),
        "under another scope the filter differs"
    );
}

/// A record field naming a storage-only EQL type may store a null as the
/// plan says, through the resolver the Go guest installs:
/// `"sealed"` stores an EQL value whose `c` is a typed null, as long as a
/// value's, and `"sql"` stores nothing for the field. Both open as a null.
#[tokio::test]
async fn a_record_stores_a_null_in_an_eql_field_as_its_plan_says() {
    use dynamic::NullMode;
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
        &EqlTargets,
    )
    .unwrap();
    let day = Some(jiff::civil::date(1990, 5, 17));
    let rows = |dob, born| BTreeMap::from([("a_dob", dob), ("b_born", born)]);
    let source = vec![rows(day, day), rows(None, None)];
    let sealed = record::encrypt_with(&keyset, frame(&source), &plan, &EqlTargets)
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

    let opened = record::decrypt_with(&cipher, sealed, &plan, None, &EqlTargets)
        .unwrap()
        .await
        .unwrap();
    assert_eq!(opened.risky_ref(), frame(&source).risky_ref());
}

/// A second frame of the same bytes. A frame is not `Clone`.
fn again(frame: &ValueFrame) -> ValueFrame {
    use stack_encrypt::AsProtectedRef as _;
    ValueFrame::from_bytes(frame.as_protected_ref()).unwrap()
}
