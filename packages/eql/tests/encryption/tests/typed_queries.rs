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
    bigint, date, double, integer, numeric, real, smallint, text, timestamp, DomainType,
};
use eql_bindings::Identifier;
use serde::Serialize;
use stack_encrypt::dynamic::{self, record, FieldPlan, Op, Operand, TargetDescriptor, ValueFrame};
use stack_encrypt::op::{Probabilistic, Stats};
use stack_encrypt::target::Scope;
use stack_encrypt::{ContextPiece, Encrypt, Error, KeysetCipher, NonEmpty, StackCipher};
use stack_encrypt::{DecryptSource, EncryptInto, EncryptTarget};
use std::cmp::Ordering;
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
    integer_eq: i32,
    integer_ord_ore: i32,
    integer_ord: i32,
    integer_ord_ope: i32,
    smallint_eq: i16,
    smallint_ord_ore: i16,
    smallint_ord: i16,
    smallint_ord_ope: i16,
    bigint_eq: i64,
    bigint_ord_ore: i64,
    bigint_ord: i64,
    bigint_ord_ope: i64,
    date_eq: Date,
    date_ord_ore: Date,
    date_ord: Date,
    date_ord_ope: Date,
    timestamp_eq: Timestamp,
    timestamp_ord_ore: Timestamp,
    timestamp_ord: Timestamp,
    timestamp_ord_ope: Timestamp,
    numeric_eq: Decimal,
    numeric_ord_ore: Decimal,
    numeric_ord: Decimal,
    numeric_ord_ope: Decimal,
    text_eq: String,
    text_match: String,
    text_ord_ore: String,
    text_ord: String,
    text_ord_ope: String,
    text_search_ore: String,
    text_search: String,
    real_eq: f32,
    real_ord_ore: f32,
    real_ord: f32,
    real_ord_ope: f32,
    double_eq: f64,
    double_ord_ore: f64,
    double_ord: f64,
    double_ord_ope: f64,
}

/// A record with a field of each EQL type that answers an operator, in the
/// table `users`. Its field references are the typed queries under test.
#[derive(EncryptTarget)]
#[stash(struct = Columns, scope = "users")]
struct EncryptedColumns {
    integer_eq: integer::IntegerEq,
    integer_ord_ore: integer::IntegerOrdOre,
    integer_ord: integer::IntegerOrd,
    integer_ord_ope: integer::IntegerOrdOpe,
    smallint_eq: smallint::SmallintEq,
    smallint_ord_ore: smallint::SmallintOrdOre,
    smallint_ord: smallint::SmallintOrd,
    smallint_ord_ope: smallint::SmallintOrdOpe,
    bigint_eq: bigint::BigintEq,
    bigint_ord_ore: bigint::BigintOrdOre,
    bigint_ord: bigint::BigintOrd,
    bigint_ord_ope: bigint::BigintOrdOpe,
    date_eq: date::DateEq,
    date_ord_ore: date::DateOrdOre,
    date_ord: date::DateOrd,
    date_ord_ope: date::DateOrdOpe,
    timestamp_eq: timestamp::TimestampEq,
    timestamp_ord_ore: timestamp::TimestampOrdOre,
    timestamp_ord: timestamp::TimestampOrd,
    timestamp_ord_ope: timestamp::TimestampOrdOpe,
    numeric_eq: numeric::NumericEq,
    numeric_ord_ore: numeric::NumericOrdOre,
    numeric_ord: numeric::NumericOrd,
    numeric_ord_ope: numeric::NumericOrdOpe,
    text_eq: text::TextEq,
    text_match: text::TextMatch,
    text_ord_ore: text::TextOrdOre,
    text_ord: text::TextOrd,
    text_ord_ope: text::TextOrdOpe,
    text_search_ore: text::TextSearchOre,
    text_search: text::TextSearch,
    real_eq: real::RealEq,
    real_ord_ore: real::RealOrdOre,
    real_ord: real::RealOrd,
    real_ord_ope: real::RealOrdOpe,
    double_eq: double::DoubleEq,
    double_ord_ore: double::DoubleOrdOre,
    double_ord: double::DoubleOrd,
    double_ord_ope: double::DoubleOrdOpe,
}

/// The row each query below asks for. The float values are the ones whose
/// terms the semantic baseline folds (`-0.0`, NaN), and the timestamp has
/// nanoseconds below a microsecond, which both paths truncate alike.
fn columns() -> Columns {
    Columns {
        integer_eq: -42,
        integer_ord_ore: -42,
        integer_ord: -42,
        integer_ord_ope: -42,
        smallint_eq: -7,
        smallint_ord_ore: -7,
        smallint_ord: -7,
        smallint_ord_ope: -7,
        bigint_eq: i64::MIN + 1,
        bigint_ord_ore: i64::MIN + 1,
        bigint_ord: i64::MIN + 1,
        bigint_ord_ope: i64::MIN + 1,
        date_eq: common::date_of_days(19_000),
        date_ord_ore: common::date_of_days(19_000),
        date_ord: common::date_of_days(19_000),
        date_ord_ope: common::date_of_days(19_000),
        timestamp_eq: common::timestamp_of(1_700_000_000, 123_456_789),
        timestamp_ord_ore: common::timestamp_of(1_700_000_000, 123_456_789),
        timestamp_ord: common::timestamp_of(1_700_000_000, 123_456_789),
        timestamp_ord_ope: common::timestamp_of(1_700_000_000, 123_456_789),
        numeric_eq: common::decimal_of(-1_234_567, 4),
        numeric_ord_ore: common::decimal_of(-1_234_567, 4),
        numeric_ord: common::decimal_of(-1_234_567, 4),
        numeric_ord_ope: common::decimal_of(-1_234_567, 4),
        text_eq: "bob@example.com".into(),
        text_match: "alice".into(),
        text_ord_ore: "bob@example.com".into(),
        text_ord: "bob@example.com".into(),
        text_ord_ope: "bob@example.com".into(),
        text_search_ore: "alice smith".into(),
        text_search: "alice smith".into(),
        real_eq: -0.0,
        real_ord_ore: -0.0,
        real_ord: -0.0,
        real_ord_ope: -0.0,
        double_eq: f64::NAN,
        double_ord_ore: f64::NAN,
        double_ord: f64::NAN,
        double_ord_ope: f64::NAN,
    }
}

/// The stored value of the field `column` of `stored`, as JSON.
fn stored_field(stored: &EncryptedColumns, column: &str) -> serde_json::Value {
    match column {
        "integer_eq" => serde_json::to_value(&stored.integer_eq),
        "integer_ord_ore" => serde_json::to_value(&stored.integer_ord_ore),
        "integer_ord" => serde_json::to_value(&stored.integer_ord),
        "integer_ord_ope" => serde_json::to_value(&stored.integer_ord_ope),
        "smallint_eq" => serde_json::to_value(&stored.smallint_eq),
        "smallint_ord_ore" => serde_json::to_value(&stored.smallint_ord_ore),
        "smallint_ord" => serde_json::to_value(&stored.smallint_ord),
        "smallint_ord_ope" => serde_json::to_value(&stored.smallint_ord_ope),
        "bigint_eq" => serde_json::to_value(&stored.bigint_eq),
        "bigint_ord_ore" => serde_json::to_value(&stored.bigint_ord_ore),
        "bigint_ord" => serde_json::to_value(&stored.bigint_ord),
        "bigint_ord_ope" => serde_json::to_value(&stored.bigint_ord_ope),
        "date_eq" => serde_json::to_value(&stored.date_eq),
        "date_ord_ore" => serde_json::to_value(&stored.date_ord_ore),
        "date_ord" => serde_json::to_value(&stored.date_ord),
        "date_ord_ope" => serde_json::to_value(&stored.date_ord_ope),
        "timestamp_eq" => serde_json::to_value(&stored.timestamp_eq),
        "timestamp_ord_ore" => serde_json::to_value(&stored.timestamp_ord_ore),
        "timestamp_ord" => serde_json::to_value(&stored.timestamp_ord),
        "timestamp_ord_ope" => serde_json::to_value(&stored.timestamp_ord_ope),
        "numeric_eq" => serde_json::to_value(&stored.numeric_eq),
        "numeric_ord_ore" => serde_json::to_value(&stored.numeric_ord_ore),
        "numeric_ord" => serde_json::to_value(&stored.numeric_ord),
        "numeric_ord_ope" => serde_json::to_value(&stored.numeric_ord_ope),
        "text_eq" => serde_json::to_value(&stored.text_eq),
        "text_match" => serde_json::to_value(&stored.text_match),
        "text_ord_ore" => serde_json::to_value(&stored.text_ord_ore),
        "text_ord" => serde_json::to_value(&stored.text_ord),
        "text_ord_ope" => serde_json::to_value(&stored.text_ord_ope),
        "text_search_ore" => serde_json::to_value(&stored.text_search_ore),
        "text_search" => serde_json::to_value(&stored.text_search),
        "real_eq" => serde_json::to_value(&stored.real_eq),
        "real_ord_ore" => serde_json::to_value(&stored.real_ord_ore),
        "real_ord" => serde_json::to_value(&stored.real_ord),
        "real_ord_ope" => serde_json::to_value(&stored.real_ord_ope),
        "double_eq" => serde_json::to_value(&stored.double_eq),
        "double_ord_ore" => serde_json::to_value(&stored.double_ord_ore),
        "double_ord" => serde_json::to_value(&stored.double_ord),
        "double_ord_ope" => serde_json::to_value(&stored.double_ord_ope),
        other => panic!("`EncryptedColumns` has no field {other}"),
    }
    .unwrap()
}

/// A field query for one operator, as what the tests compare: the bytes
/// it binds with its query domain, the column the field reference names, and the
/// input the data path is given for the same query.
struct Typed {
    bytes: (Vec<u8>, String),
    column: &'static str,
    input: ValueFrame,
}

/// The query `$reference.<operator>(value)` under `$keyset`, for the
/// operator named at run time among those the type answers: each of
/// `$exact` returns the twin, and `matches` a `MatchTwin` of it, whose twin
/// is what binds. `value` is the row's `$field`, and the data path's input
/// is the same value. The row is built again for each: a plaintext is not
/// `Clone`. An arm compiles only if the type implements `op::Answers` for
/// its operator.
macro_rules! typed {
    ($keyset:expr, $operator:expr, $reference:expr, $field:ident, [$($exact:ident),*] $(, $matches:ident)?) => {{
        let reference = $reference;
        let bytes = match $operator {
            $(stringify!($exact) => typed_bytes(
                &reference.$exact(columns().$field).encrypt($keyset).await.unwrap(),
            ),)*
            $(stringify!($matches) => typed_bytes(
                reference.$matches(columns().$field).encrypt($keyset).await.unwrap().twin(),
            ),)?
            other => panic!("{} answers no `{other}` from a field reference", stringify!($field)),
        };
        Typed {
            bytes,
            column: reference.name(),
            input: frame(columns().$field),
        }
    }};
}

/// The field query for each operator a type answers, for the value the
/// row `columns()` holds: one arm per row of `ANSWERS`, so a type that
/// starts answering an operator fails here until it has one.
async fn typed_and_input(keyset: &Keyset<'_>, name: &str, operator: &str) -> Typed {
    match name {
        "IntegerEq" => typed!(
            keyset,
            operator,
            EncryptedColumns::INTEGER_EQ,
            integer_eq,
            [eq]
        ),
        "IntegerOrdOre" => typed!(
            keyset,
            operator,
            EncryptedColumns::INTEGER_ORD_ORE,
            integer_ord_ore,
            [lt, lte, gt, gte]
        ),
        "IntegerOrd" => typed!(
            keyset,
            operator,
            EncryptedColumns::INTEGER_ORD,
            integer_ord,
            [lt, lte, gt, gte]
        ),
        "IntegerOrdOpe" => typed!(
            keyset,
            operator,
            EncryptedColumns::INTEGER_ORD_OPE,
            integer_ord_ope,
            [lt, lte, gt, gte]
        ),
        "SmallintEq" => typed!(
            keyset,
            operator,
            EncryptedColumns::SMALLINT_EQ,
            smallint_eq,
            [eq]
        ),
        "SmallintOrdOre" => typed!(
            keyset,
            operator,
            EncryptedColumns::SMALLINT_ORD_ORE,
            smallint_ord_ore,
            [lt, lte, gt, gte]
        ),
        "SmallintOrd" => typed!(
            keyset,
            operator,
            EncryptedColumns::SMALLINT_ORD,
            smallint_ord,
            [lt, lte, gt, gte]
        ),
        "SmallintOrdOpe" => typed!(
            keyset,
            operator,
            EncryptedColumns::SMALLINT_ORD_OPE,
            smallint_ord_ope,
            [lt, lte, gt, gte]
        ),
        "BigintEq" => typed!(
            keyset,
            operator,
            EncryptedColumns::BIGINT_EQ,
            bigint_eq,
            [eq]
        ),
        "BigintOrdOre" => typed!(
            keyset,
            operator,
            EncryptedColumns::BIGINT_ORD_ORE,
            bigint_ord_ore,
            [lt, lte, gt, gte]
        ),
        "BigintOrd" => typed!(
            keyset,
            operator,
            EncryptedColumns::BIGINT_ORD,
            bigint_ord,
            [lt, lte, gt, gte]
        ),
        "BigintOrdOpe" => typed!(
            keyset,
            operator,
            EncryptedColumns::BIGINT_ORD_OPE,
            bigint_ord_ope,
            [lt, lte, gt, gte]
        ),
        "DateEq" => typed!(keyset, operator, EncryptedColumns::DATE_EQ, date_eq, [eq]),
        "DateOrdOre" => typed!(
            keyset,
            operator,
            EncryptedColumns::DATE_ORD_ORE,
            date_ord_ore,
            [lt, lte, gt, gte]
        ),
        "DateOrd" => typed!(
            keyset,
            operator,
            EncryptedColumns::DATE_ORD,
            date_ord,
            [lt, lte, gt, gte]
        ),
        "DateOrdOpe" => typed!(
            keyset,
            operator,
            EncryptedColumns::DATE_ORD_OPE,
            date_ord_ope,
            [lt, lte, gt, gte]
        ),
        "TimestampEq" => typed!(
            keyset,
            operator,
            EncryptedColumns::TIMESTAMP_EQ,
            timestamp_eq,
            [eq]
        ),
        "TimestampOrdOre" => typed!(
            keyset,
            operator,
            EncryptedColumns::TIMESTAMP_ORD_ORE,
            timestamp_ord_ore,
            [lt, lte, gt, gte]
        ),
        "TimestampOrd" => typed!(
            keyset,
            operator,
            EncryptedColumns::TIMESTAMP_ORD,
            timestamp_ord,
            [lt, lte, gt, gte]
        ),
        "TimestampOrdOpe" => typed!(
            keyset,
            operator,
            EncryptedColumns::TIMESTAMP_ORD_OPE,
            timestamp_ord_ope,
            [lt, lte, gt, gte]
        ),
        "NumericEq" => typed!(
            keyset,
            operator,
            EncryptedColumns::NUMERIC_EQ,
            numeric_eq,
            [eq]
        ),
        "NumericOrdOre" => typed!(
            keyset,
            operator,
            EncryptedColumns::NUMERIC_ORD_ORE,
            numeric_ord_ore,
            [lt, lte, gt, gte]
        ),
        "NumericOrd" => typed!(
            keyset,
            operator,
            EncryptedColumns::NUMERIC_ORD,
            numeric_ord,
            [lt, lte, gt, gte]
        ),
        "NumericOrdOpe" => typed!(
            keyset,
            operator,
            EncryptedColumns::NUMERIC_ORD_OPE,
            numeric_ord_ope,
            [lt, lte, gt, gte]
        ),
        "TextEq" => typed!(keyset, operator, EncryptedColumns::TEXT_EQ, text_eq, [eq]),
        "TextMatch" => typed!(
            keyset,
            operator,
            EncryptedColumns::TEXT_MATCH,
            text_match,
            [],
            matches
        ),
        "TextOrdOre" => typed!(
            keyset,
            operator,
            EncryptedColumns::TEXT_ORD_ORE,
            text_ord_ore,
            [eq, lt, lte, gt, gte]
        ),
        "TextOrd" => typed!(
            keyset,
            operator,
            EncryptedColumns::TEXT_ORD,
            text_ord,
            [eq, lt, lte, gt, gte]
        ),
        "TextOrdOpe" => typed!(
            keyset,
            operator,
            EncryptedColumns::TEXT_ORD_OPE,
            text_ord_ope,
            [eq, lt, lte, gt, gte]
        ),
        "TextSearchOre" => typed!(
            keyset,
            operator,
            EncryptedColumns::TEXT_SEARCH_ORE,
            text_search_ore,
            [eq, lt, lte, gt, gte],
            matches
        ),
        "TextSearch" => typed!(
            keyset,
            operator,
            EncryptedColumns::TEXT_SEARCH,
            text_search,
            [eq, lt, lte, gt, gte],
            matches
        ),
        "RealEq" => typed!(keyset, operator, EncryptedColumns::REAL_EQ, real_eq, [eq]),
        "RealOrdOre" => typed!(
            keyset,
            operator,
            EncryptedColumns::REAL_ORD_ORE,
            real_ord_ore,
            [lt, lte, gt, gte]
        ),
        "RealOrd" => typed!(
            keyset,
            operator,
            EncryptedColumns::REAL_ORD,
            real_ord,
            [lt, lte, gt, gte]
        ),
        "RealOrdOpe" => typed!(
            keyset,
            operator,
            EncryptedColumns::REAL_ORD_OPE,
            real_ord_ope,
            [lt, lte, gt, gte]
        ),
        "DoubleEq" => typed!(
            keyset,
            operator,
            EncryptedColumns::DOUBLE_EQ,
            double_eq,
            [eq]
        ),
        "DoubleOrdOre" => typed!(
            keyset,
            operator,
            EncryptedColumns::DOUBLE_ORD_ORE,
            double_ord_ore,
            [lt, lte, gt, gte]
        ),
        "DoubleOrd" => typed!(
            keyset,
            operator,
            EncryptedColumns::DOUBLE_ORD,
            double_ord,
            [lt, lte, gt, gte]
        ),
        "DoubleOrdOpe" => typed!(
            keyset,
            operator,
            EncryptedColumns::DOUBLE_ORD_OPE,
            double_ord_ope,
            [lt, lte, gt, gte]
        ),
        _ => panic!(
            "{name} answers `{operator}` from a field reference: give it a field in \
             `EncryptedColumns` and an arm here, with the input the data path is given"
        ),
    }
}

/// The operators each type answers from a field reference are exactly the
/// ones the data path answers for a field that names it, type by type, in
/// order: the equality, match and ordered types, and text search. The
/// typed impls and `ANSWERS` are generated from one rule, so this is what
/// holds that rule to the engine's.
#[test]
fn a_field_reference_answers_what_the_data_path_answers() {
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
        assert_eq!(
            typed, data,
            "{}: a field reference answers what the data path answers",
            target.name
        );
    }
    for (name, _) in ANSWERS {
        assert!(eql_targets::target(name).is_some(), "{name} is a target");
    }
    let ordered = ANSWERS
        .iter()
        .filter(|(_, ops)| ops.contains(&"lt"))
        .count();
    assert_eq!(
        ordered, 29,
        "every ordered type and both text search types answer the orderings"
    );
}

/// Every field query binds the bytes the data path derives for the same
/// column, operator and value, under the same query domain, save a block
/// ORE term's nonce. The twin names the column the field reference names:
/// the record's scope, then the field.
#[tokio::test]
async fn every_field_query_is_the_data_paths_query() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let mut block_ore = 0;
    for (name, operators) in ANSWERS {
        for operator in *operators {
            let typed = typed_and_input(&keyset, name, operator).await;
            let op = Op::parse(operator).unwrap();
            let (bytes, domain) = data_term(&cipher, name, typed.column, op, typed.input).await;
            assert_eq!(typed.bytes.1, domain, "{name} {operator}: the query domain");
            let json: serde_json::Value = serde_json::from_slice(&typed.bytes.0).unwrap();
            let data: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            if json.get("ob").is_some() {
                block_ore += 1;
            } else {
                assert_eq!(typed.bytes.0, bytes, "{name} {operator}: the bytes");
            }
            assertions::same_terms(name, operator, &json, &data);
            assert_eq!(json["v"], 4, "{name}");
            assert_eq!(
                json["i"],
                serde_json::json!({"t": "users", "c": typed.column}),
                "{name}: the field reference's column"
            );
        }
    }
    assert!(block_ore > 0, "some queries carry a block ORE term");
}

/// Every field query carries the terms of the row its record stored for
/// the same value, so an equality finds the row and an ordering compares
/// equal to it: the `hm` and `op` of the row, a block ORE term that compares
/// equal to the row's, and for a match, a filter the stored `bf` contains.
#[tokio::test]
async fn every_field_query_is_the_term_of_the_row_its_record_stored() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let stored: EncryptedColumns = columns().encrypt_into(&keyset).await.unwrap();
    for (name, operators) in ANSWERS {
        for operator in *operators {
            let typed = typed_and_input(&keyset, name, operator).await;
            let query: serde_json::Value = serde_json::from_slice(&typed.bytes.0).unwrap();
            let row = stored_field(&stored, typed.column);
            assert_eq!(query["i"], row["i"], "{name}: the same column");
            match *operator {
                "matches" => {
                    let stored = row["bf"].as_array().unwrap();
                    let asked = query["bf"].as_array().unwrap();
                    assert!(!asked.is_empty(), "{name}: the query sets a position");
                    assert!(
                        asked.iter().all(|position| stored.contains(position)),
                        "{name}: the stored filter contains the query's"
                    );
                }
                "eq" | "lt" | "lte" | "gt" | "gte" => {
                    assertions::carries_the_rows_terms(name, operator, &query, &row)
                }
                other => panic!("{name} answers `{other}`: say what its query finds here"),
            }
        }
    }
}

mod assertions {
    use super::*;

    /// Two query values for one value carry the same terms: the same JSON,
    /// save a block ORE `ob`, which carries a random nonce, so two
    /// derivations of one value differ in their bytes and compare equal.
    pub(super) fn same_terms(
        name: &str,
        operator: &str,
        typed: &serde_json::Value,
        data: &serde_json::Value,
    ) {
        let (mut typed, mut data) = (typed.clone(), data.clone());
        let typed_ob = typed.as_object_mut().unwrap().remove("ob");
        let data_ob = data.as_object_mut().unwrap().remove("ob");
        match (&typed_ob, &data_ob) {
            (Some(typed_ob), Some(data_ob)) => assert_eq!(
                common::ob_order(name, typed_ob, data_ob),
                Ordering::Equal,
                "{name} {operator}: the block ORE terms of one value compare equal"
            ),
            (None, None) => {}
            _ => panic!("{name} {operator}: one path carries a block ORE term, the other none"),
        }
        assert_eq!(typed, data, "{name} {operator}: the same terms");
    }

    /// An exact query of the row's own value carries the row's terms: each
    /// of `hm` and `op` it carries is the row's, and a block ORE `ob`
    /// compares equal to the row's. It carries at least one.
    pub(super) fn carries_the_rows_terms(
        name: &str,
        operator: &str,
        query: &serde_json::Value,
        row: &serde_json::Value,
    ) {
        let mut carried = 0;
        for key in ["hm", "op"] {
            if let Some(term) = query.get(key) {
                carried += 1;
                assert_eq!(term, &row[key], "{name} {operator}: the row's `{key}`");
            }
        }
        if let Some(term) = query.get("ob") {
            carried += 1;
            assert_eq!(
                common::ob_order(name, term, &row["ob"]),
                Ordering::Equal,
                "{name} {operator}: compares equal to the row's `ob`"
            );
        }
        assert!(
            carried > 0,
            "{name} {operator}: the query carries a term: {query}"
        );
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
