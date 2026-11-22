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

/// Everything the tests below know of each EQL type that answers an
/// operator, written once per type: its name, the field of
/// `EncryptedColumns` that holds it and that field's reference, the type,
/// the plaintext and the row's value, and the operators it answers from a
/// field reference (`matches` after `+`). Each row becomes a field of the
/// plaintext record and of the encrypted one, a value of the row, an arm of
/// `stored_field`, `typed_and_input` and `column_of`.
macro_rules! answering_types {
    ($(
        $name:ident: $field:ident / $reference:ident: $ty:path, $plaintext:ty = $value:expr,
            [$($exact:ident),*] $(+ $matches:ident)?;
    )+) => {
        /// One plaintext for each EQL type that answers an operator. Each
        /// field is named after its type, and the name is its column.
        #[derive(Zeroize)]
        struct Columns {
            $($field: $plaintext,)+
        }

        /// A record with a field of each EQL type that answers an operator,
        /// in the table `users`. Its field references are the typed queries
        /// under test.
        #[derive(EncryptTarget)]
        #[stash(struct = Columns, scope = "users")]
        struct EncryptedColumns {
            $($field: $ty,)+
        }

        /// The row each query below asks for. The float values are the ones
        /// whose terms the semantic baseline folds (`-0.0`, NaN), and the
        /// timestamp has nanoseconds below a microsecond, which both paths
        /// truncate alike.
        fn columns() -> Columns {
            Columns {
                $($field: $value,)+
            }
        }

        /// The stored value of the field `column` of `stored`, as JSON.
        fn stored_field(stored: &EncryptedColumns, column: &str) -> serde_json::Value {
            match column {
                $(stringify!($field) => serde_json::to_value(&stored.$field),)+
                other => panic!("`EncryptedColumns` has no field {other}"),
            }
            .unwrap()
        }

        /// The field of `EncryptedColumns` that holds the type `name`, which
        /// is its column.
        fn column_of(name: &str) -> &'static str {
            match name {
                $(stringify!($name) => stringify!($field),)+
                other => panic!("`EncryptedColumns` holds no {other}"),
            }
        }

        /// The field query for each operator a type answers, for the value
        /// the row `columns()` holds: one arm per row of `ANSWERS`, so a type
        /// that starts answering an operator fails here until it has one.
        async fn typed_and_input(keyset: &Keyset<'_>, name: &str, operator: &str) -> Typed {
            match name {
                $(stringify!($name) => typed!(
                    keyset,
                    operator,
                    EncryptedColumns::$reference,
                    $field,
                    [$($exact),*]
                    $(, $matches)?
                ),)+
                _ => panic!(
                    "{name} answers `{operator}` from a field reference: give it a row in \
                     `answering_types!`, with the value the data path is given"
                ),
            }
        }
    };
}

answering_types! {
    IntegerEq: integer_eq / INTEGER_EQ: integer::IntegerEq, i32 = -42, [eq];
    IntegerOrdOre: integer_ord_ore / INTEGER_ORD_ORE: integer::IntegerOrdOre, i32 = -42,
        [lt, lte, gt, gte];
    IntegerOrd: integer_ord / INTEGER_ORD: integer::IntegerOrd, i32 = -42, [lt, lte, gt, gte];
    IntegerOrdOpe: integer_ord_ope / INTEGER_ORD_OPE: integer::IntegerOrdOpe, i32 = -42,
        [lt, lte, gt, gte];
    SmallintEq: smallint_eq / SMALLINT_EQ: smallint::SmallintEq, i16 = -7, [eq];
    SmallintOrdOre: smallint_ord_ore / SMALLINT_ORD_ORE: smallint::SmallintOrdOre, i16 = -7,
        [lt, lte, gt, gte];
    SmallintOrd: smallint_ord / SMALLINT_ORD: smallint::SmallintOrd, i16 = -7,
        [lt, lte, gt, gte];
    SmallintOrdOpe: smallint_ord_ope / SMALLINT_ORD_OPE: smallint::SmallintOrdOpe, i16 = -7,
        [lt, lte, gt, gte];
    BigintEq: bigint_eq / BIGINT_EQ: bigint::BigintEq, i64 = i64::MIN + 1, [eq];
    BigintOrdOre: bigint_ord_ore / BIGINT_ORD_ORE: bigint::BigintOrdOre, i64 = i64::MIN + 1,
        [lt, lte, gt, gte];
    BigintOrd: bigint_ord / BIGINT_ORD: bigint::BigintOrd, i64 = i64::MIN + 1,
        [lt, lte, gt, gte];
    BigintOrdOpe: bigint_ord_ope / BIGINT_ORD_OPE: bigint::BigintOrdOpe, i64 = i64::MIN + 1,
        [lt, lte, gt, gte];
    DateEq: date_eq / DATE_EQ: date::DateEq, Date = common::date_of_days(19_000), [eq];
    DateOrdOre: date_ord_ore / DATE_ORD_ORE: date::DateOrdOre,
        Date = common::date_of_days(19_000), [lt, lte, gt, gte];
    DateOrd: date_ord / DATE_ORD: date::DateOrd, Date = common::date_of_days(19_000),
        [lt, lte, gt, gte];
    DateOrdOpe: date_ord_ope / DATE_ORD_OPE: date::DateOrdOpe,
        Date = common::date_of_days(19_000), [lt, lte, gt, gte];
    TimestampEq: timestamp_eq / TIMESTAMP_EQ: timestamp::TimestampEq,
        Timestamp = common::timestamp_of(1_700_000_000, 123_456_789), [eq];
    TimestampOrdOre: timestamp_ord_ore / TIMESTAMP_ORD_ORE: timestamp::TimestampOrdOre,
        Timestamp = common::timestamp_of(1_700_000_000, 123_456_789), [lt, lte, gt, gte];
    TimestampOrd: timestamp_ord / TIMESTAMP_ORD: timestamp::TimestampOrd,
        Timestamp = common::timestamp_of(1_700_000_000, 123_456_789), [lt, lte, gt, gte];
    TimestampOrdOpe: timestamp_ord_ope / TIMESTAMP_ORD_OPE: timestamp::TimestampOrdOpe,
        Timestamp = common::timestamp_of(1_700_000_000, 123_456_789), [lt, lte, gt, gte];
    NumericEq: numeric_eq / NUMERIC_EQ: numeric::NumericEq,
        Decimal = common::decimal_of(-1_234_567, 4), [eq];
    NumericOrdOre: numeric_ord_ore / NUMERIC_ORD_ORE: numeric::NumericOrdOre,
        Decimal = common::decimal_of(-1_234_567, 4), [lt, lte, gt, gte];
    NumericOrd: numeric_ord / NUMERIC_ORD: numeric::NumericOrd,
        Decimal = common::decimal_of(-1_234_567, 4), [lt, lte, gt, gte];
    NumericOrdOpe: numeric_ord_ope / NUMERIC_ORD_OPE: numeric::NumericOrdOpe,
        Decimal = common::decimal_of(-1_234_567, 4), [lt, lte, gt, gte];
    TextEq: text_eq / TEXT_EQ: text::TextEq, String = "bob@example.com".into(), [eq];
    TextMatch: text_match / TEXT_MATCH: text::TextMatch, String = "alice".into(), [] + matches;
    TextOrdOre: text_ord_ore / TEXT_ORD_ORE: text::TextOrdOre,
        String = "bob@example.com".into(), [eq, lt, lte, gt, gte];
    TextOrd: text_ord / TEXT_ORD: text::TextOrd, String = "bob@example.com".into(),
        [eq, lt, lte, gt, gte];
    TextOrdOpe: text_ord_ope / TEXT_ORD_OPE: text::TextOrdOpe,
        String = "bob@example.com".into(), [eq, lt, lte, gt, gte];
    TextSearchOre: text_search_ore / TEXT_SEARCH_ORE: text::TextSearchOre,
        String = "alice smith".into(), [eq, lt, lte, gt, gte] + matches;
    TextSearch: text_search / TEXT_SEARCH: text::TextSearch, String = "alice smith".into(),
        [eq, lt, lte, gt, gte] + matches;
    RealEq: real_eq / REAL_EQ: real::RealEq, f32 = -0.0, [eq];
    RealOrdOre: real_ord_ore / REAL_ORD_ORE: real::RealOrdOre, f32 = -0.0, [lt, lte, gt, gte];
    RealOrd: real_ord / REAL_ORD: real::RealOrd, f32 = -0.0, [lt, lte, gt, gte];
    RealOrdOpe: real_ord_ope / REAL_ORD_OPE: real::RealOrdOpe, f32 = -0.0, [lt, lte, gt, gte];
    DoubleEq: double_eq / DOUBLE_EQ: double::DoubleEq, f64 = f64::NAN, [eq];
    DoubleOrdOre: double_ord_ore / DOUBLE_ORD_ORE: double::DoubleOrdOre, f64 = f64::NAN,
        [lt, lte, gt, gte];
    DoubleOrd: double_ord / DOUBLE_ORD: double::DoubleOrd, f64 = f64::NAN, [lt, lte, gt, gte];
    DoubleOrdOpe: double_ord_ope / DOUBLE_ORD_OPE: double::DoubleOrdOpe, f64 = f64::NAN,
        [lt, lte, gt, gte];
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
            assertions::carries_the_terms_its_descriptor_says(name, operator, &json);
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

    /// A match query's filter sets positions, and the stored filter of the
    /// row `row` sets each of them, so the database's `matches` finds the
    /// row.
    pub(super) fn stored_filter_contains_the_querys(
        name: &str,
        needle: &str,
        query: &serde_json::Value,
        row: &serde_json::Value,
    ) {
        assert_eq!(query["i"], row["i"], "{name} {needle:?}: the same column");
        let asked = query["bf"].as_array().unwrap();
        let stored = row["bf"].as_array().unwrap();
        assert!(
            !asked.is_empty(),
            "{name} {needle:?}: the query sets a position: {query}"
        );
        assert!(
            asked.iter().all(|position| stored.contains(position)),
            "{name} {needle:?}: the stored filter of {row} contains the query's {query}"
        );
    }

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

    /// A query carries the term of every index its type carries exactly
    /// when the type's descriptor says so, which is what the data path
    /// prepares a query by; otherwise the answering index's term alone.
    pub(super) fn carries_the_terms_its_descriptor_says(
        name: &str,
        operator: &str,
        query: &serde_json::Value,
    ) {
        let target = eql_targets::target(name).unwrap();
        let carried = ["hm", "op", "ob", "bf"]
            .into_iter()
            .filter(|term| query.get(term).is_some())
            .count();
        let every = TargetDescriptor::from(target).query_carries_every_term;
        assert_eq!(
            carried,
            if every { target.indexes.len() } else { 1 },
            "{name} {operator}: the query carries every index's term exactly when the \
             descriptor says so ({every}): {query}"
        );
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

/// A field reference's match query keeps a query's two-letter words only
/// when it cuts no 3-gram, as the data path's does, on every type with a
/// match index: `TextMatch`, and `TextSearch` and `TextSearchOre`, whose
/// twins carry the equality and order terms beside the match term. "Ng" is
/// its word and does not find "Nguyen"; "Mike Ng" and "ke Ng" are their
/// 3-grams and find "Mike Nguyen".
mod given_a_two_letter_word_in_a_match_query {
    use super::*;

    /// The types with a match index, each with the column its field
    /// reference on `EncryptedColumns` names.
    const MATCH_TYPES: [(&str, &str); 3] = [
        ("TextMatch", "text_match"),
        ("TextSearch", "text_search"),
        ("TextSearchOre", "text_search_ore"),
    ];

    /// The rows each query is verified against.
    const PAGE: [&str; 5] = ["Ng", "Mike Ng", "Mike Nguyen", "Nguyen", "Mike"];

    /// Each query, and which rows of [`PAGE`] it keeps.
    const QUERIES: [(&str, [bool; 5]); 3] = [
        ("Ng", [true, true, false, false, false]),
        ("Mike Ng", [false, true, true, false, false]),
        ("ke Ng", [false, true, true, false, false]),
    ];

    /// The field reference's match query of `needle` on the type `name`, as
    /// it binds, and its verdict on each row of [`PAGE`].
    async fn field_query(keyset: &Keyset<'_>, name: &str, needle: &str) -> (Vec<u8>, Vec<bool>) {
        macro_rules! cut {
            ($reference:expr) => {{
                let query = $reference.matches(needle).encrypt(keyset).await.unwrap();
                (
                    serde_json::to_vec(&query).unwrap(),
                    PAGE.iter().map(|row| query.verify(row)).collect(),
                )
            }};
        }
        match name {
            "TextMatch" => cut!(EncryptedColumns::TEXT_MATCH),
            "TextSearch" => cut!(EncryptedColumns::TEXT_SEARCH),
            "TextSearchOre" => cut!(EncryptedColumns::TEXT_SEARCH_ORE),
            other => panic!("{other} has no match index"),
        }
    }

    /// A record whose match fields all hold "Mike Nguyen", stored.
    async fn scenario(keyset: &Keyset<'_>) -> EncryptedColumns {
        Columns {
            text_match: "Mike Nguyen".into(),
            text_search: "Mike Nguyen".into(),
            text_search_ore: "Mike Nguyen".into(),
            ..columns()
        }
        .encrypt_into(keyset)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn the_field_query_verifies_by_the_query_rule() {
        let (cipher, _) = common::cipher().await;
        let keyset = cipher.default_keyset();
        for (name, _) in MATCH_TYPES {
            for (needle, want) in QUERIES {
                let (_, verdicts) = field_query(&keyset, name, needle).await;
                assert_eq!(
                    verdicts, want,
                    "{name} {needle:?}: verifies by the query's rule"
                );
            }
        }
    }

    #[test]
    fn the_data_path_verifies_alike() {
        for (name, column) in MATCH_TYPES {
            let plan = data_plan(name, column);
            for (needle, want) in QUERIES {
                let data = dynamic::verify(
                    &plan,
                    "value",
                    Op::Matches,
                    frame(needle),
                    PAGE,
                    &EqlTargets,
                )
                .unwrap();
                assert_eq!(
                    data, want,
                    "{name} {needle:?}: the data path verifies alike"
                );
            }
        }
    }

    #[tokio::test]
    async fn the_field_query_is_the_data_paths_bytes() {
        let (cipher, _) = common::cipher().await;
        let keyset = cipher.default_keyset();
        for (name, column) in MATCH_TYPES {
            for (needle, _) in QUERIES {
                let (typed, _) = field_query(&keyset, name, needle).await;
                let (data, _) = data_term(&cipher, name, column, Op::Matches, frame(needle)).await;
                assert_eq!(
                    typed, data,
                    "{name} {needle:?}: the data path sends the same filter"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_partly_typed_name_finds_the_stored_full_name() {
        let (cipher, _) = common::cipher().await;
        let keyset = cipher.default_keyset();
        let stored = scenario(&keyset).await;
        for (name, column) in MATCH_TYPES {
            for needle in ["Mike Ng", "ke Ng"] {
                let (typed, _) = field_query(&keyset, name, needle).await;
                let query: serde_json::Value = serde_json::from_slice(&typed).unwrap();
                assertions::stored_filter_contains_the_querys(
                    name,
                    needle,
                    &query,
                    &stored_field(&stored, column),
                );
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

/// An ordered text query whose terms cannot all be derived is refused by
/// both paths with the same error, before any key is requested: block ORE
/// text that ends in NUL or folds past the scheme's limit, and text no
/// index can normalize. Each case goes through a keyset whose index key is
/// not loaded yet, so a refusal that came only from deriving a term would
/// show as a key load.
///
/// A `TextOrd*` twin carries its `hm` and its order term for every
/// operator, so its `eq` is refused for what the order index refuses. A
/// text search twin carries the answering index's term alone, so its `eq`
/// is answered for the same text.
mod given_order_text {
    use super::*;
    use stack_encrypt::sem::TermError;
    use stack_kms::IdentifiedBy;

    const EVERY_OPERATOR: &[&str] = &["eq", "lt", "lte", "gt", "gte"];
    const ORDERINGS: &[&str] = &["lt", "lte", "gt", "gte"];

    /// Block ORE text over the scheme's limit once folded.
    fn too_long() -> String {
        "a".repeat(2000)
    }

    /// Block ORE text whose fold ends in NUL.
    fn trailing_nul() -> String {
        "ab\0".to_owned()
    }

    /// Text with a code point Unicode 16 does not assign, which no index
    /// normalizes.
    fn unassigned() -> String {
        "a\u{0378}b".to_owned()
    }

    /// The refusal a case expects: a `TermError` variant.
    #[derive(Clone, Copy, Debug)]
    enum Refusal {
        OreBlockTrailingNul,
        OreBlockTooLong,
        Normalize,
    }

    impl Refusal {
        fn is(self, error: &TermError) -> bool {
            matches!(
                (self, error),
                (Self::OreBlockTrailingNul, TermError::OreBlockTrailingNul)
                    | (Self::OreBlockTooLong, TermError::OreBlockTooLong)
                    | (Self::Normalize, TermError::Normalize(_))
            )
        }
    }

    /// `$reference.<operator>(value)` under `$keyset`, for an operator named
    /// at run time, its query dropped.
    macro_rules! field_query {
        ($keyset:expr, $operator:expr, $reference:expr, $value:expr) => {
            match $operator {
                "eq" => $reference.eq($value).encrypt($keyset).await.map(drop),
                "lt" => $reference.lt($value).encrypt($keyset).await.map(drop),
                "lte" => $reference.lte($value).encrypt($keyset).await.map(drop),
                "gt" => $reference.gt($value).encrypt($keyset).await.map(drop),
                "gte" => $reference.gte($value).encrypt($keyset).await.map(drop),
                other => panic!("no `{other}` case"),
            }
        };
    }

    /// The field query of `value` on the field of `EncryptedColumns` that
    /// names the type `name`.
    async fn field_query(
        keyset: &Keyset<'_>,
        name: &str,
        operator: &str,
        value: String,
    ) -> Result<(), Error> {
        match name {
            "TextOrdOre" => field_query!(keyset, operator, EncryptedColumns::TEXT_ORD_ORE, value),
            "TextOrd" => field_query!(keyset, operator, EncryptedColumns::TEXT_ORD, value),
            "TextOrdOpe" => field_query!(keyset, operator, EncryptedColumns::TEXT_ORD_OPE, value),
            "TextSearchOre" => {
                field_query!(keyset, operator, EncryptedColumns::TEXT_SEARCH_ORE, value)
            }
            "TextSearch" => field_query!(keyset, operator, EncryptedColumns::TEXT_SEARCH, value),
            other => panic!("no case for {other}"),
        }
    }

    /// One query by each path, each through its own cipher and a keyset
    /// whose index key is not loaded: the field reference's, the data
    /// path's at a binding's boundary (`check_query`, which has no keyset),
    /// and the data path's own (`query_term`), with the key requests each
    /// cipher saw.
    struct Outcome {
        typed: Result<(), Error>,
        checked: Result<(), dynamic::Error>,
        data: Result<(), dynamic::Error>,
        typed_keys: usize,
        data_keys: usize,
    }

    /// Every key request a cipher's source saw: index key loads and data
    /// keys generated or retrieved.
    fn key_requests(calls: &std::sync::Mutex<common::Calls>) -> usize {
        let calls = calls.lock().unwrap();
        calls.loads + calls.generate.len() + calls.retrieve.len()
    }

    fn unloaded(cipher: &Cipher) -> Keyset<'_> {
        cipher.keyset(IdentifiedBy::Name("acme".to_string().into()))
    }

    async fn scenario(name: &str, operator: &str, value: &str) -> Outcome {
        let (typed_cipher, typed_calls) = common::cipher().await;
        let typed = field_query(&unloaded(&typed_cipher), name, operator, value.to_owned()).await;

        let plan = data_plan(name, column_of(name));
        let op = Op::parse(operator).unwrap();
        let checked = dynamic::check_query(&plan, "value", op, frame(value), &EqlTargets);
        let (data_cipher, data_calls) = common::cipher().await;
        let keyset = unloaded(&data_cipher);
        let data = match dynamic::query_term(&keyset, &plan, "value", op, frame(value), &EqlTargets)
        {
            Ok(pending) => pending.await.map(drop).map_err(dynamic::Error::Cipher),
            Err(refused) => Err(refused),
        };
        Outcome {
            typed,
            checked,
            data,
            typed_keys: key_requests(&typed_calls),
            data_keys: key_requests(&data_calls),
        }
    }

    mod given_a_value_an_index_of_the_twin_refuses {
        use super::*;

        /// Each type, the operators whose query derives a term the value
        /// cannot have, the value, and the refusal.
        fn cases() -> Vec<(&'static str, &'static [&'static str], String, Refusal)> {
            use Refusal::{Normalize, OreBlockTooLong, OreBlockTrailingNul};
            vec![
                (
                    "TextOrdOre",
                    EVERY_OPERATOR,
                    trailing_nul(),
                    OreBlockTrailingNul,
                ),
                ("TextOrdOre", EVERY_OPERATOR, too_long(), OreBlockTooLong),
                ("TextOrdOre", EVERY_OPERATOR, unassigned(), Normalize),
                ("TextOrd", EVERY_OPERATOR, unassigned(), Normalize),
                ("TextOrdOpe", EVERY_OPERATOR, unassigned(), Normalize),
                (
                    "TextSearchOre",
                    ORDERINGS,
                    trailing_nul(),
                    OreBlockTrailingNul,
                ),
                ("TextSearchOre", ORDERINGS, too_long(), OreBlockTooLong),
                ("TextSearchOre", EVERY_OPERATOR, unassigned(), Normalize),
                ("TextSearch", EVERY_OPERATOR, unassigned(), Normalize),
            ]
        }

        #[tokio::test]
        async fn both_paths_refuse_it_alike_before_any_key_request() {
            for (name, operators, value, expected) in cases() {
                for operator in operators {
                    let outcome = scenario(name, operator, &value).await;
                    assertions::refused_before_any_key(name, operator, &outcome, expected);
                }
            }
        }
    }

    mod given_a_value_only_an_index_the_query_does_not_derive_refuses {
        use super::*;

        /// A text search `eq` derives the `hm` alone, so block ORE text it
        /// could not order is still a query, by both paths.
        #[tokio::test]
        async fn both_paths_answer_it() {
            for value in [trailing_nul(), too_long()] {
                let outcome = scenario("TextSearchOre", "eq", &value).await;
                assert!(
                    outcome.typed.is_ok(),
                    "the field query is answered: {:?}",
                    outcome.typed
                );
                assert!(
                    outcome.checked.is_ok(),
                    "a binding's boundary passes it: {:?}",
                    outcome.checked
                );
                assert!(
                    outcome.data.is_ok(),
                    "the data path answers it: {:?}",
                    outcome.data
                );
            }
        }
    }

    mod assertions {
        use super::*;

        pub(super) fn refused_before_any_key(
            name: &str,
            operator: &str,
            outcome: &Outcome,
            expected: Refusal,
        ) {
            assert!(
                matches!(&outcome.typed, Err(Error::Term(error)) if expected.is(error)),
                "{name} {operator}: the field query is refused with {expected:?}: {:?}",
                outcome.typed
            );
            assert!(
                matches!(&outcome.checked, Err(dynamic::Error::Cipher(Error::Term(error))) if expected.is(error)),
                "{name} {operator}: a binding's boundary refuses it with {expected:?}: {:?}",
                outcome.checked
            );
            assert!(
                matches!(&outcome.data, Err(dynamic::Error::Cipher(Error::Term(error))) if expected.is(error)),
                "{name} {operator}: the data path refuses it with {expected:?}: {:?}",
                outcome.data
            );
            assert_eq!(
                outcome.typed_keys, 0,
                "{name} {operator}: the field query requested no key"
            );
            assert_eq!(
                outcome.data_keys, 0,
                "{name} {operator}: the data path requested no key"
            );
        }
    }
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
