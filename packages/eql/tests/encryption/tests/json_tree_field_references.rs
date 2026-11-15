//! An encrypted JSON document field queried from its field reference: the typed
//! Rust form of the JSON operators, returning the EQL query types a
//! parameter binds as.
//!
//! The record seals the field under the options its `#[stash(json(..))]`
//! names, and the field's reference derives each query under the same column
//! and options. Each query is held to the operand a data plan of the same
//! declaration derives, which is the path the Go SDK takes and the one the
//! PostgreSQL suite checks against `jsonb`, and to the document the record
//! sealed:
//!
//! - `contains`, `contained_by` and `at(path).eq` derive the containment
//!   needle (`JsonTreeQuery`), and find the documents that hold it;
//! - the orderings at a path derive `JsonTreeLeafQuery`, with the path's
//!   selector, and `between` the two bounds;
//! - `elements(path)` derives `JsonTreeElementsQuery`, `predicate(text)`
//!   `JsonTreePredicateQuery`, and `children(path)` the node's token;
//! - an ordering at a path the field does not order is refused before any
//!   key is requested.

mod common;

use std::num::NonZeroU32;

use eql_bindings::encryption::EqlTargets;
use eql_bindings::v4::json_tree::{
    JsonTreeDocument, JsonTreeElementsQuery, JsonTreeLeafQuery, JsonTreePredicateQuery,
    JsonTreeQuery, JsonTreeSelector, JsonTreeToken,
};
use serde_json::{json, Value};
use stack_encrypt::dynamic::{self, record, ValueFrame};
use stack_encrypt::json::{JsonDocument, JsonPlaintext, JsonQuery};
use stack_encrypt::sem::TermError;
use stack_encrypt::target::{DecryptSource, EncryptTarget};
use stack_encrypt::{AsProtectedRef as _, DecryptFrom, EncryptInto, Error, KeysetCipher};
use zeroize::Zeroize;

/// A customer, and the profile document stored for them.
#[derive(Zeroize)]
struct Customer {
    profile: JsonPlaintext,
}

/// The plan's example: the profile is stored under `customers/profile`,
/// ordering the age and each visit's time and place.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Customer, scope = "customers")]
struct EncryptedCustomer {
    #[stash(json(ordered = ["$.age", "$.visits[*].at", "$.visits[*].place"]))]
    profile: JsonTreeDocument,
}

fn profile() -> Value {
    json!({
        "name": "Ada",
        "age": 35,
        "visits": [{"place": "home", "at": 15}, {"place": "work", "at": 9}]
    })
}

/// The field as a data plan, under the record's options.
fn plan() -> record::Plan {
    let wire = json!({
        "profile": {
            "context": ["customers", "profile"],
            "type": "json",
            "null": "sql",
            "target": {
                "name": "JsonSearch",
                "options": {"ordered": ["$.age", "$.visits[*].at", "$.visits[*].place"]}
            }
        }
    });
    record::plan_with(
        dynamic::frame::serde::to_vec(&wire)
            .unwrap()
            .as_protected_ref(),
        &EqlTargets,
    )
    .unwrap()
}

/// The data plan's operand for `operator` and its input.
async fn data(
    keyset: &KeysetCipher<'_, common::RecordingKeySource>,
    operator: &str,
    input: Value,
) -> dynamic::Operand {
    let frame = ValueFrame::from_bytes(
        dynamic::frame::serde::to_vec(&input)
            .unwrap()
            .as_protected_ref(),
    )
    .unwrap();
    dynamic::query_term(
        keyset,
        &plan(),
        "profile",
        dynamic::Op::parse(operator).unwrap(),
        frame,
        &EqlTargets,
    )
    .unwrap()
    .await
    .unwrap()
    .operand()
    .clone()
}

fn one(operand: dynamic::Operand) -> Value {
    match operand {
        dynamic::Operand::One(bytes) => serde_json::from_slice(&bytes).unwrap(),
        other => panic!("one operand: {other:?}"),
    }
}

fn text(operand: dynamic::Operand) -> String {
    match operand {
        dynamic::Operand::Text(text) => text,
        other => panic!("text: {other:?}"),
    }
}

/// A containment needle as the engine's `JsonQuery`, which compares as
/// sets: each derivation sends its selector set in a random order of its
/// own.
fn needle(query: &JsonTreeQuery) -> JsonQuery {
    serde_json::from_value(serde_json::to_value(query).unwrap()).unwrap()
}

/// The JSON index's own document under the EQL envelope, whose selector
/// set compares as a set.
fn index_document(document: &JsonTreeDocument) -> JsonDocument {
    let wire = serde_json::to_value(document).unwrap();
    serde_json::from_value(json!({"h": wire["h"], "sv": wire["sv"], "q": wire["q"]})).unwrap()
}

/// The plan's "Query a JSON document" example, run: each query's type is
/// the EQL query type the field reference fixes.
#[tokio::test]
async fn the_plans_json_query_example_runs() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let stored: EncryptedCustomer = Customer {
        profile: profile().into(),
    }
    .encrypt_into(&keyset)
    .await
    .unwrap();

    let ada: JsonTreeQuery = EncryptedCustomer::PROFILE
        .contains(json!({ "name": "Ada" }))
        .encrypt(&keyset)
        .await
        .unwrap();
    let older: JsonTreeLeafQuery = EncryptedCustomer::PROFILE
        .at("$.age")
        .gt(30)
        .encrypt(&keyset)
        .await
        .unwrap();
    let (low, high): (JsonTreeLeafQuery, JsonTreeLeafQuery) = EncryptedCustomer::PROFILE
        .at("$.age")
        .between(18, 65)
        .encrypt(&keyset)
        .await
        .unwrap();
    let home: JsonTreeElementsQuery = EncryptedCustomer::PROFILE
        .elements("$.visits[*]")
        .eq("place", "home")
        .gt("at", 10)
        .encrypt(&keyset)
        .await
        .unwrap();
    let adult: JsonTreePredicateQuery = EncryptedCustomer::PROFILE
        .predicate("$.age >= $min")
        .vars(json!({"min": 18}))
        .encrypt(&keyset)
        .await
        .unwrap();
    let visits: JsonTreeToken = EncryptedCustomer::PROFILE
        .children("$.visits")
        .encrypt(&keyset)
        .await
        .unwrap();
    let age: JsonTreeSelector = EncryptedCustomer::PROFILE
        .at("$.age")
        .selector()
        .encrypt(&keyset)
        .await
        .unwrap();

    assert_eq!(
        older.s, age,
        "an ordering is compared at the path's selector"
    );
    assert_eq!((&low.s, &high.s), (&age, &age));
    assert_eq!(home.m.len(), 2, "one member per condition");
    assert!(matches!(adult, JsonTreePredicateQuery::And(_)), "{adult:?}");
    assert!(
        serde_json::to_value(&visits).unwrap().is_string(),
        "a token is text"
    );
    assert!(
        needle(&ada).matches(index_document(&stored.profile).selector_set()),
        "the stored document holds the needle"
    );

    let opened = Customer::decrypt_from(stored, &keyset).await.unwrap();
    assert_eq!(opened.profile.value(), &profile());
}

/// Every field query derives the operand the data plan derives for the
/// same declaration.
#[tokio::test]
async fn each_query_is_the_data_plans_operand() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();

    let typed = EncryptedCustomer::PROFILE
        .contains(json!({"visits": [{"place": "home"}]}))
        .encrypt(&keyset)
        .await
        .unwrap();
    let wire = one(data(
        &keyset,
        "contains",
        json!({"json": json!({"visits": [{"place": "home"}]}).to_string()}),
    )
    .await);
    assert_eq!(
        needle(&typed),
        serde_json::from_value::<JsonQuery>(wire).unwrap()
    );

    let typed = EncryptedCustomer::PROFILE
        .at("$.visits[*].place")
        .eq("home")
        .encrypt(&keyset)
        .await
        .unwrap();
    let wire = one(data(
        &keyset,
        "eq_at",
        json!({"path": "$.visits[*].place", "json": "\"home\""}),
    )
    .await);
    assert_eq!(
        needle(&typed),
        serde_json::from_value::<JsonQuery>(wire).unwrap()
    );

    let typed = EncryptedCustomer::PROFILE
        .at("$.visits[*].at")
        .lte(20)
        .encrypt(&keyset)
        .await
        .unwrap();
    let wire = one(data(
        &keyset,
        "lte_at",
        json!({"path": "$.visits[*].at", "json": "20"}),
    )
    .await);
    assert_eq!(serde_json::to_value(&typed).unwrap(), wire);

    let typed = EncryptedCustomer::PROFILE
        .elements("$.visits[*]")
        .eq("place", "home")
        .between("at", 10, 20)
        .wildcard_bound(NonZeroU32::new(8).unwrap())
        .encrypt(&keyset)
        .await
        .unwrap();
    let wire = one(data(
        &keyset,
        "element_match",
        json!({"path": "$.visits[*]", "wildcard_bound": 8, "predicates": [
            {"member": "place", "op": "eq", "json": "\"home\""},
            {"member": "at", "op": "between", "low": "10", "high": "20"}
        ]}),
    )
    .await);
    assert_eq!(serde_json::to_value(&typed).unwrap(), wire);

    let typed = EncryptedCustomer::PROFILE
        .predicate("$.age >= $min && exists($.name)")
        .vars(json!({"min": 30}))
        .encrypt(&keyset)
        .await
        .unwrap();
    let wire = one(data(
        &keyset,
        "match",
        json!({"predicate": "$.age >= $min && exists($.name)", "vars": "{\"min\": 30}"}),
    )
    .await);
    assert_eq!(serde_json::to_value(&typed).unwrap(), wire);

    let typed = EncryptedCustomer::PROFILE
        .at("$.age")
        .selector()
        .encrypt(&keyset)
        .await
        .unwrap();
    let wire = text(data(&keyset, "selector", json!({"path": "$.age"})).await);
    assert_eq!(serde_json::to_value(&typed).unwrap(), json!(wire));

    let typed = EncryptedCustomer::PROFILE
        .children("$.visits")
        .encrypt(&keyset)
        .await
        .unwrap();
    let wire = text(data(&keyset, "children", json!({"path": "$.visits"})).await);
    assert_eq!(serde_json::to_value(&typed).unwrap(), json!(wire));
}

/// An ordering at a path the field does not order is refused before any
/// key is requested, as the data plan refuses it.
#[tokio::test]
async fn an_ordering_the_field_does_not_order_is_refused_before_any_key() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let refused = EncryptedCustomer::PROFILE
        .at("$.name")
        .gt("A")
        .encrypt(&keyset)
        .await;
    assert!(
        matches!(refused, Err(Error::Term(TermError::JsonPathNotOrdered))),
        "{refused:?}"
    );
    let calls = calls.lock().unwrap();
    assert!(
        calls.generate.is_empty() && calls.retrieve.is_empty(),
        "no key requested"
    );
}
