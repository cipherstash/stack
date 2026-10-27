//! The real scheme, reduced to its wire form: seal each document and derive
//! each query term through the crate's public API, under the fake key
//! source the other JSON tests use, and serialize everything with
//! `serde_json` as the EQL domain stores and sends it.
//!
//! Deliberately thin: it says which API each [`Query`] goes through and
//! nothing about what the result reveals. When the format changes, this file
//! changes only where the API does.

use serde_json::Value;
use stack_encrypt::json::{JsonDocument, JsonOptions, JsonPath};
use stack_encrypt::op;
use stack_encrypt::target::Json;
use stack_encrypt::{nonempty, Plan, StackCipher};
use stack_kms::FakeDataKeySource;

use super::observe::QueryKind;
use super::profile::{Column, Query};

type JsonPlan =
    stack_encrypt::plan::ValuePlan<Value, stack_encrypt::plan::Laid<Json, JsonDocument>>;

/// The crate's options for a column.
pub fn options(column: &Column) -> JsonOptions {
    JsonOptions {
        sealed_root: column.sealed_root,
        ordered: column.ordered.iter().cloned().collect(),
    }
}

fn plan(column: &Column) -> JsonPlan {
    Plan::value::<Value>()
        .context("users/profile")
        .encrypt_with_layout(Json::new(options(column)))
        .build()
        .expect("the plan builds")
}

/// The rows and query terms the database would hold and receive.
pub async fn world(
    cipher: &StackCipher<FakeDataKeySource>,
    column: &Column,
    docs: &[Value],
    queries: &[Query],
) -> (Vec<Value>, Vec<(QueryKind, Value)>) {
    let plan = plan(column);
    let mut rows = Vec::with_capacity(docs.len());
    for doc in docs {
        let sealed = cipher.encrypt(doc).using(&plan).await.expect("seals");
        rows.push(serde_json::to_value(&sealed).expect("serializes"));
    }
    let keyset = cipher.default_keyset();
    let mut sent = Vec::with_capacity(queries.len());
    for query in queries {
        sent.push(match query {
            Query::Extract(path) => {
                let selector = keyset
                    .json_selector(
                        &JsonPath::parse(path).expect("a path"),
                        nonempty!("users").with("profile"),
                    )
                    .await
                    .expect("derives");
                (QueryKind::Extract, serde_json::to_value(selector).unwrap())
            }
            Query::Subtree {
                path,
                bound,
                budget,
            } => {
                let key = keyset
                    .json_subtree_key_with_bound(
                        &JsonPath::parse(path).expect("a path"),
                        &options(column),
                        *bound,
                        nonempty!("users").with("profile"),
                    )
                    .await
                    .expect("derives");
                // What `json_tree_subtree(doc, key.tokens(), budget)` hands
                // the database: the key's wire form, `{"t": [...]}`, and the
                // budget argument beside it.
                let mut wire = serde_json::to_value(&key).unwrap();
                wire["budget"] = serde_json::json!(budget);
                (QueryKind::Subtree, wire)
            }
            Query::Contains(needle) => {
                let term = cipher
                    .query(op::Contains, needle)
                    .on(&plan)
                    .await
                    .expect("derives");
                (QueryKind::Contains, serde_json::to_value(&term).unwrap())
            }
            Query::Equals(path, value) => {
                let term = cipher
                    .query(op::AtPath(op::Eq), &(path.clone(), value.clone()))
                    .on(&plan)
                    .await
                    .expect("derives");
                (QueryKind::Equals, serde_json::to_value(&term).unwrap())
            }
            Query::Order(path, value) => {
                let term = cipher
                    .query(op::AtPath(op::Gte), &(path.clone(), value.clone()))
                    .on(&plan)
                    .await
                    .expect("derives");
                (QueryKind::Order, serde_json::to_value(&term).unwrap())
            }
        });
    }
    (rows, sent)
}
