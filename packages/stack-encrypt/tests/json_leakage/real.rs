//! The real scheme, reduced to its wire form: seal each document and derive
//! each query term through the crate's public API, under the fake key
//! source the other JSON tests use, and serialize everything with
//! `serde_json` as the EQL domain stores and sends it.
//!
//! Deliberately thin: it says which API each [`Query`] goes through and
//! nothing about what the result reveals. When the format changes, this file
//! changes only where the API does.
//!
//! A document is sealed by the JSON index's own sealing operation
//! ([`json_document`]), under the column's options. A path's selector and a
//! subtree read's tokens come from the keyset. Containment, equality at a
//! path and an ordering at a path are derived as a binding derives them,
//! through a data plan ([`dynamic::query_term`]): the operand is the JSON
//! the database is sent, and it is read here as the type it serializes
//! ([`JsonQuery`], [`JsonLeafQuery`]).

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use stack_encrypt::dynamic::{
    self, record, Op, Operand, TargetDescriptor, TargetError, TargetOptions, TargetResolver,
    ValueFrame, ValueKind,
};
use stack_encrypt::json::{JsonDocument, JsonLeafQuery, JsonOptions, JsonPath, JsonQuery};
use stack_encrypt::target::{json_document, Borrowed, CallerContext, DeclaredContext, IndexSpec};
use stack_encrypt::{nonempty, AsProtectedRef as _, KeysetCipher, Label, Pending, StackCipher};
use stack_kms::FakeDataKeySource;

use super::observe::QueryKind;
use super::profile::{Column, Query};

/// The crate's options for a column.
pub fn options(column: &Column) -> JsonOptions {
    JsonOptions {
        sealed_root: column.sealed_root,
        ordered: column.ordered.iter().cloned().collect(),
    }
}

/// A resolver that names one type, `JsonSearch`, so that a plan can name
/// it. The queries here are the JSON operators, which the engine derives;
/// the documents are sealed by [`json_document`], not through the plan. So
/// nothing here is asked to seal, open or derive.
struct Documents;

impl TargetResolver for Documents {
    fn targets(&self) -> Vec<TargetDescriptor> {
        vec![TargetDescriptor::new(
            "JsonSearch",
            "json",
            "",
            Some(ValueKind::Json),
            "public.eql_v4_json_search",
            vec!["json".to_string()],
            Some("JsonSearchQuery".to_string()),
            Some("eql_v4.query_json".to_string()),
            true,
            None,
        )
        .with_leaf_query_sql_domain("eql_v4.query_json_leaf")]
    }

    fn encrypt<'a, K: 'static>(
        &self,
        _: &str,
        _: Option<&TargetOptions>,
        _: &'a KeysetCipher<'_, K>,
        _: &Label,
        _: &DeclaredContext,
        _: ValueFrame,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        unreachable!("the documents are sealed by the JSON index's own operation")
    }

    fn decrypt<'a, K: 'static>(
        &self,
        _: &str,
        _: &'a StackCipher<K>,
        _: &Label,
        _: &DeclaredContext,
        _: &[u8],
    ) -> Result<Pending<'a, ValueFrame, K>, TargetError> {
        unreachable!("nothing is opened here")
    }

    fn query<'a, K: 'static>(
        &self,
        _: &str,
        _: &IndexSpec,
        _: &'a KeysetCipher<'_, K>,
        _: &Label,
        _: &DeclaredContext,
        _: ValueFrame,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        unreachable!("the JSON operators are the engine's")
    }
}

/// The column as a binding's plan names it: one `json` field, `profile`,
/// under `users/profile`, storing `JsonSearch` with the column's options.
fn plan(column: &Column) -> record::Plan {
    let wire = json!({
        "profile": {
            "context": ["users", "profile"],
            "type": "json",
            "null": "sql",
            "target": {
                "name": "JsonSearch",
                "options": {"sealed_root": column.sealed_root, "ordered": column.ordered}
            }
        }
    });
    record::plan_with(
        dynamic::frame::serde::to_vec(&wire)
            .expect("the plan is a frame")
            .as_protected_ref(),
        &Documents,
    )
    .expect("the plan builds")
}

/// The operand of `operator` for `input`, as the data plan derives it: the
/// JSON bytes the database is sent, read as `T`, the type that serializes
/// to them, and serialized again. The two are checked to be the same JSON,
/// so what is returned is what was sent, lists in the order sent.
async fn operand<T: DeserializeOwned + Serialize>(
    keyset: &KeysetCipher<'_, FakeDataKeySource>,
    plan: &record::Plan,
    operator: Op,
    input: &Value,
) -> Value {
    let input = ValueFrame::from_bytes(
        dynamic::frame::serde::to_vec(input)
            .expect("the input is a frame")
            .as_protected_ref(),
    )
    .expect("the input is a value");
    let term = dynamic::query_term(keyset, plan, "profile", operator, input, &Documents)
        .expect("the field answers the operator")
        .await
        .expect("derives");
    let Operand::One(bytes) = term.operand() else {
        panic!("{}: one operand, got {:?}", operator.name(), term.operand())
    };
    let typed: T = serde_json::from_slice(bytes).expect("the operand is its type's JSON");
    let wire = serde_json::to_value(&typed).expect("serializes");
    assert_eq!(
        serde_json::from_slice::<Value>(bytes).expect("the operand is JSON"),
        wire,
        "{}: the typed operand is the JSON sent",
        operator.name()
    );
    wire
}

/// The rows and query terms the database would hold and receive.
pub async fn world(
    cipher: &StackCipher<FakeDataKeySource>,
    column: &Column,
    docs: &[Value],
    queries: &[Query],
) -> (Vec<Value>, Vec<(QueryKind, Value)>) {
    let plan = plan(column);
    let keyset = cipher.default_keyset();
    let mut rows = Vec::with_capacity(docs.len());
    for doc in docs {
        let sealed: JsonDocument = keyset
            .run(
                json_document::<_, Borrowed>(options(column)),
                doc,
                CallerContext::from(nonempty!("users").with("profile")),
            )
            .await
            .expect("seals");
        rows.push(serde_json::to_value(&sealed).expect("serializes"));
    }
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
            Query::Contains(needle) => (
                QueryKind::Contains,
                operand::<JsonQuery>(
                    &keyset,
                    &plan,
                    Op::Contains,
                    &json!({"json": needle.to_string()}),
                )
                .await,
            ),
            Query::Equals(path, value) => (
                QueryKind::Equals,
                operand::<JsonQuery>(
                    &keyset,
                    &plan,
                    Op::EqAt,
                    &json!({"path": path, "json": value.to_string()}),
                )
                .await,
            ),
            Query::Order(path, value) => (
                QueryKind::Order,
                operand::<JsonLeafQuery>(
                    &keyset,
                    &plan,
                    Op::GteAt,
                    &json!({"path": path, "json": value.to_string()}),
                )
                .await,
            ),
        });
    }
    (rows, sent)
}
