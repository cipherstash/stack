//! A document field's JSON operators and reads through the data plan, with
//! the engine's own JSON index behind the target: what a binding names by
//! operator (`contains`, `eq_at`, the orderings at a path, `selector`,
//! `subtree`, `children`, `child_count`, `element_match`), the operand each derives and the
//! type it binds as, the refusals made before anything is derived, and
//! reads opened against the request that prepared them.
//!
//! The resolver here stores the engine's `JsonDocument` as JSON, so the
//! whole path runs inside this crate. `packages/eql/tests/encryption/tests/
//! json_tree_data_plan.rs` runs the same path through eql-bindings' table
//! and holds every operand to the typed chain's.
#![cfg(feature = "dynamic")]

mod common;

use std::collections::BTreeMap;

use base64ct::{Base64, Encoding};
use serde_json::{json, Value};
use stack_encrypt::dynamic::{
    self, record, OpSpec, Operand, QueryTerm, Reason, TargetDescriptor, TargetError, TargetOptions,
    TargetResolver, ValueFrame, ValueKind,
};
use stack_encrypt::json::{JsonDocument, Tag};
use stack_encrypt::target::{Borrowed, CallerContext, IndexSpec};
use stack_encrypt::{CipherText, Encrypt, KeysetCipher, Label, NonEmpty, Pending, StackCipher};
use stack_kms::{DataKeySource, IndexKeySource};

/// What the helpers below run over: any key source a test builds its
/// cipher on.
trait Source: DataKeySource + IndexKeySource + Send + Sync + 'static {}
impl<K: DataKeySource + IndexKeySource + Send + Sync + 'static> Source for K {}

/// A resolver holding one type, `JsonSearch`, sealed with the engine's
/// JSON index under the options the plan resolved. It stores the
/// `JsonDocument` as JSON and needs no query twin: the JSON operators are
/// derived by the engine, not the resolver.
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
        .with_leaf_query_sql_domain("eql_v4.query_json_leaf")
        .with_elements_query_sql_domain("eql_v4.query_json_elements")]
    }

    fn encrypt<'a, K: 'static>(
        &self,
        _: &str,
        options: Option<&TargetOptions>,
        keyset: &'a KeysetCipher<'_, K>,
        label: &Label,
        plaintext: ValueFrame,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        let options = options
            .and_then(TargetOptions::json)
            .cloned()
            .unwrap_or_default();
        let document =
            dynamic::read_json(&plaintext).map_err(|e| TargetError::Other(Box::new(e)))?;
        Ok(keyset
            .run(
                stack_encrypt::target::json_document::<_, Borrowed>(options),
                document.value(),
                CallerContext::from(NonEmpty::from(label.clone())),
            )
            .try_map(|doc| {
                serde_json::to_vec(&doc).map_err(|e| stack_encrypt::Error::Other(Box::new(e)))
            }))
    }

    fn decrypt<'a, K: 'static>(
        &self,
        _: &str,
        _: &'a StackCipher<K>,
        _: &Label,
        _: &[u8],
    ) -> Result<Pending<'a, ValueFrame, K>, TargetError> {
        unreachable!("these tests open documents through reads")
    }

    fn query<'a, K: 'static>(
        &self,
        _: &str,
        _: &IndexSpec,
        _: &'a KeysetCipher<'_, K>,
        _: &Label,
        _: ValueFrame,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        unreachable!("the JSON operators are the engine's")
    }
}

/// `profile` under `users/profile`, ordering `$.age` and every visit's
/// `at`, as a binding writes it.
fn plan() -> record::Plan {
    plan_of(json!({
        "name": "JsonSearch",
        "options": {"ordered": ["$.age", "$.visits[*].at"]}
    }))
}

fn plan_of(target: Value) -> record::Plan {
    let wire = json!({
        "profile": {"context": ["users", "profile"], "type": "json", "null": "sql", "target": target}
    });
    record::plan_with(&dynamic::frame::serde::to_vec(&wire).unwrap(), &Documents).unwrap()
}

fn frame<T: Encrypt>(value: T) -> ValueFrame {
    ValueFrame::of(value).unwrap()
}

/// A JSON value as a frame: what a binding sends as an input or a request.
fn json_frame(value: &Value) -> ValueFrame {
    ValueFrame::from_bytes(&dynamic::frame::serde::to_vec(value).unwrap()).unwrap()
}

async fn term<K: Source>(
    keyset: &KeysetCipher<'_, K>,
    plan: &record::Plan,
    operator: &str,
    input: Value,
) -> QueryTerm {
    dynamic::query_term(
        keyset,
        plan,
        "profile",
        OpSpec::parse(operator).unwrap(),
        json_frame(&input),
        &Documents,
    )
    .unwrap()
    .await
    .unwrap()
}

/// A document sealed through the plan, as the engine's `JsonDocument`.
async fn seal<K: Source>(
    keyset: &KeysetCipher<'_, K>,
    plan: &record::Plan,
    document: &Value,
) -> JsonDocument {
    let text = document.to_string();
    let row = record::encrypt_with(
        keyset,
        frame(BTreeMap::from([("profile", text.as_str())])),
        plan,
        &Documents,
    )
    .unwrap()
    .await
    .unwrap();
    stored(&row, "profile")
}

/// The document a sealed row stores for `field`.
fn stored(row: &stack_encrypt::StackCipherText, field: &str) -> JsonDocument {
    let CipherText::Map(fields) = row else {
        panic!("a row is a map")
    };
    let Some((_, CipherText::Map(outputs))) = fields.iter().find(|(name, _)| name == field) else {
        panic!("{field} is a map of outputs")
    };
    let Some((_, CipherText::Passthrough(payload))) = outputs.iter().find(|(key, _)| key == "eql")
    else {
        panic!("{field}'s stored value is a passthrough")
    };
    let bytes: bytes::Bytes = dynamic::frame::serde::from_slice(&payload.0).unwrap();
    serde_json::from_slice(&bytes.0).unwrap()
}

fn tag(text: &str) -> Tag {
    Base64::decode_vec(text).unwrap().try_into().unwrap()
}

/// The entry `doc -> selector` returns: the first carrying the selector.
fn extracted(doc: &JsonDocument, selector: &str) -> Vec<String> {
    let selector = tag(selector);
    doc.entries()
        .iter()
        .position(|entry| entry.selector() == &selector)
        .map(|j| {
            serde_json::to_value(doc.node(j).unwrap())
                .unwrap()
                .to_string()
        })
        .into_iter()
        .collect()
}

/// The rows `json_tree_subtree(doc, tokens, 0)` returns: each node with
/// its depth grafted.
fn subtree(doc: &JsonDocument, tokens: &[String]) -> Vec<String> {
    let tokens: Vec<Tag> = tokens.iter().map(|t| tag(t)).collect();
    doc.subtree(&tokens)
        .into_iter()
        .map(|(j, _, d)| {
            let mut wire = serde_json::to_value(doc.node(j).unwrap()).unwrap();
            wire["d"] = json!(d);
            wire.to_string()
        })
        .collect()
}

async fn open<K: Source>(
    keyset: &KeysetCipher<'_, K>,
    plan: &record::Plan,
    request: Value,
    groups: Vec<Vec<String>>,
) -> Result<Vec<Vec<Value>>, stack_encrypt::Error> {
    let opened = dynamic::json_open(
        keyset,
        plan,
        "profile",
        json_frame(&request),
        frame(&groups),
        &Documents,
    )
    .unwrap()
    .await?;
    let groups: Vec<Vec<bytes::Bytes>> =
        dynamic::frame::serde::from_slice(opened.risky_ref()).unwrap();
    Ok(groups
        .into_iter()
        .map(|g| {
            g.into_iter()
                .map(|b| serde_json::from_slice(&b.0).unwrap())
                .collect()
        })
        .collect())
}

/// A byte string read out of a frame.
mod bytes {
    pub struct Bytes(pub Vec<u8>);
    impl<'de> serde::Deserialize<'de> for Bytes {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl serde::de::Visitor<'_> for V {
                type Value = Bytes;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("bytes")
                }
                fn visit_bytes<E>(self, v: &[u8]) -> Result<Bytes, E> {
                    Ok(Bytes(v.to_vec()))
                }
                fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Bytes, E> {
                    Ok(Bytes(v))
                }
            }
            d.deserialize_bytes(V)
        }
    }
}

/// Each operator derives an operand in the encoding it names, bound as the
/// domain the target names for it: a needle for containment and `eq_at`,
/// a leaf operand for an ordering, text for a selector or a node's token,
/// and a text array for a subtree read.
#[tokio::test]
async fn every_operator_derives_its_tagged_operand() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let plan = plan();
    let needle = |term: &QueryTerm| match term.operand() {
        Operand::One(bytes) => serde_json::from_slice::<Value>(bytes).unwrap(),
        other => panic!("{}: {other:?}", term.operator()),
    };

    for (operator, input) in [
        ("contains", json!({"json": r#"{"name": "Alice"}"#})),
        (
            "contained_by",
            json!({"json": r#"{"name": "Alice", "age": 1}"#}),
        ),
        ("eq_at", json!({"path": "$.visits[*].at", "json": "3"})),
    ] {
        let term = term(&keyset, &plan, operator, input).await;
        assert_eq!(term.encoding(), "eql", "{operator}");
        assert_eq!(term.domain(), Some("eql_v4.query_json"), "{operator}");
        assert!(needle(&term).is_object(), "{operator}");
    }
    // Equality at a path is a containment needle, the shape `contains`
    // derives; an ordering at the same path is a leaf operand, another.
    let keys = |v: &Value| -> Vec<String> { v.as_object().unwrap().keys().cloned().collect() };
    let at_age = json!({"path": "$.age", "json": "40"});
    let contains = needle(
        &term(
            &keyset,
            &plan,
            "contains",
            json!({"json": r#"{"age": 40}"#}),
        )
        .await,
    );
    let eq = needle(&term(&keyset, &plan, "eq_at", at_age.clone()).await);
    let lt = needle(&term(&keyset, &plan, "lt_at", at_age).await);
    assert_eq!(keys(&eq), keys(&contains), "eq_at is a needle: {eq}");
    assert_ne!(keys(&lt), keys(&eq), "an ordering is a leaf operand: {lt}");
    for operator in ["lt_at", "lte_at", "gt_at", "gte_at"] {
        let term = term(
            &keyset,
            &plan,
            operator,
            json!({"path": "$.age", "json": "40"}),
        )
        .await;
        assert_eq!(term.domain(), Some("eql_v4.query_json_leaf"));
        assert!(needle(&term).is_object(), "{operator}");
    }
    let between = term(
        &keyset,
        &plan,
        "between_at",
        json!({"path": "$.visits[*].at", "low": "1", "high": "\"z\""}),
    )
    .await;
    assert!(matches!(between.operand(), Operand::Range { .. }));
    assert_eq!(between.domain(), Some("eql_v4.query_json_leaf"));

    let selector = term(&keyset, &plan, "selector", json!({"path": "$.name"})).await;
    assert_eq!(
        (selector.encoding(), selector.domain()),
        ("text", Some("text"))
    );
    let Operand::Text(selector) = selector.operand() else {
        panic!("a selector is text")
    };
    assert_eq!(tag(selector).len(), 16);

    let tokens = term(
        &keyset,
        &plan,
        "subtree",
        json!({"path": "$.visits[*].at", "wildcard_bound": 3}),
    )
    .await;
    assert_eq!(
        (tokens.encoding(), tokens.domain()),
        ("text_array", Some("text[]"))
    );
    let Operand::TextList(tokens) = tokens.operand() else {
        panic!("a subtree read is a text list")
    };
    assert_eq!(
        tokens.len(),
        3 + 1,
        "one token per element below the bound, and one past it that shows a longer array"
    );

    let children = term(&keyset, &plan, "children", json!({"path": "$.visits"})).await;
    let count = term(&keyset, &plan, "child_count", json!({"path": "$.visits"})).await;
    let selector = term(&keyset, &plan, "selector", json!({"path": "$.visits"})).await;
    assert_ne!(
        children.operand(),
        selector.operand(),
        "a node's token is not its selector"
    );
    assert_eq!(
        children.operand(),
        count.operand(),
        "both take the node's token"
    );
    assert!(matches!(children.operand(), Operand::Text(_)));
}

/// A field with no ordered path lists no ordering, and an ordering asked
/// of it is not answered. (Options on a target that takes none are
/// refused when the plan is built, `Reason::TargetOptions`: the record
/// module's plan tests.)
#[test]
fn the_orderings_follow_the_resolved_options() {
    let names = |plan: &record::Plan| -> Vec<&'static str> {
        dynamic::field_operators(plan, "profile", &Documents)
            .unwrap()
            .into_iter()
            .map(|(op, _)| op.name())
            .collect()
    };
    assert!(names(&plan()).contains(&"lt_at"));
    let unordered = plan_of(json!("JsonSearch"));
    assert_eq!(
        names(&unordered),
        [
            "contains",
            "contained_by",
            "eq_at",
            "selector",
            "subtree",
            "children",
            "child_count"
        ]
    );
    let error = dynamic::check_query(
        &unordered,
        "profile",
        OpSpec::LtAt,
        json_frame(&json!({"path": "$.age", "json": "1"})),
        &Documents,
    )
    .unwrap_err();
    assert_eq!(error.reason(), Some(Reason::OperatorNotAnswered));
}

/// Inputs refused before anything is derived, each with its own reason and
/// never a byte of the input; and the engine's own refusals of a path or a
/// value it cannot answer.
#[test]
fn malformed_inputs_are_refused_with_their_reason() {
    let plan = plan();
    let check = |operator: OpSpec, input: Value| {
        dynamic::check_query(&plan, "profile", operator, json_frame(&input), &Documents)
    };
    // The data plan's reason, or for the engine's own refusals the index's
    // term error by name, so a refusal of another kind fails the row.
    let reason = |operator: OpSpec, input: Value| -> String {
        let error = check(operator, input).unwrap_err();
        assert!(!error.to_string().contains("secret"), "{error}");
        match (&error, error.reason()) {
            (_, Some(reason)) => reason.as_str().to_owned(),
            (dynamic::Error::Cipher(stack_encrypt::Error::Term(term)), None) => {
                let name = format!("{term:?}");
                name.split(['(', ' ', '{'])
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            }
            (other, None) => panic!("neither a reason nor a term error: {other:?}"),
        }
    };
    for (operator, input, want) in [
        (OpSpec::Contains, json!({"needle": "{}"}), "json_input"),
        (OpSpec::Contains, json!({"json": 1}), "json_input"),
        (OpSpec::Contains, json!("{}"), "json_input"),
        (OpSpec::EqAt, json!({"path": "$.a"}), "json_input"),
        (
            OpSpec::BetweenAt,
            json!({"path": "$.age", "low": "1"}),
            "json_input",
        ),
        (
            OpSpec::Subtree,
            json!({"path": "$.a", "wildcard_bound": "x"}),
            "json_input",
        ),
        (
            OpSpec::Contains,
            json!({"json": r#"{"secret": 1, "secret": 2}"#}),
            "json_duplicate_key",
        ),
        (
            OpSpec::Contains,
            json!({"json": r#"{"secret""#}),
            "json_syntax",
        ),
        (
            OpSpec::Contains,
            json!({"json": "99999999999999999999"}),
            "json_integer_range",
        ),
        (
            OpSpec::EqAt,
            json!({"path": "$.a[2]", "json": "1"}),
            "json_path_position",
        ),
        (
            OpSpec::LtAt,
            json!({"path": "$.visits[0].at", "json": "1"}),
            // A position on an ordering is the index's own refusal, the
            // one the typed ordering gives.
            "JsonOrderingAtPosition",
        ),
        (
            OpSpec::Selector,
            json!({"path": "$.a[0].b"}),
            "json_path_position",
        ),
        (
            OpSpec::Children,
            json!({"path": "$.a[*]"}),
            "json_path_wildcard",
        ),
        (
            OpSpec::ChildCount,
            json!({"path": "$.a[*].b"}),
            "json_path_wildcard",
        ),
        // The engine's own: a container at a path, a path the field does
        // not order, a value no ordering takes, a path that is not one.
        (
            OpSpec::EqAt,
            json!({"path": "$.a", "json": r#"{"secret": 1}"#}),
            "JsonValueNotScalar",
        ),
        (
            OpSpec::LtAt,
            json!({"path": "$.name", "json": "1"}),
            "JsonPathNotOrdered",
        ),
        (
            OpSpec::GtAt,
            json!({"path": "$.age", "json": "true"}),
            "JsonLeafNotOrdered",
        ),
        (OpSpec::Selector, json!({"path": "secret"}), "JsonPath"),
        // A path with more steps than a document has levels names no node,
        // and is refused before a document as deep is built.
        (
            OpSpec::EqAt,
            json!({"path": format!("${}", ".a".repeat(50_000)), "json": "1"}),
            "JsonTooDeep",
        ),
        (
            OpSpec::Selector,
            json!({"path": format!("${}", ".a".repeat(128))}),
            "JsonTooDeep",
        ),
    ] {
        assert_eq!(reason(operator, input.clone()), want, "{operator:?}");
    }
    for (operator, input) in [
        (OpSpec::Contains, json!({"json": "[1, {\"a\": null}]"})),
        (OpSpec::EqAt, json!({"path": "$.visits[*].at", "json": "1"})),
        (
            OpSpec::BetweenAt,
            json!({"path": "$.age", "low": "1", "high": "2"}),
        ),
        (OpSpec::Subtree, json!({"path": "$.visits[1]"})),
        (OpSpec::ChildCount, json!({"path": "$.visits"})),
        // As many steps as a document has levels: the deepest path that
        // can name a node is not refused as too deep.
        (
            OpSpec::Selector,
            json!({"path": format!("${}", ".a".repeat(127))}),
        ),
    ] {
        assert!(
            check(operator, input.clone()).is_ok(),
            "{operator:?} {input}"
        );
    }
}

/// Two documents read through the data path: `->` by selector, absence as
/// no value, a wildcard subtree per row, and rows refused against another
/// read's request or past the bound, each group opening on its own.
#[tokio::test]
async fn reads_open_against_the_request_that_prepared_them() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let plan = plan();
    let docs = [
        seal(
            &keyset,
            &plan,
            &json!({"name": "Alice", "age": 34, "visits": [{"at": 3}, {"at": 1, "where": "x"}]}),
        )
        .await,
        seal(&keyset, &plan, &json!({"name": "Bob", "visits": []})).await,
    ];

    let selector = |t: QueryTerm| match t.operand() {
        Operand::Text(text) => text.clone(),
        other => panic!("{other:?}"),
    };
    let name = selector(term(&keyset, &plan, "selector", json!({"path": "$.name"})).await);
    let age = selector(term(&keyset, &plan, "selector", json!({"path": "$.age"})).await);
    let names = open(
        &keyset,
        &plan,
        json!({"operation": "selector", "path": "$.name"}),
        docs.iter().map(|d| extracted(d, &name)).collect(),
    )
    .await
    .unwrap();
    assert_eq!(names, [vec![json!("Alice")], vec![json!("Bob")]]);
    let ages = open(
        &keyset,
        &plan,
        json!({"operation": "selector", "path": "$.age"}),
        docs.iter().map(|d| extracted(d, &age)).collect(),
    )
    .await
    .unwrap();
    assert_eq!(
        ages,
        [vec![json!(34)], vec![]],
        "absence is no value, not null"
    );

    let tokens = |t: QueryTerm| match t.operand() {
        Operand::TextList(list) => list.clone(),
        other => panic!("{other:?}"),
    };
    let ats = tokens(term(&keyset, &plan, "subtree", json!({"path": "$.visits[*].at"})).await);
    let read = open(
        &keyset,
        &plan,
        json!({"operation": "subtree", "path": "$.visits[*].at"}),
        docs.iter().map(|d| subtree(d, &ats)).collect(),
    )
    .await
    .unwrap();
    assert_eq!(read, [vec![json!(3), json!(1)], vec![]]);

    // Rows opened against another read's request are refused: the
    // request, not the rows, says which path they are for.
    let wrong = open(
        &keyset,
        &plan,
        json!({"operation": "subtree", "path": "$.name"}),
        vec![subtree(&docs[0], &ats)],
    )
    .await;
    assert!(
        matches!(wrong, Err(stack_encrypt::Error::JsonWrongEntry { .. })),
        "{wrong:?}"
    );
    let wrong = open(
        &keyset,
        &plan,
        json!({"operation": "selector", "path": "$.age"}),
        vec![extracted(&docs[0], &name)],
    )
    .await;
    assert!(
        matches!(wrong, Err(stack_encrypt::Error::JsonWrongEntry { .. })),
        "{wrong:?}"
    );

    // A wildcard read of an array longer than its bound fails rather than
    // open to part of the answer.
    let short = tokens(
        term(
            &keyset,
            &plan,
            "subtree",
            json!({"path": "$.visits[*].at", "wildcard_bound": 1}),
        )
        .await,
    );
    let truncated = open(
        &keyset,
        &plan,
        json!({"operation": "subtree", "path": "$.visits[*].at", "wildcard_bound": 1}),
        vec![subtree(&docs[0], &short)],
    )
    .await;
    assert!(
        matches!(
            truncated,
            Err(stack_encrypt::Error::JsonWildcardTruncated { .. })
        ),
        "{truncated:?}"
    );
}

/// Rows that are not the read's are refused whichever way they differ:
/// rows of a document sealed under another keyset (refused before any key
/// is retrieved, since the read opens through the keyset that derived it),
/// an entry of another field of the plan, and rows of a selector read
/// handed over as a subtree read's, or the reverse.
#[tokio::test]
async fn rows_that_are_not_the_reads_are_refused() {
    let (cipher, _, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let other_keyset = cipher
        .keyset(stack_kms::IdentifiedBy::Name("other".to_string().into()))
        .await
        .unwrap();
    let plan = plan();
    let document = json!({"name": "Alice", "age": 34, "visits": [{"at": 3}]});
    let mine = seal(&keyset, &plan, &document).await;
    let theirs = seal(&other_keyset, &plan, &document).await;
    let text = |t: QueryTerm| match t.operand() {
        Operand::Text(text) => text.clone(),
        other => panic!("{other:?}"),
    };
    let list = |t: QueryTerm| match t.operand() {
        Operand::TextList(list) => list.clone(),
        other => panic!("{other:?}"),
    };

    // Another keyset's document: its selectors are not this keyset's, so
    // no row is the one asked for, and nothing is retrieved.
    let name = text(term(&keyset, &plan, "selector", json!({"path": "$.name"})).await);
    let their_name = text(term(&other_keyset, &plan, "selector", json!({"path": "$.name"})).await);
    let before = retrieves.load(std::sync::atomic::Ordering::SeqCst);
    let refused = open(
        &keyset,
        &plan,
        json!({"operation": "selector", "path": "$.name"}),
        vec![extracted(&theirs, &their_name)],
    )
    .await;
    assert!(
        matches!(refused, Err(stack_encrypt::Error::JsonWrongEntry { .. })),
        "{refused:?}"
    );
    let visits = list(term(&keyset, &plan, "subtree", json!({"path": "$.visits"})).await);
    let their_visits =
        list(term(&other_keyset, &plan, "subtree", json!({"path": "$.visits"})).await);
    let refused = open(
        &keyset,
        &plan,
        json!({"operation": "subtree", "path": "$.visits"}),
        vec![subtree(&theirs, &their_visits)],
    )
    .await;
    // Rows the key's tokens do match, but under a header naming another
    // keyset: the read opens through its own keyset alone.
    assert!(
        matches!(refused, Err(stack_encrypt::Error::ForeignKeyset { .. })),
        "{refused:?}"
    );
    assert_eq!(
        retrieves.load(std::sync::atomic::Ordering::SeqCst),
        before,
        "another keyset's rows are refused before any key is retrieved"
    );

    // An entry of another field of the plan, under another column: the
    // selector is derived under this field's column, so it is not the
    // one asked for.
    let two = record::plan_with(
        &dynamic::frame::serde::to_vec(&json!({
            "profile": {"context": ["users", "profile"], "type": "json", "null": "sql",
                        "target": {"name": "JsonSearch", "options": {"ordered": ["$.age"]}}},
            "prefs": {"context": ["users", "prefs"], "type": "json", "null": "sql",
                      "target": "JsonSearch"}
        }))
        .unwrap(),
        &Documents,
    )
    .unwrap();
    let text_of = document.to_string();
    let row = record::encrypt_with(
        &keyset,
        frame(BTreeMap::from([("prefs", text_of.as_str())])),
        &two,
        &Documents,
    )
    .unwrap()
    .await
    .unwrap();
    let prefs = stored(&row, "prefs");
    let prefs_name = text(
        dynamic::query_term(
            &keyset,
            &two,
            "prefs",
            OpSpec::Selector,
            json_frame(&json!({"path": "$.name"})),
            &Documents,
        )
        .unwrap()
        .await
        .unwrap(),
    );
    assert_ne!(prefs_name, name, "a selector is the column's");
    let refused = open(
        &keyset,
        &plan,
        json!({"operation": "selector", "path": "$.name"}),
        vec![extracted(&prefs, &prefs_name)],
    )
    .await;
    assert!(
        matches!(refused, Err(stack_encrypt::Error::JsonWrongEntry { .. })),
        "{refused:?}"
    );

    // A selector read's row handed over as a subtree read's: the entry
    // `->` returns for a leaf is the node a subtree read of the same path
    // names, so it opens to the same value, and under another path's
    // subtree read it is refused. A subtree read's rows of a container
    // handed over as a selector read's are more than the one entry `->`
    // returns, and are refused before anything is derived.
    let same = open(
        &keyset,
        &plan,
        json!({"operation": "subtree", "path": "$.name"}),
        vec![extracted(&mine, &name)],
    )
    .await
    .unwrap();
    assert_eq!(same, [vec![json!("Alice")]]);
    let refused = open(
        &keyset,
        &plan,
        json!({"operation": "subtree", "path": "$.age"}),
        vec![extracted(&mine, &name)],
    )
    .await;
    assert!(
        matches!(refused, Err(stack_encrypt::Error::JsonWrongEntry { .. })),
        "{refused:?}"
    );
    let rows = subtree(&mine, &visits);
    assert!(rows.len() > 1, "a container and its members");
    let refused = dynamic::json_open(
        &keyset,
        &plan,
        "profile",
        json_frame(&json!({"operation": "selector", "path": "$.visits"})),
        frame(vec![rows]),
        &Documents,
    );
    assert_eq!(
        refused.err().and_then(|error| error.reason()),
        Some(Reason::JsonInput),
        "a subtree read's rows as a selector read's"
    );
}

/// A read's request and rows are checked before anything is derived.
#[test]
fn a_malformed_read_is_refused_before_any_key() {
    let plan = plan();
    let check = |request: Value, rows: Value| {
        dynamic::check_json_open(
            &plan,
            "profile",
            json_frame(&request),
            json_frame(&rows),
            &Documents,
        )
    };
    let refused = |request: Value, rows: Value| {
        let error = check(request.clone(), rows).unwrap_err();
        match error.reason() {
            Some(reason) => {
                assert_eq!(error.field(), Some("profile"), "{request}");
                reason.as_str()
            }
            None => "engine",
        }
    };
    assert!(check(
        json!({"operation": "selector", "path": "$.a"}),
        json!([[], []])
    )
    .is_ok());
    assert!(check(
        json!({"operation": "subtree", "path": "$.a[*]", "wildcard_bound": 2}),
        json!([[]])
    )
    .is_ok());
    for (request, rows, want) in [
        (
            json!({"operation": "contains", "path": "$.a"}),
            json!([]),
            "json_input",
        ),
        (
            json!({"operation": "nope", "path": "$.a"}),
            json!([]),
            "json_input",
        ),
        (
            json!({"operation": "selector", "path": "$.a", "wildcard_bound": 2}),
            json!([]),
            "json_input",
        ),
        (json!({"path": "$.a"}), json!([]), "json_input"),
        (
            json!({"operation": "selector", "path": "$.a"}),
            json!([["not an entry"]]),
            "json_input",
        ),
        (
            json!({"operation": "selector", "path": "$.a"}),
            json!({"rows": 1}),
            "json_input",
        ),
        (
            json!({"operation": "selector", "path": "$.a[1]"}),
            json!([]),
            "json_path_position",
        ),
        (
            json!({"operation": "subtree", "path": "secret"}),
            json!([]),
            "engine",
        ),
    ] {
        assert_eq!(refused(request.clone(), rows), want, "{request}");
    }

    // A selector group holds one entry or none: `->` returns one.
    let entry = json!({"s": "AAAAAAAAAAAAAAAAAAAAAA==", "c": "AA=="}).to_string();
    let two = check(
        json!({"operation": "selector", "path": "$.a"}),
        json!([[entry.clone(), entry]]),
    );
    assert!(two.is_err());

    // A field that does not store a document has no reads.
    let wire =
        json!({"email": {"context": ["users", "email"], "type": "string", "outputs": ["c"]}});
    let scalar =
        record::plan_with(&dynamic::frame::serde::to_vec(&wire).unwrap(), &Documents).unwrap();
    let error = dynamic::check_json_open(
        &scalar,
        "email",
        json_frame(&json!({"operation": "selector", "path": "$.a"})),
        json_frame(&json!([])),
        &Documents,
    )
    .unwrap_err();
    assert_eq!(error.reason(), Some(Reason::OperatorNotAnswered));
}

/// `element_match`: a predicate on one element of an array, its operand the
/// members' subtree reads and their bounds, as the `subtree` operator and
/// the orderings derive them. `json_tree_element_match` is modelled over
/// the rows `JsonDocument::subtree` returns, as the subtree tests model
/// `json_tree_subtree`; `packages/eql/tests/encryption` runs the SQL.
mod element_match {
    use super::*;

    use proptest::prelude::*;
    use proptest::test_runner::{Config, TestCaseError, TestRunner};

    /// `profile`, ordering a contact's `relationship`, `calls`,
    /// `address.postcode` and `["first name"]`, but not its `note`.
    fn contacts() -> record::Plan {
        plan_of(json!({
            "name": "JsonSearch",
            "options": {"ordered": [
                "$.contacts[*].relationship",
                "$.contacts[*].calls",
                "$.contacts[*].address.postcode",
                "$.contacts[*][\"first name\"]",
            ]}
        }))
    }

    fn input(bound: u32, predicates: Value) -> Value {
        json!({"path": "$.contacts[*]", "wildcard_bound": bound, "predicates": predicates})
    }

    /// The operand's JSON, `eql_v4.query_json_elements`.
    async fn operand<K: Source>(
        keyset: &KeysetCipher<'_, K>,
        plan: &record::Plan,
        input: Value,
    ) -> Value {
        let term = term(keyset, plan, "element_match", input).await;
        assert_eq!(term.encoding(), "eql", "an EQL operand");
        assert_eq!(
            term.domain(),
            Some("eql_v4.query_json_elements"),
            "bound as the target's element predicate domain"
        );
        match term.operand() {
            Operand::One(bytes) => serde_json::from_slice(bytes).unwrap(),
            other => panic!("one operand, got {other:?}"),
        }
    }

    /// The one leaf operand an ordering at `path` derives for `json`.
    async fn leaf<K: Source>(
        keyset: &KeysetCipher<'_, K>,
        plan: &record::Plan,
        operator: &str,
        path: &str,
        json: &str,
    ) -> Value {
        let term = term(keyset, plan, operator, json!({"path": path, "json": json})).await;
        match term.operand() {
            Operand::One(bytes) => serde_json::from_slice(bytes).unwrap(),
            other => panic!("{operator}: {other:?}"),
        }
    }

    /// The tokens a `subtree` read of `path` at `bound` sends.
    async fn tokens<K: Source>(
        keyset: &KeysetCipher<'_, K>,
        plan: &record::Plan,
        path: &str,
        bound: u32,
    ) -> Value {
        let term = term(
            keyset,
            plan,
            "subtree",
            json!({"path": path, "wildcard_bound": bound}),
        )
        .await;
        match term.operand() {
            Operand::TextList(tokens) => json!(tokens),
            other => panic!("{other:?}"),
        }
    }

    /// What `json_tree_element_match(doc, operand)` answers: whether one
    /// `k` has, for every member, the node its `k`-th token names at the
    /// member's selector and inside its bounds, compared as the SQL
    /// compares ordering terms (bytes); or `None` where a token names a
    /// node at another selector, a probe's hit, which the SQL raises on.
    fn element_match(doc: &JsonDocument, operand: &Value) -> Option<bool> {
        let members = operand["m"].as_array().unwrap();
        let width = members[0]["t"].as_array().unwrap().len();
        let term = |leaf: &Value| Base64::decode_vec(leaf["op"].as_str().unwrap()).unwrap();
        let mut truncated = false;
        let mut matched = false;
        for k in 0..width {
            let mut all = true;
            for member in members {
                let bounds: Vec<(&str, &Value)> = ["gt", "gte", "lt", "lte"]
                    .into_iter()
                    .filter_map(|key| member.get(key).map(|leaf| (key, leaf)))
                    .collect();
                let selector = tag(bounds[0].1["s"].as_str().unwrap());
                let token = tag(member["t"][k].as_str().unwrap());
                let Some((j, entry, _)) = doc.subtree(&[token]).into_iter().next() else {
                    all = false;
                    continue;
                };
                if entry.selector() != &selector {
                    truncated = true;
                    all = false;
                    continue;
                }
                let node = serde_json::to_value(doc.node(j).unwrap()).unwrap();
                if node.get("op").is_none() {
                    all = false;
                    continue;
                }
                let stored = term(&node);
                all &= bounds.iter().all(|(key, leaf)| {
                    let bound = term(leaf);
                    match *key {
                        "gt" => stored > bound,
                        "gte" => stored >= bound,
                        "lt" => stored < bound,
                        _ => stored <= bound,
                    }
                });
            }
            matched |= all;
        }
        (!truncated).then_some(matched)
    }

    mod given_a_predicate_per_comparison {
        use super::*;

        /// Each `op` derives the bound the ordering of the same name
        /// derives, under its own key; `eq` is `gte` and `lte` at one
        /// value, and `between` is `between_at`'s two.
        #[tokio::test]
        async fn each_bound_is_the_orderings_leaf_operand() {
            let cipher = common::stack_cipher().await;
            let keyset = cipher.default_keyset();
            let plan = contacts();
            let calls = "$.contacts[*].calls";
            let operand = operand(
                &keyset,
                &plan,
                input(
                    2,
                    json!([
                        {"member": "calls", "op": "eq", "json": "5"},
                        {"member": "calls", "op": "lt", "json": "5"},
                        {"member": "calls", "op": "lte", "json": "5"},
                        {"member": "calls", "op": "gt", "json": "5"},
                        {"member": "calls", "op": "gte", "json": "5"},
                        {"member": "calls", "op": "between", "low": "1", "high": "9"},
                    ]),
                ),
            )
            .await;
            let m = operand["m"].as_array().unwrap();
            assert_eq!(m.len(), 6, "one member per predicate: {operand}");
            let at_five = leaf(&keyset, &plan, "gte_at", calls, "5").await;
            assert_eq!(
                leaf(&keyset, &plan, "lt_at", calls, "5").await,
                at_five,
                "a leaf operand is one term, whichever ordering asks"
            );
            let keys = |member: &Value| -> Vec<String> {
                member.as_object().unwrap().keys().cloned().collect()
            };
            assert_eq!(keys(&m[0]), ["gte", "lte", "t"], "eq: {}", m[0]);
            assert_eq!(m[0]["gte"], at_five, "eq's low bound is the value's");
            assert_eq!(m[0]["lte"], m[0]["gte"], "eq is lo = hi");
            for (member, key) in [(&m[1], "lt"), (&m[2], "lte"), (&m[3], "gt"), (&m[4], "gte")] {
                assert_eq!(keys(member), [key, "t"], "{member}");
                assert_eq!(member[key], at_five, "{key}: the value's leaf operand");
            }
            let between = term(
                &keyset,
                &plan,
                "between_at",
                json!({"path": calls, "low": "1", "high": "9"}),
            )
            .await;
            let Operand::Range { lo, hi } = between.operand() else {
                panic!("between_at is a range")
            };
            let json = |bytes: &[u8]| serde_json::from_slice::<Value>(bytes).unwrap();
            assert_eq!(keys(&m[5]), ["gte", "lte", "t"], "between: {}", m[5]);
            assert_eq!(m[5]["gte"], json(lo), "between's low bound is between_at's");
            assert_eq!(
                m[5]["lte"],
                json(hi),
                "between's high bound is between_at's"
            );
            assert_ne!(m[5]["gte"], m[5]["lte"], "two values, two terms");
        }

        /// Every member's tokens are the `subtree` read of its full path at
        /// the bound, the default bound when the input names none: one per
        /// element below it, then the probe, the element at the bound
        /// itself, which every member shares.
        #[tokio::test]
        async fn each_member_reads_its_full_path_and_ends_with_the_probe() {
            let cipher = common::stack_cipher().await;
            let keyset = cipher.default_keyset();
            let plan = contacts();
            let read = operand(
                &keyset,
                &plan,
                input(
                    3,
                    json!([
                        {"member": "relationship", "op": "eq", "json": "\"Sibling\""},
                        {"member": "address.postcode", "op": "gte", "json": "3000"},
                        {"member": "[\"first name\"]", "op": "lt", "json": "\"M\""},
                    ]),
                ),
            )
            .await;
            let m = read["m"].as_array().unwrap();
            for (member, path) in [
                (&m[0], "$.contacts[*].relationship"),
                (&m[1], "$.contacts[*].address.postcode"),
                (&m[2], "$.contacts[*][\"first name\"]"),
            ] {
                assert_eq!(
                    member["t"],
                    tokens(&keyset, &plan, path, 3).await,
                    "{path}: the subtree read's tokens"
                );
                assert_eq!(member["t"].as_array().unwrap().len(), 3 + 1, "{path}");
            }
            assert_eq!(m[0]["t"][3], m[1]["t"][3], "the probe is the element's");
            assert_eq!(m[0]["t"][3], m[2]["t"][3], "the probe is the element's");
            assert_ne!(m[0]["t"][0], m[1]["t"][0], "a field's token is its own");

            let defaulted = operand(
                &keyset,
                &plan,
                json!({"path": "$.contacts[*]", "predicates": [
                    {"member": "calls", "op": "gt", "json": "1"}
                ]}),
            )
            .await;
            assert_eq!(
                defaulted["m"][0]["t"],
                tokens(&keyset, &plan, "$.contacts[*].calls", 64).await,
                "no bound named is the subtree read's default"
            );
        }
    }

    mod given_documents {
        use super::*;

        fn sibling_with_more_than_five_calls(bound: u32) -> Value {
            input(
                bound,
                json!([
                    {"member": "relationship", "op": "eq", "json": "\"Sibling\""},
                    {"member": "calls", "op": "gt", "json": "5"},
                ]),
            )
        }

        /// A Sibling with more than five calls. Two contacts each matching
        /// half of it are not a match, one matching both is, and an array
        /// longer than the bound is the probe's hit, not an answer.
        #[tokio::test]
        async fn one_element_must_satisfy_every_member() {
            let cipher = common::stack_cipher().await;
            let keyset = cipher.default_keyset();
            let plan = contacts();
            let operand = operand(&keyset, &plan, sibling_with_more_than_five_calls(2)).await;
            for (document, want, why) in [
                (
                    json!({"contacts": [
                        {"relationship": "Sibling", "calls": 3},
                        {"relationship": "Friend", "calls": 7}
                    ]}),
                    Some(false),
                    "each half in another element",
                ),
                (
                    json!({"contacts": [
                        {"relationship": "Friend", "calls": 9},
                        {"relationship": "Sibling", "calls": 7}
                    ]}),
                    Some(true),
                    "both halves in the second element",
                ),
                (
                    json!({"contacts": [{"relationship": "Sibling"}, {"calls": 8}]}),
                    Some(false),
                    "a field absent from an element satisfies none of its bounds",
                ),
                (json!({"contacts": []}), Some(false), "no element"),
                (json!({"other": 1}), Some(false), "no array"),
                (
                    json!({"contacts": [
                        {"relationship": "Friend", "calls": 1},
                        {"relationship": "Friend", "calls": 1},
                        {"relationship": "Sibling", "calls": 9}
                    ]}),
                    None,
                    "three elements past a bound of two: the probe names a node",
                ),
            ] {
                let doc = seal(&keyset, &plan, &document).await;
                assert_eq!(element_match(&doc, &operand), want, "{why}: {document}");
            }
        }

        /// Against plaintext jsonpath over random arrays: within the bound
        /// the operand answers `exists($.contacts[*] ? (@.relationship ==
        /// $r && @.calls <op> $n))`, and past it the probe names a node.
        #[test]
        fn answers_as_the_jsonpath_over_the_plaintext() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let cipher = runtime.block_on(common::stack_cipher());
            let keyset = cipher.default_keyset();
            let plan = contacts();
            let bound = 3u32;
            let names = ["Sibling", "Friend", "Parent"];
            let contact = (0..names.len(), proptest::option::of(0u64..8));
            let ops = prop::sample::select(vec!["eq", "lt", "lte", "gt", "gte", "between"]);
            let strategy = (
                prop::collection::vec(contact, 0..=4),
                0..names.len(),
                ops,
                0u64..8,
                0u64..8,
            );
            let mut runner = TestRunner::new(Config {
                cases: 48,
                ..Config::default()
            });
            runner
                .run(&strategy, |(contacts, wanted, op, n, m)| {
                    let document = json!({"contacts": contacts
                        .iter()
                        .map(|(name, calls)| match calls {
                            Some(calls) => json!({"relationship": names[*name], "calls": calls}),
                            None => json!({"relationship": names[*name]}),
                        })
                        .collect::<Vec<_>>()});
                    let (low, high) = (n.min(m), n.max(m));
                    let calls = match op {
                        "between" => json!({
                            "member": "calls", "op": op,
                            "low": low.to_string(), "high": high.to_string()
                        }),
                        _ => json!({"member": "calls", "op": op, "json": n.to_string()}),
                    };
                    let predicates = json!([
                        {"member": "relationship", "op": "eq", "json": json!(names[wanted]).to_string()},
                        calls,
                    ]);
                    let (doc, operand) = runtime.block_on(async {
                        (
                            seal(&keyset, &plan, &document).await,
                            operand(&keyset, &plan, input(bound, predicates)).await,
                        )
                    });
                    let holds = |calls: u64| match op {
                        "eq" => calls == n,
                        "lt" => calls < n,
                        "lte" => calls <= n,
                        "gt" => calls > n,
                        "gte" => calls >= n,
                        _ => (low..=high).contains(&calls),
                    };
                    let within = contacts.len() <= usize::try_from(bound).unwrap();
                    let want = within.then(|| {
                        contacts
                            .iter()
                            .any(|(name, calls)| *name == wanted && calls.is_some_and(holds))
                    });
                    let got = element_match(&doc, &operand);
                    if got != want {
                        return Err(TestCaseError::fail(format!(
                            "{document} {op} {n} {m}: got {got:?}, want {want:?}"
                        )));
                    }
                    Ok(())
                })
                .unwrap();
        }
    }

    mod given_an_input_it_cannot_answer {
        use super::*;

        /// The refusals made before anything is derived, each by its
        /// reason, or the index's term error by name.
        #[test]
        fn is_refused_with_its_reason() {
            let plan = contacts();
            let check = |input: &Value| {
                dynamic::check_query(
                    &plan,
                    "profile",
                    OpSpec::ElementMatch,
                    json_frame(input),
                    &Documents,
                )
            };
            let reason = |input: &Value| -> String {
                let error = check(input).unwrap_err();
                match (&error, error.reason()) {
                    (_, Some(reason)) => reason.as_str().to_owned(),
                    (dynamic::Error::Cipher(stack_encrypt::Error::Term(term)), None) => {
                        format!("{term:?}")
                            .split(['(', ' ', '{'])
                            .next()
                            .unwrap_or_default()
                            .to_owned()
                    }
                    (other, None) => panic!("neither a reason nor a term error: {other:?}"),
                }
            };
            let calls = |op: &str| json!([{"member": "calls", "op": op, "json": "1"}]);
            let one = |predicate: Value| input(2, json!([predicate]));
            let deep_member = |steps: usize| {
                one(json!({"member": vec!["a"; steps].join("."), "op": "gt", "json": "1"}))
            };
            for (input, want) in [
                (input(2, json!([])), "json_no_predicates"),
                (
                    json!({"path": "$.contacts", "predicates": calls("gt")}),
                    "json_path_no_wildcard",
                ),
                (
                    json!({"path": "$.contacts[0]", "predicates": calls("gt")}),
                    "json_path_no_wildcard",
                ),
                (
                    json!({"path": "$.contacts[1].tags[*]", "predicates": calls("gt")}),
                    "JsonOrderingAtPosition",
                ),
                (
                    one(json!({"member": "note", "op": "eq", "json": "\"x\""})),
                    "JsonPathNotOrdered",
                ),
                (
                    one(json!({"member": "address", "op": "gt", "json": "1"})),
                    "JsonPathNotOrdered",
                ),
                (
                    one(json!({"member": "address[0].postcode", "op": "gt", "json": "1"})),
                    "JsonOrderingAtPosition",
                ),
                (
                    one(json!({"member": "phones[*]", "op": "gt", "json": "1"})),
                    "json_path_wildcard",
                ),
                (input(2, calls("ne")), "json_unknown_predicate_op"),
                (input(2, calls("between_at")), "json_unknown_predicate_op"),
                (input(0, calls("gt")), "json_wildcard_bound_zero"),
                (one(json!({"member": "calls", "op": "gt"})), "json_input"),
                (
                    one(json!({"member": "calls", "op": "eq", "low": "1", "high": "2"})),
                    "json_input",
                ),
                (
                    one(json!({"member": "calls", "op": "gt", "json": "1", "low": "1"})),
                    "json_input",
                ),
                (
                    one(json!({"member": "calls", "op": "gt", "json": "1", "high": "1"})),
                    "json_input",
                ),
                (
                    one(json!({"member": "calls", "op": "between", "low": "1"})),
                    "json_input",
                ),
                (
                    one(json!({"member": "calls", "op": "between", "high": "1"})),
                    "json_input",
                ),
                (
                    one(
                        json!({"member": "calls", "op": "between", "json": "1", "low": "1", "high": "2"}),
                    ),
                    "json_input",
                ),
                (
                    one(json!({"member": "calls", "op": "gt", "json": "1", "extra": 1})),
                    "json_input",
                ),
                (json!({"path": "$.contacts[*]"}), "json_input"),
                (
                    one(json!({"member": "calls", "op": "eq", "json": "true"})),
                    "JsonLeafNotOrdered",
                ),
                (
                    one(json!({"member": "calls", "op": "between", "low": "1", "high": "null"})),
                    "JsonLeafNotOrdered",
                ),
                (
                    one(json!({"member": "calls", "op": "between", "low": "[1]", "high": "2"})),
                    "JsonLeafNotOrdered",
                ),
                (
                    one(json!({"member": "", "op": "gt", "json": "1"})),
                    "JsonPath",
                ),
                (
                    json!({"path": "secret", "predicates": calls("gt")}),
                    "JsonPath",
                ),
                // The path has two steps, so a member of 125 is a full path
                // of 127, as deep as a document goes, and one of 126 deeper.
                (deep_member(125), "JsonPathNotOrdered"),
                (deep_member(126), "JsonTooDeep"),
            ] {
                assert_eq!(reason(&input), want, "{input}");
            }
            // A member that does not parse is refused at an offset into the
            // member's own text, whichever form it starts with.
            for (member, at) in [("a.b[", 4), ("[\"a\"].", 6), ("a..b", 2), ("[x]", 1)] {
                let error =
                    check(&one(json!({"member": member, "op": "gt", "json": "1"}))).unwrap_err();
                let dynamic::Error::Cipher(stack_encrypt::Error::Term(
                    stack_encrypt::sem::TermError::JsonPath(error),
                )) = error
                else {
                    panic!("{member}: not a path error: {error:?}")
                };
                assert_eq!(error.at, at, "{member}: {error}");
            }
            for input in [
                input(1, calls("gte")),
                input(2, calls("gte")),
                input(
                    2,
                    json!([
                        {"member": "relationship", "op": "eq", "json": "\"a\""},
                        {"member": "calls", "op": "between", "low": "1", "high": "2"},
                    ]),
                ),
            ] {
                assert!(check(&input).is_ok(), "{input}");
            }
        }
    }

    mod given_the_fields_type {
        use super::*;

        /// A resolver whose `JsonSearch` names no element predicate domain:
        /// what a host presents that has not been taught the operand.
        struct Unnamed;

        impl TargetResolver for Unnamed {
            fn targets(&self) -> Vec<TargetDescriptor> {
                let mut targets = Documents.targets();
                targets[0].elements_query_sql_domain = None;
                targets
            }
            fn encrypt<'a, K: 'static>(
                &self,
                name: &str,
                options: Option<&TargetOptions>,
                keyset: &'a KeysetCipher<'_, K>,
                label: &Label,
                plaintext: ValueFrame,
            ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
                Documents.encrypt(name, options, keyset, label, plaintext)
            }
            fn decrypt<'a, K: 'static>(
                &self,
                name: &str,
                cipher: &'a StackCipher<K>,
                label: &Label,
                bytes: &[u8],
            ) -> Result<Pending<'a, ValueFrame, K>, TargetError> {
                Documents.decrypt(name, cipher, label, bytes)
            }
            fn query<'a, K: 'static>(
                &self,
                name: &str,
                index: &IndexSpec,
                keyset: &'a KeysetCipher<'_, K>,
                label: &Label,
                plaintext: ValueFrame,
            ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
                Documents.query(name, index, keyset, label, plaintext)
            }
        }

        fn names(plan: &record::Plan, resolver: &impl TargetResolver) -> Vec<&'static str> {
            dynamic::field_operators(plan, "profile", resolver)
                .unwrap()
                .into_iter()
                .map(|(op, _)| op.name())
                .collect()
        }

        /// Answered, through the JSON index, on a field that orders a path
        /// and whose type names the operand's domain; its input is
        /// `path_predicates`.
        #[test]
        fn lists_it_when_a_path_is_ordered_and_the_domain_named() {
            let plan = contacts();
            assert_eq!(
                names(&plan, &Documents).last(),
                Some(&"element_match"),
                "the last operator, in OpSpec::ALL's order"
            );
            let (_, index) = dynamic::field_operators(&plan, "profile", &Documents)
                .unwrap()
                .into_iter()
                .find(|(op, _)| *op == OpSpec::ElementMatch)
                .unwrap();
            assert!(
                matches!(index, IndexSpec::Json(_)),
                "the JSON index answers it: {index:?}"
            );
            assert_eq!(
                OpSpec::parse("element_match"),
                Some(OpSpec::ElementMatch),
                "the wire name parses"
            );
            assert_eq!(
                OpSpec::ElementMatch.input(),
                "path_predicates",
                "its input shape"
            );
            assert_eq!(
                OpSpec::ElementMatch.fidelity(),
                OpSpec::BetweenAt.fidelity(),
                "compared as the orderings compare"
            );
        }

        #[test]
        fn does_not_list_it_without_an_ordered_path() {
            let names = names(&plan_of(json!("JsonSearch")), &Documents);
            assert!(
                !names.contains(&"element_match"),
                "no ordering term to compare: {names:?}"
            );
        }

        #[test]
        fn does_not_answer_it_when_the_type_names_no_domain() {
            let wire = json!({
                "profile": {"context": ["users", "profile"], "type": "json", "null": "sql",
                            "target": {"name": "JsonSearch", "options": {"ordered": ["$.a[*].b"]}}}
            });
            let plan = record::plan_with(&dynamic::frame::serde::to_vec(&wire).unwrap(), &Unnamed)
                .unwrap();
            let names = names(&plan, &Unnamed);
            assert!(names.contains(&"lt_at"), "the orderings still: {names:?}");
            assert!(!names.contains(&"element_match"), "{names:?}");
            let error = dynamic::check_query(
                &plan,
                "profile",
                OpSpec::ElementMatch,
                json_frame(&json!({"path": "$.a[*]", "predicates": [
                    {"member": "b", "op": "gt", "json": "1"}
                ]})),
                &Unnamed,
            )
            .unwrap_err();
            assert_eq!(
                error.reason(),
                Some(Reason::OperatorNotAnswered),
                "{error:?}"
            );
        }
    }
}
