//! A document field's JSON operators and reads through the data plan, with
//! the engine's own JSON index behind the target: what a binding names by
//! operator (`contains`, `eq_at`, the orderings at a path, `selector`,
//! `subtree`, `children`, `child_count`), the operand each derives and the
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
        .with_leaf_query_sql_domain("eql_v4.query_json_leaf")]
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
