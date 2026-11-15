//! An encrypted JSON document through a data plan: the path a language SDK
//! takes (the Go guest installs the same resolver), and the path a Rust
//! program queries a document by, since an EQL type has no typed JSON
//! query. Sealing is held to the typed Rust path, `JsonTree::new(options)`,
//! which it must agree with.
//!
//! A data-plan field names the target `JsonSearch`, declares the `json`
//! type, and hands its document over as JSON text. The engine parses it by
//! one set of rules, lays it out with the JSON index under the field's
//! options, and stores the `public.eql_v4_json_search` value; opening gives
//! the document's text back. Here:
//!
//! - a batch of documents seals in one key request and opens to the same
//!   values, scalar roots, arrays and a JSON `null` included;
//! - the data plan and `JsonTree::new(options)` write the same search terms
//!   (selectors, ordering terms, the containment selector set) for the same
//!   document under the same column, and each opens what the other sealed;
//! - text that is not a document is refused before any key is requested,
//!   naming the field and a code, never a byte of the text;
//! - each operator's operand reads as the EQL type the SQL binds it as
//!   (`JsonTreeQuery`, `JsonTreeLeafQuery`, a selector, a list of tokens),
//!   is bound as the domain the target names for it, and finds the stored
//!   documents it should, decided here with no database;
//! - rows open against the request that prepared them;
//! - a document sealed under a scope and a binding is found by a query
//!   under the scope, and read under the scope and the binding.

mod common;

use stack_encrypt::AsProtectedRef as _;
use std::collections::BTreeMap;

use eql_bindings::encryption::targets as eql_targets;
use eql_bindings::encryption::EqlTargets;
use eql_bindings::v4::json_tree::{JsonTree, JsonTreeDocument, JsonTreeLeafQuery, JsonTreeQuery};
use eql_bindings::Identifier;
use serde_json::{json, Value};
use stack_encrypt::dynamic::{self, record, TargetError, ValueFrame};
use stack_encrypt::json::{JsonDocument, JsonOptions, JsonPlaintext, JsonQuery};
use stack_encrypt::{CipherText, DecryptFrom, Encrypt, KeysetCipher, Label, NonEmpty};

/// The options the documents are sealed under on both paths.
fn options() -> JsonOptions {
    JsonOptions::default()
        .ordering(["$.age", "$.visits[*].at"])
        .unwrap()
}

/// A plan with one `json` field, `profile`, under `users/profile`, naming
/// `JsonSearch` with [`options`], as a binding writes it.
fn plan() -> record::Plan {
    let wire = json!({
        "profile": {
            "context": ["users", "profile"],
            "type": "json",
            "null": "sql",
            "target": {
                "name": "JsonSearch",
                "options": {"ordered": ["$.age", "$.visits[*].at"]}
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

fn frame<T: Encrypt>(value: T) -> ValueFrame {
    ValueFrame::of(value).unwrap()
}

/// The documents a batch carries, as values.
fn documents() -> Vec<Value> {
    conformance_cases()["documents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|text| serde_json::from_str(text.as_str().unwrap()).unwrap())
        .collect()
}

/// The EQL value a sealed row stores for `profile`, parsed.
fn stored(row: &stack_encrypt::StackCipherText) -> JsonTreeDocument {
    let CipherText::Map(fields) = row else {
        panic!("a row is a map")
    };
    let (_, CipherText::Map(outputs)) = fields
        .iter()
        .find(|(name, _)| name == "profile")
        .expect("profile is stored")
    else {
        panic!("profile is a map of outputs");
    };
    let Some((_, CipherText::Passthrough(payload))) = outputs.iter().find(|(key, _)| key == "eql")
    else {
        panic!("profile's EQL value is a passthrough");
    };
    let bytes: Vec<u8> =
        match dynamic::frame::serde::from_slice::<serde_bytes_like::Bytes>(&payload.0) {
            Ok(bytes) => bytes.0,
            Err(_) => panic!("the EQL value is bytes"),
        };
    serde_json::from_slice(&bytes).expect("the EQL value is a json_tree document")
}

/// A byte string read out of a frame.
mod serde_bytes_like {
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

/// The JSON index's own document under the EQL envelope, whose selector
/// set compares as a set.
fn index_document(document: &JsonTreeDocument) -> JsonDocument {
    let wire = serde_json::to_value(document).unwrap();
    serde_json::from_value(json!({"h": wire["h"], "sv": wire["sv"], "q": wire["q"]})).unwrap()
}

/// What each stored entry shows a query, as a sorted list: its selector,
/// its ordering term and whether it carries a parent tag. Entries are
/// stored in a random order, so two seals of one document compare as
/// multisets.
fn search_terms(document: &JsonTreeDocument) -> Vec<(String, String, bool)> {
    let mut terms: Vec<_> = document
        .sv
        .iter()
        .map(|entry| {
            (
                serde_json::to_string(&entry.s).unwrap(),
                serde_json::to_string(&entry.op).unwrap(),
                entry.p.is_some(),
            )
        })
        .collect();
    terms.sort();
    terms
}

fn column() -> NonEmpty<Identifier> {
    Identifier::for_column("users", "profile").unwrap()
}

/// Every document of a batch, as JSON text, seals in one key request and
/// opens to the same value: the text is not promised back byte for byte,
/// the value is.
#[tokio::test]
async fn a_batch_of_documents_round_trips_in_one_request() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let plan = plan();
    let texts: Vec<String> = documents().iter().map(Value::to_string).collect();
    let source: Vec<BTreeMap<&str, &str>> = texts
        .iter()
        .map(|text| BTreeMap::from([("profile", text.as_str())]))
        .collect();
    let sealed = record::encrypt_with(&keyset, frame(&source), &plan, &EqlTargets)
        .unwrap()
        .await
        .unwrap();
    assert_eq!(
        calls.lock().unwrap().generate.len(),
        1,
        "every document's key in one request"
    );
    let opened = record::decrypt_with(&cipher, sealed, &plan, None, &EqlTargets)
        .unwrap()
        .await
        .unwrap();
    assert_eq!(calls.lock().unwrap().retrieve.len(), 1, "and one to open");
    let rows: Vec<BTreeMap<String, serde_bytes_like::Bytes>> =
        dynamic::frame::serde::from_slice(opened.risky_ref()).unwrap();
    let back: Vec<Value> = rows
        .iter()
        .map(|row| serde_json::from_slice(&row["profile"].0).unwrap())
        .collect();
    assert_eq!(back, documents());
}

/// The data plan and the typed layout write the same search terms for the
/// same document under the same column: the root's entry first, then every
/// entry's selector, parent tag's place and ordering term, and the
/// containment selector set, compared as sets because each seal draws its
/// own storage order. Only the ciphertexts, the data key, the tags salted
/// by it and the order differ. And each opens what the other sealed.
#[tokio::test]
async fn the_data_plan_and_the_typed_layout_agree() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let plan = plan();
    for document in documents() {
        let text = document.to_string();
        let source = BTreeMap::from([("profile", text.as_str())]);
        let sealed = record::encrypt_with(&keyset, frame(&source), &plan, &EqlTargets)
            .unwrap()
            .await
            .unwrap();
        let data = stored(&sealed);
        let typed: JsonTreeDocument = keyset
            .run(JsonTree::new(options()).encryption(), &document, column())
            .await
            .unwrap();
        assert_eq!(data.i, typed.i, "{text}: the column");
        assert_eq!(
            index_document(&data).selector_set(),
            index_document(&typed).selector_set(),
            "{text}: the containment selector set"
        );
        assert_eq!(data.sv[0].s, typed.sv[0].s, "{text}: the root first");
        assert_eq!(
            search_terms(&data),
            search_terms(&typed),
            "{text}: one entry per node, each with its selector, ordering term and parent tag's place"
        );

        // The typed path opens the data plan's document...
        let opened = JsonPlaintext::decrypt_from_with_context(data, &cipher, column())
            .await
            .unwrap();
        assert_eq!(opened.value(), &document);
        // ...and the data plan opens the typed path's.
        let record = CipherText::Map(vec![(
            "profile".to_owned(),
            CipherText::Map(vec![(
                "eql".to_owned(),
                CipherText::Passthrough(stack_encrypt::PassthroughFrame(
                    frame(stack_encrypt::Protected::new(
                        serde_json::to_vec(&typed).unwrap(),
                    ))
                    .risky_ref()
                    .to_vec(),
                )),
            )]),
        )]);
        let opened = record::decrypt_with(&cipher, record, &plan, None, &EqlTargets)
            .unwrap()
            .await
            .unwrap();
        let row: BTreeMap<String, serde_bytes_like::Bytes> =
            dynamic::frame::serde::from_slice(opened.risky_ref()).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&row["profile"].0).unwrap(),
            document
        );
    }
}

/// Under `"null": "sql"` a frame null, or a row with no `profile`, stores
/// no value for the field, and opens as a null; a JSON `null` beside them
/// is a document and round-trips as one.
#[tokio::test]
async fn a_sql_null_stores_no_document() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let plan = plan();
    let rows: Vec<BTreeMap<&str, Option<&str>>> = vec![
        BTreeMap::from([("profile", Some(r#"{"name": "Alice"}"#))]),
        BTreeMap::from([("profile", None)]),
        BTreeMap::new(),
        BTreeMap::from([("profile", Some("null"))]),
    ];
    let sealed = record::encrypt_with(&keyset, frame(&rows), &plan, &EqlTargets)
        .unwrap()
        .await
        .unwrap();
    let CipherText::Sequence(stored) = &sealed else {
        panic!("a batch is a sequence")
    };
    let stores_profile: Vec<bool> = stored
        .iter()
        .map(|row| {
            let CipherText::Map(fields) = row else {
                panic!("a row is a map")
            };
            fields.iter().any(|(name, _)| name == "profile")
        })
        .collect();
    assert_eq!(stores_profile, [true, false, false, true]);
    let opened = record::decrypt_with(&cipher, sealed, &plan, None, &EqlTargets)
        .unwrap()
        .await
        .unwrap();
    let rows: Vec<BTreeMap<String, Option<serde_bytes_like::Bytes>>> =
        dynamic::frame::serde::from_slice(opened.risky_ref()).unwrap();
    let back: Vec<Option<Value>> = rows
        .iter()
        .map(|row| {
            row["profile"]
                .as_ref()
                .map(|text| serde_json::from_slice(&text.0).unwrap())
        })
        .collect();
    assert_eq!(
        back,
        [
            Some(json!({"name": "Alice"})),
            None,
            None,
            Some(Value::Null)
        ]
    );
}

/// A document sealed for one column does not open as another's: the data
/// plan opens `JsonSearch` under the field's own column, and a document
/// whose envelope names another is refused before any key is retrieved.
#[tokio::test]
async fn a_document_does_not_open_under_another_column() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let text = documents()[0].to_string();
    let sealed = record::encrypt_with(
        &keyset,
        frame(BTreeMap::from([("profile", text.as_str())])),
        &plan(),
        &EqlTargets,
    )
    .unwrap()
    .await
    .unwrap();
    let other = record::plan_with(
        (dynamic::frame::serde::to_vec(&json!({
            "profile": {
                "context": ["users", "other"],
                "type": "json",
                "null": "sql",
                "target": {
                    "name": "JsonSearch",
                    "options": {"ordered": ["$.age", "$.visits[*].at"]}
                }
            }
        }))
        .unwrap())
        .as_protected_ref(),
        &EqlTargets,
    )
    .unwrap();
    calls.lock().unwrap().retrieve.clear();
    let refused = record::decrypt_with(&cipher, sealed, &other, None, &EqlTargets)
        .unwrap()
        .await;
    assert!(
        matches!(refused, Err(stack_encrypt::Error::ContextMismatch { .. })),
        "{:?}",
        refused.map(drop)
    );
    assert!(
        calls.lock().unwrap().retrieve.is_empty(),
        "refused before any key is retrieved"
    );
}

/// Text that is not a document is refused when the record is read, before
/// any key is requested, naming the field and what was wrong by its code.
#[tokio::test]
async fn text_that_is_not_a_document_is_refused_before_any_key() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let plan = plan();
    for case in conformance_cases()["invalid_documents"].as_array().unwrap() {
        let text = case["text"].as_str().unwrap();
        let code = case["reason"].as_str().unwrap();
        let source = BTreeMap::from([("profile", text)]);
        let error = match record::encrypt_with(&keyset, frame(&source), &plan, &EqlTargets) {
            Err(error) => error,
            Ok(_) => panic!("{text:?} was accepted"),
        };
        let shown = format!("{error} {:?}", stack_encrypt::ErrorPayload::payload(&error));
        assert!(
            matches!(&error, dynamic::Error::Target(TargetError::Json { name, reason, .. }) if name == "profile" && *reason == code),
            "{text:?}: {error:?}"
        );
        assert!(
            !shown.contains("secret") && !shown.contains("9999"),
            "{shown}"
        );
    }
    // A value of another kind is not a document either.
    let source = BTreeMap::from([("profile", 7u32)]);
    assert!(record::encrypt_with(&keyset, frame(&source), &plan, &EqlTargets).is_err());
    assert!(
        calls.lock().unwrap().generate.is_empty(),
        "no key was requested"
    );
}

// =============================================================================
// Operators: each operand's shape, and what it finds
// =============================================================================

/// An operator's input as a binding writes it: an object of named inputs.
fn input(entries: &[(&str, Value)]) -> ValueFrame {
    let object: serde_json::Map<String, Value> = entries
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    ValueFrame::from_bytes(
        dynamic::frame::serde::to_vec(&object)
            .unwrap()
            .as_protected_ref(),
    )
    .unwrap()
}

/// The data path's term for one operator and input on `profile`.
async fn data_term(
    keyset: &KeysetCipher<'_, common::Observed>,
    plan: &record::Plan,
    operator: &str,
    entries: &[(&str, Value)],
) -> dynamic::QueryTerm {
    dynamic::query_term(
        keyset,
        plan,
        "profile",
        dynamic::Op::parse(operator).unwrap(),
        input(entries),
        &EqlTargets,
    )
    .unwrap()
    .await
    .unwrap()
}

fn one(term: &dynamic::QueryTerm) -> Value {
    let dynamic::Operand::One(bytes) = term.operand() else {
        panic!("{}: one operand", term.operator());
    };
    serde_json::from_slice(bytes).unwrap()
}

/// A containment or equality operand, read back as the engine's
/// `JsonQuery`, which compares as sets: each derivation sends its selector
/// set in a random order of its own.
fn containment(operand: Value) -> JsonQuery {
    serde_json::from_value(operand).unwrap()
}

/// The operators a document field answers, with the input each takes:
/// the orderings at a path and `element_match` only when the field orders
/// a path, and `match` on every field.
#[test]
fn a_document_field_answers_the_json_operators() {
    let names = |plan: &record::Plan| -> Vec<(&'static str, &'static str)> {
        dynamic::field_operators(plan, "profile", &EqlTargets)
            .unwrap()
            .into_iter()
            .map(|(op, index)| {
                assert_eq!(index.key(), "json");
                (op.name(), op.input())
            })
            .collect()
    };
    assert_eq!(
        names(&plan()),
        [
            ("contains", "json"),
            ("contained_by", "json"),
            ("eq_at", "path_json"),
            ("lt_at", "path_json"),
            ("lte_at", "path_json"),
            ("gt_at", "path_json"),
            ("gte_at", "path_json"),
            ("between_at", "path_pair"),
            ("selector", "path"),
            ("subtree", "path_bound"),
            ("children", "path"),
            ("child_count", "path"),
            ("element_match", "path_predicates"),
            ("match", "predicate"),
        ]
    );
    let unordered = record::plan_with(
        (dynamic::frame::serde::to_vec(&json!({
            "profile": {"context": ["users", "profile"], "target": "JsonSearch"}
        }))
        .unwrap())
        .as_protected_ref(),
        &EqlTargets,
    )
    .unwrap();
    assert_eq!(
        names(&unordered)
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>(),
        [
            "contains",
            "contained_by",
            "eq_at",
            "selector",
            "subtree",
            "children",
            "child_count",
            "match"
        ],
        "no ordering and no `element_match` without an ordered path"
    );
}

/// A document sealed through the plan, as the engine's document: what an
/// operand is decided against here, with no database.
async fn sealed(
    keyset: &KeysetCipher<'_, common::Observed>,
    plan: &record::Plan,
    document: &Value,
) -> JsonDocument {
    let text = document.to_string();
    let row = record::encrypt_with(
        keyset,
        frame(BTreeMap::from([("profile", text.as_str())])),
        plan,
        &EqlTargets,
    )
    .unwrap()
    .await
    .unwrap();
    engine_document(&stored(&row))
}

/// The ordering term the document stores at a selector, as the SQL's
/// `col -> selector` reads it: bytes, which order as the plaintexts do.
fn stored_ordering_term(document: &JsonDocument, selector: &str) -> Vec<u8> {
    use base64::Engine;
    let selector: [u8; 16] = base64::engine::general_purpose::STANDARD
        .decode(selector)
        .unwrap()
        .try_into()
        .unwrap();
    document
        .entries()
        .iter()
        .find(|entry| entry.selector() == &selector)
        .expect("the document has a node at the selector")
        .ordering_term()
        .expect("the path is ordered")
        .to_vec()
}

/// Every operand the data path derives is in the EQL wire form: it reads
/// as the type the SQL binds it as, and is bound as the domain the target
/// names for it. Each finds the stored documents it should: a containment
/// or equality operand as `jsonb @>` decides it over the stored selector
/// sets, and an ordering operand as the SQL compares ordering terms.
#[tokio::test]
async fn every_operand_is_in_the_eql_wire_form_and_finds_what_it_should() {
    use base64::Engine;
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let plan = plan();
    let document = json!({"visits": [{"at": 3}], "name": "Alice"});
    // Three stored documents: one that holds `document` and more, one that
    // is part of it, and one that differs from it.
    let more = sealed(
        &keyset,
        &plan,
        &json!({"visits": [{"at": 3}, {"at": 1}], "name": "Alice", "age": 34}),
    )
    .await;
    let part = sealed(&keyset, &plan, &json!({"name": "Alice"})).await;
    let other = sealed(
        &keyset,
        &plan,
        &json!({"visits": [{"at": 4}], "name": "Bob", "age": 52}),
    )
    .await;
    calls.lock().unwrap().generate.clear();

    // A needle reads as the EQL type, and writes back as the operand.
    let needle = |term: &dynamic::QueryTerm| -> JsonQuery {
        let operand = one(term);
        let typed: JsonTreeQuery = serde_json::from_value(operand.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(&typed).unwrap(),
            operand,
            "{}",
            term.operator()
        );
        assert_eq!(term.domain(), Some("eql_v4.query_json"));
        assert_eq!(term.encoding(), "eql");
        containment(operand)
    };

    let contains = needle(
        &data_term(
            &keyset,
            &plan,
            "contains",
            &[("json", json!(document.to_string()))],
        )
        .await,
    );
    assert!(contains.matches(more.selector_set()), "@> a superset");
    assert!(!contains.matches(part.selector_set()), "@> a part");
    assert!(!contains.matches(other.selector_set()), "@> another");

    // `<@` sends the same needle, and the SQL reads it the other way: the
    // stored document's selector set is inside the needle's.
    let contained_by = needle(
        &data_term(
            &keyset,
            &plan,
            "contained_by",
            &[("json", json!(document.to_string()))],
        )
        .await,
    );
    assert_eq!(contained_by, contains, "one needle for both directions");
    let within =
        |stored: &JsonDocument| contained_by.selector_set().contains(stored.selector_set());
    assert!(within(&part), "<@ a part");
    assert!(!within(&more), "<@ a superset");
    assert!(!within(&other), "<@ another");

    let eq = data_term(
        &keyset,
        &plan,
        "eq_at",
        &[("path", json!("$.name")), ("json", json!("\"Alice\""))],
    )
    .await;
    let eq = needle(&eq);
    assert!(eq.matches(more.selector_set()), "$.name == Alice");
    assert!(eq.matches(part.selector_set()), "$.name == Alice");
    assert!(!eq.matches(other.selector_set()), "$.name == Alice");

    let lt = data_term(
        &keyset,
        &plan,
        "lt_at",
        &[("path", json!("$.age")), ("json", json!("40"))],
    )
    .await;
    assert_eq!(lt.domain(), Some("eql_v4.query_json_leaf"));
    assert_eq!(lt.encoding(), "eql");
    // A bound reads as the EQL type: the path's selector, which `->` takes,
    // and the value's ordering term.
    let bound: JsonTreeLeafQuery = serde_json::from_value(one(&lt)).unwrap();
    assert_eq!(serde_json::to_value(&bound).unwrap(), one(&lt));
    let age = keyset
        .json_selector(
            &stack_encrypt::json::JsonPath::parse("$.age").unwrap(),
            column(),
        )
        .await
        .unwrap()
        .to_string();
    assert_eq!(bound.s.0.as_str(), age);
    let forty = base64::engine::general_purpose::STANDARD
        .decode(bound.op.0.as_str())
        .unwrap();
    assert!(stored_ordering_term(&more, &age) < forty, "34 < 40");
    assert!(stored_ordering_term(&other, &age) > forty, "52 > 40");

    let between = data_term(
        &keyset,
        &plan,
        "between_at",
        &[
            ("path", json!("$.age")),
            ("low", json!("18")),
            ("high", json!("40")),
        ],
    )
    .await;
    let dynamic::Operand::Range { lo, hi } = between.operand() else {
        panic!("a range");
    };
    let gte = data_term(
        &keyset,
        &plan,
        "gte_at",
        &[("path", json!("$.age")), ("json", json!("18"))],
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<Value>(lo).unwrap(),
        one(&gte),
        "the low bound"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(hi).unwrap(),
        one(&lt),
        "the high bound"
    );
    assert_eq!(between.domain(), Some("eql_v4.query_json_leaf"));

    let path = stack_encrypt::json::JsonPath::parse("$.visits[*].at").unwrap();
    let selector = data_term(
        &keyset,
        &plan,
        "selector",
        &[("path", json!("$.visits[*].at"))],
    )
    .await;
    assert_eq!(
        selector.operand(),
        &dynamic::Operand::Text(
            keyset
                .json_selector(&path, column())
                .await
                .unwrap()
                .to_string()
        )
    );
    assert_eq!(
        (selector.domain(), selector.encoding()),
        (Some("text"), "text")
    );

    let subtree = data_term(
        &keyset,
        &plan,
        "subtree",
        &[
            ("path", json!("$.visits[*].at")),
            ("wildcard_bound", json!(4)),
        ],
    )
    .await;
    let key = keyset
        .json_subtree_key_with_bound(&path, &options(), 4, column())
        .await
        .unwrap();
    assert_eq!(subtree.operand(), &dynamic::Operand::TextList(key.tokens()));
    assert_eq!(key.tokens().len(), 5, "four elements and a probe");
    assert_eq!(
        (subtree.domain(), subtree.encoding()),
        (Some("text[]"), "text_array")
    );

    let children = data_term(&keyset, &plan, "children", &[("path", json!("$.visits"))]).await;
    let visits = keyset
        .json_subtree_key(
            &stack_encrypt::json::JsonPath::parse("$.visits").unwrap(),
            &options(),
            column(),
        )
        .await
        .unwrap();
    assert_eq!(
        children.operand(),
        &dynamic::Operand::Text(visits.tokens()[0].clone())
    );
    let count = data_term(
        &keyset,
        &plan,
        "child_count",
        &[("path", json!("$.visits"))],
    )
    .await;
    assert_eq!(count.operand(), children.operand());

    assert!(
        calls.lock().unwrap().generate.is_empty(),
        "a query mints no key"
    );
}

/// The refusals a JSON operator makes before it derives anything, each
/// naming the field and a reason or an engine error, never the input.
#[test]
fn a_json_operator_refuses_what_it_cannot_answer() {
    let plan = plan();
    let check = |operator: &str, entries: &[(&str, Value)]| {
        dynamic::check_query(
            &plan,
            "profile",
            dynamic::Op::parse(operator).unwrap(),
            input(entries),
            &EqlTargets,
        )
    };
    let reason = |operator: &str, entries: &[(&str, Value)]| {
        let error = check(operator, entries).unwrap_err();
        assert!(!format!("{error}").contains("secret"), "{error}");
        match error.reason() {
            // An input refusal names the field and a reason; the engine's
            // own refusal is a term error, which carries no reason.
            Some(reason) => {
                assert_eq!(error.field(), Some("profile"), "{error}");
                reason.as_str()
            }
            None => "engine",
        }
    };
    use dynamic::Reason;
    assert_eq!(reason("contains", &[("needle", json!("{}"))]), "json_input");
    assert_eq!(
        reason("contains", &[("json", json!(r#"{"secret":1,"secret":1}"#))]),
        "json_duplicate_key"
    );
    assert_eq!(
        reason("contains", &[("json", json!("{\"secret\""))]),
        "json_syntax"
    );
    assert_eq!(
        reason("eq_at", &[("path", json!("$.a[2]")), ("json", json!("1"))]),
        "json_path_position"
    );
    assert_eq!(
        reason("selector", &[("path", json!("$.a[0].b"))]),
        "json_path_position"
    );
    assert_eq!(
        reason("children", &[("path", json!("$.a[*]"))]),
        "json_path_wildcard"
    );
    // The engine's own refusals: a container at a path, a path the field
    // does not order, a value no ordering takes, a path that is not one.
    for (operator, entries) in [
        (
            "eq_at",
            vec![("path", json!("$.a")), ("json", json!(r#"{"secret":1}"#))],
        ),
        (
            "lt_at",
            vec![("path", json!("$.name")), ("json", json!("1"))],
        ),
        (
            "lt_at",
            vec![("path", json!("$.age")), ("json", json!("true"))],
        ),
        (
            "lt_at",
            vec![("path", json!("$.visits[2].at")), ("json", json!("1"))],
        ),
        ("selector", vec![("path", json!("secret"))]),
    ] {
        assert_eq!(reason(operator, &entries), "engine", "{operator}");
    }
    // `eq` and friends are not a document's operators.
    let error = dynamic::check_query(&plan, "profile", dynamic::Op::Eq, input(&[]), &EqlTargets)
        .unwrap_err();
    assert_eq!(error.reason(), Some(Reason::OperatorNotAnswered));
}

// =============================================================================
// Reads: rows opened against the request that prepared them
// =============================================================================

/// The engine's document under a stored EQL document: its entries, `h`, `sv`
/// and `q` without the envelope.
fn engine_document(stored: &JsonTreeDocument) -> stack_encrypt::json::JsonDocument {
    let mut value = serde_json::to_value(stored).unwrap();
    let object = value.as_object_mut().unwrap();
    let _ = object.remove("v");
    let _ = object.remove("i");
    serde_json::from_value(value).unwrap()
}

/// The rows `json_tree_subtree(doc, tokens, 0)` returns, as the SQL writes
/// them: each node with its header, ordinal and depth grafted.
fn subtree_rows(doc: &stack_encrypt::json::JsonDocument, tokens: &[String]) -> Vec<String> {
    use base64::Engine;
    let tokens: Vec<[u8; 16]> = tokens
        .iter()
        .map(|t| {
            base64::engine::general_purpose::STANDARD
                .decode(t)
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    doc.subtree(&tokens)
        .into_iter()
        .map(|(j, _, d)| {
            let mut wire = serde_json::to_value(doc.node(j).unwrap()).unwrap();
            wire["d"] = json!(d);
            wire.to_string()
        })
        .collect()
}

/// The entry `doc -> selector` returns: the first entry carrying it in
/// stored order.
fn extracted_row(doc: &stack_encrypt::json::JsonDocument, selector: &str) -> Option<String> {
    use base64::Engine;
    let selector: [u8; 16] = base64::engine::general_purpose::STANDARD
        .decode(selector)
        .unwrap()
        .try_into()
        .unwrap();
    let j = doc
        .entries()
        .iter()
        .position(|e| e.selector() == &selector)?;
    Some(
        serde_json::to_value(doc.node(j).unwrap())
            .unwrap()
            .to_string(),
    )
}

async fn open(
    keyset: &KeysetCipher<'_, common::Observed>,
    plan: &record::Plan,
    request: Value,
    groups: Vec<Vec<String>>,
) -> Result<Vec<Vec<Value>>, stack_encrypt::Error> {
    let request = ValueFrame::from_bytes(
        dynamic::frame::serde::to_vec(&request)
            .unwrap()
            .as_protected_ref(),
    )
    .unwrap();
    let rows = frame(&groups);
    let opened = dynamic::json_open(keyset, plan, "profile", request, rows, &EqlTargets)
        .unwrap()
        .await?;
    let groups: Vec<Vec<serde_bytes_like::Bytes>> =
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

/// Two documents, read through the data path: `->` by selector, a concrete
/// subtree, a wildcard subtree, and a row with no node there, in one key
/// request; each group of rows opens on its own.
#[tokio::test]
async fn reads_open_against_the_request_that_prepared_them() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let plan = plan();
    let documents = [
        json!({"name": "Alice", "age": 34, "visits": [{"at": 3}, {"at": 1, "where": "x"}]}),
        json!({"name": "Bob", "visits": []}),
    ];
    let mut stored = Vec::new();
    for document in &documents {
        let text = document.to_string();
        let sealed = record::encrypt_with(
            &keyset,
            frame(BTreeMap::from([("profile", text.as_str())])),
            &plan,
            &EqlTargets,
        )
        .unwrap()
        .await
        .unwrap();
        stored.push(engine_document(&stored_of(&sealed)));
    }

    // `->` on `$.name` in each row, and a row with no `$.age` (NULL).
    let name = data_term(&keyset, &plan, "selector", &[("path", json!("$.name"))]).await;
    let dynamic::Operand::Text(name) = name.operand() else {
        panic!()
    };
    let age = data_term(&keyset, &plan, "selector", &[("path", json!("$.age"))]).await;
    let dynamic::Operand::Text(age) = age.operand() else {
        panic!()
    };
    calls.lock().unwrap().retrieve.clear();
    let names = open(
        &keyset,
        &plan,
        json!({"operation": "selector", "path": "$.name"}),
        stored
            .iter()
            .map(|d| extracted_row(d, name).into_iter().collect())
            .collect(),
    )
    .await
    .unwrap();
    assert_eq!(names, [vec![json!("Alice")], vec![json!("Bob")]]);
    assert_eq!(
        calls.lock().unwrap().retrieve.len(),
        1,
        "one key request for every row"
    );
    let ages = open(
        &keyset,
        &plan,
        json!({"operation": "selector", "path": "$.age"}),
        stored
            .iter()
            .map(|d| extracted_row(d, age).into_iter().collect())
            .collect(),
    )
    .await
    .unwrap();
    assert_eq!(
        ages,
        [vec![json!(34)], vec![]],
        "absence is no value, not null"
    );

    // `->` on a container with members returns its entry alone, which
    // commits to children the read does not return: it does not open, and
    // the refusal names that cause and an altered entry, claiming neither.
    // A container is read with `subtree`.
    let visits = data_term(&keyset, &plan, "selector", &[("path", json!("$.visits"))]).await;
    let dynamic::Operand::Text(visits) = visits.operand() else {
        panic!()
    };
    let container = open(
        &keyset,
        &plan,
        json!({"operation": "selector", "path": "$.visits"}),
        vec![extracted_row(&stored[0], visits).into_iter().collect()],
    )
    .await;
    assert!(
        matches!(container, Err(stack_encrypt::Error::JsonNotALeaf)),
        "{:?}",
        container.err()
    );

    // A wildcard read: every element's `at` below the bound, per row.
    let tokens = data_term(
        &keyset,
        &plan,
        "subtree",
        &[("path", json!("$.visits[*].at"))],
    )
    .await;
    let dynamic::Operand::TextList(tokens) = tokens.operand() else {
        panic!()
    };
    let ats = open(
        &keyset,
        &plan,
        json!({"operation": "subtree", "path": "$.visits[*].at"}),
        stored.iter().map(|d| subtree_rows(d, tokens)).collect(),
    )
    .await
    .unwrap();
    assert_eq!(ats, [vec![json!(3), json!(1)], vec![]]);

    // The rows of one read opened against another's request are refused:
    // the request, not the rows, says which path they are for.
    let wrong = open(
        &keyset,
        &plan,
        json!({"operation": "subtree", "path": "$.name"}),
        vec![subtree_rows(&stored[0], tokens)],
    )
    .await;
    assert!(
        matches!(wrong, Err(stack_encrypt::Error::JsonWrongEntry { .. })),
        "{:?}",
        wrong.err()
    );
    let wrong = open(
        &keyset,
        &plan,
        json!({"operation": "selector", "path": "$.age"}),
        vec![extracted_row(&stored[0], name).into_iter().collect()],
    )
    .await;
    assert!(
        matches!(wrong, Err(stack_encrypt::Error::JsonWrongEntry { .. })),
        "{:?}",
        wrong.err()
    );

    // A wildcard read of an array longer than its bound fails rather than
    // opening to part of the answer.
    let short = data_term(
        &keyset,
        &plan,
        "subtree",
        &[
            ("path", json!("$.visits[*].at")),
            ("wildcard_bound", json!(1)),
        ],
    )
    .await;
    let dynamic::Operand::TextList(short) = short.operand() else {
        panic!()
    };
    let truncated = open(
        &keyset,
        &plan,
        json!({"operation": "subtree", "path": "$.visits[*].at", "wildcard_bound": 1}),
        vec![subtree_rows(&stored[0], short)],
    )
    .await;
    assert!(
        matches!(
            truncated,
            Err(stack_encrypt::Error::JsonWildcardTruncated { .. })
        ),
        "{:?}",
        truncated.err()
    );
}

/// The stored document a sealed row holds for `profile`.
fn stored_of(row: &stack_encrypt::StackCipherText) -> JsonTreeDocument {
    stored(row)
}

/// [`plan`], as a binding sends it for a caller that added a tenant as a
/// scope and, for a seal or a read, a row ID as a binding. The scope
/// extends the field's context, and `"bind"` carries the binding. A query
/// takes no binding.
fn scoped_plan(tenant: u64, row: Option<u64>) -> record::Plan {
    let mut wire = json!({
        "profile": {
            "context": [["users", "profile"], tenant],
            "type": "json",
            "null": "sql",
            "target": {
                "name": "JsonSearch",
                "options": {"ordered": ["$.age", "$.visits[*].at"]}
            }
        }
    });
    if let Some(row) = row {
        wire["bind"] = json!([row]);
    }
    record::plan_with(
        dynamic::frame::serde::to_vec(&wire)
            .unwrap()
            .as_protected_ref(),
        &EqlTargets,
    )
    .unwrap()
}

/// A document sealed under a tenant and a row, through the resolver a
/// language SDK installs. Its `i` is the column alone. A query under the
/// tenant finds it, and a query under another tenant, or none, does not. A
/// read finds its entry under the tenant, and opens it under the tenant and
/// the row.
#[tokio::test]
async fn a_scoped_document_is_found_and_read_under_its_scope() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let sealing = scoped_plan(7, Some(9));
    let text = json!({"name": "Alice", "age": 34, "visits": [{"at": 3}, {"at": 1}]}).to_string();
    let sealed = record::encrypt_with(
        &keyset,
        frame(BTreeMap::from([("profile", text.as_str())])),
        &sealing,
        &EqlTargets,
    )
    .unwrap()
    .await
    .unwrap();
    let stored = stored_of(&sealed);
    assert_eq!(stored.i, *column().get(), "`i` is the column alone");
    let document = engine_document(&stored);

    // A containment query.
    let alice = json!(json!({"name": "Alice"}).to_string());
    let contains = |plan: record::Plan| {
        let (keyset, alice) = (&keyset, alice.clone());
        async move {
            containment(one(&data_term(
                keyset,
                &plan,
                "contains",
                &[("json", alice)],
            )
            .await))
        }
    };
    assert!(
        contains(scoped_plan(7, None))
            .await
            .matches(document.selector_set()),
        "the tenant's query finds the tenant's document"
    );
    for (other, whose) in [
        (scoped_plan(8, None), "another tenant"),
        (plan(), "no tenant"),
    ] {
        assert!(
            !contains(other).await.matches(document.selector_set()),
            "{whose}"
        );
    }

    // A read: `->` by selector, then the entry opened.
    let name = data_term(
        &keyset,
        &scoped_plan(7, None),
        "selector",
        &[("path", json!("$.name"))],
    )
    .await;
    let dynamic::Operand::Text(name) = name.operand() else {
        panic!("a selector is text")
    };
    let entry = extracted_row(&document, name).expect("the tenant's selector names an entry");
    let request = || json!({"operation": "selector", "path": "$.name"});
    let names = open(&keyset, &sealing, request(), vec![vec![entry.clone()]])
        .await
        .unwrap();
    assert_eq!(names, [vec![json!("Alice")]]);
    for (other, whose) in [
        (scoped_plan(7, Some(10)), "another row"),
        (scoped_plan(7, None), "no row"),
        (scoped_plan(8, Some(9)), "another tenant"),
        (plan(), "no tenant"),
    ] {
        let refused = open(&keyset, &other, request(), vec![vec![entry.clone()]]).await;
        assert!(refused.is_err(), "{whose}");
    }
}

/// A document is queried by a JSON operator, which the engine derives
/// from named inputs; eql-bindings' one-plaintext query refuses it by
/// name rather than falling through its generated dispatch.
#[tokio::test]
async fn a_document_has_no_one_plaintext_query() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let label: Label = "users/profile".parse().unwrap();
    let error = eql_targets::query(
        "JsonSearch",
        &stack_encrypt::target::IndexSpec::Json(JsonOptions::default()),
        &keyset,
        &label,
        frame("{}"),
    )
    .err()
    .expect("refused");
    assert!(
        matches!(
            error,
            eql_targets::TargetError::DocumentQuery { name: "JsonSearch" }
        ),
        "{error}"
    );
}

/// Which targets take the JSON index's options is decided twice: the
/// engine gives them to a target whose descriptor carries the `json`
/// index, and eql-bindings seals a target of a document family with them
/// and refuses them on any other. The two must name the same producible
/// targets, or a write the engine configures is one eql-bindings refuses.
#[tokio::test]
async fn the_engine_and_the_table_agree_on_which_targets_take_json_options() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let label: Label = "users/profile".parse().unwrap();
    let options = dynamic::TargetOptions::Json(JsonOptions::default());
    for target in eql_targets::targets().iter().filter(|t| t.producible) {
        let engine = target.indexes.contains(&"json");
        let refused = matches!(
            eql_targets::encrypt_with(target.name, Some(&options), &keyset, &label, frame(true)),
            Err(eql_targets::TargetError::Options { .. })
        );
        assert_eq!(engine, !refused, "{}", target.name);
    }
}

fn conformance_cases() -> Value {
    let cases: Value = serde_json::from_str(include_str!(
        "../../../../../conformance/stack-encrypt/v1/eql-json-v1.cases.json"
    ))
    .unwrap();
    assert_eq!(cases["version"], 1);
    assert_eq!(cases["profile"], "eql-json-v1");
    cases
}
