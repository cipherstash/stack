//! The JSON index end to end, with no database: a document seals into one
//! entry per node under one data key and opens again; the token chain
//! reaches every child from its parent's token and ordinal, and nothing
//! from any other token;
//! a moved, reordered or regrafted entry fails to open; and containment
//! over the element-nested projection agrees with PostgreSQL's `jsonb @>`
//! on the design's corpus and on random documents, through a Rust model
//! of `jsonb @>` written here from the rules PostgreSQL documents.

mod common;

use common::stack_cipher;
use serde_json::{json, Map, Value};
use stack_encrypt::json::{
    JsonDocument, JsonExtracted, JsonNode, JsonOptions, JsonPath, JsonQuery, JsonSelector,
    JsonSubtree, JsonSubtreeKey,
};
use stack_encrypt::op;
use stack_encrypt::sem::TermError;
use stack_encrypt::target::{
    AeadContext, CallerContext, DecryptField, Decryption, IndexSpec, Json,
};
use stack_encrypt::{nonempty, Error, Plan, PlanError, StackCipher};
use stack_kms::FakeDataKeySource;

fn context() -> CallerContext {
    CallerContext::from(nonempty!("users").with("profile"))
}

fn aead() -> AeadContext {
    AeadContext::from(nonempty!("users").with("profile"))
}

async fn seal(cipher: &StackCipher<FakeDataKeySource>, value: &Value) -> JsonDocument {
    cipher
        .default_keyset()
        .encrypt_as::<Value, JsonDocument>(value, context())
        .await
        .expect("seals")
}

async fn seal_with(
    cipher: &StackCipher<FakeDataKeySource>,
    value: &Value,
    options: &JsonOptions,
) -> JsonDocument {
    cipher
        .default_keyset()
        .run(
            stack_encrypt::target::json_document::<_, stack_encrypt::target::Borrowed>(
                options.clone(),
            ),
            value,
            context(),
        )
        .await
        .expect("seals")
}

/// The options with the root open.
fn open_root() -> JsonOptions {
    JsonOptions {
        sealed_root: false,
        ..JsonOptions::new()
    }
}

/// The options ordering `paths`.
fn ordering(paths: &[&str]) -> JsonOptions {
    JsonOptions::default().ordering(paths).unwrap()
}

async fn open(cipher: &StackCipher<FakeDataKeySource>, doc: JsonDocument) -> Result<Value, Error> {
    cipher.decrypt_as::<Value, JsonDocument>(doc, aead()).await
}

/// The design's fixture document.
fn fixture() -> Value {
    json!({"hello": "world-1", "nested": {"deep": "constant", "list": [{"x": 1}, {"x": 2}]}, "number": 1})
}

/// How many nodes a value has.
fn nodes(value: &Value) -> usize {
    1 + match value {
        Value::Object(map) => map.values().map(nodes).sum(),
        Value::Array(items) => items.iter().map(nodes).sum(),
        _ => 0,
    }
}

// =============================================================================
// Round trips
// =============================================================================

#[tokio::test]
async fn a_document_seals_one_entry_per_node_and_opens_again() {
    let cipher = stack_cipher().await;
    for value in [
        fixture(),
        json!({}),
        json!([]),
        json!("a"),
        json!(2.5),
        json!(null),
        json!(true),
        json!([[1, 2], [3, [4, {"a": null}]]]),
        json!({"a": {"b": {"c": {"d": [1, "x", false]}}}}),
        json!({"a": "b", "a b": 1, "é": [], "0": {}}),
        json!({"n": 18446744073709551615u64, "m": -9223372036854775808i64, "f": 1e300}),
    ] {
        for options in [JsonOptions::default(), open_root()] {
            let doc = seal_with(&cipher, &value, &options).await;
            assert_eq!(
                doc.entries().len(),
                nodes(&value),
                "{value}: one entry per node"
            );
            assert_eq!(doc.header().sealed_root(), options.sealed_root);
            let back = open(&cipher, doc).await.unwrap();
            assert_eq!(back, value, "{value} under {options:?}");
        }
    }
}

/// The deepest document the index takes opens again under either root
/// option, and one level deeper is refused when it is sealed, not when it is
/// read. A sealed root's plaintext is the document as JSON, which
/// `serde_json` reads back only to 128 levels of nesting.
#[tokio::test]
async fn the_deepest_document_the_index_takes_opens_again() {
    let cipher = stack_cipher().await;
    let arrays = |n: usize| (0..n).fold(json!(1), |inner, _| json!([inner]));
    let objects = |n: usize| (0..n).fold(json!("leaf"), |inner, _| json!({"k": inner}));
    for nested in [arrays, objects] {
        for options in [JsonOptions::default(), open_root()] {
            let deepest = nested(127);
            let doc = seal_with(&cipher, &deepest, &options).await;
            assert_eq!(
                open(&cipher, doc).await.unwrap(),
                deepest,
                "127 levels under {options:?}"
            );
            let refused = cipher
                .default_keyset()
                .run(
                    stack_encrypt::target::json_document::<_, stack_encrypt::target::Borrowed>(
                        options.clone(),
                    ),
                    &nested(128),
                    context(),
                )
                .await;
            assert!(
                matches!(refused, Err(Error::Term(TermError::JsonTooDeep))),
                "128 levels under {options:?} is refused when sealed"
            );
        }
    }
}

#[tokio::test]
async fn the_wire_form_is_what_the_sql_domain_stores() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let wire = serde_json::to_value(&doc).unwrap();
    let keys: Vec<&str> = wire
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["h", "q", "sv"]);
    // `q` is the document's own projection, written once: the needle a
    // `Contains` of the whole document derives has the same pairs in the
    // same groups, and nothing else.
    let needle = cipher
        .query(op::Contains, &fixture())
        .on(&plan())
        .await
        .unwrap();
    assert_eq!(wire["q"], serde_json::to_value(&needle).unwrap());
    assert!(
        serde_json::from_value::<JsonDocument>(json!({"h": wire["h"], "sv": wire["sv"]})).is_err(),
        "a document without `q` is not a document: the projection is the only place the value selectors live"
    );
    let back: JsonDocument = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(&back).unwrap(),
        wire,
        "`q` round-trips as stored"
    );
    assert_eq!(
        serde_json::to_value(back.projection()).unwrap(),
        wire["q"],
        "the projection read back is the stored one"
    );
    for (j, entry) in wire["sv"].as_array().unwrap().iter().enumerate() {
        let entry = entry.as_object().unwrap();
        for key in entry.keys() {
            assert!(
                ["s", "c", "x", "p", "op"].contains(&key.as_str()),
                "entry {j} carries an unknown key {key}"
            );
        }
        assert!(entry.contains_key("x"), "entry {j} carries its self tag");
        for (tag, chars, bytes) in [("s", 24, 16), ("x", 12, 8), ("p", 12, 8)] {
            if let Some(text) = entry.get(tag) {
                assert_eq!(
                    text.as_str().unwrap().len(),
                    chars,
                    "entry {j}'s {tag} is {bytes} bytes of padded base64"
                );
            }
        }
        let c = entry["c"].as_str().unwrap();
        assert!(
            c.bytes()
                .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\'),
            "entry {j}'s c is base85 in an alphabet a JSON string carries unescaped"
        );
    }
    let back: JsonDocument = serde_json::from_value(wire).unwrap();
    assert_eq!(back, doc);
}

#[tokio::test]
async fn the_chain_fields_sit_where_the_design_says() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let entries = doc.entries();
    // $, $.hello, $.nested, $.nested.deep, $.nested.list, [0], [0].x, [1], [1].x, $.number
    assert_eq!(entries.len(), 10);
    let root = &entries[0];
    assert!(root.parent_tag().is_none());
    for head in [&entries[1], &entries[2], &entries[9]] {
        assert!(
            head.parent_tag().is_none(),
            "a head has no parent tag under the sealed root"
        );
    }
    for below in &entries[3..9] {
        assert!(below.parent_tag().is_some());
    }
    // Every entry carries a self tag, the root and the heads included, and
    // every one is distinct, so its presence marks nothing.
    let selves: std::collections::HashSet<_> = entries.iter().map(|e| *e.self_tag()).collect();
    assert_eq!(
        selves.len(),
        entries.len(),
        "one distinct self tag per entry"
    );
    // Every parent tag is distinct: siblings are not linkable at rest.
    let tags: std::collections::HashSet<_> = entries[3..9]
        .iter()
        .map(|e| *e.parent_tag().unwrap())
        .collect();
    assert_eq!(tags.len(), 6);
    // The projection groups the two list elements: each is a nested group
    // holding its own pair and its `x`.
    let q = serde_json::to_value(doc.projection()).unwrap();
    assert_eq!(q["el"].as_array().unwrap().len(), 2);
    assert_eq!(q["el"][0]["sv"].as_array().unwrap().len(), 2);
    assert_eq!(
        q["sv"].as_array().unwrap().len(),
        6,
        "$, hello, nested, deep, list, number"
    );
    // No path is ordered by default, so no entry carries a term.
    assert!(entries.iter().all(|e| e.ordering_term().is_none()));
    // Equal values at one path share selectors but not ciphertexts; the
    // value selectors, in the projection, tell equal values from different.
    let pair = |doc: &JsonDocument, i: usize| -> (String, String) {
        let q = serde_json::to_value(doc.projection()).unwrap();
        (
            q["sv"][i]["s"].as_str().unwrap().to_owned(),
            q["sv"][i]["vs"].as_str().unwrap().to_owned(),
        )
    };
    let doc2 = seal(&cipher, &json!([1, 1])).await;
    let (a, b) = (&doc2.entries()[1], &doc2.entries()[2]);
    assert_eq!(a.selector(), b.selector());
    assert_eq!(pair(&doc2, 1), pair(&doc2, 2));
    assert_ne!(a.ciphertext(), b.ciphertext());
    let doc3 = seal(&cipher, &json!([1, 2])).await;
    let (one, two) = (&doc3.entries()[1], &doc3.entries()[2]);
    assert_eq!(one.selector(), two.selector(), "one path");
    assert_ne!(
        pair(&doc3, 1),
        pair(&doc3, 2),
        "different values at one path have different value selectors"
    );
    assert_eq!(
        pair(&doc3, 1),
        pair(&doc2, 1),
        "the value selector names the value at its path, in any document"
    );

    // Without the sealed root, the top-level fields chain from the root.
    let open_doc = seal_with(&cipher, &fixture(), &open_root()).await;
    assert!(open_doc.entries()[1].parent_tag().is_some());
}

// =============================================================================
// The token chain
// =============================================================================

async fn subtree_key(
    cipher: &StackCipher<FakeDataKeySource>,
    path: &str,
    options: JsonOptions,
) -> Result<JsonSubtreeKey, Error> {
    cipher
        .default_keyset()
        .json_subtree_key(
            &JsonPath::parse(path).unwrap(),
            &options,
            nonempty!("users").with("profile"),
        )
        .await
}

/// The selector of `path` under the suite's column.
async fn selector_of(cipher: &StackCipher<FakeDataKeySource>, path: &str) -> JsonSelector {
    cipher
        .default_keyset()
        .json_selector(
            &JsonPath::parse(path).unwrap(),
            nonempty!("users").with("profile"),
        )
        .await
        .unwrap()
}

/// `node` as `->` on `path` returned it, opened by the selector derived
/// for `path`: the only way to open an extracted entry.
async fn extracted(
    cipher: &StackCipher<FakeDataKeySource>,
    path: &str,
    node: JsonNode,
) -> JsonExtracted {
    selector_of(cipher, path).await.open(node)
}

/// `rows` as the key derived for `path` opens them: the only way to build
/// a [`JsonSubtree`].
async fn keyed(
    cipher: &StackCipher<FakeDataKeySource>,
    path: &str,
    rows: Vec<JsonNode>,
) -> JsonSubtree {
    subtree_key(cipher, path, JsonOptions::default())
        .await
        .unwrap()
        .open(rows)
}

/// An ordering term sits on a number or string leaf at an ordered path and
/// nowhere else: a wildcard covers every element. A position is refused,
/// since `->` reads it as the wildcard and no ordering could reach the leaf
/// it names.
#[tokio::test]
async fn an_ordering_term_sits_only_at_an_ordered_path() {
    let cipher = stack_cipher().await;
    // $, $.hello, $.nested, $.nested.deep, $.nested.list, [0], [0].x, [1], [1].x, $.number
    let with_term = |doc: &JsonDocument| -> Vec<usize> {
        doc.entries()
            .iter()
            .enumerate()
            .filter(|(_, e)| e.ordering_term().is_some())
            .map(|(j, _)| j)
            .collect()
    };
    let doc = seal_with(&cipher, &fixture(), &ordering(&["$.hello", "$.number"])).await;
    assert_eq!(with_term(&doc), [1, 9]);
    let wild = seal_with(&cipher, &fixture(), &ordering(&["$.nested.list[*].x"])).await;
    assert_eq!(with_term(&wild), [6, 8], "a wildcard covers every element");
    assert!(matches!(
        JsonOptions::default().ordering(["$.nested.list[1].x"]),
        Err(TermError::JsonOrderingAtPosition)
    ));
    assert!(matches!(
        JsonOptions::default().ordering(["nested"]),
        Err(TermError::JsonPath(_))
    ));
    // Set on the field, which `ordering` guards, a position refuses the
    // seal rather than put a term no ordering reaches on one element.
    let mut positional = JsonOptions::default();
    let _ = positional
        .ordered
        .insert(JsonPath::parse("$.nested.list[1].x").unwrap());
    let refused = cipher
        .default_keyset()
        .run(
            stack_encrypt::target::json_document::<_, stack_encrypt::target::Borrowed>(positional),
            &fixture(),
            context(),
        )
        .await;
    assert!(
        matches!(refused, Err(Error::Term(TermError::JsonOrderingAtPosition))),
        "{refused:?}"
    );
    // A container, a boolean or a null at an ordered path carries none.
    let kinds = seal_with(
        &cipher,
        &json!({"a": true, "b": null, "c": {"d": 1}, "e": [1, "x"]}),
        &ordering(&["$.a", "$.b", "$.c", "$.e", "$.e[*]"]),
    )
    .await;
    // $, $.a, $.b, $.c, $.c.d, $.e, $.e[0], $.e[1]
    assert_eq!(with_term(&kinds), [6, 7]);
    // The root scalar itself, at `$`.
    let scalar = seal_with(&cipher, &json!(7), &ordering(&["$"])).await;
    assert_eq!(with_term(&scalar), [0]);
    // The documents open regardless.
    assert_eq!(open(&cipher, doc).await.unwrap(), fixture());
    assert_eq!(open(&cipher, wild).await.unwrap(), fixture());
}
#[tokio::test]
async fn a_token_derived_from_the_path_alone_finds_exactly_its_node() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let key = subtree_key(&cipher, "$.nested", JsonOptions::default())
        .await
        .unwrap();
    assert_eq!(
        key.tokens().len(),
        1,
        "a path with no wildcard sends one token"
    );
    assert!(key.probes().is_empty(), "and no probe");
    assert_eq!(
        key.path(),
        &JsonPath::parse("$.nested").unwrap(),
        "the key carries the path it was derived from"
    );
    let under = doc.subtree(&key.token_bytes());
    let found: Vec<usize> = under.iter().map(|(j, _, _)| *j).collect();
    assert_eq!(
        found,
        [2, 3, 4, 5, 6, 7, 8],
        "nested itself, then deep, list, both elements, both leaves"
    );
    let depths: Vec<u32> = under.iter().map(|(_, _, d)| *d).collect();
    assert_eq!(
        depths,
        [0, 1, 1, 2, 3, 2, 3],
        "each row's depth below nested"
    );

    let garbage = doc.subtree(&[[7; 16]]);
    assert!(garbage.is_empty(), "a wrong token finds nothing");

    // Below a head the client derives every token itself: a member's from
    // its parent's and its selector, an element's with its index too. The
    // read of the second element sends that element's token, and nothing
    // that covers the list or nested.
    let deeper = subtree_key(&cipher, "$.nested.list[1]", JsonOptions::default())
        .await
        .unwrap();
    assert_eq!(deeper.tokens().len(), 1, "one token");
    assert_ne!(deeper.token_bytes(), key.token_bytes(), "not nested's");
    let found: Vec<usize> = doc
        .subtree(&deeper.token_bytes())
        .iter()
        .map(|(j, _, _)| *j)
        .collect();
    assert_eq!(found, [7, 8], "the second element and its x");
    let list = subtree_key(&cipher, "$.nested.list", JsonOptions::default())
        .await
        .unwrap();
    let (_, entry, list_token) = doc
        .children(&key.token_bytes()[0])
        .into_iter()
        .find(|(j, _, _)| *j == 4)
        .expect("the list is a child of nested");
    assert_eq!(
        list_token,
        Some(list.token_bytes()[0]),
        "the server derives the token the client sends"
    );
    assert_eq!(doc.find(&list.token_bytes()[0]).map(|(j, _)| j), Some(4));
    assert_eq!(entry.selector(), doc.entries()[4].selector());

    // The children of a node, by ordinal: the list's two elements.
    let children: Vec<usize> = doc
        .children(&list.token_bytes()[0])
        .iter()
        .map(|(j, _, _)| *j)
        .collect();
    assert_eq!(children, [5, 7]);
    assert!(doc.children(&[7; 16]).is_empty(), "no node, no children");

    // `$` is a read under either root. Under the sealed root its token
    // finds the root entry and nothing beneath it, since nothing chains
    // from it; under an open root it covers every node.
    let sealed_root = subtree_key(&cipher, "$", JsonOptions::default())
        .await
        .unwrap();
    assert_eq!(
        doc.subtree(&sealed_root.token_bytes())
            .iter()
            .map(|(j, _, d)| (*j, *d))
            .collect::<Vec<_>>(),
        [(0, 0)],
        "the sealed root alone"
    );
    let open_doc = seal_with(&cipher, &fixture(), &open_root()).await;
    let root = subtree_key(&cipher, "$", open_root()).await.unwrap();
    assert_eq!(
        open_doc.subtree(&root.token_bytes()).len(),
        10,
        "the root and every entry beneath it"
    );
    let array_doc = seal_with(&cipher, &json!([[1, 2], [3]]), &open_root()).await;
    let second_row = subtree_key(&cipher, "$[1]", open_root()).await.unwrap();
    let found: Vec<usize> = array_doc
        .subtree(&second_row.token_bytes())
        .iter()
        .map(|(j, _, _)| *j)
        .collect();
    assert_eq!(found, [4, 5], "$, [0], [0][0], [0][1], [1], [1][0]");
}

#[tokio::test]
async fn a_selector_is_the_stored_one_and_folds_positions_into_the_wildcard() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let keyset = cipher.default_keyset();
    let selector = |path: &str| {
        let path = JsonPath::parse(path).unwrap();
        keyset.json_selector(&path, nonempty!("users").with("profile"))
    };
    assert_eq!(
        selector("$.nested.deep").await.unwrap().as_bytes(),
        doc.entries()[3].selector()
    );
    assert_eq!(
        selector("$.nested.list[*].x").await.unwrap().as_bytes(),
        doc.entries()[6].selector()
    );
    assert_eq!(
        selector("$.nested.list[1].x").await.unwrap().as_bytes(),
        doc.entries()[8].selector()
    );
    assert_eq!(
        selector("$").await.unwrap().as_bytes(),
        doc.entries()[0].selector()
    );
    assert_ne!(
        selector("$.hello").await.unwrap().as_bytes(),
        keyset
            .json_selector(
                &JsonPath::parse("$.hello").unwrap(),
                nonempty!("users").with("bio")
            )
            .await
            .unwrap()
            .as_bytes(),
        "a selector is bound to its column"
    );
}

// =============================================================================
// Extraction
// =============================================================================

#[tokio::test]
async fn an_extracted_node_opens_to_its_scalar_and_a_subtree_to_its_value() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let node = |j: usize| doc.node(j).unwrap();
    let scalar = |path: &'static str, j: usize| {
        let cipher = &cipher;
        let node = node(j);
        async move {
            cipher
                .decrypt_as::<Value, JsonExtracted>(extracted(cipher, path, node).await, aead())
                .await
        }
    };
    assert_eq!(scalar("$.hello", 1).await.unwrap(), json!("world-1"));
    assert_eq!(scalar("$.nested.list[0].x", 6).await.unwrap(), json!(1));
    assert_eq!(
        scalar("$", 0).await.unwrap(),
        fixture(),
        "the sealed root is the document"
    );
    assert!(
        matches!(scalar("$.nested", 2).await, Err(Error::OpenedType { .. })),
        "a container node holds no value of its own"
    );

    let key = subtree_key(&cipher, "$.nested", JsonOptions::default())
        .await
        .unwrap();
    let rows = read_rows(&doc, &key);
    let nested = cipher
        .decrypt_as::<Value, JsonSubtree>(key.open(rows.clone()), aead())
        .await
        .unwrap();
    assert_eq!(nested, fixture()["nested"]);
    let forest = cipher
        .decrypt_as::<Vec<Value>, JsonSubtree>(key.open(rows), aead())
        .await
        .unwrap();
    assert_eq!(
        forest,
        vec![fixture()["nested"].clone()],
        "one value: the node at the path"
    );

    // The list, below nested: its own token finds it and its subtree.
    let list = subtree_key(&cipher, "$.nested.list", JsonOptions::default())
        .await
        .unwrap();
    let rows = read_rows(&doc, &list);
    let elements = cipher
        .decrypt_as::<Value, JsonSubtree>(list.open(rows), aead())
        .await
        .unwrap();
    assert_eq!(elements, json!([{"x": 1}, {"x": 2}]));

    // An extracted node round-trips through its wire form with the
    // envelope fields the SQL grafts beside it.
    let mut wire = serde_json::to_value(node(6)).unwrap();
    wire["i"] = json!({"t": "users", "c": "profile"});
    wire["v"] = json!(4);
    let back: JsonNode = serde_json::from_value(wire).unwrap();
    assert_eq!(back.ordinal(), 6);
    assert_eq!(
        cipher
            .decrypt_as::<Value, JsonExtracted>(
                extracted(&cipher, "$.nested.list[*].x", back).await,
                aead()
            )
            .await
            .unwrap(),
        json!(1)
    );
}

/// The rows of a walk come from the server, which can repeat an entry or
/// pick which entries to return. Every entry is authentic, but the rebuild
/// nests the containers it is handed: a repeated row is refused, and so is
/// a line of containers that are not one subtree's consecutive entries,
/// before the rebuild can recurse as deep as the rows.
#[tokio::test]
async fn subtree_rows_the_server_repeats_or_lines_up_are_refused() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let node = |j: usize| doc.node(j).unwrap();
    let repeated = keyed(&cipher, "$.nested", vec![node(1), node(1)]).await;
    assert!(matches!(
        cipher
            .decrypt_as::<Vec<Value>, JsonSubtree>(repeated, aead())
            .await,
        Err(Error::OpenedType { .. })
    ));

    // A wide document of one-member objects: its objects, returned as rows
    // with the last leaf after them, each take the next as their member,
    // and would nest 200 deep.
    let wide = Value::Object(
        (0..200)
            .map(|i| (format!("k{i:03}"), json!({"x": 1})))
            .collect(),
    );
    let doc = seal(&cipher, &wide).await;
    let last = doc.entries().len() - 1;
    let containers: Vec<JsonNode> = (1..doc.entries().len())
        .filter(|j| j % 2 == 1 || *j == last)
        .map(|j| doc.node(j).unwrap())
        .collect();
    assert_eq!(containers.len(), 201);
    assert!(matches!(
        cipher
            .decrypt_as::<Vec<Value>, JsonSubtree>(
                keyed(&cipher, "$.k000", containers).await,
                aead()
            )
            .await,
        Err(Error::JsonWrongEntry { .. })
    ));

    // The same through arrays: one outer array, then every key's inner
    // one-element array, each taken as the element of the one before it.
    let wide = Value::Object(
        (0..200)
            .map(|i| (format!("k{i:03}"), json!([[0]])))
            .collect(),
    );
    let doc = seal(&cipher, &wide).await;
    let last = doc.entries().len() - 1;
    let arrays: Vec<JsonNode> = (1..doc.entries().len())
        .filter(|j| *j == 1 || j % 3 == 2 || *j == last)
        .map(|j| doc.node(j).unwrap())
        .collect();
    assert_eq!(arrays.len(), 202);
    assert!(matches!(
        cipher
            .decrypt_as::<Vec<Value>, JsonSubtree>(keyed(&cipher, "$.k000", arrays).await, aead())
            .await,
        Err(Error::JsonWrongEntry { .. })
    ));
}

// =============================================================================
// Tamper evidence
// =============================================================================

#[tokio::test]
async fn a_moved_reordered_or_regrafted_entry_fails_to_open() {
    let cipher = stack_cipher().await;
    let value = json!({"a": "x", "b": "y"});
    let doc = seal_with(&cipher, &value, &open_root()).await;
    let other = seal_with(&cipher, &value, &open_root()).await;
    let tamper = |mut wire: Value, f: &dyn Fn(&mut Vec<Value>)| {
        let sv = wire["sv"].as_array_mut().unwrap();
        f(sv);
        serde_json::from_value::<JsonDocument>(wire).unwrap()
    };
    let wire = serde_json::to_value(&doc).unwrap();
    let other_wire = serde_json::to_value(&other).unwrap();

    let reordered = tamper(wire.clone(), &|sv| sv.swap(1, 2));
    assert!(
        matches!(open(&cipher, reordered).await, Err(Error::Aead)),
        "reordered"
    );

    let regrafted = tamper(wire.clone(), &|sv| sv[1] = other_wire["sv"][1].clone());
    assert!(
        matches!(open(&cipher, regrafted).await, Err(Error::Aead)),
        "regrafted from another document"
    );

    let truncated = tamper(wire.clone(), &|sv| {
        let _ = sv.pop();
    });
    assert!(
        matches!(
            open(&cipher, truncated).await,
            Err(Error::OpenedType { .. })
        ),
        "truncated"
    );

    let flipped = tamper(wire.clone(), &|sv| {
        let c = sv[1]["c"].as_str().unwrap().to_owned();
        let mut bytes = c.into_bytes();
        bytes[3] = if bytes[3] == b'A' { b'B' } else { b'A' };
        sv[1]["c"] = Value::String(String::from_utf8(bytes).unwrap());
    });
    assert!(
        matches!(open(&cipher, flipped).await, Err(Error::Aead)),
        "a changed byte"
    );

    let wrong_context = cipher
        .decrypt_as::<Value, JsonDocument>(doc, AeadContext::from(nonempty!("users").with("bio")))
        .await;
    assert!(matches!(wrong_context, Err(Error::Aead)), "another column");

    // A node lifted out of its document fails under another ordinal.
    let sealed = seal(&cipher, &value).await;
    let mut lifted = serde_json::to_value(sealed.node(1).unwrap()).unwrap();
    lifted["j"] = json!(2);
    let lifted: JsonNode = serde_json::from_value(lifted).unwrap();
    assert!(matches!(
        cipher
            .decrypt_as::<Value, JsonExtracted>(extracted(&cipher, "$.a", lifted).await, aead())
            .await,
        Err(Error::Aead)
    ));
}

// =============================================================================
// Queries
// =============================================================================

type JsonPlan = stack_encrypt::plan::ValuePlan<Value, stack_encrypt::plan::Typed<JsonDocument>>;

fn plan() -> JsonPlan {
    Plan::value::<Value>()
        .context("users/profile")
        .encrypt_into::<JsonDocument>()
        .build()
        .unwrap()
}

type OrderedPlan =
    stack_encrypt::plan::ValuePlan<Value, stack_encrypt::plan::Laid<Json, JsonDocument>>;

/// The plan laid out by the JSON index with `$.hello`, `$.number` and
/// `$.flag` ordered.
fn ordered_plan() -> OrderedPlan {
    Plan::value::<Value>()
        .context("users/profile")
        .encrypt_with_layout(Json::new(ordering(&["$.hello", "$.number", "$.flag"])))
        .build()
        .unwrap()
}

/// PostgreSQL's `jsonb @>`, from its documented rules: an object contains
/// another when it has every key with a containing value; an array
/// contains another when every needle element is contained by some stored
/// element; a top-level array contains a scalar that is one of its
/// elements; scalars contain equal scalars, numbers by value.
fn pg_contains(stored: &Value, needle: &Value, top: bool) -> bool {
    match (stored, needle) {
        (Value::Object(a), Value::Object(b)) => b
            .iter()
            .all(|(k, vb)| a.get(k).is_some_and(|va| pg_contains(va, vb, false))),
        (Value::Array(a), Value::Array(b)) => b
            .iter()
            .all(|vb| a.iter().any(|va| pg_contains(va, vb, false))),
        (Value::Array(a), scalar) if top && !scalar.is_object() && !scalar.is_array() => {
            a.iter().any(|va| pg_contains(va, scalar, false))
        }
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        (Value::Object(_) | Value::Array(_), _) | (_, Value::Object(_) | Value::Array(_)) => false,
        (a, b) => a == b,
    }
}

/// The design's two corpora: `jsonb-semantics.sql` and
/// `containment-oracle.sql`, as `(stored, needle)` pairs.
fn corpus() -> Vec<(Value, Value)> {
    [
        (r#"["a"]"#, r#""a""#),
        (r#""a""#, r#"["a"]"#),
        (r#"{"a":[1]}"#, r#"{"a":1}"#),
        (r#"{"a":1}"#, r#"{"a":[1]}"#),
        (r#"[1,[2]]"#, r#"[2]"#),
        (r#"[1,[2]]"#, r#"[[2]]"#),
        (r#"{"a":{"b":1}}"#, r#"{"a":{}}"#),
        (r#"{"a":{}}"#, r#"{"a":{"b":1}}"#),
        (r#"{"a":[1,2]}"#, r#"{"a":[]}"#),
        (r#"{"a":1}"#, r#"{}"#),
        (r#"[1]"#, r#"{}"#),
        (r#"[1]"#, r#"[]"#),
        (r#"[1,2]"#, r#"[1,1,1]"#),
        (
            r#"{"a":[{"x":1,"y":5},{"x":7,"y":2}]}"#,
            r#"{"a":[{"x":1,"y":2}]}"#,
        ),
        (r#"{"a":[{"x":1,"y":2,"z":3}]}"#, r#"{"a":[{"x":1,"y":2}]}"#),
        (r#"{"a":[{"x":1}]}"#, r#"{"a":[{"x":1},{"x":1}]}"#),
        (
            r#"{"a":[{"b":[{"x":1},{"y":2}]}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
        ),
        (
            r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
        ),
        (r#"{"a":[["x"]]}"#, r#"{"a":["x"]}"#),
        (r#""a""#, r#""a""#),
        (r#"2"#, r#"2.0"#),
        (r#"{"a":null}"#, r#"{"a":null}"#),
        (r#"[["a"]]"#, r#""a""#),
        (
            r#"{"a":[{"b":[{"x":1,"y":2}],"c":3},{"b":[{"x":1,"y":9}],"c":4}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}],"c":4}]}"#,
        ),
        (
            r#"{"a":[{"b":[{"x":1,"y":2}],"c":3},{"b":[{"x":1,"y":9}],"c":4}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}],"c":3}]}"#,
        ),
        (
            r#"{"a":[{"b":{"c":1,"d":2}},{"b":{"c":3,"d":2}}]}"#,
            r#"{"a":[{"b":{"c":1,"d":2}}]}"#,
        ),
        (
            r#"{"a":[{"b":{"c":1,"d":5}},{"b":{"c":3,"d":2}}]}"#,
            r#"{"a":[{"b":{"c":1,"d":2}}]}"#,
        ),
        (r#"{"a":[[1,2],[3,4]]}"#, r#"{"a":[[1,4]]}"#),
        (r#"{"a":[[1,2],[3,4]]}"#, r#"{"a":[[1,2]]}"#),
        (r#"{"a":[[1,2],[3,4]]}"#, r#"{"a":[[1],[4]]}"#),
        (r#"{"a":"2"}"#, r#"{"a":2}"#),
        (r#"{"a":2}"#, r#"{"a":2.0}"#),
        (r#"{"a":[{"x":1}]}"#, r#"{"a":[{}]}"#),
        (r#"{"a":[1]}"#, r#"{"a":[{}]}"#),
        (
            r#"{"a":[{"t":[{"u":1,"v":2}]},{"t":[{"u":1},{"v":2}]}]}"#,
            r#"{"a":[{"t":[{"u":1,"v":2}]}]}"#,
        ),
        (
            r#"{"a":[{"t":[{"u":1},{"v":2}]}]}"#,
            r#"{"a":[{"t":[{"u":1,"v":2}]}]}"#,
        ),
        (r#"{"a":[{}]}"#, r#"{"a":[{}]}"#),
        (r#"{"a":[[]]}"#, r#"{"a":[[]]}"#),
        (r#"{"a":[[]]}"#, r#"{"a":[{}]}"#),
        (r#"[{"a":1},{"b":2}]"#, r#"[{"a":1,"b":2}]"#),
        (r#"[{"a":1,"b":2}]"#, r#"[{"a":1},{"b":2}]"#),
        (r#"{"a":[true,false,null]}"#, r#"{"a":[null,true]}"#),
        (r#"{"a":[true]}"#, r#"{"a":[false]}"#),
        (r#"{"a":[{"x":[1,2]},{"x":[3]}]}"#, r#"{"a":[{"x":[2,3]}]}"#),
        (r#"{"a":[{"x":[1,2]},{"x":[3]}]}"#, r#"{"a":[{"x":[1,2]}]}"#),
    ]
    .iter()
    .map(|(a, b)| {
        (
            serde_json::from_str(a).unwrap(),
            serde_json::from_str(b).unwrap(),
        )
    })
    .collect()
}

/// The pinned answers of `jsonb-semantics.sql`, so the model above is held
/// to PostgreSQL and not only to itself.
#[test]
fn the_containment_model_gives_postgresqls_answers() {
    let expect = [
        (r#"["a"]"#, r#""a""#, true),
        (r#""a""#, r#"["a"]"#, false),
        (r#"{"a":[1]}"#, r#"{"a":1}"#, false),
        (r#"{"a":1}"#, r#"{"a":[1]}"#, false),
        (r#"[1,[2]]"#, r#"[2]"#, false),
        (r#"[1,[2]]"#, r#"[[2]]"#, true),
        (r#"{"a":{"b":1}}"#, r#"{"a":{}}"#, true),
        (r#"{"a":{}}"#, r#"{"a":{"b":1}}"#, false),
        (r#"{"a":[1,2]}"#, r#"{"a":[]}"#, true),
        (r#"{"a":1}"#, r#"{}"#, true),
        (r#"[1]"#, r#"{}"#, false),
        (r#"[1]"#, r#"[]"#, true),
        (r#"[1,2]"#, r#"[1,1,1]"#, true),
        (
            r#"{"a":[{"x":1,"y":5},{"x":7,"y":2}]}"#,
            r#"{"a":[{"x":1,"y":2}]}"#,
            false,
        ),
        (
            r#"{"a":[{"x":1,"y":2,"z":3}]}"#,
            r#"{"a":[{"x":1,"y":2}]}"#,
            true,
        ),
        (r#"{"a":[{"x":1}]}"#, r#"{"a":[{"x":1},{"x":1}]}"#, true),
        (
            r#"{"a":[{"b":[{"x":1},{"y":2}]}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
            false,
        ),
        (
            r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
            r#"{"a":[{"b":[{"x":1,"y":2}]}]}"#,
            true,
        ),
        (r#"{"a":[["x"]]}"#, r#"{"a":["x"]}"#, false),
        (r#""a""#, r#""a""#, true),
        (r#"2"#, r#"2.0"#, true),
        (r#"{"a":null}"#, r#"{"a":null}"#, true),
        (r#"[["a"]]"#, r#""a""#, false),
    ];
    for (stored, needle, answer) in expect {
        let (a, b): (Value, Value) = (
            serde_json::from_str(stored).unwrap(),
            serde_json::from_str(needle).unwrap(),
        );
        assert_eq!(pg_contains(&a, &b, true), answer, "{stored} @> {needle}");
    }
}

/// A small deterministic generator of documents over a few keys and
/// values, so needles drawn from it overlap stored documents often.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn value(&mut self, depth: u32) -> Value {
        match self.below(if depth == 0 { 4 } else { 6 }) {
            0 => json!(self.below(3)),
            1 => json!(["x", "y", "z"][self.below(3) as usize]),
            2 => json!(self.below(2) == 0),
            3 => Value::Null,
            4 => Value::Array((0..self.below(4)).map(|_| self.value(depth - 1)).collect()),
            _ => {
                let mut map = Map::new();
                for _ in 0..self.below(4) {
                    let key = ["a", "b", "c"][self.below(3) as usize].to_owned();
                    let _ = map.insert(key, self.value(depth - 1));
                }
                Value::Object(map)
            }
        }
    }
}

#[tokio::test]
async fn containment_over_the_projection_is_postgresqls_containment() {
    let cipher = stack_cipher().await;
    let plan = plan();
    let mut cases = corpus();
    let mut rng = Lcg(42);
    for _ in 0..150 {
        let stored = rng.value(3);
        let needle = rng.value(2);
        cases.push((stored.clone(), needle));
        // A needle taken from the stored document itself is always contained.
        cases.push((stored.clone(), stored));
    }
    for (stored, needle) in cases {
        let doc = cipher.encrypt(&stored).using(&plan).await.unwrap();
        let projection = doc.projection();
        let query: JsonQuery = cipher.query(op::Contains, &needle).on(&plan).await.unwrap();
        assert_eq!(
            query.matches(projection),
            pg_contains(&stored, &needle, true),
            "{stored} @> {needle}"
        );
        // `<@` compares the same two projections the other way round. The
        // one case it cannot answer is a stored root scalar inside a needle
        // root array: a stored document carries no alternative pair, so the
        // SQL answers false where `jsonb` answers true, as the design's
        // leakage table records for v3's `@>`.
        let reverse: JsonQuery = cipher
            .query(op::ContainedBy, &needle)
            .on(&plan)
            .await
            .unwrap();
        let scalar_in_array = !stored.is_object() && !stored.is_array() && needle.is_array();
        assert_eq!(
            reverse.projection().contains(projection),
            pg_contains(&needle, &stored, true) && !scalar_in_array,
            "{stored} <@ {needle}"
        );
    }
}

#[tokio::test]
async fn a_query_term_serializes_as_the_needle_operand_and_derives_no_key() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let plan = plan();
    let query = cipher
        .query(op::Contains, &json!({"a": [{"x": 1}]}))
        .on(&plan)
        .await
        .unwrap();
    let wire = serde_json::to_value(&query).unwrap();
    assert_eq!(
        wire["sv"].as_array().unwrap().len(),
        2,
        "$ and $.a sit outside the element"
    );
    assert_eq!(wire["el"].as_array().unwrap().len(), 1);
    assert_eq!(
        wire["el"][0]["sv"].as_array().unwrap().len(),
        2,
        "the element and its x"
    );
    assert!(wire.get("alt").is_none());
    assert_eq!(
        generates.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "a query mints no key"
    );

    let scalar = cipher
        .query(op::Contains, &json!("a"))
        .on(&plan)
        .await
        .unwrap();
    let wire = serde_json::to_value(&scalar).unwrap();
    assert!(
        wire.get("alt").is_some(),
        "a root scalar carries its root-array alternative"
    );
}

#[tokio::test]
async fn an_accessor_asks_at_a_path() {
    let cipher = stack_cipher().await;
    let plan = plan();
    let doc = cipher.encrypt(&fixture()).using(&plan).await.unwrap();
    let projection = doc.projection();

    let hit: JsonQuery = cipher
        .query(op::AtPath(op::Eq), &("$.nested.list[*].x", 2))
        .on(&plan)
        .await
        .unwrap();
    assert!(hit.matches(projection));
    let miss: JsonQuery = cipher
        .query(op::AtPath(op::Eq), &("$.nested.list[*].x", 3))
        .on(&plan)
        .await
        .unwrap();
    assert!(!miss.matches(projection));
    let deep: JsonQuery = cipher
        .query(op::AtPath(op::Eq), &("$.nested.deep", "constant"))
        .on(&plan)
        .await
        .unwrap();
    assert!(deep.matches(projection));
    let wrong_kind: JsonQuery = cipher
        .query(op::AtPath(op::Eq), &("$.number", "1"))
        .on(&plan)
        .await
        .unwrap();
    assert!(
        !wrong_kind.matches(projection),
        "a string is not the number"
    );

    // An ordering at a path: the path's selector and a leaf term that
    // orders as the stored leaf's does, under native byte comparison. The
    // plan declares the paths it orders, and the query runs under them.
    let plan = ordered_plan();
    let doc = cipher.encrypt(&fixture()).using(&plan).await.unwrap();
    let bound = cipher
        .query(op::AtPath(op::Gte), &("$.number", 0))
        .on(&plan)
        .await
        .unwrap();
    assert_eq!(bound.selector().as_bytes(), doc.entries()[9].selector());
    assert!(
        bound.ordering_term() < doc.entries()[9].ordering_term().unwrap(),
        "0 < 1"
    );
    let above = cipher
        .query(op::AtPath(op::Lt), &("$.number", 5))
        .on(&plan)
        .await
        .unwrap();
    assert!(
        above.ordering_term() > doc.entries()[9].ordering_term().unwrap(),
        "5 > 1"
    );
    let text = cipher
        .query(op::AtPath(op::Gt), &("$.hello", "world-0"))
        .on(&plan)
        .await
        .unwrap();
    assert!(text.ordering_term() < doc.entries()[1].ordering_term().unwrap());
    let range = cipher
        .query(op::AtPath(op::Between), &("$.number", (0, 5)))
        .on(&plan)
        .await
        .unwrap();
    assert!(range.lo().ordering_term() < range.hi().ordering_term());
    assert_eq!(
        range.lo().selector().as_bytes(),
        doc.entries()[9].selector()
    );
    let wire = serde_json::to_value(range.lo()).unwrap();
    assert_eq!(
        wire.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["op", "s"]
    );

    // Refusals, before any term is derived.
    let bad_path = cipher
        .query(op::AtPath(op::Eq), &("address.city", "Sydney"))
        .on(&plan)
        .await;
    assert!(matches!(bad_path, Err(Error::Term(TermError::JsonPath(_)))));
    let unordered = cipher
        .query(op::AtPath(op::Gte), &("$.flag", true))
        .on(&plan)
        .await;
    assert!(matches!(
        unordered,
        Err(Error::Term(TermError::JsonLeafNotOrdered))
    ));
    // A path the plan does not order is refused: no stored leaf there
    // carries a term, so the comparison would match no row. Under the
    // default plan that is every path.
    let not_ordered = cipher
        .query(op::AtPath(op::Lt), &("$.nested.deep", "z"))
        .on(&plan)
        .await;
    assert!(
        matches!(not_ordered, Err(Error::Term(TermError::JsonPathNotOrdered))),
        "{not_ordered:?}"
    );
    let default_plan = self::plan();
    let not_ordered = cipher
        .query(op::AtPath(op::Between), &("$.number", (0, 5)))
        .on(&default_plan)
        .await;
    assert!(
        matches!(not_ordered, Err(Error::Term(TermError::JsonPathNotOrdered))),
        "{not_ordered:?}"
    );
    // An ordering at a wildcard path is covered by the wildcard. One at a
    // position is refused whatever the plan orders: `->` reads a position
    // as the wildcard and would compare the first element, not the one
    // named.
    let by_element = Plan::value::<Value>()
        .context("users/profile")
        .encrypt_with_layout(Json::new(ordering(&["$.nested.list[*].x"])))
        .build()
        .unwrap();
    assert!(cipher
        .query(op::AtPath(op::Gt), &("$.nested.list[*].x", 0))
        .on(&by_element)
        .await
        .is_ok());
    for path in ["$.nested.list[1].x", "$.nested.list[0].x"] {
        let refused = cipher
            .query(op::AtPath(op::Gt), &(path, 0))
            .on(&by_element)
            .await;
        assert!(
            matches!(refused, Err(Error::Term(TermError::JsonOrderingAtPosition))),
            "{path}: {refused:?}"
        );
        let refused = cipher
            .query(op::AtPath(op::Between), &(path, (0, 5)))
            .on(&by_element)
            .await;
        assert!(
            matches!(refused, Err(Error::Term(TermError::JsonOrderingAtPosition))),
            "{path}: {refused:?}"
        );
    }
    // Equality at a path compares one value: an object or an array would be
    // containment, which `op::Contains` asks for.
    for container in [json!({"deep": "constant"}), json!([]), json!([{"x": 1}])] {
        let refused = cipher
            .query(op::AtPath(op::Eq), &("$.nested", container.clone()))
            .on(&plan)
            .await;
        assert!(
            matches!(refused, Err(Error::Term(TermError::JsonValueNotScalar))),
            "{container}"
        );
    }
}

/// A plan laid out by the index opens what it wrote, one document or a
/// batch, and reports its layout.
#[tokio::test]
async fn a_laid_out_plan_opens_what_it_wrote() {
    let cipher = stack_cipher().await;
    let plan = ordered_plan();
    let options = ordering(&["$.hello", "$.number", "$.flag"]);
    assert_eq!(plan.layout().options(), &options);
    assert_eq!(plan.specs(), [IndexSpec::Json(options.clone())]);
    assert_eq!(
        stack_encrypt::target::Layout::<Value>::specs(&Json::new(options.clone())),
        [IndexSpec::Json(options)]
    );
    assert!(
        format!("{plan:?}").contains("Laid<stack_encrypt::json::JsonDocument>(Json"),
        "{plan:?}"
    );
    let doc = cipher.encrypt(&fixture()).using(&plan).await.unwrap();
    let back: Value = cipher.open(doc.clone()).using(&plan).await.unwrap();
    assert_eq!(back, fixture());
    let docs: Vec<Value> = cipher
        .open(vec![doc.clone(), doc.clone()])
        .using(&plan)
        .await
        .unwrap();
    assert_eq!(docs, [fixture(), fixture()]);
    // The plan was built with its context, so an open that names one is
    // refused, one document or a batch, before any key is requested.
    let clash = cipher
        .open(doc.clone())
        .context("users/other")
        .using(&plan)
        .await;
    assert!(
        matches!(clash, Err(Error::Plan(PlanError::TwoContextSources { .. }))),
        "{clash:?}"
    );
    let clash = cipher
        .open(vec![doc.clone()])
        .context("users/other")
        .using(&plan)
        .await;
    assert!(
        matches!(clash, Err(Error::Plan(PlanError::TwoContextSources { .. }))),
        "{clash:?}"
    );
    // The index named on the query says only which: the plan's own, with
    // its options, answers.
    let through_default = cipher
        .query(op::AtPath(op::Gte), &("$.number", 0))
        .via(Json)
        .on(&plan)
        .await
        .unwrap();
    let chosen = cipher
        .query(op::AtPath(op::Gte), &("$.number", 0))
        .on(&plan)
        .await
        .unwrap();
    assert_eq!(through_default.selector(), chosen.selector());
}

/// At the root, equality is of the root value: `("$", 1)` matches a stored
/// `1` and not a stored `[1]`, which containment of the scalar `1` would.
#[tokio::test]
async fn equality_at_the_root_is_not_containment() {
    let cipher = stack_cipher().await;
    let plan = plan();
    let at_root: JsonQuery = cipher
        .query(op::AtPath(op::Eq), &("$", 1))
        .on(&plan)
        .await
        .unwrap();
    let contains: JsonQuery = cipher
        .query(op::Contains, &json!(1))
        .on(&plan)
        .await
        .unwrap();
    let scalar = cipher.encrypt(&json!(1)).using(&plan).await.unwrap();
    let array = cipher.encrypt(&json!([1])).using(&plan).await.unwrap();
    assert!(at_root.matches(scalar.projection()));
    assert!(!at_root.matches(array.projection()));
    assert!(contains.matches(array.projection()), "jsonb: [1] @> 1");
    assert!(serde_json::to_value(&at_root).unwrap().get("alt").is_none());
}

#[tokio::test]
async fn a_query_under_other_options_is_refused_by_the_plan() {
    let cipher = stack_cipher().await;
    let plan = plan();
    let refused = cipher
        .query(op::Contains, &json!({}))
        .via(Json::new(open_root()))
        .on(&plan)
        .await;
    assert!(
        matches!(refused, Err(Error::Plan(PlanError::IndexOptions { .. }))),
        "{refused:?}"
    );
    assert_eq!(
        <JsonDocument as stack_encrypt::EncryptFrom<Value>>::indexes(),
        [IndexSpec::Json(JsonOptions::default())]
    );
    assert_eq!(Json, Json::default(), "the value is the default index");
}

#[tokio::test]
async fn opening_through_the_plan_is_the_typed_open() {
    let cipher = stack_cipher().await;
    let plan = plan();
    let doc = cipher.encrypt(&fixture()).using(&plan).await.unwrap();
    let back: Value = cipher.open(doc).using(&plan).await.unwrap();
    assert_eq!(back, fixture());
}

#[cfg(feature = "dynamic")]
#[test]
fn the_json_index_has_a_wire_form() {
    use stack_encrypt::dynamic::{not_admitted, Reason, ValueKind};
    assert_eq!(
        IndexSpec::parse("json"),
        Some(IndexSpec::Json(JsonOptions::default()))
    );
    assert_eq!(IndexSpec::Json(JsonOptions::default()).key(), "json");
    assert_eq!(
        serde_json::to_value(IndexSpec::Json(JsonOptions::default())).unwrap(),
        json!("json")
    );
    assert_eq!(
        serde_json::to_value(IndexSpec::Json(open_root())).unwrap(),
        json!({"json": {"sealed_root": false, "ordered": []}}),
        "every option is written when any is not the default"
    );
    let frame =
        vitaminc_aead_frame::serde::to_vec(&json!({"json": {"sealed_root": false}})).unwrap();
    assert_eq!(
        IndexSpec::from_frame(&frame).unwrap(),
        IndexSpec::Json(open_root())
    );
    let frame = vitaminc_aead_frame::serde::to_vec(&json!({"json": {"nope": true}})).unwrap();
    assert!(IndexSpec::from_frame(&frame).is_err());
    // The ordered paths ride in `ordered`, written in their canonical
    // order and read back parsed; a text that is not a path refuses the
    // index.
    let ordered = IndexSpec::Json(ordering(&["$.orders[*].total", "$.age", "$.age"]));
    assert_eq!(
        serde_json::to_value(&ordered).unwrap(),
        json!({"json": {"sealed_root": true, "ordered": ["$.age", "$.orders[*].total"]}})
    );
    let frame = vitaminc_aead_frame::serde::to_vec(
        &json!({"json": {"ordered": ["$.age", "$.orders[*].total"]}}),
    )
    .unwrap();
    assert_eq!(IndexSpec::from_frame(&frame).unwrap(), ordered);
    let frame = vitaminc_aead_frame::serde::to_vec(&json!({"json": {"ordered": ["age"]}})).unwrap();
    assert!(IndexSpec::from_frame(&frame).is_err());
    // A position in an ordered path refuses the index too: no ordering can
    // reach the leaf it names.
    let frame =
        vitaminc_aead_frame::serde::to_vec(&json!({"json": {"ordered": ["$.scores[2]"]}})).unwrap();
    assert!(IndexSpec::from_frame(&frame).is_err());
    assert_eq!(
        not_admitted(ValueKind::Object, &IndexSpec::Json(JsonOptions::default())),
        Some(Reason::JsonIndexPending)
    );
}

// =============================================================================
// What the suite pins beyond the round trips
// =============================================================================

/// No token is stored: every tag in the document is a self tag or a
/// parent tag, salted by the document, and no tag, nor a selector, is a
/// token or a prefix of one.
#[tokio::test]
async fn no_stored_tag_is_a_token() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let nested = subtree_key(&cipher, "$.nested", JsonOptions::default())
        .await
        .unwrap();
    let mut tokens = nested.token_bytes();
    let mut frontier = nested.token_bytes();
    while let Some(token) = frontier.pop() {
        assert!(
            tokens.len() <= doc.entries().len(),
            "the chain is a tree: no token is reached twice"
        );
        for (_, _, child) in doc.children(&token) {
            let child = child.expect("every child of a sealed node takes a rule");
            tokens.push(child);
            frontier.push(child);
        }
    }
    assert_eq!(tokens.len(), 7, "nested and its six descendants");
    for entry in doc.entries() {
        for tag in std::iter::once(entry.self_tag()).chain(entry.parent_tag()) {
            assert!(
                !tokens.iter().any(|t| t.starts_with(tag)),
                "a stored tag is not a prefix of a token"
            );
        }
        assert!(!tokens.contains(entry.selector()), "nor is a selector");
    }
    assert_eq!(nested.tokens(), [base64(&nested.token_bytes()[0])]);
}

/// A position names an array element and nothing else. A column's rows
/// need not agree on a node's kind, so a token derived for `$.a[0]` must
/// not find a member of a row whose `$.a` is an object, the member named
/// `"0"` included: `jsonb` has no node at `{a,0}` there under a strict
/// path, and neither does the index. A member's token and an element's are
/// different hashes, so no entry there carries the element's self tag.
#[tokio::test]
async fn a_position_reaches_no_object_member() {
    let cipher = stack_cipher().await;
    for path in ["$.a[0]", "$.h.a[0]"] {
        let first = subtree_key(&cipher, path, JsonOptions::default())
            .await
            .unwrap();
        let array = seal(&cipher, &json!({"a": [{"x": 2}], "h": {"a": [{"x": 2}]}})).await;
        let found: Vec<usize> = array
            .subtree(&first.token_bytes())
            .iter()
            .map(|(j, _, _)| *j)
            .collect();
        let at = array
            .entries()
            .iter()
            .position(|e| e.self_tag() == array.entries()[found[0]].self_tag())
            .unwrap();
        assert_eq!(found, [at, at + 1], "{path}: the element and its x");
        for object in [
            json!({"a": {"k": {"x": 1}}, "h": {"a": {"k": {"x": 1}}}}),
            json!({"a": {"k": [1, 2]}, "h": {"a": {"k": [1, 2]}}}),
            json!({"a": {"0": {"x": 1}}, "h": {"a": {"0": {"x": 1}}}}),
        ] {
            let doc = seal(&cipher, &object).await;
            assert!(
                doc.subtree(&first.token_bytes()).is_empty(),
                "{path} in {object}: an object member is not an element"
            );
        }
    }
}

/// Padded standard base64, as the SQL reads and writes it.
fn base64(bytes: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(bytes)
}

/// A wildcard read's rows hold each element it reaches below the bound,
/// each at depth 0 with everything beneath it. As a list they open to one
/// value per element; as one value they refuse, unless exactly one element
/// is there. A probe that finds an element fails the read with the bound.
#[tokio::test]
async fn wildcard_rows_open_to_one_value_per_element_or_fail_with_the_bound() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let xs = subtree_key(&cipher, "$.nested.list[*].x", JsonOptions::default())
        .await
        .unwrap();
    assert_eq!(xs.tokens().len(), 65, "64 positions and the probe");
    assert_eq!(xs.probes(), [64]);
    let rows = read_rows(&doc, &xs);
    assert_eq!(rows.len(), 2, "both x");
    let values = cipher
        .decrypt_as::<Vec<Value>, JsonSubtree>(xs.open(rows.clone()), aead())
        .await
        .unwrap();
    assert_eq!(values, vec![json!(1), json!(2)]);
    match cipher
        .decrypt_as::<Value, JsonSubtree>(xs.open(rows), aead())
        .await
    {
        Err(Error::OpenedType { expected }) => {
            assert_eq!(expected, "one node at the walked path")
        }
        other => panic!("{other:?}"),
    }
    // At a bound of 1, the second element is the probe's: the read fails
    // rather than return the first x alone, as a list and as one value.
    let one = cipher
        .default_keyset()
        .json_subtree_key_with_bound(
            &JsonPath::parse("$.nested.list[*].x").unwrap(),
            &JsonOptions::default(),
            1,
            nonempty!("users").with("profile"),
        )
        .await
        .unwrap();
    assert_eq!(one.tokens().len(), 2, "one position and the probe");
    let rows = read_rows(&doc, &one);
    assert_eq!(
        rows.len(),
        3,
        "the first x, and the second element with its x"
    );
    for opened in [
        cipher
            .decrypt_as::<Vec<Value>, JsonSubtree>(one.open(rows.clone()), aead())
            .await
            .map(|_| ()),
        cipher
            .decrypt_as::<Option<Value>, JsonSubtree>(one.open(rows.clone()), aead())
            .await
            .map(|_| ()),
    ] {
        assert!(
            matches!(opened, Err(Error::JsonWildcardTruncated { bound: 1 })),
            "{opened:?}"
        );
    }
    // At a bound of 2, exactly as long: no probe finds anything.
    let two = cipher
        .default_keyset()
        .json_subtree_key_with_bound(
            &JsonPath::parse("$.nested.list[*].x").unwrap(),
            &JsonOptions::default(),
            2,
            nonempty!("users").with("profile"),
        )
        .await
        .unwrap();
    let values = cipher
        .decrypt_as::<Vec<Value>, JsonSubtree>(two.open(read_rows(&doc, &two)), aead())
        .await
        .unwrap();
    assert_eq!(
        values,
        vec![json!(1), json!(2)],
        "an array as long as the bound"
    );
}

/// A document, an extracted node and a walked subtree are each the one
/// recoverable field of a derived record: each opens through
/// `DecryptField`, as a record holding one would.
#[tokio::test]
async fn each_stored_form_opens_as_a_record_field() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let node = extracted(&cipher, "$.hello", doc.node(1).unwrap()).await;
    let list = subtree_key(&cipher, "$.nested.list", JsonOptions::default())
        .await
        .unwrap();
    let rows = read_rows(&doc, &list);
    let subtree = list.open(rows.clone());
    assert_eq!(subtree.nodes(), rows.as_slice());
    assert_eq!(
        subtree.nodes().len(),
        5,
        "the list, both elements and both leaves"
    );

    let opening: Option<Decryption<Value, FakeDataKeySource>> = doc.decryption_field(aead());
    let opened = cipher
        .run_decryption(opening.expect("a document opens"))
        .await
        .unwrap();
    assert_eq!(opened, fixture());
    let opening: Option<Decryption<Value, FakeDataKeySource>> = node.decryption_field(aead());
    let opened = cipher
        .run_decryption(opening.expect("a node opens"))
        .await
        .unwrap();
    assert_eq!(opened, json!("world-1"));
    let opening: Option<Decryption<Value, FakeDataKeySource>> = subtree.decryption_field(aead());
    let opened = cipher
        .run_decryption(opening.expect("a subtree opens"))
        .await
        .unwrap();
    assert_eq!(opened, json!([{"x": 1}, {"x": 2}]));
}

/// Past its budget the server returns the sealed root alone, at depth 0,
/// in place of the subtree: the rows open to the whole document and the
/// key's path selects over it. A path that reaches nothing, or a wildcard
/// that reaches two nodes where one value is asked for, is refused; a root
/// at depth 0 under an unsealed document is not the fallback. A fallback
/// with no path cannot be built: the key is the only constructor.
#[tokio::test]
async fn the_sealed_root_a_walk_fell_back_to_opens_at_the_path() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    let fallback = |doc: &JsonDocument| -> JsonNode {
        let mut wire = serde_json::to_value(doc.node(0).unwrap()).unwrap();
        wire["d"] = json!(0);
        serde_json::from_value(wire).unwrap()
    };
    let root = fallback(&doc);
    let rows = keyed(&cipher, "$.nested", vec![root.clone()]).await;
    assert!(rows.is_sealed_root());
    assert_eq!(rows.path().to_string(), "$.nested");

    let nested = cipher
        .decrypt_as::<Value, JsonSubtree>(rows, aead())
        .await
        .unwrap();
    assert_eq!(nested, fixture()["nested"]);
    let xs = cipher
        .decrypt_as::<Vec<Value>, JsonSubtree>(
            keyed(&cipher, "$.nested.list[*].x", vec![root.clone()]).await,
            aead(),
        )
        .await
        .unwrap();
    assert_eq!(xs, vec![json!(1), json!(2)]);
    let none = cipher
        .decrypt_as::<Vec<Value>, JsonSubtree>(
            keyed(&cipher, "$.missing[*]", vec![root.clone()]).await,
            aead(),
        )
        .await
        .unwrap();
    assert!(none.is_empty(), "a path that reaches nothing is no subtree");

    // Each refusal names what it expected: nothing at the path, or one node
    // where a wildcard reached two.
    for (path, expected) in [
        ("$.missing", "a node at the walked path"),
        ("$.nested.list[*].x", "one node at the walked path"),
    ] {
        let refused = cipher
            .decrypt_as::<Value, JsonSubtree>(
                keyed(&cipher, path, vec![root.clone()]).await,
                aead(),
            )
            .await;
        match refused {
            Err(Error::OpenedType { expected: got }) => assert_eq!(got, expected, "{path}"),
            other => panic!("{path}: {other:?}"),
        }
    }

    // The same root at depth 1, or at depth 0 under an unsealed document,
    // is a walk's row and not the fallback, and not a child of the walked
    // node either: its selector is the root's.
    let mut as_walked = serde_json::to_value(doc.node(0).unwrap()).unwrap();
    as_walked["d"] = json!(1);
    let as_walked: JsonNode = serde_json::from_value(as_walked).unwrap();
    let rows = keyed(&cipher, "$.nested", vec![as_walked]).await;
    assert!(!rows.is_sealed_root());
    let refused = cipher.decrypt_as::<Value, JsonSubtree>(rows, aead()).await;
    assert!(
        matches!(refused, Err(Error::JsonWrongEntry { .. })),
        "{refused:?}"
    );
    let open_doc = seal_with(&cipher, &fixture(), &open_root()).await;
    assert!(!keyed(&cipher, "$.nested", vec![fallback(&open_doc)])
        .await
        .is_sealed_root());
    assert!(!keyed(&cipher, "$.nested", vec![]).await.is_sealed_root());
    assert!(!keyed(&cipher, "$.nested", vec![root.clone(), root])
        .await
        .is_sealed_root());
}

/// The rows `json_tree_subtree(doc, key.tokens(), 0)` returns for `key`,
/// read here as the SQL reads them, each with its depth below the node its
/// token named.
fn read_rows(doc: &JsonDocument, key: &JsonSubtreeKey) -> Vec<JsonNode> {
    doc.subtree(&key.token_bytes())
        .iter()
        .map(|(j, _, d)| {
            let mut wire = serde_json::to_value(doc.node(*j).unwrap()).unwrap();
            wire["d"] = json!(d);
            serde_json::from_value(wire).unwrap()
        })
        .collect()
}

/// The sealed root a read fell back to opens to exactly what the walked
/// rows open to, as a list, as an optional value and as one value, so a
/// caller's result does not change shape when a document grows past the
/// budget: the key's concrete paths and probes are evaluated over the
/// whole document.
#[tokio::test]
async fn the_key_built_fallback_opens_to_what_the_walk_opens_to() {
    let document = json!({
        "list": [{"x": 1}, {"x": 2}],
        "obj": {"a": "constant", "b": [1, 2], "c": {"d": [true, null]}, "e": {}, "f": []},
        "hello": "world"
    });
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &document).await;
    let mut root = serde_json::to_value(doc.node(0).unwrap()).unwrap();
    root["d"] = json!(0);
    let root: JsonNode = serde_json::from_value(root).unwrap();
    for text in [
        "$",
        "$.list",
        "$.obj",
        "$.hello",
        "$.list[1]",
        "$.obj.b",
        "$.obj.c.d",
        "$.obj.b[0]",
        "$.list[*].x",
        "$.list[1].x",
        "$.obj.c",
        "$.obj.e",
        "$.obj.f",
        "$.missing",
        "$.obj.c.d[*]",
        "$.list[*]",
        "$[*]",
        "$.obj.missing[*]",
    ] {
        let key = subtree_key(&cipher, text, JsonOptions::default())
            .await
            .unwrap();
        let walked = read_rows(&doc, &key);
        let fallen_back = key.open(vec![root.clone()]);
        assert!(fallen_back.is_sealed_root(), "{text}");
        let as_walked = cipher
            .decrypt_as::<Vec<Value>, JsonSubtree>(key.open(walked.clone()), aead())
            .await
            .unwrap();
        let as_fallen = cipher
            .decrypt_as::<Vec<Value>, JsonSubtree>(fallen_back.clone(), aead())
            .await
            .unwrap();
        let expected: Vec<Value> = key.path().select(&document).into_iter().cloned().collect();
        assert_eq!(as_walked, expected, "{text}, walked, as a list");
        assert_eq!(as_fallen, expected, "{text}, fallen back, as a list");
        let one_walked = cipher
            .decrypt_as::<Option<Value>, JsonSubtree>(key.open(walked), aead())
            .await;
        let one_fallen = cipher
            .decrypt_as::<Option<Value>, JsonSubtree>(fallen_back, aead())
            .await;
        match (one_walked, one_fallen) {
            (Ok(a), Ok(b)) => assert_eq!(a, b, "{text}, as one value"),
            (Err(Error::OpenedType { .. }), Err(Error::OpenedType { .. })) => {
                assert!(expected.len() > 1, "{text}: refused only for several nodes")
            }
            (a, b) => panic!("{text}: the walk opened to {a:?}, the fallback to {b:?}"),
        }
    }
}

/// The walk reports each row's depth below where it started, in `d`; an
/// extracted node carries none.
#[tokio::test]
async fn a_walked_row_carries_its_depth() {
    let cipher = stack_cipher().await;
    let doc = seal(&cipher, &fixture()).await;
    assert_eq!(doc.node(6).unwrap().depth(), None);
    let mut wire = serde_json::to_value(doc.node(6).unwrap()).unwrap();
    assert!(wire.get("d").is_none());
    wire["d"] = json!(3);
    let walked: JsonNode = serde_json::from_value(wire).unwrap();
    assert_eq!(walked.depth(), Some(3));
    assert_eq!(serde_json::to_value(&walked).unwrap()["d"], json!(3));
}

/// A document sealed without the sealed root keeps the root as an ordinary
/// node, and opens from its entries.
#[tokio::test]
async fn a_document_without_the_sealed_root_opens_from_its_entries() {
    let cipher = stack_cipher().await;
    for value in [fixture(), json!({"": {}}), json!([[], {}, ""]), json!("a")] {
        let doc = seal_with(&cipher, &value, &open_root()).await;
        assert!(!doc.header().sealed_root());
        assert_eq!(doc.entries().len(), nodes(&value));
        assert_eq!(open(&cipher, doc).await.unwrap(), value);
    }
}

/// An accessor whose path or bounds the index refuses is refused when the
/// query is awaited, before the keyset it names is loaded.
#[tokio::test]
async fn an_accessor_is_refused_before_its_keyset_loads() {
    let (cipher, loads) = common::loads_counting_cipher().await;
    let plan = ordered_plan();
    let eq = cipher
        .query(op::AtPath(op::Eq), &("address.city", "Sydney"))
        .on(&plan)
        .keyset("tenant")
        .await;
    assert!(
        matches!(eq, Err(Error::Term(TermError::JsonPath(_)))),
        "{eq:?}"
    );
    let between = cipher
        .query(op::AtPath(op::Between), &("address.age", (1, 2)))
        .on(&plan)
        .keyset("tenant")
        .await;
    assert!(
        matches!(between, Err(Error::Term(TermError::JsonPath(_)))),
        "{between:?}"
    );
    let unordered = cipher
        .query(op::AtPath(op::Between), &("$.flag", (false, true)))
        .on(&plan)
        .keyset("tenant")
        .await;
    assert!(
        matches!(unordered, Err(Error::Term(TermError::JsonLeafNotOrdered))),
        "{unordered:?}"
    );
    let not_ordered = cipher
        .query(op::AtPath(op::Lt), &("$.nested.deep", "z"))
        .on(&plan)
        .keyset("tenant")
        .await;
    assert!(
        matches!(not_ordered, Err(Error::Term(TermError::JsonPathNotOrdered))),
        "{not_ordered:?}"
    );
    let at_position = cipher
        .query(op::AtPath(op::Gte), &("$.nested.list[0].x", 1))
        .on(&plan)
        .keyset("tenant")
        .await;
    assert!(
        matches!(
            at_position,
            Err(Error::Term(TermError::JsonOrderingAtPosition))
        ),
        "{at_position:?}"
    );
    // An open that names a context the plan already has is refused the
    // same way, one document or a batch, before the keyset loads.
    let doc = seal(&stack_cipher().await, &fixture()).await;
    let clash = cipher
        .open(doc.clone())
        .context("users/other")
        .using(&plan)
        .keyset("tenant")
        .await;
    assert!(
        matches!(clash, Err(Error::Plan(PlanError::TwoContextSources { .. }))),
        "{clash:?}"
    );
    let clash = cipher
        .open(vec![doc])
        .context("users/other")
        .using(&plan)
        .keyset("tenant")
        .await;
    assert!(
        matches!(clash, Err(Error::Plan(PlanError::TwoContextSources { .. }))),
        "{clash:?}"
    );
    assert_eq!(
        loads.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no keyset was loaded for a refused query or open"
    );
    // The same query with a path the index takes does load it.
    let _ = cipher
        .query(op::AtPath(op::Eq), &("$.address.city", "Sydney"))
        .on(&plan)
        .keyset("tenant")
        .await
        .unwrap();
    assert_eq!(loads.load(std::sync::atomic::Ordering::SeqCst), 1);
}
