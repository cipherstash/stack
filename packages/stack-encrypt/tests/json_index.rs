//! The JSON index end to end, with no database: a document seals into one
//! entry per node under one data key and opens again; the token chain
//! reaches every child from its parent's token and ordinal, and nothing
//! from any other token; a moved, reordered or regrafted entry fails to
//! open; and containment over the element-nested projection agrees with
//! PostgreSQL's `jsonb @>` on the design's corpus and on documents proptest
//! generates, through a Rust model of `jsonb @>` written here from the
//! rules PostgreSQL documents (the live oracle against PostgreSQL itself is
//! `packages/eql/tests/encryption/tests/json_tree.rs`).
//!
//! Each `given_<scenario>` module is one situation, and each test in it is
//! named for what it expects. Shared setup is [`scenario`] and the helpers
//! below it; repeated checks are in [`assertions`]. The generated cases are
//! in [`given_generated_documents`]: a fixed ChaCha seed that
//! `PROPTEST_RNG_SEED` replaces, and a case count `PROPTEST_CASES` replaces.

// `.unwrap()` is how a test says "this cannot fail here".
#![allow(clippy::unwrap_used)]

mod common;

use common::stack_cipher;
use serde_json::{json, Map, Value};
use stack_encrypt::json::{
    JsonDocument, JsonNode, JsonOptions, JsonPath, JsonQuery, JsonSubtree, JsonSubtreeKey, Tag,
};
use stack_encrypt::op;
use stack_encrypt::sem::TermError;
use stack_encrypt::target::{
    AeadContext, CallerContext, DecryptField, Decryption, IndexSpec, Json,
};
use stack_encrypt::{nonempty, Error, Plan, PlanError, StackCipher};
use stack_kms::FakeDataKeySource;

// =============================================================================
// Setup
// =============================================================================

type Cipher = StackCipher<FakeDataKeySource>;

type JsonPlan = stack_encrypt::plan::ValuePlan<Value, stack_encrypt::plan::Typed<JsonDocument>>;

type OrderedPlan =
    stack_encrypt::plan::ValuePlan<Value, stack_encrypt::plan::Laid<Json, JsonDocument>>;

/// What most tests start from: a cipher over the fake key source and the
/// default plan for a JSON column under `users/profile`.
struct Scenario {
    cipher: Cipher,
    plan: JsonPlan,
}

async fn scenario() -> Scenario {
    Scenario {
        cipher: stack_cipher().await,
        plan: plan(),
    }
}

fn context() -> CallerContext {
    CallerContext::from(nonempty!("users").with("profile"))
}

fn aead() -> AeadContext {
    AeadContext::from(nonempty!("users").with("profile"))
}

fn plan() -> JsonPlan {
    Plan::value::<Value>()
        .context("users/profile")
        .encrypt_into::<JsonDocument>()
        .build()
        .unwrap()
}

/// The plan laid out by the JSON index with `$.hello`, `$.number` and
/// `$.flag` ordered.
fn ordered_plan() -> OrderedPlan {
    Plan::value::<Value>()
        .context("users/profile")
        .encrypt_with_layout(Json::new(ordering(&["$.hello", "$.number", "$.flag"])))
        .build()
        .unwrap()
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

/// The design's fixture document. Its entries, by ordinal: `$`, `$.hello`,
/// `$.nested`, `$.nested.deep`, `$.nested.list`, `[0]`, `[0].x`, `[1]`,
/// `[1].x`, `$.number`. The tests pin those ordinals, so the document is
/// fixed rather than generated.
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

/// Seal through the typed target, as `encrypt_as` does.
async fn seal(cipher: &Cipher, value: &Value) -> JsonDocument {
    cipher
        .default_keyset()
        .encrypt_as::<Value, JsonDocument>(value, context())
        .await
        .expect("seals")
}

/// Seal through the JSON document target under `options`.
async fn seal_with(cipher: &Cipher, value: &Value, options: &JsonOptions) -> JsonDocument {
    try_seal(cipher, value, options).await.expect("seals")
}

async fn try_seal(
    cipher: &Cipher,
    value: &Value,
    options: &JsonOptions,
) -> Result<JsonDocument, Error> {
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
}

async fn open(cipher: &Cipher, doc: JsonDocument) -> Result<Value, Error> {
    cipher.decrypt_as::<Value, JsonDocument>(doc, aead()).await
}

async fn subtree_key(
    cipher: &Cipher,
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

/// `rows` as the key derived for `path` opens them: the only way to build
/// a [`JsonSubtree`].
async fn keyed(cipher: &Cipher, path: &str, rows: Vec<JsonNode>) -> JsonSubtree {
    subtree_key(cipher, path, JsonOptions::default())
        .await
        .unwrap()
        .open(rows)
}

/// Padded standard base64, as the SQL reads and writes it.
fn base64(bytes: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(bytes)
}

/// The ordinals the walk from `token` reaches.
fn subtree_ordinals(doc: &JsonDocument, token: &Tag) -> Vec<usize> {
    doc.subtree(token).iter().map(|(j, _, _)| *j).collect()
}

/// The nodes the walk from `token` reaches, as the server returns them.
fn subtree_nodes(doc: &JsonDocument, token: &Tag) -> Vec<JsonNode> {
    doc.subtree(token)
        .iter()
        .map(|(j, _, _)| doc.node(*j).unwrap())
        .collect()
}

/// The token of the child at ordinal `j` under `token`, as the server
/// derives it.
fn child_token(doc: &JsonDocument, token: &Tag, j: usize) -> Tag {
    doc.children(token)
        .into_iter()
        .find(|(ordinal, _, _)| *ordinal == j)
        .map(|(_, _, t)| t)
        .unwrap_or_else(|| panic!("entry {j} is a child of the token's node"))
}

/// Node `j` as a walk returns it, `d` levels below where it started.
fn with_depth(doc: &JsonDocument, j: usize, d: u32) -> JsonNode {
    let mut wire = serde_json::to_value(doc.node(j).unwrap()).unwrap();
    wire["d"] = json!(d);
    serde_json::from_value(wire).unwrap()
}

/// The rows `json_tree_subtree_at(doc, token, gates)` returns for `key`,
/// walked here as the SQL walks them: from the key's token, through each
/// gate (a selector the entry at that depth must carry, or `#n:<selector>`,
/// the child at ordinal `n` carrying it), then everything beneath each node
/// the gates reach, each row with its depth below that node.
fn gated_walk(doc: &JsonDocument, key: &JsonSubtreeKey) -> Vec<JsonNode> {
    let mut frontier = vec![(None, *key.token_bytes())];
    for gate in key.gates() {
        let mut next = Vec::new();
        for (_, token) in &frontier {
            let children = doc.children(token);
            match gate.strip_prefix('#') {
                Some(slot) => {
                    let (n, selector) = slot.split_once(':').unwrap();
                    if let Some((j, entry, t)) = children.get(n.parse::<usize>().unwrap()) {
                        if base64(entry.selector()) == selector {
                            next.push((Some(*j), *t));
                        }
                    }
                }
                None => next.extend(
                    children
                        .iter()
                        .filter(|(_, entry, _)| base64(entry.selector()) == gate)
                        .map(|(j, _, t)| (Some(*j), *t)),
                ),
            }
        }
        frontier = next;
    }
    let mut rows = Vec::new();
    for (reached, token) in frontier {
        let below = u32::from(reached.is_some());
        if let Some(j) = reached {
            rows.push(with_depth(doc, j, 0));
        }
        rows.extend(
            doc.subtree(&token)
                .iter()
                .map(|(j, _, d)| with_depth(doc, *j, d - 1 + below)),
        );
    }
    rows.sort_by_key(JsonNode::ordinal);
    rows
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

/// `<@` compares the same two projections the other way round. The one
/// case it cannot answer is a stored root scalar inside a needle root
/// array: a stored document carries no alternative pair, so the SQL answers
/// false where `jsonb` answers true, as the design's leakage table records
/// for v3's `@>`.
fn scalar_in_array(stored: &Value, needle: &Value) -> bool {
    !stored.is_object() && !stored.is_array() && needle.is_array()
}

// =============================================================================
// Round trips
// =============================================================================

mod given_a_document {
    use super::*;

    /// A document of every shape the index takes.
    fn values() -> Vec<Value> {
        vec![
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
        ]
    }

    #[tokio::test]
    async fn seals_one_entry_per_node_and_opens_again() {
        let Scenario { cipher, .. } = scenario().await;
        for value in values() {
            for options in [JsonOptions::default(), open_root()] {
                let what = format!("{value} under {options:?}");
                let doc = seal_with(&cipher, &value, &options).await;
                assertions::one_entry_per_node(&doc, &value, &what);
                assert_eq!(
                    doc.header().sealed_root(),
                    options.sealed_root,
                    "{what}: the header records whether the root is sealed"
                );
                assertions::opens_to(&cipher, doc, &value, &what).await;
            }
        }
    }
}

mod given_an_open_root {
    use super::*;

    /// A document sealed without the sealed root keeps the root as an
    /// ordinary node, and opens from its entries.
    #[tokio::test]
    async fn keeps_the_root_as_an_entry_and_opens_from_the_entries() {
        let Scenario { cipher, .. } = scenario().await;
        for value in [fixture(), json!({"": {}}), json!([[], {}, ""]), json!("a")] {
            let doc = seal_with(&cipher, &value, &open_root()).await;
            assert!(
                !doc.header().sealed_root(),
                "{value}: the header records the open root"
            );
            assertions::one_entry_per_node(&doc, &value, &value.to_string());
            assertions::opens_to(&cipher, doc, &value, &value.to_string()).await;
        }
    }
}

mod given_the_deepest_document {
    use super::*;

    /// The deepest document the index takes opens again under either root
    /// option, and one level deeper is refused when it is sealed, not when
    /// it is read. A sealed root's plaintext is the document as JSON, which
    /// `serde_json` reads back only to 128 levels of nesting.
    #[tokio::test]
    async fn opens_again_and_one_level_deeper_is_refused_when_sealed() {
        let Scenario { cipher, .. } = scenario().await;
        let arrays = |n: usize| (0..n).fold(json!(1), |inner, _| json!([inner]));
        let objects = |n: usize| (0..n).fold(json!("leaf"), |inner, _| json!({"k": inner}));
        for nested in [arrays, objects] {
            for options in [JsonOptions::default(), open_root()] {
                let deepest = nested(127);
                let doc = seal_with(&cipher, &deepest, &options).await;
                assertions::opens_to(
                    &cipher,
                    doc,
                    &deepest,
                    &format!("127 levels under {options:?}"),
                )
                .await;
                let refused = try_seal(&cipher, &nested(128), &options).await;
                assertions::refused_by_term(
                    &refused,
                    |e| matches!(e, TermError::JsonTooDeep),
                    &format!("128 levels under {options:?} is refused when sealed"),
                );
            }
        }
    }
}

// =============================================================================
// The stored form
// =============================================================================

mod given_the_fixture_document {
    use super::*;

    #[tokio::test]
    async fn stores_the_wire_form_the_sql_domain_checks() {
        let Scenario { cipher, plan } = scenario().await;
        let doc = seal(&cipher, &fixture()).await;
        let wire = serde_json::to_value(&doc).unwrap();
        let keys: Vec<&str> = wire
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["h", "q", "sv"], "the document's wire keys");
        // `q` is the document's own projection, written once: the needle a
        // `Contains` of the whole document derives has the same pairs in the
        // same groups, and nothing else.
        let needle = cipher
            .query(op::Contains, &fixture())
            .on(&plan)
            .await
            .unwrap();
        assert_eq!(
            wire["q"],
            serde_json::to_value(&needle).unwrap(),
            "`q` is the needle a `Contains` of the whole document derives"
        );
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
                    ["s", "c", "p", "op"].contains(&key.as_str()),
                    "entry {j} carries an unknown key {key}"
                );
            }
            for (tag, chars, bytes) in [("s", 24, 16), ("p", 12, 8)] {
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
                "entry {j}'s c is base85 in an alphabet a JSON string carries unescaped: {c:?}"
            );
        }
        let back: JsonDocument = serde_json::from_value(wire).unwrap();
        assert_eq!(back, doc, "the wire form reads back to the document");
    }

    #[tokio::test]
    async fn places_the_chain_fields_where_the_design_says() {
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal(&cipher, &fixture()).await;
        let entries = doc.entries();
        assert_eq!(entries.len(), 10, "one entry per node of the fixture");
        assert!(
            entries[0].parent_tag().is_none(),
            "the root has no parent tag"
        );
        for head in [&entries[1], &entries[2], &entries[9]] {
            assert!(
                head.parent_tag().is_none(),
                "a head has no parent tag under the sealed root"
            );
        }
        for (j, below) in entries[3..9].iter().enumerate() {
            assert!(
                below.parent_tag().is_some(),
                "entry {} below a head carries a parent tag",
                j + 3
            );
        }
        // Every parent tag is distinct: siblings are not linkable at rest.
        let tags: std::collections::HashSet<_> = entries[3..9]
            .iter()
            .map(|e| *e.parent_tag().unwrap())
            .collect();
        assert_eq!(tags.len(), 6, "every parent tag is distinct");
        // The projection groups the two list elements: each is a nested group
        // holding its own pair and its `x`.
        let q = serde_json::to_value(doc.projection()).unwrap();
        assert_eq!(
            q["el"].as_array().unwrap().len(),
            2,
            "one group per list element"
        );
        assert_eq!(
            q["el"][0]["sv"].as_array().unwrap().len(),
            2,
            "an element's group holds its own pair and its x"
        );
        assert_eq!(
            q["sv"].as_array().unwrap().len(),
            6,
            "$, hello, nested, deep, list, number"
        );
        assert!(
            entries.iter().all(|e| e.ordering_term().is_none()),
            "no path is ordered by default, so no entry carries a term"
        );
    }

    /// Equal values at one path share selectors but not ciphertexts; the
    /// value selectors, in the projection, tell equal values from different.
    #[tokio::test]
    async fn gives_equal_values_at_one_path_one_value_selector_and_two_ciphertexts() {
        let Scenario { cipher, .. } = scenario().await;
        let pair = |doc: &JsonDocument, i: usize| -> (String, String) {
            let q = serde_json::to_value(doc.projection()).unwrap();
            (
                q["sv"][i]["s"].as_str().unwrap().to_owned(),
                q["sv"][i]["vs"].as_str().unwrap().to_owned(),
            )
        };
        let same = seal(&cipher, &json!([1, 1])).await;
        let (a, b) = (&same.entries()[1], &same.entries()[2]);
        assert_eq!(a.selector(), b.selector(), "two elements share a path");
        assert_eq!(
            pair(&same, 1),
            pair(&same, 2),
            "equal values at one path share a value selector"
        );
        assert_ne!(
            a.ciphertext(),
            b.ciphertext(),
            "equal values do not share a ciphertext"
        );
        let different = seal(&cipher, &json!([1, 2])).await;
        let (one, two) = (&different.entries()[1], &different.entries()[2]);
        assert_eq!(one.selector(), two.selector(), "one path");
        assert_ne!(
            pair(&different, 1),
            pair(&different, 2),
            "different values at one path have different value selectors"
        );
        assert_eq!(
            pair(&different, 1),
            pair(&same, 1),
            "the value selector names the value at its path, in any document"
        );
    }

    #[tokio::test]
    async fn chains_the_top_level_fields_from_an_open_root() {
        let Scenario { cipher, .. } = scenario().await;
        let open_doc = seal_with(&cipher, &fixture(), &open_root()).await;
        assert!(
            open_doc.entries()[1].parent_tag().is_some(),
            "without the sealed root, the top-level fields chain from the root"
        );
    }

    #[tokio::test]
    async fn derives_the_stored_selector_from_a_path_folding_positions_into_the_wildcard() {
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal(&cipher, &fixture()).await;
        let keyset = cipher.default_keyset();
        let selector = |path: &str| {
            let path = JsonPath::parse(path).unwrap();
            keyset.json_selector(&path, nonempty!("users").with("profile"))
        };
        for (path, j) in [
            ("$.nested.deep", 3),
            ("$.nested.list[*].x", 6),
            ("$.nested.list[1].x", 8),
            ("$", 0),
        ] {
            assert_eq!(
                selector(path).await.unwrap().as_bytes(),
                doc.entries()[j].selector(),
                "{path} derives entry {j}'s stored selector"
            );
        }
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

    /// No token is stored: an entry below a head carries only the parent
    /// tag, and no tag in the document is a token, or a parent's hash of one
    /// without the document's salt.
    #[tokio::test]
    async fn stores_no_token() {
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = subtree_key(&cipher, "$.nested", JsonOptions::default())
            .await
            .unwrap();
        let mut tokens = vec![*nested.token_bytes()];
        let mut frontier = vec![*nested.token_bytes()];
        while let Some(token) = frontier.pop() {
            assert!(
                tokens.len() <= doc.entries().len(),
                "the chain is a tree: no token is reached twice"
            );
            for (_, _, child) in doc.children(&token) {
                tokens.push(child);
                frontier.push(child);
            }
        }
        assert_eq!(tokens.len(), 7, "nested and its six descendants");
        for (j, entry) in doc.entries().iter().enumerate() {
            if let Some(p) = entry.parent_tag() {
                assert!(
                    !tokens.iter().any(|t| t.starts_with(p)),
                    "entry {j}'s parent tag is not a prefix of a token"
                );
            }
            assert!(
                !tokens.contains(entry.selector()),
                "entry {j}'s selector is not a token"
            );
        }
        assert_eq!(
            nested.token(),
            base64(nested.token_bytes()),
            "a token's text form is its padded base64"
        );
    }
}

mod given_ordered_paths {
    use super::*;

    /// Which entries carry an ordering term.
    fn with_term(doc: &JsonDocument) -> Vec<usize> {
        doc.entries()
            .iter()
            .enumerate()
            .filter(|(_, e)| e.ordering_term().is_some())
            .map(|(j, _)| j)
            .collect()
    }

    /// An ordering term sits on a number or string leaf at an ordered path
    /// and nowhere else: a wildcard covers every element.
    #[tokio::test]
    async fn puts_a_term_only_on_a_number_or_string_leaf_at_an_ordered_path() {
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal_with(&cipher, &fixture(), &ordering(&["$.hello", "$.number"])).await;
        assert_eq!(with_term(&doc), [1, 9], "$.hello and $.number");
        let wild = seal_with(&cipher, &fixture(), &ordering(&["$.nested.list[*].x"])).await;
        assert_eq!(with_term(&wild), [6, 8], "a wildcard covers every element");
        // A container, a boolean or a null at an ordered path carries none.
        let kinds = seal_with(
            &cipher,
            &json!({"a": true, "b": null, "c": {"d": 1}, "e": [1, "x"]}),
            &ordering(&["$.a", "$.b", "$.c", "$.e", "$.e[*]"]),
        )
        .await;
        // $, $.a, $.b, $.c, $.c.d, $.e, $.e[0], $.e[1]
        assert_eq!(with_term(&kinds), [6, 7], "only the number and the string");
        let scalar = seal_with(&cipher, &json!(7), &ordering(&["$"])).await;
        assert_eq!(with_term(&scalar), [0], "the root scalar itself, at `$`");
        assertions::opens_to(&cipher, doc, &fixture(), "ordered at $.hello and $.number").await;
        assertions::opens_to(&cipher, wild, &fixture(), "ordered at a wildcard").await;
    }

    /// A position is refused, since `->` reads it as the wildcard and no
    /// ordering could reach the leaf it names; so is a text that is not a
    /// path.
    #[tokio::test]
    async fn refuses_a_position_or_a_text_that_is_not_a_path() {
        let Scenario { cipher, .. } = scenario().await;
        let position = JsonOptions::default().ordering(["$.nested.list[1].x"]);
        assert!(
            matches!(position, Err(TermError::JsonOrderingAtPosition)),
            "a position is refused as an ordered path: {position:?}"
        );
        let not_a_path = JsonOptions::default().ordering(["nested"]);
        assert!(
            matches!(not_a_path, Err(TermError::JsonPath(_))),
            "a text that is not a path is refused: {not_a_path:?}"
        );
        // Set on the field, which `ordering` guards, a position refuses the
        // seal rather than put a term no ordering reaches on one element.
        let mut positional = JsonOptions::default();
        let _ = positional
            .ordered
            .insert(JsonPath::parse("$.nested.list[1].x").unwrap());
        let refused = try_seal(&cipher, &fixture(), &positional).await;
        assertions::refused_by_term(
            &refused,
            |e| matches!(e, TermError::JsonOrderingAtPosition),
            "a position set on the field refuses the seal",
        );
    }
}

// =============================================================================
// The token chain
// =============================================================================

mod given_a_subtree_key {
    use super::*;

    #[tokio::test]
    async fn unlocks_exactly_its_subtree_from_the_path_alone() {
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal(&cipher, &fixture()).await;
        let key = subtree_key(&cipher, "$.nested", JsonOptions::default())
            .await
            .unwrap();
        assert!(
            key.gates().is_empty(),
            "a chain head's token is derived, nothing to gate"
        );
        assert_eq!(
            key.path(),
            &JsonPath::parse("$.nested").unwrap(),
            "the key carries the path it was derived from"
        );
        let under = doc.subtree(key.token_bytes());
        let found: Vec<usize> = under.iter().map(|(j, _, _)| *j).collect();
        assert_eq!(
            found,
            [3, 4, 5, 6, 7, 8],
            "deep, list, both elements, both leaves"
        );
        let depths: Vec<u32> = under.iter().map(|(_, _, d)| *d).collect();
        assert_eq!(
            depths,
            [1, 1, 2, 3, 2, 3],
            "each row's depth below $.nested"
        );
        assert!(
            doc.subtree(&[7; 16]).is_empty(),
            "a wrong token unlocks nothing"
        );
    }

    /// Below a head the client derives nothing but array positions: a key
    /// step becomes a gate, and the walk from the head takes it.
    #[tokio::test]
    async fn gates_each_key_step_below_its_head() {
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal(&cipher, &fixture()).await;
        let key = subtree_key(&cipher, "$.nested", JsonOptions::default())
            .await
            .unwrap();
        let deeper = subtree_key(&cipher, "$.nested.list[1]", JsonOptions::default())
            .await
            .unwrap();
        assert_eq!(
            deeper.token_bytes(),
            key.token_bytes(),
            "anchored at the head"
        );
        assert_eq!(deeper.gates().len(), 2, "list, then [1]");
        assert_eq!(
            deeper.gates()[1],
            format!("#1:{}", base64(doc.entries()[5].selector())),
            "the position, and the selector every element of the list carries"
        );
        let list_token = child_token(&doc, key.token_bytes(), 4);
        let second = child_token(&doc, &list_token, 7);
        assert_eq!(
            subtree_ordinals(&doc, &second),
            [8],
            "the second element's x"
        );
        let children: Vec<usize> = doc
            .children(&list_token)
            .iter()
            .map(|(j, _, _)| *j)
            .collect();
        assert_eq!(
            children,
            [5, 7],
            "the children of a node, by ordinal: the list's two elements"
        );
        // A wildcard path anchors at the head and gates on each step's
        // selector: the list's, then every element's (the wildcard's), then x's.
        let gated = subtree_key(&cipher, "$.nested.list[*].x", JsonOptions::default())
            .await
            .unwrap();
        assert_eq!(
            gated.token_bytes(),
            key.token_bytes(),
            "a wildcard path anchors at the head"
        );
        assert_eq!(
            gated.gates(),
            [
                base64(doc.entries()[4].selector()),
                base64(doc.entries()[5].selector()),
                base64(doc.entries()[6].selector()),
            ],
            "the list's selector, every element's, then x's"
        );
    }

    /// The sealed root has no token; the open root's unlocks every node, and
    /// under an open root the chain is derivable down to the first key step.
    #[tokio::test]
    async fn has_no_token_at_a_sealed_root_and_derives_from_an_open_one() {
        let Scenario { cipher, .. } = scenario().await;
        for path in ["$", "$[*].x"] {
            let refused = subtree_key(&cipher, path, JsonOptions::default()).await;
            assertions::refused_by_term(
                &refused,
                |e| matches!(e, TermError::JsonSealedRoot),
                &format!("{path} under the sealed root"),
            );
        }
        let open_doc = seal_with(&cipher, &fixture(), &open_root()).await;
        let root = subtree_key(&cipher, "$", open_root()).await.unwrap();
        assert_eq!(
            open_doc.subtree(root.token_bytes()).len(),
            9,
            "every entry but the root"
        );
        // `$[0]` would be a position, `$.nested` is a gate.
        let open_key = subtree_key(&cipher, "$.nested.list[1]", open_root())
            .await
            .unwrap();
        assert_eq!(
            open_key.token_bytes(),
            root.token_bytes(),
            "anchored at the open root"
        );
        assert_eq!(open_key.gates().len(), 3, "nested, list, then [1]");
        let array_doc = seal_with(&cipher, &json!([[1, 2], [3]]), &open_root()).await;
        let second_row = subtree_key(&cipher, "$[1]", open_root()).await.unwrap();
        assert!(second_row.gates().is_empty(), "positions derive");
        assert_eq!(
            subtree_ordinals(&array_doc, second_row.token_bytes()),
            [5],
            "$, [0], [0][0], [0][1], [1], [1][0]"
        );
    }
}

mod given_a_position {
    use super::*;

    /// A position names an array element and nothing else. A column's rows
    /// need not agree on a node's kind, and an object member's ordinal is a
    /// rank among its siblings, so a token derived for `$.a[0]` must not
    /// open the rank-0 member of a row whose `$.a` is an object: `jsonb` has
    /// no node at `{a,0}` there, and neither does the index.
    #[tokio::test]
    async fn reaches_no_object_member() {
        let Scenario { cipher, .. } = scenario().await;
        let first = subtree_key(&cipher, "$.a[0]", JsonOptions::default())
            .await
            .unwrap();
        assert!(
            first.gates().is_empty(),
            "a position after the head derives"
        );
        let array = seal(&cipher, &json!({"a": [{"x": 2}]})).await;
        assert_eq!(
            subtree_ordinals(&array, first.token_bytes()),
            [3],
            "$, $.a, $.a[0], $.a[0].x"
        );
        for object in [
            json!({"a": {"k": {"x": 1}}}),
            json!({"a": {"k": [1, 2]}}),
            json!({"a": {"0": {"x": 1}}}),
        ] {
            let doc = seal(&cipher, &object).await;
            assert!(
                doc.subtree(first.token_bytes()).is_empty(),
                "{object}: an object member is not an element"
            );
        }
    }

    /// The same below a key step, where the position is a gate: the walk
    /// from the head reaches `$.h.a` by its selector, and the gate at the
    /// next step admits an element only. A member at ordinal 0 under an
    /// object `$.h.a` carries its own selector, not the element's.
    #[tokio::test]
    async fn gates_on_the_elements_selector_below_a_key_step() {
        let Scenario { cipher, .. } = scenario().await;
        let gated = subtree_key(&cipher, "$.h.a[0]", JsonOptions::default())
            .await
            .unwrap();
        assert_eq!(gated.gates().len(), 2, "a, then [0]");
        let element = cipher
            .default_keyset()
            .json_selector(
                &JsonPath::parse("$.h.a[*]").unwrap(),
                nonempty!("users").with("profile"),
            )
            .await
            .unwrap();
        assert_eq!(
            gated.gates()[1],
            format!("#0:{element}"),
            "the position gate names the elements' selector"
        );
    }
}

// =============================================================================
// Extraction
// =============================================================================

mod given_an_extracted_node {
    use super::*;

    #[tokio::test]
    async fn opens_to_its_scalar_and_a_walked_subtree_to_its_value() {
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal(&cipher, &fixture()).await;
        let node = |j: usize| doc.node(j).unwrap();
        let scalar = |j: usize| cipher.decrypt_as::<Value, JsonNode>(node(j), aead());
        assert_eq!(
            scalar(1).await.unwrap(),
            json!("world-1"),
            "$.hello opens to its scalar"
        );
        assert_eq!(
            scalar(6).await.unwrap(),
            json!(1),
            "[0].x opens to its scalar"
        );
        assert_eq!(
            scalar(0).await.unwrap(),
            fixture(),
            "the sealed root is the document"
        );
        assertions::refused_as_opened_type(
            &scalar(2).await,
            None,
            "a container node holds no value of its own",
        );

        let key = subtree_key(&cipher, "$.nested", JsonOptions::default())
            .await
            .unwrap();
        let rows = subtree_nodes(&doc, key.token_bytes());
        let nested = cipher
            .decrypt_as::<Value, JsonSubtree>(key.open(rows.clone()), aead())
            .await
            .unwrap();
        assert_eq!(
            nested,
            fixture()["nested"],
            "the walk under $.nested opens to its value"
        );
        let forest = cipher
            .decrypt_as::<Vec<Value>, JsonSubtree>(key.open(rows), aead())
            .await
            .unwrap();
        assert_eq!(
            forest,
            vec![json!("constant"), json!([{"x": 1}, {"x": 2}])],
            "as a list, the walk opens to $.nested's members"
        );

        // The list's token is the server's to derive, one level under nested.
        let list = child_token(&doc, key.token_bytes(), 4);
        let elements = cipher
            .decrypt_as::<Value, JsonSubtree>(
                keyed(&cipher, "$.nested.list", subtree_nodes(&doc, &list)).await,
                aead(),
            )
            .await
            .unwrap();
        assert_eq!(
            elements,
            json!([{"x": 1}, {"x": 2}]),
            "the walk under the list opens to the list"
        );
    }

    /// An extracted node round-trips through its wire form with the
    /// envelope fields the SQL grafts beside it.
    #[tokio::test]
    async fn round_trips_with_the_envelope_the_sql_grafts() {
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal(&cipher, &fixture()).await;
        let mut wire = serde_json::to_value(doc.node(6).unwrap()).unwrap();
        wire["i"] = json!({"t": "users", "c": "profile"});
        wire["v"] = json!(4);
        let back: JsonNode = serde_json::from_value(wire).unwrap();
        assert_eq!(back.ordinal(), 6, "the node keeps its ordinal");
        assert_eq!(
            cipher
                .decrypt_as::<Value, JsonNode>(back, aead())
                .await
                .unwrap(),
            json!(1),
            "the grafted node opens to its scalar"
        );
    }

    /// The walk reports each row's depth below where it started, in `d`; an
    /// extracted node carries none.
    #[tokio::test]
    async fn carries_no_depth_until_a_walk_gives_it_one() {
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal(&cipher, &fixture()).await;
        assert_eq!(
            doc.node(6).unwrap().depth(),
            None,
            "an extracted node has no depth"
        );
        let mut wire = serde_json::to_value(doc.node(6).unwrap()).unwrap();
        assert!(
            wire.get("d").is_none(),
            "an extracted node writes no `d`: {wire}"
        );
        wire["d"] = json!(3);
        let walked: JsonNode = serde_json::from_value(wire).unwrap();
        assert_eq!(walked.depth(), Some(3), "a walked row reads its depth");
        assert_eq!(
            serde_json::to_value(&walked).unwrap()["d"],
            json!(3),
            "a walked row writes its depth back"
        );
    }
}

mod given_gated_walk_rows {
    use super::*;

    /// The rows of a gated walk carry the node the gates reached at depth 0
    /// and its descendants beneath. Opened as a value, they are that node's
    /// value; two reached nodes open as a list, or refuse to be one value.
    #[tokio::test]
    async fn open_to_the_reached_nodes_value() {
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = subtree_key(&cipher, "$.nested", JsonOptions::default())
            .await
            .unwrap();
        let list = child_token(&doc, nested.token_bytes(), 4);
        // What `json_tree_subtree_at(doc, t(nested), [s(list), #1])` returns:
        // the second element at d = 0, its x at d = 1.
        let rows_at = |reached: &[usize], below: &[(usize, u32)]| -> Vec<JsonNode> {
            reached
                .iter()
                .map(|j| (*j, 0u32))
                .chain(below.iter().copied())
                .map(|(j, d)| with_depth(&doc, j, d))
                .collect()
        };
        let second = keyed(&cipher, "$.nested.list[1]", rows_at(&[7], &[(8, 1)])).await;
        assert!(
            !second.is_sealed_root(),
            "a reached node is not the fallback"
        );
        let value = cipher
            .decrypt_as::<Value, JsonSubtree>(second.clone(), aead())
            .await
            .unwrap();
        assert_eq!(value, json!({"x": 2}), "the reached node's own value");
        let values = cipher
            .decrypt_as::<Vec<Value>, JsonSubtree>(second, aead())
            .await
            .unwrap();
        assert_eq!(
            values,
            vec![json!({"x": 2})],
            "as a list, the one reached node"
        );
        // A scalar reached by a gate opens to the scalar, where the ungated
        // walk of a scalar yields no rows and no value.
        let x = cipher
            .decrypt_as::<Value, JsonSubtree>(
                keyed(&cipher, "$.nested.list[1].x", rows_at(&[8], &[])).await,
                aead(),
            )
            .await
            .unwrap();
        assert_eq!(x, json!(2), "a scalar reached by a gate opens to it");
        // Two reached nodes (a wildcard): a list, never one value.
        let both = keyed(&cipher, "$.nested.list[*].x", rows_at(&[6, 8], &[])).await;
        let values = cipher
            .decrypt_as::<Vec<Value>, JsonSubtree>(both.clone(), aead())
            .await
            .unwrap();
        assert_eq!(
            values,
            vec![json!(1), json!(2)],
            "two reached nodes open as a list"
        );
        assertions::refused_as_opened_type(
            &cipher.decrypt_as::<Value, JsonSubtree>(both, aead()).await,
            Some("one node at the walked path"),
            "two reached nodes are not one value",
        );
        // Without a d = 0 row the same entries are the children of one node and
        // assemble into it.
        let elements = cipher
            .decrypt_as::<Value, JsonSubtree>(
                keyed(&cipher, "$.nested.list", subtree_nodes(&doc, &list)).await,
                aead(),
            )
            .await
            .unwrap();
        assert_eq!(
            elements,
            json!([{"x": 1}, {"x": 2}]),
            "without a d = 0 row the rows assemble into their parent"
        );
    }
}

mod given_a_derived_record {
    use super::*;

    /// A document, an extracted node and a walked subtree are each the one
    /// recoverable field of a derived record: each opens through
    /// `DecryptField`, as a record holding one would.
    #[tokio::test]
    async fn opens_each_stored_form_as_its_field() {
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal(&cipher, &fixture()).await;
        let node = doc.node(1).unwrap();
        let key = subtree_key(&cipher, "$.nested", JsonOptions::default())
            .await
            .unwrap();
        let list = child_token(&doc, key.token_bytes(), 4);
        let rows = subtree_nodes(&doc, &list);
        let subtree = keyed(&cipher, "$.nested.list", rows.clone()).await;
        assert_eq!(
            subtree.nodes(),
            rows.as_slice(),
            "a subtree holds the rows it was opened with"
        );
        assert_eq!(subtree.nodes().len(), 4, "both elements and both leaves");

        let opening: Option<Decryption<Value, FakeDataKeySource>> = doc.decryption_field(aead());
        let opened = cipher
            .run_decryption(opening.expect("a document opens"))
            .await
            .unwrap();
        assert_eq!(opened, fixture(), "the document field");
        let opening: Option<Decryption<Value, FakeDataKeySource>> = node.decryption_field(aead());
        let opened = cipher
            .run_decryption(opening.expect("a node opens"))
            .await
            .unwrap();
        assert_eq!(opened, json!("world-1"), "the node field");
        let opening: Option<Decryption<Value, FakeDataKeySource>> =
            subtree.decryption_field(aead());
        let opened = cipher
            .run_decryption(opening.expect("a subtree opens"))
            .await
            .unwrap();
        assert_eq!(opened, json!([{"x": 1}, {"x": 2}]), "the subtree field");
    }
}

mod given_a_fallback_root {
    use super::*;

    /// The document's root as a walk past its budget returns it: alone, at
    /// depth 0.
    fn fallback(doc: &JsonDocument) -> JsonNode {
        with_depth(doc, 0, 0)
    }

    /// Past its budget the server returns the sealed root alone, at depth
    /// 0, in place of the subtree: the rows open to the whole document and
    /// the key's path selects over it.
    #[tokio::test]
    async fn opens_at_the_keys_path() {
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal(&cipher, &fixture()).await;
        let root = fallback(&doc);
        let rows = keyed(&cipher, "$.nested", vec![root.clone()]).await;
        assert!(
            rows.is_sealed_root(),
            "the root alone at d = 0 is the fallback"
        );
        assert_eq!(
            rows.path().to_string(),
            "$.nested",
            "the fallback carries the key's path"
        );
        let nested = cipher
            .decrypt_as::<Value, JsonSubtree>(rows, aead())
            .await
            .unwrap();
        assert_eq!(nested, fixture()["nested"], "the value at the path");
        let xs = cipher
            .decrypt_as::<Vec<Value>, JsonSubtree>(
                keyed(&cipher, "$.nested.list[*].x", vec![root.clone()]).await,
                aead(),
            )
            .await
            .unwrap();
        assert_eq!(
            xs,
            vec![json!(1), json!(2)],
            "a wildcard path selects every node over the document"
        );
        let none = cipher
            .decrypt_as::<Vec<Value>, JsonSubtree>(
                keyed(&cipher, "$.missing[*]", vec![root]).await,
                aead(),
            )
            .await
            .unwrap();
        assert!(
            none.is_empty(),
            "a path that reaches nothing is no subtree: {none:?}"
        );
    }

    /// A path that reaches nothing, or a wildcard that reaches two nodes
    /// where one value is asked for, is refused, and each refusal names
    /// what it expected.
    #[tokio::test]
    async fn refuses_one_value_where_the_path_reaches_none_or_two() {
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal(&cipher, &fixture()).await;
        let root = fallback(&doc);
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
            assertions::refused_as_opened_type(&refused, Some(expected), path);
        }
    }

    /// The same root at depth 1, or at depth 0 under an unsealed document,
    /// is a walk's row and not the fallback; neither assembles. A fallback
    /// with no path cannot be built: the key is the only constructor.
    #[tokio::test]
    async fn is_only_the_sealed_root_alone_at_depth_zero() {
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal(&cipher, &fixture()).await;
        let root = fallback(&doc);
        let rows = keyed(&cipher, "$.nested", vec![with_depth(&doc, 0, 1)]).await;
        assert!(
            !rows.is_sealed_root(),
            "the root at depth 1 is a walk's row"
        );
        assertions::refused_as_opened_type(
            &cipher.decrypt_as::<Value, JsonSubtree>(rows, aead()).await,
            None,
            "the root at depth 1 does not assemble",
        );
        let open_doc = seal_with(&cipher, &fixture(), &open_root()).await;
        assert!(
            !keyed(&cipher, "$.nested", vec![fallback(&open_doc)])
                .await
                .is_sealed_root(),
            "an unsealed root at depth 0 is not the fallback"
        );
        assert!(
            !keyed(&cipher, "$.nested", vec![]).await.is_sealed_root(),
            "no rows are not the fallback"
        );
        assert!(
            !keyed(&cipher, "$.nested", vec![root.clone(), root])
                .await
                .is_sealed_root(),
            "two roots are not the fallback"
        );
    }

    /// The sealed root a walk fell back to opens to exactly what the walked
    /// rows open to, so a caller's result does not change shape when a
    /// document grows past the budget, and no caller says which walk the
    /// rows came from: the key does, by its gates. A key with none keyed
    /// `json_tree_subtree`, whose rows are the descendants of the path's
    /// node, so a `Vec` opens to that node's children; a key with gates
    /// keyed `json_tree_subtree_at`, whose rows are the nodes the path
    /// reaches.
    #[tokio::test]
    async fn opens_to_what_the_walk_opens_to() {
        let document = json!({
            "list": [{"x": 1}, {"x": 2}],
            "obj": {"a": "constant", "b": [1, 2], "c": {"d": [true, null]}},
            "hello": "world"
        });
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal(&cipher, &document).await;
        let root = fallback(&doc);
        let sorted = |mut values: Vec<Value>| {
            values.sort_by_key(ToString::to_string);
            values
        };
        for (text, gated) in [
            ("$.list", false),
            ("$.obj", false),
            ("$.hello", false),
            ("$.list[1]", false),
            ("$.obj.b", true),
            ("$.obj.c.d", true),
            ("$.obj.b[0]", true),
            ("$.list[*].x", true),
            ("$.list[1].x", true),
            ("$.obj.c", true),
        ] {
            let key = subtree_key(&cipher, text, JsonOptions::default())
                .await
                .unwrap();
            assert_eq!(
                !key.gates().is_empty(),
                gated,
                "{text}: whether the key gates"
            );
            let walked = if gated {
                gated_walk(&doc, &key)
            } else {
                subtree_nodes(&doc, key.token_bytes())
            };
            let fallen_back = key.open(vec![root.clone()]);
            assert!(fallen_back.is_sealed_root(), "{text}: the fallback");
            let as_walked = cipher
                .decrypt_as::<Vec<Value>, JsonSubtree>(key.open(walked.clone()), aead())
                .await
                .unwrap();
            let as_fallen = cipher
                .decrypt_as::<Vec<Value>, JsonSubtree>(fallen_back.clone(), aead())
                .await
                .unwrap();
            // An object's members come back in an order neither form fixes.
            assert_eq!(sorted(as_fallen), sorted(as_walked), "{text}, as a list");
            // A walk with no rows (a scalar's, or an empty container's) is
            // never past a budget, so it never falls back: nothing to compare.
            if walked.is_empty() {
                continue;
            }
            let one_walked = cipher
                .decrypt_as::<Value, JsonSubtree>(key.open(walked), aead())
                .await;
            let one_fallen = cipher
                .decrypt_as::<Value, JsonSubtree>(fallen_back, aead())
                .await;
            match (one_walked, one_fallen) {
                (Ok(a), Ok(b)) => assert_eq!(a, b, "{text}, as one value"),
                (Err(_), Err(_)) => {}
                (a, b) => panic!("{text}: the walk opened to {a:?}, the fallback to {b:?}"),
            }
        }
        // As one value an ungated walk opens to its node, either way.
        let key = subtree_key(&cipher, "$.obj", JsonOptions::default())
            .await
            .unwrap();
        assert_eq!(
            cipher
                .decrypt_as::<Value, JsonSubtree>(key.open(vec![root.clone()]), aead())
                .await
                .unwrap(),
            document["obj"],
            "an ungated fallback opens to its node as one value"
        );
        // An ungated key names one node: a fallback with nothing at the path
        // is refused.
        let missing = subtree_key(&cipher, "$.missing", JsonOptions::default())
            .await
            .unwrap();
        assertions::refused_as_opened_type(
            &cipher
                .decrypt_as::<Vec<Value>, JsonSubtree>(missing.open(vec![root]), aead())
                .await,
            Some("one node at the walked path"),
            "an ungated fallback with nothing at the path",
        );
    }
}

// =============================================================================
// Tamper evidence
// =============================================================================

mod given_rows_the_server_chose {
    use super::*;

    /// The rows of a walk come from the server, which can repeat an entry or
    /// pick which entries to return. Every entry is authentic, but the
    /// rebuild nests the containers it is handed: a repeated row is refused,
    /// and so is a line of containers deeper than any document the index
    /// seals, as a shape mismatch rather than a recursion as deep as the
    /// rows.
    #[tokio::test]
    async fn refuses_a_repeated_row_or_a_line_of_containers() {
        let Scenario { cipher, .. } = scenario().await;
        let doc = seal(&cipher, &fixture()).await;
        let node = |j: usize| doc.node(j).unwrap();
        let repeated = keyed(&cipher, "$.nested", vec![node(1), node(1)]).await;
        assertions::refused_as_opened_type(
            &cipher
                .decrypt_as::<Vec<Value>, JsonSubtree>(repeated, aead())
                .await,
            None,
            "a repeated row",
        );

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
        assert_eq!(containers.len(), 201, "200 objects and the last leaf");
        assertions::refused_as_opened_type(
            &cipher
                .decrypt_as::<Vec<Value>, JsonSubtree>(
                    keyed(&cipher, "$.k000", containers).await,
                    aead(),
                )
                .await,
            None,
            "a line of 200 objects",
        );

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
        assert_eq!(
            arrays.len(),
            202,
            "the outer array, 200 inner and the last leaf"
        );
        assertions::refused_as_opened_type(
            &cipher
                .decrypt_as::<Vec<Value>, JsonSubtree>(
                    keyed(&cipher, "$.k000", arrays).await,
                    aead(),
                )
                .await,
            None,
            "a line of 202 arrays",
        );
    }
}

mod given_a_tampered_document {
    use super::*;

    #[tokio::test]
    async fn fails_to_open_a_moved_reordered_or_regrafted_entry() {
        let Scenario { cipher, .. } = scenario().await;
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
        assertions::refused_as_tampered(&open(&cipher, reordered).await, "reordered");

        let regrafted = tamper(wire.clone(), &|sv| sv[1] = other_wire["sv"][1].clone());
        assertions::refused_as_tampered(
            &open(&cipher, regrafted).await,
            "regrafted from another document",
        );

        let truncated = tamper(wire.clone(), &|sv| {
            let _ = sv.pop();
        });
        assertions::refused_as_opened_type(&open(&cipher, truncated).await, None, "truncated");

        let flipped = tamper(wire.clone(), &|sv| {
            let c = sv[1]["c"].as_str().unwrap().to_owned();
            let mut bytes = c.into_bytes();
            bytes[3] = if bytes[3] == b'A' { b'B' } else { b'A' };
            sv[1]["c"] = Value::String(String::from_utf8(bytes).unwrap());
        });
        assertions::refused_as_tampered(&open(&cipher, flipped).await, "a changed byte");

        let wrong_context = cipher
            .decrypt_as::<Value, JsonDocument>(
                doc,
                AeadContext::from(nonempty!("users").with("bio")),
            )
            .await;
        assertions::refused_as_tampered(&wrong_context, "another column");

        // A node lifted out of its document fails under another ordinal.
        let sealed = seal(&cipher, &value).await;
        let mut lifted = serde_json::to_value(sealed.node(1).unwrap()).unwrap();
        lifted["j"] = json!(2);
        let lifted: JsonNode = serde_json::from_value(lifted).unwrap();
        assertions::refused_as_tampered(
            &cipher.decrypt_as::<Value, JsonNode>(lifted, aead()).await,
            "a node under another ordinal",
        );
    }
}

// =============================================================================
// Containment
// =============================================================================

mod given_the_containment_model {
    use super::*;

    /// The pinned answers of `jsonb-semantics.sql`, so the model is held to
    /// PostgreSQL and not only to itself.
    #[test]
    fn gives_postgresqls_pinned_answers() {
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
}

mod given_the_design_corpus {
    use super::*;

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

    /// Every pair of the corpus, both ways round: `@>` over the projections
    /// is `jsonb @>`, and `<@` is `jsonb <@` but for a stored root scalar in
    /// a needle root array.
    #[tokio::test]
    async fn answers_containment_both_ways_as_jsonb_does() {
        let Scenario { cipher, plan } = scenario().await;
        for (stored, needle) in corpus() {
            let doc = cipher.encrypt(&stored).using(&plan).await.unwrap();
            let contains: JsonQuery = cipher.query(op::Contains, &needle).on(&plan).await.unwrap();
            let contained_by: JsonQuery = cipher
                .query(op::ContainedBy, &needle)
                .on(&plan)
                .await
                .unwrap();
            assertions::contains_as_jsonb(&contains, &doc, &stored, &needle);
            assertions::is_contained_by_as_jsonb(&contained_by, &doc, &stored, &needle);
        }
    }
}

mod given_generated_documents {
    //! The containment property over documents and needles proptest
    //! generates. A case is one stored document and one needle: a random
    //! value, the document itself or a pruning of it (which it contains by
    //! construction), or such a pruning with one edit. A failure shrinks to a small
    //! document and needle, and proptest appends its seed to
    //! `proptest-regressions/json_index.txt` in this crate, which every
    //! later run replays first. The strategies mirror the EQL live oracle's
    //! (`packages/eql/tests/encryption/tests/json_tree/generated.rs`), which
    //! sits in another Cargo workspace.

    use std::cell::Cell;
    use std::fmt;
    use std::future::IntoFuture;

    use proptest::collection::vec as vec_of;
    use proptest::prelude::*;
    use proptest::sample::{select, Index};
    use proptest::strategy::ValueTree;
    use proptest::test_runner::{
        Config, FileFailurePersistence, RngAlgorithm, RngSeed, TestCaseError, TestRunner,
    };

    use super::*;

    /// The seed the run uses when `PROPTEST_RNG_SEED` is unset. Fixed, so
    /// every run checks the same cases.
    const DEFAULT_SEED: u64 = 1336;

    /// The cases a run checks when `PROPTEST_CASES` is unset.
    const DEFAULT_CASES: u32 = 512;

    /// Where proptest records a failing case's seed: `Direct`, with the
    /// crate's own path, rather than resolving `file!()` from the working
    /// directory.
    const REGRESSIONS: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/proptest-regressions/json_index.txt"
    );

    /// Numbers, several of them one value to `jsonb` in different
    /// representations: `1`, `1.0` and `1e0`; `100` and `1e2`; `0`, `0.0`
    /// and `-0.0`; `0.5` and `5e-1`.
    const NUMBERS: &[&str] = &[
        "0",
        "0.0",
        "-0.0",
        "1",
        "1.0",
        "1e0",
        "2",
        "2.00",
        "-1",
        "-1.0",
        "10",
        "1e1",
        "100",
        "1e2",
        "0.5",
        "5e-1",
        "1.5",
        "123456789012",
        "1e20",
    ];

    /// Strings, some spelled like a number, a boolean or null.
    const STRINGS: &[&str] = &["x", "y", "", "1", "1.0", "2", "true", "null", "a b", "ü"];

    /// Object keys: few, so they repeat across levels and siblings.
    const KEYS: &[&str] = &["a", "b", "c", "x", "1", ""];

    /// proptest's defaults, which read `PROPTEST_CASES` and
    /// `PROPTEST_RNG_SEED`, with this suite's own default for each one left
    /// unset.
    fn config() -> Config {
        let mut config = Config::default();
        if std::env::var_os("PROPTEST_CASES").is_none() {
            config.cases = DEFAULT_CASES;
        }
        if config.rng_seed == RngSeed::Random {
            config.rng_seed = RngSeed::Fixed(DEFAULT_SEED);
        }
        config.rng_algorithm = RngAlgorithm::ChaCha;
        config.failure_persistence = Some(Box::new(FileFailurePersistence::Direct(REGRESSIONS)));
        config
    }

    /// One edit that turns a contained needle into a near miss. `at` picks
    /// the node, in document order; an edit that does not fit the node's
    /// kind changes its kind instead.
    #[derive(Clone, Debug)]
    enum Edit {
        Leaf {
            at: Index,
            to: Value,
        },
        Key {
            at: Index,
            key: String,
            value: Value,
        },
        Element {
            at: Index,
            value: Value,
        },
        Kind {
            at: Index,
        },
    }

    /// A needle as proptest draws it. `keep` says, one member or element at
    /// a time in document order, what a pruning keeps; once it runs out,
    /// nothing more is kept, so shrinking it makes the needle smaller.
    #[derive(Clone, Debug)]
    enum NeedleSpec {
        Random(Value),
        /// The stored document itself, which contains itself.
        Itself,
        Pruned {
            keep: Vec<bool>,
            at: Option<Index>,
        },
        NearMiss {
            keep: Vec<bool>,
            edit: Edit,
        },
    }

    /// One generated case: a stored document and a needle derived from it.
    #[derive(Clone)]
    struct Case {
        stored: Value,
        needle: NeedleSpec,
    }

    impl Case {
        /// The needle as a value, and whether the stored document contains
        /// it by construction.
        fn needle(&self) -> (Value, bool) {
            match &self.needle {
                NeedleSpec::Random(value) => (value.clone(), false),
                NeedleSpec::Itself => (self.stored.clone(), true),
                NeedleSpec::Pruned { keep, at } => {
                    let pointer = at
                        .as_ref()
                        .map_or_else(String::new, |at| at.get(&pointers(&self.stored)).clone());
                    let node = self.stored.pointer(&pointer).unwrap();
                    (prune(node, &mut keep.iter()), pointer.is_empty())
                }
                NeedleSpec::NearMiss { keep, edit } => {
                    let mut value = prune(&self.stored, &mut keep.iter());
                    apply(edit, &mut value);
                    (value, false)
                }
            }
        }
    }

    /// Printed as JSON: what proptest shows for the minimal failing case.
    impl fmt::Debug for Case {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let (needle, _) = self.needle();
            write!(
                f,
                "stored {}, needle {needle} ({:?})",
                self.stored, self.needle
            )
        }
    }

    fn prune(v: &Value, keep: &mut std::slice::Iter<'_, bool>) -> Value {
        match v {
            Value::Object(map) => {
                let mut out = Map::new();
                for (key, member) in map {
                    if keep.next().copied().unwrap_or(false) {
                        let _ = out.insert(key.clone(), prune(member, keep));
                    }
                }
                Value::Object(out)
            }
            Value::Array(items) => {
                let mut out = Vec::new();
                for item in items {
                    if keep.next().copied().unwrap_or(false) {
                        out.push(prune(item, keep));
                    }
                }
                Value::Array(out)
            }
            scalar => scalar.clone(),
        }
    }

    /// Every node's JSON pointer, in document order, the root (`""`) first.
    fn pointers(v: &Value) -> Vec<String> {
        fn walk(v: &Value, at: String, out: &mut Vec<String>) {
            out.push(at.clone());
            match v {
                Value::Object(map) => {
                    for (key, member) in map {
                        let key = key.replace('~', "~0").replace('/', "~1");
                        walk(member, format!("{at}/{key}"), out);
                    }
                }
                Value::Array(items) => {
                    for (i, item) in items.iter().enumerate() {
                        walk(item, format!("{at}/{i}"), out);
                    }
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        walk(v, String::new(), &mut out);
        out
    }

    fn apply(edit: &Edit, needle: &mut Value) {
        let at = match edit {
            Edit::Leaf { at, .. }
            | Edit::Key { at, .. }
            | Edit::Element { at, .. }
            | Edit::Kind { at } => at,
        };
        let pointer = at.get(&pointers(needle)).clone();
        let node = needle.pointer_mut(&pointer).unwrap();
        match edit {
            Edit::Leaf { to, .. } if !node.is_object() && !node.is_array() && node != to => {
                *node = to.clone();
            }
            Edit::Key { key, value, .. } if node.is_object() => {
                let _ = node
                    .as_object_mut()
                    .unwrap()
                    .insert(key.clone(), value.clone());
            }
            Edit::Element { value, .. } if node.is_array() => {
                node.as_array_mut().unwrap().push(value.clone());
            }
            _ => {
                *node = match node.take() {
                    Value::Object(map) => Value::Array(map.into_iter().map(|(_, v)| v).collect()),
                    Value::Array(items) => {
                        json!({ "a": items.into_iter().next().unwrap_or(Value::Null) })
                    }
                    scalar => Value::Array(vec![scalar]),
                };
            }
        }
    }

    mod strategies {
        use super::*;

        pub(super) fn scalar() -> BoxedStrategy<Value> {
            prop_oneof![
                4 => select(NUMBERS).prop_map(|text| serde_json::from_str::<Value>(text).unwrap()),
                3 => select(STRINGS).prop_map(|text| Value::String(text.to_owned())),
                2 => any::<bool>().prop_map(Value::Bool),
                1 => Just(Value::Null),
            ]
            .boxed()
        }

        fn key() -> BoxedStrategy<String> {
            select(KEYS).prop_map(str::to_owned).boxed()
        }

        /// An object of up to four members. A key drawn twice keeps its
        /// later value, as `jsonb` does.
        fn object_of(inner: BoxedStrategy<Value>) -> BoxedStrategy<Value> {
            vec_of((key(), inner), 0..5)
                .prop_map(|members| Value::Object(members.into_iter().collect()))
                .boxed()
        }

        /// An array: of anything, of objects, of arrays, or with some
        /// elements repeated.
        fn array_of(inner: BoxedStrategy<Value>) -> BoxedStrategy<Value> {
            prop_oneof![
                3 => vec_of(inner.clone(), 0..5).prop_map(Value::Array),
                1 => vec_of(object_of(inner.clone()), 1..4).prop_map(Value::Array),
                1 => vec_of(vec_of(inner.clone(), 0..3).prop_map(Value::Array), 1..4)
                    .prop_map(Value::Array),
                1 => (vec_of(inner, 1..4), vec_of(any::<Index>(), 1..3)).prop_map(
                    |(mut items, repeats)| {
                        for repeat in repeats {
                            let copy = repeat.get(&items).clone();
                            items.push(copy);
                        }
                        Value::Array(items)
                    }
                ),
            ]
            .boxed()
        }

        /// A value with up to `depth` levels of recursion below it.
        pub(super) fn value(depth: u32) -> BoxedStrategy<Value> {
            scalar()
                .prop_recursive(depth, 48, 4, |inner| {
                    prop_oneof![object_of(inner.clone()), array_of(inner)]
                })
                .boxed()
        }

        /// A stored document: mostly an object, sometimes a root array, and
        /// sometimes a root scalar.
        pub(super) fn document() -> BoxedStrategy<Value> {
            prop_oneof![
                6 => object_of(value(3)),
                3 => array_of(value(2)),
                1 => scalar(),
            ]
            .boxed()
        }

        fn keep() -> BoxedStrategy<Vec<bool>> {
            vec_of(proptest::bool::weighted(0.7), 0..32).boxed()
        }

        fn edit() -> BoxedStrategy<Edit> {
            prop_oneof![
                (any::<Index>(), scalar()).prop_map(|(at, to)| Edit::Leaf { at, to }),
                (any::<Index>(), key(), value(1)).prop_map(|(at, key, value)| Edit::Key {
                    at,
                    key,
                    value
                }),
                (any::<Index>(), value(1)).prop_map(|(at, value)| Edit::Element { at, value }),
                any::<Index>().prop_map(|at| Edit::Kind { at }),
            ]
            .boxed()
        }

        fn needle() -> BoxedStrategy<NeedleSpec> {
            prop_oneof![
                1 => value(2).prop_map(NeedleSpec::Random),
                1 => Just(NeedleSpec::Itself),
                2 => (keep(), proptest::option::weighted(0.3, any::<Index>()))
                    .prop_map(|(keep, at)| NeedleSpec::Pruned { keep, at }),
                2 => (keep(), edit()).prop_map(|(keep, edit)| NeedleSpec::NearMiss { keep, edit }),
            ]
            .boxed()
        }

        pub(super) fn case() -> BoxedStrategy<Case> {
            (document(), needle())
                .prop_map(|(stored, needle)| Case { stored, needle })
                .boxed()
        }
    }

    /// Run `body` over a whole proptest run on one runtime and cipher, and
    /// fail with the minimal case and the way to replay it.
    fn run(
        name: &str,
        body: impl Fn(&Scenario, &tokio::runtime::Runtime, &Case) -> Result<(), TestCaseError>,
    ) {
        let config = config();
        let replay = format!(
            "seed {seed}, {cases} cases; replay with PROPTEST_RNG_SEED={seed} PROPTEST_CASES={cases}",
            seed = config.rng_seed,
            cases = config.cases
        );
        eprintln!("json_index generated {name}: {replay}");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let scenario = runtime.block_on(scenario());
        let mut runner = TestRunner::new(config);
        if let Err(error) = runner.run(&strategies::case(), |case| body(&scenario, &runtime, &case))
        {
            panic!("json_index generated {name}: {replay}\n{error}");
        }
    }

    /// The stored document, sealed through the plan.
    fn sealed(
        scenario: &Scenario,
        runtime: &tokio::runtime::Runtime,
        stored: &Value,
    ) -> JsonDocument {
        runtime
            .block_on(
                scenario
                    .cipher
                    .encrypt(stored)
                    .using(&scenario.plan)
                    .into_future(),
            )
            .unwrap()
    }

    #[test]
    fn contains_as_jsonb_contains() {
        run("@>", |scenario, runtime, case| {
            let (needle, contained) = case.needle();
            let doc = sealed(scenario, runtime, &case.stored);
            let query: JsonQuery = runtime
                .block_on(
                    scenario
                        .cipher
                        .query(op::Contains, &needle)
                        .on(&scenario.plan)
                        .into_future(),
                )
                .unwrap();
            prop_assert!(
                !contained || pg_contains(&case.stored, &needle, true),
                "a pruning of the whole document should be contained by it: {} @> {needle}",
                case.stored
            );
            prop_assert_eq!(
                query.matches(doc.projection()),
                pg_contains(&case.stored, &needle, true),
                "{} @> {}",
                &case.stored,
                &needle
            );
            Ok(())
        });
    }

    #[test]
    fn is_contained_by_as_jsonb_except_a_root_scalar_in_a_root_array() {
        let excluded = Cell::new(0);
        run("<@", |scenario, runtime, case| {
            let (needle, _) = case.needle();
            let doc = sealed(scenario, runtime, &case.stored);
            let query: JsonQuery = runtime
                .block_on(
                    scenario
                        .cipher
                        .query(op::ContainedBy, &needle)
                        .on(&scenario.plan)
                        .into_future(),
                )
                .unwrap();
            let jsonb = pg_contains(&needle, &case.stored, true);
            if jsonb && scalar_in_array(&case.stored, &needle) {
                excluded.set(excluded.get() + 1);
            }
            prop_assert_eq!(
                query.projection().contains(doc.projection()),
                jsonb && !scalar_in_array(&case.stored, &needle),
                "{} <@ {}",
                &case.stored,
                &needle
            );
            Ok(())
        });
        assert!(
            excluded.get() > 0,
            "no stored root scalar sat inside a needle root array, so the `<@` exception went unexercised"
        );
    }

    mod given_the_document_strategy {
        use super::*;

        /// Every feature the property relies on, counted over a run's worth
        /// of generated documents, so a change to the generator that stops
        /// producing one fails here.
        #[test]
        fn produces_every_feature_the_property_relies_on() {
            let mut runner = TestRunner::new(config());
            let strategy = strategies::document();
            let docs: Vec<Value> = (0..400)
                .map(|_| strategy.new_tree(&mut runner).unwrap().current())
                .collect();
            assertions::covers_every_feature(&docs);
        }
    }
}

// =============================================================================
// Queries
// =============================================================================

mod given_a_containment_query {
    use super::*;

    #[tokio::test]
    async fn serializes_as_the_needle_operand_and_derives_no_key() {
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
        assert_eq!(
            wire["el"].as_array().unwrap().len(),
            1,
            "one group for the one element"
        );
        assert_eq!(
            wire["el"][0]["sv"].as_array().unwrap().len(),
            2,
            "the element and its x"
        );
        assert!(
            wire.get("alt").is_none(),
            "an object needle carries no alternative: {wire}"
        );
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
}

mod given_equality_at_the_root {
    use super::*;

    /// At the root, equality is of the root value: `("$", 1)` matches a
    /// stored `1` and not a stored `[1]`, which containment of the scalar
    /// `1` would.
    #[tokio::test]
    async fn matches_the_root_value_and_not_an_array_holding_it() {
        let Scenario { cipher, plan } = scenario().await;
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
        assert!(
            at_root.matches(scalar.projection()),
            "(\"$\", 1) matches a stored 1"
        );
        assert!(
            !at_root.matches(array.projection()),
            "(\"$\", 1) does not match a stored [1]"
        );
        assert!(contains.matches(array.projection()), "jsonb: [1] @> 1");
        assert!(
            serde_json::to_value(&at_root).unwrap().get("alt").is_none(),
            "equality at the root carries no alternative"
        );
    }
}

mod given_an_accessor {
    use super::*;

    #[tokio::test]
    async fn matches_the_value_at_its_path() {
        let Scenario { cipher, plan } = scenario().await;
        let doc = cipher.encrypt(&fixture()).using(&plan).await.unwrap();
        let projection = doc.projection();
        for (path, value, matches, what) in [
            ("$.nested.list[*].x", json!(2), true, "an element's x is 2"),
            ("$.nested.list[*].x", json!(3), false, "no element's x is 3"),
            ("$.nested.deep", json!("constant"), true, "the deep string"),
            ("$.number", json!("1"), false, "a string is not the number"),
        ] {
            let query: JsonQuery = cipher
                .query(op::AtPath(op::Eq), &(path, value))
                .on(&plan)
                .await
                .unwrap();
            assert_eq!(query.matches(projection), matches, "{what}");
        }
    }

    /// An ordering at a path: the path's selector and a leaf term that
    /// orders as the stored leaf's does, under native byte comparison. The
    /// plan declares the paths it orders, and the query runs under them.
    #[tokio::test]
    async fn orders_as_the_stored_leaf_at_an_ordered_path() {
        let Scenario { cipher, .. } = scenario().await;
        let plan = ordered_plan();
        let doc = cipher.encrypt(&fixture()).using(&plan).await.unwrap();
        let number = &doc.entries()[9];
        let bound = cipher
            .query(op::AtPath(op::Gte), &("$.number", 0))
            .on(&plan)
            .await
            .unwrap();
        assert_eq!(
            bound.selector().as_bytes(),
            number.selector(),
            "the bound asks at $.number"
        );
        assert!(
            bound.ordering_term() < number.ordering_term().unwrap(),
            "0 < 1"
        );
        let above = cipher
            .query(op::AtPath(op::Lt), &("$.number", 5))
            .on(&plan)
            .await
            .unwrap();
        assert!(
            above.ordering_term() > number.ordering_term().unwrap(),
            "5 > 1"
        );
        let text = cipher
            .query(op::AtPath(op::Gt), &("$.hello", "world-0"))
            .on(&plan)
            .await
            .unwrap();
        assert!(
            text.ordering_term() < doc.entries()[1].ordering_term().unwrap(),
            "world-0 < world-1"
        );
        let range = cipher
            .query(op::AtPath(op::Between), &("$.number", (0, 5)))
            .on(&plan)
            .await
            .unwrap();
        assert!(
            range.lo().ordering_term() < range.hi().ordering_term(),
            "the range's bounds are in order"
        );
        assert_eq!(
            range.lo().selector().as_bytes(),
            number.selector(),
            "the range asks at $.number"
        );
        let wire = serde_json::to_value(range.lo()).unwrap();
        assert_eq!(
            wire.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["op", "s"],
            "a bound's wire keys"
        );
    }

    /// Refusals, before any term is derived: a text that is not a path, a
    /// leaf kind that has no ordering, and a path the plan does not order
    /// (no stored leaf there carries a term, so the comparison would match
    /// no row; under the default plan that is every path).
    #[tokio::test]
    async fn refuses_a_bad_path_an_unordered_leaf_or_a_path_the_plan_does_not_order() {
        let Scenario {
            cipher,
            plan: default_plan,
        } = scenario().await;
        let plan = ordered_plan();
        let bad_path = cipher
            .query(op::AtPath(op::Eq), &("address.city", "Sydney"))
            .on(&plan)
            .await;
        assertions::refused_by_term(
            &bad_path,
            |e| matches!(e, TermError::JsonPath(_)),
            "a text that is not a path",
        );
        let unordered = cipher
            .query(op::AtPath(op::Gte), &("$.flag", true))
            .on(&plan)
            .await;
        assertions::refused_by_term(
            &unordered,
            |e| matches!(e, TermError::JsonLeafNotOrdered),
            "a boolean has no ordering",
        );
        let not_ordered = cipher
            .query(op::AtPath(op::Lt), &("$.nested.deep", "z"))
            .on(&plan)
            .await;
        assertions::refused_by_term(
            &not_ordered,
            |e| matches!(e, TermError::JsonPathNotOrdered),
            "a path the plan does not order",
        );
        let not_ordered = cipher
            .query(op::AtPath(op::Between), &("$.number", (0, 5)))
            .on(&default_plan)
            .await;
        assertions::refused_by_term(
            &not_ordered,
            |e| matches!(e, TermError::JsonPathNotOrdered),
            "the default plan orders no path",
        );
    }

    /// An ordering at a wildcard path is covered by the wildcard. One at a
    /// position is refused whatever the plan orders: `->` reads a position
    /// as the wildcard and would compare the first element, not the one
    /// named.
    #[tokio::test]
    async fn orders_at_a_wildcard_and_refuses_a_position() {
        let Scenario { cipher, .. } = scenario().await;
        let by_element = Plan::value::<Value>()
            .context("users/profile")
            .encrypt_with_layout(Json::new(ordering(&["$.nested.list[*].x"])))
            .build()
            .unwrap();
        let wildcard = cipher
            .query(op::AtPath(op::Gt), &("$.nested.list[*].x", 0))
            .on(&by_element)
            .await;
        assert!(
            wildcard.is_ok(),
            "the wildcard the plan orders: {wildcard:?}"
        );
        for path in ["$.nested.list[1].x", "$.nested.list[0].x"] {
            let refused = cipher
                .query(op::AtPath(op::Gt), &(path, 0))
                .on(&by_element)
                .await;
            assertions::refused_by_term(
                &refused,
                |e| matches!(e, TermError::JsonOrderingAtPosition),
                &format!("{path} with Gt"),
            );
            let refused = cipher
                .query(op::AtPath(op::Between), &(path, (0, 5)))
                .on(&by_element)
                .await;
            assertions::refused_by_term(
                &refused,
                |e| matches!(e, TermError::JsonOrderingAtPosition),
                &format!("{path} with Between"),
            );
        }
    }

    /// Equality at a path compares one value: an object or an array would
    /// be containment, which `op::Contains` asks for.
    #[tokio::test]
    async fn refuses_a_container_for_equality() {
        let Scenario { cipher, .. } = scenario().await;
        let plan = ordered_plan();
        for container in [json!({"deep": "constant"}), json!([]), json!([{"x": 1}])] {
            let refused = cipher
                .query(op::AtPath(op::Eq), &("$.nested", container.clone()))
                .on(&plan)
                .await;
            assertions::refused_by_term(
                &refused,
                |e| matches!(e, TermError::JsonValueNotScalar),
                &container.to_string(),
            );
        }
    }

    /// An accessor whose path or bounds the index refuses is refused when
    /// the query is awaited, before the keyset it names is loaded; so is an
    /// open that names a context the plan already has.
    #[tokio::test]
    async fn is_refused_before_its_keyset_loads() {
        let (cipher, loads) = common::loads_counting_cipher().await;
        let plan = ordered_plan();
        let eq = cipher
            .query(op::AtPath(op::Eq), &("address.city", "Sydney"))
            .on(&plan)
            .keyset("tenant")
            .await;
        assertions::refused_by_term(
            &eq,
            |e| matches!(e, TermError::JsonPath(_)),
            "Eq at a bad path",
        );
        let between = cipher
            .query(op::AtPath(op::Between), &("address.age", (1, 2)))
            .on(&plan)
            .keyset("tenant")
            .await;
        assertions::refused_by_term(
            &between,
            |e| matches!(e, TermError::JsonPath(_)),
            "Between at a bad path",
        );
        let unordered = cipher
            .query(op::AtPath(op::Between), &("$.flag", (false, true)))
            .on(&plan)
            .keyset("tenant")
            .await;
        assertions::refused_by_term(
            &unordered,
            |e| matches!(e, TermError::JsonLeafNotOrdered),
            "Between over booleans",
        );
        let not_ordered = cipher
            .query(op::AtPath(op::Lt), &("$.nested.deep", "z"))
            .on(&plan)
            .keyset("tenant")
            .await;
        assertions::refused_by_term(
            &not_ordered,
            |e| matches!(e, TermError::JsonPathNotOrdered),
            "a path the plan does not order",
        );
        let at_position = cipher
            .query(op::AtPath(op::Gte), &("$.nested.list[0].x", 1))
            .on(&plan)
            .keyset("tenant")
            .await;
        assertions::refused_by_term(
            &at_position,
            |e| matches!(e, TermError::JsonOrderingAtPosition),
            "an ordering at a position",
        );
        let doc = seal(&stack_cipher().await, &fixture()).await;
        let clash = cipher
            .open(doc.clone())
            .context("users/other")
            .using(&plan)
            .keyset("tenant")
            .await;
        assertions::refused_for_two_contexts(&clash, "one document");
        let clash = cipher
            .open(vec![doc])
            .context("users/other")
            .using(&plan)
            .keyset("tenant")
            .await;
        assertions::refused_for_two_contexts(&clash, "a batch");
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
        assert_eq!(
            loads.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a query the index takes loads the keyset"
        );
    }
}

// =============================================================================
// Plans
// =============================================================================

mod given_a_plan {
    use super::*;

    #[tokio::test]
    async fn refuses_a_query_under_other_options() {
        let Scenario { cipher, plan } = scenario().await;
        let refused = cipher
            .query(op::Contains, &json!({}))
            .via(Json::new(open_root()))
            .on(&plan)
            .await;
        assert!(
            matches!(refused, Err(Error::Plan(PlanError::IndexOptions { .. }))),
            "a query under other options is refused: {refused:?}"
        );
        assert_eq!(
            <JsonDocument as stack_encrypt::EncryptFrom<Value>>::indexes(),
            [IndexSpec::Json(JsonOptions::default())],
            "a JSON document's index is the default JSON index"
        );
        assert_eq!(Json, Json::default(), "the value is the default index");
    }

    #[tokio::test]
    async fn opens_what_it_wrote_as_the_typed_open_does() {
        let Scenario { cipher, plan } = scenario().await;
        let doc = cipher.encrypt(&fixture()).using(&plan).await.unwrap();
        let typed = open(&cipher, doc.clone()).await.unwrap();
        let back: Value = cipher.open(doc).using(&plan).await.unwrap();
        assert_eq!(back, fixture(), "the plan opens what it wrote");
        assert_eq!(back, typed, "and the typed open agrees");
    }
}

mod given_a_laid_out_plan {
    use super::*;

    #[test]
    fn reports_its_layout() {
        let plan = ordered_plan();
        let options = ordering(&["$.hello", "$.number", "$.flag"]);
        assert_eq!(plan.layout().options(), &options, "the layout's options");
        assert_eq!(
            plan.specs(),
            [IndexSpec::Json(options.clone())],
            "the plan's index specs"
        );
        assert_eq!(
            stack_encrypt::target::Layout::<Value>::specs(&Json::new(options.clone())),
            [IndexSpec::Json(options)],
            "the layout's index specs"
        );
        assert!(
            format!("{plan:?}").contains("Laid<stack_encrypt::json::JsonDocument>(Json"),
            "the plan's Debug names its layout: {plan:?}"
        );
    }

    /// A plan laid out by the index opens what it wrote, one document or a
    /// batch.
    #[tokio::test]
    async fn opens_what_it_wrote_one_document_or_a_batch() {
        let Scenario { cipher, .. } = scenario().await;
        let plan = ordered_plan();
        let doc = cipher.encrypt(&fixture()).using(&plan).await.unwrap();
        let back: Value = cipher.open(doc.clone()).using(&plan).await.unwrap();
        assert_eq!(back, fixture(), "one document");
        let docs: Vec<Value> = cipher
            .open(vec![doc.clone(), doc])
            .using(&plan)
            .await
            .unwrap();
        assert_eq!(docs, [fixture(), fixture()], "a batch");
    }

    /// The plan was built with its context, so an open that names one is
    /// refused, one document or a batch, before any key is requested.
    #[tokio::test]
    async fn refuses_an_open_that_names_another_context() {
        let Scenario { cipher, .. } = scenario().await;
        let plan = ordered_plan();
        let doc = cipher.encrypt(&fixture()).using(&plan).await.unwrap();
        let clash = cipher
            .open(doc.clone())
            .context("users/other")
            .using(&plan)
            .await;
        assertions::refused_for_two_contexts(&clash, "one document");
        let clash = cipher
            .open(vec![doc])
            .context("users/other")
            .using(&plan)
            .await;
        assertions::refused_for_two_contexts(&clash, "a batch");
    }

    /// The index named on the query says only which: the plan's own, with
    /// its options, answers.
    #[tokio::test]
    async fn answers_a_named_index_with_its_own_options() {
        let Scenario { cipher, .. } = scenario().await;
        let plan = ordered_plan();
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
        assert_eq!(
            through_default.selector(),
            chosen.selector(),
            "the default index named on the query answers as the plan's own"
        );
    }
}

#[cfg(feature = "dynamic")]
mod given_the_json_index_spec {
    use super::*;

    /// The spec's wire form is a fixed contract with stored data and the Go
    /// guest, so its strings are pinned literally.
    #[test]
    fn has_a_wire_form() {
        use stack_encrypt::dynamic::{not_admitted, Reason, ValueKind};
        assert_eq!(
            IndexSpec::parse("json"),
            Some(IndexSpec::Json(JsonOptions::default())),
            "`json` parses as the default index"
        );
        assert_eq!(
            IndexSpec::Json(JsonOptions::default()).key(),
            "json",
            "the default index's key"
        );
        assert_eq!(
            serde_json::to_value(IndexSpec::Json(JsonOptions::default())).unwrap(),
            json!("json"),
            "the default index is written as its key"
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
            IndexSpec::Json(open_root()),
            "an option read from a frame"
        );
        let frame = vitaminc_aead_frame::serde::to_vec(&json!({"json": {"nope": true}})).unwrap();
        assert!(
            IndexSpec::from_frame(&frame).is_err(),
            "an unknown option refuses the index"
        );
        // The ordered paths ride in `ordered`, written in their canonical
        // order and read back parsed; a text that is not a path refuses the
        // index.
        let ordered = IndexSpec::Json(ordering(&["$.orders[*].total", "$.age", "$.age"]));
        assert_eq!(
            serde_json::to_value(&ordered).unwrap(),
            json!({"json": {"sealed_root": true, "ordered": ["$.age", "$.orders[*].total"]}}),
            "ordered paths are written once, in canonical order"
        );
        let frame = vitaminc_aead_frame::serde::to_vec(
            &json!({"json": {"ordered": ["$.age", "$.orders[*].total"]}}),
        )
        .unwrap();
        assert_eq!(
            IndexSpec::from_frame(&frame).unwrap(),
            ordered,
            "ordered paths read back parsed"
        );
        let frame =
            vitaminc_aead_frame::serde::to_vec(&json!({"json": {"ordered": ["age"]}})).unwrap();
        assert!(
            IndexSpec::from_frame(&frame).is_err(),
            "a text that is not a path refuses the index"
        );
        // A position in an ordered path refuses the index too: no ordering
        // can reach the leaf it names.
        let frame =
            vitaminc_aead_frame::serde::to_vec(&json!({"json": {"ordered": ["$.scores[2]"]}}))
                .unwrap();
        assert!(
            IndexSpec::from_frame(&frame).is_err(),
            "a position in an ordered path refuses the index"
        );
        assert_eq!(
            not_admitted(ValueKind::Object, &IndexSpec::Json(JsonOptions::default())),
            Some(Reason::JsonIndexPending),
            "the data plan does not admit the JSON index yet"
        );
    }
}

// =============================================================================
// Assertions
// =============================================================================

mod assertions {
    use std::fmt::Debug;

    use super::*;

    pub(super) fn one_entry_per_node(doc: &JsonDocument, value: &Value, what: &str) {
        assert_eq!(
            doc.entries().len(),
            nodes(value),
            "{what}: one entry per node"
        );
    }

    pub(super) async fn opens_to(cipher: &Cipher, doc: JsonDocument, expected: &Value, what: &str) {
        let opened = open(cipher, doc).await;
        assert!(
            matches!(&opened, Ok(value) if value == expected),
            "{what}: should open to {expected}, opened {opened:?}"
        );
    }

    /// `result` is the term error `is` picks out.
    pub(super) fn refused_by_term<T: Debug>(
        result: &Result<T, Error>,
        is: impl Fn(&TermError) -> bool,
        what: &str,
    ) {
        assert!(
            matches!(result, Err(Error::Term(error)) if is(error)),
            "{what}: refused with the wrong outcome: {result:?}"
        );
    }

    /// `result` is a shape mismatch, naming `expected` when one is given.
    pub(super) fn refused_as_opened_type<T: Debug>(
        result: &Result<T, Error>,
        expected: Option<&str>,
        what: &str,
    ) {
        assert!(
            matches!(result, Err(Error::OpenedType { expected: got }) if expected.is_none_or(|e| e == *got)),
            "{what}: should be refused as a shape mismatch expecting {expected:?}, got {result:?}"
        );
    }

    /// `result` is tamper evidence: the authentication failed.
    pub(super) fn refused_as_tampered<T: Debug>(result: &Result<T, Error>, what: &str) {
        assert!(
            matches!(result, Err(Error::Aead)),
            "{what}: should fail authentication, got {result:?}"
        );
    }

    /// `result` is the refusal of an open that names a second context.
    pub(super) fn refused_for_two_contexts<T: Debug>(result: &Result<T, Error>, what: &str) {
        assert!(
            matches!(
                result,
                Err(Error::Plan(PlanError::TwoContextSources { .. }))
            ),
            "{what}: an open naming another context should be refused, got {result:?}"
        );
    }

    /// `@>` over the projections is the model's `jsonb @>`.
    pub(super) fn contains_as_jsonb(
        query: &JsonQuery,
        doc: &JsonDocument,
        stored: &Value,
        needle: &Value,
    ) {
        assert_eq!(
            query.matches(doc.projection()),
            pg_contains(stored, needle, true),
            "{stored} @> {needle}"
        );
    }

    /// `<@` is the model's `jsonb <@`, but for a stored root scalar in a
    /// needle root array.
    pub(super) fn is_contained_by_as_jsonb(
        query: &JsonQuery,
        doc: &JsonDocument,
        stored: &Value,
        needle: &Value,
    ) {
        assert_eq!(
            query.projection().contains(doc.projection()),
            pg_contains(needle, stored, true) && !scalar_in_array(stored, needle),
            "{stored} <@ {needle}"
        );
    }

    /// Every feature the generator is meant to cover appears in `docs`.
    pub(super) fn covers_every_feature(docs: &[Value]) {
        #[derive(Debug, Default)]
        struct Census {
            root_objects: usize,
            root_arrays: usize,
            root_scalars: usize,
            empty_objects: usize,
            empty_arrays: usize,
            arrays_of_objects: usize,
            arrays_of_arrays: usize,
            duplicate_elements: usize,
            keys_on_two_levels: usize,
            float_spelled_integers: usize,
            numeric_strings: usize,
            booleans: usize,
            nulls: usize,
            max_depth: usize,
        }
        fn walk<'v>(
            census: &mut Census,
            v: &'v Value,
            depth: usize,
            keys: &mut std::collections::BTreeMap<&'v str, std::collections::BTreeSet<usize>>,
        ) {
            census.max_depth = census.max_depth.max(depth);
            match v {
                Value::Object(map) => {
                    census.empty_objects += usize::from(map.is_empty());
                    for (key, member) in map {
                        let _ = keys.entry(key).or_default().insert(depth);
                        walk(census, member, depth + 1, keys);
                    }
                }
                Value::Array(items) => {
                    census.empty_arrays += usize::from(items.is_empty());
                    census.arrays_of_objects += usize::from(items.iter().any(Value::is_object));
                    census.arrays_of_arrays += usize::from(items.iter().any(Value::is_array));
                    census.duplicate_elements += usize::from(
                        items
                            .iter()
                            .enumerate()
                            .any(|(i, a)| items[i + 1..].contains(a)),
                    );
                    for item in items {
                        walk(census, item, depth + 1, keys);
                    }
                }
                Value::Number(n) => {
                    census.float_spelled_integers +=
                        usize::from(n.is_f64() && n.as_f64().is_some_and(|f| f.fract() == 0.0));
                }
                Value::String(s) => census.numeric_strings += usize::from(s.parse::<f64>().is_ok()),
                Value::Bool(_) => census.booleans += 1,
                Value::Null => census.nulls += 1,
            }
        }
        let mut census = Census::default();
        for doc in docs {
            match doc {
                Value::Object(_) => census.root_objects += 1,
                Value::Array(_) => census.root_arrays += 1,
                _ => census.root_scalars += 1,
            }
            let mut keys = std::collections::BTreeMap::new();
            walk(&mut census, doc, 0, &mut keys);
            census.keys_on_two_levels += usize::from(
                keys.values()
                    .any(|depths: &std::collections::BTreeSet<usize>| depths.len() > 1),
            );
        }
        for (what, count) in [
            ("root objects", census.root_objects),
            ("root arrays", census.root_arrays),
            ("root scalars", census.root_scalars),
            ("empty objects", census.empty_objects),
            ("empty arrays", census.empty_arrays),
            ("arrays of objects", census.arrays_of_objects),
            ("arrays of arrays", census.arrays_of_arrays),
            ("duplicate array elements", census.duplicate_elements),
            ("a key on two levels", census.keys_on_two_levels),
            ("integers spelled as floats", census.float_spelled_integers),
            ("strings spelled as numbers", census.numeric_strings),
            ("booleans", census.booleans),
            ("nulls", census.nulls),
        ] {
            assert!(
                count > 0,
                "the generated documents should hold {what}: {census:?}"
            );
        }
        assert!(
            census.max_depth >= 4,
            "the generated documents should nest at least four levels: {census:?}"
        );
    }
}
