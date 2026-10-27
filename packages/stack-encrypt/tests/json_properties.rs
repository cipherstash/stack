//! Properties of the JSON index's reads over random documents, with no
//! database: the rows the server's read returns are modelled by
//! `JsonDocument::subtree`, the Rust twin of `json_tree_subtree`, and
//! opened through the key, as a caller opens what PostgreSQL returns.
//!
//! - **Metamorphic.** A read of `$.a` with `.b` applied on the client is the
//!   read of `$.a.b`; a read of `$` (the open root walked, the sealed root
//!   opened whole) with any path applied is the read of that path; `->` and
//!   the read agree on every scalar; the reads of the top-level paths
//!   reassemble the document; a node's children are its child count.
//! - **Independence.** Selectors, the entry layout and the tokens follow
//!   from the shape and the keys alone, not from the values or the `iv`;
//!   the stored tags and ciphertexts of two rows are all distinct.
//! - **What a read sends.** The tokens a key sends are exactly those of
//!   the concrete paths its path names, below the bound, and the probes, and
//!   no token of a node above them.
//! - **What a row stores.** `x` on every entry, `p` on every entry but the
//!   root and the heads, under either root option; the entries in a random
//!   order that is a permutation of the nodes with the root at slot 0.
//! - **Placement and tampering.** The rows of a read open to the same value
//!   in any order they arrive in; and any one row changed, dropped,
//!   repeated or misreported is refused, with the error that names how.

mod common;

use std::collections::BTreeSet;

use common::stack_cipher;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use serde_json::{json, Map, Value};
use stack_encrypt::json::{
    JsonDocument, JsonExtracted, JsonNode, JsonOptions, JsonPath, JsonSubtree, Segment,
};
use stack_encrypt::target::{AeadContext, CallerContext};
use stack_encrypt::{nonempty, Error, StackCipher};
use stack_kms::FakeDataKeySource;

type Cipher = StackCipher<FakeDataKeySource>;

/// `proptest!` generates synchronous `#[test]` functions and runs each body
/// once per case through a plain closure, so `#[tokio::test]` cannot wrap a
/// property; each test builds one runtime and `block_on`s its cases.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn aead() -> AeadContext {
    AeadContext::from(nonempty!("users").with("profile"))
}

fn options(sealed_root: bool) -> JsonOptions {
    JsonOptions {
        sealed_root,
        ..JsonOptions::new()
    }
}

async fn seal(cipher: &Cipher, value: &Value, options: &JsonOptions) -> JsonDocument {
    cipher
        .default_keyset()
        .run(
            stack_encrypt::target::json_document::<_, stack_encrypt::target::Borrowed>(
                options.clone(),
            ),
            value,
            CallerContext::from(nonempty!("users").with("profile")),
        )
        .await
        .expect("seals")
}

async fn key(
    cipher: &Cipher,
    path: &JsonPath,
    options: &JsonOptions,
    bound: u32,
) -> stack_encrypt::json::JsonSubtreeKey {
    cipher
        .default_keyset()
        .json_subtree_key_with_bound(path, options, bound, nonempty!("users").with("profile"))
        .await
        .unwrap()
}

/// The rows the server's read returns for `key`, in full.
fn rows(doc: &JsonDocument, key: &stack_encrypt::json::JsonSubtreeKey) -> Vec<JsonNode> {
    doc.subtree(&key.token_bytes())
        .iter()
        .map(|(j, _, d)| with_depth(doc, *j, *d))
        .collect()
}

fn with_depth(doc: &JsonDocument, j: usize, d: u32) -> JsonNode {
    let mut wire = serde_json::to_value(doc.node(j).unwrap()).unwrap();
    wire["d"] = json!(d);
    serde_json::from_value(wire).unwrap()
}

/// The read of `path` in `doc`, as `Option<Value>`.
async fn read(
    cipher: &Cipher,
    doc: &JsonDocument,
    path: &JsonPath,
    options: &JsonOptions,
) -> Option<Value> {
    let key = key(cipher, path, options, 4).await;
    cipher
        .decrypt_as::<Option<Value>, JsonSubtree>(key.open(rows(doc, &key)), aead())
        .await
        .unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// Every node's path in `value`, depth first, the root first, members in
/// key order. The index stores the nodes in a random order instead; a node's
/// slot is found by its path's token ([`slot`]).
fn node_paths(value: &Value) -> Vec<JsonPath> {
    fn visit(value: &Value, at: &JsonPath, out: &mut Vec<JsonPath>) {
        out.push(at.clone());
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    visit(child, &append(at, &Segment::Key(key.clone())), out);
                }
            }
            Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    visit(child, &append(at, &Segment::Index(i as u64)), out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    visit(value, &JsonPath::root(), &mut out);
    out
}

/// The slot the node at the concrete `path` is stored at, found by the
/// self tag of the path's token, as the server finds it.
async fn slot(
    cipher: &Cipher,
    doc: &JsonDocument,
    path: &JsonPath,
    options: &JsonOptions,
) -> Option<usize> {
    let k = key(cipher, path, options, 0).await;
    doc.find(&k.token_bytes()[0]).map(|(j, _)| j)
}

/// `items` in the order a Fisher–Yates shuffle driven by `seed` puts them:
/// any permutation, reproducibly from the case.
fn permuted<T>(mut items: Vec<T>, seed: u64) -> Vec<T> {
    let mut state = seed | 1;
    for i in (1..items.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        items.swap(i, (state % (i as u64 + 1)) as usize);
    }
    items
}

fn append(at: &JsonPath, step: &Segment) -> JsonPath {
    let text = match step {
        Segment::Key(key) => format!("[{}]", serde_json::to_string(key).unwrap()),
        Segment::Index(i) => format!("[{i}]"),
        Segment::Wildcard => "[*]".to_owned(),
    };
    JsonPath::parse(&format!("{at}{text}")).unwrap()
}

/// Keys that stress the path encoding, beside ordinary ones: the empty key,
/// unicode, the characters a path spells steps with, quotes and
/// backslashes, and `"0"`, which must never meet the index 0.
fn key_name() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just("0".to_owned()),
        Just("a.b".to_owned()),
        Just("[*]".to_owned()),
        Just("]".to_owned()),
        Just("$".to_owned()),
        Just("\"\\".to_owned()),
        Just("é✓".to_owned()),
        "[a-c]{1,2}",
    ]
}

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        any::<u64>().prop_map(|n| json!(n)),
        Just(json!(2.0)),
        Just(json!(-0.0)),
        Just(json!(1e30)),
        // Quarters are exact in binary and in decimal. An arbitrary `f64`
        // can come back one unit in the last place off: the stored text is
        // parsed by serde_json without `float_roundtrip`, a defect of its
        // own and not of the reads these properties are about.
        (-4_000_000i32..4_000_000).prop_map(|n| json!(f64::from(n) / 4.0)),
        "[a-z ]{0,6}".prop_map(Value::String),
    ]
}

fn document() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(4, 40, 5, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            prop::collection::btree_map(key_name(), inner, 0..5)
                .prop_map(|m| Value::Object(m.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

/// `value` with every scalar replaced by another, the shape and the keys
/// kept.
fn revalue(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            Value::Object(map.iter().map(|(k, v)| (k.clone(), revalue(v))).collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(revalue).collect()),
        Value::String(s) => json!(format!("{s}~")),
        Value::Number(_) => json!("a number once"),
        Value::Bool(b) => json!(!b),
        Value::Null => json!(0),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// Every path's read is the value `jsonb` holds there (modelled by
    /// `JsonPath::select`), and the reads of the root's children reassemble
    /// the document.
    #[test]
    fn the_reads_of_every_path_reassemble_the_document(value in document(), sealed in any::<bool>()) {
        let rt = runtime();
        rt.block_on(async {
            let cipher = stack_cipher().await;
            let options = options(sealed);
            let doc = seal(&cipher, &value, &options).await;
            for path in node_paths(&value) {
                let expected = path.select(&value).first().cloned().cloned();
                prop_assert_eq!(read(&cipher, &doc, &path, &options).await, expected, "{}", path);
            }
            let rebuilt = match &value {
                Value::Object(map) => {
                    let mut out = Map::new();
                    for key in map.keys() {
                        let path = append(&JsonPath::root(), &Segment::Key(key.clone()));
                        let _ = out.insert(key.clone(), read(&cipher, &doc, &path, &options).await.unwrap());
                    }
                    Value::Object(out)
                }
                Value::Array(items) => {
                    let mut out = Vec::new();
                    for i in 0..items.len() {
                        let path = append(&JsonPath::root(), &Segment::Index(i as u64));
                        out.push(read(&cipher, &doc, &path, &options).await.unwrap());
                    }
                    Value::Array(out)
                }
                scalar => read(&cipher, &doc, &JsonPath::root(), &options).await.unwrap_or(scalar.clone()),
            };
            prop_assert_eq!(rebuilt, value);
            Ok(())
        })?;
    }

    /// A read of a node with a step applied on the client is the read of the
    /// longer path; a read of `$` with any path applied is the read of that
    /// path. Under the sealed root `$` comes back as the root alone and
    /// opens whole; under an open root it is walked.
    #[test]
    fn a_read_then_a_step_is_the_read_of_the_longer_path(value in document(), sealed in any::<bool>()) {
        let rt = runtime();
        rt.block_on(async {
            let cipher = stack_cipher().await;
            let options = options(sealed);
            let doc = seal(&cipher, &value, &options).await;
            let whole = read(&cipher, &doc, &JsonPath::root(), &options).await;
            prop_assert_eq!(whole.as_ref(), Some(&value), "`$` is the document");
            for path in node_paths(&value) {
                let direct = read(&cipher, &doc, &path, &options).await;
                let from_root = path.select(whole.as_ref().unwrap()).first().cloned().cloned();
                prop_assert_eq!(&direct, &from_root, "{} from `$`", path);
                if let Some((last, parent)) = path.segments().split_last() {
                    let parent_path = parent.iter().fold(JsonPath::root(), |at, s| append(&at, s));
                    let above = read(&cipher, &doc, &parent_path, &options).await;
                    let stepped = above.and_then(|v| append(&JsonPath::root(), last).select(&v).first().cloned().cloned());
                    prop_assert_eq!(direct, stepped, "{} from its parent", path);
                }
            }
            Ok(())
        })?;
    }

    /// `->`, which returns the first entry at a selector, and the read agree
    /// on every scalar at a path with no position; and the children the
    /// server enumerates under a node are its child count, none under a
    /// scalar.
    #[test]
    fn the_arrow_and_the_children_agree_with_the_read(value in document()) {
        let rt = runtime();
        rt.block_on(async {
            let cipher = stack_cipher().await;
            let options = options(false);
            let doc = seal(&cipher, &value, &options).await;
            for path in node_paths(&value) {
                let node = path.select(&value)[0].clone();
                let k = key(&cipher, &path, &options, 4).await;
                let children = doc.children(&k.token_bytes()[0]).len();
                let count = match &node {
                    Value::Object(m) => m.len(),
                    Value::Array(a) => a.len(),
                    _ => 0,
                };
                prop_assert_eq!(children, count, "{} children", path);
                let positional = path.segments().iter().any(|s| matches!(s, Segment::Index(_)));
                if positional || node.is_object() || node.is_array() {
                    continue;
                }
                let selector = cipher
                    .default_keyset()
                    .json_selector(&path, nonempty!("users").with("profile"))
                    .await
                    .unwrap();
                let j = doc.entries().iter().position(|e| e.selector() == selector.as_bytes()).unwrap();
                let arrow = cipher
                    .decrypt_as::<Value, JsonExtracted>(selector.open(doc.node(j).unwrap()), aead())
                    .await
                    .unwrap();
                prop_assert_eq!(Some(arrow), read(&cipher, &doc, &path, &options).await, "{}", path);
            }
            Ok(())
        })?;
    }

    /// Two rows of one shape and one set of keys, with different values and
    /// different data keys: the same selectors (each in its own random
    /// order), every path's token finding the node at that path in both, and
    /// no self tag, parent tag or ciphertext in common.
    #[test]
    fn selectors_and_tokens_follow_the_shape_alone(value in document(), sealed in any::<bool>()) {
        let rt = runtime();
        rt.block_on(async {
            let cipher = stack_cipher().await;
            let options = options(sealed);
            let one = seal(&cipher, &value, &options).await;
            let two = seal(&cipher, &revalue(&value), &options).await;
            prop_assert_ne!(one.header().iv(), two.header().iv());
            let s = |d: &JsonDocument| {
                let mut s = d.entries().iter().map(|e| *e.selector()).collect::<Vec<_>>();
                s.sort_unstable();
                s
            };
            prop_assert_eq!(s(&one), s(&two), "the same multiset of selectors");
            for path in node_paths(&value) {
                let (a, b) = (
                    slot(&cipher, &one, &path, &options).await,
                    slot(&cipher, &two, &path, &options).await,
                );
                let (Some(a), Some(b)) = (a, b) else {
                    return Err(TestCaseError::fail(format!("{path} found in both rows")));
                };
                prop_assert_eq!(one.entries()[a].selector(), two.entries()[b].selector(), "{}", path);
            }
            let mut tags = BTreeSet::new();
            let mut total = 0;
            for doc in [&one, &two] {
                for e in doc.entries() {
                    total += 1 + usize::from(e.parent_tag().is_some());
                    let _ = tags.insert(e.self_tag().to_vec());
                    if let Some(p) = e.parent_tag() {
                        let _ = tags.insert(p.to_vec());
                    }
                }
            }
            prop_assert_eq!(tags.len(), total, "every stored tag distinct");
            let cs: BTreeSet<Vec<u8>> = one.entries().iter().chain(two.entries()).map(|e| e.ciphertext().to_vec()).collect();
            prop_assert_eq!(cs.len(), one.entries().len() * 2, "every ciphertext distinct");
            Ok(())
        })?;
    }

    /// `x` on every entry, `p` on every entry but the root and the heads;
    /// and the entries are a permutation of the nodes, the root at slot 0.
    #[test]
    fn every_entry_carries_a_self_tag_and_only_the_heads_lack_a_parent_tag(value in document(), sealed in any::<bool>()) {
        let rt = runtime();
        rt.block_on(async {
            let cipher = stack_cipher().await;
            let options = options(sealed);
            let doc = seal(&cipher, &value, &options).await;
            let wire = serde_json::to_value(&doc).unwrap();
            let sv = wire["sv"].as_array().unwrap();
            let paths = node_paths(&value);
            prop_assert_eq!(sv.len(), paths.len(), "one entry per node");
            let mut slots = Vec::new();
            for path in &paths {
                let Some(j) = slot(&cipher, &doc, path, &options).await else {
                    return Err(TestCaseError::fail(format!("{path} is stored")));
                };
                slots.push(j);
                let entry = &sv[j];
                prop_assert!(entry.get("x").is_some(), "entry {} has x", j);
                let head = path.segments().is_empty() || (sealed && path.segments().len() == 1);
                prop_assert_eq!(entry.get("p").is_none(), head, "entry {} ({}): p absent only on a head", j, path);
            }
            prop_assert_eq!(slots[0], 0, "the root at slot 0");
            slots.sort_unstable();
            prop_assert_eq!(slots, (0..paths.len()).collect::<Vec<_>>(), "a permutation of the slots");
            Ok(())
        })?;
    }

    /// The rows of a read open to the same value whatever order they arrive
    /// in: the client places them by the chain, not by their slots or their
    /// order.
    #[test]
    fn a_reads_rows_open_in_any_order(value in document(), sealed in any::<bool>(), pick in any::<prop::sample::Index>(), seed in any::<u64>()) {
        let rt = runtime();
        rt.block_on(async {
            let cipher = stack_cipher().await;
            let options = options(sealed);
            let doc = seal(&cipher, &value, &options).await;
            let paths = node_paths(&value);
            let path = &paths[pick.index(paths.len())];
            let k = key(&cipher, path, &options, 4).await;
            let shuffled = permuted(rows(&doc, &k), seed);
            let opened = cipher
                .decrypt_as::<Option<Value>, JsonSubtree>(k.open(shuffled), aead())
                .await
                .unwrap_or_else(|error| panic!("{path}: {error}"));
            prop_assert_eq!(opened, path.select(&value).first().cloned().cloned(), "{}", path);
            Ok(())
        })?;
    }

    /// Any one row of the read of the whole document (the root open, so the
    /// read walks every entry) changed, dropped, repeated or misreported is
    /// refused, with the refusal that says how: a changed ciphertext or a
    /// dropped child by the cipher, since a parent's ciphertext commits to
    /// its children's tags; a dropped root by the rows no read reaches; a
    /// repeated row before any key is retrieved; a wrong depth by the depth
    /// check.
    #[test]
    fn any_one_tampered_row_is_refused(value in document(), pick in any::<prop::sample::Index>(), how in 0u8..4, byte in any::<prop::sample::Index>()) {
        let rt = runtime();
        rt.block_on(async {
            let cipher = stack_cipher().await;
            let options = options(false);
            let doc = seal(&cipher, &value, &options).await;
            let k = key(&cipher, &JsonPath::root(), &options, 4).await;
            let mut rows = rows(&doc, &k);
            let at = pick.index(rows.len());
            let top = at == 0;
            let mut wire = serde_json::to_value(&rows[at]).unwrap();
            let expected = match how {
                0 => {
                    // One byte of the ciphertext, the tag's included, changed.
                    let c = wire["c"].as_str().unwrap().to_owned();
                    let mut bytes = c.into_bytes();
                    // Lowered to base85's zero digit, so the group it sits
                    // in still decodes: the first character from a random
                    // place on that is not zero already.
                    let start = byte.index(bytes.len());
                    let i = (0..bytes.len())
                        .map(|k| (start + k) % bytes.len())
                        .find(|&i| bytes[i] != b'0')
                        .unwrap();
                    bytes[i] = b'0';
                    wire["c"] = json!(String::from_utf8(bytes).unwrap());
                    rows[at] = serde_json::from_value(wire).unwrap();
                    "aead"
                }
                1 => {
                    let _ = rows.remove(at);
                    if top && rows.is_empty() {
                        // Nothing returned: the database's word that the
                        // row has no node there (ADR 0010).
                        "none"
                    } else if top {
                        "rows the walked paths reach"
                    } else {
                        "aead"
                    }
                }
                2 => {
                    let copy = rows[at].clone();
                    rows.push(copy);
                    "rows of distinct entries"
                }
                _ => {
                    wire["d"] = json!(wire["d"].as_u64().unwrap() + 1);
                    rows[at] = serde_json::from_value(wire).unwrap();
                    "a row at the depth the chain gives it"
                }
            };
            let opened = cipher
                .decrypt_as::<Option<Value>, JsonSubtree>(k.open(rows), aead())
                .await;
            match (expected, opened) {
                ("aead", Err(Error::Aead)) | ("none", Ok(None)) => {}
                (expected, Err(Error::JsonWrongEntry { expected: got })) if got == expected => {}
                (expected, got) => {
                    return Err(TestCaseError::fail(format!("row {at}, tamper {how}: expected {expected}, got {got:?}")));
                }
            }
            Ok(())
        })?;
    }

    /// A member's selector, and its token, are the same whatever its
    /// siblings are.
    #[test]
    fn a_members_selector_and_token_ignore_its_siblings(
        left in prop::collection::btree_map(key_name(), leaf(), 0..8),
        right in prop::collection::btree_map(key_name(), leaf(), 0..8),
    ) {
        let rt = runtime();
        rt.block_on(async {
            let cipher = stack_cipher().await;
            let row = |siblings: &std::collections::BTreeMap<String, Value>| {
                let mut a: Map<String, Value> = siblings.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                let _ = a.insert("member".into(), json!({"leaf": 1}));
                json!({"a": a})
            };
            let path = JsonPath::parse("$.a.member.leaf").unwrap();
            let k = key(&cipher, &path, &options(true), 4).await;
            let mut found = Vec::new();
            for siblings in [&left, &right] {
                let doc = seal(&cipher, &row(siblings), &options(true)).await;
                let (j, entry) = doc.find(&k.token_bytes()[0]).expect("found by its token");
                found.push(*entry.selector());
                prop_assert_eq!(read(&cipher, &doc, &path, &options(true)).await, Some(json!(1)));
                prop_assert!(j > 0);
            }
            prop_assert_eq!(found[0], found[1]);
            Ok(())
        })?;
    }

    /// The tokens a read sends are exactly the tokens of the concrete paths
    /// its path names below the bound and of its probes, in document order,
    /// and none of a node above them; a path with no wildcard sends one. The
    /// tokens are checked against a witness document holding every concrete
    /// path and one element past the bound at every wildcard: each token
    /// must find the node at its path there, by the stored self tag.
    #[test]
    fn a_key_sends_exactly_the_tokens_of_the_paths_it_names(
        steps in prop::collection::vec(prop_oneof![
            key_name().prop_map(Segment::Key),
            (0u64..3).prop_map(Segment::Index),
            Just(Segment::Wildcard),
        ], 0..4),
        bound in 0u32..3,
        sealed in any::<bool>(),
    ) {
        let rt = runtime();
        rt.block_on(async {
            let cipher = stack_cipher().await;
            let options = options(sealed);
            let n = bound as usize;
            fn witness(steps: &[Segment], n: usize) -> Value {
                let Some((step, rest)) = steps.split_first() else { return json!(0) };
                match step {
                    Segment::Key(k) => json!({ k.clone(): witness(rest, n) }),
                    Segment::Index(i) => Value::Array((0..=*i).map(|_| witness(rest, n)).collect()),
                    Segment::Wildcard => Value::Array((0..=n).map(|_| witness(rest, n)).collect()),
                }
            }
            /// Every concrete path the read names, in document order, and
            /// whether it is a probe.
            fn named(steps: &[Segment], at: JsonPath, n: usize, out: &mut Vec<(JsonPath, bool)>) {
                let Some((step, rest)) = steps.split_first() else { out.push((at, false)); return };
                match step {
                    Segment::Wildcard => {
                        for i in 0..n {
                            named(rest, append(&at, &Segment::Index(i as u64)), n, out);
                        }
                        out.push((append(&at, &Segment::Index(n as u64)), true));
                    }
                    other => named(rest, append(&at, other), n, out),
                }
            }
            let value = witness(&steps, n);
            let path = steps.iter().fold(JsonPath::root(), |at, s| append(&at, s));
            let doc = seal(&cipher, &value, &options).await;
            let paths = node_paths(&value);
            let k = key(&cipher, &path, &options, bound).await;
            let mut expected = Vec::new();
            named(&steps, JsonPath::root(), n, &mut expected);
            prop_assert_eq!(k.tokens().len(), expected.len(), "one token per concrete path");
            let probes: Vec<usize> = expected.iter().enumerate().filter(|(_, (_, p))| *p).map(|(i, _)| i).collect();
            prop_assert_eq!(k.probes(), probes);
            if path.is_positional() {
                prop_assert_eq!(k.tokens().len(), 1, "no wildcard, one token");
            }
            let found: Vec<usize> = k
                .token_bytes()
                .iter()
                .map(|t| doc.find(t).map(|(j, _)| j).expect("every token names a node of the witness"))
                .collect();
            // Where each node of the witness is stored, by its own path's
            // key: the slots are random, so the read's tokens are checked
            // against the nodes the paths name, not against positions.
            let mut stored = std::collections::BTreeMap::new();
            for p in &paths {
                let _ = stored.insert(p.clone(), slot(&cipher, &doc, p, &options).await.unwrap());
            }
            let at: Vec<usize> = expected.iter().map(|(q, _)| stored[q]).collect();
            prop_assert_eq!(&found, &at, "each token finds the node at its path");
            for (q, _) in &expected {
                for len in 0..q.segments().len() {
                    let ancestor = q.segments()[..len].iter().fold(JsonPath::root(), |a, s| append(&a, s));
                    let j = stored[&ancestor];
                    prop_assert!(!found.contains(&j), "no token of {}, above {}", ancestor, q);
                }
            }
            // The parameter the SQL takes is the base64 of exactly these.
            let sent: Value = serde_json::to_value(&k).unwrap();
            prop_assert_eq!(sent, json!({"t": k.tokens()}));
            Ok(())
        })?;
    }
}

/// A wildcard read of a document whose array is at the bound minus one,
/// at it, or one past it: exact, exact, and the bound's error, never part
/// of the list, read in full and fallen back to the sealed root alike.
#[tokio::test]
async fn a_wildcard_read_fails_past_its_bound_and_only_there() {
    let cipher = stack_cipher().await;
    let path = JsonPath::parse("$.items[*].x").unwrap();
    for bound in [1u32, 3, 64] {
        let k = key(&cipher, &path, &options(true), bound).await;
        for len in [bound as usize - 1, bound as usize, bound as usize + 1] {
            let value = json!({"items": (0..len).map(|i| json!({"x": i})).collect::<Vec<_>>()});
            let doc = seal(&cipher, &value, &options(true)).await;
            let root = with_depth(&doc, 0, 0);
            for rows in [rows(&doc, &k), vec![root]] {
                let opened = cipher
                    .decrypt_as::<Vec<Value>, JsonSubtree>(k.open(rows), aead())
                    .await;
                if len > bound as usize {
                    assert!(
                        matches!(opened, Err(Error::JsonWildcardTruncated { bound: b }) if b == bound),
                        "{len} past {bound}: {opened:?}"
                    );
                } else {
                    assert_eq!(
                        opened.unwrap(),
                        (0..len).map(|i| json!(i)).collect::<Vec<_>>(),
                        "{len} within {bound}"
                    );
                }
            }
        }
    }
}

/// The stored size the self tag costs. Each entry gains `,"x":"…"`, twelve
/// characters of base64 and seven of framing, on entries of about two
/// hundred characters: about ten percent. The bounds are the measured
/// ratios on these two shapes with a margin, so a change that grows the
/// stored form further fails here before a benchmark notices.
#[tokio::test]
async fn the_self_tag_costs_about_a_tenth_of_the_stored_size() {
    let cipher = stack_cipher().await;
    let nested = json!({
        "number": 1,
        "hello": "h1",
        "orders": (0..12).map(|k| json!({
            "id": k, "total": k * 7,
            "items": (0..5).map(|m| json!({"sku": format!("s{m}"), "qty": m, "gift": m == 0})).collect::<Vec<_>>()
        })).collect::<Vec<_>>()
    });
    let flat = json!({"number": 1, "hello": "h1", "flag": true});
    for (name, value, low, high) in [("nested", nested, 0.08, 0.12), ("flat", flat, 0.07, 0.12)] {
        let doc = seal(&cipher, &value, &options(true)).await;
        let wire = serde_json::to_value(&doc).unwrap();
        let with_x = wire.to_string().len();
        let mut without = wire.clone();
        for entry in without["sv"].as_array_mut().unwrap() {
            let _ = entry.as_object_mut().unwrap().remove("x");
        }
        let without_x = without.to_string().len();
        let growth = with_x as f64 / without_x as f64 - 1.0;
        eprintln!(
            "{name}: {without_x} -> {with_x} characters, +{:.1}%",
            growth * 100.0
        );
        assert!(
            (low..high).contains(&growth),
            "{name}: the self tag adds {:.1}% where {:.0}% to {:.0}% was measured",
            growth * 100.0,
            low * 100.0,
            high * 100.0
        );
    }
}

/// The stored order is drawn afresh for every document: ten seals of one
/// ten-node document do not all store it alike, while each keeps the root
/// at slot 0. (Two seals agree with probability 1/9!, so ten all agreeing
/// is never seen.)
/// An object's members get a fresh random permutation of ordinals each
/// time the document is sealed: the children a token enumerates come back
/// in another order from seal to seal, and always as the whole object.
#[tokio::test]
async fn every_seal_draws_its_own_member_ordinals() {
    let cipher = stack_cipher().await;
    let value = json!({"a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6});
    let options = options(false);
    let root = key(&cipher, &JsonPath::root(), &options, 1).await;
    let mut orders = BTreeSet::new();
    for _ in 0..10 {
        let doc = seal(&cipher, &value, &options).await;
        let children = doc.children(&root.token_bytes()[0]);
        assert_eq!(children.len(), 6, "every member at an ordinal from 0 to 5");
        let order: Vec<Vec<u8>> = children
            .iter()
            .map(|(_, entry, _)| entry.selector().to_vec())
            .collect();
        let _ = orders.insert(order);
    }
    assert!(orders.len() > 1, "ten seals, one member order: {orders:?}");
}

#[tokio::test]
async fn every_seal_draws_its_own_order() {
    let cipher = stack_cipher().await;
    let value =
        json!({"hello": "w", "nested": {"deep": "c", "list": [{"x": 1}, {"x": 2}]}, "number": 1});
    let options = options(true);
    let mut orders = BTreeSet::new();
    for _ in 0..10 {
        let doc = seal(&cipher, &value, &options).await;
        let mut order = Vec::new();
        for path in node_paths(&value) {
            order.push(slot(&cipher, &doc, &path, &options).await.unwrap());
        }
        assert_eq!(order[0], 0, "the root at slot 0");
        let _ = orders.insert(order);
    }
    assert!(orders.len() > 1, "ten seals, one order: {orders:?}");
}
