//! What the client checks when it opens the rows a JSON index read
//! returned, with no database: the entry `->` returns must carry the
//! selector the client derived for the path, and every row of a subtree
//! walk must sit where the key that keyed the walk says its rows are.
//! Each entry's ciphertext is bound to its own selector and position, so
//! without these checks any entry of the row would open in place of the one
//! asked for.
//!
//! The rows here are built as the SQL returns them (the entry, the header
//! and the ordinal grafted, and a walk's depth), from a sealed document, so
//! every entry in them is genuine. What varies is which entries a dishonest
//! database hands back.

mod common;

use std::sync::atomic::Ordering;

use common::CountingSource;
use serde_json::{json, Value};
use stack_encrypt::json::{
    JsonDocument, JsonExtracted, JsonNode, JsonOptions, JsonPath, JsonSelector, JsonSubtree,
    JsonSubtreeKey,
};
use stack_encrypt::target::{AeadContext, CallerContext};
use stack_encrypt::{nonempty, Error, StackCipher};

type Cipher = StackCipher<CountingSource>;

async fn cipher() -> (Cipher, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let source = CountingSource::new();
    let (_, retrieved) = source.counters();
    let cipher = StackCipher::builder()
        .kms(source)
        .init()
        .await
        .expect("build cipher");
    (cipher, retrieved)
}

fn aead() -> AeadContext {
    AeadContext::from(nonempty!("users").with("profile"))
}

/// `$`, `hello` (1), `nested` (2), `deep` (3), `list` (4), its elements (5,
/// 7) and their `x` (6, 8), `number` (9): depth-first, members in key order.
fn fixture() -> Value {
    json!({"hello": "world-1", "nested": {"deep": "constant", "list": [{"x": 1}, {"x": 2}]}, "number": 1})
}

async fn seal(cipher: &Cipher, value: &Value) -> JsonDocument {
    cipher
        .default_keyset()
        .encrypt_as::<Value, JsonDocument>(
            value,
            CallerContext::from(nonempty!("users").with("profile")),
        )
        .await
        .expect("seals")
}

async fn selector(cipher: &Cipher, path: &str) -> JsonSelector {
    cipher
        .default_keyset()
        .json_selector(
            &JsonPath::parse(path).unwrap(),
            nonempty!("users").with("profile"),
        )
        .await
        .unwrap()
}

async fn key(cipher: &Cipher, path: &str) -> JsonSubtreeKey {
    key_with(cipher, path, &JsonOptions::default()).await
}

async fn key_with(cipher: &Cipher, path: &str, options: &JsonOptions) -> JsonSubtreeKey {
    cipher
        .default_keyset()
        .json_subtree_key(
            &JsonPath::parse(path).unwrap(),
            options,
            nonempty!("users").with("profile"),
        )
        .await
        .unwrap()
}

async fn seal_with(cipher: &Cipher, value: &Value, options: &JsonOptions) -> JsonDocument {
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

/// The options with the root not sealed.
fn open_root() -> JsonOptions {
    JsonOptions {
        sealed_root: false,
        ..JsonOptions::new()
    }
}

/// The entry at `j` as an extractor returns it, at depth `d` when a walk
/// returned it.
fn row(doc: &JsonDocument, j: usize, d: Option<u32>) -> JsonNode {
    let mut wire = serde_json::to_value(doc.node(j).unwrap()).unwrap();
    if let Some(d) = d {
        wire["d"] = json!(d);
    }
    serde_json::from_value(wire).unwrap()
}

/// The rows the SQL walk returns for `key`, walked as it walks: with no
/// gates, every descendant of the token's node from depth 1; with gates,
/// through each gate (a selector, or `#n:<selector>`), then each node the
/// gates reach at depth 0 with everything beneath it.
fn walk(doc: &JsonDocument, key: &JsonSubtreeKey) -> Vec<JsonNode> {
    let gates = key.gates();
    if gates.is_empty() {
        return doc
            .subtree(key.token_bytes())
            .iter()
            .map(|(j, _, d)| row(doc, *j, Some(*d)))
            .collect();
    }
    let mut frontier = vec![(None, *key.token_bytes())];
    for gate in &gates {
        let mut next = Vec::new();
        for (_, token) in &frontier {
            let children = doc.children(token);
            match gate.strip_prefix('#') {
                Some(slot) => {
                    let (n, wanted) = slot.split_once(':').unwrap();
                    if let Some((j, entry, t)) = children.get(n.parse::<usize>().unwrap()) {
                        if base64(entry.selector()) == wanted {
                            next.push((Some(*j), *t));
                        }
                    }
                }
                None => next.extend(
                    children
                        .iter()
                        .filter(|(_, entry, _)| base64(entry.selector()) == *gate)
                        .map(|(j, _, t)| (Some(*j), *t)),
                ),
            }
        }
        frontier = next;
    }
    let mut rows = Vec::new();
    for (j, token) in frontier {
        rows.push(row(doc, j.unwrap(), Some(0)));
        rows.extend(
            doc.subtree(&token)
                .iter()
                .map(|(j, _, d)| row(doc, *j, Some(*d))),
        );
    }
    rows
}

fn base64(bytes: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(bytes)
}

async fn open_extracted(cipher: &Cipher, extracted: JsonExtracted) -> Result<Value, Error> {
    cipher
        .decrypt_as::<Value, JsonExtracted>(extracted, aead())
        .await
}

async fn open_value(cipher: &Cipher, rows: JsonSubtree) -> Result<Value, Error> {
    cipher.decrypt_as::<Value, JsonSubtree>(rows, aead()).await
}

async fn open_list(cipher: &Cipher, rows: JsonSubtree) -> Result<Vec<Value>, Error> {
    cipher
        .decrypt_as::<Vec<Value>, JsonSubtree>(rows, aead())
        .await
}

mod assertions {
    use super::*;

    /// The read was refused as the wrong entry, naming `expected`.
    pub(crate) fn wrong_entry<T: std::fmt::Debug>(result: Result<T, Error>, expected: &str) {
        match result {
            Err(Error::JsonWrongEntry { expected: got }) => {
                assert_eq!(got, expected, "the refusal names what the read expected")
            }
            other => panic!("expected JsonWrongEntry ({expected}), got {other:?}"),
        }
    }
}

mod given_the_entry_arrow_returned {
    use super::*;

    #[tokio::test]
    async fn the_entry_at_the_path_opens_to_its_scalar() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let hello = selector(&cipher, "$.hello").await;
        let opened = open_extracted(&cipher, hello.open(row(&doc, 1, None))).await;
        assert_eq!(opened.unwrap(), json!("world-1"), "the value at the path");
    }

    #[tokio::test]
    async fn another_paths_entry_is_refused_before_any_key_is_retrieved() {
        let (cipher, retrieved) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let hello = selector(&cipher, "$.hello").await;
        // `$.number` is a genuine entry of the row, and opens on its own
        // selector: the database answered `$.hello` with it.
        let extracted = hello.open(row(&doc, 9, None));
        assert_eq!(extracted.selector(), hello, "the selector asked for");
        assert_eq!(extracted.node().ordinal(), 9, "the row as returned");
        assert_wrong(open_extracted(&cipher, extracted).await);
        assert_eq!(
            retrieved.load(Ordering::SeqCst),
            0,
            "the refusal retrieved no key"
        );
    }

    #[tokio::test]
    async fn the_sealed_root_is_refused_in_place_of_a_node() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let hello = selector(&cipher, "$.hello").await;
        // The sealed root opens to the whole document: every field, for a
        // read of one.
        assert_wrong(open_extracted(&cipher, hello.open(row(&doc, 0, None))).await);
    }

    #[tokio::test]
    async fn the_sealed_root_opens_when_the_root_was_asked_for() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let root = selector(&cipher, "$").await;
        let opened = open_extracted(&cipher, root.open(row(&doc, 0, None))).await;
        assert_eq!(opened.unwrap(), fixture(), "`$` is the whole document");
    }

    #[tokio::test]
    async fn an_entry_relabelled_with_the_selector_asked_for_fails_to_open() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let hello = selector(&cipher, "$.hello").await;
        // Passing the check by rewriting `s` breaks the ciphertext's
        // binding to its own selector instead.
        let mut wire = serde_json::to_value(doc.node(9).unwrap()).unwrap();
        wire["s"] = json!(hello.to_string());
        let relabelled: JsonNode = serde_json::from_value(wire).unwrap();
        let opened = open_extracted(&cipher, hello.open(relabelled)).await;
        assert!(matches!(opened, Err(Error::Aead)), "{opened:?}");
    }

    #[tokio::test]
    async fn any_element_at_the_path_opens_since_a_selector_reads_a_position_as_the_wildcard() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let second = selector(&cipher, "$.nested.list[1].x").await;
        // `->` returns the first element at the path; the selector cannot
        // say which position was meant.
        let opened = open_extracted(&cipher, second.open(row(&doc, 6, None))).await;
        assert_eq!(opened.unwrap(), json!(1), "the first element's x");
    }

    #[tokio::test]
    async fn the_same_path_from_another_row_opens_by_design() {
        let (cipher, _) = cipher().await;
        let other = seal(&cipher, &json!({"hello": "world-2"})).await;
        let hello = selector(&cipher, "$.hello").await;
        // Row provenance is the database's word (ADR 0010): an entry
        // returned with its own row's header opens.
        let opened = open_extracted(&cipher, hello.open(row(&other, 1, None))).await;
        assert_eq!(opened.unwrap(), json!("world-2"), "another row's value");
    }

    fn assert_wrong(result: Result<Value, Error>) {
        assertions::wrong_entry(result, "the entry at the path asked for");
    }
}

mod given_the_rows_of_a_walk_without_gates {
    use super::*;

    const CHILD: &str = "a child of the walked node";
    const NEXT: &str = "the next node of the walked subtree";

    #[tokio::test]
    async fn the_honest_rows_open_to_the_nodes_value() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        assert!(nested.gates().is_empty(), "a chain head's token");
        let rows = walk(&doc, &nested);
        assert_eq!(rows.len(), 6, "nested's descendants");
        let value = open_value(&cipher, nested.open(rows.clone())).await;
        assert_eq!(value.unwrap(), fixture()["nested"], "the sub-document");
        let list = open_list(&cipher, nested.open(rows)).await;
        assert_eq!(
            list.unwrap(),
            vec![json!("constant"), json!([{"x": 1}, {"x": 2}])],
            "the members' values"
        );
    }

    #[tokio::test]
    async fn the_rows_of_another_field_of_the_same_shape_are_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &json!({"a": {"x": 1}, "b": {"x": 2}})).await;
        let a = key(&cipher, "$.a").await;
        let b = key(&cipher, "$.b").await;
        // The database answers `$.a` with `$.b`'s subtree: one genuine
        // member, in its place, but under `$.b`'s path.
        let refused = open_value(&cipher, a.open(walk(&doc, &b))).await;
        assertions::wrong_entry(refused, CHILD);
    }

    #[tokio::test]
    async fn a_row_of_another_path_spliced_in_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        // `number` (9) sits right after nested's subtree in the document,
        // so it follows the rows without a gap; its selector is not a
        // member of nested's.
        let mut rows = walk(&doc, &nested);
        rows.push(row(&doc, 9, Some(1)));
        let refused = open_value(&cipher, nested.open(rows)).await;
        assertions::wrong_entry(refused, CHILD);
    }

    #[tokio::test]
    async fn a_dropped_row_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        // The first element (5) is dropped, so its `x` (6) would be taken
        // for the element itself.
        let rows: Vec<JsonNode> = walk(&doc, &nested)
            .into_iter()
            .filter(|n| n.ordinal() != 5)
            .collect();
        let refused = open_value(&cipher, nested.open(rows)).await;
        assertions::wrong_entry(refused, NEXT);
    }

    #[tokio::test]
    async fn a_row_reported_at_the_wrong_depth_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        let rows: Vec<JsonNode> = walk(&doc, &nested)
            .into_iter()
            .map(|n| {
                if n.ordinal() == 6 {
                    row(&doc, 6, Some(1))
                } else {
                    n
                }
            })
            .collect();
        let refused = open_value(&cipher, nested.open(rows)).await;
        assertions::wrong_entry(refused, NEXT);
    }

    #[tokio::test]
    async fn a_member_reported_at_the_wrong_depth_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        let rows: Vec<JsonNode> = walk(&doc, &nested)
            .into_iter()
            .map(|n| {
                if n.ordinal() == 3 {
                    row(&doc, 3, Some(2))
                } else {
                    n
                }
            })
            .collect();
        let refused = open_value(&cipher, nested.open(rows)).await;
        assertions::wrong_entry(refused, CHILD);
    }

    #[tokio::test]
    async fn an_orphan_whose_parent_was_left_out_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        // `deep` (3) and then the second element's `x` (8) alone: its
        // parent and everything between are missing.
        let rows = vec![row(&doc, 3, Some(1)), row(&doc, 8, Some(3))];
        let refused = open_value(&cipher, nested.open(rows)).await;
        assertions::wrong_entry(refused, CHILD);
    }

    #[tokio::test]
    async fn a_gap_between_two_members_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &json!({"a": {"x": 1, "y": {"z": 2}, "w": 3}})).await;
        let a = key(&cipher, "$.a").await;
        // `$.a`'s members are w (2), x (3) and y (4) with z (5) below: the
        // database leaves x out, and w and y are each genuine members.
        let rows: Vec<JsonNode> = walk(&doc, &a)
            .into_iter()
            .filter(|n| n.ordinal() != 3)
            .collect();
        let refused = open_value(&cipher, a.open(rows)).await;
        assertions::wrong_entry(refused, CHILD);
    }

    #[tokio::test]
    async fn the_deepest_document_the_index_seals_opens_from_the_open_root() {
        let (cipher, _) = cipher().await;
        // 127 arrays: the innermost scalar 127 levels below the root, the
        // deepest the index seals.
        let mut value = json!(1);
        for _ in 0..127 {
            value = json!([value]);
        }
        let doc = seal_with(&cipher, &value, &open_root()).await;
        let root = key_with(&cipher, "$", &open_root()).await;
        let rows = walk(&doc, &root);
        assert_eq!(rows.len(), 127, "every node below the root");
        let opened = open_value(&cipher, root.open(rows)).await;
        assert_eq!(opened.unwrap(), value, "the whole document");
    }

    #[tokio::test]
    async fn rows_with_no_reported_depth_are_placed_by_the_document() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        // The depth is the database's report; the rows' positions and the
        // opened nodes place them, so rows without it open the same.
        let rows: Vec<JsonNode> = walk(&doc, &nested)
            .iter()
            .map(|n| row(&doc, n.ordinal() as usize, None))
            .collect();
        let value = open_value(&cipher, nested.open(rows)).await;
        assert_eq!(value.unwrap(), fixture()["nested"], "the sub-document");
    }
}

mod given_the_rows_of_a_gated_walk {
    use super::*;

    const REACHED: &str = "a node the walked path reaches";

    #[tokio::test]
    async fn the_honest_rows_open_to_the_reached_nodes() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let second = key(&cipher, "$.nested.list[1]").await;
        let value = open_value(&cipher, second.open(walk(&doc, &second))).await;
        assert_eq!(value.unwrap(), json!({"x": 2}), "the second element");
        let xs = key(&cipher, "$.nested.list[*].x").await;
        let values = open_list(&cipher, xs.open(walk(&doc, &xs))).await;
        assert_eq!(values.unwrap(), vec![json!(1), json!(2)], "every x");
    }

    #[tokio::test]
    async fn another_position_of_the_array_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let second = key(&cipher, "$.nested.list[1]").await;
        // The first element carries the same selector as the second: the
        // position in its label tells them apart.
        let first = key(&cipher, "$.nested.list[0]").await;
        let refused = open_value(&cipher, second.open(walk(&doc, &first))).await;
        assertions::wrong_entry(refused, REACHED);
    }

    #[tokio::test]
    async fn a_node_of_another_path_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let xs = key(&cipher, "$.nested.list[*].x").await;
        let refused = open_list(&cipher, xs.open(vec![row(&doc, 3, Some(0))])).await;
        assertions::wrong_entry(refused, REACHED);
    }

    #[tokio::test]
    async fn a_descendant_left_without_its_reached_node_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let list = key(&cipher, "$.nested.list").await;
        // The list's own row is dropped: what is left are its children,
        // which the gated walk does not return on their own.
        let rows: Vec<JsonNode> = walk(&doc, &list)
            .into_iter()
            .filter(|n| n.ordinal() != 4)
            .collect();
        let refused = open_value(&cipher, list.open(rows)).await;
        assertions::wrong_entry(refused, REACHED);
    }

    #[tokio::test]
    async fn a_reached_node_reported_below_depth_zero_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let xs = key(&cipher, "$.nested.list[*].x").await;
        let refused = open_list(&cipher, xs.open(vec![row(&doc, 6, Some(1))])).await;
        assertions::wrong_entry(refused, REACHED);
    }

    #[tokio::test]
    async fn the_sealed_root_among_walked_rows_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let list = key(&cipher, "$.nested.list").await;
        // The root at depth 1 is not the fallback, and its selector is not
        // the list's.
        let mut rows = walk(&doc, &list);
        rows.push(row(&doc, 0, Some(1)));
        let refused = open_value(&cipher, list.open(rows)).await;
        assertions::wrong_entry(refused, REACHED);
    }
}
