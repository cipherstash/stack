//! What the client checks when it opens the rows a JSON index read
//! returned, with no database: the entry `->` returns must carry the
//! selector the client derived for the path, and the rows of a subtree read
//! must be the subtree of the node the key's token names. The cascade
//! refuses, at the cipher ([`Error::Aead`]), any change to the rows beneath
//! that node: a row swapped, dropped, added, reordered or moved under
//! another parent changes a tag on the way up. The client's own checks
//! ([`Error::JsonWrongEntry`]) refuse the rest: a repeated row, a row no
//! read reaches, a reported depth the chain does not give, a self tag no
//! rule derives, and a node at the top of a read whose selector or label is
//! not its path's.
//!
//! The rows here are built as the SQL returns them (the entry, the header
//! and the slot grafted, and a walk's depth), from a sealed document, so
//! every entry in them is genuine unless a test rewrites a tag. Entries are
//! stored in a random order, so a test finds a node's row by its path
//! ([`slot`]), never by a fixed slot number.

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

/// `$`, `hello`, `nested`, `nested.deep`, `nested.list`, its two elements
/// and their `x`, and `number`: ten nodes, stored in a random order.
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

/// The slot the node at the concrete `path` is stored at, found as the
/// server finds it: by the self tag of the path's token.
async fn slot(cipher: &Cipher, doc: &JsonDocument, path: &str) -> usize {
    slot_with(cipher, doc, path, &JsonOptions::default()).await
}

async fn slot_with(
    cipher: &Cipher,
    doc: &JsonDocument,
    path: &str,
    options: &JsonOptions,
) -> usize {
    let key = key_with(cipher, path, options).await;
    doc.find(&key.token_bytes()[0])
        .unwrap_or_else(|| panic!("the document has {path}"))
        .0
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

/// The rows `json_tree_subtree(doc, key.tokens(), 0)` returns for `key`,
/// read as the SQL reads them: for each token, the node it names at depth
/// 0 and everything beneath it.
fn walk(doc: &JsonDocument, key: &JsonSubtreeKey) -> Vec<JsonNode> {
    doc.subtree(&key.token_bytes())
        .iter()
        .map(|(j, _, d)| row(doc, *j, Some(*d)))
        .collect()
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

    /// The read was refused by the cipher: some node did not open under the
    /// digest of the children the chain gave it, or under its own AAD.
    pub(crate) fn aead<T: std::fmt::Debug>(result: Result<T, Error>) {
        assert!(
            matches!(result, Err(Error::Aead)),
            "expected Aead, got {result:?}"
        );
    }
}

mod given_the_entry_arrow_returned {
    use super::*;

    #[tokio::test]
    async fn the_entry_at_the_path_opens_to_its_scalar() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let hello = selector(&cipher, "$.hello").await;
        let at = slot(&cipher, &doc, "$.hello").await;
        let opened = open_extracted(&cipher, hello.open(row(&doc, at, None))).await;
        assert_eq!(opened.unwrap(), json!("world-1"), "the value at the path");
    }

    #[tokio::test]
    async fn another_paths_entry_is_refused_before_any_key_is_retrieved() {
        let (cipher, retrieved) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let hello = selector(&cipher, "$.hello").await;
        // `$.number` is a genuine entry of the row, and opens on its own
        // selector: the database answered `$.hello` with it.
        let number = slot(&cipher, &doc, "$.number").await;
        let extracted = hello.open(row(&doc, number, None));
        assert_eq!(extracted.selector(), hello, "the selector asked for");
        assert_eq!(
            extracted.node().slot(),
            number as u64,
            "the row as returned"
        );
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
        let number = slot(&cipher, &doc, "$.number").await;
        let mut wire = serde_json::to_value(doc.node(number).unwrap()).unwrap();
        wire["s"] = json!(hello.to_string());
        let relabelled: JsonNode = serde_json::from_value(wire).unwrap();
        let opened = open_extracted(&cipher, hello.open(relabelled)).await;
        assert!(matches!(opened, Err(Error::JsonNotALeaf)), "{opened:?}");
    }

    #[tokio::test]
    async fn any_element_at_the_path_opens_since_a_selector_reads_a_position_as_the_wildcard() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let second = selector(&cipher, "$.nested.list[1].x").await;
        // `->` returns whichever element at the path the stored order puts
        // first; the selector cannot say which position was meant.
        let first = slot(&cipher, &doc, "$.nested.list[0].x").await;
        let opened = open_extracted(&cipher, second.open(row(&doc, first, None))).await;
        assert_eq!(opened.unwrap(), json!(1), "the first element's x");
    }

    /// A container's entry is sealed over its children's tags, which `->`
    /// does not return: alone it does not open, and since nothing outside
    /// the ciphertext says it is a container, the refusal names that and
    /// tampering as the two causes rather than claiming one. An empty
    /// container opens, and holds no value of its own.
    #[tokio::test]
    async fn a_container_does_not_open_alone() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &json!({"full": {"a": 1}, "empty": {}})).await;
        let full = selector(&cipher, "$.full").await;
        let at = slot(&cipher, &doc, "$.full").await;
        let opened = open_extracted(&cipher, full.open(row(&doc, at, None))).await;
        assert!(matches!(opened, Err(Error::JsonNotALeaf)), "{opened:?}");
        let empty = selector(&cipher, "$.empty").await;
        let at = slot(&cipher, &doc, "$.empty").await;
        let opened = open_extracted(&cipher, empty.open(row(&doc, at, None))).await;
        assert!(
            matches!(opened, Err(Error::OpenedType { .. })),
            "{opened:?}"
        );
    }

    #[tokio::test]
    async fn the_same_path_from_another_row_opens_by_design() {
        let (cipher, _) = cipher().await;
        let other = seal(&cipher, &json!({"hello": "world-2"})).await;
        let hello = selector(&cipher, "$.hello").await;
        // Row provenance is the database's word (ADR 0010): an entry
        // returned with its own row's header opens.
        let at = slot(&cipher, &other, "$.hello").await;
        let opened = open_extracted(&cipher, hello.open(row(&other, at, None))).await;
        assert_eq!(opened.unwrap(), json!("world-2"), "another row's value");
    }

    fn assert_wrong(result: Result<Value, Error>) {
        assertions::wrong_entry(result, "the entry at the path asked for");
    }
}

mod given_the_rows_of_a_read {
    use super::*;

    const REACHED: &str = "a node the walked path reaches";
    const UNREACHED: &str = "rows the walked paths reach";
    const DEPTH: &str = "a row at the depth the chain gives it";
    const RULE: &str = "a child the member or element rule names";

    #[tokio::test]
    async fn the_honest_rows_open_to_the_nodes_value_in_any_order() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        let rows = walk(&doc, &nested);
        assert_eq!(rows.len(), 7, "nested and its descendants");
        let value = open_value(&cipher, nested.open(rows.clone())).await;
        assert_eq!(value.unwrap(), fixture()["nested"], "the sub-document");
        let list = open_list(&cipher, nested.open(rows.clone())).await;
        assert_eq!(
            list.unwrap(),
            vec![fixture()["nested"].clone()],
            "one node, one value"
        );
        // The rows are placed by the chain, not by the order they arrive in.
        let mut reversed = rows.clone();
        reversed.reverse();
        let mut by_slot = rows;
        by_slot.sort_by_key(JsonNode::slot);
        for rows in [reversed, by_slot] {
            let value = open_value(&cipher, nested.open(rows)).await;
            assert_eq!(value.unwrap(), fixture()["nested"]);
        }
    }

    /// The database answers `$.a` with `$.b`'s subtree: genuine entries,
    /// under `$.b`'s path. As they are, no row carries the self tag of the
    /// token the read sent; with `$.b`'s self tag rewritten to `$.a`'s, the
    /// chain finds no children of `$.a` among them, so `$.b` does not open
    /// under the digest of no children; and a leaf `$.b` that does open
    /// carries `$.b`'s selector, not `$.a`'s.
    #[tokio::test]
    async fn the_rows_of_another_field_are_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &json!({"a": {"x": 1}, "b": {"x": 2}})).await;
        let a = key(&cipher, "$.a").await;
        let b = key(&cipher, "$.b").await;
        assertions::wrong_entry(open_value(&cipher, a.open(walk(&doc, &b))).await, UNREACHED);
        let forged = with_x(walk(&doc, &b), 0, x_of(&doc, &a));
        assertions::aead(open_value(&cipher, a.open(forged)).await);

        let doc = seal(&cipher, &json!({"a": 1, "b": 2})).await;
        let forged = with_x(walk(&doc, &b), 0, x_of(&doc, &a));
        assertions::wrong_entry(open_value(&cipher, a.open(forged)).await, REACHED);
    }

    /// The first element carries the same selector as the second, and here
    /// the second's self tag: its decrypted position tells them apart. A
    /// container element in its place is refused before that, by the
    /// cascade, since the chain finds none of its children under the second
    /// element's token.
    #[tokio::test]
    async fn another_position_of_the_array_is_refused_by_its_label() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &json!({"arr": [10, 20]})).await;
        let second = key(&cipher, "$.arr[1]").await;
        let first = key(&cipher, "$.arr[0]").await;
        let forged = with_x(walk(&doc, &first), 0, x_of(&doc, &second));
        assertions::wrong_entry(open_value(&cipher, second.open(forged)).await, REACHED);

        let doc = seal(&cipher, &fixture()).await;
        let second = key(&cipher, "$.nested.list[1]").await;
        let first = key(&cipher, "$.nested.list[0]").await;
        let forged = with_x(walk(&doc, &first), 0, x_of(&doc, &second));
        assertions::aead(open_value(&cipher, second.open(forged)).await);
    }

    #[tokio::test]
    async fn a_node_no_token_names_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let hello = key(&cipher, "$.hello").await;
        // `$.hello`'s own entry with another self tag: the database walked
        // from a token the read did not send.
        let forged = with_x(walk(&doc, &hello), 0, "AAAAAAAAAAA=".into());
        assertions::wrong_entry(open_value(&cipher, hello.open(forged)).await, UNREACHED);
    }

    #[tokio::test]
    async fn one_token_answered_twice_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let xs = key(&cipher, "$.nested.list[*].x").await;
        // Both x, the second carrying the first's self tag: the first
        // token's read takes one of them, and the other is reached by no
        // token the read sent.
        let rows = walk(&doc, &xs);
        assert_eq!(rows.len(), 2, "both x");
        let first = serde_json::to_value(&rows[0]).unwrap()["x"]
            .as_str()
            .unwrap()
            .to_owned();
        let forged = with_x(rows, 1, first);
        assertions::wrong_entry(open_list(&cipher, xs.open(forged)).await, UNREACHED);
    }

    #[tokio::test]
    async fn an_entry_returned_twice_is_refused_before_any_key_is_retrieved() {
        let (cipher, retrieved) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        // nested's rows with one of them returned twice: a genuine entry at
        // its own slot, which would let the database line one container up
        // as often as it likes. An honest database never returns one, so it
        // is the wrong entry, not a shape.
        let mut rows = walk(&doc, &nested);
        rows.insert(2, rows[1].clone());
        assertions::wrong_entry(
            open_value(&cipher, nested.open(rows)).await,
            "rows of distinct entries",
        );
        assert_eq!(
            retrieved.load(Ordering::SeqCst),
            0,
            "the refusal retrieved no key"
        );
    }

    #[tokio::test]
    async fn rows_of_two_documents_are_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let other = seal(&cipher, &fixture()).await;
        let xs = key(&cipher, "$.nested.list[*].x").await;
        // The first x from this row and the second from another, each with
        // its own row's header. Either row's answer alone opens (ADR 0010),
        // but a read is of one row, and its rows of two are not the answer
        // to it.
        let rows = vec![walk(&doc, &xs)[0].clone(), walk(&other, &xs)[1].clone()];
        assertions::wrong_entry(
            open_list(&cipher, xs.open(rows)).await,
            "rows of one document",
        );
    }

    #[tokio::test]
    async fn a_child_with_a_forged_self_tag_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        let deep = slot(&cipher, &doc, "$.nested.deep").await;
        let rows = walk(&doc, &nested);
        let at = rows.iter().position(|n| n.slot() == deep as u64).unwrap();
        let forged = with_x(rows, at, "AAAAAAAAAAA=".into());
        assertions::wrong_entry(open_value(&cipher, nested.open(forged)).await, RULE);
    }

    /// A member whose self tag is rewritten to the one the element rule
    /// derives at its ordinal: the server would take it for an element, and
    /// so would the chain, but its decrypted label is a key.
    #[tokio::test]
    async fn a_child_under_the_other_rule_is_refused_by_its_label() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &json!({"a": {"k": 1}})).await;
        let a = key(&cipher, "$.a").await;
        let k = slot(&cipher, &doc, "$.a.k").await;
        let s = selector_bytes(&selector(&cipher, "$.a.k").await);
        let as_element = chain::element_token(&a.token_bytes()[0], &s, 0);
        let rows = walk(&doc, &a);
        let at = rows.iter().position(|n| n.slot() == k as u64).unwrap();
        let forged = with_x(
            rows,
            at,
            base64(&chain::self_tag(doc.header().iv(), &as_element)),
        );
        assertions::wrong_entry(
            open_value(&cipher, a.open(forged)).await,
            "a child under the rule its label names",
        );
    }

    #[tokio::test]
    async fn a_row_of_another_path_added_to_the_answer_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        // `number`, a genuine entry no token the read sent reaches.
        let number = slot(&cipher, &doc, "$.number").await;
        for d in [Some(1), None] {
            let mut rows = walk(&doc, &nested);
            rows.push(row(&doc, number, d));
            assertions::wrong_entry(open_value(&cipher, nested.open(rows)).await, UNREACHED);
        }
    }

    /// `number`, a genuine entry, with its parent tag and self tag rewritten
    /// to make it a third element of `nested.list`: the chain takes it for
    /// one, and the list, sealed over two, does not open.
    #[tokio::test]
    async fn an_added_child_is_refused_by_the_cascade() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        let list = key(&cipher, "$.nested.list").await;
        // The server derives a hit's token from the hit's own selector.
        let s = selector_bytes(&selector(&cipher, "$.number").await);
        let iv = doc.header().iv();
        let third = chain::element_token(&list.token_bytes()[0], &s, 2);
        let number = slot(&cipher, &doc, "$.number").await;
        let mut wire = serde_json::to_value(row(&doc, number, Some(2))).unwrap();
        wire["x"] = json!(base64(&chain::self_tag(iv, &third)));
        wire["p"] = json!(base64(&chain::parent_tag(iv, &list.token_bytes()[0], 2)));
        let mut rows = walk(&doc, &nested);
        rows.push(serde_json::from_value(wire).unwrap());
        assertions::aead(open_value(&cipher, nested.open(rows)).await);
    }

    #[tokio::test]
    async fn a_dropped_child_is_refused_by_the_cascade() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        // The first element is dropped: the list's children are then
        // probed from ordinal 0 and none is found, and its x is reached by
        // nothing.
        let first = slot(&cipher, &doc, "$.nested.list[0]").await;
        let rows = without(walk(&doc, &nested), first);
        assertions::aead(open_value(&cipher, nested.open(rows)).await);
    }

    #[tokio::test]
    async fn a_truncated_subtree_is_refused_by_the_cascade() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        // The deepest node of the last element left out: the element says
        // nothing of it in a position, but its ciphertext commits to its
        // child's tag.
        let last = slot(&cipher, &doc, "$.nested.list[1].x").await;
        let rows = without(walk(&doc, &nested), last);
        assertions::aead(open_value(&cipher, nested.open(rows)).await);
    }

    #[tokio::test]
    async fn a_gap_between_two_members_is_refused_by_the_cascade() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &json!({"a": {"x": 1, "y": {"z": 2}, "w": 3}})).await;
        let a = key(&cipher, "$.a").await;
        // The database leaves `x` out; `w` and `y` are each genuine members.
        let x = slot(&cipher, &doc, "$.a.x").await;
        let rows = without(walk(&doc, &a), x);
        assertions::aead(open_value(&cipher, a.open(rows)).await);
    }

    /// The two elements of `nested.list` with their parent tags and self
    /// tags exchanged: the chain finds each at the other's ordinal, under
    /// the rule its self tag now names, and the list, sealed over its
    /// elements in order, does not open.
    #[tokio::test]
    async fn reordered_children_are_refused_by_the_cascade() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let list = key(&cipher, "$.nested.list").await;
        let first = slot(&cipher, &doc, "$.nested.list[0]").await;
        let second = slot(&cipher, &doc, "$.nested.list[1]").await;
        let rows = exchange_tags(walk(&doc, &list), first, second);
        assertions::aead(open_value(&cipher, list.open(rows)).await);
    }

    /// The design's substitution (decision 8): a read of `$.nested.list[0]`
    /// answered with the element itself and then the other element's `x` in
    /// place of its own, carrying its own `x`'s self tag and parent tag.
    /// Every element's `x` shares one selector, the label is `x` either way,
    /// the depth and the parent's child count agree, and the forged tags
    /// match; the element's ciphertext, which commits to its own `x`'s tag,
    /// is the one thing that refuses it. Opened, it would read `{"x": 2}`
    /// for `{"x": 1}`.
    #[tokio::test]
    async fn another_elements_child_in_place_of_the_nodes_own_is_refused_by_the_cascade() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let first = key(&cipher, "$.nested.list[0]").await;
        let element = slot(&cipher, &doc, "$.nested.list[0]").await;
        let own = slot(&cipher, &doc, "$.nested.list[0].x").await;
        let other = slot(&cipher, &doc, "$.nested.list[1].x").await;
        let honest = walk(&doc, &first);
        assert_eq!(
            honest.iter().map(JsonNode::slot).collect::<Vec<_>>(),
            [element as u64, own as u64],
            "the element and its x"
        );
        assert_eq!(
            open_value(&cipher, first.open(honest)).await.unwrap(),
            json!({"x": 1})
        );
        let swapped = vec![
            row(&doc, element, Some(0)),
            with_tags_of(&doc, row(&doc, other, Some(1)), own),
        ];
        assertions::aead(open_value(&cipher, first.open(swapped)).await);
    }

    /// The `x` of the two elements, each moved under the other's element:
    /// each element's ciphertext commits to its own child's tag.
    #[tokio::test]
    async fn a_child_moved_under_another_parent_is_refused_by_the_cascade() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let list = key(&cipher, "$.nested.list").await;
        let own = slot(&cipher, &doc, "$.nested.list[0].x").await;
        let other = slot(&cipher, &doc, "$.nested.list[1].x").await;
        let rows = exchange_tags(walk(&doc, &list), own, other);
        assertions::aead(open_value(&cipher, list.open(rows)).await);
    }

    /// Two rows of the subtree with their ciphertexts exchanged: each now
    /// opens under the other's selector and slot.
    #[tokio::test]
    async fn swapped_entries_are_refused_by_the_cipher() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        let deep = slot(&cipher, &doc, "$.nested.deep").await;
        let x = slot(&cipher, &doc, "$.nested.list[0].x").await;
        let mut rows = walk(&doc, &nested);
        let (i, k) = (
            rows.iter().position(|n| n.slot() == deep as u64).unwrap(),
            rows.iter().position(|n| n.slot() == x as u64).unwrap(),
        );
        let mut a = serde_json::to_value(&rows[i]).unwrap();
        let mut b = serde_json::to_value(&rows[k]).unwrap();
        let c = a["c"].take();
        a["c"] = b["c"].take();
        b["c"] = c;
        rows[i] = serde_json::from_value(a).unwrap();
        rows[k] = serde_json::from_value(b).unwrap();
        assertions::aead(open_value(&cipher, nested.open(rows)).await);
    }

    #[tokio::test]
    async fn a_row_reported_at_the_wrong_depth_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        for (path, d) in [
            ("$.nested.list[0].x", 1),
            ("$.nested.deep", 2),
            ("$.nested", 1),
        ] {
            let j = slot(&cipher, &doc, path).await;
            let rows: Vec<JsonNode> = walk(&doc, &nested)
                .into_iter()
                .map(|n| {
                    if n.slot() == j as u64 {
                        row(&doc, j, Some(d))
                    } else {
                        n
                    }
                })
                .collect();
            assertions::wrong_entry(open_value(&cipher, nested.open(rows)).await, DEPTH);
        }
    }

    #[tokio::test]
    async fn an_orphan_whose_parent_was_left_out_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        // nested, `deep` and then the second element's `x` alone: its parent
        // and everything between are missing.
        let rows = vec![
            row(&doc, slot(&cipher, &doc, "$.nested").await, Some(0)),
            row(&doc, slot(&cipher, &doc, "$.nested.deep").await, Some(1)),
            row(
                &doc,
                slot(&cipher, &doc, "$.nested.list[1].x").await,
                Some(3),
            ),
        ];
        assertions::aead(open_value(&cipher, nested.open(rows)).await);
    }

    #[tokio::test]
    async fn the_sealed_root_among_read_rows_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let list = key(&cipher, "$.nested.list").await;
        // Added to the rows, no token reaches it.
        let mut rows = walk(&doc, &list);
        rows.push(row(&doc, 0, Some(1)));
        assertions::wrong_entry(open_value(&cipher, list.open(rows)).await, UNREACHED);
        // In place of `$.hello`, under `$.hello`'s self tag: it opens, since
        // it commits to no children, and is the whole document. (Alone at
        // depth 0 it is the budget fallback, which opens whole and is read
        // at the key's paths; with no depth it is a row of a walk.)
        let hello = key(&cipher, "$.hello").await;
        let fallback = with_x(vec![row(&doc, 0, Some(0))], 0, x_of(&doc, &hello));
        assert_eq!(
            open_value(&cipher, hello.open(fallback)).await.unwrap(),
            json!("world-1"),
            "the fallback, read at the path"
        );
        let forged = with_x(vec![row(&doc, 0, None)], 0, x_of(&doc, &hello));
        assertions::wrong_entry(
            open_value(&cipher, hello.open(forged)).await,
            "a node of the walked subtree",
        );
    }

    /// The rows opened under another column's context: every entry's AAD
    /// binds the column, and the cipher refuses them.
    #[tokio::test]
    async fn the_rows_opened_under_another_column_are_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        let opened = cipher
            .decrypt_as::<Value, JsonSubtree>(
                nested.open(walk(&doc, &nested)),
                AeadContext::from(nonempty!("users").with("other")),
            )
            .await;
        assertions::aead(opened);
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
        assert_eq!(rows.len(), 128, "the root and every node below it");
        let opened = open_value(&cipher, root.open(rows)).await;
        assert_eq!(opened.unwrap(), value, "the whole document");
        let deepest = key_with(&cipher, &format!("${}", "[0]".repeat(126)), &open_root()).await;
        let opened = open_value(&cipher, deepest.open(walk(&doc, &deepest))).await;
        assert_eq!(
            opened.unwrap(),
            json!([1]),
            "126 positions down, by its own token"
        );
    }

    #[tokio::test]
    async fn an_array_read_missing_its_first_or_last_element_is_refused() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &json!({"arr": [10, 20, 30]})).await;
        let arr = key(&cipher, "$.arr").await;
        // Leaving out the first would have opened as `[20, 30]` when the
        // walk began at the children (review of #1358), and leaving out the
        // last as `[10, 20]`: the array's ciphertext commits to all three.
        for path in ["$.arr[0]", "$.arr[2]"] {
            let dropped = slot(&cipher, &doc, path).await;
            let rows = without(walk(&doc, &arr), dropped);
            assertions::aead(open_value(&cipher, arr.open(rows.clone())).await);
            assertions::aead(open_list(&cipher, arr.open(rows)).await);
        }
    }

    #[tokio::test]
    async fn rows_with_no_reported_depth_are_placed_by_the_chain() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        let rows: Vec<JsonNode> = walk(&doc, &nested)
            .iter()
            .map(|n| row(&doc, n.slot() as usize, None))
            .collect();
        let value = open_value(&cipher, nested.open(rows)).await;
        assert_eq!(value.unwrap(), fixture()["nested"], "the sub-document");
    }
}

/// What the read check allows by design, and says it allows: no bound field
/// names an entry's row, or the element a node at a selector sits under,
/// and nothing above the node at the top of a read is read.
mod given_answers_the_check_cannot_tell_apart {
    use super::*;

    #[tokio::test]
    async fn another_rows_node_at_the_same_path_opens() {
        let (cipher, _) = cipher().await;
        let other = seal(&cipher, &json!({"nested": {"deep": "other", "list": []}})).await;
        let nested = key(&cipher, "$.nested").await;
        // Row provenance is the database's word (ADR 0010).
        let opened = open_value(&cipher, nested.open(walk(&other, &nested))).await;
        assert_eq!(
            opened.unwrap(),
            json!({"deep": "other", "list": []}),
            "the other row's"
        );
    }

    #[tokio::test]
    async fn the_same_selector_under_another_element_opens() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, &fixture()).await;
        let second = key(&cipher, "$.nested.list[1].x").await;
        // `$.nested.list[0].x` with `$.nested.list[1].x`'s self tag at the
        // top of a read: the same selector and the same label, which is all
        // the node at the top binds.
        let first = slot(&cipher, &doc, "$.nested.list[0].x").await;
        let forged = with_x(vec![row(&doc, first, Some(0))], 0, x_of(&doc, &second));
        let opened = open_value(&cipher, second.open(forged)).await;
        assert_eq!(
            opened.unwrap(),
            json!(1),
            "the first element's x, by design"
        );
    }

    #[tokio::test]
    async fn rows_withheld_whole_read_as_no_node() {
        let (cipher, _) = cipher().await;
        let nested = key(&cipher, "$.nested").await;
        let opened = cipher
            .decrypt_as::<Option<Value>, JsonSubtree>(nested.open(Vec::new()), aead())
            .await;
        assert_eq!(
            opened.unwrap(),
            None,
            "the database's word that there is none"
        );
    }
}

/// The four answers a read at a path with no wildcard gives, as `jsonb #>`
/// gives them: an empty object, an empty array, a scalar and no node, as a
/// `Value`, an `Option<Value>` and a `Vec<Value>`.
mod given_a_read_of_one_node {
    use super::*;

    #[tokio::test]
    async fn each_answer_opens_as_jsonb_holds_it() {
        let (cipher, _) = cipher().await;
        let document = json!({"o": {}, "a": [], "s": "text", "n": null, "z": 0});
        let doc = seal(&cipher, &document).await;
        for (path, expected) in [
            ("$.o", Some(json!({}))),
            ("$.a", Some(json!([]))),
            ("$.s", Some(json!("text"))),
            ("$.n", Some(Value::Null)),
            ("$.missing", None),
            ("$.o.missing", None),
            ("$.a[0]", None),
        ] {
            let read = key(&cipher, path).await;
            let rows = walk(&doc, &read);
            let option = cipher
                .decrypt_as::<Option<Value>, JsonSubtree>(read.open(rows.clone()), aead())
                .await
                .unwrap();
            assert_eq!(option, expected, "{path} as Option<Value>");
            let list = open_list(&cipher, read.open(rows.clone())).await.unwrap();
            assert_eq!(
                list,
                expected.clone().into_iter().collect::<Vec<_>>(),
                "{path} as Vec<Value>"
            );
            match (open_value(&cipher, read.open(rows)).await, expected) {
                (Ok(value), Some(expected)) => assert_eq!(value, expected, "{path} as Value"),
                (Err(Error::OpenedType { expected }), None) => {
                    assert_eq!(expected, "a node at the walked path", "{path}")
                }
                (got, expected) => panic!("{path}: {got:?}, expected {expected:?}"),
            }
        }
    }
}

/// The in-crate model of the SQL reads finds what the SQL finds where a
/// document repeats a tag, which no sealing produces: the server's index
/// keeps the last entry carrying it (`jsonb_object_agg` keeps the last
/// value of a repeated key), so the model's `find` and `children` do too.
#[tokio::test]
async fn the_model_keeps_the_last_entry_carrying_a_tag_as_the_sql_index_does() {
    let (cipher, _) = cipher().await;
    let doc = seal_with(&cipher, &fixture(), &open_root()).await;
    let root = key_with(&cipher, "$", &open_root()).await;
    let hello = key_with(&cipher, "$.hello", &open_root()).await;
    let at = slot_with(&cipher, &doc, "$.hello", &open_root()).await;
    // `hello` appended again at the end: its self tag and parent tag now
    // name two entries, its own slot and 10.
    let mut wire = serde_json::to_value(&doc).unwrap();
    let sv = wire["sv"].as_array_mut().unwrap();
    let copy = sv[at].clone();
    sv.push(copy);
    let forged: JsonDocument = serde_json::from_value(wire).unwrap();
    assert_eq!(
        forged.find(&hello.token_bytes()[0]).map(|(j, _)| j),
        Some(10),
        "the last entry with the self tag"
    );
    let children: Vec<usize> = forged
        .children(&root.token_bytes()[0])
        .iter()
        .map(|(j, _, _)| *j)
        .collect();
    assert_eq!(children.len(), 3, "the root's three members");
    assert!(
        children.contains(&10) && !children.contains(&at),
        "the last entry with the parent tag: {children:?}"
    );
}

/// The self tag the stored node at `key`'s only token carries, as the
/// database could write it on any entry: it holds the token and the `iv`.
fn x_of(doc: &JsonDocument, key: &JsonSubtreeKey) -> String {
    let (j, _) = doc.find(&key.token_bytes()[0]).expect("the node is there");
    base64(doc.entries()[j].self_tag())
}

/// `rows` with the self tag of the row at `at` rewritten to `x`.
fn with_x(mut rows: Vec<JsonNode>, at: usize, x: String) -> Vec<JsonNode> {
    let mut wire = serde_json::to_value(&rows[at]).unwrap();
    wire["x"] = json!(x);
    rows[at] = serde_json::from_value(wire).unwrap();
    rows
}

/// `rows` without the row of the entry at slot `j`.
fn without(rows: Vec<JsonNode>, j: usize) -> Vec<JsonNode> {
    let before = rows.len();
    let rows: Vec<JsonNode> = rows.into_iter().filter(|n| n.slot() != j as u64).collect();
    assert_eq!(rows.len() + 1, before, "the row at {j} was among them");
    rows
}

/// `node` carrying the self tag and parent tag of the entry at slot `j`.
fn with_tags_of(doc: &JsonDocument, node: JsonNode, j: usize) -> JsonNode {
    let entry = &doc.entries()[j];
    let mut wire = serde_json::to_value(&node).unwrap();
    wire["x"] = json!(base64(entry.self_tag()));
    wire["p"] = json!(entry.parent_tag().map(|p| base64(p)));
    serde_json::from_value(wire).unwrap()
}

/// `rows` with the self tags and parent tags of the rows of the entries at
/// slots `a` and `b` exchanged.
fn exchange_tags(rows: Vec<JsonNode>, a: usize, b: usize) -> Vec<JsonNode> {
    let tags = |n: &JsonNode| {
        let wire = serde_json::to_value(n).unwrap();
        (wire["x"].clone(), wire["p"].clone())
    };
    let find = |j: usize| rows.iter().position(|n| n.slot() == j as u64).unwrap();
    let (i, k) = (find(a), find(b));
    let ((xa, pa), (xb, pb)) = (tags(&rows[i]), tags(&rows[k]));
    let retag = |n: &JsonNode, x: &Value, p: &Value| {
        let mut wire = serde_json::to_value(n).unwrap();
        wire["x"] = x.clone();
        wire["p"] = p.clone();
        serde_json::from_value::<JsonNode>(wire).unwrap()
    };
    let mut rows = rows.clone();
    rows[i] = retag(&rows[i], &xb, &pb);
    rows[k] = retag(&rows[k], &xa, &pa);
    rows
}

/// The sixteen bytes of a selector.
fn selector_bytes(selector: &JsonSelector) -> [u8; 16] {
    use base64ct::{Base64, Encoding};
    Base64::decode_vec(&selector.to_string())
        .unwrap()
        .try_into()
        .unwrap()
}

/// The chain's public hash functions, as the design writes them and the
/// server computes them: what a database holding a read's tokens can
/// compute for itself, and so what a forged row may carry.
mod chain {
    use sha2::{Digest, Sha256};

    fn h(parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().into()
    }

    /// `H16("t" ‖ t(array) ‖ s(element) ‖ LE32(i))`.
    pub(crate) fn element_token(array: &[u8; 16], s: &[u8; 16], i: u32) -> [u8; 16] {
        h(&[b"t", array, s, &i.to_le_bytes()])[..16]
            .try_into()
            .unwrap()
    }

    /// `H("x" ‖ iv ‖ t)[..8]`.
    pub(crate) fn self_tag(iv: &[u8], token: &[u8; 16]) -> [u8; 8] {
        h(&[b"x", iv, token])[..8].try_into().unwrap()
    }

    /// `H("p" ‖ iv ‖ t(parent) ‖ LE32(o))[..8]`.
    pub(crate) fn parent_tag(iv: &[u8], parent: &[u8; 16], o: u32) -> [u8; 8] {
        h(&[b"p", iv, parent, &o.to_le_bytes()])[..8]
            .try_into()
            .unwrap()
    }
}
