//! The JSON targets through the owned traits, with no database: a
//! [`JsonPlaintext`] seals into a [`JsonDocument`], and the document, one
//! entry of it ([`JsonExtracted`]) and the rows of a read ([`JsonSubtree`])
//! each open to a `JsonPlaintext`, which is wiped when it is dropped.
//!
//! The rows here are built as the SQL returns them, from a sealed document,
//! as `json_read_checks.rs` builds them. That file holds the checks a read
//! makes on its rows. This one holds the forms a caller opens with (one
//! `JsonPlaintext`, an `Option` of one and a `Vec` of them), the answer
//! each gives and the refusals each makes.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use common::CountingSource;
use serde_json::{json, Value};
use stack_encrypt::json::{
    JsonDocument, JsonExtracted, JsonNode, JsonOptions, JsonPath, JsonPlaintext, JsonSelector,
    JsonSubtree, JsonSubtreeKey,
};
use stack_encrypt::target::{AeadContext, CallerContext, IndexSpec};
use stack_encrypt::{nonempty, DecryptFrom, EncryptInto, EncryptTarget, Error, StackCipher};

type Cipher = StackCipher<CountingSource>;

async fn cipher() -> (Cipher, Arc<AtomicUsize>) {
    let source = CountingSource::new();
    let (_, retrieved) = source.counters();
    let cipher = StackCipher::builder()
        .kms(source)
        .init()
        .await
        .expect("build cipher");
    (cipher, retrieved)
}

/// The column the documents here are stored in.
fn column() -> CallerContext {
    CallerContext::from(nonempty!("users").with("profile"))
}

fn aead() -> AeadContext {
    AeadContext::from(column())
}

/// `$`, `hello`, `nested`, `nested.deep`, `nested.list`, its two elements
/// and their `x`, and `number`: ten nodes, stored in a random order.
fn fixture() -> Value {
    json!({"hello": "world-1", "nested": {"deep": "constant", "list": [{"x": 1}, {"x": 2}]}, "number": 1})
}

/// Seal `value` through the owned API, under the column.
async fn seal(cipher: &Cipher, value: Value) -> JsonDocument {
    JsonPlaintext::from(value)
        .encrypt_into_with_context(&cipher.default_keyset(), column())
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
    cipher
        .default_keyset()
        .json_subtree_key(
            &JsonPath::parse(path).unwrap(),
            &JsonOptions::default(),
            nonempty!("users").with("profile"),
        )
        .await
        .unwrap()
}

/// The slot the node at the concrete `path` is stored at, found as the
/// server finds it: by the self tag of the path's token.
async fn slot(cipher: &Cipher, doc: &JsonDocument, path: &str) -> usize {
    let key = key(cipher, path).await;
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

/// The rows a subtree read returns for `key`: for each token, the node it
/// names at depth 0 and everything beneath it.
fn walk(doc: &JsonDocument, key: &JsonSubtreeKey) -> Vec<JsonNode> {
    doc.subtree(&key.token_bytes())
        .iter()
        .map(|(j, _, d)| row(doc, *j, Some(*d)))
        .collect()
}

/// The entry `->` returns for `path`, with the selector the client derived.
async fn extracted(cipher: &Cipher, doc: &JsonDocument, path: &str) -> JsonExtracted {
    let at = slot(cipher, doc, path).await;
    selector(cipher, path).await.open(row(doc, at, None))
}

/// The rows of a read at `path`, with the key the client derived.
async fn read(cipher: &Cipher, doc: &JsonDocument, path: &str) -> JsonSubtree {
    let key = key(cipher, path).await;
    let rows = walk(doc, &key);
    key.open(rows)
}

/// The documents a list of plaintexts holds.
fn values(list: &[JsonPlaintext]) -> Vec<Value> {
    list.iter().map(|opened| opened.value().clone()).collect()
}

mod given_a_document {
    use super::*;

    #[tokio::test]
    async fn it_seals_from_a_json_plaintext_and_opens_to_one() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, fixture()).await;
        let opened = JsonPlaintext::decrypt_from_with_context(doc, &cipher, aead())
            .await
            .expect("opens");
        assert_eq!(opened.value(), &fixture(), "the document that was sealed");
    }

    #[tokio::test]
    async fn it_does_not_open_under_another_column() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, fixture()).await;
        let other = AeadContext::from(nonempty!("users").with("settings"));
        let opened = JsonPlaintext::decrypt_from_with_context(doc, &cipher, other).await;
        assert!(
            matches!(opened, Err(Error::Aead)),
            "another column's context opens nothing: {opened:?}"
        );
    }

    /// A plan field typed with the document lets a query use the JSON
    /// index, under the default options.
    #[test]
    fn it_declares_the_json_index() {
        assert_eq!(
            <JsonDocument as EncryptTarget<JsonPlaintext>>::indexes(),
            vec![IndexSpec::Json(JsonOptions::default())],
        );
    }
}

mod given_the_entry_arrow_returned {
    use super::*;

    #[tokio::test]
    async fn the_entry_at_the_path_opens_to_its_scalar() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, fixture()).await;
        let hello = extracted(&cipher, &doc, "$.hello").await;
        let opened = JsonPlaintext::decrypt_from_with_context(hello, &cipher, aead())
            .await
            .expect("opens");
        assert_eq!(opened.value(), &json!("world-1"), "the value at the path");
    }

    #[tokio::test]
    async fn the_sealed_root_opens_to_the_whole_document() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, fixture()).await;
        let root = selector(&cipher, "$").await.open(row(&doc, 0, None));
        let opened = JsonPlaintext::decrypt_from_with_context(root, &cipher, aead())
            .await
            .expect("opens");
        assert_eq!(opened.value(), &fixture(), "`$` is the whole document");
    }

    #[tokio::test]
    async fn another_paths_entry_is_refused_before_any_key_is_retrieved() {
        let (cipher, retrieved) = cipher().await;
        let doc = seal(&cipher, fixture()).await;
        // `$.number` is a genuine entry of the row: the database answered
        // `$.hello` with it.
        let number = slot(&cipher, &doc, "$.number").await;
        let answered = selector(&cipher, "$.hello")
            .await
            .open(row(&doc, number, None));
        let opened = JsonPlaintext::decrypt_from_with_context(answered, &cipher, aead()).await;
        assert!(
            matches!(opened, Err(Error::JsonWrongEntry { .. })),
            "{opened:?}"
        );
        assert_eq!(
            retrieved.load(Ordering::SeqCst),
            0,
            "the refusal retrieved no key"
        );
    }

    #[tokio::test]
    async fn a_container_with_children_does_not_open_alone() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, fixture()).await;
        let nested = extracted(&cipher, &doc, "$.nested").await;
        let opened = JsonPlaintext::decrypt_from_with_context(nested, &cipher, aead()).await;
        assert!(matches!(opened, Err(Error::JsonNotALeaf)), "{opened:?}");
    }
}

mod given_the_rows_of_a_read {
    use super::*;

    #[tokio::test]
    async fn the_node_at_the_path_opens_with_everything_beneath_it() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, fixture()).await;
        let nested = read(&cipher, &doc, "$.nested").await;
        let opened = JsonPlaintext::decrypt_from_with_context(nested, &cipher, aead())
            .await
            .expect("opens");
        assert_eq!(opened.value(), &fixture()["nested"], "the subtree");
    }

    /// The four answers `jsonb #>` gives at a path with no wildcard: an
    /// empty object, an empty array, a scalar and no node.
    #[tokio::test]
    async fn each_answer_opens_as_jsonb_holds_it() {
        let (cipher, _) = cipher().await;
        let document = json!({"o": {}, "a": [], "s": "text", "n": null});
        let doc = seal(&cipher, document).await;
        for (path, expected) in [
            ("$.o", Some(json!({}))),
            ("$.a", Some(json!([]))),
            ("$.s", Some(json!("text"))),
            ("$.n", Some(Value::Null)),
            ("$.missing", None),
        ] {
            let option = Option::<JsonPlaintext>::decrypt_from_with_context(
                read(&cipher, &doc, path).await,
                &cipher,
                aead(),
            )
            .await
            .expect("opens");
            assert_eq!(
                option.as_ref().map(JsonPlaintext::value),
                expected.as_ref(),
                "{path} as an Option"
            );

            let list = Vec::<JsonPlaintext>::decrypt_from_with_context(
                read(&cipher, &doc, path).await,
                &cipher,
                aead(),
            )
            .await
            .expect("opens");
            assert_eq!(
                values(&list),
                expected.clone().into_iter().collect::<Vec<_>>(),
                "{path} as a Vec"
            );

            let one = JsonPlaintext::decrypt_from_with_context(
                read(&cipher, &doc, path).await,
                &cipher,
                aead(),
            )
            .await;
            match (one, expected) {
                (Ok(opened), Some(expected)) => {
                    assert_eq!(opened.value(), &expected, "{path} as one value")
                }
                (Err(Error::OpenedType { expected }), None) => {
                    assert_eq!(expected, "a node at the walked path", "{path}")
                }
                (got, expected) => panic!("{path}: {got:?}, expected {expected:?}"),
            }
        }
    }

    #[tokio::test]
    async fn a_wildcard_opens_to_a_list_in_document_order() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, fixture()).await;
        let xs = read(&cipher, &doc, "$.nested.list[*].x").await;
        let list = Vec::<JsonPlaintext>::decrypt_from_with_context(xs, &cipher, aead())
            .await
            .expect("opens");
        assert_eq!(values(&list), vec![json!(1), json!(2)], "every element's x");
    }

    #[tokio::test]
    async fn a_wildcard_that_reaches_several_nodes_is_not_one_value() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, fixture()).await;
        for (target, opened) in [
            (
                "one value",
                JsonPlaintext::decrypt_from_with_context(
                    read(&cipher, &doc, "$.nested.list[*].x").await,
                    &cipher,
                    aead(),
                )
                .await
                .map(|_| ()),
            ),
            (
                "an Option",
                Option::<JsonPlaintext>::decrypt_from_with_context(
                    read(&cipher, &doc, "$.nested.list[*].x").await,
                    &cipher,
                    aead(),
                )
                .await
                .map(|_| ()),
            ),
        ] {
            assert!(
                matches!(opened, Err(Error::OpenedType { .. })),
                "{target}: {opened:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_rows_do_not_open_under_another_column() {
        let (cipher, _) = cipher().await;
        let doc = seal(&cipher, fixture()).await;
        let nested = read(&cipher, &doc, "$.nested").await;
        let other = AeadContext::from(nonempty!("users").with("settings"));
        let opened = JsonPlaintext::decrypt_from_with_context(nested, &cipher, other).await;
        assert!(
            matches!(opened, Err(Error::Aead)),
            "another column's context opens nothing: {opened:?}"
        );
    }
}
