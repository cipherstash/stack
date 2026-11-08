//! The JSON index under a keyset whose index key lasts one settle, as a key
//! vendor backend's does: the cipher holds no index key, so a document's
//! terms, a read's selector and key, and the selectors that check a read's
//! rows are all derived inside the settle that loads the key. They are the
//! ones a cipher that holds the same key derives, so a document sealed
//! through either opens through the other.

mod common;

use std::sync::atomic::Ordering;

use common::PerSettleSource;
use serde_json::{json, Value};
use stack_encrypt::json::{
    JsonDocument, JsonNode, JsonOptions, JsonPath, JsonSelector, JsonSubtree, JsonSubtreeKey,
};
use stack_encrypt::target::{AeadContext, Borrowed, CallerContext};
use stack_encrypt::{nonempty, StackCipher};
use stack_kms::{DataKeySource, DeterministicSource, IndexKeySource};

fn fixture() -> Value {
    json!({"hello": "world-1", "nested": {"deep": "constant", "list": [{"x": 1}, {"x": 2}]}, "number": 1})
}

fn aead() -> AeadContext {
    AeadContext::from(nonempty!("users").with("profile"))
}

fn open_root() -> JsonOptions {
    JsonOptions {
        sealed_root: false,
        ..JsonOptions::new()
    }
}

async fn seal<K>(cipher: &StackCipher<K>, value: &Value, options: &JsonOptions) -> JsonDocument
where
    K: DataKeySource + IndexKeySource + Send + Sync + 'static,
{
    cipher
        .default_keyset()
        .run(
            stack_encrypt::target::json_document::<_, Borrowed>(options.clone()),
            value,
            CallerContext::from(nonempty!("users").with("profile")),
        )
        .await
        .expect("seals")
}

async fn open<K>(cipher: &StackCipher<K>, doc: JsonDocument) -> Value
where
    K: DataKeySource + IndexKeySource + Send + Sync + 'static,
{
    cipher
        .decrypt_as::<Value, JsonDocument>(doc, aead())
        .await
        .expect("opens")
}

async fn selector<K>(cipher: &StackCipher<K>, path: &str) -> JsonSelector
where
    K: DataKeySource + IndexKeySource + Send + Sync + 'static,
{
    cipher
        .default_keyset()
        .json_selector(
            &JsonPath::parse(path).unwrap(),
            nonempty!("users").with("profile"),
        )
        .await
        .expect("derives a selector")
}

async fn key<K>(cipher: &StackCipher<K>, path: &str, options: &JsonOptions) -> JsonSubtreeKey
where
    K: DataKeySource + IndexKeySource + Send + Sync + 'static,
{
    cipher
        .default_keyset()
        .json_subtree_key(
            &JsonPath::parse(path).unwrap(),
            options,
            nonempty!("users").with("profile"),
        )
        .await
        .expect("derives a read key")
}

/// The rows `json_tree_subtree(doc, key.tokens(), 0)` returns for `key`.
fn walk(doc: &JsonDocument, key: &JsonSubtreeKey) -> Vec<JsonNode> {
    doc.subtree(&key.token_bytes())
        .iter()
        .map(|(j, _, d)| {
            let mut wire = serde_json::to_value(doc.node(*j).unwrap()).unwrap();
            wire["d"] = json!(d);
            serde_json::from_value(wire).unwrap()
        })
        .collect()
}

/// A cipher that holds its index key, one whose index key lasts one
/// settle, over the same keys, and the latter's counter of settle loads.
async fn ciphers() -> (
    StackCipher<DeterministicSource>,
    StackCipher<PerSettleSource>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let (per_settle, loads) = common::per_settle_cipher().await;
    let held = common::deterministic_cipher(common::PER_SETTLE_SEED).await;
    (held, per_settle, loads)
}

#[tokio::test]
async fn a_per_settle_keyset_holds_no_index_key() {
    let (_, per_settle, loads) = ciphers().await;
    assert!(per_settle.default_keyset().prf().is_none());
    assert_eq!(loads.load(Ordering::SeqCst), 0, "building loads none");
}

/// A document sealed under either cipher opens under both, with the root
/// open (each read derives the root's token under the keyset the document
/// names) and sealed.
#[tokio::test]
async fn a_document_opens_under_either_cipher() {
    let (held, per_settle, loads) = ciphers().await;
    for options in [open_root(), JsonOptions::default()] {
        let mine = seal(&per_settle, &fixture(), &options).await;
        assert_eq!(open(&per_settle, mine.clone()).await, fixture());
        assert_eq!(open(&held, mine).await, fixture());
        let theirs = seal(&held, &fixture(), &options).await;
        assert_eq!(open(&per_settle, theirs).await, fixture());
    }
    assert!(loads.load(Ordering::SeqCst) > 0);
}

/// A selector and a read key derived inside the settle are the ones a
/// cipher holding the index key derives.
#[tokio::test]
async fn selectors_and_read_keys_match_a_cipher_that_holds_the_key() {
    let (held, per_settle, loads) = ciphers().await;
    for path in ["$", "$.hello", "$.nested.list[*].x"] {
        assert_eq!(
            selector(&per_settle, path).await.to_string(),
            selector(&held, path).await.to_string(),
            "{path}"
        );
        for options in [open_root(), JsonOptions::default()] {
            assert_eq!(
                key(&per_settle, path, &options).await.tokens(),
                key(&held, path, &options).await.tokens(),
                "{path}"
            );
        }
    }
    assert_eq!(loads.load(Ordering::SeqCst), 9, "one load per settle");
}

/// A read keyed under a per-settle keyset opens its rows: the selectors
/// that check them are derived under the index key the open's settle
/// loads, since the key holds none.
#[tokio::test]
async fn a_subtree_read_opens_under_a_per_settle_keyset() {
    let (held, per_settle, loads) = ciphers().await;
    let options = open_root();
    let doc = seal(&held, &fixture(), &options).await;
    let read = key(&per_settle, "$.nested.list[*].x", &options).await;
    let before = loads.load(Ordering::SeqCst);
    let values = per_settle
        .decrypt_as::<Vec<Value>, JsonSubtree>(read.open(walk(&doc, &read)), aead())
        .await
        .expect("opens");
    assert_eq!(values, [json!(1), json!(2)]);
    assert_eq!(
        loads.load(Ordering::SeqCst),
        before + 1,
        "the open loads one"
    );
}
