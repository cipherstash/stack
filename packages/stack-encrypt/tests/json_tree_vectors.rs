//! The JSON index's derivations, pinned: the selector `s`, the self tag `x`
//! and the parent tag `p` of every entry of one document, and the tokens a
//! read sends for the root, a chain head, an object member and an array
//! element, under both root options. Sealed under the deterministic key
//! source, whose index key is fixed and whose `iv` follows from its seed,
//! so every one of them is the same in every run. The ciphertexts carry a
//! fresh nonce each and are not pinned.
//!
//! A stored document's `x` and `p` are derived from the tokens, and a read
//! finds nodes by them, so a change to any derivation here is a change to
//! the stored form: every stored row stops answering reads. Regenerate with
//! `STACK_ENCRYPT_UPDATE_JSON_TREE_VECTORS=1` (exactly `1`; any other value
//! regenerates nothing), deliberately not the crate's routine
//! `STACK_ENCRYPT_UPDATE_FIXTURES`, and only when the break is intended.

mod common;

use std::ffi::OsStr;
use std::path::PathBuf;

use serde_json::{json, Value};
use stack_encrypt::json::{JsonDocument, JsonOptions, JsonPath};
use stack_encrypt::nonempty;
use stack_encrypt::target::CallerContext;

const SEED: [u8; 32] = [0x4a; 32];

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/json_tree_vectors.json")
}

/// Whether the fixture is to be rewritten: only for exactly
/// `STACK_ENCRYPT_UPDATE_JSON_TREE_VECTORS=1`. A rewrite hides a real
/// drift, so `0`, an empty value or any other spelling must not trigger one.
fn update_requested(value: Option<&OsStr>) -> bool {
    value == Some(OsStr::new("1"))
}

fn document() -> Value {
    json!({"a": {"b": [1, {"c": true}]}, "d": "e"})
}

/// The paths whose tokens are pinned: the root, a head, a member below a
/// head, an array, an element, and a member below an element.
const READS: [&str; 6] = ["$", "$.a", "$.a.b", "$.a.b[0]", "$.a.b[1]", "$.a.b[1].c"];

fn base64(bytes: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(bytes)
}

async fn vectors(options: &JsonOptions) -> Value {
    let cipher = common::deterministic_cipher(SEED).await;
    let doc: JsonDocument = cipher
        .default_keyset()
        .run(
            stack_encrypt::target::json_document::<_, stack_encrypt::target::Borrowed>(
                options.clone(),
            ),
            &document(),
            CallerContext::from(nonempty!("users").with("profile")),
        )
        .await
        .expect("seals");
    let entries: Vec<Value> = doc
        .entries()
        .iter()
        .map(|e| {
            json!({
                "s": base64(e.selector()),
                "x": base64(e.self_tag()),
                "p": e.parent_tag().map(|p| base64(p)),
            })
        })
        .collect();
    let mut tokens = serde_json::Map::new();
    for path in READS {
        let key = cipher
            .default_keyset()
            .json_subtree_key(
                &JsonPath::parse(path).unwrap(),
                options,
                nonempty!("users").with("profile"),
            )
            .await
            .unwrap();
        let _ = tokens.insert(path.to_owned(), json!(key.tokens()));
    }
    json!({
        "iv": base64(doc.header().iv()),
        "entries": entries,
        "tokens": tokens,
    })
}

const DRIFT: &str = "\
Under the same deterministic key source, the JSON index's selectors, self tags, \
parent tags or read tokens no longer match tests/fixtures/json_tree_vectors.json. \
A stored json_tree document's `x` and `p` are derived from these tokens, and a \
read finds nodes by them, so a change here stops every stored row answering \
reads: a breaking change to stored data, not a fixture refresh. Regenerate with \
STACK_ENCRYPT_UPDATE_JSON_TREE_VECTORS=1 only when the break is intended, and \
say so in the changeset.";

#[tokio::test]
async fn the_derivations_are_pinned_under_the_deterministic_source() {
    let actual = json!({
        "_comment": "The JSON index's s, x and p per entry, and the tokens a read sends, under the deterministic key source. Read by tests/json_tree_vectors.rs; regenerate with STACK_ENCRYPT_UPDATE_JSON_TREE_VECTORS=1 only for an intended break. Do not edit by hand.",
        "document": document(),
        "sealed_root": vectors(&JsonOptions::default()).await,
        "open_root": vectors(&JsonOptions { sealed_root: false, ..JsonOptions::new() }).await,
    });
    if update_requested(std::env::var_os("STACK_ENCRYPT_UPDATE_JSON_TREE_VECTORS").as_deref()) {
        std::fs::write(
            fixture_path(),
            serde_json::to_string_pretty(&actual).unwrap() + "\n",
        )
        .unwrap();
    }
    let pinned: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_path()).expect("the fixture exists"))
            .unwrap();
    assert_eq!(
        pinned["document"], actual["document"],
        "the pinned document"
    );
    assert_eq!(
        pinned["sealed_root"]["iv"], actual["sealed_root"]["iv"],
        "the deterministic source's iv moved: a test-infrastructure change in stack-kms, not a stored-data break"
    );
    assert_eq!(pinned, actual, "{DRIFT}");
}

#[test]
fn only_exactly_one_requests_an_update() {
    assert!(update_requested(Some(OsStr::new("1"))), "exactly 1");
    for other in ["0", "", "true", "yes", " 1"] {
        assert!(!update_requested(Some(OsStr::new(other))), "{other:?}");
    }
    assert!(!update_requested(None), "unset");
}

#[tokio::test]
async fn the_deterministic_source_seals_the_same_tags_twice() {
    let one = vectors(&JsonOptions::default()).await;
    let two = vectors(&JsonOptions::default()).await;
    assert_eq!(one, two, "a pin needs a run that repeats");
}
