//! The parts of a JSON tree document through the owned API, with no
//! database: one entry ([`JsonTreeExtracted`]) and the rows of a read
//! ([`JsonTreeSubtree`]) each open to a [`JsonPlaintext`], which is wiped
//! when it is dropped.
//!
//! The rows are built from a sealed document, as the SQL returns them.
//! `json_tree.rs` holds the PostgreSQL tests of the same reads.

mod common;

use eql_bindings::v4::json_tree::{
    JsonTreeDocument, JsonTreeEntry, JsonTreeExtracted, JsonTreeSubtree,
};
use eql_bindings::Identifier;
use serde_json::{json, Value};
use stack_encrypt::json::{JsonOptions, JsonPath, JsonPlaintext, JsonSelector, JsonSubtreeKey};
use stack_encrypt::target::{CallerContext, DeclaredContext, Scope};
use stack_encrypt::{
    nonempty, DecryptFrom, DecryptSource, EncryptInto, EncryptTarget, Error, NonEmpty,
};
use zeroize::Zeroize;

type Cipher = stack_encrypt::StackCipher<common::Observed>;

fn column() -> NonEmpty<Identifier> {
    Identifier::for_column("users", "profile").unwrap()
}

fn fixture() -> Value {
    json!({"hello": "world-1", "nested": {"deep": "constant", "list": [{"x": 1}, {"x": 2}]}, "number": 1})
}

/// Seal `value` through the owned API, under the column, with the default
/// options: the whole document is sealed in the root entry.
async fn seal(cipher: &Cipher, value: Value) -> JsonTreeDocument {
    JsonPlaintext::from(value)
        .encrypt_into_with_context(&cipher.default_keyset(), column())
        .await
        .expect("seals")
}

async fn selector(cipher: &Cipher, path: &str) -> JsonSelector {
    cipher
        .default_keyset()
        .json_selector(&JsonPath::parse(path).unwrap(), column())
        .await
        .unwrap()
}

async fn key(cipher: &Cipher, path: &str) -> JsonSubtreeKey {
    cipher
        .default_keyset()
        .json_subtree_key(
            &JsonPath::parse(path).unwrap(),
            &JsonOptions::default(),
            column(),
        )
        .await
        .unwrap()
}

/// The entry at slot `at`, with the header and the slot grafted as an
/// extractor grafts them.
fn returned(stored: &JsonTreeDocument, at: usize) -> JsonTreeEntry {
    let mut entry = stored.sv[at].clone();
    entry.h = Some(stored.h.clone());
    entry.j = Some(at as u64);
    entry
}

/// The entry `->` returns for `selector`: the one entry that carries it.
fn entry_of(stored: &JsonTreeDocument, selector: &JsonSelector) -> JsonTreeEntry {
    let at = stored
        .sv
        .iter()
        .position(|e| serde_json::to_value(&e.s).unwrap() == json!(selector.to_string()))
        .expect("the document has the path");
    returned(stored, at)
}

/// The rows a subtree read returns once it is past its budget: the sealed
/// root alone, at depth `0`. They open to the whole document, and the key's
/// paths are read from it.
fn sealed_root(stored: &JsonTreeDocument) -> Vec<JsonTreeEntry> {
    let mut root = returned(stored, 0);
    root.d = Some(0);
    vec![root]
}

/// The documents a list of plaintexts holds.
fn values(list: &[JsonPlaintext]) -> Vec<Value> {
    list.iter().map(|opened| opened.value().clone()).collect()
}

mod given_the_entry_arrow_returned {
    use super::*;

    #[tokio::test]
    async fn the_entry_at_the_path_opens_to_its_scalar() {
        let (cipher, _) = common::cipher().await;
        let stored = seal(&cipher, fixture()).await;
        let hello = selector(&cipher, "$.hello").await;
        let extracted = JsonTreeExtracted::from_selector(&hello, entry_of(&stored, &hello));
        let opened = JsonPlaintext::decrypt_from_with_context(extracted, &cipher, column())
            .await
            .expect("opens");
        assert_eq!(opened.value(), &json!("world-1"), "the value at the path");
    }

    #[tokio::test]
    async fn another_paths_entry_is_refused_before_any_key_is_retrieved() {
        let (cipher, calls) = common::cipher().await;
        let stored = seal(&cipher, fixture()).await;
        let hello = selector(&cipher, "$.hello").await;
        let number = selector(&cipher, "$.number").await;
        // The database answered `$.number` with the entry of `$.hello`.
        let answered = JsonTreeExtracted::from_selector(&number, entry_of(&stored, &hello));
        let opened = JsonPlaintext::decrypt_from_with_context(answered, &cipher, column()).await;
        assert!(
            matches!(opened, Err(Error::JsonWrongEntry { .. })),
            "{opened:?}"
        );
        assert!(
            calls.lock().unwrap().retrieve.is_empty(),
            "the refusal retrieved no key"
        );
    }

    #[tokio::test]
    async fn an_entry_with_no_header_is_refused() {
        let (cipher, _) = common::cipher().await;
        let stored = seal(&cipher, fixture()).await;
        let hello = selector(&cipher, "$.hello").await;
        let mut bare = entry_of(&stored, &hello);
        bare.h = None;
        bare.j = None;
        let extracted = JsonTreeExtracted::from_selector(&hello, bare);
        let opened = JsonPlaintext::decrypt_from_with_context(extracted, &cipher, column()).await;
        assert!(matches!(opened, Err(Error::Other(_))), "{opened:?}");
    }

    #[tokio::test]
    async fn the_entry_does_not_open_under_another_column() {
        let (cipher, _) = common::cipher().await;
        let stored = seal(&cipher, fixture()).await;
        let hello = selector(&cipher, "$.hello").await;
        let extracted = JsonTreeExtracted::from_selector(&hello, entry_of(&stored, &hello));
        let other = Identifier::for_column("users", "bio").unwrap();
        let opened = JsonPlaintext::decrypt_from_with_context(extracted, &cipher, other).await;
        assert!(
            matches!(opened, Err(Error::JsonNotALeaf)),
            "another column's context opens nothing: {opened:?}"
        );
    }
}

mod given_the_rows_of_a_read {
    use super::*;

    #[tokio::test]
    async fn the_value_at_the_path_opens() {
        let (cipher, _) = common::cipher().await;
        let stored = seal(&cipher, fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        let rows = JsonTreeSubtree::from_key(&nested, sealed_root(&stored));
        let opened = JsonPlaintext::decrypt_from_with_context(rows, &cipher, column())
            .await
            .expect("opens");
        assert_eq!(opened.value(), &fixture()["nested"], "the subtree");
    }

    #[tokio::test]
    async fn a_path_the_row_lacks_opens_to_none_and_is_not_one_value() {
        let (cipher, _) = common::cipher().await;
        let stored = seal(&cipher, fixture()).await;
        let missing = key(&cipher, "$.missing").await;

        let rows = JsonTreeSubtree::from_key(&missing, sealed_root(&stored));
        let option = Option::<JsonPlaintext>::decrypt_from_with_context(rows, &cipher, column())
            .await
            .expect("opens");
        assert!(option.is_none(), "no node at the path");

        let rows = JsonTreeSubtree::from_key(&missing, sealed_root(&stored));
        let one = JsonPlaintext::decrypt_from_with_context(rows, &cipher, column()).await;
        assert!(matches!(one, Err(Error::OpenedType { .. })), "{one:?}");
    }

    #[tokio::test]
    async fn a_node_at_the_path_opens_as_some() {
        let (cipher, _) = common::cipher().await;
        let stored = seal(&cipher, fixture()).await;
        let hello = key(&cipher, "$.hello").await;
        let rows = JsonTreeSubtree::from_key(&hello, sealed_root(&stored));
        let option = Option::<JsonPlaintext>::decrypt_from_with_context(rows, &cipher, column())
            .await
            .expect("opens");
        assert_eq!(
            option.as_ref().map(JsonPlaintext::value),
            Some(&json!("world-1")),
            "the node at the path"
        );
    }

    #[tokio::test]
    async fn a_wildcard_opens_to_a_list_in_document_order() {
        let (cipher, _) = common::cipher().await;
        let stored = seal(&cipher, fixture()).await;
        let xs = key(&cipher, "$.nested.list[*].x").await;
        let rows = JsonTreeSubtree::from_key(&xs, sealed_root(&stored));
        let list = Vec::<JsonPlaintext>::decrypt_from_with_context(rows, &cipher, column())
            .await
            .expect("opens");
        assert_eq!(values(&list), vec![json!(1), json!(2)], "every element's x");
    }

    #[tokio::test]
    async fn rows_with_no_header_are_refused() {
        let (cipher, _) = common::cipher().await;
        let stored = seal(&cipher, fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        let mut rows = sealed_root(&stored);
        rows[0].h = None;
        let rows = JsonTreeSubtree::from_key(&nested, rows);
        let opened = JsonPlaintext::decrypt_from_with_context(rows, &cipher, column()).await;
        assert!(matches!(opened, Err(Error::Other(_))), "{opened:?}");
    }

    #[tokio::test]
    async fn the_rows_do_not_open_under_another_column() {
        let (cipher, _) = common::cipher().await;
        let stored = seal(&cipher, fixture()).await;
        let nested = key(&cipher, "$.nested").await;
        let rows = JsonTreeSubtree::from_key(&nested, sealed_root(&stored));
        let other = Identifier::for_column("users", "bio").unwrap();
        let opened = JsonPlaintext::decrypt_from_with_context(rows, &cipher, other).await;
        assert!(
            matches!(opened, Err(Error::Aead)),
            "another column's context opens nothing: {opened:?}"
        );
    }
}

/// A document that is a field of a record is sealed under the field's
/// column, then the record's scopes, then its bindings. Its parts open
/// under that same context. The selector of a path derives under the column
/// and the scopes, as every search term does.
mod given_a_document_that_is_a_field_of_a_record {
    use super::*;

    #[derive(Clone, Zeroize)]
    struct Lead {
        profile: JsonPlaintext,
    }

    /// The column of `profile` is the table `leads` and the column
    /// `profile`. The caller supplies a tenant and a row.
    #[derive(EncryptTarget, DecryptSource)]
    #[stash(struct = Lead, scope = "leads", scope(tenant: u64), bind(row: u128))]
    struct EncryptedLead {
        profile: JsonTreeDocument,
    }

    /// The context of `profile` for tenant 42 and row 9.
    fn field_context() -> CallerContext {
        DeclaredContext::default()
            .with(CallerContext::from(Scope::new(42u64).bind(9u128)))
            .under(nonempty!("leads").with("profile"))
    }

    async fn sealed(cipher: &Cipher) -> JsonTreeDocument {
        let lead = Lead {
            profile: fixture().into(),
        };
        let record: EncryptedLead = lead
            .encrypt_into_with_context(&cipher.default_keyset(), Scope::new(42u64).bind(9u128))
            .await
            .expect("seals");
        record.profile
    }

    /// The selector of `$.hello` for tenant 42: derived under the query
    /// context, which is the column and the tenant.
    async fn hello(cipher: &Cipher) -> JsonSelector {
        let query = NonEmpty::new(field_context().query()).unwrap();
        cipher
            .default_keyset()
            .json_selector(&JsonPath::parse("$.hello").unwrap(), query)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn an_entry_opens_under_the_column_the_scope_and_the_binding() {
        let (cipher, _) = common::cipher().await;
        let stored = sealed(&cipher).await;
        let hello = hello(&cipher).await;
        let extracted = JsonTreeExtracted::from_selector(&hello, entry_of(&stored, &hello));
        let opened = JsonPlaintext::decrypt_from_with_context(extracted, &cipher, field_context())
            .await
            .expect("opens");
        assert_eq!(opened.value(), &json!("world-1"), "the value at the path");
    }

    #[tokio::test]
    async fn an_entry_does_not_open_under_the_column_alone() {
        let (cipher, _) = common::cipher().await;
        let stored = sealed(&cipher).await;
        let hello = hello(&cipher).await;
        let extracted = JsonTreeExtracted::from_selector(&hello, entry_of(&stored, &hello));
        let column = Identifier::for_column("leads", "profile").unwrap();
        let opened = JsonPlaintext::decrypt_from_with_context(extracted, &cipher, column).await;
        assert!(
            matches!(opened, Err(Error::JsonNotALeaf)),
            "the tenant and the row are missing: {opened:?}"
        );
    }
}
