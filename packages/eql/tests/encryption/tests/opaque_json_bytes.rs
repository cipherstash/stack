//! Byte pins for opaque JSON: a document sealed as one value, EQL's `json`
//! type (`public.eql_v4_json`, the `Json` target). The JSON tree
//! (`JsonSearch`) is another scheme and is not covered here.
//!
//! A language binding seals opaque JSON through a data plan: a field of type
//! `json` naming the `Json` target, whose value crosses as the document's
//! text in a text or bytes frame. A Rust program seals it through the typed
//! `Json` target from a `JsonPlaintext`. A sealed leaf carries a random
//! AES-GCM nonce, so the stored bytes cannot be compared. These tests seal
//! under the deterministic key source, keep the data keys it generated, open
//! each `c` leaf with them and stack-encrypt's leaf AAD, and pin the
//! plaintext that was sealed: the text leaf of the document's compact JSON,
//! the same leaf on every path, and the plain null for an absent document.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use eql_bindings::encryption::{EqlTargets, NativeCiphertextVisitor as NativeLeaf};
use eql_bindings::v3::terms::Ciphertext;
use eql_bindings::v4::json;
use eql_bindings::v4::plaintext::JsonPlaintext;
use eql_bindings::Identifier;
use serde_json::{json, Value};
use stack_encrypt::dynamic::{self, frame::OwnedFrame, record};
use stack_encrypt::target::transcode::{Reader, Visitor};
use stack_encrypt::{
    AsProtectedRef as _, CipherText, Encrypt, EncryptInto, NonEmpty, SealedValue, StackCipher,
    StackCipherText,
};
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, DeterministicSource, GenerateKeyPayload, IdentifiedBy,
    IndexKey, IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
};
use uuid::Uuid;
use vitaminc_aead::seal::Cipher;
use vitaminc_aead::{Context, FrameWriter, IntoContext, LocalCipherText, Unspecified};
use vitaminc_encrypt::{Aes256Cipher, Key as AesKey};
use vitaminc_protected::{Buffer, Controlled as _, Protected};

const SEED: [u8; 32] = *b"eql opaque json bytes v1        ";

/// The document every test seals, and its compact JSON text.
fn document() -> Value {
    json!({"a": [1, "x"], "b": null})
}
const TEXT: &str = r#"{"a":[1,"x"],"b":null}"#;

/// The leaf the document seals as on every path: the text tag `0x0a`, then
/// the compact JSON, with no length. It is the leaf stack-encrypt's
/// `tests/fixtures/value_bytes_v1.json` pins for a `JsonPlaintext` on the
/// typed Rust path (`json.typed_leaf.leaf`).
const DOCUMENT_LEAF: &str = "0a7b2261223a5b312c2278225d2c2262223a6e756c6c7d";

/// The leaf an absent document seals as: the plain null. A document has no
/// fixed length, so its null is not padded.
const NULL_LEAF: &str = "00";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// =============================================================================
// Opening a sealed leaf to the plaintext sealed in it
// =============================================================================

type Keys = Arc<Mutex<HashMap<Vec<u8>, [u8; 32]>>>;

/// [`DeterministicSource`], keeping each data key it generates by its IV.
struct KeptKeys {
    inner: DeterministicSource,
    keys: Keys,
}

impl stack_kms::KeySourceKind for KeptKeys {
    type Kind = stack_kms::OwnIdentity;
}

impl DataKeySource for KeptKeys {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
        let keys = self
            .inner
            .generate_keys(payloads, keyset_id, unverified_context)
            .await?;
        let mut kept = self.keys.lock().unwrap();
        for key in &keys {
            let _ = kept.insert(key.key.iv.to_vec(), *key.key.key());
        }
        Ok(keys)
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_kms::Error> {
        self.inner
            .retrieve_keys(payloads, keyset_id, unverified_context)
            .await
    }
}

impl IndexKeySource for KeptKeys {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
        self.inner.load_index_key(keyset_id).await
    }
}

async fn cipher() -> (StackCipher<KeptKeys>, Keys) {
    let keys = Keys::default();
    let cipher = StackCipher::builder()
        .kms(KeptKeys {
            inner: DeterministicSource::new(SEED),
            keys: Arc::clone(&keys),
        })
        .init()
        .await
        .expect("build cipher");
    (cipher, keys)
}

/// A vitaminc cipher that opens a stored leaf with its kept key, under the
/// AAD stack-encrypt binds a leaf to (`stack-encrypt/leaf`, the format
/// version, the keyset, the AAD of the leaf's place and the key tag, as a
/// PAE), and keeps each plaintext it opened.
struct Reveal<'k> {
    keys: &'k HashMap<Vec<u8>, [u8; 32]>,
    opened: RefCell<Vec<String>>,
}

impl Cipher for Reveal<'_> {
    type Leaf = SealedValue;
    type Error = Unspecified;

    fn seal(&self, _: Protected<Vec<u8>>, _: &Context<'_>) -> Result<SealedValue, Unspecified> {
        Err(Unspecified)
    }

    fn open(
        &self,
        leaf: SealedValue,
        aad: &Context<'_>,
    ) -> Result<Protected<Vec<u8>>, Unspecified> {
        let (keyset_id, iv, tag, ciphertext) = leaf.into_parts();
        let key = self.keys.get(iv.as_slice()).ok_or(Unspecified)?;
        let aad = Context::pae(&[
            b"stack-encrypt/leaf",
            &[SealedValue::FORMAT_VERSION],
            keyset_id.as_bytes(),
            aad.as_bytes(),
            &tag,
        ]);
        let cipher = Aes256Cipher::new(&AesKey::from(*key))?;
        let plaintext = cipher.open(LocalCipherText::from(ciphertext), &aad)?;
        self.opened.borrow_mut().push(hex(plaintext.risky_ref()));
        Ok(plaintext)
    }
}

/// The plaintext of the one leaf of a stored `c`, sealed under the column.
fn reveal(keys: &Keys, c: Ciphertext, column: NonEmpty<Identifier>) -> String {
    let tree: StackCipherText = c.read(NativeLeaf).expect("a stack-encrypt leaf");
    let keys = keys.lock().unwrap();
    let reveal = Reveal {
        keys: &keys,
        opened: RefCell::default(),
    };
    let mut out = Buffer::default();
    vitaminc_aead::decrypt_into(
        &reveal,
        tree,
        column.into_context(),
        FrameWriter::new(&mut out),
    )
    .unwrap_or_else(|_| panic!("the leaf opens under its kept key"));
    let mut opened = reveal.opened.into_inner();
    assert_eq!(opened.len(), 1, "one leaf");
    opened.remove(0)
}

// =============================================================================
// The paths
// =============================================================================

fn column() -> NonEmpty<Identifier> {
    Identifier::for_column("users", "profile").unwrap()
}

/// A data plan of one `json` field, `profile`, naming the opaque `Json`
/// target, as a binding writes it, with the field's `null` policy.
fn plan(null: Option<&str>) -> record::Plan {
    let mut field = json!({
        "context": ["users", "profile"],
        "type": "json",
        "target": {"name": "Json"},
    });
    if let Some(policy) = null {
        field["null"] = json!(policy);
    }
    record::plan_with(
        dynamic::frame::serde::to_vec(&json!({ "profile": field }))
            .unwrap()
            .as_protected_ref(),
        &EqlTargets,
    )
    .expect("a valid plan")
}

fn frame<T: Encrypt>(value: T) -> OwnedFrame {
    OwnedFrame::of(value).unwrap()
}

fn row(value: OwnedFrame) -> OwnedFrame {
    struct Row(OwnedFrame);
    impl Encrypt for Row {
        fn visit<S: vitaminc_aead::plaintext::Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            vitaminc_aead::plaintext::visit_map(sink, Some(1), [("profile", &self.0)])
        }
    }
    frame(Row(value))
}

/// The stored `public.eql_v4_json` value of `profile`, or `None` when the
/// field is stored as SQL `NULL`.
fn stored(row: &StackCipherText) -> Option<json::Json> {
    let CipherText::Map(fields) = row else {
        panic!("a row is a map")
    };
    let (_, CipherText::Map(outputs)) = fields.iter().find(|(name, _)| name == "profile")? else {
        panic!("profile is a map of outputs");
    };
    let Some((_, CipherText::Passthrough(payload))) = outputs.iter().find(|(key, _)| key == "eql")
    else {
        panic!("profile's EQL value is a passthrough");
    };
    let bytes = dynamic::frame::serde::from_slice::<Bytes>(&payload.0)
        .expect("the EQL value is bytes")
        .0;
    Some(serde_json::from_slice(&bytes).expect("the EQL value is a json value"))
}

/// A byte string read out of a frame.
struct Bytes(Vec<u8>);

impl<'de> serde::Deserialize<'de> for Bytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Read;
        impl serde::de::Visitor<'_> for Read {
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
        d.deserialize_bytes(Read)
    }
}

/// What the data plan stores for one `profile` value: the leaf of its `c`,
/// `None` for SQL `NULL`, or the refusal's reason.
async fn through_the_data_plan(
    cipher: &StackCipher<KeptKeys>,
    keys: &Keys,
    null: Option<&str>,
    value: OwnedFrame,
) -> Result<Option<String>, String> {
    let keyset = cipher.default_keyset();
    let pending =
        record::encrypt_with(&keyset, row(value), &plan(null), &EqlTargets).map_err(|error| {
            match error.reason() {
                Some(reason) => reason.as_str().to_owned(),
                None => error.to_string(),
            }
        })?;
    let sealed = pending.await.expect("the record seals");
    Ok(stored(&sealed).map(|stored| reveal(keys, stored.c, column())))
}

// =============================================================================
// The pins
// =============================================================================

/// The document's text, in a text frame or a bytes frame, seals through the
/// data plan as the typed path's text leaf.
#[tokio::test]
async fn the_data_plan_seals_a_document_as_the_typed_text_leaf() {
    let (cipher, keys) = cipher().await;
    // Spacing is the caller's: the document is sealed as its compact text.
    let spaced = r#" { "a" : [ 1, "x" ], "b" : null } "#;
    for value in [
        frame(String::from(TEXT)),
        frame(TEXT.as_bytes().to_vec()),
        frame(String::from(spaced)),
    ] {
        assert_eq!(
            through_the_data_plan(&cipher, &keys, None, value).await,
            Ok(Some(DOCUMENT_LEAF.into()))
        );
    }
}

/// The typed `Json` target seals a `JsonPlaintext` as the same leaf, and so
/// does stack-encrypt's `encrypt_tree` of it alone.
#[tokio::test]
async fn the_typed_target_seals_the_same_leaf() {
    let (cipher, keys) = cipher().await;
    let keyset = cipher.default_keyset();
    let typed: json::Json = JsonPlaintext::from(document())
        .encrypt_into_with_context(&keyset, column())
        .await
        .unwrap();
    assert_eq!(reveal(&keys, typed.c, column()), DOCUMENT_LEAF);

    let some: json::Json = Some(JsonPlaintext::from(document()))
        .encrypt_into_with_context(&keyset, column())
        .await
        .unwrap();
    assert_eq!(reveal(&keys, some.c, column()), DOCUMENT_LEAF);

    let tree = keyset
        .encrypt_tree(JsonPlaintext::from(document()), column())
        .await
        .unwrap();
    let CipherText::Single(leaf) = tree else {
        panic!("a document seals as one leaf")
    };
    let c = eql_bindings::encryption::CiphertextVisitor
        .sealed(leaf)
        .expect("an EQL ciphertext");
    assert_eq!(reveal(&keys, c, column()), DOCUMENT_LEAF);
}

/// An absent document: the typed target's `None` seals the plain null, with
/// no padding. Through the data plan, a null under `"sql"` stores nothing,
/// and a null with no `null` policy is refused before any key: the data plan
/// never seals an absent document.
#[tokio::test]
async fn an_absent_document_is_the_plain_null() {
    let (cipher, keys) = cipher().await;
    let keyset = cipher.default_keyset();
    let none: json::Json = None::<JsonPlaintext>
        .encrypt_into_with_context(&keyset, column())
        .await
        .unwrap();
    assert_eq!(reveal(&keys, none.c, column()), NULL_LEAF);

    let null = || {
        frame(vitaminc_aead::plaintext::Raw(
            None,
            vitaminc_aead::plaintext::Physical::Null,
        ))
    };
    assert_eq!(
        through_the_data_plan(&cipher, &keys, Some("sql"), null()).await,
        Ok(None)
    );
    let unset = through_the_data_plan(&cipher, &keys, None, null()).await;
    assert_eq!(unset, Err("field_type".into()));
}
