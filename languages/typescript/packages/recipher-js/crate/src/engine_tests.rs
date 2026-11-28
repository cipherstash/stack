//! Tests of the crate's encrypt and decrypt against the engine's typed
//! Rust API. Each side decrypts the other's ciphertexts. So the tests show
//! that the crate writes the engine's bytes, for every type.

use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};

use stack_encrypt::dynamic::frame::OwnedFrame;
use stack_encrypt::dynamic::ValueKind;
use stack_encrypt::json::JsonPlaintext;
use stack_encrypt::kms::{
    DataKey, DataKeySource, DataKeyWithTag, DeterministicSource, Error, GenerateKeyPayload,
    IdentifiedBy, IndexKey, IndexKeySource, KeySourceKind, OwnIdentity, RetrieveKeyPayload,
    UnverifiedContext,
};
use stack_encrypt::value::{Decimal, Timestamp};
use stack_encrypt::{Encrypt, StackCipher};
use uuid::Uuid;

use crate::cipher::{open_in, seal, unseal, Confined, Engine};
use crate::ciphertext::{Ciphertext, Opened};
use crate::value::OneValue;

const SEED: [u8; 32] = [7; 32];

async fn engine() -> StackCipher<DeterministicSource> {
    StackCipher::builder()
        .kms(DeterministicSource::new(SEED))
        .init()
        .await
        .unwrap()
}

fn one<P: Encrypt>(value: P) -> OneValue {
    OneValue::scalar(OwnedFrame::of(value).unwrap()).unwrap()
}

/// Encrypts `values` through the crate, with the test keys.
async fn sdk_seal(values: Vec<OneValue>) -> Vec<stack_encrypt::Ciphertext> {
    seal(&engine().await.default_keyset(), values)
        .await
        .unwrap()
}

/// Decrypts `sealed` through the crate, with the test keys.
async fn sdk_open(sealed: stack_encrypt::Ciphertext) -> OwnedFrame {
    unseal(&engine().await, vec![sealed])
        .await
        .unwrap()
        .remove(0)
}

#[tokio::test]
async fn the_engine_opens_what_the_sdk_sealed() {
    let keyset = engine().await;
    let keyset = keyset.default_keyset();
    let sealed = sdk_seal(vec![one("from the sdk"), one(42i8), one(1.5f64)]).await;
    let mut sealed = sealed.into_iter();
    let text: String = keyset.decrypt(sealed.next().unwrap()).await.unwrap();
    // The value bridge reads a `bigint` at its narrowest width. The engine
    // decrypts it at any width that fits it.
    let int: i64 = keyset.decrypt(sealed.next().unwrap()).await.unwrap();
    let float: f64 = keyset.decrypt(sealed.next().unwrap()).await.unwrap();
    assert_eq!((text.as_str(), int, float), ("from the sdk", 42, 1.5));
}

#[tokio::test]
async fn the_sdk_opens_what_the_engine_sealed_of_every_type() {
    let cipher = engine().await;
    let keyset = cipher.default_keyset();
    let timestamp = Timestamp::new(
        "2026-11-23T01:02:03.000000001Z"
            .parse::<jiff::Timestamp>()
            .unwrap(),
    )
    .unwrap();
    let decimal = Decimal::new(rust_decimal::Decimal::new(150, 2));
    let timestamp_frame = OwnedFrame::of(&timestamp).unwrap();
    let decimal_frame = OwnedFrame::of(&decimal).unwrap();
    let cases: Vec<(stack_encrypt::Ciphertext, OwnedFrame)> = vec![
        (
            keyset.encrypt("text".to_owned()).await.unwrap(),
            OwnedFrame::of("text").unwrap(),
        ),
        (
            keyset.encrypt(-7i64).await.unwrap(),
            OwnedFrame::of(-7i64).unwrap(),
        ),
        (
            keyset.encrypt(u64::MAX).await.unwrap(),
            OwnedFrame::of(u64::MAX).unwrap(),
        ),
        (
            keyset.encrypt(vec![0u8, 255]).await.unwrap(),
            OwnedFrame::of(vec![0u8, 255]).unwrap(),
        ),
        (keyset.encrypt(timestamp).await.unwrap(), timestamp_frame),
        (keyset.encrypt(decimal).await.unwrap(), decimal_frame),
    ];
    for (sealed, expected) in cases {
        let stored = stack_encrypt::Ciphertext::from_bytes(&sealed.to_bytes()).unwrap();
        assert_eq!(sdk_open(stored).await.frame(), expected.frame());
    }
}

#[tokio::test]
async fn a_json_document_the_engine_sealed_opens_as_that_document() {
    let document = JsonPlaintext::from(serde_json::json!({"id": u64::MAX, "n": 5}));
    let sealed = engine()
        .await
        .default_keyset()
        .encrypt(document)
        .await
        .unwrap();
    let ciphertext = Ciphertext::new(sealed.clone(), Some(ValueKind::Json));
    let Opened::Document(opened) = ciphertext.opened(sdk_open(sealed).await).unwrap() else {
        panic!("a ciphertext read as JSON opens as a document");
    };
    assert_eq!(opened.value(), &serde_json::json!({"id": u64::MAX, "n": 5}));
}

/// Encrypts the document that `text` is the JSON text of, through the
/// crate, as `keyset.encrypt(json(..))` does once the bridge has written
/// the text.
async fn sdk_seal_json(text: &str) -> stack_encrypt::Ciphertext {
    let document = crate::json::plaintext(text.as_bytes()).unwrap();
    sdk_seal(vec![OneValue::json(document)]).await.remove(0)
}

#[tokio::test]
async fn a_json_document_the_sdk_sealed_is_the_engines_json_plaintext() {
    let sealed = sdk_seal_json(r#"{"name":"Ada","age":36,"big":18446744073709551615}"#).await;
    let opened: JsonPlaintext = engine()
        .await
        .default_keyset()
        .decrypt(sealed)
        .await
        .unwrap();
    assert_eq!(
        opened.value(),
        &serde_json::json!({"name": "Ada", "age": 36, "big": u64::MAX})
    );
}

#[tokio::test]
async fn a_json_document_is_stored_as_text_with_integers_and_sorted_members() {
    // The text the bridge writes for `json({ n: 5000000000, a: 1.5 })`.
    let sealed = sdk_seal_json(r#"{"n":5000000000,"a":1.5}"#).await;
    // The stored text is what a Go or a Rust reader parses. The integer
    // has no fraction, and the engine wrote the members in key order.
    let stored: String = engine()
        .await
        .default_keyset()
        .decrypt(sealed)
        .await
        .unwrap();
    assert_eq!(stored, r#"{"a":1.5,"n":5000000000}"#);
}

#[tokio::test]
async fn an_altered_ciphertext_does_not_open() {
    let mut bytes = sdk_seal(vec![one("intact")]).await.remove(0).to_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let altered = stack_encrypt::Ciphertext::from_bytes(&bytes).unwrap();
    let error = unseal(&engine().await, vec![altered]).await.unwrap_err();
    assert_eq!(error.code, "stack_encrypt::aead");
    assert!(!error.message.contains("intact"));
}

#[tokio::test]
async fn a_ciphertext_of_another_seed_does_not_open() {
    let other = StackCipher::builder()
        .kms(DeterministicSource::new([1; 32]))
        .init()
        .await
        .unwrap();
    let sealed = sdk_seal(vec![one("elsewhere")]).await;
    assert!(unseal(&other, sealed).await.is_err());
}

/// `keyset.decrypt` is confined to its keyset and `cipher.decrypt` is not.
/// The two differ only in the `Confined` they pass to `open_in`.
#[tokio::test]
async fn a_keyset_refuses_another_keysets_ciphertext_and_the_cipher_opens_it() {
    let cipher = engine().await;
    let other = cipher.keyset(stack_encrypt::kms::IdentifiedBy::Name(
        "another-keyset".to_owned().into(),
    ));
    let sealed = seal(&other, vec![one("in another keyset")]).await.unwrap();
    let engine = Engine::Testing(Box::new(cipher));

    let refused = open_in(&engine, sealed.clone(), Confined::ToDefault)
        .await
        .unwrap_err();
    assert_eq!(refused.code, "stack_encrypt::foreign_keyset");

    let opened = open_in(&engine, sealed, Confined::No)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(
        opened.frame(),
        OwnedFrame::of("in another keyset").unwrap().frame()
    );
}

/// A deterministic key source that counts the key requests it receives.
struct Counting {
    inner: DeterministicSource,
    generates: AtomicUsize,
    retrieves: AtomicUsize,
}

impl KeySourceKind for Counting {
    type Kind = OwnIdentity;
}

impl DataKeySource for Counting {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, Error> {
        let _ = self.generates.fetch_add(1, Ordering::SeqCst);
        self.inner
            .generate_keys(payloads, keyset_id, unverified_context)
            .await
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, Error> {
        let _ = self.retrieves.fetch_add(1, Ordering::SeqCst);
        self.inner
            .retrieve_keys(payloads, keyset_id, unverified_context)
            .await
    }
}

impl IndexKeySource for Counting {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), Error> {
        self.inner.load_index_key(keyset_id).await
    }
}

async fn counting() -> StackCipher<Counting> {
    StackCipher::builder()
        .kms(Counting {
            inner: DeterministicSource::new(SEED),
            generates: AtomicUsize::new(0),
            retrieves: AtomicUsize::new(0),
        })
        .init()
        .await
        .unwrap()
}

#[tokio::test]
async fn an_array_is_one_key_request_each_way_and_opens_in_order() {
    let cipher = counting().await;
    let sealed = seal(
        &cipher.default_keyset(),
        vec![one("first"), one("second"), one("third")],
    )
    .await
    .unwrap();
    assert_eq!(cipher.kms().generates.load(Ordering::SeqCst), 1);
    let opened = unseal(&cipher, sealed).await.unwrap();
    assert_eq!(cipher.kms().retrieves.load(Ordering::SeqCst), 1);
    let opened: Vec<_> = opened.iter().map(OwnedFrame::frame).collect();
    let expected = ["first", "second", "third"].map(|text| OwnedFrame::of(text).unwrap());
    let expected: Vec<_> = expected.iter().map(OwnedFrame::frame).collect();
    assert_eq!(opened, expected);
}

#[tokio::test]
async fn an_empty_array_makes_no_request() {
    let cipher = counting().await;
    let sealed = seal(&cipher.default_keyset(), vec![]).await.unwrap();
    assert!(sealed.is_empty());
    assert_eq!(cipher.kms().generates.load(Ordering::SeqCst), 0);
}
