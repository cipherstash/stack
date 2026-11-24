//! The crate's seal and open against the engine's typed API: each reads the
//! other's ciphertexts, so the bytes are the engine's, for every type.

use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};

use stack_encrypt::dynamic::{ValueFrame, ValueKind};
use stack_encrypt::json::JsonPlaintext;
use stack_encrypt::kms::{
    DataKey, DataKeySource, DataKeyWithTag, DeterministicSource, Error, GenerateKeyPayload,
    IdentifiedBy, IndexKey, IndexKeySource, KeySourceKind, OwnIdentity, RetrieveKeyPayload,
    UnverifiedContext,
};
use stack_encrypt::value::{Decimal, Timestamp};
use stack_encrypt::{Encrypt, StackCipher};
use uuid::Uuid;

use crate::cipher::{seal, unseal};
use crate::ciphertext::Ciphertext;
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
    OneValue::scalar(ValueFrame::of(value).unwrap()).unwrap()
}

/// Seal `values` through the crate, under the test keys.
async fn sdk_seal(values: Vec<OneValue>) -> Vec<stack_encrypt::Ciphertext> {
    seal(&engine().await.default_keyset(), values)
        .await
        .unwrap()
}

/// Open `sealed` through the crate, under the test keys.
async fn sdk_open(sealed: stack_encrypt::Ciphertext) -> ValueFrame {
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
    // vitaminc reads a `bigint` at its narrowest width; the engine opens it
    // at any width that holds it.
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
    let timestamp_frame = ValueFrame::of(&timestamp).unwrap();
    let decimal_frame = ValueFrame::of(&decimal).unwrap();
    let cases: Vec<(stack_encrypt::Ciphertext, ValueFrame)> = vec![
        (
            keyset.encrypt("text".to_owned()).await.unwrap(),
            ValueFrame::of("text").unwrap(),
        ),
        (
            keyset.encrypt(-7i64).await.unwrap(),
            ValueFrame::of(-7i64).unwrap(),
        ),
        (
            keyset.encrypt(u64::MAX).await.unwrap(),
            ValueFrame::of(u64::MAX).unwrap(),
        ),
        (
            keyset.encrypt(vec![0u8, 255]).await.unwrap(),
            ValueFrame::of(vec![0u8, 255]).unwrap(),
        ),
        (keyset.encrypt(timestamp).await.unwrap(), timestamp_frame),
        (keyset.encrypt(decimal).await.unwrap(), decimal_frame),
    ];
    for (sealed, expected) in cases {
        let stored = stack_encrypt::Ciphertext::from_bytes(&sealed.to_bytes()).unwrap();
        assert_eq!(sdk_open(stored).await, expected);
    }
}

#[tokio::test]
async fn a_json_document_the_engine_sealed_opens_as_json_with_its_big_integer() {
    let document = JsonPlaintext::from(serde_json::json!({"id": u64::MAX, "n": 5}));
    let sealed = engine()
        .await
        .default_keyset()
        .encrypt(document)
        .await
        .unwrap();
    let ciphertext = Ciphertext::new(sealed.clone(), Some(ValueKind::Json));
    let opened = ciphertext.opened(sdk_open(sealed).await).unwrap();
    // A safe integer opens as a float, as a JavaScript `number`; one outside
    // the safe range as an integer, a `bigint`.
    let expected = crate::json::document(&opened).unwrap();
    assert_eq!(
        expected.value(),
        &serde_json::json!({"id": u64::MAX, "n": 5})
    );
    assert_eq!(
        opened,
        ValueFrame::of(&OpenedDocument).unwrap(),
        "the opened frame holds `n` as a float and `id` as an integer"
    );
}

/// `{"id": u64::MAX, "n": 5.0}`, as the crate opens the document above.
struct OpenedDocument;

impl Encrypt for &OpenedDocument {
    fn visit<S: stack_encrypt::dynamic::plaintext::Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        use stack_encrypt::dynamic::plaintext::MapSink;
        let mut map = sink.map(Some(2))?;
        let _ = u64::MAX.visit(map.entry("id")?)?;
        let _ = 5.0f64.visit(map.entry("n")?)?;
        map.end()
    }
}

#[tokio::test]
async fn a_json_document_the_sdk_sealed_is_the_engines_json_plaintext() {
    let frame = ValueFrame::of(&Document).unwrap();
    let document = crate::json::document(&frame).unwrap();
    let sealed = sdk_seal(vec![OneValue::json(document)]).await.remove(0);
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

/// `{"name": "Ada", "age": 36.0, "big": u64::MAX}` as a JavaScript caller
/// hands it over: a number is a float, a `bigint` an integer.
struct Document;

impl Encrypt for &Document {
    fn visit<S: stack_encrypt::dynamic::plaintext::Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        use stack_encrypt::dynamic::plaintext::MapSink;
        let mut map = sink.map(Some(3))?;
        let _ = "Ada".visit(map.entry("name")?)?;
        let _ = 36.0f64.visit(map.entry("age")?)?;
        let _ = u64::MAX.visit(map.entry("big")?)?;
        map.end()
    }
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

/// A deterministic key source that counts the key requests it is sent.
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
    assert_eq!(
        opened,
        vec![
            ValueFrame::of("first").unwrap(),
            ValueFrame::of("second").unwrap(),
            ValueFrame::of("third").unwrap(),
        ]
    );
}

#[tokio::test]
async fn an_empty_array_makes_no_request() {
    let cipher = counting().await;
    let sealed = seal(&cipher.default_keyset(), vec![]).await.unwrap();
    assert!(sealed.is_empty());
    assert_eq!(cipher.kms().generates.load(Ordering::SeqCst), 0);
}

#[test]
fn a_uuid_is_outside_the_engines_value_model() {
    struct AUuid;
    impl Encrypt for &AUuid {
        fn visit<S: stack_encrypt::dynamic::plaintext::Sink>(
            self,
            sink: S,
        ) -> Result<S::Ok, S::Error> {
            use stack_encrypt::dynamic::plaintext::{Logical, Physical};
            sink.scalar(Some(Logical::Uuid), Physical::Bytes(&[7; 16]))
        }
    }
    assert!(ValueFrame::of(&AUuid).is_err());
}
