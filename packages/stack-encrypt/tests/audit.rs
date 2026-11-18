//! Audit metadata reaches ZeroKMS as the key requests' unverified context:
//! on encrypt and decrypt, through every public way to make a call, once
//! per request in a batch, and not at all when the caller gives none.
//!
//! Every test runs against a fake key source that records the context each
//! request carried, so none needs the network.

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use stack_encrypt::kms::{
    DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource, GenerateKeyPayload, IdentifiedBy,
    IndexKey, IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
};
use stack_encrypt::{
    all, AuditError, AuditMetadata, Ciphertext, Equality, Error, Pending, Plan, StackCipher,
};
use uuid::Uuid;

/// Which key call a request was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    Generate,
    Retrieve,
}

/// One key request as the key source received it: the call, and its
/// unverified context as JSON (`None` when the request carried none).
type Sent = (Call, Option<Value>);

/// A fake key source that records the unverified context of every key
/// request.
#[derive(Clone)]
struct RecordingSource {
    inner: Arc<FakeDataKeySource>,
    sent: Arc<Mutex<Vec<Sent>>>,
}

impl RecordingSource {
    fn new() -> Self {
        Self {
            inner: Arc::new(FakeDataKeySource::new()),
            sent: Arc::default(),
        }
    }

    fn record(&self, call: Call, context: Option<&UnverifiedContext>) {
        let context = context.map(|context| serde_json::to_value(context).unwrap());
        self.sent.lock().unwrap().push((call, context));
    }

    /// The requests made so far, cleared.
    fn take(&self) -> Vec<Sent> {
        std::mem::take(&mut *self.sent.lock().unwrap())
    }
}

impl DataKeySource for RecordingSource {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_encrypt::kms::Error> {
        self.record(Call::Generate, unverified_context.as_deref());
        self.inner
            .generate_keys(payloads, keyset_id, unverified_context)
            .await
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_encrypt::kms::Error> {
        self.record(Call::Retrieve, unverified_context);
        self.inner
            .retrieve_keys(payloads, keyset_id, unverified_context)
            .await
    }
}

impl IndexKeySource for RecordingSource {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_encrypt::kms::Error> {
        self.inner.load_index_key(keyset_id).await
    }
}

async fn cipher() -> (StackCipher<RecordingSource>, RecordingSource) {
    let source = RecordingSource::new();
    let cipher = StackCipher::builder()
        .kms(source.clone())
        .init()
        .await
        .expect("build cipher");
    (cipher, source)
}

fn list_issues() -> AuditMetadata {
    AuditMetadata::new()
        .with("purpose", "list issues")
        .with("request_id", "req_01J9Z3")
}

fn list_issues_json() -> Value {
    json!({ "purpose": "list issues", "request_id": "req_01J9Z3" })
}

#[tokio::test]
async fn a_scalar_encrypt_and_decrypt_send_their_metadata() {
    let (cipher, source) = cipher().await;
    let keyset = cipher.default_keyset();

    let stored: Ciphertext = keyset
        .encrypt(String::from("sk_live_1234"))
        .audit(AuditMetadata::new().with("purpose", "store api key"))
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![(Call::Generate, Some(json!({ "purpose": "store api key" })))]
    );

    let back: String = keyset.decrypt(stored).audit(list_issues()).await.unwrap();
    assert_eq!(back, "sk_live_1234");
    assert_eq!(
        source.take(),
        vec![(Call::Retrieve, Some(list_issues_json()))]
    );
}

/// With no metadata the key source receives `None`, as it did before audit
/// metadata existed, and empty metadata is the same as none.
#[tokio::test]
async fn no_metadata_sends_no_context() {
    let (cipher, source) = cipher().await;
    let keyset = cipher.default_keyset();

    let stored: Ciphertext = keyset.encrypt(7i64).await.unwrap();
    let back: i64 = keyset
        .decrypt(stored)
        .audit(AuditMetadata::new())
        .await
        .unwrap();
    assert_eq!(back, 7);
    assert_eq!(
        source.take(),
        vec![(Call::Generate, None), (Call::Retrieve, None)]
    );
}

/// The metadata is not bound into anything, so a decrypt may send other
/// metadata than the encrypt did, or none.
#[tokio::test]
async fn decrypt_metadata_need_not_match_encrypt_metadata() {
    let (cipher, source) = cipher().await;
    let keyset = cipher.default_keyset();

    let stored: Ciphertext = keyset
        .encrypt_with_context(42i64, "users/age")
        .audit(AuditMetadata::new().with("purpose", "signup"))
        .await
        .unwrap();
    let back: i64 = keyset
        .decrypt_with_context(stored.clone(), "users/age")
        .audit(AuditMetadata::new().with("purpose", "profile page"))
        .await
        .unwrap();
    assert_eq!(back, 42);
    let back: i64 = keyset
        .decrypt_with_context(stored, "users/age")
        .await
        .unwrap();
    assert_eq!(back, 42);
    assert_eq!(
        source.take(),
        vec![
            (Call::Generate, Some(json!({ "purpose": "signup" }))),
            (Call::Retrieve, Some(json!({ "purpose": "profile page" }))),
            (Call::Retrieve, None),
        ]
    );
}

/// A batch is one key request, and metadata attached to the merged call
/// goes on it once.
#[tokio::test]
async fn a_batch_sends_its_metadata_on_its_one_request() {
    let (cipher, source) = cipher().await;
    let keyset = cipher.default_keyset();

    let stored = Pending::all(
        &keyset,
        vec![
            keyset.encrypt(1i64),
            keyset.encrypt(2i64),
            keyset.encrypt(3i64),
        ],
    )
    .audit(list_issues())
    .await
    .unwrap();
    assert_eq!(
        source.take(),
        vec![(Call::Generate, Some(list_issues_json()))]
    );

    let opened: Vec<i64> = Pending::all(
        &keyset,
        stored
            .into_iter()
            .map(|ciphertext| keyset.decrypt(ciphertext))
            .collect(),
    )
    .audit(list_issues())
    .await
    .unwrap();
    assert_eq!(opened, vec![1, 2, 3]);
    assert_eq!(
        source.take(),
        vec![(Call::Retrieve, Some(list_issues_json()))]
    );
}

/// Parts that carry the same metadata, or none, merge. The batch keeps it.
#[tokio::test]
async fn parts_with_the_same_metadata_or_none_merge() {
    let (cipher, source) = cipher().await;
    let keyset = cipher.default_keyset();

    let (_, _): (Ciphertext, Ciphertext) = keyset
        .encrypt(1i64)
        .audit(list_issues())
        .zip(keyset.encrypt(2i64).audit(list_issues()))
        .await
        .unwrap();
    let (_, _): (Ciphertext, Ciphertext) = keyset
        .encrypt(1i64)
        .zip(keyset.encrypt(2i64).audit(list_issues()))
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![
            (Call::Generate, Some(list_issues_json())),
            (Call::Generate, Some(list_issues_json())),
        ]
    );
}

/// One request carries one map, so merging parts with different metadata
/// is refused before any request.
#[tokio::test]
async fn parts_with_different_metadata_do_not_merge() {
    let (cipher, source) = cipher().await;
    let keyset = cipher.default_keyset();

    let zipped = keyset
        .encrypt(1i64)
        .audit(AuditMetadata::new().with("purpose", "a"))
        .zip(
            keyset
                .encrypt(2i64)
                .audit(AuditMetadata::new().with("purpose", "b")),
        )
        .await;
    assert!(matches!(zipped, Err(Error::Audit(AuditError::Mismatch))));

    let collected = Pending::all(
        &keyset,
        vec![
            keyset
                .encrypt(1i64)
                .audit(AuditMetadata::new().with("purpose", "a")),
            keyset
                .encrypt(2i64)
                .audit(AuditMetadata::new().with("purpose", "b")),
        ],
    )
    .await;
    assert!(matches!(collected, Err(Error::Audit(AuditError::Mismatch))));
    assert_eq!(source.take(), vec![]);
}

/// Attaching metadata to the merged call replaces what its parts carried.
#[tokio::test]
async fn metadata_on_the_merged_call_replaces_the_parts() {
    let (cipher, source) = cipher().await;
    let keyset = cipher.default_keyset();

    let _: (Ciphertext, Ciphertext) = keyset
        .encrypt(1i64)
        .audit(AuditMetadata::new().with("purpose", "a"))
        .zip(keyset.encrypt(2i64))
        .audit(list_issues())
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![(Call::Generate, Some(list_issues_json()))]
    );
}

/// A number ZeroKMS cannot record exactly is refused before any request.
#[tokio::test]
async fn an_unrepresentable_number_is_refused_before_any_request() {
    let (cipher, source) = cipher().await;
    let keyset = cipher.default_keyset();

    let refused = keyset
        .encrypt(1i64)
        .audit(AuditMetadata::new().with("rows", u64::MAX))
        .await;
    assert!(matches!(
        refused,
        Err(Error::Audit(AuditError::NumberOutOfRange { ref key })) if key == "rows"
    ));
    assert_eq!(source.take(), vec![]);
}

/// A pending that already failed keeps its own error.
#[tokio::test]
async fn a_failed_call_keeps_its_own_error() {
    let (cipher, _source) = cipher().await;
    let failed: Pending<'_, i64, _> = Pending::failed(&cipher, Error::NoKeyset);
    let result = failed
        .audit(AuditMetadata::new().with("rows", u64::MAX))
        .await;
    assert!(matches!(result, Err(Error::NoKeyset)));
}

/// The tree entry points return a `Pending` too, so they take metadata.
/// Opening leaves from two keysets is one retrieve call per keyset, and
/// each carries the metadata.
#[tokio::test]
async fn trees_send_their_metadata_on_every_request() {
    let (cipher, source) = cipher().await;
    let first = cipher.default_keyset();
    let second = cipher
        .keyset(IdentifiedBy::Name("tenant-b".to_string().into()))
        .await
        .unwrap();

    let a = first
        .encrypt_tree(String::from("alice"), "users/name")
        .audit(list_issues())
        .await
        .unwrap();
    let b = second
        .encrypt_tree(String::from("bob"), "users/name")
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![
            (Call::Generate, Some(list_issues_json())),
            (Call::Generate, None),
        ]
    );

    let name: String = first
        .decrypt_tree(a, "users/name")
        .audit(list_issues())
        .await
        .unwrap();
    assert_eq!(name, "alice");
    assert_eq!(
        source.take(),
        vec![(Call::Retrieve, Some(list_issues_json()))]
    );

    let a = first
        .encrypt_tree(String::from("alice"), "users/name")
        .await
        .unwrap();
    let _ = source.take();

    let both: (String, String) = cipher
        .decrypt(a, "users/name")
        .zip(cipher.decrypt(b, "users/name"))
        .audit(list_issues())
        .await
        .unwrap();
    assert_eq!(both, ("alice".into(), "bob".into()));
    assert_eq!(
        source.take(),
        vec![
            (Call::Retrieve, Some(list_issues_json())),
            (Call::Retrieve, Some(list_issues_json())),
        ]
    );
}

#[tokio::test]
async fn plan_chains_send_their_metadata() {
    let (cipher, source) = cipher().await;
    let email_plan = Plan::context("users/email").with(Equality).build().unwrap();
    let email = String::from("bob@example.com");

    let written = cipher
        .encrypt(&email)
        .using(&email_plan)
        .audit(list_issues())
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![(Call::Generate, Some(list_issues_json()))]
    );

    let back: String = cipher
        .open(written)
        .using(&email_plan)
        .audit(AuditMetadata::new().with("purpose", "send receipt"))
        .await
        .unwrap();
    assert_eq!(back, email);
    assert_eq!(
        source.take(),
        vec![(Call::Retrieve, Some(json!({ "purpose": "send receipt" })))]
    );
}

/// `all` makes one request for its chains, and metadata on the batch goes
/// on it.
#[tokio::test]
async fn a_batch_of_chains_sends_its_metadata() {
    let (cipher, source) = cipher().await;
    let email_plan = Plan::context("users/email").with(Equality).build().unwrap();
    let (alice, bob) = (
        String::from("alice@example.com"),
        String::from("bob@example.com"),
    );

    let _ = all((
        cipher.encrypt(&alice).using(&email_plan),
        cipher.encrypt(&bob).using(&email_plan),
    ))
    .audit(list_issues())
    .await
    .unwrap();
    assert_eq!(
        source.take(),
        vec![(Call::Generate, Some(list_issues_json()))]
    );

    let mismatched = all((
        cipher
            .encrypt(&alice)
            .using(&email_plan)
            .audit(AuditMetadata::new().with("purpose", "a")),
        cipher
            .encrypt(&bob)
            .using(&email_plan)
            .audit(AuditMetadata::new().with("purpose", "b")),
    ))
    .await;
    assert!(matches!(
        mismatched,
        Err(Error::Audit(AuditError::Mismatch))
    ));
    assert_eq!(source.take(), vec![]);
}
