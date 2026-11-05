//! Observe the lifetime of pending work independently of the provider's result.
//! Drop witnesses prove ownership release, not erasure of arbitrary host values.
#![cfg(feature = "dynamic")]

mod common;

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::future::IntoFuture;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Waker};

use common::frames::frame;
use stack_encrypt::dynamic::{record, Scope, ValueFrame};
use stack_encrypt::{Ciphertext, EncryptInto, Pending, StackCipher, StackCipherText};
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource, GenerateKeyError,
    GenerateKeyPayload, IdentifiedBy, IndexKey, IndexKeySource, RetrieveKeyPayload,
    UnverifiedContext,
};
use uuid::Uuid;
use vitaminc_protected::Controlled as _;

#[derive(Default)]
struct Observations {
    block: AtomicBool,
    fail: AtomicBool,
    batches: Mutex<Vec<usize>>,
    provider_drops: Arc<AtomicUsize>,
    retrievals: Mutex<Vec<usize>>,
    retrieve_drops: Arc<AtomicUsize>,
}

struct DropWitness(Arc<AtomicUsize>);

impl Drop for DropWitness {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct Source {
    inner: FakeDataKeySource,
    observed: Arc<Observations>,
}

impl DataKeySource for Source {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset: Option<Uuid>,
        context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
        self.observed.batches.lock().unwrap().push(payloads.len());
        let _owned_request = DropWitness(self.observed.provider_drops.clone());
        if self.observed.block.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        if self.observed.fail.load(Ordering::SeqCst) {
            return Err(GenerateKeyError::Unauthorized.into());
        }
        self.inner.generate_keys(payloads, keyset, context).await
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset: Option<Uuid>,
        context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_kms::Error> {
        self.observed
            .retrievals
            .lock()
            .unwrap()
            .push(payloads.len());
        let _owned_request = DropWitness(self.observed.retrieve_drops.clone());
        if self.observed.block.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        self.inner.retrieve_keys(payloads, keyset, context).await
    }
}

impl IndexKeySource for Source {
    async fn load_index_key(
        &self,
        keyset: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
        self.inner.load_index_key(keyset).await
    }
}

async fn cipher() -> (StackCipher<Source>, Arc<Observations>) {
    let observed = Arc::new(Observations::default());
    let cipher = StackCipher::builder()
        .kms(Source {
            inner: FakeDataKeySource::new(),
            observed: observed.clone(),
        })
        .init()
        .await
        .unwrap();
    (cipher, observed)
}

fn plan() -> record::Plan {
    record::plan(
        &vitaminc_aead_frame::serde::to_vec(&serde_json::json!({
            "value": {"context": ["lifecycle", "value"], "outputs": ["c"], "type": "string"}
        }))
        .unwrap()
        .risky_unwrap(),
    )
    .unwrap()
}

fn rows(count: usize) -> ValueFrame {
    frame(vec![BTreeMap::from([("value", "lifecycle-input")]); count])
}

// The witness is owned by the real operation's fulfilment, not by the test's
// future. Dropping it therefore observes release of that fulfilment's captures.
fn observed<'a, T: 'a>(
    pending: Pending<'a, T, Source>,
    drops: Arc<AtomicUsize>,
) -> Pending<'a, T, Source> {
    let witness = DropWitness(drops);
    pending.map(move |output| {
        drop(witness);
        output
    })
}

#[tokio::test]
async fn dropping_unpolled_work_releases_captures_without_key_io() {
    let (cipher, calls) = cipher().await;
    let keyset = cipher.default_keyset();
    let drops = Arc::new(AtomicUsize::new(0));
    let pending = observed(
        record::encrypt(&keyset, rows(2), &plan()).unwrap(),
        drops.clone(),
    );
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert!(calls.batches.lock().unwrap().is_empty());
    drop(pending);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(calls.batches.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cancelling_in_flight_work_drops_provider_and_captures() {
    let (cipher, calls) = cipher().await;
    calls.block.store(true, Ordering::SeqCst);
    let keyset = cipher.default_keyset();
    let drops = Arc::new(AtomicUsize::new(0));
    let mut future = observed(
        record::encrypt(&keyset, rows(3), &plan()).unwrap(),
        drops.clone(),
    )
    .into_future();
    assert!(future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert_eq!(*calls.batches.lock().unwrap(), vec![3]);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(calls.provider_drops.load(Ordering::SeqCst), 0);
    drop(future);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(calls.provider_drops.load(Ordering::SeqCst), 1);
    // Cancellation does not poison the cipher or execute the abandoned work.
    calls.block.store(false, Ordering::SeqCst);
    record::encrypt(&keyset, rows(1), &plan())
        .unwrap()
        .await
        .unwrap();
    assert_eq!(*calls.batches.lock().unwrap(), vec![3, 1]);
}

#[tokio::test]
async fn success_and_provider_failure_release_captures_once() {
    for fail in [false, true] {
        let (cipher, calls) = cipher().await;
        calls.fail.store(fail, Ordering::SeqCst);
        let keyset = cipher.default_keyset();
        let drops = Arc::new(AtomicUsize::new(0));
        let result = observed(
            record::encrypt(&keyset, rows(4), &plan()).unwrap(),
            drops.clone(),
        )
        .await;
        assert_eq!(result.is_err(), fail);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(calls.provider_drops.load(Ordering::SeqCst), 1);
        assert_eq!(*calls.batches.lock().unwrap(), vec![4]);
    }
}

async fn sealed(cipher: &StackCipher<Source>, count: usize) -> StackCipherText {
    record::encrypt(&cipher.default_keyset(), rows(count), &plan())
        .unwrap()
        .await
        .unwrap()
}

#[tokio::test]
async fn dropping_unpolled_decrypt_releases_captures_without_key_io() {
    let (cipher, calls) = cipher().await;
    let stored = sealed(&cipher, 2).await;
    let drops = Arc::new(AtomicUsize::new(0));
    let pending = observed(
        record::decrypt(Scope::Client(&cipher), stored, &plan(), None).unwrap(),
        drops.clone(),
    );
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert!(calls.retrievals.lock().unwrap().is_empty());
    drop(pending);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(calls.retrievals.lock().unwrap().is_empty());
    assert_eq!(calls.retrieve_drops.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancelling_in_flight_decrypt_drops_provider_and_captures() {
    let (cipher, calls) = cipher().await;
    let (stored, retry) = (sealed(&cipher, 3).await, sealed(&cipher, 3).await);
    calls.block.store(true, Ordering::SeqCst);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut future = observed(
        record::decrypt(Scope::Client(&cipher), stored, &plan(), None).unwrap(),
        drops.clone(),
    )
    .into_future();
    assert!(future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert_eq!(*calls.retrievals.lock().unwrap(), vec![3]);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(calls.retrieve_drops.load(Ordering::SeqCst), 0);
    drop(future);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(calls.retrieve_drops.load(Ordering::SeqCst), 1);
    // Cancellation does not poison the cipher or execute the abandoned work.
    calls.block.store(false, Ordering::SeqCst);
    let opened = record::decrypt(Scope::Client(&cipher), retry, &plan(), None)
        .unwrap()
        .await
        .unwrap();
    assert_eq!(opened.risky_ref(), rows(3).risky_ref());
    assert_eq!(*calls.retrievals.lock().unwrap(), vec![3, 3]);
    assert_eq!(calls.retrieve_drops.load(Ordering::SeqCst), 2);
}

// The owned collection conversion, `Vec<S>` to `Vec<T>`, runs the element
// declaration once per element and merges the results into one pending. The
// probes below hold it to the same lifecycle as a record operation.
fn owned_column<'a>(
    keyset: &'a stack_encrypt::KeysetCipher<'_, Source>,
    count: usize,
) -> Pending<'a, Vec<Ciphertext>, Source> {
    vec![String::from("lifecycle-input"); count].encrypt_into(keyset)
}

#[tokio::test]
async fn dropping_an_unpolled_owned_column_releases_captures_without_key_io() {
    let (cipher, calls) = cipher().await;
    let keyset = cipher.default_keyset();
    let drops = Arc::new(AtomicUsize::new(0));
    let pending = observed(owned_column(&keyset, 2), drops.clone());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert!(calls.batches.lock().unwrap().is_empty());
    drop(pending);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(calls.batches.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cancelling_an_owned_column_in_flight_drops_provider_and_captures() {
    let (cipher, calls) = cipher().await;
    calls.block.store(true, Ordering::SeqCst);
    let keyset = cipher.default_keyset();
    let drops = Arc::new(AtomicUsize::new(0));
    let mut future = observed(owned_column(&keyset, 3), drops.clone()).into_future();
    assert!(future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
    assert_eq!(*calls.batches.lock().unwrap(), vec![3]);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(calls.provider_drops.load(Ordering::SeqCst), 0);
    drop(future);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(calls.provider_drops.load(Ordering::SeqCst), 1);
    calls.block.store(false, Ordering::SeqCst);
    owned_column(&keyset, 1).await.unwrap();
    assert_eq!(*calls.batches.lock().unwrap(), vec![3, 1]);
}

#[tokio::test]
async fn an_owned_column_is_one_logical_batch_and_releases_captures_once() {
    for fail in [false, true] {
        let (cipher, calls) = cipher().await;
        calls.fail.store(fail, Ordering::SeqCst);
        let keyset = cipher.default_keyset();
        let drops = Arc::new(AtomicUsize::new(0));
        let result = observed(owned_column(&keyset, 4), drops.clone()).await;
        assert_eq!(result.is_err(), fail);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(calls.provider_drops.load(Ordering::SeqCst), 1);
        assert_eq!(*calls.batches.lock().unwrap(), vec![4]);
    }
}

#[tokio::test]
async fn an_empty_owned_column_makes_no_provider_call() {
    let (cipher, calls) = cipher().await;
    let keyset = cipher.default_keyset();
    let sealed = owned_column(&keyset, 0).await.unwrap();
    assert!(sealed.is_empty());
    assert!(calls.batches.lock().unwrap().is_empty());
}
