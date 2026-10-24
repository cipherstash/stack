//! Fixtures shared by the integration test binaries.
//!
//! [`CountingSource`] is the fake source with ZeroKMS *call* counters (not
//! key counters): the design's whole claim is that an assembly of any size
//! settles in one batched call per request kind, and the tests hold it to
//! that.

// Each test binary uses a subset of these.
#![allow(dead_code)]

use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};

use stack_encrypt::StackCipher;
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource, GenerateKeyPayload, IdentifiedBy,
    IndexKey, IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
};
use uuid::Uuid;

/// A cipher over the deterministic fake source. The fake index key is
/// deterministic per keyset, so two separately built ciphers stand in for the
/// write path and a query path in another process.
pub async fn stack_cipher() -> StackCipher<FakeDataKeySource> {
    StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await
        .expect("build cipher")
}

pub struct CountingSource {
    inner: FakeDataKeySource,
    generate_calls: Arc<AtomicUsize>,
    retrieve_calls: Arc<AtomicUsize>,
    load_calls: Arc<AtomicUsize>,
}

impl CountingSource {
    pub fn new() -> Self {
        Self {
            inner: FakeDataKeySource::new(),
            generate_calls: Arc::new(AtomicUsize::new(0)),
            retrieve_calls: Arc::new(AtomicUsize::new(0)),
            load_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The counter of keyset lookups (`load_index_key` calls): what loading
    /// a keyset by id or name asks ZeroKMS.
    pub fn loads(&self) -> Arc<AtomicUsize> {
        self.load_calls.clone()
    }

    pub fn counters(&self) -> (Arc<AtomicUsize>, Arc<AtomicUsize>) {
        (self.generate_calls.clone(), self.retrieve_calls.clone())
    }
}

impl DataKeySource for CountingSource {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
        self.generate_calls.fetch_add(1, AtomicOrdering::SeqCst);
        self.inner
            .generate_keys(payloads, keyset_id, unverified_context)
            .await
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_kms::Error> {
        self.retrieve_calls.fetch_add(1, AtomicOrdering::SeqCst);
        self.inner
            .retrieve_keys(payloads, keyset_id, unverified_context)
            .await
    }
}

impl IndexKeySource for CountingSource {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
        self.load_calls.fetch_add(1, AtomicOrdering::SeqCst);
        self.inner.load_index_key(keyset_id).await
    }
}

/// A cipher over [`CountingSource`], with its counter of keyset lookups,
/// zeroed once the cipher has loaded its default keyset.
pub async fn loads_counting_cipher() -> (StackCipher<CountingSource>, Arc<AtomicUsize>) {
    let source = CountingSource::new();
    let loads = source.loads();
    let cipher = StackCipher::builder()
        .kms(source)
        .init()
        .await
        .expect("build cipher");
    loads.store(0, AtomicOrdering::SeqCst);
    (cipher, loads)
}

/// A cipher over [`CountingSource`], with its `(generate, retrieve)` call
/// counters.
pub async fn counting_cipher() -> (
    StackCipher<CountingSource>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let source = CountingSource::new();
    let (generates, retrieves) = source.counters();
    let cipher = StackCipher::builder()
        .kms(source)
        .init()
        .await
        .expect("build cipher");
    (cipher, generates, retrieves)
}

/// Every descriptor sent to ZeroKMS, per call, in payload order — what the
/// fake ignores but the real service binds into the key tag. Tests assert
/// against this, never against the fake's (non-)enforcement.
#[derive(Debug, Clone, Default)]
pub struct SentDescriptors {
    pub generate: Vec<Vec<String>>,
    pub retrieve: Vec<Vec<String>>,
}

impl SentDescriptors {
    /// Every generate-side descriptor, all calls flattened.
    pub fn generated(&self) -> Vec<String> {
        self.generate.iter().flatten().cloned().collect()
    }

    /// Every retrieve-side descriptor, all calls flattened.
    pub fn retrieved(&self) -> Vec<String> {
        self.retrieve.iter().flatten().cloned().collect()
    }
}

/// The fake source, recording the descriptor of every payload it is sent.
pub struct RecordingSource {
    inner: FakeDataKeySource,
    sent: Arc<Mutex<SentDescriptors>>,
}

impl RecordingSource {
    pub fn new() -> Self {
        Self {
            inner: FakeDataKeySource::new(),
            sent: Arc::new(Mutex::new(SentDescriptors::default())),
        }
    }

    pub fn sent(&self) -> Arc<Mutex<SentDescriptors>> {
        self.sent.clone()
    }
}

impl DataKeySource for RecordingSource {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
        self.sent
            .lock()
            .expect("lock")
            .generate
            .push(payloads.iter().map(|p| p.descriptor.to_owned()).collect());
        self.inner
            .generate_keys(payloads, keyset_id, unverified_context)
            .await
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_kms::Error> {
        self.sent
            .lock()
            .expect("lock")
            .retrieve
            .push(payloads.iter().map(|p| p.descriptor.to_owned()).collect());
        self.inner
            .retrieve_keys(payloads, keyset_id, unverified_context)
            .await
    }
}

impl IndexKeySource for RecordingSource {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
        self.inner.load_index_key(keyset_id).await
    }
}

/// A cipher over [`RecordingSource`], with the descriptors it sends.
pub async fn recording_cipher() -> (StackCipher<RecordingSource>, Arc<Mutex<SentDescriptors>>) {
    let source = RecordingSource::new();
    let sent = source.sent();
    let cipher = StackCipher::builder()
        .kms(source)
        .init()
        .await
        .expect("build cipher");
    (cipher, sent)
}

/// The deterministic source `stack-kms` ships behind `test-support`: the one
/// definition the record fixture, this suite and the Go guest's
/// `deterministic-kms` test build all read, so they cannot drift apart.
pub use stack_kms::DeterministicSource;

/// A cipher over [`DeterministicSource`] with `seed`.
pub async fn deterministic_cipher(seed: [u8; 32]) -> StackCipher<DeterministicSource> {
    StackCipher::builder()
        .kms(DeterministicSource::new(seed))
        .init()
        .await
        .expect("build cipher")
}

/// A passthrough payload: the frame of `value`, in the clear.
pub fn passthrough<P: stack_encrypt::Encrypt>(value: P) -> stack_encrypt::PassthroughFrame {
    use vitaminc_protected::Controlled;
    stack_encrypt::PassthroughFrame(
        vitaminc_aead::to_frame(value)
            .expect("a passthrough value frames")
            .risky_unwrap(),
    )
}

/// The `u32` a passthrough payload carries.
pub fn passthrough_u32(payload: &stack_encrypt::PassthroughFrame) -> u32 {
    use vitaminc_aead::Decrypt;
    let frame = payload.parse().expect("one frame");
    vitaminc_aead::Encrypt::visit(frame, u32::sink()).expect("a u32")
}

/// Values as a binding sends them: Rust values written as frames, and an
/// object of them in the order a test writes it.
#[cfg(feature = "dynamic")]
pub mod frames {
    use stack_encrypt::dynamic::ValueFrame;
    use stack_encrypt::Encrypt;
    use vitaminc_aead::plaintext::{visit_map, Sink};
    use vitaminc_protected::Controlled;

    /// A Rust value as its frame.
    pub fn frame<T: Encrypt>(value: T) -> ValueFrame {
        ValueFrame::of(value).expect("a value in the model")
    }

    /// An object of `entries`, in order.
    pub fn object<K: AsRef<str>>(entries: Vec<(K, ValueFrame)>) -> ValueFrame {
        frame(Object(entries))
    }

    /// A value as a passthrough node's payload: its frame, in the clear.
    pub fn payload<T: Encrypt>(value: T) -> Vec<u8> {
        frame(value).into_inner().risky_unwrap()
    }

    struct Object<K>(Vec<(K, ValueFrame)>);

    impl<K: AsRef<str>> Encrypt for Object<K> {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let len = Some(self.0.len());
            visit_map(
                sink,
                len,
                self.0.iter().map(|(key, value)| (key.as_ref(), value)),
            )
        }
    }
}
