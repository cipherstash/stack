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

/// A key source whose every key is a function of a seed, the descriptor and
/// the IV, so a record sealed under it in one process opens in another built
/// from the same seed: what lets a committed fixture hold real sealed bytes.
///
/// `generate_keys` derives the IV from the seed, the descriptor and a
/// counter, and the key and tag from the seed, the descriptor and the IV;
/// `retrieve_keys` re-derives both from what the leaf stores and refuses a
/// tag that does not match, so a leaf opened under another descriptor is
/// refused as ZeroKMS would refuse it. The index key is
/// [`FakeDataKeySource`]'s, deterministic per keyset, so the terms here are
/// the terms every other test derives.
///
/// A test double, not a cipher: the derivation is SHA-256 over
/// concatenated parts and models nothing of ZeroKMS beyond determinism.
pub struct DeterministicSource {
    seed: [u8; 32],
    counter: std::sync::atomic::AtomicU64,
    index: FakeDataKeySource,
}

impl DeterministicSource {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: std::sync::atomic::AtomicU64::new(0),
            index: FakeDataKeySource::new(),
        }
    }

    fn derive(&self, what: &str, descriptor: &str, salt: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.seed);
        hasher.update(what.as_bytes());
        hasher.update([0u8]);
        hasher.update(descriptor.as_bytes());
        hasher.update([0u8]);
        hasher.update(salt);
        hasher.finalize().into()
    }
}

impl DataKeySource for DeterministicSource {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        _keyset_id: Option<Uuid>,
        _unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
        Ok(payloads
            .into_iter()
            .map(|payload| {
                let n = self.counter.fetch_add(1, AtomicOrdering::SeqCst);
                let iv_bytes = self.derive("iv", payload.descriptor, &n.to_le_bytes());
                let mut iv = stack_kms::Iv::default();
                let width = iv.len();
                iv.copy_from_slice(&iv_bytes[..width]);
                let key = self.derive("key", payload.descriptor, &iv);
                let tag = self.derive("tag", payload.descriptor, &iv);
                DataKeyWithTag {
                    key: DataKey { iv, key },
                    tag: tag.to_vec(),
                    decryption_policy: payload.decryption_policy,
                }
            })
            .collect())
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        _keyset_id: Option<Uuid>,
        _unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_kms::Error> {
        payloads
            .iter()
            .map(|payload| {
                let iv: stack_kms::Iv = *payload.iv.as_ref();
                let tag = self.derive("tag", payload.descriptor, &iv);
                if tag[..] != *payload.tag {
                    return Err(stack_kms::Error::RetrieveKey(
                        stack_kms::RetrieveKeyError::FailedRetrieval(
                            "the tag is not this descriptor's".to_string(),
                        ),
                    ));
                }
                let key = self.derive("key", payload.descriptor, &iv);
                Ok(DataKey { iv, key })
            })
            .collect()
    }
}

impl IndexKeySource for DeterministicSource {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
        self.index.load_index_key(keyset_id).await
    }
}

/// A cipher over [`DeterministicSource`] with `seed`.
pub async fn deterministic_cipher(seed: [u8; 32]) -> StackCipher<DeterministicSource> {
    StackCipher::builder()
        .kms(DeterministicSource::new(seed))
        .init()
        .await
        .expect("build cipher")
}
