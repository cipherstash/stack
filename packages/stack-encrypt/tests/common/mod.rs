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
use std::sync::Arc;

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
}

impl CountingSource {
    pub fn new() -> Self {
        Self {
            inner: FakeDataKeySource::new(),
            generate_calls: Arc::new(AtomicUsize::new(0)),
            retrieve_calls: Arc::new(AtomicUsize::new(0)),
        }
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
        self.inner.load_index_key(keyset_id).await
    }
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
