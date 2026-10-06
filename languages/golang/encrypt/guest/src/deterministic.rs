//! The deterministic key source of the `deterministic-kms` test build: a
//! copy of `DeterministicSource` in stack-encrypt's `tests/common/mod.rs`,
//! which sealed the record fixture (`tests/fixtures/record_lowering.json`).
//!
//! Every data key is `SHA-256(seed ‖ "key" ‖ 0 ‖ descriptor ‖ 0 ‖ iv)`, its
//! tag `SHA-256(seed ‖ "tag" ‖ 0 ‖ descriptor ‖ 0 ‖ iv)`, and the IV
//! `SHA-256(seed ‖ "iv" ‖ 0 ‖ descriptor ‖ 0 ‖ counter)[..16]`, where
//! `descriptor` is the context the leaf is sealed under as ZeroKMS renders
//! it. A leaf opens under its own field's descriptor and no other, as under
//! ZeroKMS. The index key is `FakeDataKeySource`'s, the same every test in
//! the repository derives terms under. So a Go test that loads this build
//! with the fixture's seed opens the records Rust sealed and derives the
//! same term bytes.
//!
//! It is a test double. The feature that compiles it is off by default, the
//! Go package never embeds this build, and the fixture README beside the
//! JSON file is the one definition both copies follow.

use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource, GenerateKeyPayload, IdentifiedBy,
    IndexKey, IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
};
use uuid::Uuid;

/// The seeded source. See the [module docs](self).
pub struct DeterministicSource {
    seed: [u8; 32],
    counter: AtomicU64,
    index: FakeDataKeySource,
}

impl DeterministicSource {
    /// A source over `seed`.
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: AtomicU64::new(0),
            index: FakeDataKeySource::new(),
        }
    }

    fn derive(&self, what: &str, descriptor: &str, salt: &[u8]) -> [u8; 32] {
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
                let n = self.counter.fetch_add(1, Ordering::SeqCst);
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
