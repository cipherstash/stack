//! An abstraction over the ZeroKMS data-key operations that higher-level
//! encryption layers (e.g. `stack-encrypt`) depend on.
//!
//! [`StackKms`](crate::StackKms) is the production implementation. Downstream
//! crates take a `K: DataKeySource` rather than a concrete client so their
//! encrypt/decrypt logic can be unit-tested against a deterministic in-memory
//! fake (see [`FakeDataKeySource`], enabled by the `test-support` feature)
//! without credentials or network access.

use std::borrow::Cow;
use std::future::Future;

use uuid::Uuid;
use zerokms_protocol::UnverifiedContext;

use crate::errors::Error;
use crate::key::{DataKey, DataKeyWithTag};
use crate::payload::{GenerateKeyPayload, RetrieveKeyPayload};

/// The slice of ZeroKMS data-key functionality required to encrypt and decrypt:
/// generating fresh data keys and re-deriving them for stored ciphertexts.
///
/// Both methods take an owned `Vec` of payloads (rather than `impl IntoIterator`)
/// so the trait stays simple to implement and the returned futures are easy to
/// box behind an async [`Decipher`](vitaminc_aead::Decipher).
pub trait DataKeySource {
    /// Generate one fresh data key per payload, in payload order.
    fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> impl Future<Output = Result<Vec<DataKeyWithTag>, Error>> + Send;

    /// Re-derive one data key per payload, in payload order. Each payload's IV +
    /// tag (returned by a prior [`generate_keys`](DataKeySource::generate_keys)
    /// call and stored with the ciphertext) must reproduce the same key.
    fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> impl Future<Output = Result<Vec<DataKey>, Error>> + Send;
}

impl<C> DataKeySource for crate::StackKms<C>
where
    C: stack_auth::AuthStrategyBounds,
    for<'a> &'a C: stack_auth::AuthStrategy,
{
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, Error> {
        // Disambiguate from the trait method of the same name: the inherent
        // method takes `impl IntoIterator`, which `Vec` satisfies.
        crate::StackKms::generate_keys(self, payloads, keyset_id, unverified_context).await
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, Error> {
        crate::StackKms::retrieve_keys(self, payloads, keyset_id, unverified_context).await
    }
}

#[cfg(feature = "test-support")]
mod fake {
    use super::*;
    use crate::key::DataKey;
    use recipher::key::{Iv, Key};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A deterministic, in-process [`DataKeySource`] for tests.
    ///
    /// `generate_keys` hands out a unique IV + tag per payload (driven by an
    /// internal counter). The key material is derived from the tag **together
    /// with** the `keyset_id`, per-payload `descriptor` and `context` — the same
    /// inputs real ZeroKMS binds a data key to. `retrieve_keys` re-derives the
    /// key from those same inputs, so a generate-then-retrieve round-trip
    /// reproduces the key only when the `keyset_id` / `descriptor` / `context`
    /// match (as with real ZeroKMS), without credentials or network.
    ///
    /// The derivation is a plain SHA-256: deterministic and binding, but **not**
    /// a stand-in for ZeroKMS's real key derivation. Use it for encrypt/decrypt
    /// round-trip and wrong-context tests, not for cryptographic assertions.
    #[derive(Debug, Default)]
    pub struct FakeDataKeySource {
        counter: AtomicU64,
    }

    impl FakeDataKeySource {
        pub fn new() -> Self {
            Self::default()
        }
    }

    /// Deterministically derive 32 bytes of key material, binding it to the same
    /// inputs real ZeroKMS does: keyset, descriptor, context and tag. Every field
    /// is length-prefixed so distinct inputs can't collide via ambiguous
    /// concatenation.
    fn derive_key(
        keyset_id: Option<Uuid>,
        descriptor: &str,
        context_json: &[u8],
        tag: &[u8],
    ) -> Key {
        fn update_field(hasher: &mut Sha256, field: &[u8]) {
            hasher.update((field.len() as u64).to_le_bytes());
            hasher.update(field);
        }

        let mut hasher = Sha256::new();
        hasher.update(b"stack-kms::FakeDataKeySource::v1");
        match keyset_id {
            Some(id) => {
                hasher.update([1u8]);
                update_field(&mut hasher, id.as_bytes());
            }
            None => hasher.update([0u8]),
        }
        update_field(&mut hasher, descriptor.as_bytes());
        update_field(&mut hasher, context_json);
        update_field(&mut hasher, tag);
        hasher.finalize().into()
    }

    impl DataKeySource for FakeDataKeySource {
        async fn generate_keys(
            &self,
            payloads: Vec<GenerateKeyPayload<'_>>,
            keyset_id: Option<Uuid>,
            _unverified_context: Option<Cow<'_, UnverifiedContext>>,
        ) -> Result<Vec<DataKeyWithTag>, Error> {
            Ok(payloads
                .iter()
                .map(|payload| {
                    let n = self.counter.fetch_add(1, Ordering::Relaxed);
                    let mut iv: Iv = [0u8; 16];
                    iv[..8].copy_from_slice(&n.to_le_bytes());
                    let tag = format!("fake-kms-tag-{n}").into_bytes();
                    let context_json = serde_json::to_vec(&payload.context).unwrap_or_default();
                    let key = derive_key(keyset_id, payload.descriptor, &context_json, &tag);
                    DataKeyWithTag {
                        key: DataKey { iv, key },
                        tag,
                        decryption_policy: None,
                    }
                })
                .collect())
        }

        async fn retrieve_keys(
            &self,
            payloads: Vec<RetrieveKeyPayload<'_>>,
            keyset_id: Option<Uuid>,
            _unverified_context: Option<&UnverifiedContext>,
        ) -> Result<Vec<DataKey>, Error> {
            Ok(payloads
                .iter()
                .map(|p| {
                    let iv: Iv = *p.iv.as_ref();
                    let context_json = serde_json::to_vec(&p.context).unwrap_or_default();
                    DataKey {
                        iv,
                        key: derive_key(keyset_id, p.descriptor, &context_json, p.tag),
                    }
                })
                .collect())
        }
    }
}

#[cfg(feature = "test-support")]
pub use fake::FakeDataKeySource;

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use crate::payload::{GenerateKeyPayload, RetrieveKeyPayload};
    use std::borrow::Cow;

    #[tokio::test]
    async fn round_trips_and_binds_the_key_to_the_descriptor() {
        let src = FakeDataKeySource::new();

        let generated = src
            .generate_keys(
                vec![GenerateKeyPayload::new("users/email", Cow::Owned(vec![]))],
                None,
                None,
            )
            .await
            .unwrap();
        let dk = &generated[0];

        // Same descriptor + tag reproduces the exact key material.
        let retrieved = src
            .retrieve_keys(
                vec![RetrieveKeyPayload::new(dk.key.iv, "users/email", &dk.tag)],
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(dk.key.key(), retrieved[0].key());

        // Retrieving the same tag under a *different* descriptor yields different
        // material — the fake now binds like real ZeroKMS rather than keying on
        // the tag alone.
        let wrong = src
            .retrieve_keys(
                vec![RetrieveKeyPayload::new(dk.key.iv, "users/name", &dk.tag)],
                None,
                None,
            )
            .await
            .unwrap();
        assert_ne!(dk.key.key(), wrong[0].key());
    }
}
