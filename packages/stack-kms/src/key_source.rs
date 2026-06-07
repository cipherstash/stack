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
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A deterministic, in-process [`DataKeySource`] for tests.
    ///
    /// `generate_keys` hands out a unique IV + tag per payload (driven by an
    /// internal counter) and derives the key material purely from the tag.
    /// `retrieve_keys` re-derives the same key from the stored tag, so a
    /// generate-then-retrieve round-trip reproduces the key, while a mismatched
    /// tag yields different material — exactly the binding property real ZeroKMS
    /// provides, without credentials or network.
    #[derive(Debug, Default)]
    pub struct FakeDataKeySource {
        counter: AtomicU64,
    }

    impl FakeDataKeySource {
        pub fn new() -> Self {
            Self::default()
        }
    }

    /// Derive 32 bytes of key material from a tag. Pure function of the tag, so
    /// generate and retrieve agree; non-degenerate for the empty tag.
    fn key_from_tag(tag: &[u8]) -> Key {
        let mut k = [0u8; 32];
        for (i, b) in tag.iter().enumerate() {
            k[i % 32] = k[i % 32]
                .wrapping_add(*b)
                .wrapping_add(i as u8)
                .wrapping_add(1);
        }
        k[0] = k[0].wrapping_add(tag.len() as u8).wrapping_add(0x5a);
        k
    }

    impl DataKeySource for FakeDataKeySource {
        async fn generate_keys(
            &self,
            payloads: Vec<GenerateKeyPayload<'_>>,
            _keyset_id: Option<Uuid>,
            _unverified_context: Option<Cow<'_, UnverifiedContext>>,
        ) -> Result<Vec<DataKeyWithTag>, Error> {
            Ok(payloads
                .iter()
                .map(|_| {
                    let n = self.counter.fetch_add(1, Ordering::Relaxed);
                    let mut iv: Iv = [0u8; 16];
                    iv[..8].copy_from_slice(&n.to_le_bytes());
                    let tag = format!("fake-kms-tag-{n}").into_bytes();
                    let key = key_from_tag(&tag);
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
            _keyset_id: Option<Uuid>,
            _unverified_context: Option<&UnverifiedContext>,
        ) -> Result<Vec<DataKey>, Error> {
            Ok(payloads
                .iter()
                .map(|p| {
                    let iv: Iv = *p.iv.as_ref();
                    DataKey {
                        iv,
                        key: key_from_tag(p.tag),
                    }
                })
                .collect())
        }
    }
}

#[cfg(feature = "test-support")]
pub use fake::FakeDataKeySource;
