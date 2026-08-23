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
/// box behind an async `vitaminc_aead::Decipher`.
///
/// On native targets the returned futures are `Send` so callers can drive them
/// on a multi-threaded runtime. On wasm32 the bound is dropped, mirroring
/// [`ZeroKMSConnection`](crate::ZeroKMSConnection) and
/// [`stack_auth::AuthStrategy`]: the fetch-backed HTTP and auth futures there
/// aren't `Send`, and edge runtimes are single-threaded anyway.
#[cfg(not(target_arch = "wasm32"))]
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

/// See the native definition above; identical minus the `Send` bound on the
/// returned futures.
#[cfg(target_arch = "wasm32")]
pub trait DataKeySource {
    /// Generate one fresh data key per payload, in payload order.
    fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> impl Future<Output = Result<Vec<DataKeyWithTag>, Error>>;

    /// Re-derive one data key per payload, in payload order. Each payload's IV +
    /// tag (returned by a prior [`generate_keys`](DataKeySource::generate_keys)
    /// call and stored with the ciphertext) must reproduce the same key.
    fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> impl Future<Output = Result<Vec<DataKey>, Error>>;
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
    /// internal counter). The key material is derived from the IV and tag
    /// **together with** the `keyset_id`, per-payload `descriptor`, `context`
    /// and `decryption_policy` — the same inputs real ZeroKMS binds a data key
    /// to. `retrieve_keys` re-derives the key from those same inputs, so a
    /// generate-then-retrieve round-trip reproduces the key only when every one
    /// of them matches (as with real ZeroKMS), without credentials or network.
    ///
    /// Policies are mirrored too: a payload's `decryption_policy` is returned
    /// on the generated [`DataKeyWithTag`] (real ZeroKMS returns the resolved
    /// policy for storage beside the ciphertext) and bound into the derivation
    /// on both sides, so stripping or swapping the policy at retrieval yields
    /// different material — the fake's analogue of ZeroKMS's tag mismatch. As
    /// in the production client, a generate payload carrying a policy has its
    /// `context` dropped (`GenerateKeySpec::new_with_policy` sends none).
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

    /// Everything a fake data key is bound to. Mirrors the inputs the production
    /// client sends to ZeroKMS for one key.
    struct KeyInputs<'a> {
        keyset_id: Option<Uuid>,
        iv: &'a Iv,
        descriptor: &'a str,
        context: &'a [zerokms_protocol::Context],
        decryption_policy: Option<&'a zerokms_protocol::DecryptionPolicy>,
        tag: &'a [u8],
    }

    /// Deterministically derive 32 bytes of key material from [`KeyInputs`].
    /// Every field is length-prefixed (and `Option`s are tagged) so distinct
    /// inputs can't collide via ambiguous concatenation.
    fn derive_key(inputs: KeyInputs<'_>) -> Key {
        fn update_field(hasher: &mut Sha256, field: &[u8]) {
            hasher.update((field.len() as u64).to_le_bytes());
            hasher.update(field);
        }
        fn update_option(hasher: &mut Sha256, field: Option<&[u8]>) {
            match field {
                Some(bytes) => {
                    hasher.update([1u8]);
                    update_field(hasher, bytes);
                }
                None => hasher.update([0u8]),
            }
        }

        let context_json = serde_json::to_vec(inputs.context).unwrap_or_default();
        let policy_json = inputs
            .decryption_policy
            .map(|p| serde_json::to_vec(p).unwrap_or_default());

        let mut hasher = Sha256::new();
        hasher.update(b"stack-kms::FakeDataKeySource::v2");
        update_option(
            &mut hasher,
            inputs.keyset_id.as_ref().map(|id| id.as_bytes().as_slice()),
        );
        update_field(&mut hasher, inputs.iv);
        update_field(&mut hasher, inputs.descriptor.as_bytes());
        update_field(&mut hasher, &context_json);
        update_option(&mut hasher, policy_json.as_deref());
        update_field(&mut hasher, inputs.tag);
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
                .into_iter()
                .map(|payload| {
                    let n = self.counter.fetch_add(1, Ordering::Relaxed);
                    let mut iv: Iv = [0u8; 16];
                    iv[..8].copy_from_slice(&n.to_le_bytes());
                    let tag = format!("fake-kms-tag-{n}").into_bytes();
                    // Mirror `Client::generate_keys`: a policy-bearing spec is
                    // built with `new_with_policy`, which carries no context.
                    let context: &[zerokms_protocol::Context] =
                        if payload.decryption_policy.is_some() {
                            &[]
                        } else {
                            &payload.context
                        };
                    let key = derive_key(KeyInputs {
                        keyset_id,
                        iv: &iv,
                        descriptor: payload.descriptor,
                        context,
                        decryption_policy: payload.decryption_policy.as_ref(),
                        tag: &tag,
                    });
                    DataKeyWithTag {
                        key: DataKey { iv, key },
                        tag,
                        decryption_policy: payload.decryption_policy,
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
                    let key = derive_key(KeyInputs {
                        keyset_id,
                        iv: &iv,
                        descriptor: p.descriptor,
                        context: &p.context,
                        decryption_policy: p.decryption_policy.as_ref(),
                        tag: p.tag,
                    });
                    DataKey { iv, key }
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
    use zerokms_protocol::{Context, DecryptionPolicy, PolicyCondition};

    fn policy(claim: &str, value: &str) -> DecryptionPolicy {
        DecryptionPolicy {
            conditions: vec![PolicyCondition {
                claim: claim.to_string(),
                value: Some(value.to_string()),
            }],
        }
    }

    async fn generate_one(
        src: &FakeDataKeySource,
        payload: GenerateKeyPayload<'_>,
        keyset_id: Option<Uuid>,
    ) -> DataKeyWithTag {
        src.generate_keys(vec![payload], keyset_id, None)
            .await
            .unwrap()
            .remove(0)
    }

    async fn retrieve_one(
        src: &FakeDataKeySource,
        payload: RetrieveKeyPayload<'_>,
        keyset_id: Option<Uuid>,
    ) -> DataKey {
        src.retrieve_keys(vec![payload], keyset_id, None)
            .await
            .unwrap()
            .remove(0)
    }

    #[tokio::test]
    async fn generate_then_retrieve_reproduces_the_key() {
        let src = FakeDataKeySource::new();
        let dk = generate_one(
            &src,
            GenerateKeyPayload::new("users/email", Cow::Owned(vec![])),
            None,
        )
        .await;

        let retrieved = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "users/email", &dk.tag),
            None,
        )
        .await;

        assert_eq!(
            dk.key.key(),
            retrieved.key(),
            "retrieve must reproduce the generated key"
        );
        assert_eq!(dk.key.iv, retrieved.iv);
    }

    #[tokio::test]
    async fn generate_hands_out_unique_ivs_and_tags() {
        let src = FakeDataKeySource::new();
        let keys = src
            .generate_keys(
                vec![
                    GenerateKeyPayload::new("a", Cow::Owned(vec![])),
                    GenerateKeyPayload::new("a", Cow::Owned(vec![])),
                ],
                None,
                None,
            )
            .await
            .unwrap();

        assert_ne!(keys[0].key.iv, keys[1].key.iv);
        assert_ne!(keys[0].tag, keys[1].tag);
        assert_ne!(keys[0].key.key(), keys[1].key.key());
    }

    #[tokio::test]
    async fn mismatched_tag_yields_a_different_key() {
        let src = FakeDataKeySource::new();
        let dk = generate_one(&src, GenerateKeyPayload::new("d", Cow::Owned(vec![])), None).await;

        let wrong = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "d", b"wrong-tag"),
            None,
        )
        .await;

        assert_ne!(dk.key.key(), wrong.key());
    }

    #[tokio::test]
    async fn mismatched_iv_yields_a_different_key() {
        let src = FakeDataKeySource::new();
        let dk = generate_one(&src, GenerateKeyPayload::new("d", Cow::Owned(vec![])), None).await;

        let mut other_iv = dk.key.iv;
        other_iv[15] ^= 0xff;
        let wrong = retrieve_one(&src, RetrieveKeyPayload::new(other_iv, "d", &dk.tag), None).await;

        assert_ne!(
            dk.key.key(),
            wrong.key(),
            "the IV must feed the derivation, as it does in production"
        );
    }

    #[tokio::test]
    async fn mismatched_descriptor_yields_a_different_key() {
        let src = FakeDataKeySource::new();
        let dk = generate_one(
            &src,
            GenerateKeyPayload::new("users/email", Cow::Owned(vec![])),
            None,
        )
        .await;

        let wrong = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "users/name", &dk.tag),
            None,
        )
        .await;

        assert_ne!(dk.key.key(), wrong.key());
    }

    #[tokio::test]
    async fn mismatched_keyset_yields_a_different_key() {
        let src = FakeDataKeySource::new();
        let keyset = Uuid::new_v4();
        let dk = generate_one(
            &src,
            GenerateKeyPayload::new("d", Cow::Owned(vec![])),
            Some(keyset),
        )
        .await;

        let same = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag),
            Some(keyset),
        )
        .await;
        let other = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag),
            Some(Uuid::new_v4()),
        )
        .await;
        let none = retrieve_one(&src, RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag), None).await;

        assert_eq!(dk.key.key(), same.key());
        assert_ne!(dk.key.key(), other.key());
        assert_ne!(dk.key.key(), none.key());
    }

    #[tokio::test]
    async fn mismatched_context_yields_a_different_key() {
        let src = FakeDataKeySource::new();
        let ctx = vec![Context::Tag("tenant-1".into())];
        let dk = generate_one(
            &src,
            GenerateKeyPayload::new("d", Cow::Borrowed(&ctx)),
            None,
        )
        .await;

        let same = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag).with_context(Cow::Borrowed(&ctx)),
            None,
        )
        .await;
        let stripped =
            retrieve_one(&src, RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag), None).await;

        assert_eq!(dk.key.key(), same.key());
        assert_ne!(dk.key.key(), stripped.key());
    }

    #[tokio::test]
    async fn generate_returns_the_payloads_policy() {
        let src = FakeDataKeySource::new();
        let p = policy("sub", "alice");
        let dk = generate_one(
            &src,
            GenerateKeyPayload::new("d", Cow::Owned(vec![])).with_decryption_policy(p.clone()),
            None,
        )
        .await;

        assert_eq!(dk.decryption_policy.as_ref(), Some(&p));

        let without =
            generate_one(&src, GenerateKeyPayload::new("d", Cow::Owned(vec![])), None).await;
        assert!(without.decryption_policy.is_none());
    }

    #[tokio::test]
    async fn policy_round_trips_and_a_stripped_or_swapped_policy_changes_the_key() {
        let src = FakeDataKeySource::new();
        let p = policy("sub", "alice");
        let dk = generate_one(
            &src,
            GenerateKeyPayload::new("d", Cow::Owned(vec![])).with_decryption_policy(p.clone()),
            None,
        )
        .await;

        let same = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag).with_decryption_policy(p.clone()),
            None,
        )
        .await;
        let stripped =
            retrieve_one(&src, RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag), None).await;
        let swapped = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag)
                .with_decryption_policy(policy("sub", "mallory")),
            None,
        )
        .await;

        assert_eq!(dk.key.key(), same.key());
        assert_ne!(dk.key.key(), stripped.key());
        assert_ne!(dk.key.key(), swapped.key());
    }

    #[tokio::test]
    async fn a_policy_bearing_generate_payload_drops_its_context_like_the_client() {
        // `Client::generate_keys` builds `GenerateKeySpec::new_with_policy`,
        // which sends no context; the fake mirrors that so a retrieve without
        // context reproduces the key.
        let src = FakeDataKeySource::new();
        let p = policy("sub", "alice");
        let ctx = vec![Context::Tag("ignored".into())];
        let dk = generate_one(
            &src,
            GenerateKeyPayload::new("d", Cow::Borrowed(&ctx)).with_decryption_policy(p.clone()),
            None,
        )
        .await;

        let retrieved = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag).with_decryption_policy(p),
            None,
        )
        .await;

        assert_eq!(dk.key.key(), retrieved.key());
    }

    #[test]
    fn the_fake_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FakeDataKeySource>();
    }
}
