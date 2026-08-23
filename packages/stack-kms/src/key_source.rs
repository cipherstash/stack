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
    use crate::errors::RetrieveKeyError;
    use crate::key::DataKey;
    use recipher::key::{Iv, Key};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A deterministic, in-process [`DataKeySource`] for tests.
    ///
    /// Mirrors the *shape* of ZeroKMS's key/tag split so error behaviour matches
    /// production, without credentials or network:
    ///
    /// * **Key material** is derived from the `keyset_id`, the IV and the
    ///   `descriptor` only — as in ZeroKMS, where it is a function of the IV,
    ///   descriptor and the keyset's authority key, never of the tag, context
    ///   or policy.
    /// * **The tag** binds the `keyset_id`, IV, descriptor and either the
    ///   `decryption_policy` (policy-bearing "v1" keys, where context is
    ///   ignored on both sides — `GenerateKeySpec::new_with_policy` sends none
    ///   and `create_v1_tag` does not read it) or the `context` ("v0" keys).
    /// * **`retrieve_keys` recomputes the expected tag** from the retrieve
    ///   payload and rejects a mismatch with
    ///   [`RetrieveKeyError::FailedRetrieval`](crate::errors::RetrieveKeyError::FailedRetrieval),
    ///   as ZeroKMS rejects a failed tag proof — it never returns wrong key
    ///   material. So a wrong IV, descriptor, keyset, context or policy
    ///   surfaces as `Err`, not as an AEAD failure downstream.
    ///
    /// `generate_keys` hands out a unique IV per payload (driven by an internal
    /// counter) and returns the payload's `decryption_policy` on the
    /// [`DataKeyWithTag`], as real ZeroKMS returns the resolved policy for
    /// storage beside the ciphertext.
    ///
    /// The derivations are plain SHA-256: deterministic and binding, but **not**
    /// a stand-in for ZeroKMS's real key derivation or HMAC tag. Use it for
    /// encrypt/decrypt round-trip and wrong-context/policy tests, not for
    /// cryptographic assertions.
    #[derive(Debug, Default)]
    pub struct FakeDataKeySource {
        counter: AtomicU64,
    }

    impl FakeDataKeySource {
        pub fn new() -> Self {
            Self::default()
        }
    }

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

    /// Key material: a function of the keyset, IV and descriptor only. Every
    /// field is length-prefixed (and `Option`s tagged) so distinct inputs can't
    /// collide via ambiguous concatenation.
    fn derive_key(keyset_id: Option<Uuid>, iv: &Iv, descriptor: &str) -> Key {
        let mut hasher = Sha256::new();
        hasher.update(b"stack-kms::FakeDataKeySource::key::v3");
        update_option(
            &mut hasher,
            keyset_id.as_ref().map(|id| id.as_bytes().as_slice()),
        );
        update_field(&mut hasher, iv);
        update_field(&mut hasher, descriptor.as_bytes());
        hasher.finalize().into()
    }

    /// Everything the fake tag binds. Mirrors what ZeroKMS's HMAC tag covers
    /// for one key.
    struct TagInputs<'a> {
        keyset_id: Option<Uuid>,
        iv: &'a Iv,
        descriptor: &'a str,
        context: &'a [zerokms_protocol::Context],
        decryption_policy: Option<&'a zerokms_protocol::DecryptionPolicy>,
    }

    /// The tag: binds keyset, IV, descriptor and *either* the policy (v1 —
    /// context ignored) *or* the context (v0), exactly as `create_v1_tag` /
    /// `create_v0_tag` split them.
    fn derive_tag(inputs: TagInputs<'_>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"stack-kms::FakeDataKeySource::tag::v3");
        update_option(
            &mut hasher,
            inputs.keyset_id.as_ref().map(|id| id.as_bytes().as_slice()),
        );
        update_field(&mut hasher, inputs.iv);
        update_field(&mut hasher, inputs.descriptor.as_bytes());
        match inputs.decryption_policy {
            Some(policy) => {
                hasher.update([1u8]);
                update_field(&mut hasher, &serde_json::to_vec(policy).unwrap_or_default());
            }
            None => {
                hasher.update([0u8]);
                update_field(
                    &mut hasher,
                    &serde_json::to_vec(inputs.context).unwrap_or_default(),
                );
            }
        }
        hasher.finalize().to_vec()
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
                    let key = derive_key(keyset_id, &iv, payload.descriptor);
                    let tag = derive_tag(TagInputs {
                        keyset_id,
                        iv: &iv,
                        descriptor: payload.descriptor,
                        context: &payload.context,
                        decryption_policy: payload.decryption_policy.as_ref(),
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
            payloads
                .iter()
                .map(|p| {
                    let iv: Iv = *p.iv.as_ref();
                    let expected = derive_tag(TagInputs {
                        keyset_id,
                        iv: &iv,
                        descriptor: p.descriptor,
                        context: &p.context,
                        decryption_policy: p.decryption_policy.as_ref(),
                    });
                    // A fake, so a plain comparison is fine; ZeroKMS compares
                    // its HMAC tags in constant time.
                    if expected != p.tag {
                        return Err(Error::RetrieveKey(RetrieveKeyError::FailedRetrieval(
                            "tag mismatch: the iv, descriptor, keyset, context or policy \
                             differs from what the key was generated under"
                                .to_string(),
                        )));
                    }
                    Ok(DataKey {
                        iv,
                        key: derive_key(keyset_id, &iv, p.descriptor),
                    })
                })
                .collect()
        }
    }
}

#[cfg(feature = "test-support")]
pub use fake::FakeDataKeySource;

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use crate::errors::RetrieveKeyError;
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
    ) -> Result<DataKey, Error> {
        src.retrieve_keys(vec![payload], keyset_id, None)
            .await
            .map(|mut keys| keys.remove(0))
    }

    fn assert_rejected(result: Result<DataKey, Error>, what: &str) {
        match result {
            Err(Error::RetrieveKey(RetrieveKeyError::FailedRetrieval(_))) => {}
            Err(other) => panic!("{what}: expected FailedRetrieval, got {other:?}"),
            Ok(_) => panic!("{what}: expected rejection, got a key"),
        }
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
        .await
        .unwrap();

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
    async fn mismatched_tag_is_rejected() {
        // ZeroKMS fails the tag proof rather than returning other material.
        let src = FakeDataKeySource::new();
        let dk = generate_one(&src, GenerateKeyPayload::new("d", Cow::Owned(vec![])), None).await;

        let result = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "d", b"wrong-tag"),
            None,
        )
        .await;
        assert_rejected(result, "wrong tag");
    }

    #[tokio::test]
    async fn mismatched_iv_is_rejected() {
        let src = FakeDataKeySource::new();
        let dk = generate_one(&src, GenerateKeyPayload::new("d", Cow::Owned(vec![])), None).await;

        let mut other_iv = dk.key.iv;
        other_iv[15] ^= 0xff;
        let result =
            retrieve_one(&src, RetrieveKeyPayload::new(other_iv, "d", &dk.tag), None).await;
        assert_rejected(result, "wrong iv");
    }

    #[tokio::test]
    async fn mismatched_descriptor_is_rejected() {
        let src = FakeDataKeySource::new();
        let dk = generate_one(
            &src,
            GenerateKeyPayload::new("users/email", Cow::Owned(vec![])),
            None,
        )
        .await;

        let result = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "users/name", &dk.tag),
            None,
        )
        .await;
        assert_rejected(result, "wrong descriptor");
    }

    #[tokio::test]
    async fn mismatched_keyset_is_rejected() {
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
        .await
        .unwrap();
        assert_eq!(dk.key.key(), same.key());

        let other = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag),
            Some(Uuid::new_v4()),
        )
        .await;
        assert_rejected(other, "other keyset");

        let none = retrieve_one(&src, RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag), None).await;
        assert_rejected(none, "no keyset");
    }

    #[tokio::test]
    async fn mismatched_context_is_rejected() {
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
        .await
        .unwrap();
        assert_eq!(dk.key.key(), same.key());

        let stripped =
            retrieve_one(&src, RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag), None).await;
        assert_rejected(stripped, "stripped context");
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
    async fn policy_round_trips_and_a_stripped_or_swapped_policy_is_rejected() {
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
        .await
        .unwrap();
        assert_eq!(dk.key.key(), same.key());

        let stripped =
            retrieve_one(&src, RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag), None).await;
        assert_rejected(stripped, "stripped policy");

        let swapped = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag)
                .with_decryption_policy(policy("sub", "mallory")),
            None,
        )
        .await;
        assert_rejected(swapped, "swapped policy");
    }

    #[tokio::test]
    async fn policy_bearing_keys_ignore_context_on_both_sides() {
        // `Client::generate_keys` builds `GenerateKeySpec::new_with_policy`,
        // which sends no context, and ZeroKMS's v1 (policy) tag never reads
        // the retrieve-side context either. So with a policy present, any
        // context — matching, stripped, or different — retrieves the key.
        let src = FakeDataKeySource::new();
        let p = policy("sub", "alice");
        let ctx = vec![Context::Tag("tenant-1".into())];
        let dk = generate_one(
            &src,
            GenerateKeyPayload::new("d", Cow::Borrowed(&ctx)).with_decryption_policy(p.clone()),
            None,
        )
        .await;

        let with_same_context = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag)
                .with_context(Cow::Borrowed(&ctx))
                .with_decryption_policy(p.clone()),
            None,
        )
        .await
        .unwrap();
        assert_eq!(dk.key.key(), with_same_context.key());

        let without_context = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag).with_decryption_policy(p.clone()),
            None,
        )
        .await
        .unwrap();
        assert_eq!(dk.key.key(), without_context.key());

        let other_ctx = vec![Context::Tag("tenant-2".into())];
        let with_other_context = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag)
                .with_context(Cow::Borrowed(&other_ctx))
                .with_decryption_policy(p),
            None,
        )
        .await
        .unwrap();
        assert_eq!(dk.key.key(), with_other_context.key());
    }

    #[tokio::test]
    async fn a_batch_with_one_bad_tag_fails_as_a_whole() {
        let src = FakeDataKeySource::new();
        let dk = generate_one(&src, GenerateKeyPayload::new("d", Cow::Owned(vec![])), None).await;

        let result = src
            .retrieve_keys(
                vec![
                    RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag),
                    RetrieveKeyPayload::new(dk.key.iv, "d", b"wrong-tag"),
                ],
                None,
                None,
            )
            .await;
        assert!(
            matches!(
                result,
                Err(Error::RetrieveKey(RetrieveKeyError::FailedRetrieval(_)))
            ),
            "one bad tag must fail the batch"
        );
    }

    #[test]
    fn the_fake_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FakeDataKeySource>();
    }
}
