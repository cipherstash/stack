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
    use crate::errors::{GenerateKeyError, RetrieveKeyError};
    use crate::key::DataKey;
    use recipher::key::{Iv, Key};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use zerokms_protocol::{DecryptionPolicy, PolicyCondition, ViturRequestError};

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
    /// counter).
    ///
    /// # Caller identity and decryption policies
    ///
    /// ZeroKMS sees every request through the caller's bearer token: at
    /// generation it fills `PolicyCondition { value: None }` from the caller's
    /// JWT claims (`sub`, `workspace`, …) and returns the *resolved* policy for
    /// storage beside the ciphertext; at retrieval it rejects a policy that
    /// still carries an unresolved condition, and then checks that the caller's
    /// claims satisfy at least one condition. A [`DataKeySource`] sits above
    /// the token, so the fake needs to be told who is calling:
    /// [`as_caller`](Self::as_caller) sets the claims every request to this
    /// instance is treated as authenticated with. Key material does not
    /// depend on the instance, so two fakes with different callers model two
    /// principals sharing one KMS:
    ///
    /// ```
    /// # use stack_kms::FakeDataKeySource;
    /// let alice = FakeDataKeySource::new().as_caller([("sub", "alice")]);
    /// let mallory = FakeDataKeySource::new().as_caller([("sub", "mallory")]);
    /// // keys `alice` generates under a `sub` policy retrieve for `alice`,
    /// // and are rejected for `mallory`.
    /// ```
    ///
    /// A fake with no caller claims can still generate and retrieve keys
    /// without a policy, or with a policy whose conditions all carry explicit
    /// values — though retrieval of the latter is denied, since the (absent)
    /// caller satisfies no condition, exactly as ZeroKMS would deny a token
    /// without the claim.
    ///
    /// The derivations are plain SHA-256: deterministic and binding, but **not**
    /// a stand-in for ZeroKMS's real key derivation or HMAC tag. Use it for
    /// encrypt/decrypt round-trip and wrong-context/policy tests, not for
    /// cryptographic assertions.
    #[derive(Debug, Default)]
    pub struct FakeDataKeySource {
        counter: AtomicU64,
        /// The claims of the (single) caller this fake serves — its stand-in
        /// for the bearer token `StackKms` would send with every request.
        caller_claims: HashMap<String, String>,
    }

    /// The fake's stand-in for ZeroKMS's `UnsupportedClaim`: a policy asks for
    /// a claim the caller's token doesn't carry.
    #[derive(Debug, thiserror::Error)]
    #[error("policy condition on claim `{0}` cannot be resolved: the caller has no such claim")]
    struct UnresolvableClaim(String);

    impl FakeDataKeySource {
        pub fn new() -> Self {
            Self::default()
        }

        /// Treat every request to this fake as authenticated with `claims`
        /// (e.g. `[("sub", "alice"), ("workspace", "ws-1")]`). Replaces any
        /// claims set earlier.
        pub fn as_caller<K, V>(mut self, claims: impl IntoIterator<Item = (K, V)>) -> Self
        where
            K: Into<String>,
            V: Into<String>,
        {
            self.caller_claims = claims
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect();
            self
        }

        /// Fill in `value: None` conditions from the caller's claims, as ZeroKMS
        /// does at generation time.
        fn resolve_policy(&self, policy: DecryptionPolicy) -> Result<DecryptionPolicy, Error> {
            let conditions = policy
                .conditions
                .into_iter()
                .map(|condition| {
                    let value = match condition.value {
                        Some(value) => value,
                        None => self
                            .caller_claims
                            .get(&condition.claim)
                            .cloned()
                            .ok_or_else(|| {
                                Error::GenerateKey(GenerateKeyError::RequestFailed(
                                    ViturRequestError::other(
                                        "unresolvable decryption policy condition",
                                        UnresolvableClaim(condition.claim.clone()),
                                    ),
                                ))
                            })?,
                    };
                    Ok(PolicyCondition {
                        claim: condition.claim,
                        value: Some(value),
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?;
            Ok(DecryptionPolicy { conditions })
        }

        /// The retrieval-side policy checks ZeroKMS performs *before* and
        /// *after* the tag proof: the stored policy must be fully resolved,
        /// and the caller must satisfy at least one condition (flat OR).
        fn check_policy_is_resolved(policy: &DecryptionPolicy) -> Result<(), Error> {
            if policy.conditions.iter().any(|c| c.value.is_none()) {
                return Err(retrieval_denied(
                    "unresolved policy condition: only the resolved policy returned at \
                     generation is accepted at retrieval",
                ));
            }
            Ok(())
        }

        fn check_caller_satisfies(&self, policy: &DecryptionPolicy) -> Result<(), Error> {
            let satisfied = policy
                .conditions
                .iter()
                .any(|c| self.caller_claims.get(&c.claim) == c.value.as_ref());
            if satisfied {
                Ok(())
            } else {
                Err(retrieval_denied(
                    "policy not satisfied: none of the conditions match the caller's claims",
                ))
            }
        }
    }

    fn retrieval_denied(reason: &str) -> Error {
        Error::RetrieveKey(RetrieveKeyError::FailedRetrieval(reason.to_string()))
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
            payloads
                .into_iter()
                .map(|payload| {
                    // Resolve first: the tag binds the *resolved* policy, as
                    // `create_v1_tag` only ever sees a `ResolvedDecryptionPolicy`.
                    let decryption_policy = payload
                        .decryption_policy
                        .map(|policy| self.resolve_policy(policy))
                        .transpose()?;
                    let n = self.counter.fetch_add(1, Ordering::Relaxed);
                    let mut iv: Iv = [0u8; 16];
                    iv[..8].copy_from_slice(&n.to_le_bytes());
                    let key = derive_key(keyset_id, &iv, payload.descriptor);
                    let tag = derive_tag(TagInputs {
                        keyset_id,
                        iv: &iv,
                        descriptor: payload.descriptor,
                        context: &payload.context,
                        decryption_policy: decryption_policy.as_ref(),
                    });
                    Ok(DataKeyWithTag {
                        key: DataKey { iv, key },
                        tag,
                        decryption_policy,
                    })
                })
                .collect()
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
                    if let Some(policy) = &p.decryption_policy {
                        Self::check_policy_is_resolved(policy)?;
                    }
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
                        return Err(retrieval_denied(
                            "tag mismatch: the iv, descriptor, keyset, context or policy \
                             differs from what the key was generated under",
                        ));
                    }
                    // Tag proven, so the policy is the one written at generation;
                    // now the caller must satisfy it.
                    if let Some(policy) = &p.decryption_policy {
                        self.check_caller_satisfies(policy)?;
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

    /// A policy that ZeroKMS resolves from the caller's token at generation.
    fn unresolved_policy(claim: &str) -> DecryptionPolicy {
        DecryptionPolicy {
            conditions: vec![PolicyCondition {
                claim: claim.to_string(),
                value: None,
            }],
        }
    }

    fn alice() -> FakeDataKeySource {
        FakeDataKeySource::new().as_caller([("sub", "alice")])
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
        let src = alice();
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
        let src = alice();
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
        let src = alice();
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

    mod caller_identity {
        use super::*;
        use crate::errors::GenerateKeyError;

        fn retrieve_payload<'a>(dk: &'a DataKeyWithTag) -> RetrieveKeyPayload<'a> {
            RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag)
                .with_decryption_policy(dk.decryption_policy.clone().unwrap())
        }

        #[tokio::test]
        async fn an_unresolved_condition_is_resolved_from_the_callers_claims() {
            let src = alice();
            let dk = generate_one(
                &src,
                GenerateKeyPayload::new("d", Cow::Owned(vec![]))
                    .with_decryption_policy(unresolved_policy("sub")),
                None,
            )
            .await;

            // ZeroKMS returns the resolved policy for storage beside the ciphertext.
            assert_eq!(dk.decryption_policy, Some(policy("sub", "alice")));

            let retrieved = retrieve_one(&src, retrieve_payload(&dk), None)
                .await
                .unwrap();
            assert_eq!(dk.key.key(), retrieved.key());
        }

        #[tokio::test]
        async fn an_unresolved_condition_the_caller_cannot_satisfy_fails_generation() {
            let src = FakeDataKeySource::new().as_caller([("workspace", "ws-1")]);
            let result = src
                .generate_keys(
                    vec![GenerateKeyPayload::new("d", Cow::Owned(vec![]))
                        .with_decryption_policy(unresolved_policy("sub"))],
                    None,
                    None,
                )
                .await;

            assert!(
                matches!(
                    result,
                    Err(Error::GenerateKey(GenerateKeyError::RequestFailed(_)))
                ),
                "a policy on a claim the caller lacks must fail generation, got: {result:?}"
            );
        }

        #[tokio::test]
        async fn an_unresolved_policy_is_rejected_at_retrieval() {
            // The client must store and send back the resolved policy from
            // generation; sending the unresolved form (which the tag would
            // *not* bind either way) is rejected up-front as ZeroKMS does.
            let src = alice();
            let dk = generate_one(
                &src,
                GenerateKeyPayload::new("d", Cow::Owned(vec![]))
                    .with_decryption_policy(unresolved_policy("sub")),
                None,
            )
            .await;

            let result = retrieve_one(
                &src,
                RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag)
                    .with_decryption_policy(unresolved_policy("sub")),
                None,
            )
            .await;
            assert_rejected(result, "unresolved policy at retrieval");
        }

        #[tokio::test]
        async fn a_different_caller_is_denied_the_key() {
            let dk = generate_one(
                &alice(),
                GenerateKeyPayload::new("d", Cow::Owned(vec![]))
                    .with_decryption_policy(unresolved_policy("sub")),
                None,
            )
            .await;

            let mallory = FakeDataKeySource::new().as_caller([("sub", "mallory")]);
            assert_rejected(
                retrieve_one(&mallory, retrieve_payload(&dk), None).await,
                "mallory retrieving alice's key",
            );

            let anonymous = FakeDataKeySource::new();
            assert_rejected(
                retrieve_one(&anonymous, retrieve_payload(&dk), None).await,
                "a caller with no claims retrieving alice's key",
            );
        }

        #[tokio::test]
        async fn any_one_condition_satisfies_a_policy() {
            // Flat OR, as `ResolvedDecryptionPolicy::verify`.
            let p = DecryptionPolicy {
                conditions: vec![
                    PolicyCondition {
                        claim: "sub".into(),
                        value: Some("alice".into()),
                    },
                    PolicyCondition {
                        claim: "sub".into(),
                        value: Some("bob".into()),
                    },
                ],
            };
            let dk = generate_one(
                &alice(),
                GenerateKeyPayload::new("d", Cow::Owned(vec![])).with_decryption_policy(p),
                None,
            )
            .await;

            let bob = FakeDataKeySource::new().as_caller([("sub", "bob")]);
            let retrieved = retrieve_one(&bob, retrieve_payload(&dk), None)
                .await
                .unwrap();
            assert_eq!(dk.key.key(), retrieved.key());
        }

        #[tokio::test]
        async fn keys_without_a_policy_need_no_caller() {
            let src = FakeDataKeySource::new();
            let dk =
                generate_one(&src, GenerateKeyPayload::new("d", Cow::Owned(vec![])), None).await;
            let retrieved = retrieve_one(
                &FakeDataKeySource::new(),
                RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag),
                None,
            )
            .await
            .unwrap();
            assert_eq!(dk.key.key(), retrieved.key());
        }
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
