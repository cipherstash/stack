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
use zerokms_protocol::{IdentifiedBy, UnverifiedContext};

use crate::errors::Error;
use crate::key::{DataKey, DataKeyWithTag, IndexKey};
use crate::maybe_send::MaybeSend;
use crate::payload::{GenerateKeyPayload, RetrieveKeyPayload};

/// The slice of ZeroKMS data-key functionality required to encrypt and decrypt:
/// generating fresh data keys and re-deriving them for stored ciphertexts.
///
/// Both methods take an owned `Vec` of payloads (rather than `impl IntoIterator`)
/// so the trait stays simple to implement and the returned futures are easy to
/// box behind an async `vitaminc_aead::Decipher`.
///
/// The returned futures are bounded by [`MaybeSend`]: `Send` on native targets
/// so callers can drive them on a multi-threaded runtime, unbounded on wasm32
/// (see [`MaybeSend`] for why).
pub trait DataKeySource {
    /// Generate one fresh data key per payload, in payload order.
    fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> impl Future<Output = Result<Vec<DataKeyWithTag>, Error>> + MaybeSend;

    /// Re-derive one data key per payload, in payload order. Each payload's IV +
    /// tag (returned by a prior [`generate_keys`](DataKeySource::generate_keys)
    /// call and stored with the ciphertext) must reproduce the same key.
    fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> impl Future<Output = Result<Vec<DataKey>, Error>> + MaybeSend;
}

/// The slice of ZeroKMS functionality required to *index* encrypted data:
/// loading the deterministic per-keyset [`IndexKey`] used to generate index
/// terms (Searchable Encrypted Metadata) with PRFs and similar constructions.
///
/// Split from [`DataKeySource`] because the two capabilities are consumed
/// separately: record encryption needs data keys, term generation needs the
/// index key. Production implementations provide both.
///
/// As with [`DataKeySource`], the returned future is bounded by [`MaybeSend`].
pub trait IndexKeySource {
    /// Load the index key for a keyset — identified by id or name, or the
    /// client's default keyset when `keyset_id` is `None`. Returns the
    /// resolved keyset id alongside the key, so callers pinning `None` or a
    /// name learn which keyset they resolved to.
    ///
    /// The index key is deterministic per keyset: loading it twice yields the
    /// same key, so terms generated at write time match terms generated at
    /// query time.
    fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> impl Future<Output = Result<(Uuid, IndexKey), Error>> + MaybeSend;
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

impl<C> IndexKeySource for crate::StackKms<C>
where
    C: stack_auth::AuthStrategyBounds,
    for<'a> &'a C: stack_auth::AuthStrategy,
{
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), Error> {
        let (keyset, index_key) = self.load_keyset(keyset_id).await?;
        Ok((keyset.id, index_key))
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
    use std::sync::Mutex;
    use vitaminc::random::{Generatable, SafeRand};

    /// An in-memory stub [`DataKeySource`] for tests and examples that need
    /// `generate_keys` → `retrieve_keys` to round-trip without ZeroKMS
    /// credentials or network access.
    ///
    /// `generate_keys` hands out a random key, IV and tag per payload and
    /// remembers the key under `(iv, tag)`; `retrieve_keys` looks each payload
    /// up by the same pair and fails with
    /// [`RetrieveKeyError::FailedRetrieval`] when there is no such key. That is
    /// the whole contract.
    ///
    /// **This stub models none of ZeroKMS's authorization semantics.** The
    /// `descriptor`, `context`, `keyset_id` and `decryption_policy` on a
    /// payload are accepted and ignored (the policy is echoed back on the
    /// generated key, as the real service returns the resolved policy for
    /// storage). Nothing is derived, resolved, or verified — a wrong
    /// descriptor, a stripped context, an unresolved policy condition or a
    /// different caller all retrieve just fine here. Those decisions are
    /// ZeroKMS's, tested in `vitur-server-core`; do not assert them against
    /// this stub. Consumers testing *what they send* should mock the trait.
    ///
    /// As an [`IndexKeySource`] the index key is a fixed function of the
    /// resolved keyset id (and a name resolves to a fixed v5 UUID), so two
    /// independently built stubs agree — search terms generated by one cipher
    /// must match terms generated by another, and known-answer tests can pin
    /// term bytes. That is plain determinism, not ZeroKMS's derivation.
    #[derive(Debug, Default)]
    pub struct FakeDataKeySource {
        keys: Mutex<HashMap<(Iv, Vec<u8>), Key>>,
    }

    /// UUID namespace for name resolution: `Uuid::new_v5` mints deterministic,
    /// RFC 4122-valid UUIDs that strict validation downstream accepts.
    const KEYSET_NAME_NAMESPACE: Uuid = Uuid::from_u128(0x8ff8_1a03_4b2d_4f0b_9d6e_5a1c_3f7e_2b41);

    impl FakeDataKeySource {
        /// The name the fake reserves for the client's default keyset:
        /// resolving `IdentifiedBy::Name("default")` reaches the same keyset
        /// as passing `None` or the nil UUID. Real ZeroKMS resolves whatever
        /// name the default keyset was created under; the fake fixes it to
        /// this constant so name-based tests can address the default keyset.
        pub const DEFAULT_KEYSET_NAME: &'static str = "default";

        pub fn new() -> Self {
            Self::default()
        }

        /// Number of keys generated so far and available to retrieve.
        pub fn len(&self) -> usize {
            self.lock().len()
        }

        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(Iv, Vec<u8>), Key>> {
            lock(&self.keys)
        }
    }

    /// A poisoned lock only means another test thread panicked mid-insert;
    /// the map is still a valid map.
    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn random<T: Generatable>(rng: &mut SafeRand) -> Result<T, Error> {
        Ok(Generatable::random(rng).map_err(GenerateKeyError::GenerateIv)?)
    }

    impl IndexKeySource for FakeDataKeySource {
        async fn load_index_key(
            &self,
            keyset_id: Option<IdentifiedBy>,
        ) -> Result<(Uuid, IndexKey), Error> {
            let resolved = match keyset_id {
                None => Uuid::nil(),
                Some(IdentifiedBy::Uuid(id)) => id,
                Some(IdentifiedBy::Name(name))
                    if &*name == FakeDataKeySource::DEFAULT_KEYSET_NAME =>
                {
                    Uuid::nil()
                }
                Some(IdentifiedBy::Name(name)) => {
                    Uuid::new_v5(&KEYSET_NAME_NAMESPACE, name.as_bytes())
                }
            };
            let mut hasher = Sha256::new();
            hasher.update(b"stack-kms::FakeDataKeySource::index-key::v1");
            hasher.update(resolved.as_bytes());
            let key: Key = hasher.finalize().into();
            Ok((resolved, IndexKey::from(key)))
        }
    }

    impl DataKeySource for FakeDataKeySource {
        async fn generate_keys(
            &self,
            payloads: Vec<GenerateKeyPayload<'_>>,
            _keyset_id: Option<Uuid>,
            _unverified_context: Option<Cow<'_, UnverifiedContext>>,
        ) -> Result<Vec<DataKeyWithTag>, Error> {
            let mut rng = SafeRand::from_entropy().map_err(GenerateKeyError::GenerateIv)?;
            let mut keys = self.lock();
            payloads
                .into_iter()
                .map(|payload| {
                    let iv: Iv = random(&mut rng)?;
                    let key: Key = random(&mut rng)?;
                    let tag: [u8; 32] = random(&mut rng)?;
                    let _ = keys.insert((iv, tag.to_vec()), key);
                    Ok(DataKeyWithTag {
                        key: DataKey { iv, key },
                        tag: tag.to_vec(),
                        decryption_policy: payload.decryption_policy,
                    })
                })
                .collect()
        }

        async fn retrieve_keys(
            &self,
            payloads: Vec<RetrieveKeyPayload<'_>>,
            _keyset_id: Option<Uuid>,
            _unverified_context: Option<&UnverifiedContext>,
        ) -> Result<Vec<DataKey>, Error> {
            let keys = self.lock();
            payloads
                .iter()
                .map(|p| {
                    let iv: Iv = *p.iv.as_ref();
                    keys.get(&(iv, p.tag.to_vec()))
                        .map(|key| DataKey { iv, key: *key })
                        .ok_or_else(|| {
                            Error::RetrieveKey(RetrieveKeyError::FailedRetrieval(
                                "no key was generated with this iv and tag".to_string(),
                            ))
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
    use zerokms_protocol::{DecryptionPolicy, PolicyCondition};

    async fn generate_one(src: &FakeDataKeySource, descriptor: &str) -> DataKeyWithTag {
        src.generate_keys(
            vec![GenerateKeyPayload::new(descriptor, Cow::Owned(vec![]))],
            None,
            None,
        )
        .await
        .unwrap()
        .remove(0)
    }

    async fn retrieve_one(
        src: &FakeDataKeySource,
        payload: RetrieveKeyPayload<'_>,
    ) -> Result<DataKey, Error> {
        src.retrieve_keys(vec![payload], None, None)
            .await
            .map(|mut keys| keys.remove(0))
    }

    fn assert_not_found(result: Result<DataKey, Error>, what: &str) {
        match result {
            Err(Error::RetrieveKey(RetrieveKeyError::FailedRetrieval(_))) => {}
            Err(other) => panic!("{what}: expected FailedRetrieval, got {other:?}"),
            Ok(_) => panic!("{what}: expected rejection, got a key"),
        }
    }

    #[tokio::test]
    async fn fake_index_key_is_deterministic_per_keyset() {
        let src = FakeDataKeySource::new();
        let keyset_a = Uuid::from_u128(1);
        let keyset_b = Uuid::from_u128(2);

        let (id_a, key_a) = src.load_index_key(Some(keyset_a.into())).await.unwrap();
        let (_, key_a_again) = src.load_index_key(Some(keyset_a.into())).await.unwrap();
        let (_, key_b) = src.load_index_key(Some(keyset_b.into())).await.unwrap();
        let (id_none, _) = src.load_index_key(None).await.unwrap();

        assert_eq!(id_a, keyset_a);
        assert_eq!(key_a.key(), key_a_again.key());
        assert_ne!(key_a.key(), key_b.key());
        assert_eq!(id_none, Uuid::nil());
    }

    #[tokio::test]
    async fn independently_built_stubs_agree_on_index_keys() {
        // Search terms generated through one cipher must match terms generated
        // through another, so the index key cannot be per-instance state.
        let (_, a) = FakeDataKeySource::new().load_index_key(None).await.unwrap();
        let (_, b) = FakeDataKeySource::new().load_index_key(None).await.unwrap();
        assert_eq!(a.key(), b.key());
    }

    #[tokio::test]
    async fn fake_index_key_resolves_names_deterministically() {
        let src = FakeDataKeySource::new();
        // `InvalidNameError` has no `Debug`, so go via `ok()`.
        let by_name = |n: &str| zerokms_protocol::IdentifiedBy::Name(n.try_into().ok().unwrap());

        let (id_a, key_a) = src.load_index_key(Some(by_name("users"))).await.unwrap();
        let (id_a_again, key_a_again) = src.load_index_key(Some(by_name("users"))).await.unwrap();
        let (id_b, key_b) = src.load_index_key(Some(by_name("orders"))).await.unwrap();
        // Pinning the resolved id must reach the same keyset as the name.
        let (_, key_a_by_id) = src.load_index_key(Some(id_a.into())).await.unwrap();

        assert_eq!(id_a, id_a_again);
        assert_eq!(key_a.key(), key_a_again.key());
        assert_ne!(id_a, id_b);
        assert_ne!(key_a.key(), key_b.key());
        assert_eq!(key_a.key(), key_a_by_id.key());
    }

    #[tokio::test]
    async fn fake_name_resolution_mints_rfc4122_uuids() {
        let src = FakeDataKeySource::new();
        let by_name = |n: &str| zerokms_protocol::IdentifiedBy::Name(n.try_into().ok().unwrap());

        let (id, _) = src.load_index_key(Some(by_name("users"))).await.unwrap();

        // Strict UUID validation downstream must accept the minted ids.
        assert_eq!(id.get_version_num(), 5);
        assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
    }

    #[tokio::test]
    async fn the_default_keyset_name_is_equivalent_to_none() {
        // Real ZeroKMS resolves the default keyset's name to the same keyset
        // as `None`, so keys and index terms written under `None` must be
        // reachable by the fake's reserved default-keyset name too.
        let src = FakeDataKeySource::new();
        let by_name = |n: &str| zerokms_protocol::IdentifiedBy::Name(n.try_into().ok().unwrap());

        let (id_none, key_none) = src.load_index_key(None).await.unwrap();
        let (id_name, key_name) = src
            .load_index_key(Some(by_name(FakeDataKeySource::DEFAULT_KEYSET_NAME)))
            .await
            .unwrap();

        assert_eq!(id_none, id_name);
        assert_eq!(key_none.key(), key_name.key());
    }

    #[tokio::test]
    async fn none_resolves_to_the_same_index_key_as_the_reported_default_keyset() {
        // The pin-the-resolved-id pattern advertised by
        // `IndexKeySource::load_index_key`: loading under `None` and then under
        // the id it reported must yield the same index key.
        let src = FakeDataKeySource::new();
        let (resolved, key_none) = src.load_index_key(None).await.unwrap();
        let (_, key_resolved) = src.load_index_key(Some(resolved.into())).await.unwrap();
        assert_eq!(key_none.key(), key_resolved.key());
    }

    #[tokio::test]
    async fn generate_then_retrieve_reproduces_the_key() {
        let src = FakeDataKeySource::new();
        let dk = generate_one(&src, "users/email").await;

        let retrieved = retrieve_one(
            &src,
            RetrieveKeyPayload::new(dk.key.iv, "users/email", &dk.tag),
        )
        .await
        .unwrap();

        assert_eq!(dk.key.key(), retrieved.key());
        assert_eq!(dk.key.iv, retrieved.iv);
        assert_eq!(src.len(), 1);
    }

    #[tokio::test]
    async fn every_generated_key_is_distinct() {
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
        assert_eq!(src.len(), 2);
    }

    #[tokio::test]
    async fn an_unknown_tag_or_iv_is_not_found() {
        let src = FakeDataKeySource::new();
        let dk = generate_one(&src, "d").await;

        assert_not_found(
            retrieve_one(&src, RetrieveKeyPayload::new(dk.key.iv, "d", b"wrong-tag")).await,
            "wrong tag",
        );

        let mut other_iv = dk.key.iv;
        other_iv[15] ^= 0xff;
        assert_not_found(
            retrieve_one(&src, RetrieveKeyPayload::new(other_iv, "d", &dk.tag)).await,
            "wrong iv",
        );

        assert_not_found(
            retrieve_one(
                &FakeDataKeySource::new(),
                RetrieveKeyPayload::new(dk.key.iv, "d", &dk.tag),
            )
            .await,
            "a different stub instance",
        );
    }

    #[tokio::test]
    async fn a_batch_with_one_unknown_key_fails_as_a_whole() {
        let src = FakeDataKeySource::new();
        let dk = generate_one(&src, "d").await;

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
            "one unknown key must fail the batch"
        );
    }

    #[tokio::test]
    async fn the_policy_is_echoed_back_and_nothing_else_is_interpreted() {
        // Pins the documented non-contract: descriptor, context, keyset and
        // policy are not consulted on retrieval. If this test starts failing
        // because someone made the stub "smarter", read the type's docs first.
        let src = FakeDataKeySource::new();
        let policy = DecryptionPolicy {
            conditions: vec![PolicyCondition {
                claim: "sub".into(),
                value: None,
            }],
        };
        let dk = src
            .generate_keys(
                vec![GenerateKeyPayload::new("d", Cow::Owned(vec![]))
                    .with_decryption_policy(policy.clone())],
                Some(Uuid::new_v4()),
                None,
            )
            .await
            .unwrap()
            .remove(0);
        assert_eq!(dk.decryption_policy, Some(policy));

        let retrieved = src
            .retrieve_keys(
                vec![RetrieveKeyPayload::new(
                    dk.key.iv,
                    "something-else",
                    &dk.tag,
                )],
                Some(Uuid::new_v4()),
                None,
            )
            .await
            .unwrap()
            .remove(0);
        assert_eq!(dk.key.key(), retrieved.key());
    }

    #[test]
    fn the_stub_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FakeDataKeySource>();
    }
}
