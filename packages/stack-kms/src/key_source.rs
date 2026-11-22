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

use stack_auth::{CredentialPerCall, OwnIdentity, SecretToken};
use uuid::Uuid;
use zerokms_protocol::{IdentifiedBy, UnverifiedContext};

use crate::errors::Error;
use crate::key::{DataKey, DataKeyWithTag, IndexKey};
use crate::maybe_send::MaybeSend;
use crate::payload::{GenerateKeyPayload, RetrieveKeyPayload};

/// Which of the two kinds a key source is.
///
/// A key source makes every request as itself, or as the caller whose
/// credential comes with the call. It is never both: a key source that had
/// both would make a call that forgot its credential as itself, and nobody
/// would know. This trait is what stops a type from being both. A type
/// implements it once, so it has one [`Kind`](Self::Kind):
///
/// - [`OwnIdentity`], for a key source with an identity of its own.
///   [`DataKeySource`] and [`IndexKeySource`] require this kind.
/// - [`CredentialPerCall`], for a key source that takes a credential with
///   each call. [`CredentialKeySource`] requires this kind.
///
/// Every key source states its kind, in one impl beside the traits of that
/// kind. [`StackKms`](crate::StackKms) does not choose: its kind is the kind
/// of its auth strategy ([`stack_auth::StrategyKind`]).
///
/// Code built on a key source, such as Stack Encrypt, reads the kind from
/// which of the traits the key source has. It adds no rule of its own.
///
// The examples wrap the test doubles, so they are in the docs only with
// `test-support`.
#[cfg_attr(
    feature = "test-support",
    doc = r#"# Example

A key source of your own with an identity of its own. This one counts the
keyset loads of the key source it wraps:

```
use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};

use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, Error, FakeDataKeySource, GenerateKeyPayload,
    IdentifiedBy, IndexKey, IndexKeySource, KeySourceKind, OwnIdentity, RetrieveKeyPayload,
    UnverifiedContext,
};
use uuid::Uuid;

#[derive(Default)]
struct Counted {
    inner: FakeDataKeySource,
    loads: AtomicUsize,
}

impl KeySourceKind for Counted {
    type Kind = OwnIdentity;
}

impl DataKeySource for Counted {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, Error> {
        self.inner.generate_keys(payloads, keyset_id, unverified_context).await
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, Error> {
        self.inner.retrieve_keys(payloads, keyset_id, unverified_context).await
    }
}

impl IndexKeySource for Counted {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), Error> {
        self.loads.fetch_add(1, Ordering::Relaxed);
        self.inner.load_index_key(keyset_id).await
    }
}

# async fn example() -> Result<(), Error> {
let source = Counted::default();
let (keyset_id, _index_key) = source.load_index_key(None).await?;
# let _ = keyset_id;
assert_eq!(source.loads.load(Ordering::Relaxed), 1);
# Ok(())
# }
# tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(example()).unwrap();
```

A key source of both kinds does not compile. `Both` says it has an identity
of its own, so it cannot also take a credential with each call:

```compile_fail,E0271
use std::borrow::Cow;

use stack_kms::{
    CredentialKeySource, DataKey, DataKeyWithTag, Error, FakeCredentialKeySource,
    GenerateKeyPayload, IdentifiedBy, IndexKey, KeySourceKind, OwnIdentity, RetrieveKeyPayload,
    SecretToken, UnverifiedContext,
};
use uuid::Uuid;

#[derive(Default)]
struct Both {
    inner: FakeCredentialKeySource,
}

impl KeySourceKind for Both {
    type Kind = OwnIdentity;
}

impl CredentialKeySource for Both {
    async fn generate_keys_with_credential(
        &self,
        credential: &SecretToken,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, Error> {
        self.inner
            .generate_keys_with_credential(credential, payloads, keyset_id, unverified_context)
            .await
    }

    async fn retrieve_keys_with_credential(
        &self,
        credential: &SecretToken,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, Error> {
        self.inner
            .retrieve_keys_with_credential(credential, payloads, keyset_id, unverified_context)
            .await
    }

    async fn load_index_key_with_credential(
        &self,
        credential: &SecretToken,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), Error> {
        self.inner.load_index_key_with_credential(credential, keyset_id).await
    }
}
```"#
)]
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not say which kind of key source it is",
    label = "this key source has no `KeySourceKind`",
    note = "a key source with an identity of its own (`DataKeySource`, `IndexKeySource`) implements `KeySourceKind` with `type Kind = OwnIdentity`",
    note = "a key source that takes a credential with each call (`CredentialKeySource`) implements `KeySourceKind` with `type Kind = CredentialPerCall`"
)]
pub trait KeySourceKind {
    /// [`OwnIdentity`] or [`CredentialPerCall`].
    type Kind;
}

/// A ZeroKMS client is the kind of key source that its auth strategy is a
/// kind of strategy. stack-auth decides that, and a strategy is one kind.
impl<C, Conn> KeySourceKind for crate::StackKms<C, Conn>
where
    C: stack_auth::AuthStrategyBounds,
    &'static C: stack_auth::StrategyKind,
{
    type Kind = <&'static C as stack_auth::StrategyKind>::Kind;
}

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
///
/// A source that implements this trait has an identity of its own, and
/// makes every request as that identity: it states the kind
/// [`OwnIdentity`] ([`KeySourceKind`]). A source that takes a credential
/// with each call implements [`CredentialKeySource`] instead, and cannot
/// implement this trait.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a key source with an identity of its own",
    label = "this makes a key request with no credential",
    note = "if `{Self}` takes a credential with each call (`CredentialKeySource`), pass one: in Stack Encrypt, call `.with_credential(..)` before `.await`"
)]
pub trait DataKeySource: KeySourceKind<Kind = OwnIdentity> {
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
/// As with [`DataKeySource`], the returned future is bounded by [`MaybeSend`],
/// and a source that implements this trait has an identity of its own.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a key source with an identity of its own",
    label = "this loads a keyset with no credential",
    note = "if `{Self}` takes a credential with each call (`CredentialKeySource`), pass one: in Stack Encrypt, call `.with_credential(..)` before `.await`"
)]
pub trait IndexKeySource: KeySourceKind<Kind = OwnIdentity> {
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

/// A key source that makes each request with a credential that comes with
/// the call, so ZeroKMS serves and logs the request as that caller.
///
/// The credential is whatever the source's auth strategy exchanges for an
/// access token. For [`StackKms`](crate::StackKms) over an
/// [`OidcFederationStrategy`](stack_auth::OidcFederationStrategy) built
/// with `credential_per_call`, it is the JWT of an end user. One long-lived
/// source then serves every caller, and each request says which caller it
/// is for.
///
/// Each method is the one of [`DataKeySource`] or [`IndexKeySource`] with
/// `credential` added. An implementation must make the request with that
/// credential, or fail. It must never fall back to another identity.
///
/// A key source is one kind or the other, never both. [`KeySourceKind`]
/// holds that: a type states one kind, and each trait requires its own.
///
/// - A source with an identity of its own (an access key, a saved login)
///   implements [`DataKeySource`] and [`IndexKeySource`], and not this
///   trait. Code that passes a credential does not compile against it, so
///   a credential is never ignored.
/// - A source that takes a credential with each call implements this
///   trait, and not the other two. Code that makes a request with no
///   credential does not compile against it, so a credential is never
///   forgotten.
///
/// [`StackKms`](crate::StackKms) is the first kind over a
/// [`stack_auth::AuthStrategy`], and the second over a
/// [`stack_auth::CredentialAuthStrategy`]. A strategy is one of the two and
/// never both ([`stack_auth::StrategyKind`]), so a `StackKms` is one kind.
///
/// As with [`DataKeySource`], the returned futures are bounded by
/// [`MaybeSend`].
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not take a credential with each call",
    label = "this passes a credential to a key source that has an identity of its own",
    note = "a key source with an identity of its own makes every request as that identity. To make each request as its caller, build the key source over an auth strategy that takes a credential with each call, such as `OidcFederationStrategy::credential_per_call`"
)]
pub trait CredentialKeySource: KeySourceKind<Kind = CredentialPerCall> {
    /// [`DataKeySource::generate_keys`], made with `credential`.
    fn generate_keys_with_credential(
        &self,
        credential: &SecretToken,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> impl Future<Output = Result<Vec<DataKeyWithTag>, Error>> + MaybeSend;

    /// [`DataKeySource::retrieve_keys`], made with `credential`.
    fn retrieve_keys_with_credential(
        &self,
        credential: &SecretToken,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> impl Future<Output = Result<Vec<DataKey>, Error>> + MaybeSend;

    /// [`IndexKeySource::load_index_key`], made with `credential`.
    fn load_index_key_with_credential(
        &self,
        credential: &SecretToken,
        keyset_id: Option<IdentifiedBy>,
    ) -> impl Future<Output = Result<(Uuid, IndexKey), Error>> + MaybeSend;
}

impl<C, Conn> DataKeySource for crate::StackKms<C, Conn>
where
    C: stack_auth::AuthStrategyBounds,
    for<'a> &'a C: stack_auth::AuthStrategy,
    Conn: crate::ZeroKMSConnection + Send + Sync,
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

impl<C, Conn> IndexKeySource for crate::StackKms<C, Conn>
where
    C: stack_auth::AuthStrategyBounds,
    for<'a> &'a C: stack_auth::AuthStrategy,
    Conn: crate::ZeroKMSConnection + Send + Sync,
{
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), Error> {
        let (keyset, index_key) = self.load_keyset(keyset_id).await?;
        Ok((keyset.id, index_key))
    }
}

impl<C, Conn> CredentialKeySource for crate::StackKms<C, Conn>
where
    C: stack_auth::AuthStrategyBounds,
    for<'a> &'a C: stack_auth::CredentialAuthStrategy,
    Conn: crate::ZeroKMSConnection + Send + Sync,
{
    async fn generate_keys_with_credential(
        &self,
        credential: &SecretToken,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, Error> {
        // The inherent method of the same name, which takes `impl IntoIterator`.
        crate::StackKms::generate_keys_with_credential(
            self,
            credential,
            payloads,
            keyset_id,
            unverified_context,
        )
        .await
    }

    async fn retrieve_keys_with_credential(
        &self,
        credential: &SecretToken,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, Error> {
        crate::StackKms::retrieve_keys_with_credential(
            self,
            credential,
            payloads,
            keyset_id,
            unverified_context,
        )
        .await
    }

    async fn load_index_key_with_credential(
        &self,
        credential: &SecretToken,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), Error> {
        let (keyset, index_key) = self
            .load_keyset_with_credential(credential, keyset_id)
            .await?;
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
    ///
    /// This stub has an identity of its own: no request takes a credential.
    /// [`FakeCredentialKeySource`] is the stub that takes one with each
    /// call.
    #[derive(Default)]
    pub struct FakeDataKeySource {
        keys: Mutex<HashMap<(Iv, Vec<u8>), Key>>,
    }

    /// The number of keys held. The keys are key material, so they are not
    /// printed.
    impl std::fmt::Debug for FakeDataKeySource {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FakeDataKeySource")
                .field("keys", &self.len())
                .finish()
        }
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

    impl FakeDataKeySource {
        /// The index key of `keyset_id`, whoever asks.
        fn index_key(&self, keyset_id: Option<IdentifiedBy>) -> (Uuid, IndexKey) {
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
            (resolved, IndexKey::from(key))
        }

        /// One fresh key for each payload, remembered, whoever asks.
        fn generate(
            &self,
            payloads: Vec<GenerateKeyPayload<'_>>,
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

        /// The remembered key of each payload, whoever asks.
        fn retrieve(&self, payloads: Vec<RetrieveKeyPayload<'_>>) -> Result<Vec<DataKey>, Error> {
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

    impl KeySourceKind for FakeDataKeySource {
        type Kind = OwnIdentity;
    }

    impl IndexKeySource for FakeDataKeySource {
        async fn load_index_key(
            &self,
            keyset_id: Option<IdentifiedBy>,
        ) -> Result<(Uuid, IndexKey), Error> {
            Ok(self.index_key(keyset_id))
        }
    }

    impl DataKeySource for FakeDataKeySource {
        async fn generate_keys(
            &self,
            payloads: Vec<GenerateKeyPayload<'_>>,
            _keyset_id: Option<Uuid>,
            _unverified_context: Option<Cow<'_, UnverifiedContext>>,
        ) -> Result<Vec<DataKeyWithTag>, Error> {
            self.generate(payloads)
        }

        async fn retrieve_keys(
            &self,
            payloads: Vec<RetrieveKeyPayload<'_>>,
            _keyset_id: Option<Uuid>,
            _unverified_context: Option<&UnverifiedContext>,
        ) -> Result<Vec<DataKey>, Error> {
            self.retrieve(payloads)
        }
    }

    /// An in-memory stub [`CredentialKeySource`], for tests and examples of
    /// code that makes each key request as its caller.
    ///
    /// It is [`FakeDataKeySource`] with a credential on every request: it
    /// generates, retrieves and loads as that stub does, takes any
    /// credential, and records it.
    /// [`credentials_seen`](Self::credentials_seen) lists the credential of
    /// each request, in order. A test of a request handler reads the list
    /// to check that the handler's key requests carried its own caller's
    /// credential.
    ///
    /// Like every [`CredentialKeySource`], it has no request without a
    /// credential. A test of a request handler built on it does not
    /// compile if the handler makes a key request without one.
    ///
    /// The stub exchanges nothing and refuses no credential, so it says
    /// nothing about whether ZeroKMS would accept one. Its index keys are
    /// those of [`FakeDataKeySource`], so the terms of one stub match the
    /// terms of the other.
    ///
    /// # Example
    ///
    /// ```
    /// use stack_kms::{CredentialKeySource, FakeCredentialKeySource, SecretToken};
    ///
    /// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
    /// let source = FakeCredentialKeySource::new();
    /// let alice = SecretToken::new("alice.jwt");
    ///
    /// let (keyset_id, _index_key) = source.load_index_key_with_credential(&alice, None).await?;
    /// assert!(keyset_id.is_nil(), "the stub's default keyset");
    /// assert_eq!(source.credentials_seen(), ["alice.jwt"]);
    /// # Ok::<(), stack_kms::Error>(())
    /// # }).unwrap();
    /// ```
    ///
    /// A request with no credential does not compile:
    ///
    /// ```compile_fail,E0599
    /// use stack_kms::{FakeCredentialKeySource, IndexKeySource};
    ///
    /// let source = FakeCredentialKeySource::new();
    /// let _ = source.load_index_key(None);
    /// ```
    #[derive(Default)]
    pub struct FakeCredentialKeySource {
        keys: FakeDataKeySource,
        /// The credential of each request, in order.
        credentials: Mutex<Vec<SecretToken>>,
    }

    /// The number of keys held, and of credentials seen. The keys are key
    /// material and the credentials are secrets, so neither is printed.
    impl std::fmt::Debug for FakeCredentialKeySource {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FakeCredentialKeySource")
                .field("keys", &self.len())
                .field("credentials_seen", &lock(&self.credentials).len())
                .finish()
        }
    }

    impl FakeCredentialKeySource {
        pub fn new() -> Self {
            Self::default()
        }

        /// Number of keys generated so far and available to retrieve.
        pub fn len(&self) -> usize {
            self.keys.len()
        }

        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }

        /// The credential of each request, in the order the requests were
        /// made.
        ///
        /// The credentials are returned as plain strings so that a test can
        /// compare them. Use test values, never a real credential.
        pub fn credentials_seen(&self) -> Vec<String> {
            lock(&self.credentials)
                .iter()
                .map(|credential| credential.as_str().to_string())
                .collect()
        }

        fn saw(&self, credential: &SecretToken) {
            lock(&self.credentials).push(credential.clone());
        }
    }

    impl KeySourceKind for FakeCredentialKeySource {
        type Kind = CredentialPerCall;
    }

    impl CredentialKeySource for FakeCredentialKeySource {
        async fn generate_keys_with_credential(
            &self,
            credential: &SecretToken,
            payloads: Vec<GenerateKeyPayload<'_>>,
            _keyset_id: Option<Uuid>,
            _unverified_context: Option<Cow<'_, UnverifiedContext>>,
        ) -> Result<Vec<DataKeyWithTag>, Error> {
            self.saw(credential);
            self.keys.generate(payloads)
        }

        async fn retrieve_keys_with_credential(
            &self,
            credential: &SecretToken,
            payloads: Vec<RetrieveKeyPayload<'_>>,
            _keyset_id: Option<Uuid>,
            _unverified_context: Option<&UnverifiedContext>,
        ) -> Result<Vec<DataKey>, Error> {
            self.saw(credential);
            self.keys.retrieve(payloads)
        }

        async fn load_index_key_with_credential(
            &self,
            credential: &SecretToken,
            keyset_id: Option<IdentifiedBy>,
        ) -> Result<(Uuid, IndexKey), Error> {
            self.saw(credential);
            Ok(self.keys.index_key(keyset_id))
        }
    }
}

#[cfg(feature = "test-support")]
pub use fake::{FakeCredentialKeySource, FakeDataKeySource};

/// The deterministic test source: every key derives from a seed and the
/// descriptor, so a record sealed in one process opens in another built from
/// the same seed. `stack-encrypt`'s record fixture
/// (`tests/fixtures/record_lowering.json`) is sealed under it, and the Go
/// guest's `deterministic-kms` test build runs over it, so both read one
/// definition and cannot drift apart.
#[cfg(feature = "test-support")]
mod deterministic {
    use std::borrow::Cow;
    use std::sync::atomic::{AtomicU64, Ordering};

    use sha2::{Digest, Sha256};
    use uuid::Uuid;
    use zerokms_protocol::{
        IdentifiedBy, UnverifiedContext, ViturRequestError, ViturRequestErrorKind,
    };

    use super::fake::FakeDataKeySource;
    use super::{DataKeySource, IndexKeySource};
    use crate::errors::{Error, RetrieveKeyError};
    use crate::key::{DataKey, DataKeyWithTag, IndexKey};
    use crate::payload::{GenerateKeyPayload, RetrieveKeyPayload};

    /// A [`DataKeySource`] whose keys are a function of a seed and the
    /// descriptor, for fixtures that hold real sealed bytes.
    ///
    /// Every data key is `SHA-256(seed ‖ "key" ‖ 0 ‖ descriptor ‖ 0 ‖ iv)`,
    /// its tag `SHA-256(seed ‖ "tag" ‖ 0 ‖ descriptor ‖ 0 ‖ iv)`, and the IV
    /// `SHA-256(seed ‖ "iv" ‖ 0 ‖ descriptor ‖ 0 ‖ counter)[..16]`, where
    /// `descriptor` is the context the leaf is sealed under as ZeroKMS
    /// renders it. `retrieve_keys` re-derives the key and the tag from what
    /// the leaf stores and refuses a tag that is not this descriptor's, so a
    /// leaf opened under another field's label is refused as ZeroKMS would
    /// refuse it — and with the same classification: a forbidden request
    /// ([`RetrieveKeyError::RequestFailed`] of kind
    /// [`ViturRequestErrorKind::Forbidden`], ZeroKMS's HTTP 403), not a
    /// missing key. A test that asserts the error of a wrong-context open
    /// against this source therefore asserts what production reports. The
    /// index key is [`FakeDataKeySource`]'s, deterministic per keyset, so
    /// terms are the terms every other test derives.
    ///
    /// A test double, not a cipher: the derivation is SHA-256 over
    /// concatenated parts and models nothing of ZeroKMS beyond determinism.
    pub struct DeterministicSource {
        seed: [u8; 32],
        counter: AtomicU64,
        index: FakeDataKeySource,
    }

    // Debug without the seed, which derives every key.
    opaque_debug::implement!(DeterministicSource);

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

    impl super::KeySourceKind for DeterministicSource {
        type Kind = super::OwnIdentity;
    }

    impl DataKeySource for DeterministicSource {
        async fn generate_keys(
            &self,
            payloads: Vec<GenerateKeyPayload<'_>>,
            _keyset_id: Option<Uuid>,
            _unverified_context: Option<Cow<'_, UnverifiedContext>>,
        ) -> Result<Vec<DataKeyWithTag>, Error> {
            Ok(payloads
                .into_iter()
                .map(|payload| {
                    let n = self.counter.fetch_add(1, Ordering::SeqCst);
                    let iv_bytes = self.derive("iv", payload.descriptor, &n.to_le_bytes());
                    let mut iv = crate::Iv::default();
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
        ) -> Result<Vec<DataKey>, Error> {
            payloads
                .iter()
                .map(|payload| {
                    let iv: crate::Iv = *payload.iv.as_ref();
                    let tag = self.derive("tag", payload.descriptor, &iv);
                    if tag[..] != *payload.tag {
                        return Err(Error::RetrieveKey(RetrieveKeyError::RequestFailed(
                            ViturRequestError::new(
                                ViturRequestErrorKind::Forbidden,
                                "the data key is bound to another context",
                                WrongContext,
                            ),
                        )));
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
        ) -> Result<(Uuid, IndexKey), Error> {
            self.index.load_index_key(keyset_id).await
        }
    }

    /// The error behind the forbidden request: what ZeroKMS's 403 stands
    /// for here, a tag derived under one descriptor presented with another.
    #[derive(Debug)]
    struct WrongContext;

    impl std::fmt::Display for WrongContext {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("the tag is not this descriptor's")
        }
    }

    impl std::error::Error for WrongContext {}
}

#[cfg(feature = "test-support")]
pub use deterministic::DeterministicSource;

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

    /// The credential stub records the credential of each request, in
    /// order, round-trips a key between two callers, agrees with the plain
    /// stub on a keyset's index key, and keeps keys and credentials out of
    /// `Debug`.
    #[tokio::test]
    async fn the_credential_fake_records_the_credential_of_each_request() {
        let src = FakeCredentialKeySource::new();
        let (alice, bob) = (SecretToken::new("alice.jwt"), SecretToken::new("bob.jwt"));
        assert!(src.is_empty());
        assert!(src.credentials_seen().is_empty());

        let (default, index_key) = src
            .load_index_key_with_credential(&alice, None)
            .await
            .unwrap();
        let (plain_default, plain_index_key) =
            FakeDataKeySource::new().load_index_key(None).await.unwrap();
        assert_eq!(default, plain_default);
        assert_eq!(index_key.key(), plain_index_key.key());

        let generated = src
            .generate_keys_with_credential(
                &bob,
                vec![GenerateKeyPayload::new("users/email", Cow::Owned(vec![]))],
                None,
                None,
            )
            .await
            .unwrap()
            .remove(0);
        assert_eq!(src.len(), 1);
        assert!(!src.is_empty());
        let retrieved = src
            .retrieve_keys_with_credential(
                &alice,
                vec![RetrieveKeyPayload::new(
                    generated.key.iv,
                    "users/email",
                    &generated.tag,
                )],
                None,
                None,
            )
            .await
            .unwrap()
            .remove(0);
        assert_eq!(retrieved.key(), generated.key.key());

        assert_eq!(
            src.credentials_seen(),
            ["alice.jwt", "bob.jwt", "alice.jwt"]
        );
        let debug = format!("{src:?}");
        assert!(debug.contains("keys: 1"), "{debug}");
        assert!(debug.contains("credentials_seen: 3"), "{debug}");
        assert!(!debug.contains("alice.jwt"), "{debug}");
    }

    /// The deterministic source refuses a key retrieved under another
    /// descriptor the way ZeroKMS does, as a forbidden request, so the Go
    /// hermetic suite and the live suite assert one error for a wrong
    /// context.
    #[tokio::test]
    async fn deterministic_wrong_descriptor_is_forbidden_not_missing() {
        use zerokms_protocol::ViturRequestErrorKind;
        let src = DeterministicSource::new([7u8; 32]);
        let dk = src
            .generate_keys(
                vec![GenerateKeyPayload::new("users/email", Cow::Owned(vec![]))],
                None,
                None,
            )
            .await
            .unwrap()
            .remove(0);
        let result = src
            .retrieve_keys(
                vec![RetrieveKeyPayload::new(dk.key.iv, "users/notes", &dk.tag)],
                None,
                None,
            )
            .await;
        match result {
            Err(Error::RetrieveKey(RetrieveKeyError::RequestFailed(e))) => {
                assert!(
                    matches!(e.kind, ViturRequestErrorKind::Forbidden),
                    "{:?}",
                    e.kind
                )
            }
            other => panic!("expected a forbidden request, got {other:?}"),
        }
        // Under its own descriptor the key comes back.
        let keys = src
            .retrieve_keys(
                vec![RetrieveKeyPayload::new(dk.key.iv, "users/email", &dk.tag)],
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(keys[0].key, dk.key.key);
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
