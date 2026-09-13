//! Implementation of [`StackCipher`]. For usage, start at the crate docs; this
//! module documents the internals.
//!
//! `StackCipher` is scoped to one ZeroKMS client; a [`KeysetCipher`] — the
//! cipher bound to one of that client's keysets — is a vitaminc [`Cipher`]
//! whose per-leaf keys are ZeroKMS data keys, minted under that keyset,
//! rather than one fixed key. Structurally it mirrors
//! `vitaminc_encrypt::Aes256Cipher`: encrypting an [`Encrypt`] value produces
//! a recursive ciphertext tree ([`StackCipherText`], the analog of
//! `AesCipherText`) whose leaves ([`SealedValue`]) each carry the ZeroKMS
//! metadata for their own data key — the keyset it was minted under
//! included, which is why decrypting needs no keyset named and lives on the
//! client-scoped `StackCipher`.
//!
//! ## Batching the key fetch
//!
//! Data-key generation/retrieval is an async ZeroKMS round-trip, so the key
//! fetch cannot happen inside the synchronous [`Cipher`]/[`Decipher`] trait
//! methods. It is front-loaded on both sides; the AES work stays inside the
//! trait drive:
//!
//! * **Encrypt** — driving the [`Cipher`] trait over a `&KeysetCipher` builds
//!   a *pending* tree ([`PendingStackCipherText`]) that holds plaintext plus
//!   each leaf's fully derived AAD, but does no I/O. A single
//!   [`PendingStackCipherText::seal`] (or the [`KeysetCipher::encrypt`]
//!   convenience) then batches **one** `generate_keys` call for the whole
//!   tree, under the handle's keyset, and seals every leaf.
//! * **Decrypt** — [`StackCipher::decrypt`] batches **one** `retrieve_keys`
//!   call per keyset the leaves were sealed under and zips each key onto its
//!   leaf, building a [`StackDecipher`] it does not hand out. The
//!   value's [`Decrypt`] impl then drives that decipher exactly as it would
//!   `AesDecipher`: each leaf is opened under the AAD the drive supplies, so
//!   the visitor pattern (nested `Vec`/`HashMap`/`Option`/`Protected` values,
//!   and AAD-deriving wrappers such as `vitaminc_aead::Element`) works
//!   identically to `Aes256Cipher`.
//!
//! ## AAD derivation
//!
//! The caller's AAD is refined per node with the same domain-separated
//! derivations `Aes256Cipher` uses, so the container *shape* is authenticated:
//!
//! * sequence elements are sealed under [`Aad::for_sequence_element`];
//! * map values under [`Aad::for_map_entry`] of their cleartext key (so
//!   swapping or renaming keys fails decryption);
//! * authenticated-absent markers under [`Aad::for_none`], and empty
//!   sequences/maps under [`Aad::for_empty_sequence`]/[`Aad::for_empty_map`] —
//!   each sealing an *empty* plaintext, verified as empty on open.
//!
//! The decrypt side performs the same derivations inside [`StackDecipher`]'s
//! `decrypt_seq`/`decrypt_map`/`decrypt_option` as the caller's `Decrypt` impl
//! drives it, so there is a single source of truth for the per-node AAD.
//!
//! ## Leaf crypto and wire format
//!
//! Each leaf ([`SealedValue`]) stores the ZeroKMS keyset id, `iv` and key
//! `tag` — enough to retrieve the data key — plus a vitaminc
//! [`LocalCipherText`] sealed under that key by
//! [`vitaminc_encrypt::Aes256Cipher`] (AES-256-GCM via vitaminc's backend:
//! `aws-lc-rs` on native, RustCrypto on wasm32; vitaminc's own random nonce
//! and versioned leaf layout). The leaf AAD is the labelled derivation
//! `leaf_aad` (private):
//! `PAE("stack-encrypt/leaf", version, keyset_id, derived_aad, tag)`, with
//! [`SealedValue::FORMAT_VERSION`] — the version byte that prefixes the
//! leaf's frozen byte encoding ([`SealedValue::to_bytes`]) — and the keyset
//! id bound under the tag, so a stored leaf relabelled with a different
//! version byte fails verification instead of selecting different parsing
//! rules, and one re-pointed at another keyset fails instead of asking that
//! keyset for a key it never minted. The `tag` is always bound, so the
//! ciphertext is cryptographically tied to its ZeroKMS data key (key
//! binding); a caller AAD (e.g. a [`ContextTag`](vitaminc_aead::ContextTag))
//! adds a further binding layer.
//! Every data key is requested under a ZeroKMS **descriptor**: the context
//! the tree is sealed under, rendered as a string by
//! [`Descriptor`]. ZeroKMS HMACs the descriptor into the
//! key `tag` and demands the same descriptor to re-derive the key, so the
//! binding the leaf AAD makes locally is enforced at ZeroKMS as well, and
//! the descriptor is what ZeroKMS logs per retrieval. The lock context on
//! each request is empty.
//!
//! This is a fresh framing and is intentionally **not** byte-compatible with
//! `cipherstash-client`'s `EncryptedRecord` AAD (a raw `descriptor || tag`
//! concatenation). A compatibility module can be added later to read existing
//! records as customers of `cipherstash-client` migrate.

use std::any::Any;
use std::borrow::Cow;
use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use stack_kms::{DataKey, DataKeySource, DataKeyWithTag, IdentifiedBy, IndexKeySource};
#[cfg(feature = "http")]
use stack_kms::{EnvKeyProvider, StackKms, StackKmsBuilder};
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
use stack_kms::{FallbackKeyProvider, KeyProvider, KeyProviderError, ProfileStore};
use uuid::Uuid;
use vitaminc_aead::{
    Aad, Cipher, CipherText, Decipher, DecipherVisitor, Decrypt, Encrypt, IntoAad, LocalCipherText,
    MapAccess, MapCipher, SeqAccess, SeqCipher, Unspecified,
};
use vitaminc_encrypt::{Aes256Cipher, AesCipherText, Key as AesKey};
use vitaminc_protected::{Controlled, Protected};

use crate::keyset::{KeysetCache, KeysetCipher, KeysetState, Lookup, DEFAULT_NAME_TTL};
use crate::Descriptor;

/// The passthrough payload type: type-erased, as for Rust-native vitaminc
/// ciphers. Callers box on the way in and downcast on the way out.
pub type BoxedPassthrough = Box<dyn Any + Send + 'static>;

/// The recursive ciphertext container produced by [`StackCipher`]: vitaminc's
/// generic [`CipherText`] tree over [`SealedValue`] leaves. Its shape
/// mirrors the encrypted plaintext: a scalar yields `Single`, a `Vec` yields
/// `Sequence` (or `EmptySequence`), a `HashMap` or struct yields `Map` (or
/// `EmptyMap`). Map keys are stored in the clear but bound into their value's
/// AAD.
pub type StackCipherText = CipherText<SealedValue, BoxedPassthrough>;

/// Errors from sealing or opening a [`StackCipherText`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A ZeroKMS data-key generate/retrieve call failed.
    #[error("ZeroKMS data-key operation failed: {0}")]
    Kms(#[from] stack_kms::Error),
    /// AEAD sealing/opening failed, or the ciphertext shape did not match the
    /// requested type. On decrypt this is the expected outcome for a wrong key,
    /// wrong AAD, or tampered ciphertext.
    #[error("AEAD operation failed (wrong key, AAD mismatch, or malformed ciphertext)")]
    Aead,
    /// ZeroKMS returned a different number of keys than were requested.
    #[error("expected {expected} data keys from ZeroKMS but received {received}")]
    KeyCountMismatch { expected: usize, received: usize },
    /// A context rendered to a descriptor longer than ZeroKMS can bind
    /// ([`Descriptor::MAX_LEN`]). Raised before any request is sent, so no
    /// key is minted or retrieved for the batch.
    #[error(
        "context renders to a {len}-byte ZeroKMS descriptor; the limit is {} bytes",
        Descriptor::MAX_LEN
    )]
    DescriptorTooLong { len: usize },
    /// Building a ZeroKMS client from the environment failed: credentials or
    /// client key missing or malformed.
    ///
    /// Boxed rather than naming `stack_kms::StackKmsBuilderError` directly:
    /// that type only exists with `http`, and a variant whose presence tracks
    /// a feature is not additive — feature unification elsewhere in the graph
    /// would then change this enum's shape under a downstream match.
    #[error("could not build a ZeroKMS client from the environment: {0}")]
    Config(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// An index term failed to derive.
    #[error(transparent)]
    Term(#[from] crate::sem::TermError),
    /// A third-party [`EncryptFrom`](crate::target::EncryptFrom) /
    /// [`DecryptInto`](crate::target::DecryptInto) implementation failed
    /// for a reason of its own.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// A [`Pending`](crate::target::Pending) fulfilment's requests and
    /// responses did not line up: it drew more responses — or a different
    /// kind — than its requests asked for, or left some of them unconsumed.
    /// Always a composition bug in an `EncryptFrom`/`DecryptInto`
    /// implementation, never a data error.
    #[error("a pending fulfilment's responses did not match its requests")]
    ResponseShape,
    /// [`Pending`](crate::target::Pending)s scoped to different keysets were
    /// merged (`zip` / `all`): one built through a [`KeysetCipher`] for one
    /// keyset, the other for another. A row belongs to one tenant; an
    /// assembly that spans two is a composition bug, caught before any
    /// I/O. (Opening leaves from several keysets in one batch is allowed —
    /// through the [`StackCipher`], which is scoped to none.)
    ///
    /// The keyset is the *whole* merge rule: two pendings built through two
    /// different [`StackCipher`] values merge freely as long as they agree
    /// on a keyset, because a keyset id is global and a cipher only holds a
    /// keyset ZeroKMS resolved for its client. (Before the multi-keyset
    /// `StackCipher` there was a `CipherMismatch` variant here, raised on
    /// pointer equality of the two ciphers; it tested object identity
    /// rather than client identity, and so refused two ciphers over the
    /// same client and the same keyset.)
    #[error("merged pendings were scoped to different keysets ({left} and {right})")]
    KeysetMismatch { left: Uuid, right: Uuid },
    /// A leaf sealed under one keyset was handed to a [`KeysetCipher`] for
    /// another. The handle's keyset is a constraint the caller asked for —
    /// a tenant-scoped request handler must not open another tenant's row
    /// — so this is refused before any key is retrieved. To open leaves
    /// from any keyset, decrypt through the [`StackCipher`].
    #[error("leaf was sealed under keyset {found}, not the handle's keyset {expected}")]
    ForeignKeyset { expected: Uuid, found: Uuid },
    /// A data key was requested through a [`StackCipher`] rather than a
    /// [`KeysetCipher`]: a [`Request::generate_data_key`] needs a keyset
    /// to mint under, and only a keyset-scoped pending has one. Always a
    /// composition bug in a hand-written `EncryptFrom`, caught before any
    /// I/O.
    ///
    /// [`Request::generate_data_key`]: crate::target::Request::generate_data_key
    #[error("a data key was requested with no keyset to mint it under")]
    NoKeyset,
    /// A [`DecryptField`](crate::target::DecryptField) implementation
    /// declared its type [`DECRYPTABLE`](crate::target::Decryptable::DECRYPTABLE)
    /// but passed the field over. Always a bug in a third-party
    /// `DecryptField`, never a data error.
    #[error("a field declared decryptable was not opened by its DecryptField implementation")]
    NotOpened,
}

#[cfg(feature = "http")]
impl From<stack_kms::StackKmsBuilderError> for Error {
    fn from(error: stack_kms::StackKmsBuilderError) -> Self {
        Error::Config(Box::new(error))
    }
}

impl From<Unspecified> for Error {
    fn from(_: Unspecified) -> Self {
        Error::Aead
    }
}

/// The CipherStash cipher, scoped to one client: a ZeroKMS client (a
/// [`DataKeySource`] — production: [`stack_kms::StackKms`]; tests:
/// `stack_kms::FakeDataKeySource`) and the keysets that client uses.
///
/// Per-leaf keying is deliberate: every value access requires its own data-key
/// retrieval, so individual value accesses are visible (and auditable) as
/// ZeroKMS key-retrieval events.
///
/// # Keysets
///
/// Sealing values, sealing records and deriving index terms all happen
/// under a keyset, and a client may use many — one per tenant, say. So
/// those operations bind to a [`KeysetCipher`], the cipher scoped to one
/// keyset: [`default_keyset`](Self::default_keyset) for the client's
/// default — the keyset a ZeroKMS administrator set for this client —
/// [`keyset`](Self::keyset) for any other, by id or by name. Keysets load lazily, through a bounded
/// least-recently-used cache: the first selection of a keyset is one
/// ZeroKMS round trip (its index key, which
/// [Searchable Encrypted Metadata](crate::sem) terms are derived from),
/// and every later one is a lookup. A backend that cannot supply an index
/// key is not a Stack Encrypt backend; plain AEAD with no indexing is what
/// `vitaminc` alone provides.
///
/// Decrypting is not keyset-scoped: a sealed leaf carries the id of the
/// keyset it was sealed under, and retrieving its data key needs nothing
/// more than that and the client. So [`decrypt`](Self::decrypt) lives here
/// and opens leaves from any keyset the client is authorised for, in one
/// batch. The same method on a [`KeysetCipher`] adds a constraint: it
/// refuses a leaf from any other keyset before any key is retrieved.
///
/// # Construction
///
// `new()` builds the ZeroKMS client from the environment, so it exists only
// with `http`; the builder path below works in either shape.
#[cfg_attr(
    feature = "http",
    doc = r#"[`new`](Self::new) is the default path — a ZeroKMS client from the
environment, on that client's default keyset:

```no_run
# async fn example() -> Result<(), stack_encrypt::Error> {
use stack_encrypt::StackCipher;

let cipher = StackCipher::new().await?;
# Ok(())
# }
```

Override with [`builder`](Self::builder) — a different keyset, or a
different data-key source entirely:"#
)]
#[cfg_attr(
    not(feature = "http"),
    doc = "Build with [`builder`](Self::builder), over an explicit data-key source:"
)]
///
/// ```
/// # async fn example() -> Result<(), stack_encrypt::Error> {
/// use stack_encrypt::StackCipher;
/// use stack_kms::FakeDataKeySource;
///
/// let cipher = StackCipher::builder()
///     .kms(FakeDataKeySource::new())
///     .init()
///     .await?;
/// # Ok(())
/// # }
/// # tokio_test_block_on(example()).unwrap();
/// # fn tokio_test_block_on<F: std::future::Future>(f: F) -> F::Output {
/// #     tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
/// # }
/// ```
///
/// Construction is async because it resolves the client's default keyset
/// and loads its index key — one ZeroKMS round-trip, paid once, so a
/// misconfigured client fails here rather than on first use.
pub struct StackCipher<K> {
    kms: K,
    /// The client's default keyset, loaded eagerly by `init` and never
    /// evicted. Not the caller's to choose — see
    /// [`default_keyset`](Self::default_keyset).
    default: Arc<KeysetState>,
    /// Every other keyset this cipher has selected, least recently used
    /// first out. See [`keyset`](Self::keyset).
    keysets: Mutex<KeysetCache>,
}

#[cfg(feature = "http")]
impl StackCipher<StackKms<stack_auth::AutoStrategy>> {
    /// Build a cipher over a ZeroKMS client configured from the environment,
    /// on that client's default keyset.
    ///
    /// Equivalent to `StackCipher::builder().init()`. For a different keyset
    /// or a different data-key source, use [`builder`](StackCipher::builder).
    pub async fn new() -> Result<Self, Error> {
        StackCipher::builder().init().await
    }
}

impl StackCipher<FromEnv> {
    /// Start building a cipher: pick a keyset, or supply a data-key source
    /// other than the environment's ZeroKMS client.
    ///
    /// A convenience alias for [`StackCipherBuilder::new`], which is the
    /// canonical entry point. This one is anchored on `StackCipher<FromEnv>`
    /// purely so `StackCipher::builder()` names a single concrete `K` and
    /// resolves without a type annotation; `StackCipher<FromEnv>` is never
    /// constructed.
    pub fn builder() -> StackCipherBuilder {
        StackCipherBuilder::new()
    }
}

/// Opaque: the default keyset's identity and the data-key source's type
/// name, and nothing else. A cipher reaches the whole keyset cache — every
/// loaded keyset's index-key PRF — and, through its backend, the client key
/// and access token; none of that is printable, and a `Debug` that walked
/// the cache would also take its lock.
impl<K> std::fmt::Debug for StackCipher<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StackCipher")
            .field("default_keyset_id", &self.default.id)
            .field("default_keyset_name", &self.default.name)
            .field("kms", &std::any::type_name::<K>())
            .finish_non_exhaustive()
    }
}

impl<K> StackCipher<K> {
    /// The cipher bound to the client's default keyset: the one a ZeroKMS
    /// administrator set for this client, which is what naming no keyset
    /// resolves to. Loaded at `init`, so this never touches ZeroKMS.
    ///
    /// Always that keyset, whatever else the cipher has selected — the
    /// default is the workspace's statement about this client, not a
    /// preference a caller can override. To work under another keyset,
    /// select it with [`keyset`](Self::keyset).
    pub fn default_keyset(&self) -> KeysetCipher<'_, K> {
        KeysetCipher::new(self, Arc::clone(&self.default))
    }

    /// The underlying data-key source.
    pub fn kms(&self) -> &K {
        &self.kms
    }

    fn keysets(&self) -> std::sync::MutexGuard<'_, KeysetCache> {
        // The cache holds no invariant a panic mid-update could break (an
        // insert is two map writes, and a stale name entry only points at
        // a still-valid state), so a poisoned lock is recovered, not
        // propagated.
        self.keysets.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<K: IndexKeySource> StackCipher<K> {
    /// The cipher bound to a keyset, by id or by name.
    ///
    /// The one async point of keyset selection: a keyset this cipher has
    /// not seen (or has evicted) is loaded from ZeroKMS here — its id
    /// resolved and its index key fetched — and cached; every later
    /// selection is a lookup. The returned handle keeps that keyset loaded
    /// for as long as it is held, so a request handler that selects its
    /// tenant's keyset once never pays again within the request.
    ///
    /// ```
    /// # async fn example() -> Result<(), stack_encrypt::Error> {
    /// use stack_encrypt::{nonempty, StackCipher};
    /// use stack_kms::{FakeDataKeySource, IdentifiedBy};
    ///
    /// let cipher = StackCipher::builder()
    ///     .kms(FakeDataKeySource::new())
    ///     .init()
    ///     .await?;
    /// let tenant = cipher.keyset(IdentifiedBy::Name("acme".to_string().into())).await?;
    /// let sealed = tenant.encrypt("hello".to_string(), nonempty!("greeting")).await?;
    /// # Ok(())
    /// # }
    /// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
    /// ```
    ///
    /// A keyset ZeroKMS does not know, or has disabled, is
    /// [`Error::Kms`]. The name-to-id resolution is ZeroKMS's: a keyset
    /// selected by name reports the resolved id from
    /// [`KeysetCipher::keyset_id`], and a name the cipher resolved earlier
    /// is trusted for a bounded window
    /// ([`keyset_name_ttl`](StackCipherBuilder::keyset_name_ttl)) before it
    /// is asked again — ZeroKMS allows renames, and a running process
    /// notices one within that window. Selecting by id never asks twice.
    pub async fn keyset(
        &self,
        keyset: impl Into<IdentifiedBy>,
    ) -> Result<KeysetCipher<'_, K>, Error> {
        let keyset = keyset.into();
        let resolution = match self.keysets().get(&keyset) {
            Lookup::Hit(state) => return Ok(KeysetCipher::new(self, state)),
            // A name past its window: the keyset is still loaded, but
            // whether the name still means it is ZeroKMS's to say.
            Lookup::Stale(resolution) | Lookup::Miss(resolution) => resolution,
        };
        // Loaded outside the lock: a round trip must not hold up every other
        // selection. Two selections racing on the same miss load twice; the
        // cache keeps both keysets by id, and the name follows the later
        // lookup whichever answer lands first — and so does this caller,
        // who is handed the answer that won, not the one that lost.
        let asked_name = match &keyset {
            IdentifiedBy::Name(name) => Some(name.to_string()),
            IdentifiedBy::Uuid(_) => None,
        };
        let state = match load_keyset(&self.kms, keyset).await {
            Ok(state) => state,
            Err(error) => {
                // ZeroKMS's own answer that no keyset has this name is an
                // answer about the name, and the cache orders it like one:
                // the binding an earlier lookup made goes, and an earlier
                // positive answer still in flight cannot bind the name after
                // it. A lookup that got no answer (transport, auth) says
                // nothing about the name and leaves the cache as it was.
                if let (Some(name), true) = (&asked_name, is_keyset_not_found(&error)) {
                    self.keysets().forget(name, resolution);
                }
                return Err(error);
            }
        };
        let state = self.keysets().insert(state, resolution);
        Ok(KeysetCipher::new(self, state))
    }
}

/// Resolve a keyset at ZeroKMS and build the state the cipher holds for it:
/// its resolved id, the name it was selected by (a selection by id has
/// none), and the PRF keyed by its index key. The one round trip a keyset
/// costs, shared by eager loading at
/// [`init`](StackCipherBuilder::init) and lazy loading in
/// [`StackCipher::keyset`] so both hold a keyset in exactly the same shape.
/// ZeroKMS answered a load with "no such keyset" — as opposed to not
/// answering at all.
fn is_keyset_not_found(error: &Error) -> bool {
    matches!(
        error,
        Error::Kms(stack_kms::Error::LoadKeyset(
            stack_kms::LoadKeysetError::KeysetNotFound(_)
        ))
    )
}

async fn load_keyset<K: IndexKeySource>(
    kms: &K,
    keyset: IdentifiedBy,
) -> Result<Arc<KeysetState>, Error> {
    let name = match &keyset {
        IdentifiedBy::Name(name) => Some(name.to_string()),
        IdentifiedBy::Uuid(_) => None,
    };
    let (id, index_key) = kms.load_index_key(Some(keyset)).await?;
    Ok(Arc::new(KeysetState {
        id,
        name,
        prf: hmac_prf_from_index_key(&index_key),
    }))
}

/// The client's own default keyset — the one a ZeroKMS administrator set for
/// this client — asked for by naming nothing. Loaded once, by
/// [`init`](StackCipherBuilder::init); it is not the caller's to choose, so
/// there is no id or name to carry.
async fn load_default_keyset<K: IndexKeySource>(kms: &K) -> Result<Arc<KeysetState>, Error> {
    let (id, index_key) = kms.load_index_key(None).await?;
    Ok(Arc::new(KeysetState {
        id,
        name: None,
        prf: hmac_prf_from_index_key(&index_key),
    }))
}

/// The state of a [`StackCipherBuilder`] that has not been given a data-key
/// source: [`init`](StackCipherBuilder::init) will build a ZeroKMS client from
/// the environment (and, on native targets, the CLI's profile directory).
pub struct FromEnv;

/// The client key, looked up the way [`stack_auth::AutoStrategy`] looks up the
/// access token: `CS_CLIENT_ID` / `CS_CLIENT_KEY` first, then the current
/// workspace's `secretkey.json` in the profile directory. A profile directory
/// that cannot be resolved is not an error here — env-only setups (CI) have
/// none — it just leaves the environment as the only source.
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
fn client_key_provider() -> FallbackKeyProvider<EnvKeyProvider, ProfileClientKey> {
    FallbackKeyProvider::new(
        EnvKeyProvider,
        ProfileClientKey(ProfileStore::resolve(None).ok()),
    )
}

/// wasm32 has no filesystem, so no profile: the environment is the only source.
#[cfg(all(feature = "http", target_arch = "wasm32"))]
fn client_key_provider() -> EnvKeyProvider {
    EnvKeyProvider
}

/// [`ProfileStore`] as a [`KeyProvider`], tolerating an unresolvable profile
/// directory so the "not configured" message can say what to do about it
/// rather than only that `CS_CLIENT_ID` is unset.
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
struct ProfileClientKey(Option<ProfileStore>);

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
impl KeyProvider for ProfileClientKey {
    async fn client_key(&self) -> Result<stack_kms::ClientKey, KeyProviderError> {
        match &self.0 {
            Some(store) => store.client_key().await,
            None => Err(KeyProviderError::NotConfigured(
                "no client key: set CS_CLIENT_ID / CS_CLIENT_KEY, or run `npx stash auth login`"
                    .into(),
            )),
        }
    }
}

/// Builder for a [`StackCipher`]. Start with [`StackCipherBuilder::new`] (or
/// its alias [`StackCipher::builder`]).
pub struct StackCipherBuilder<K = FromEnv> {
    kms: K,
    cache_size: NonZeroUsize,
    name_ttl: Duration,
}

impl StackCipherBuilder<FromEnv> {
    /// Start building a cipher: pick a keyset, or supply a data-key source
    /// other than the environment's ZeroKMS client.
    ///
    /// The `K = FromEnv` type default makes this resolve without a type
    /// annotation whether or not the `http` feature is on.
    pub fn new() -> Self {
        Self {
            kms: FromEnv,
            cache_size: KeysetCache::DEFAULT_CAPACITY,
            name_ttl: DEFAULT_NAME_TTL,
        }
    }
}

impl Default for StackCipherBuilder<FromEnv> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K> StackCipherBuilder<K> {
    /// How many keysets beyond the default the cipher keeps loaded
    /// (default 1024). A process serving more tenants than this reloads a
    /// keyset's index key from ZeroKMS when it comes back into use; nothing
    /// stored depends on the cache, so the bound only trades memory for
    /// round trips. See [`StackCipher::keyset`].
    pub fn keyset_cache_size(mut self, size: NonZeroUsize) -> Self {
        self.cache_size = size;
        self
    }

    /// How long a keyset selected by name is trusted to still be the keyset
    /// that name resolved to (default five minutes, [`DEFAULT_NAME_TTL`]).
    /// ZeroKMS allows a keyset to be renamed; within the window a rename is
    /// invisible to a running process, after it the next selection by that
    /// name asks ZeroKMS again. `Duration::ZERO` makes every selection by
    /// name a round trip; selection by id is never affected. See
    /// [`StackCipher::keyset`].
    ///
    /// [`DEFAULT_NAME_TTL`]: crate::keyset::DEFAULT_NAME_TTL
    pub fn keyset_name_ttl(mut self, ttl: Duration) -> Self {
        self.name_ttl = ttl;
        self
    }
}

impl StackCipherBuilder<FromEnv> {
    /// Use an explicit data-key source rather than building a ZeroKMS client
    /// from the environment.
    ///
    /// This is the seam for a custom authentication strategy: build a
    /// [`stack_kms::StackKms`] — with `stack_kms::StackKmsBuilder`,
    /// or over the host's own transport — and hand it over. It is also how
    /// tests inject `stack_kms::FakeDataKeySource`.
    pub fn kms<K>(self, kms: K) -> StackCipherBuilder<K> {
        StackCipherBuilder {
            kms,
            cache_size: self.cache_size,
            name_ttl: self.name_ttl,
        }
    }

    /// Build a ZeroKMS client from the environment, then resolve the keyset
    /// and load its index key.
    ///
    /// Credentials come from the same two places for both halves of the
    /// client — the access token and the client key:
    ///
    /// 1. the environment (`CS_CLIENT_ACCESS_KEY` + `CS_WORKSPACE_CRN`;
    ///    `CS_CLIENT_ID` + `CS_CLIENT_KEY`), then
    /// 2. the current workspace in the CLI's profile directory
    ///    (`auth.json`; `secretkey.json`), which `npx stash auth login`
    ///    writes.
    ///
    /// So on a developer machine, logging in with the CLI is sufficient; in
    /// CI, the four variables are.
    #[cfg(feature = "http")]
    pub async fn init(self) -> Result<StackCipher<StackKms<stack_auth::AutoStrategy>>, Error> {
        let kms = StackKmsBuilder::auto()?
            .with_key_provider(client_key_provider())
            .build()
            .await?;
        self.kms(kms).init().await
    }
}

impl<K: DataKeySource + IndexKeySource> StackCipherBuilder<K> {
    /// Resolve the default keyset and load its index key, producing a
    /// cipher whose [`default_keyset`](StackCipher::default_keyset) can both
    /// seal values and derive index terms. The one round trip a cipher
    /// always pays; every other keyset loads on first selection.
    pub async fn init(self) -> Result<StackCipher<K>, Error> {
        let default = load_default_keyset(&self.kms).await?;
        Ok(StackCipher {
            kms: self.kms,
            keysets: Mutex::new(KeysetCache::new(
                self.cache_size,
                self.name_ttl,
                Arc::clone(&default),
            )),
            default,
        })
    }
}

/// Build the local HMAC-SHA256 PRF from a per-keyset
/// [`IndexKey`](stack_kms::IndexKey), wiping the intermediate stack copy of the
/// raw key bytes.
fn hmac_prf_from_index_key(index_key: &stack_kms::IndexKey) -> vitaminc_hmac::HmacSha256Prf {
    use zeroize::Zeroize;

    // `[u8; 32]` is `Copy`: the move into `Protected` leaves this stack copy
    // behind, so wipe it before returning.
    let mut key = *index_key.key();
    let prf = <vitaminc_hmac::HmacSha256Prf as vitaminc_prf::PrfKeyInit>::new(Protected::new(key));
    key.zeroize();
    prf
}

impl<K: DataKeySource> KeysetCipher<'_, K> {
    /// Encrypt a value, binding `aad`, and seal it against fresh ZeroKMS data
    /// keys in a single batched `generate_keys` call under this keyset.
    /// Every key is requested under the [`Descriptor`] of `aad`.
    pub async fn encrypt<'a, T, A>(&self, value: T, aad: A) -> Result<StackCipherText, Error>
    where
        T: Encrypt,
        A: IntoAad<'a>,
    {
        let aad = aad.into_aad_piece();
        let pending = value.encrypt_with_aad(self, aad.clone().into_aad())?;
        pending.seal(self, aad).await
    }

    /// [`StackCipher::decrypt`], constrained to this keyset: a leaf sealed
    /// under any other is [`Error::ForeignKeyset`], refused before any key
    /// is retrieved.
    pub async fn decrypt<'a, T, A>(&self, ciphertext: StackCipherText, aad: A) -> Result<T, Error>
    where
        T: Decrypt<'static> + 'static,
        A: IntoAad<'a>,
    {
        decrypt_through(self, ciphertext, aad).await
    }
}

/// Retrieve every leaf's data key under `aad`'s descriptor and bind them
/// onto the ciphertext, for either scope. The work is the same on both —
/// one descriptor, one pending, one settle — and the scope is the whole
/// difference: a [`KeysetCipher`] constrains the leaves to its keyset, a
/// [`StackCipher`] constrains nothing.
///
/// Deliberately private. The returned [`StackDecipher`] is driven with an
/// AAD supplied per call, so exposing this would let a caller retrieve keys
/// under one context and authenticate the ciphertext under an unrelated
/// one. Every leaf's AAD is a derivation of the descriptor its key was
/// minted under — `for_sequence_element`, `for_map_entry`, `for_leaf` —
/// and that derivation is the library's to compute, never the caller's to
/// supply. [`decrypt_through`] is the only way in, and it passes one `aad`
/// to both halves.
async fn decipher_through<'s, 'a, K: DataKeySource + 's>(
    scope: impl crate::target::CipherScope<'s, K>,
    ciphertext: StackCipherText,
    aad: impl IntoAad<'a>,
) -> Result<StackDecipher, Error> {
    crate::target::decipher_pending(scope, ciphertext, Descriptor::of(aad))
        .settle()
        .await
}

/// `decrypt`, for either scope: [`decipher_through`], then the value's own
/// [`Decrypt`] drive under the same `aad`.
async fn decrypt_through<'s, 'a, T, K: DataKeySource + 's>(
    scope: impl crate::target::CipherScope<'s, K>,
    ciphertext: StackCipherText,
    aad: impl IntoAad<'a>,
) -> Result<T, Error>
where
    T: Decrypt<'static> + 'static,
{
    let aad = aad.into_aad_piece();
    let decipher = decipher_through(scope, ciphertext, aad.clone()).await?;
    T::decrypt_with_aad(decipher, aad.into_aad()).map_err(Error::from)
}

impl<K: DataKeySource> StackCipher<K> {
    /// Decrypt a [`StackCipherText`] into `T`, authenticating against `aad`.
    ///
    /// One batched `retrieve_keys` call per keyset the leaves were sealed
    /// under, every key under the [`Descriptor`] of `aad`, then `T`'s
    /// [`Decrypt`] impl drives the resulting [`StackDecipher`] with the
    /// *same* `aad` — exactly as `Aes256Cipher::decrypt_with_aad` drives
    /// `AesDecipher`. One context in, and every leaf's AAD derived from it;
    /// there is no form of this call that takes two.
    ///
    /// Not keyset-scoped: each leaf carries the id of the keyset it was
    /// sealed under, and this opens leaves from any keyset the client is
    /// authorised for. To insist on one keyset, decrypt through its
    /// [`KeysetCipher`] instead.
    ///
    /// # Fan-out
    ///
    /// The retrieve calls are one per *distinct keyset* among the leaves,
    /// issued in sequence, and the keyset ids come from the ciphertext —
    /// so their number is the input's to decide, up to the keysets this
    /// client can retrieve from (ZeroKMS refuses a retrieve whose tag it
    /// did not mint, and the first refusal ends the batch). A ciphertext
    /// assembled from many tenants' leaves costs a round trip per tenant to
    /// open here, whoever assembled it. A service opening rows it does not
    /// trust — one tenant's data at a time — should hold that tenant's
    /// [`KeysetCipher`], whose decrypt is one round trip at most and refuses
    /// a foreign leaf before any.
    pub async fn decrypt<'a, T, A>(&self, ciphertext: StackCipherText, aad: A) -> Result<T, Error>
    where
        T: Decrypt<'static> + 'static,
        A: IntoAad<'a>,
    {
        decrypt_through(self, ciphertext, aad).await
    }
}

/// A single sealed leaf: the ZeroKMS metadata needed to retrieve its data key
/// (`iv`, `tag`) plus the vitaminc `LocalCipherText` sealed under that key.
///
/// This is the only byte-format commitment the crate makes for *ciphertext* —
/// the container tree ([`StackCipherText`]) has no canonical encoding, so
/// callers that persist or transmit ciphertext serialise leaves and rebuild
/// the tree around them. Index terms are a separate commitment with their own
/// frozen encodings (see the
/// [index-term encodings](crate::sem#byte-encodings)).
///
/// # Frozen byte encoding
///
/// [`to_bytes`](Self::to_bytes) / [`from_bytes`](Self::from_bytes) are the
/// canonical encoding — the one storage format every consumer (this crate,
/// the language bindings, anything reading a database column) agrees on.
/// The v1 layout:
///
/// | offset          | field              | size            | value |
/// |-----------------|--------------------|-----------------|-------|
/// | 0               | envelope version   | 1               | [`FORMAT_VERSION`](Self::FORMAT_VERSION) (`0x01`) |
/// | 1               | keyset id          | 16              | the ZeroKMS keyset the data key was minted under, raw UUID bytes |
/// | 17              | ZeroKMS `iv`       | 16              | identifies the data key for retrieval |
/// | 33              | `tag_len`          | 2               | length of `tag`, `u16` little-endian |
/// | 35              | ZeroKMS key `tag`  | `tag_len`       | required to retrieve the key |
/// | 35 + `tag_len`  | local ciphertext   | rest of buffer  | the vitaminc `LocalCipherText` |
///
/// The keyset id is what lets a leaf be opened without the caller saying
/// which keyset it belongs to: retrieving the data key needs the keyset,
/// and the leaf is self-describing so that a leaf lifted from a tree — what
/// a database column holds — is too.
///
/// The local ciphertext is itself a framed value — vitaminc's leaf wire
/// format, versioned and owned by vitaminc — so the full stored byte string
/// nests two framings, each led by its own version byte:
///
/// ```text
/// ┌─ envelope (stack-encrypt, this table) ──────────────────────────────────────────────┐
/// │ version ‖ keyset_id ‖ iv ‖ tag_len ‖ tag ‖ ┌─ local ciphertext (vitaminc) ───────────┐ │
/// │   0x01                                     │ version ‖ nonce ‖ ciphertext ‖ gcm_tag  │ │
/// │                                            └─────────────────────────────────────────┘ │
/// └─────────────────────────────────────────────────────────────────────────────────────┘
/// ```
///
/// Both version bytes and the keyset id are authenticated under the one GCM
/// tag, each bound by the layer that owns its framing: the envelope version
/// and the keyset id through this crate's leaf-AAD derivation,
/// `PAE("stack-encrypt/leaf", version, keyset_id, derived_aad, tag)`, and
/// the inner version through vitaminc's `Aad::for_leaf`, applied inside
/// `Aes256Cipher` to the AAD this crate hands it. Relabel either version
/// byte, or re-point the leaf at another keyset, in storage and the leaf
/// fails authentication rather than parsing under the wrong rules. Parsing
/// is structural only — nothing about a decoded leaf is trusted until it
/// decrypts.
///
/// The `serde` `Serialize`/`Deserialize` derives and
/// [`into_parts`](Self::into_parts) / [`from_parts`](Self::from_parts)
/// remain for callers that manage their own storage format; they carry the
/// same fields, but their wire form is the serialiser's, not a commitment
/// of this crate.
#[derive(Debug, Serialize, Deserialize)]
#[serde(try_from = "SealedValueRepr")]
pub struct SealedValue {
    /// The keyset the data key was minted under; retrieval names it.
    keyset_id: Uuid,
    /// ZeroKMS IV: identifies the data key for retrieval.
    iv: stack_kms::Iv,
    /// ZeroKMS key tag: required to retrieve the key, and bound into the
    /// leaf's AAD so the ciphertext is tied to its data key.
    tag: Vec<u8>,
    /// The leaf sealed by [`vitaminc_encrypt::Aes256Cipher`] under the data
    /// key: `version ‖ nonce ‖ ciphertext ‖ gcm_tag`.
    ciphertext: LocalCipherText,
}

/// A [`SealedValue`] byte encoding failed to encode or decode. Purely
/// structural — a leaf that *decodes* has proven nothing about integrity
/// (that is the AEAD open's job); a leaf that fails here was never a valid
/// v1 encoding at all.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LeafBytesError {
    /// The leading version byte is not one this build knows how to parse.
    /// (A version this build *does* know, stamped on bytes sealed under a
    /// different version, passes here and fails authentication instead —
    /// the version byte is bound into the leaf AAD.)
    #[error("unknown sealed-leaf format version {0}")]
    UnknownVersion(u8),
    /// The buffer ends before the fixed-width fields, or before the key tag
    /// the `tag_len` field promises.
    #[error("sealed-leaf bytes are truncated")]
    Truncated,
    /// The key tag does not fit the format's `u16` length field. Every
    /// construction site rejects an oversized tag — [`SealedValue::from_parts`]
    /// and `serde` deserialisation with this error, and the seal path (where a
    /// custom [`DataKeySource`] could return one; real ZeroKMS tags are tens
    /// of bytes) by failing the encrypt — so a live `SealedValue` always
    /// encodes.
    #[error("key tag of {0} bytes exceeds the format's u16 length field")]
    TagTooLong(usize),
}

impl SealedValue {
    /// The version byte prefixing the frozen byte encoding
    /// ([`to_bytes`](Self::to_bytes)). Also bound into every leaf's AAD (the
    /// private `leaf_aad` derivation): bumping it re-keys authentication, so
    /// old leaves can never be relabelled as the new version (nor new as
    /// old).
    pub const FORMAT_VERSION: u8 = 1;

    /// Encode into the frozen v1 byte layout — see the type-level docs for
    /// the format. The inverse of [`from_bytes`](Self::from_bytes).
    ///
    /// Infallible: every way of building a `SealedValue` rejects a tag too
    /// long for the `u16` length field ([`LeafBytesError::TagTooLong`]), so a
    /// value that exists always encodes.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Exact by the `tag_fits_length_field` check every construction site
        // applies — `from_parts`, serde deserialisation, and the seal path
        // (which guards against a `DataKeySource` returning an oversized tag).
        // The saturating fallback is unreachable, and asserted so in tests.
        let tag_len = u16::try_from(self.tag.len()).unwrap_or(u16::MAX);
        debug_assert_eq!(usize::from(tag_len), self.tag.len());
        let ciphertext = self.ciphertext.as_ref();
        let mut out =
            Vec::with_capacity(1 + 16 + self.iv.len() + 2 + self.tag.len() + ciphertext.len());
        out.push(Self::FORMAT_VERSION);
        out.extend_from_slice(self.keyset_id.as_bytes());
        out.extend_from_slice(&self.iv);
        out.extend_from_slice(&tag_len.to_le_bytes());
        out.extend_from_slice(&self.tag);
        out.extend_from_slice(ciphertext);
        out
    }

    /// Decode the frozen v1 byte layout — the inverse of
    /// [`to_bytes`](Self::to_bytes). Structural only: a decoded leaf is
    /// untrusted bytes until it decrypts.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LeafBytesError> {
        const IV_LEN: usize = 16;

        let (&version, rest) = bytes.split_first().ok_or(LeafBytesError::Truncated)?;
        if version != Self::FORMAT_VERSION {
            return Err(LeafBytesError::UnknownVersion(version));
        }
        if rest.len() < 16 + IV_LEN + 2 {
            return Err(LeafBytesError::Truncated);
        }
        let (keyset_bytes, rest) = rest.split_at(16);
        let keyset_id = Uuid::from_slice(keyset_bytes).map_err(|_| LeafBytesError::Truncated)?;
        let (iv_bytes, rest) = rest.split_at(IV_LEN);
        let mut iv: stack_kms::Iv = [0; IV_LEN];
        iv.copy_from_slice(iv_bytes);
        let (tag_len_bytes, rest) = rest.split_at(2);
        let tag_len = usize::from(u16::from_le_bytes([tag_len_bytes[0], tag_len_bytes[1]]));
        if rest.len() < tag_len {
            return Err(LeafBytesError::Truncated);
        }
        let (tag, ciphertext) = rest.split_at(tag_len);
        Ok(Self {
            keyset_id,
            iv,
            tag: tag.to_vec(),
            ciphertext: LocalCipherText::from(ciphertext.to_vec()),
        })
    }

    /// The one invariant that makes [`to_bytes`](Self::to_bytes) infallible:
    /// the key tag must fit the format's `u16` length field.
    fn tag_fits_length_field(tag: &[u8]) -> Result<(), LeafBytesError> {
        if tag.len() > usize::from(u16::MAX) {
            return Err(LeafBytesError::TagTooLong(tag.len()));
        }
        Ok(())
    }

    /// Rebuild a leaf from its persisted parts — the inverse of
    /// [`into_parts`](Self::into_parts).
    ///
    /// Fails with [`LeafBytesError::TagTooLong`] if `tag` does not fit the
    /// byte format's `u16` length field. Structural only: nothing about the
    /// parts is trusted until the leaf decrypts.
    pub fn from_parts(
        keyset_id: Uuid,
        iv: stack_kms::Iv,
        tag: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Self, LeafBytesError> {
        Self::tag_fits_length_field(&tag)?;
        Ok(Self {
            keyset_id,
            iv,
            tag,
            ciphertext: LocalCipherText::from(ciphertext),
        })
    }

    /// Decompose into `(keyset_id, iv, tag, ciphertext)` for persistence.
    pub fn into_parts(self) -> (Uuid, stack_kms::Iv, Vec<u8>, Vec<u8>) {
        (
            self.keyset_id,
            self.iv,
            self.tag,
            self.ciphertext.into_inner().to_vec(),
        )
    }

    /// The keyset this leaf's data key was minted under, and so the one it
    /// is retrieved from. Authenticated: a leaf re-pointed at another
    /// keyset fails to open.
    pub fn keyset_id(&self) -> Uuid {
        self.keyset_id
    }

    /// The ZeroKMS IV identifying this leaf's data key.
    pub fn iv(&self) -> &stack_kms::Iv {
        &self.iv
    }

    /// The ZeroKMS key tag.
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// The sealed bytes (`version ‖ nonce ‖ ciphertext ‖ gcm_tag`).
    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext.as_ref()
    }
}

impl Clone for SealedValue {
    fn clone(&self) -> Self {
        Self {
            keyset_id: self.keyset_id,
            iv: self.iv,
            tag: self.tag.clone(),
            ciphertext: LocalCipherText::from(self.ciphertext.as_ref().to_vec()),
        }
    }
}

/// [`SealedValue::from_bytes`] as a std conversion — the same decoder, for
/// callers who prefer the std trait.
impl TryFrom<&[u8]> for SealedValue {
    type Error = LeafBytesError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

/// Deserialisation shadow for [`SealedValue`]: `serde` bypasses
/// [`SealedValue::from_parts`], so the tag-length invariant
/// [`to_bytes`](SealedValue::to_bytes) relies on is re-checked here. Same
/// field names as the derive, so the wire form is unchanged.
#[derive(Deserialize)]
#[serde(rename = "SealedValue")]
struct SealedValueRepr {
    keyset_id: Uuid,
    iv: stack_kms::Iv,
    tag: Vec<u8>,
    ciphertext: LocalCipherText,
}

impl TryFrom<SealedValueRepr> for SealedValue {
    type Error = LeafBytesError;

    fn try_from(repr: SealedValueRepr) -> Result<Self, Self::Error> {
        let SealedValueRepr {
            keyset_id,
            iv,
            tag,
            ciphertext,
        } = repr;
        Self::tag_fits_length_field(&tag)?;
        Ok(Self {
            keyset_id,
            iv,
            tag,
            ciphertext,
        })
    }
}

/// A leaf with its retrieved data key bound alongside. Produced by
/// [`bind_keys`] once the batched `retrieve_keys` call has returned; consumed by
/// [`StackDecipher`], which opens it under whatever AAD the driving
/// [`Decrypt`] impl supplies.
pub(crate) struct KeyedLeaf {
    leaf: SealedValue,
    key: DataKey,
}

/// [`StackCipherText`] with a [`DataKey`] zipped onto every keyed leaf.
pub(crate) type KeyedCipherText = CipherText<KeyedLeaf, BoxedPassthrough>;

/// Zip retrieved keys onto the tree in the same depth-first order the
/// target layer requested them (`retrieve_requests`), so each leaf carries its
/// own key and the subsequent [`Decipher`] drive is free of ordering
/// assumptions.
pub(crate) fn bind_keys(
    ciphertext: StackCipherText,
    keys: &mut impl Iterator<Item = DataKey>,
) -> Result<KeyedCipherText, Unspecified> {
    fn bind(
        leaf: SealedValue,
        keys: &mut impl Iterator<Item = DataKey>,
    ) -> Result<KeyedLeaf, Unspecified> {
        let key = keys.next().ok_or(Unspecified)?;
        Ok(KeyedLeaf { leaf, key })
    }

    match ciphertext {
        CipherText::Single(leaf) => Ok(CipherText::Single(bind(leaf, keys)?)),
        CipherText::None(leaf) => Ok(CipherText::None(bind(leaf, keys)?)),
        CipherText::EmptySequence(leaf) => Ok(CipherText::EmptySequence(bind(leaf, keys)?)),
        CipherText::EmptyMap(leaf) => Ok(CipherText::EmptyMap(bind(leaf, keys)?)),
        CipherText::Sequence(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(bind_keys(item, keys)?);
            }
            Ok(CipherText::Sequence(out))
        }
        CipherText::Map(entries) => {
            let mut out = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                out.push((k, bind_keys(v, keys)?));
            }
            Ok(CipherText::Map(out))
        }
        CipherText::Passthrough(value) => Ok(CipherText::Passthrough(value)),
    }
}

// =============================================================================
// Pending tree (`Cipher::Ok`) — built synchronously, sealed asynchronously
// =============================================================================

/// The intermediate result of driving the [`Cipher`] trait: a tree that holds
/// plaintext (and the AAD each leaf will be sealed against, fully derived) but
/// has done no ZeroKMS I/O. [`seal`](Self::seal) turns it into a
/// [`StackCipherText`].
pub enum PendingStackCipherText {
    /// A scalar awaiting a data key, with its bound (derived) AAD.
    Single {
        plaintext: Protected<Vec<u8>>,
        aad: Aad<'static>,
    },
    /// A pending sequence with at least one element.
    Sequence(Vec<PendingStackCipherText>),
    /// A pending empty-sequence marker; `aad` is already the
    /// [`Aad::for_empty_sequence`] derivation.
    EmptySequence { aad: Aad<'static> },
    /// A pending map with at least one entry.
    Map(Vec<(String, PendingStackCipherText)>),
    /// A pending empty-map marker; `aad` is already the [`Aad::for_empty_map`]
    /// derivation.
    EmptyMap { aad: Aad<'static> },
    /// A pending authenticated-absent marker; `aad` is already the
    /// [`Aad::for_none`] derivation.
    None { aad: Aad<'static> },
    /// A passthrough value (needs no key).
    Passthrough(BoxedPassthrough),
}

impl PendingStackCipherText {
    /// Number of leaves that need a ZeroKMS data key (everything but
    /// passthrough — markers are sealed leaves too).
    pub(crate) fn key_count(&self) -> usize {
        match self {
            PendingStackCipherText::Single { .. }
            | PendingStackCipherText::None { .. }
            | PendingStackCipherText::EmptySequence { .. }
            | PendingStackCipherText::EmptyMap { .. } => 1,
            PendingStackCipherText::Sequence(items) => items.iter().map(Self::key_count).sum(),
            PendingStackCipherText::Map(entries) => {
                entries.iter().map(|(_, v)| v.key_count()).sum()
            }
            PendingStackCipherText::Passthrough(_) => 0,
        }
    }

    /// Generate one data key per keyed leaf (one batched ZeroKMS call — none
    /// for a passthrough-only tree), every key under the [`Descriptor`] of
    /// `aad`, and seal the whole tree.
    ///
    /// `aad` is the context the tree was built under — the value passed to
    /// `encrypt_with_aad`, in the same shape (see the
    /// [descriptor docs](crate::descriptor)). The tree itself only carries
    /// the *derived* per-leaf AADs, so the root is named here; nothing can
    /// check that the two agree, which is why [`KeysetCipher::encrypt`], which
    /// does both steps from one value, is the form to prefer.
    ///
    /// Settles through the target layer's request carrier
    /// ([`seal_pending`](crate::target)), so this and
    /// `encrypt_into_with_context` into a `StackCipherText` share one definition of how a tree
    /// is sealed and one path to ZeroKMS.
    pub async fn seal<'a, K: DataKeySource>(
        self,
        cipher: &KeysetCipher<'_, K>,
        aad: impl IntoAad<'a>,
    ) -> Result<StackCipherText, Error> {
        self.into_pending(cipher, aad).settle().await
    }

    /// Turn this tree into a [`Pending`](crate::target::Pending) request
    /// carrier without settling it.
    ///
    /// [`seal`](Self::seal) is this plus an immediate settle — one ZeroKMS
    /// call per tree. `into_pending` exists for callers that hold *several*
    /// independently built trees (each from its own [`Encrypt`] drive, e.g.
    /// one per record field in a language binding) and want them merged with
    /// [`Pending::zip`](crate::target::Pending::zip) /
    /// [`Pending::all`](crate::target::Pending::all) so the whole assembly
    /// seals in **one** batched `generate_keys` call. Same sealing path
    /// either way.
    ///
    /// **Context contract.** The cipher-directed path deliberately accepts
    /// *any* AAD, including none at all (`()`) — it mirrors
    /// `Aes256Cipher`, where AAD-less sealing is a legitimate AEAD use,
    /// opened symmetrically by [`StackCipher::decrypt`]. But a tree that
    /// will be opened through the target layer's
    /// [`decrypt_into`](crate::target::DecryptInto) — a per-field record
    /// assembly in an FFI front-end, say — is bound by that layer's rule: it
    /// opens only under a [`NonEmpty`](crate::NonEmpty) context, so seal
    /// under one here (a `NonEmpty<T>` is an [`IntoAad`] like any other, and
    /// encodes exactly as `T` does) or the ciphertext can never be read that
    /// way.
    pub fn into_pending<'c, 'a, K>(
        self,
        cipher: &'a KeysetCipher<'_, K>,
        aad: impl IntoAad<'c>,
    ) -> crate::target::Pending<'a, StackCipherText, K> {
        crate::target::seal_pending(cipher, self, Descriptor::of(aad))
    }

    /// Recursively seal under `keyset_id`, drawing one key per leaf from
    /// `keys` in traversal order.
    pub(crate) fn seal_with(
        self,
        keyset_id: Uuid,
        keys: &mut impl Iterator<Item = DataKeyWithTag>,
    ) -> Result<StackCipherText, Unspecified> {
        // Markers seal an *empty* plaintext so the AEAD tag still binds their
        // (already domain-separated) AAD, mirroring `Aes256Cipher`.
        fn seal_marker(
            aad: Aad<'static>,
            keyset_id: Uuid,
            keys: &mut impl Iterator<Item = DataKeyWithTag>,
        ) -> Result<SealedValue, Unspecified> {
            let key = keys.next().ok_or(Unspecified)?;
            seal_leaf(Protected::new(Vec::new()), &aad, keyset_id, key)
        }

        match self {
            PendingStackCipherText::Single { plaintext, aad } => {
                let key = keys.next().ok_or(Unspecified)?;
                Ok(CipherText::Single(seal_leaf(
                    plaintext, &aad, keyset_id, key,
                )?))
            }
            PendingStackCipherText::None { aad } => {
                Ok(CipherText::None(seal_marker(aad, keyset_id, keys)?))
            }
            PendingStackCipherText::EmptySequence { aad } => Ok(CipherText::EmptySequence(
                seal_marker(aad, keyset_id, keys)?,
            )),
            PendingStackCipherText::EmptyMap { aad } => {
                Ok(CipherText::EmptyMap(seal_marker(aad, keyset_id, keys)?))
            }
            PendingStackCipherText::Sequence(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(item.seal_with(keyset_id, keys)?);
                }
                Ok(CipherText::Sequence(out))
            }
            PendingStackCipherText::Map(entries) => {
                let mut out = Vec::with_capacity(entries.len());
                for (k, v) in entries {
                    out.push((k, v.seal_with(keyset_id, keys)?));
                }
                Ok(CipherText::Map(out))
            }
            PendingStackCipherText::Passthrough(value) => Ok(CipherText::Passthrough(value)),
        }
    }
}

// =============================================================================
// Leaf crypto
// =============================================================================

/// Build the per-leaf vitaminc cipher from a ZeroKMS data key.
///
/// Each leaf has its own data key, so each leaf gets its own
/// [`Aes256Cipher`] (and with it a fresh random nonce — the ZeroKMS IV is a
/// key identifier only, never reused as a nonce).
fn leaf_cipher(key: &DataKey) -> Result<Aes256Cipher, Unspecified> {
    // `Key::from` moves the 32 bytes straight into a `Protected`; the source
    // `DataKey` is wiped on its own drop.
    Aes256Cipher::new(&AesKey::from(*key.key()))
}

/// Derives the effective AAD every leaf is sealed against — and opened
/// under — binding the caller's derived AAD, the ZeroKMS key `tag`, the
/// keyset the key was minted under, and the [`SealedValue::FORMAT_VERSION`]
/// byte that prefixes the leaf's frozen byte encoding.
///
/// The labelled five-piece PAE can never collide with a caller's own
/// composite AAD (a tuple encodes with no leading domain label) or with
/// vitaminc's internal derivations (different labels). Binding the format
/// version and the keyset id under the tag is what makes those bytes in
/// [`SealedValue::to_bytes`] more than parse hints: bytes relabelled with a
/// different version fail verification instead of selecting different
/// parsing and derivation rules — mirroring vitaminc's `Aad::for_leaf`,
/// which binds the *inner* [`LocalCipherText`] wire version the same way —
/// and a leaf re-pointed at another keyset fails verification instead of
/// asking that keyset for a key it never minted.
///
/// The domain label deliberately carries no `/v1` suffix: the version is a
/// *parameter* here, not part of the label.
///
/// # Breaking change
///
/// This derivation has changed twice while the crate is `publish = false`
/// (an unlabelled `PAE(aad, tag)` tuple; then a four-piece labelled form
/// without the keyset id), each time without a version bump, because only
/// dev-persisted data existed. A leaf sealed under an earlier form fails
/// authentication in `open_leaf` with a plain AEAD error, indistinguishable
/// from tampering; re-encrypt anything that matters.
fn leaf_aad(aad: &Aad<'_>, keyset_id: Uuid, tag: &[u8]) -> Aad<'static> {
    const LEAF_AAD_DOMAIN: &[u8] = b"stack-encrypt/leaf";
    Aad::pae(&[
        LEAF_AAD_DOMAIN,
        &[SealedValue::FORMAT_VERSION],
        keyset_id.as_bytes(),
        aad.as_bytes(),
        tag,
    ])
}

/// Seal one plaintext leaf under a freshly generated data key.
///
/// The AAD is the [`leaf_aad`] derivation of the caller's (derived) AAD, the
/// keyset the key was minted under, and the key `tag` — `tag` is always
/// bound, so the leaf is cryptographically tied to its ZeroKMS data key.
fn seal_leaf(
    plaintext: Protected<Vec<u8>>,
    aad: &Aad<'_>,
    keyset_id: Uuid,
    key: DataKeyWithTag,
) -> Result<SealedValue, Unspecified> {
    // The `DataKeySource` is caller-supplied, so the key tag is not trusted
    // to fit the frozen byte format's `u16` length field: an oversized tag
    // must fail here — the last construction site — or `to_bytes` would emit
    // a length field that no longer frames the tag and `from_bytes` would
    // stop inverting it.
    SealedValue::tag_fits_length_field(&key.tag).map_err(|_| Unspecified)?;
    let iv = key.key.iv;
    let cipher = leaf_cipher(&key.key)?;
    match (&cipher).encrypt_bytes_vec(plaintext, leaf_aad(aad, keyset_id, &key.tag))? {
        AesCipherText::Single(ciphertext) => Ok(SealedValue {
            keyset_id,
            iv,
            tag: key.tag,
            ciphertext,
        }),
        _ => Err(Unspecified),
    }
}

/// Open one keyed leaf under `aad`, returning the plaintext bytes.
fn open_leaf(keyed: KeyedLeaf, aad: &Aad<'_>) -> Result<Protected<Vec<u8>>, Unspecified> {
    /// Keeps the recovered bytes inside `Protected` across the visitor
    /// boundary (the blanket `Decrypt for Vec<u8>` would unwrap them).
    struct ProtectedBytes;
    impl<'c> DecipherVisitor<'c> for ProtectedBytes {
        type Value = Protected<Vec<u8>>;
        fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<Self::Value, Unspecified> {
            Ok(data)
        }
    }

    let KeyedLeaf { leaf, key } = keyed;
    let cipher = leaf_cipher(&key)?;
    cipher
        .decipher(AesCipherText::Single(leaf.ciphertext))
        .decrypt_bytes(ProtectedBytes, leaf_aad(aad, leaf.keyset_id, &leaf.tag))
}

/// Open one marker leaf (absent / empty-sequence / empty-map) and require the
/// sealed plaintext to be empty. Without the emptiness check, a `Single` leaf
/// could be re-tagged as a marker of the same AAD derivation.
fn verify_empty_marker(keyed: KeyedLeaf, aad: &Aad<'_>) -> Result<(), Unspecified> {
    let plaintext = open_leaf(keyed, aad)?;
    if plaintext.risky_ref().is_empty() {
        Ok(())
    } else {
        Err(Unspecified)
    }
}

// =============================================================================
// Encrypt side: `Cipher` impl over a `&KeysetCipher` (builds the pending tree)
// =============================================================================

impl<'c, 'k, K> Cipher for &'c KeysetCipher<'k, K> {
    type Ok = PendingStackCipherText;
    type Error = Unspecified;
    type Passthrough = BoxedPassthrough;
    type SeqCipher = PendingSeqCipher<'c, 'k, K>;
    type MapCipher = PendingMapCipher<'c, 'k, K>;

    fn encrypt_bytes_vec<'a, A>(
        self,
        data: Protected<Vec<u8>>,
        aad: A,
    ) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        Ok(PendingStackCipherText::Single {
            plaintext: data,
            aad: aad.into_aad().into_owned(),
        })
    }

    fn encrypt_seq<'a, A>(self, size_hint: Option<usize>, aad: A) -> Self::SeqCipher
    where
        A: IntoAad<'a>,
    {
        let aad = aad.into_aad().into_owned();
        PendingSeqCipher {
            cipher: self,
            items: Vec::with_capacity(size_hint.unwrap_or(0)),
            // Both derived once here, then borrowed per element.
            element_aad: aad.for_sequence_element(),
            aad,
            encrypted: false,
        }
    }

    fn encrypt_map<'a, A>(self, aad: A) -> Self::MapCipher
    where
        A: IntoAad<'a>,
    {
        PendingMapCipher {
            cipher: self,
            entries: Vec::new(),
            seen_keys: HashSet::new(),
            current_key: None,
            aad: aad.into_aad().into_owned(),
            encrypted: false,
        }
    }

    fn encrypt_none<'a, A>(self, aad: A) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        // Domain-separated so a `Single` leaf sealed under the bare AAD can
        // never be re-tagged as an authenticated absence (and vice versa).
        Ok(PendingStackCipherText::None {
            aad: aad.into_aad().for_none(),
        })
    }

    fn passthrough(self, value: Self::Passthrough) -> Result<Self::Ok, Self::Error> {
        Ok(PendingStackCipherText::Passthrough(value))
    }

    fn passthrough_boxed(
        self,
        value: Box<dyn Any + Send + 'static>,
    ) -> Result<Self::Ok, Self::Error> {
        // This cipher's passthrough type *is* `Box<dyn Any + Send>`, so the
        // type-erased box is already the passthrough payload.
        self.passthrough(value)
    }
}

/// [`SeqCipher`] driver: accumulates a pending sub-tree per element. Holds the
/// cipher only to re-drive nested [`Encrypt`] values (no I/O happens here).
pub struct PendingSeqCipher<'c, 'k, K> {
    cipher: &'c KeysetCipher<'k, K>,
    items: Vec<PendingStackCipherText>,
    /// The AAD fixed at [`Cipher::encrypt_seq`]; the empty marker is sealed
    /// against its `for_empty_sequence` derivation.
    aad: Aad<'static>,
    /// [`Aad::for_sequence_element`] of `aad`, derived once and applied to
    /// every element.
    element_aad: Aad<'static>,
    /// Whether at least one element went through the authenticated
    /// [`encrypt_next`](SeqCipher::encrypt_next) path *and* produced a sealed
    /// node — see [`end`](SeqCipher::end).
    encrypted: bool,
}

impl<K> SeqCipher for PendingSeqCipher<'_, '_, K> {
    type Ok = PendingStackCipherText;
    type Error = Unspecified;
    type Passthrough = BoxedPassthrough;

    fn encrypt_next<T>(mut self, data: T) -> Result<Self, Self::Error>
    where
        T: Encrypt,
    {
        // Borrow the stored derived AAD — no allocation per element.
        let pending =
            data.encrypt_with_aad(self.cipher, Aad::from_slice(self.element_aad.as_bytes()))?;
        // A nested `Encrypt` impl may route through the passthrough channel;
        // only a genuinely pending-sealed node may satisfy `end`'s
        // all-passthrough rejection.
        self.encrypted |= !matches!(pending, PendingStackCipherText::Passthrough(_));
        self.items.push(pending);
        Ok(self)
    }

    fn passthrough_next(mut self, value: Self::Passthrough) -> Result<Self, Self::Error> {
        self.items.push(PendingStackCipherText::Passthrough(value));
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        if self.items.is_empty() {
            Ok(PendingStackCipherText::EmptySequence {
                aad: self.aad.for_empty_sequence(),
            })
        } else if !self.encrypted {
            // Every item is a passthrough: nothing in the container would
            // authenticate the AAD, so refuse to produce it — mirroring
            // `decrypt_tree`'s rejection on open.
            Err(Unspecified)
        } else {
            Ok(PendingStackCipherText::Sequence(self.items))
        }
    }
}

/// [`MapCipher`] driver: keys are stored in the clear; values become pending
/// sub-trees sealed against [`Aad::for_map_entry`] of the map AAD and their
/// key. Mirrors `AesMapCipher`'s key/value and duplicate-key contract checks.
pub struct PendingMapCipher<'c, 'k, K> {
    cipher: &'c KeysetCipher<'k, K>,
    entries: Vec<(String, PendingStackCipherText)>,
    /// Duplicate keys are rejected at encrypt time: `decrypt_tree` rejects
    /// them outright, so accepting one here would produce a permanently
    /// unreadable ciphertext.
    seen_keys: HashSet<String>,
    current_key: Option<Cow<'static, str>>,
    /// The AAD fixed at [`Cipher::encrypt_map`].
    aad: Aad<'static>,
    /// See [`PendingSeqCipher::encrypted`].
    encrypted: bool,
}

impl<K> MapCipher for PendingMapCipher<'_, '_, K> {
    type Ok = PendingStackCipherText;
    type Error = Unspecified;
    type Passthrough = BoxedPassthrough;

    fn encrypt_key<S>(mut self, key: S) -> Result<Self, Self::Error>
    where
        S: Into<Cow<'static, str>>,
    {
        // A pending key means `encrypt_key` ran twice with no intervening
        // `encrypt_value` — fail rather than silently drop the first key.
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
        let key = key.into();
        if !self.seen_keys.insert(key.as_ref().to_owned()) {
            return Err(Unspecified);
        }
        self.current_key = Some(key);
        Ok(self)
    }

    fn encrypt_value<U>(mut self, value: U) -> Result<Self, Self::Error>
    where
        U: Encrypt,
    {
        let key = self.current_key.take().ok_or(Unspecified)?;
        // Seal against PAE(domain, aad, key) — key and value are inseparable.
        // `decrypt_tree` derives the same AAD on open.
        let entry_aad = self.aad.for_map_entry(&key);
        let pending = value.encrypt_with_aad(self.cipher, entry_aad)?;
        self.encrypted |= !matches!(pending, PendingStackCipherText::Passthrough(_));
        self.entries.push((key.into_owned(), pending));
        Ok(self)
    }

    fn passthrough_entry<S>(mut self, key: S, value: Self::Passthrough) -> Result<Self, Self::Error>
    where
        S: Into<Cow<'static, str>>,
    {
        // Adopting a pending key here would silently drop it — same contract
        // violation `encrypt_key` rejects.
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
        let key = key.into();
        if !self.seen_keys.insert(key.as_ref().to_owned()) {
            return Err(Unspecified);
        }
        self.entries
            .push((key.into_owned(), PendingStackCipherText::Passthrough(value)));
        Ok(self)
    }

    fn passthrough_entry_boxed<S>(
        self,
        key: S,
        value: Box<dyn Any + Send + 'static>,
    ) -> Result<Self, Self::Error>
    where
        S: Into<Cow<'static, str>>,
    {
        // This cipher's passthrough type *is* `Box<dyn Any + Send>`, so the
        // type-erased box is already the payload — same as `passthrough_boxed`.
        self.passthrough_entry(key, value)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        // Finalising with a pending key would silently drop the entry.
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
        if self.entries.is_empty() {
            Ok(PendingStackCipherText::EmptyMap {
                aad: self.aad.for_empty_map(),
            })
        } else if !self.encrypted {
            // Every entry is a passthrough — see `PendingSeqCipher::end`.
            Err(Unspecified)
        } else {
            Ok(PendingStackCipherText::Map(self.entries))
        }
    }
}

// Decrypt side: a synchronous `Decipher` over a key-bound ciphertext tree
// =============================================================================

/// A [`Decipher`] over a single [`StackCipherText`] whose leaves already
/// carry their retrieved data keys, built inside
/// [`StackCipher::decrypt`] and driven there by the value's [`Decrypt`]
/// impl under the same context the keys were retrieved with.
///
/// Structurally identical to `vitaminc_encrypt::AesDecipher` — the only
/// difference is where each leaf's key comes from. The AAD is supplied per call
/// by [`Decrypt::decrypt_with_aad`] and refined here exactly as the encrypt side
/// refined it: sequence elements under [`Aad::for_sequence_element`], map
/// values under [`Aad::for_map_entry`] of their key, markers under their
/// respective derivations with an enforced-empty plaintext. Because the
/// derivation lives in this drive (not in a pre-pass), `Decrypt` impls that
/// transform the AAD themselves (e.g. `vitaminc_aead::Element`) work unchanged.
pub struct StackDecipher {
    ciphertext: KeyedCipherText,
}

impl StackDecipher {
    pub(crate) fn over(ciphertext: KeyedCipherText) -> Self {
        Self { ciphertext }
    }

    /// Typed convenience over [`Decipher::decrypt_passthrough`] for this
    /// cipher's [`BoxedPassthrough`] payload type: recovers the payload and
    /// downcasts it to `T`, returning [`Unspecified`] if the ciphertext is not
    /// a passthrough or the stored type does not match.
    pub fn decrypt_passthrough_as<T>(self) -> Result<T, Unspecified>
    where
        T: Any + Send + 'static,
    {
        self.decrypt_passthrough()?
            .downcast::<T>()
            .map(|b| *b)
            .map_err(|_| Unspecified)
    }
}

impl<'c> Decipher<'c> for StackDecipher {
    type Ok<T>
        = Result<T, Unspecified>
    where
        T: Send + 'c;

    type Passthrough = BoxedPassthrough;

    fn map_ok<T, U, F>(ok: Self::Ok<T>, f: F) -> Self::Ok<U>
    where
        T: Send + 'c,
        U: Send + 'c,
        F: FnOnce(T) -> U,
    {
        ok.map(f)
    }

    fn decrypt_bytes<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        match self.ciphertext {
            CipherText::Single(keyed) => {
                let bytes = open_leaf(keyed, &aad.into_aad())?;
                visitor.visit_bytes_vec(bytes)
            }
            _ => Err(Unspecified),
        }
    }

    fn decrypt_seq<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        match self.ciphertext {
            // At least one non-passthrough item required: passthrough items
            // authenticate nothing, so an all-passthrough (or entry-less)
            // sequence would verify under any AAD. The encrypt side refuses to
            // produce one; refuse to open one. Emptiness is only provable by
            // the authenticated `EmptySequence` marker.
            CipherText::Sequence(items)
                if items
                    .iter()
                    .any(|i| !matches!(i, CipherText::Passthrough(_))) =>
            {
                visitor.visit_seq(StackSeqAccess {
                    items: items.into_iter(),
                    element_aad: aad.into_aad().for_sequence_element(),
                })
            }
            CipherText::EmptySequence(keyed) => {
                let aad = aad.into_aad();
                verify_empty_marker(keyed, &aad.for_empty_sequence())?;
                // Store the element derivation exactly as the non-empty arm
                // does: never read (the iterator is empty), but a divergent
                // value here would silently break a visitor that consulted it.
                visitor.visit_seq(StackSeqAccess {
                    items: Vec::new().into_iter(),
                    element_aad: aad.for_sequence_element(),
                })
            }
            _ => Err(Unspecified),
        }
    }

    fn decrypt_map<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        match self.ciphertext {
            // At least one non-passthrough entry required — see `decrypt_seq`.
            CipherText::Map(entries)
                if entries
                    .iter()
                    .any(|(_, v)| !matches!(v, CipherText::Passthrough(_))) =>
            {
                // Reject duplicate keys before the visitor sees any entry: two
                // ciphertexts of the same logical record seal a given key's
                // value against the identical `for_map_entry` AAD, so a stale
                // entry appended to a current ciphertext *verifies* — with a
                // last-wins visitor that is a single-field rollback.
                let mut seen = HashSet::with_capacity(entries.len());
                if !entries.iter().all(|(key, _)| seen.insert(key.as_str())) {
                    return Err(Unspecified);
                }
                visitor.visit_map(StackMapAccess {
                    entries: entries.into_iter(),
                    aad: aad.into_aad(),
                    pending: None,
                })
            }
            CipherText::EmptyMap(keyed) => {
                let aad = aad.into_aad();
                verify_empty_marker(keyed, &aad.for_empty_map())?;
                // Raw caller AAD, not the marker derivation — see `decrypt_seq`.
                visitor.visit_map(StackMapAccess {
                    entries: Vec::new().into_iter(),
                    aad,
                    pending: None,
                })
            }
            _ => Err(Unspecified),
        }
    }

    fn decrypt_any<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        match self.ciphertext {
            ct @ CipherText::Single(_) => Self::over(ct).decrypt_bytes(visitor, aad),
            ct @ (CipherText::Sequence(_) | CipherText::EmptySequence(_)) => {
                Self::over(ct).decrypt_seq(visitor, aad)
            }
            ct @ (CipherText::Map(_) | CipherText::EmptyMap(_)) => {
                Self::over(ct).decrypt_map(visitor, aad)
            }
            CipherText::None(keyed) => {
                // Verify the domain-separated marker (tag AND empty plaintext)
                // before reporting absence — an unauthenticated `visit_none`
                // would let an attacker forge "absent" values, and a bare-AAD
                // check would let a `Single` leaf be re-tagged as one. Mirrors
                // `decrypt_option`.
                verify_empty_marker(keyed, &aad.into_aad().for_none())?;
                visitor.visit_none()
            }
            // A self-describing visitor recovers a passthrough via
            // `visit_passthrough` (type-erased); visitors that do not override
            // it inherit the default rejection.
            CipherText::Passthrough(boxed) => visitor.visit_passthrough(boxed),
        }
    }

    fn decrypt_passthrough(self) -> Self::Ok<Self::Passthrough> {
        match self.ciphertext {
            CipherText::Passthrough(boxed) => Ok(boxed),
            _ => Err(Unspecified),
        }
    }

    fn decrypt_option<'a, T, A>(self, aad: A) -> Self::Ok<Option<T>>
    where
        T: Decrypt<'c> + 'c,
        A: IntoAad<'a>,
    {
        match self.ciphertext {
            CipherText::None(keyed) => {
                // Verify the tag over the domain-separated marker AAD AND that
                // the sealed plaintext is actually empty. Without both, a
                // `Single(leaf)` sealed under the same caller AAD could be
                // re-tagged as `None(leaf)` and decrypt as Ok(None) — silent
                // authenticated data deletion.
                verify_empty_marker(keyed, &aad.into_aad().for_none())?;
                Ok(None)
            }
            // Passthrough must never be decoded as an Option payload.
            CipherText::Passthrough(_) => Err(Unspecified),
            // Any other variant is the `Some` payload: recurse into `T` with
            // the caller's AAD unchanged (there is no depth tag; the shape of
            // nested options is decided by `T` at the call site, as in
            // `AesDecipher`).
            other => T::decrypt_with_aad(Self::over(other), aad).map(Some),
        }
    }
}

struct StackSeqAccess {
    items: std::vec::IntoIter<KeyedCipherText>,
    /// [`Aad::for_sequence_element`] of the caller's AAD, derived once at
    /// construction and re-supplied per element by borrowing. Mirrors
    /// `PendingSeqCipher::element_aad` on the encrypt side.
    element_aad: Aad<'static>,
}

impl<'c> SeqAccess<'c> for StackSeqAccess {
    type Error = Unspecified;

    fn next_element<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<T>, Self::Error> {
        match self.items.next() {
            Some(ct) => {
                T::decrypt_with_aad(StackDecipher::over(ct), self.element_aad.as_bytes()).map(Some)
            }
            None => Ok(None),
        }
    }
}

struct StackMapAccess<'a> {
    entries: std::vec::IntoIter<(String, KeyedCipherText)>,
    aad: Aad<'a>,
    /// The entry handed out by `next_key` and not yet consumed by
    /// `next_value` / `next_passthrough`. Held as ciphertext rather than
    /// decrypted up front so the caller can choose the plaintext type after
    /// seeing the key — see [`MapAccess::next_key`] — alongside the entry
    /// AAD it was sealed under, derived once here so the key itself moves
    /// out to the caller.
    pending: Option<(Aad<'static>, KeyedCipherText)>,
}

impl<'c, 'a> MapAccess<'c> for StackMapAccess<'a> {
    type Error = Unspecified;

    fn next_key(&mut self) -> Result<Option<String>, Self::Error> {
        // A still-pending entry means the caller skipped a value. Refused
        // rather than tolerated: an entry whose value is never opened is an
        // entry whose AAD binding is never verified.
        if self.pending.is_some() {
            return Err(Unspecified);
        }
        match self.entries.next() {
            Some((key, ct)) => {
                // Mirror `PendingMapCipher::encrypt_value`: the value was
                // sealed against `for_map_entry(key)`, so a swapped or
                // renamed key fails when the entry is opened.
                self.pending = Some((self.aad.for_map_entry(&key), ct));
                Ok(Some(key))
            }
            None => Ok(None),
        }
    }

    fn next_value<T: Decrypt<'c> + 'c>(&mut self) -> Result<T, Self::Error> {
        let (entry_aad, ct) = self.pending.take().ok_or(Unspecified)?;
        T::decrypt_with_aad(StackDecipher::over(ct), entry_aad)
    }

    fn next_passthrough(&mut self) -> Result<Box<dyn Any + Send + 'static>, Self::Error> {
        match self.pending.take() {
            Some((_key, CipherText::Passthrough(value))) => Ok(value),
            // A sealed value under a key the caller asked to read as a
            // passthrough: refuse rather than hand it back with its tag
            // unchecked — but keep the entry pending. The refusal is the
            // caller's answer, not a reason to lose the entry: it can still
            // open it with `next_value`, and until it does `next_key` keeps
            // refusing to move past it.
            Some(entry) => {
                self.pending = Some(entry);
                Err(Unspecified)
            }
            None => Err(Unspecified),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_access(entries: Vec<(&str, KeyedCipherText)>) -> StackMapAccess<'static> {
        StackMapAccess {
            entries: entries
                .into_iter()
                .map(|(key, ct)| (key.to_string(), ct))
                .collect::<Vec<_>>()
                .into_iter(),
            aad: Aad::from_slice(b"map"),
            pending: None,
        }
    }

    #[test]
    fn a_passthrough_entry_is_read_back_as_the_boxed_value() {
        let mut map = map_access(vec![("plain", CipherText::Passthrough(Box::new(7u32)))]);

        assert_eq!(map.next_key(), Ok(Some("plain".to_string())));
        let value = map.next_passthrough().expect("passthrough entry");
        assert_eq!(value.downcast_ref::<u32>(), Some(&7));
        assert_eq!(map.next_key(), Ok(None));
    }

    /// Asking for a sealed entry as a passthrough is refused, and the entry
    /// stays pending: it is neither handed back unverified nor lost, so the
    /// caller can still open it with `next_value` and cannot skip it.
    #[test]
    fn a_sealed_entry_survives_being_misread_as_a_passthrough() {
        let mut map = map_access(vec![
            ("sealed", CipherText::Sequence(vec![])),
            ("plain", CipherText::Passthrough(Box::new(7u32))),
        ]);

        assert_eq!(map.next_key(), Ok(Some("sealed".to_string())));
        assert!(map.next_passthrough().is_err());
        // Still pending: the map refuses to advance past an unopened entry.
        assert_eq!(map.next_key(), Err(Unspecified));
        // And the refusal is repeatable, not a one-shot that then drops it.
        assert!(map.next_passthrough().is_err());
        assert_eq!(map.next_key(), Err(Unspecified));
    }

    /// A draw with nothing pending — before any `next_key`, or after the
    /// entry has already been taken — is a clean refusal, never a value and
    /// never a panic. This is the guard that keeps an absent or unverified
    /// value from being handed back, so a refactor from `ok_or(..)?` to an
    /// `unwrap` would regress silently without it.
    #[test]
    fn drawing_a_value_with_nothing_pending_is_refused() {
        let mut map = map_access(vec![("plain", CipherText::Passthrough(Box::new(7u32)))]);

        // No `next_key` yet: nothing is pending.
        assert!(map.next_value::<String>().is_err());
        assert!(map.next_passthrough().is_err());

        // A legitimate draw consumes the entry, so a second draw of either
        // kind is refused too.
        assert_eq!(map.next_key(), Ok(Some("plain".to_string())));
        assert!(map.next_passthrough().is_ok());
        assert!(map.next_passthrough().is_err());
        assert!(map.next_value::<String>().is_err());
        assert_eq!(map.next_key(), Ok(None));
    }

    /// Byte-level pin for the [`leaf_aad`] derivation. This is part of the
    /// frozen leaf format: a change to the domain label, the version byte,
    /// the keyset id's place, the piece order, or the PAE framing makes
    /// every stored leaf fail authentication, so it must be deliberate —
    /// and, once anything is stored, must come with a
    /// [`SealedValue::FORMAT_VERSION`] bump, which this pin forces into view.
    #[test]
    fn leaf_aad_bytes_are_pinned() {
        let keyset = Uuid::from_bytes(*b"keyset-fixture16");
        let aad = leaf_aad(&Aad::from_slice(b"caller-aad"), keyset, b"key-tag");
        let hex: String = aad.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        // PAE: LE64 count (5) ‖ per piece LE64 length ‖ piece, the pieces
        // being "stack-encrypt/leaf", [FORMAT_VERSION], the keyset id's 16
        // bytes, the caller AAD, and the key tag.
        assert_eq!(
            hex,
            "05000000000000001200000000000000737461636b2d656e63727970742f6c65616601000000000000000110000000000000006b65797365742d6669787475726531360a0000000000000063616c6c65722d61616407000000000000006b65792d746167"
        );
    }
}
