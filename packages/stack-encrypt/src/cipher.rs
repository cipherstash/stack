//! Implementation of [`StackCipher`]. For usage, start at the crate docs; this
//! module documents the internals.
//!
//! `StackCipher` is scoped to one ZeroKMS client; a [`KeysetCipher`] — the
//! cipher bound to one of that client's keysets — seals values whose
//! per-leaf keys are ZeroKMS data keys, minted under that keyset, rather
//! than one fixed key. The value side is vitaminc's: a value describes
//! itself once ([`Encrypt`]), vitaminc plans it into a tree of pending
//! leaves, each with its tagged plaintext and the AAD its place derives,
//! and a bytes-only [`Cipher`] seals and opens one leaf at a time. The
//! result is a ciphertext tree ([`StackCipherText`], the analog of
//! `AesCipherText`) whose leaves ([`SealedValue`]) each carry the ZeroKMS
//! metadata for their own data key — the keyset it was minted under
//! included, which is why decrypting needs no keyset named and lives on the
//! client-scoped `StackCipher`.
//!
//! ## Batching the key fetch
//!
//! Data-key generation/retrieval is an async ZeroKMS round-trip, and each
//! leaf needs its own key, so the keys are fetched for the whole tree
//! before any leaf is sealed or opened. The AES work stays in vitaminc's
//! synchronous walk:
//!
//! * **Encrypt** — [`PendingStackCipherText::plan`] walks the value into
//!   vitaminc's pending tree and does no I/O. A single
//!   [`PendingStackCipherText::seal`] (or the [`KeysetCipher::encrypt`]
//!   convenience) then batches **one** `generate_keys` call for the whole
//!   tree, under the handle's keyset, and seals every leaf through
//!   `MintedKeys`, the sealing half of this crate's [`Cipher`], one key per
//!   leaf in walk order.
//! * **Decrypt** — [`StackCipher::decrypt`] batches **one** `retrieve_keys`
//!   call per keyset the leaves were sealed under and zips each key onto
//!   its leaf. vitaminc's [`decrypt`](vitaminc_aead::decrypt) then opens
//!   every leaf through `BoundKeys`, the opening half, and walks the opened
//!   tree into the value's [`Decrypt`] sink.
//!
//! Neither half is vitaminc's `AsyncCipher`. Its `seal_many` batches the
//! leaves of one document, but a ZeroKMS request names the descriptor of
//! the context the whole tree is sealed under, which a leaf's derived AAD
//! does not carry, and the target layer merges the key requests of many
//! documents (the fields of a record, the rows of a column) into one call
//! (RFC 0002). So the fetch is the target layer's
//! [`Pending`](crate::target::Pending), and the cipher vitaminc drives is
//! the synchronous one.
//!
//! ## AAD derivation
//!
//! vitaminc derives each leaf's AAD from the caller's, on both sides, with
//! the same domain-separated derivations every vitaminc cipher gets, so the
//! container *shape* is authenticated:
//!
//! * sequence elements are sealed under [`Context::for_sequence_element`];
//! * map values under [`Context::for_map_entry`] of their cleartext key (so
//!   swapping or renaming keys fails decryption);
//! * empty sequences/maps under [`Context::for_empty_sequence`] /
//!   [`Context::for_empty_map`], each sealing an *empty* plaintext,
//!   verified as empty on open. An absent value (`None`) is a null leaf like
//!   any other scalar.
//!
//! This crate binds its own envelope on top of that, per leaf (below).
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

use std::cell::RefCell;
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
use vitaminc_aead::seal::seal_all;
use vitaminc_aead::{
    Cipher, CipherText, Context, Decrypt, Encrypt, IntoAad, IntoContext, LocalCipherText, Node,
    Pending, Unspecified,
};
use vitaminc_encrypt::{Aes256Cipher, Key as AesKey};
use vitaminc_protected::Protected;

use crate::keyset::{KeysetCache, KeysetCipher, KeysetState, Lookup, DEFAULT_NAME_TTL};
use crate::Descriptor;

/// The recursive ciphertext container produced by [`StackCipher`]: vitaminc's
/// ciphertext tree ([`Node`]) over [`SealedValue`] leaves. Its shape
/// mirrors the encrypted plaintext: a scalar, `None` included, yields
/// `Single`, a `Vec` yields `Sequence` (or `EmptySequence`), a `HashMap` or
/// struct yields `Map` (or `EmptyMap`). Map keys are stored in the clear but
/// bound into their value's AAD. A passthrough subtree travels in the clear
/// as a [`PassthroughFrame`](vitaminc_aead::PassthroughFrame): the subtree's
/// frame bytes.
pub type StackCipherText = Node<SealedValue>;

/// Errors from sealing or opening a [`StackCipherText`].
///
/// Every variant has a `stack_encrypt::` miette code, or forwards the code
/// of the error it carries ([`Kms`](Self::Kms), [`Term`](Self::Term),
/// [`Plan`](Self::Plan)); its structured fields are its
/// [`ErrorPayload`](crate::ErrorPayload). No message carries a context's
/// descriptor or another library's text (see the rule on
/// [`ErrorPayload`](crate::ErrorPayload)).
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum Error {
    /// A ZeroKMS data-key or keyset operation failed. Transparent: the
    /// message, code and help are the [`stack_kms::Error`]'s, so a caller
    /// across a binding sees `stack_kms::keyset_not_found` itself.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Kms(#[from] stack_kms::Error),
    /// AEAD sealing/opening failed, or the ciphertext shape did not match the
    /// requested type. On decrypt this is the expected outcome for a wrong key,
    /// wrong AAD, or tampered ciphertext.
    #[error("AEAD operation failed (wrong key, AAD mismatch, or malformed ciphertext)")]
    #[diagnostic(
        code(stack_encrypt::aead),
        help("Open the value under the context it was sealed with. If the context is right, the ciphertext is damaged or was altered.")
    )]
    Aead,
    /// ZeroKMS returned a different number of keys than were requested.
    #[error("expected {expected} data keys from ZeroKMS but received {received}")]
    #[diagnostic(code(stack_encrypt::key_count_mismatch))]
    KeyCountMismatch { expected: usize, received: usize },
    /// A context rendered to a descriptor longer than ZeroKMS can bind
    /// ([`Descriptor::MAX_LEN`]). Raised before any request is sent, so no
    /// key is minted or retrieved for the batch.
    #[error(
        "context renders to a {len}-byte ZeroKMS descriptor; the limit is {} bytes",
        Descriptor::MAX_LEN
    )]
    #[diagnostic(
        code(stack_encrypt::descriptor_too_long),
        help(
            "ZeroKMS binds a descriptor of at most {} bytes. Shorten the context: fewer parts, shorter labels, or an id in place of a long name.",
            Descriptor::MAX_LEN
        )
    )]
    DescriptorTooLong { len: usize },
    /// Building a ZeroKMS client from the environment failed: credentials or
    /// client key missing or malformed.
    ///
    /// Boxed rather than naming `stack_encrypt::kms::StackKmsBuilderError` directly:
    /// that type only exists with `http`, and a variant whose presence tracks
    /// a feature is not additive — feature unification elsewhere in the graph
    /// would then change this enum's shape under a downstream match.
    ///
    /// The box holds whatever built it: this crate fills it with
    /// `StackKmsBuilderError`, whose message obeys the rule on
    /// [`ErrorPayload`](crate::ErrorPayload), and so may be shown here.
    ///
    /// Its payload is the builder error's (the variable at fault, say). Its
    /// code stays this one; the builder error's own is on the source.
    #[error("could not build a ZeroKMS client from the environment: {0}")]
    #[diagnostic(
        code(stack_encrypt::config),
        help("The message says which setting failed. Check `CS_WORKSPACE_CRN`, `CS_CLIENT_ID`, `CS_CLIENT_KEY`, `CS_CLIENT_ACCESS_KEY` and `CS_ZEROKMS_HOST`, or log in with `stash auth login`.")
    )]
    Config(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// An index term failed to derive.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Term(#[from] crate::sem::TermError),
    /// A third-party [`EncryptFrom`](crate::target::EncryptFrom) /
    /// [`DecryptInto`](crate::target::DecryptInto) implementation failed
    /// for a reason of its own.
    ///
    /// Its message is the implementation's, shown as given: an
    /// implementation that fills this slot writes its message under the
    /// rule on [`ErrorPayload`](crate::ErrorPayload), naming what it refused
    /// and never a byte of the value or the ciphertext.
    #[error(transparent)]
    #[diagnostic(code(stack_encrypt::other))]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// A [`transcode::Visitor`](crate::target::transcode::Visitor) was handed
    /// an encrypted output shape its destination does not accept: a scalar
    /// destination offered a sequence, say. Raised by the visitor's default
    /// methods, so a destination only has to describe the shapes it stores.
    /// Never a data error: the output was produced correctly, the
    /// destination just has nowhere to put it.
    #[error("destination does not support this encrypted output shape")]
    #[diagnostic(code(stack_encrypt::unsupported_shape))]
    UnsupportedShape,
    /// A record carrying its context in storage (`#[stash(context_field)]`)
    /// was opened with an [`ExpectedContext`](crate::target::ExpectedContext)
    /// naming a different one. Refused before any key is retrieved.
    ///
    /// `stored` is the stored context's descriptor, rendered as ZeroKMS
    /// would log it, for a caller in this process. The message gives only
    /// its length and number of parts: a stored context can be built from
    /// a record field, so its descriptor can be customer data.
    #[error(
        "stored context ({} bytes in {} parts) does not match the expected context",
        stored.len(),
        descriptor_parts(stored)
    )]
    #[diagnostic(
        code(stack_encrypt::context_mismatch),
        help("The record was stored under another context than the one it is opened with. Open it with the context it was stored under.")
    )]
    ContextMismatch { stored: Descriptor },
    /// A [`Pending`](crate::target::Pending) fulfilment's requests and
    /// responses did not line up: it drew more responses — or a different
    /// kind — than its requests asked for, or left some of them unconsumed.
    /// Always a composition bug in an `EncryptFrom`/`DecryptInto`
    /// implementation, never a data error.
    #[error("a pending fulfilment's responses did not match its requests")]
    #[diagnostic(code(stack_encrypt::response_shape))]
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
    #[diagnostic(
        code(stack_encrypt::keyset_mismatch),
        help("Build every part of one record or batch through the same keyset.")
    )]
    KeysetMismatch { left: Uuid, right: Uuid },
    /// A leaf sealed under one keyset was handed to a [`KeysetCipher`] for
    /// another. The handle's keyset is a constraint the caller asked for —
    /// a tenant-scoped request handler must not open another tenant's row
    /// — so this is refused before any key is retrieved. To open leaves
    /// from any keyset, decrypt through the [`StackCipher`].
    #[error("leaf was sealed under keyset {found}, not the handle's keyset {expected}")]
    #[diagnostic(
        code(stack_encrypt::foreign_keyset),
        help(
            "Decrypt through the client, not a keyset-bound cipher, to open rows from any keyset."
        )
    )]
    ForeignKeyset { expected: Uuid, found: Uuid },
    /// A data key was requested through a [`StackCipher`] rather than a
    /// [`KeysetCipher`]: a [`Request::generate_data_key`] needs a keyset
    /// to mint under, and only a keyset-scoped pending has one. Always a
    /// composition bug in a hand-written `EncryptFrom`, caught before any
    /// I/O.
    ///
    /// [`Request::generate_data_key`]: crate::target::Request::generate_data_key
    #[error("a data key was requested with no keyset to mint it under")]
    #[diagnostic(
        code(stack_encrypt::no_keyset),
        help("Encrypt through a keyset cipher: `default_keyset()` or `keyset(..)` on the client.")
    )]
    NoKeyset,
    /// A [`DecryptField`](crate::target::DecryptField) implementation
    /// declared its type [`DECRYPTABLE`](crate::target::Decryptable::DECRYPTABLE)
    /// but passed the field over. Always a bug in a third-party
    /// `DecryptField`, never a data error.
    #[error("a field declared decryptable was not opened by its DecryptField implementation")]
    #[diagnostic(code(stack_encrypt::not_opened))]
    NotOpened,
    /// A [plan](crate::plan) was refused: it did not validate when it was
    /// built, or the value, record or query it was run with does not match
    /// it. A refusal at build or when a plan runs is raised before any key
    /// is requested; [`FieldValues::take`](crate::plan::FieldValues::take)
    /// also returns one for a record already in hand.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Plan(#[from] crate::plan::PlanError),
}

/// How many separator-delimited parts a descriptor has: what an error about
/// a context says of it in place of the descriptor itself.
fn descriptor_parts(descriptor: &Descriptor) -> usize {
    descriptor.as_str().split(Descriptor::SEPARATOR).count()
}

impl crate::ErrorPayload for Error {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        use crate::diagnostic::payload;
        match self {
            Self::Kms(error) => error.payload(),
            Self::Term(error) => error.payload(),
            Self::Plan(error) => error.payload(),
            Self::KeyCountMismatch { expected, received } => payload([
                ("expected", (*expected).into()),
                ("received", (*received).into()),
            ]),
            Self::DescriptorTooLong { len } => payload([
                ("len", (*len).into()),
                ("limit", Descriptor::MAX_LEN.into()),
            ]),
            Self::ContextMismatch { stored } => payload([
                ("stored_len", stored.len().into()),
                ("stored_parts", descriptor_parts(stored).into()),
            ]),
            Self::KeysetMismatch { left, right } => payload([
                ("left", left.to_string().into()),
                ("right", right.to_string().into()),
            ]),
            Self::ForeignKeyset { expected, found } => payload([
                ("expected", expected.to_string().into()),
                ("found", found.to_string().into()),
            ]),
            #[cfg(feature = "http")]
            Self::Config(error) => error
                .downcast_ref::<stack_kms::StackKmsBuilderError>()
                .map(crate::ErrorPayload::payload)
                .unwrap_or_default(),
            #[cfg(not(feature = "http"))]
            Self::Config(_) => serde_json::Map::new(),
            Self::Aead
            | Self::Other(_)
            | Self::UnsupportedShape
            | Self::ResponseShape
            | Self::NoKeyset
            | Self::NotOpened => serde_json::Map::new(),
        }
    }
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
/// [`DataKeySource`] — production: [`kms::StackKms`](crate::kms::StackKms); tests:
/// `stack_encrypt::kms::FakeDataKeySource`) and the keysets that client uses.
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
/// use stack_encrypt::kms::FakeDataKeySource;
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
    /// use stack_encrypt::kms::{FakeDataKeySource, IdentifiedBy};
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
    /// [`kms::StackKms`](crate::kms::StackKms) — with `stack_encrypt::kms::StackKmsBuilder`,
    /// or over the host's own transport — and hand it over. It is also how
    /// tests inject `stack_encrypt::kms::FakeDataKeySource`.
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
/// [`IndexKey`](crate::kms::IndexKey), wiping the intermediate stack copy of the
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
        A: IntoContext<'a>,
    {
        let context = aad.into_context();
        let pending = PendingStackCipherText::plan(value, context.clone())?;
        pending.seal(self, context).await
    }

    /// [`StackCipher::decrypt`], constrained to this keyset: a leaf sealed
    /// under any other is [`Error::ForeignKeyset`], refused before any key
    /// is retrieved.
    pub async fn decrypt<'a, T, A>(&self, ciphertext: StackCipherText, aad: A) -> Result<T, Error>
    where
        T: Decrypt,
        A: IntoContext<'a>,
    {
        decrypt_through(self, ciphertext, aad).await
    }
}

/// `decrypt`, for either scope: retrieve every leaf's data key under
/// `aad`'s descriptor, bind them onto the ciphertext, and open it into `T`
/// under the same `aad`. The work is the same on both scopes — one
/// descriptor, one pending, one settle — and the scope is the whole
/// difference: a [`KeysetCipher`] constrains the leaves to its keyset, a
/// [`StackCipher`] constrains nothing.
///
/// One `aad` goes to both halves, and that is the point: every leaf's AAD
/// is a derivation of the descriptor its key was minted under —
/// `for_sequence_element`, `for_map_entry`, `for_leaf` — and that
/// derivation is the library's to compute, never the caller's to supply.
async fn decrypt_through<'s, 'a, T, K: DataKeySource + 's>(
    scope: impl crate::target::CipherScope<'s, K>,
    ciphertext: StackCipherText,
    aad: impl IntoContext<'a>,
) -> Result<T, Error>
where
    T: Decrypt,
{
    let context = aad.into_context();
    let keyed = crate::target::bind_pending(scope, ciphertext, Descriptor::of(context.clone()))
        .settle()
        .await?;
    open_keyed(keyed, context)
}

impl<K: DataKeySource> StackCipher<K> {
    /// Decrypt a [`StackCipherText`] into `T`, authenticating against `aad`.
    ///
    /// One batched `retrieve_keys` call per keyset the leaves were sealed
    /// under, every key under the [`Descriptor`] of `aad`, then vitaminc
    /// opens every leaf under the AAD it derives from the *same* `aad` and
    /// walks the result into `T`'s [`Decrypt`] sink — exactly as
    /// `vitaminc_aead::decrypt` does over an `Aes256Cipher`. One context in,
    /// and every leaf's AAD derived from it; there is no form of this call
    /// that takes two.
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
        T: Decrypt,
        A: IntoContext<'a>,
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
/// the inner version through vitaminc's `Context::for_leaf`, applied inside
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
#[derive(Debug, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum LeafBytesError {
    /// The leading version byte is not one this build knows how to parse.
    /// (A version this build *does* know, stamped on bytes sealed under a
    /// different version, passes here and fails authentication instead —
    /// the version byte is bound into the leaf AAD.)
    #[error("unknown sealed-leaf format version {0}")]
    #[diagnostic(
        code(stack_encrypt::leaf_version),
        help("The value was sealed by a newer build of stack-encrypt, or the bytes are not a sealed value.")
    )]
    UnknownVersion(u8),
    /// The buffer ends before the fixed-width fields, or before the key tag
    /// the `tag_len` field promises.
    #[error("sealed-leaf bytes are truncated")]
    #[diagnostic(code(stack_encrypt::leaf_truncated))]
    Truncated,
    /// The key tag does not fit the format's `u16` length field. Every
    /// construction site rejects an oversized tag — [`SealedValue::from_parts`]
    /// and `serde` deserialisation with this error, and the seal path (where a
    /// custom [`DataKeySource`] could return one; real ZeroKMS tags are tens
    /// of bytes) by failing the encrypt — so a live `SealedValue` always
    /// encodes.
    #[error("key tag of {0} bytes exceeds the format's u16 length field")]
    #[diagnostic(code(stack_encrypt::leaf_tag_too_long))]
    TagTooLong(usize),
}

impl crate::ErrorPayload for LeafBytesError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        use crate::diagnostic::payload;
        match self {
            Self::UnknownVersion(version) => payload([("version", (*version).into())]),
            Self::TagTooLong(len) => payload([("len", (*len).into())]),
            Self::Truncated => serde_json::Map::new(),
        }
    }
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
/// [`bind_keys`] once the batched `retrieve_keys` call has returned; opened
/// by [`BoundKeys`] under the AAD vitaminc's walk derives for its place.
pub(crate) struct KeyedLeaf {
    leaf: SealedValue,
    key: DataKey,
}

/// [`StackCipherText`] with a [`DataKey`] zipped onto every keyed leaf.
pub(crate) type KeyedCipherText = Node<KeyedLeaf>;

/// Zip retrieved keys onto the tree in the same depth-first order the
/// target layer requested them (`retrieve_requests`), so each leaf carries
/// its own key and opening it makes no assumption about the order vitaminc
/// visits leaves in.
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
// Pending tree — planned synchronously, sealed asynchronously
// =============================================================================

/// A value planned for sealing: vitaminc's tree of pending leaves, each
/// holding its tagged plaintext and the AAD its place in the value derives,
/// with no ZeroKMS I/O done yet. [`seal`](Self::seal) turns it into a
/// [`StackCipherText`].
///
/// [`plan`](Self::plan) walks the value once, through vitaminc's
/// `EncryptSink`, which owns every container rule (element and entry AAD,
/// the empty markers, duplicate keys, a container with nothing sealed in
/// it). This crate decides only where each leaf's key comes from.
pub struct PendingStackCipherText(Node<Pending>);

impl PendingStackCipherText {
    /// Plan `value` for sealing under `aad`. No key is requested.
    ///
    /// A value vitaminc refuses to encrypt as given (a map with a repeated
    /// key, a container whose every child is a passthrough, a nesting deeper
    /// than the transport carries) is [`Error::Aead`], as it is when the
    /// value is sealed in one step.
    pub fn plan<'a, P: Encrypt>(value: P, aad: impl IntoAad<'a>) -> Result<Self, Error> {
        vitaminc_aead::plan::<_, Unspecified, _>(value, aad)
            .map(Self)
            .map_err(|_| Error::Aead)
    }

    /// Number of leaves that need a ZeroKMS data key: every leaf, the empty
    /// markers included; a passthrough needs none.
    pub(crate) fn key_count(&self) -> usize {
        fn count(node: &Node<Pending>) -> usize {
            match node {
                CipherText::Single(_) | CipherText::EmptySequence(_) | CipherText::EmptyMap(_) => 1,
                CipherText::Sequence(items) => items.iter().map(count).sum(),
                CipherText::Map(entries) => entries.iter().map(|(_, v)| count(v)).sum(),
                CipherText::Passthrough(_) => 0,
            }
        }
        count(&self.0)
    }

    /// Generate one data key per keyed leaf (one batched ZeroKMS call — none
    /// for a passthrough-only tree), every key under the [`Descriptor`] of
    /// `aad`, and seal the whole tree.
    ///
    /// `aad` is the context the tree was planned under — the value passed to
    /// [`plan`](Self::plan), in the same shape (see the
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
        aad: impl IntoContext<'a>,
    ) -> Result<StackCipherText, Error> {
        self.into_pending(cipher, aad).settle().await
    }

    /// Turn this tree into a [`Pending`](crate::target::Pending) request
    /// carrier without settling it.
    ///
    /// [`seal`](Self::seal) is this plus an immediate settle — one ZeroKMS
    /// call per tree. `into_pending` exists for callers that hold *several*
    /// independently planned trees (one per record field in a language
    /// binding, say) and want them merged with
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
    /// under one here (a `NonEmpty<T>` is an [`IntoContext`] like any other, and
    /// encodes exactly as `T` does) or the ciphertext can never be read that
    /// way.
    pub fn into_pending<'c, 'a, K>(
        self,
        cipher: &'a KeysetCipher<'_, K>,
        aad: impl IntoContext<'c>,
    ) -> crate::target::Pending<'a, StackCipherText, K> {
        crate::target::seal_pending(cipher, self, Descriptor::of(aad))
    }

    /// Seal under `keyset_id`, drawing one key per leaf from `keys` in
    /// vitaminc's walk order. A leaf with no key left is refused.
    pub(crate) fn seal_with(
        self,
        keyset_id: Uuid,
        mut keys: impl Iterator<Item = DataKeyWithTag>,
    ) -> Result<StackCipherText, Unspecified> {
        let minted = MintedKeys {
            keyset_id,
            keys: RefCell::new(&mut keys),
        };
        seal_all(&minted, self.0).map_err(|_| Unspecified)
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
/// parsing and derivation rules — mirroring vitaminc's `Context::for_leaf`,
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
fn leaf_aad(aad: &Context<'_>, keyset_id: Uuid, tag: &[u8]) -> Context<'static> {
    const LEAF_AAD_DOMAIN: &[u8] = b"stack-encrypt/leaf";
    Context::pae(&[
        LEAF_AAD_DOMAIN,
        &[SealedValue::FORMAT_VERSION],
        keyset_id.as_bytes(),
        aad.as_bytes(),
        tag,
    ])
}

/// Seal one leaf's tagged plaintext under a freshly generated data key.
///
/// The AAD is the [`leaf_aad`] derivation of the AAD vitaminc derived for
/// the leaf's place, the keyset the key was minted under, and the key
/// `tag` — `tag` is always bound, so the leaf is cryptographically tied to
/// its ZeroKMS data key.
fn seal_leaf(
    plaintext: Protected<Vec<u8>>,
    aad: &Context<'_>,
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
    let ciphertext = cipher.seal(plaintext, &leaf_aad(aad, keyset_id, &key.tag))?;
    Ok(SealedValue {
        keyset_id,
        iv,
        tag: key.tag,
        ciphertext,
    })
}

/// Open one keyed leaf under `aad`, returning its tagged plaintext.
fn open_leaf(keyed: KeyedLeaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Unspecified> {
    let KeyedLeaf { leaf, key } = keyed;
    let cipher = leaf_cipher(&key)?;
    cipher.open(leaf.ciphertext, &leaf_aad(aad, leaf.keyset_id, &leaf.tag))
}

// =============================================================================
// The vitaminc ciphers: one leaf at a time, keys already in hand
// =============================================================================

/// The sealing half of this crate's vitaminc [`Cipher`]: seals each leaf
/// under the next of a batch of data keys ZeroKMS has already generated,
/// in the order vitaminc's [`seal_all`] visits the leaves.
///
/// The batch is fetched before the walk, in one `generate_keys` call per
/// pending (see [`PendingStackCipherText::seal`]), so the walk itself is
/// synchronous. A leaf for which no key is left is refused.
struct MintedKeys<'k, I> {
    keyset_id: Uuid,
    keys: RefCell<&'k mut I>,
}

impl<I: Iterator<Item = DataKeyWithTag>> Cipher for MintedKeys<'_, I> {
    type Leaf = SealedValue;
    type Error = Unspecified;

    fn seal(
        &self,
        plaintext: Protected<Vec<u8>>,
        aad: &Context<'_>,
    ) -> Result<SealedValue, Unspecified> {
        let key = self.keys.borrow_mut().next().ok_or(Unspecified)?;
        seal_leaf(plaintext, aad, self.keyset_id, key)
    }

    /// Opening goes through [`BoundKeys`], whose leaves carry their
    /// retrieved keys. A minted key is never used to open.
    fn open(&self, _: SealedValue, _: &Context<'_>) -> Result<Protected<Vec<u8>>, Unspecified> {
        Err(Unspecified)
    }
}

/// The opening half of this crate's vitaminc [`Cipher`]: opens a leaf
/// whose retrieved data key [`bind_keys`] has already bound to it, under
/// the AAD vitaminc's walk derives for the leaf's place. vitaminc then
/// checks the empty markers and the container rules and hands each
/// scalar to the sink, so the decrypt side has one definition of the
/// per-node AAD, shared with every other vitaminc cipher.
pub(crate) struct BoundKeys;

impl Cipher for BoundKeys {
    type Leaf = KeyedLeaf;
    type Error = Unspecified;

    /// Sealing goes through [`MintedKeys`]: a leaf is sealed under a key
    /// generated for it, never one retrieved for another leaf.
    fn seal(&self, _: Protected<Vec<u8>>, _: &Context<'_>) -> Result<KeyedLeaf, Unspecified> {
        Err(Unspecified)
    }

    fn open(&self, leaf: KeyedLeaf, aad: &Context<'_>) -> Result<Protected<Vec<u8>>, Unspecified> {
        open_leaf(leaf, aad)
    }
}

/// Open a key-bound tree into `T` under `aad`. Every failure is
/// [`Error::Aead`]: a wrong key or AAD, a tampered leaf or marker, a
/// malformed tree, and a value that is not a `T` all read the same to the
/// caller, as they did before vitaminc split them.
pub(crate) fn open_keyed<'a, T: Decrypt>(
    keyed: KeyedCipherText,
    aad: impl IntoAad<'a>,
) -> Result<T, Error> {
    vitaminc_aead::decrypt(&BoundKeys, keyed, aad).map_err(|_| Error::Aead)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cipher's `Debug` — and a keyset handle's — names the keyset and the
    /// source's type and stops there: the cache behind a cipher holds every
    /// loaded keyset's index key, a handle carries its keyset's, and the
    /// backend holds the credentials.
    #[tokio::test]
    async fn debug_shows_the_keyset_and_the_source_type_only() {
        let cipher = StackCipher::builder()
            .kms(stack_kms::FakeDataKeySource::new())
            .init()
            .await
            .unwrap();
        let keyset = cipher.default_keyset();
        let keyset_id = keyset.keyset_id().to_string();

        for (debug, type_name) in [
            (format!("{cipher:?}"), "StackCipher {"),
            (format!("{keyset:?}"), "KeysetCipher {"),
        ] {
            assert!(debug.starts_with(type_name), "{debug}");
            assert!(debug.contains(&keyset_id), "{debug}");
            assert!(debug.contains("FakeDataKeySource"), "{debug}");
            assert!(debug.ends_with(", .. }"), "non-exhaustive: {debug}");
        }
    }

    /// Each half of the cipher does one thing: a minted key never opens a
    /// leaf, and a key bound to a leaf for opening never seals one.
    #[test]
    fn each_half_of_the_cipher_refuses_the_other_halfs_work() {
        let leaf =
            SealedValue::from_parts(Uuid::nil(), [0; 16], vec![1; 4], vec![2; 32]).expect("a leaf");
        let mut keys = std::iter::empty::<DataKeyWithTag>();
        let minted = MintedKeys {
            keyset_id: Uuid::nil(),
            keys: RefCell::new(&mut keys),
        };
        let aad = Context::from_encoded(b"aad");
        assert!(minted.open(leaf, &aad).is_err(), "a minted key never opens");
        assert!(
            minted.seal(Protected::new(vec![1]), &aad).is_err(),
            "and seals nothing once the batch is spent"
        );
        assert!(
            BoundKeys.seal(Protected::new(vec![1]), &aad).is_err(),
            "a bound key never seals"
        );
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
        let aad = leaf_aad(&Context::from_encoded(b"caller-aad"), keyset, b"key-tag");
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
