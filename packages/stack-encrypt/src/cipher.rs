//! Implementation of [`StackCipher`]. For usage, start at the crate docs; this
//! module documents the internals.
//!
//! `StackCipher` is a vitaminc [`Cipher`] whose per-leaf keys are ZeroKMS data
//! keys rather than one fixed key. Structurally it mirrors
//! `vitaminc_encrypt::Aes256Cipher`: encrypting an [`Encrypt`] value produces
//! a recursive ciphertext tree ([`StackCipherText`], the analog of
//! `AesCipherText`) whose leaves ([`SealedValue`]) each carry the ZeroKMS
//! metadata for their own data key.
//!
//! ## Batching the key fetch
//!
//! Data-key generation/retrieval is an async ZeroKMS round-trip, so the key
//! fetch cannot happen inside the synchronous [`Cipher`]/[`Decipher`] trait
//! methods. It is front-loaded on both sides; the AES work stays inside the
//! trait drive:
//!
//! * **Encrypt** — driving the [`Cipher`] trait builds a *pending* tree
//!   ([`PendingStackCipherText`]) that holds plaintext plus each leaf's fully
//!   derived AAD, but does no I/O. A single [`PendingStackCipherText::seal`]
//!   (or the [`StackCipher::encrypt`] convenience) then batches **one**
//!   `generate_keys` call for the whole tree and seals every leaf.
//! * **Decrypt** — [`StackCipher::decipher`] batches **one** `retrieve_keys`
//!   call and zips each key onto its leaf, returning a [`StackDecipher`]. The
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
//! Each leaf ([`SealedValue`]) stores the ZeroKMS `iv` and key `tag` — enough
//! to retrieve the data key — plus a vitaminc [`LocalCipherText`] sealed under
//! that key by [`vitaminc_encrypt::Aes256Cipher`] (AES-256-GCM via vitaminc's
//! backend: `aws-lc-rs` on native, RustCrypto on wasm32; vitaminc's own random
//! nonce and versioned leaf layout). The leaf AAD is the tuple
//! `(derived_aad, tag)`, which vitaminc PAE-encodes so distinct pairs never
//! collide. The `tag` is always bound, so the ciphertext is cryptographically
//! tied to its ZeroKMS data key (key binding); a caller AAD (e.g. a
//! [`ContextTag`](vitaminc_aead::ContextTag)) adds a further binding layer.
//! Every data key is requested with an empty descriptor: stack-encrypt does
//! not use descriptors.
//!
//! This is a fresh framing and is intentionally **not** byte-compatible with
//! `cipherstash-client`'s `EncryptedRecord` AAD (a raw `descriptor || tag`
//! concatenation). A compatibility module can be added later to read existing
//! records as customers of `cipherstash-client` migrate.

use std::any::Any;
use std::borrow::Cow;
use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, EnvKeyProvider, IdentifiedBy, IndexKeySource, StackKms,
    StackKmsBuilder,
};
#[cfg(not(target_arch = "wasm32"))]
use stack_kms::{FallbackKeyProvider, KeyProvider, KeyProviderError, ProfileStore};
use uuid::Uuid;
use vitaminc_aead::{
    Aad, Cipher, CipherText, Decipher, DecipherVisitor, Decrypt, Encrypt, IntoAad, LocalCipherText,
    MapAccess, MapCipher, SeqAccess, SeqCipher, Unspecified,
};
use vitaminc_encrypt::{Aes256Cipher, AesCipherText, Key as AesKey};
use vitaminc_protected::{Controlled, Protected};

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
    /// Building a ZeroKMS client from the environment failed: credentials or
    /// client key missing or malformed.
    #[error("could not build a ZeroKMS client from the environment: {0}")]
    Config(#[from] stack_kms::StackKmsBuilderError),
    /// The per-field encryption context was empty. An empty context defeats
    /// per-field domain separation: equal plaintexts in different fields
    /// would produce identical index terms, ORE/OPE keys would be shared
    /// across fields, and ciphertexts would be transplantable between them.
    #[error("the encryption context must not be empty (it domain-separates fields)")]
    EmptyContext,
    /// An index term failed to derive. An empty context is *not* reported
    /// here — it folds into [`Error::EmptyContext`] so every path spells the
    /// same misconfiguration the same way.
    #[error(transparent)]
    Term(crate::sem::TermError),
    /// A third-party [`EncryptFrom`](crate::target::EncryptFrom) /
    /// [`DecryptFrom`](crate::target::DecryptFrom) implementation failed
    /// for a reason of its own.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// A [`Pending`](crate::target::Pending) fulfilment drew more responses —
    /// or a different kind of response — than its requests asked for. Always a
    /// composition bug in an `EncryptFrom`/`DecryptFrom` implementation,
    /// never a data error.
    #[error("a pending fulfilment drew responses its requests never asked for")]
    ResponseShape,
    /// [`Pending`](crate::target::Pending)s built on different
    /// [`StackCipher`] instances were merged (`zip` / `all`). An assembly
    /// settles through one cipher's backend and keyset, so the other side's
    /// keys would be minted under the wrong keyset. Always a composition
    /// bug, caught before any I/O.
    #[error("merged pendings were built from different ciphers")]
    CipherMismatch,
}

impl From<crate::sem::TermError> for Error {
    fn from(error: crate::sem::TermError) -> Self {
        match error {
            crate::sem::TermError::EmptyContext => Error::EmptyContext,
            other => Error::Term(other),
        }
    }
}

impl From<Unspecified> for Error {
    fn from(_: Unspecified) -> Self {
        Error::Aead
    }
}

/// The CipherStash cipher: a vitaminc [`Cipher`] whose per-leaf keys are ZeroKMS
/// data keys, sourced through a [`DataKeySource`] (production:
/// [`StackKms`]; tests: `stack_kms::FakeDataKeySource`), carrying the
/// per-keyset PRF that [Searchable Encrypted Metadata](crate::sem) terms are
/// derived from.
///
/// Per-leaf keying is deliberate: every value access requires its own data-key
/// retrieval, so individual value accesses are visible (and auditable) as
/// ZeroKMS key-retrieval events.
///
/// A cipher is always able to derive index terms: its keyset's
/// [`IndexKey`](stack_kms::IndexKey) is loaded during construction, so a
/// backend that cannot supply one is not a Stack Encrypt backend. Plain AEAD
/// with no indexing is what `vitaminc` alone provides.
///
/// # Construction
///
/// [`new`](Self::new) is the default path — a ZeroKMS client from the
/// environment, on that client's default keyset:
///
/// ```no_run
/// # async fn example() -> Result<(), stack_encrypt::Error> {
/// use stack_encrypt::StackCipher;
///
/// let cipher = StackCipher::new().await?;
/// # Ok(())
/// # }
/// ```
///
/// Override with [`builder`](Self::builder) — a different keyset, or a
/// different data-key source entirely:
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
/// Construction is async because it resolves the keyset and loads its index
/// key — one ZeroKMS round-trip, paid once.
pub struct StackCipher<K> {
    kms: K,
    /// The resolved keyset. Every generate/retrieve call is pinned to it, and
    /// the PRF below is keyed by *this* keyset's index key: sealing data keys
    /// under one keyset while deriving terms under another's index key would
    /// make every query silently match nothing.
    keyset_id: Uuid,
    prf: vitaminc_hmac::HmacSha256Prf,
}

impl StackCipher<StackKms<stack_auth::AutoStrategy>> {
    /// Build a cipher over a ZeroKMS client configured from the environment,
    /// on that client's default keyset.
    ///
    /// Equivalent to `StackCipher::builder().init()`. For a different keyset
    /// or a different data-key source, use [`builder`](Self::builder).
    pub async fn new() -> Result<Self, Error> {
        Self::builder().init().await
    }

    /// Start building a cipher: pick a keyset, or supply a data-key source
    /// other than the environment's ZeroKMS client.
    pub fn builder() -> StackCipherBuilder {
        StackCipherBuilder {
            kms: FromEnv,
            keyset: None,
        }
    }
}

impl<K> StackCipher<K> {
    /// The keyset every generate/retrieve call is pinned to, and whose index
    /// key keys [`prf`](Self::prf).
    pub fn keyset_id(&self) -> Uuid {
        self.keyset_id
    }

    /// The PRF index terms are derived from, keyed by this cipher's keyset.
    ///
    /// Public so that other crates can implement their own term types against
    /// this cipher (see [`crate::sem`]).
    pub fn prf(&self) -> &vitaminc_hmac::HmacSha256Prf {
        &self.prf
    }

    /// The underlying data-key source.
    pub fn kms(&self) -> &K {
        &self.kms
    }
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
#[cfg(not(target_arch = "wasm32"))]
fn client_key_provider() -> FallbackKeyProvider<EnvKeyProvider, ProfileClientKey> {
    FallbackKeyProvider::new(
        EnvKeyProvider,
        ProfileClientKey(ProfileStore::resolve(None).ok()),
    )
}

/// wasm32 has no filesystem, so no profile: the environment is the only source.
#[cfg(target_arch = "wasm32")]
fn client_key_provider() -> EnvKeyProvider {
    EnvKeyProvider
}

/// [`ProfileStore`] as a [`KeyProvider`], tolerating an unresolvable profile
/// directory so the "not configured" message can say what to do about it
/// rather than only that `CS_CLIENT_ID` is unset.
#[cfg(not(target_arch = "wasm32"))]
struct ProfileClientKey(Option<ProfileStore>);

#[cfg(not(target_arch = "wasm32"))]
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

/// Builder for a [`StackCipher`]. See [`StackCipher::builder`].
pub struct StackCipherBuilder<K = FromEnv> {
    kms: K,
    keyset: Option<IdentifiedBy>,
}

impl<K> StackCipherBuilder<K> {
    /// Pin the cipher to a specific keyset, by id or by name, instead of the
    /// data-key source's default.
    pub fn keyset(mut self, keyset: IdentifiedBy) -> Self {
        self.keyset = Some(keyset);
        self
    }
}

impl StackCipherBuilder<FromEnv> {
    /// Use an explicit data-key source rather than building a ZeroKMS client
    /// from the environment.
    ///
    /// This is the seam for a custom authentication strategy: build a
    /// [`StackKms`] with [`StackKmsBuilder`] and hand it over. It is also how
    /// tests inject `stack_kms::FakeDataKeySource`.
    pub fn kms<K>(self, kms: K) -> StackCipherBuilder<K> {
        StackCipherBuilder {
            kms,
            keyset: self.keyset,
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
    pub async fn init(self) -> Result<StackCipher<StackKms<stack_auth::AutoStrategy>>, Error> {
        let kms = StackKmsBuilder::auto()?
            .with_key_provider(client_key_provider())
            .build()
            .await?;
        StackCipherBuilder {
            kms,
            keyset: self.keyset,
        }
        .init()
        .await
    }
}

impl<K: DataKeySource + IndexKeySource> StackCipherBuilder<K> {
    /// Resolve the keyset and load its index key, producing a cipher that can
    /// both seal values and derive index terms.
    pub async fn init(self) -> Result<StackCipher<K>, Error> {
        let (keyset_id, index_key) = self.kms.load_index_key(self.keyset).await?;
        let prf = hmac_prf_from_index_key(&index_key);
        Ok(StackCipher {
            kms: self.kms,
            keyset_id,
            prf,
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
    let prf = vitaminc_hmac::HmacSha256Prf::new(Protected::new(key));
    key.zeroize();
    prf
}

impl<K: DataKeySource> StackCipher<K> {
    /// Encrypt a value, binding `aad`, and seal it against fresh ZeroKMS data
    /// keys in a single batched `generate_keys` call.
    pub async fn encrypt<'a, T, A>(&self, value: T, aad: A) -> Result<StackCipherText, Error>
    where
        T: Encrypt,
        A: IntoAad<'a>,
    {
        let pending = value.encrypt_with_aad(self, aad)?;
        pending.seal(self).await
    }

    /// Decrypt a [`StackCipherText`] into `T`, authenticating against `aad`.
    ///
    /// Thin wrapper over [`decipher`](Self::decipher): one batched
    /// `retrieve_keys` call, then `T`'s [`Decrypt`] impl drives the returned
    /// [`StackDecipher`] with `aad` — exactly as `Aes256Cipher::decrypt_with_aad`
    /// drives `AesDecipher`.
    pub async fn decrypt<'a, T, A>(&self, ciphertext: StackCipherText, aad: A) -> Result<T, Error>
    where
        T: Decrypt<'static> + 'static,
        A: IntoAad<'a>,
    {
        let decipher = self.decipher(ciphertext).await?;
        T::decrypt_with_aad(decipher, aad).map_err(Error::from)
    }

    /// Fetch every leaf's data key (one batched `retrieve_keys` call) and bind
    /// them onto the ciphertext, returning a synchronous [`Decipher`] that does
    /// the AEAD opening as the value's [`Decrypt`] impl drives it.
    ///
    /// This is the decrypt-side counterpart to passing `&cipher` (a [`Cipher`])
    /// on the encrypt side, mirroring `Aes256Cipher::decipher`: the ZeroKMS I/O
    /// is front-loaded here, and the AAD is supplied per call by
    /// [`Decrypt::decrypt_with_aad`], so `Decrypt` impls that derive their own
    /// AAD (e.g. `vitaminc_aead::Element`) behave identically to `AesDecipher`.
    ///
    /// Settles through the target layer's request carrier
    /// ([`decipher_pending`](crate::target)), so this and
    /// `decrypt_into` share one definition of how leaves map to retrieve
    /// requests and one path to ZeroKMS.
    pub async fn decipher(&self, ciphertext: StackCipherText) -> Result<StackDecipher, Error> {
        crate::target::decipher_pending(self, ciphertext)
            .settle()
            .await
    }
}

/// A single sealed leaf: the ZeroKMS metadata needed to retrieve its data key
/// (`iv`, `tag`) plus the vitaminc [`LocalCipherText`] sealed under that key.
///
/// This is the only byte-format commitment the crate makes — the container
/// tree ([`StackCipherText`]) has no canonical encoding, so callers that
/// persist or transmit ciphertext serialise leaves (it derives `serde`
/// `Serialize`/`Deserialize`, or use [`into_parts`](Self::into_parts) /
/// [`from_parts`](Self::from_parts)) and rebuild the tree around them.
#[derive(Debug, Serialize, Deserialize)]
pub struct SealedValue {
    /// ZeroKMS IV: identifies the data key for retrieval.
    iv: stack_kms::Iv,
    /// ZeroKMS key tag: required to retrieve the key, and bound into the
    /// leaf's AAD so the ciphertext is tied to its data key.
    tag: Vec<u8>,
    /// The leaf sealed by [`vitaminc_encrypt::Aes256Cipher`] under the data
    /// key: `version ‖ nonce ‖ ciphertext ‖ gcm_tag`.
    ciphertext: LocalCipherText,
}

impl SealedValue {
    /// Rebuild a leaf from its persisted parts — the inverse of
    /// [`into_parts`](Self::into_parts).
    pub fn from_parts(iv: stack_kms::Iv, tag: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self {
            iv,
            tag,
            ciphertext: LocalCipherText::from(ciphertext),
        }
    }

    /// Decompose into `(iv, tag, ciphertext)` for persistence.
    pub fn into_parts(self) -> (stack_kms::Iv, Vec<u8>, Vec<u8>) {
        (self.iv, self.tag, self.ciphertext.into_inner().to_vec())
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
            iv: self.iv,
            tag: self.tag.clone(),
            ciphertext: LocalCipherText::from(self.ciphertext.as_ref().to_vec()),
        }
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
    /// for a passthrough-only tree) and seal the whole tree.
    ///
    /// Settles through the target layer's request carrier
    /// ([`seal_pending`](crate::target)), so this and
    /// `encrypt_into::<StackCipherText>` share one definition of how a tree
    /// is sealed and one path to ZeroKMS.
    pub async fn seal<K: DataKeySource>(
        self,
        cipher: &StackCipher<K>,
    ) -> Result<StackCipherText, Error> {
        crate::target::seal_pending(cipher, self).settle().await
    }

    /// Recursively seal, drawing one key per leaf from `keys` in traversal order.
    pub(crate) fn seal_with(
        self,
        keys: &mut impl Iterator<Item = DataKeyWithTag>,
    ) -> Result<StackCipherText, Unspecified> {
        // Markers seal an *empty* plaintext so the AEAD tag still binds their
        // (already domain-separated) AAD, mirroring `Aes256Cipher`.
        fn seal_marker(
            aad: Aad<'static>,
            keys: &mut impl Iterator<Item = DataKeyWithTag>,
        ) -> Result<SealedValue, Unspecified> {
            let key = keys.next().ok_or(Unspecified)?;
            seal_leaf(Protected::new(Vec::new()), &aad, key)
        }

        match self {
            PendingStackCipherText::Single { plaintext, aad } => {
                let key = keys.next().ok_or(Unspecified)?;
                Ok(CipherText::Single(seal_leaf(plaintext, &aad, key)?))
            }
            PendingStackCipherText::None { aad } => Ok(CipherText::None(seal_marker(aad, keys)?)),
            PendingStackCipherText::EmptySequence { aad } => {
                Ok(CipherText::EmptySequence(seal_marker(aad, keys)?))
            }
            PendingStackCipherText::EmptyMap { aad } => {
                Ok(CipherText::EmptyMap(seal_marker(aad, keys)?))
            }
            PendingStackCipherText::Sequence(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(item.seal_with(keys)?);
                }
                Ok(CipherText::Sequence(out))
            }
            PendingStackCipherText::Map(entries) => {
                let mut out = Vec::with_capacity(entries.len());
                for (k, v) in entries {
                    out.push((k, v.seal_with(keys)?));
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

/// Seal one plaintext leaf under a freshly generated data key.
///
/// The AAD is the tuple `(derived_aad, tag)` — vitaminc PAE-encodes tuples,
/// so distinct pairs never collide, and `tag` is always bound: the leaf is
/// cryptographically tied to its ZeroKMS data key.
fn seal_leaf(
    plaintext: Protected<Vec<u8>>,
    aad: &Aad<'_>,
    key: DataKeyWithTag,
) -> Result<SealedValue, Unspecified> {
    let iv = key.key.iv;
    let cipher = leaf_cipher(&key.key)?;
    match (&cipher).encrypt_bytes_vec(plaintext, (aad.as_bytes(), key.tag.as_slice()))? {
        AesCipherText::Single(ciphertext) => Ok(SealedValue {
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
        .decrypt_bytes(ProtectedBytes, (aad.as_bytes(), leaf.tag.as_slice()))
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
// Encrypt side: `Cipher` impl over a `&StackCipher` (builds the pending tree)
// =============================================================================

impl<'c, K> Cipher for &'c StackCipher<K> {
    type Ok = PendingStackCipherText;
    type Error = Unspecified;
    type Passthrough = BoxedPassthrough;
    type SeqCipher = PendingSeqCipher<'c, K>;
    type MapCipher = PendingMapCipher<'c, K>;

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
pub struct PendingSeqCipher<'c, K> {
    cipher: &'c StackCipher<K>,
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

impl<'c, K> SeqCipher for PendingSeqCipher<'c, K> {
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
pub struct PendingMapCipher<'c, K> {
    cipher: &'c StackCipher<K>,
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

impl<'c, K> MapCipher for PendingMapCipher<'c, K> {
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
/// carry their retrieved data keys, produced by [`StackCipher::decipher`].
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
                })
            }
            CipherText::EmptyMap(keyed) => {
                let aad = aad.into_aad();
                verify_empty_marker(keyed, &aad.for_empty_map())?;
                // Raw caller AAD, not the marker derivation — see `decrypt_seq`.
                visitor.visit_map(StackMapAccess {
                    entries: Vec::new().into_iter(),
                    aad,
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
}

impl<'c, 'a> MapAccess<'c> for StackMapAccess<'a> {
    type Error = Unspecified;

    fn next_entry<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<(String, T)>, Self::Error> {
        match self.entries.next() {
            Some((key, ct)) => {
                // Mirror `PendingMapCipher::encrypt_value`: the value was sealed
                // against `for_map_entry(key)`, so a swapped or renamed key
                // fails here.
                let entry_aad = self.aad.for_map_entry(&key);
                let value = T::decrypt_with_aad(StackDecipher::over(ct), entry_aad)?;
                Ok(Some((key, value)))
            }
            None => Ok(None),
        }
    }
}
