//! A vitaminc [`Cipher`]/[`Decipher`] keyed by ZeroKMS data keys, fetched lazily.
//!
//! [`ZeroKmsCipher`] mirrors the structure of `vitaminc_encrypt::Aes256Cipher`:
//! encrypting an [`Encrypt`] value produces a recursive ciphertext tree
//! ([`ZeroKmsCipherText`], the analog of `AesCipherText`). The difference is
//! *where the key comes from*: rather than a single fixed key, every leaf is
//! sealed under its own ZeroKMS data key.
//!
//! Because data-key generation/retrieval is an async ZeroKMS round-trip, the
//! crypto cannot happen inside the synchronous [`Cipher`]/[`Decipher`] trait
//! methods. Instead:
//!
//! * **Encrypt** — driving the [`Cipher`] trait builds a *pending* tree
//!   ([`PendingCipherText`]) that holds plaintext but does no I/O. A single
//!   [`PendingCipherText::seal`] (or the [`ZeroKmsCipher::encrypt`] convenience)
//!   then batches **one** `generate_keys` call for the whole tree and seals
//!   every leaf.
//! * **Decrypt** — [`ZeroKmsCipher::decrypt`] batches **one** `retrieve_keys`
//!   call, decrypts every leaf, then drives the value's [`Decrypt`] impl through
//!   a synchronous in-memory [`Decipher`] over the recovered plaintext — so the
//!   visitor pattern (and arbitrary nested `Vec`/`HashMap`/`Option`/`Protected`
//!   values) works exactly as it does for `Aes256Cipher`.
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
//! Because leaf decryption happens *before* the structural decode (in
//! [`decrypt_tree`], while the [`Decipher`] drive is crypto-free), the decrypt
//! side re-derives the same per-node AADs by walking the ciphertext tree.
//!
//! ## Wire format
//!
//! Each leaf stores the ZeroKMS `iv` and key `tag`. The AES-256-GCM-SIV nonce is
//! the first 12 bytes of the `iv`, and the AEAD AAD is the PAE-encoded tuple
//! `(derived_aad, tag)`. PAE (length-prefixed) encoding is injective, so
//! distinct `(derived_aad, tag)` pairs can never collide on the same AAD bytes.
//! The `tag` is always bound, so the ciphertext is cryptographically tied to its
//! ZeroKMS data key (key binding); a caller AAD (e.g. a
//! [`ContextTag`](vitaminc_aead::ContextTag)) adds a further binding layer.
//!
//! This is a fresh framing and is intentionally **not** byte-compatible with
//! `cipherstash-client`'s `EncryptedRecord` AAD (a raw `descriptor || tag`
//! concatenation). A compatibility module can be added later to read existing
//! records as customers of `cipherstash-client` migrate.

use std::any::Any;
use std::borrow::Cow;
use std::collections::HashSet;

use aes_gcm_siv::aead::AeadInPlace;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce as GcmNonce};
use stack_kms::{DataKey, DataKeySource, DataKeyWithTag, GenerateKeyPayload, RetrieveKeyPayload};
use uuid::Uuid;
use vitaminc_aead::{
    Aad, Cipher, CipherText, Decipher, DecipherVisitor, Decrypt, Encrypt, IntoAad, MapAccess,
    MapCipher, SeqAccess, SeqCipher, Unspecified,
};
use vitaminc_protected::{Controlled, Protected};

/// AES-256-GCM-SIV nonce length in bytes (the leading bytes of the ZeroKMS IV).
const NONCE_LEN: usize = 12;

/// The passthrough payload type: type-erased, as for Rust-native vitaminc
/// ciphers. Callers box on the way in and downcast on the way out.
pub type BoxedPassthrough = Box<dyn Any + Send + 'static>;

/// The recursive ciphertext container produced by [`ZeroKmsCipher`]: vitaminc's
/// generic [`CipherText`] tree over [`DataKeyCipherText`] leaves. Its shape
/// mirrors the encrypted plaintext: a scalar yields `Single`, a `Vec` yields
/// `Sequence` (or `EmptySequence`), a `HashMap` or struct yields `Map` (or
/// `EmptyMap`). Map keys are stored in the clear but bound into their value's
/// AAD.
pub type ZeroKmsCipherText = CipherText<DataKeyCipherText, BoxedPassthrough>;

/// Errors from sealing or opening a [`ZeroKmsCipherText`].
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
}

impl From<Unspecified> for Error {
    fn from(_: Unspecified) -> Self {
        Error::Aead
    }
}

/// A vitaminc cipher whose per-leaf keys are ZeroKMS data keys, sourced through
/// a [`DataKeySource`] (production: `stack_kms::StackKms`; tests:
/// `stack_kms::FakeDataKeySource`).
///
/// Per-leaf keying is deliberate: every value access requires its own data-key
/// retrieval, so individual value accesses are visible (and auditable) as
/// ZeroKMS key-retrieval events.
pub struct ZeroKmsCipher<K> {
    kms: K,
    keyset_id: Option<Uuid>,
}

impl<K> ZeroKmsCipher<K> {
    /// Create a cipher over the given data-key source, using the source's
    /// default keyset.
    pub fn new(kms: K) -> Self {
        Self {
            kms,
            keyset_id: None,
        }
    }

    /// Pin generate/retrieve operations to a specific ZeroKMS keyset.
    pub fn with_keyset_id(mut self, keyset_id: Uuid) -> Self {
        self.keyset_id = Some(keyset_id);
        self
    }
}

impl<K: DataKeySource> ZeroKmsCipher<K> {
    /// Encrypt a value, binding `aad`, and seal it against fresh ZeroKMS data
    /// keys in a single batched `generate_keys` call.
    pub async fn encrypt<'a, T, A>(&self, value: T, aad: A) -> Result<ZeroKmsCipherText, Error>
    where
        T: Encrypt,
        A: IntoAad<'a>,
    {
        let pending = value.encrypt_with_aad(self, aad)?;
        pending.seal(self).await
    }

    /// Decrypt a [`ZeroKmsCipherText`] into `T`, authenticating against `aad`.
    /// Retrieves every leaf's data key in a single batched `retrieve_keys` call,
    /// then drives `T`'s [`Decrypt`] impl over the recovered plaintext.
    pub async fn decrypt<'a, T, A>(&self, ciphertext: ZeroKmsCipherText, aad: A) -> Result<T, Error>
    where
        T: Decrypt<'static> + 'static,
        A: IntoAad<'a>,
    {
        let aad = aad.into_aad().into_owned();

        // Collect every leaf's retrieve payload (borrowing the ciphertext), make
        // one batched call, then drop the borrow before consuming the tree.
        let keys = {
            let mut payloads = Vec::new();
            collect_retrieve_payloads(&ciphertext, &mut payloads);
            if payloads.is_empty() {
                Vec::new()
            } else {
                self.kms
                    .retrieve_keys(payloads, self.keyset_id, None)
                    .await?
            }
        };

        let mut keys = keys.into_iter();
        let plaintext = decrypt_tree(ciphertext, &mut keys, &aad)?;
        // Every key must have been consumed; leftovers mean the tree shape and
        // the payload collection disagreed.
        if keys.next().is_some() {
            return Err(Error::Aead);
        }

        // The plaintext is fully recovered; the structural decode is synchronous
        // and ignores AAD (already authenticated above).
        T::decrypt_with_aad(PlaintextDecipher { tree: plaintext }, ()).map_err(Error::from)
    }
}

/// A single leaf: the ZeroKMS metadata needed to re-derive the key plus the
/// AES-256-GCM-SIV ciphertext (`ciphertext || gcm_tag`).
#[derive(Debug, Clone)]
pub struct DataKeyCipherText {
    /// ZeroKMS IV. Its first [`NONCE_LEN`] bytes are the AEAD nonce, and the
    /// full IV is needed to retrieve the data key.
    iv: stack_kms::Iv,
    /// ZeroKMS key tag: required to retrieve the key and used as the AEAD AAD.
    tag: Vec<u8>,
    /// AES-256-GCM-SIV output: ciphertext with the 16-byte auth tag appended.
    ciphertext: Vec<u8>,
}

/// Walk the tree in depth-first order, pushing one retrieve payload per keyed
/// leaf (markers included). Must match [`decrypt_tree`]'s traversal so payloads
/// and returned keys line up.
fn collect_retrieve_payloads<'b>(
    ciphertext: &'b ZeroKmsCipherText,
    out: &mut Vec<RetrieveKeyPayload<'b>>,
) {
    match ciphertext {
        CipherText::Single(leaf)
        | CipherText::None(leaf)
        | CipherText::EmptySequence(leaf)
        | CipherText::EmptyMap(leaf) => {
            // Empty descriptor — see the module-level wire-format note.
            out.push(RetrieveKeyPayload::new(leaf.iv, "", &leaf.tag));
        }
        CipherText::Sequence(items) => {
            for item in items {
                collect_retrieve_payloads(item, out);
            }
        }
        CipherText::Map(entries) => {
            for (_, value) in entries {
                collect_retrieve_payloads(value, out);
            }
        }
        CipherText::Passthrough(_) => {}
    }
}

// =============================================================================
// Pending tree (`Cipher::Ok`) — built synchronously, sealed asynchronously
// =============================================================================

/// The intermediate result of driving the [`Cipher`] trait: a tree that holds
/// plaintext (and the AAD each leaf will be sealed against, fully derived) but
/// has done no ZeroKMS I/O. [`seal`](Self::seal) turns it into a
/// [`ZeroKmsCipherText`].
pub enum PendingCipherText {
    /// A scalar awaiting a data key, with its bound (derived) AAD.
    Single {
        plaintext: Protected<Vec<u8>>,
        aad: Aad<'static>,
    },
    /// A pending sequence with at least one element.
    Sequence(Vec<PendingCipherText>),
    /// A pending empty-sequence marker; `aad` is already the
    /// [`Aad::for_empty_sequence`] derivation.
    EmptySequence { aad: Aad<'static> },
    /// A pending map with at least one entry.
    Map(Vec<(String, PendingCipherText)>),
    /// A pending empty-map marker; `aad` is already the [`Aad::for_empty_map`]
    /// derivation.
    EmptyMap { aad: Aad<'static> },
    /// A pending authenticated-absent marker; `aad` is already the
    /// [`Aad::for_none`] derivation.
    None { aad: Aad<'static> },
    /// A passthrough value (needs no key).
    Passthrough(BoxedPassthrough),
}

impl PendingCipherText {
    /// Number of leaves that need a ZeroKMS data key (everything but
    /// passthrough — markers are sealed leaves too).
    fn key_count(&self) -> usize {
        match self {
            PendingCipherText::Single { .. }
            | PendingCipherText::None { .. }
            | PendingCipherText::EmptySequence { .. }
            | PendingCipherText::EmptyMap { .. } => 1,
            PendingCipherText::Sequence(items) => items.iter().map(Self::key_count).sum(),
            PendingCipherText::Map(entries) => entries.iter().map(|(_, v)| v.key_count()).sum(),
            PendingCipherText::Passthrough(_) => 0,
        }
    }

    /// Generate one data key per keyed leaf (one batched ZeroKMS call) and seal
    /// the whole tree.
    pub async fn seal<K: DataKeySource>(
        self,
        cipher: &ZeroKmsCipher<K>,
    ) -> Result<ZeroKmsCipherText, Error> {
        let count = self.key_count();
        if count == 0 {
            // Passthrough-only tree: no keys, no ZeroKMS call.
            return Ok(self.seal_with(&mut std::iter::empty())?);
        }

        // Empty descriptor + empty context for every leaf (see wire-format note).
        let payloads: Vec<GenerateKeyPayload<'_>> = (0..count)
            .map(|_| GenerateKeyPayload::new("", Cow::Owned(Vec::new())))
            .collect();

        let keys = cipher
            .kms
            .generate_keys(payloads, cipher.keyset_id, None)
            .await?;

        if keys.len() != count {
            return Err(Error::KeyCountMismatch {
                expected: count,
                received: keys.len(),
            });
        }

        let mut keys = keys.into_iter();
        Ok(self.seal_with(&mut keys)?)
    }

    /// Recursively seal, drawing one key per leaf from `keys` in traversal order.
    fn seal_with(
        self,
        keys: &mut impl Iterator<Item = DataKeyWithTag>,
    ) -> Result<ZeroKmsCipherText, Unspecified> {
        // Markers seal an *empty* plaintext so the AEAD tag still binds their
        // (already domain-separated) AAD, mirroring `Aes256Cipher`.
        fn seal_marker(
            aad: Aad<'static>,
            keys: &mut impl Iterator<Item = DataKeyWithTag>,
        ) -> Result<DataKeyCipherText, Unspecified> {
            let key = keys.next().ok_or(Unspecified)?;
            seal_leaf(Protected::new(Vec::new()), &aad, key)
        }

        match self {
            PendingCipherText::Single { plaintext, aad } => {
                let key = keys.next().ok_or(Unspecified)?;
                Ok(CipherText::Single(seal_leaf(plaintext, &aad, key)?))
            }
            PendingCipherText::None { aad } => Ok(CipherText::None(seal_marker(aad, keys)?)),
            PendingCipherText::EmptySequence { aad } => {
                Ok(CipherText::EmptySequence(seal_marker(aad, keys)?))
            }
            PendingCipherText::EmptyMap { aad } => {
                Ok(CipherText::EmptyMap(seal_marker(aad, keys)?))
            }
            PendingCipherText::Sequence(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(item.seal_with(keys)?);
                }
                Ok(CipherText::Sequence(out))
            }
            PendingCipherText::Map(entries) => {
                let mut out = Vec::with_capacity(entries.len());
                for (k, v) in entries {
                    out.push((k, v.seal_with(keys)?));
                }
                Ok(CipherText::Map(out))
            }
            PendingCipherText::Passthrough(value) => Ok(CipherText::Passthrough(value)),
        }
    }
}

// =============================================================================
// Leaf crypto
// =============================================================================

/// Compose the AEAD AAD as the PAE-encoded tuple `(derived_aad, tag)`.
///
/// PAE (length-prefixed) encoding is injective, so distinct `(derived_aad, tag)`
/// pairs can never collide on the same AAD bytes — unlike a raw concatenation,
/// which is only unambiguous when the tag has a fixed length. `tag` is always
/// bound, so the leaf is cryptographically tied to its ZeroKMS data key.
fn leaf_aad(derived_aad: &Aad<'_>, tag: &[u8]) -> Vec<u8> {
    (derived_aad.as_bytes(), tag).into_aad().as_bytes().to_vec()
}

/// Seal one plaintext leaf under a freshly generated data key.
fn seal_leaf(
    plaintext: Protected<Vec<u8>>,
    aad: &Aad<'_>,
    key: DataKeyWithTag,
) -> Result<DataKeyCipherText, Unspecified> {
    let iv = key.key.iv;
    let aead = Aes256GcmSiv::new_from_slice(key.key.key()).map_err(|_| Unspecified)?;
    let nonce = GcmNonce::from_slice(&iv[..NONCE_LEN]);
    let aad = leaf_aad(aad, &key.tag);

    // The plaintext bytes are overwritten in place by the ciphertext.
    let mut buf = plaintext.risky_unwrap();
    aead.encrypt_in_place(nonce, &aad, &mut buf)
        .map_err(|_| Unspecified)?;

    Ok(DataKeyCipherText {
        iv,
        tag: key.tag,
        ciphertext: buf,
    })
}

/// Open one leaf with its retrieved data key, returning the plaintext bytes.
fn open_leaf(
    leaf: DataKeyCipherText,
    key: &DataKey,
    aad: &Aad<'_>,
) -> Result<Protected<Vec<u8>>, Unspecified> {
    let aead = Aes256GcmSiv::new_from_slice(key.key()).map_err(|_| Unspecified)?;
    let nonce = GcmNonce::from_slice(&leaf.iv[..NONCE_LEN]);
    let aad = leaf_aad(aad, &leaf.tag);

    let mut buf = leaf.ciphertext;
    aead.decrypt_in_place(nonce, &aad, &mut buf)
        .map_err(|_| Unspecified)?;
    Ok(Protected::new(buf))
}

/// Open one marker leaf (absent / empty-sequence / empty-map) and require the
/// sealed plaintext to be empty. Without the emptiness check, a `Single` leaf
/// could be re-tagged as a marker of the same AAD derivation.
fn verify_empty_marker(
    leaf: DataKeyCipherText,
    key: &DataKey,
    aad: &Aad<'_>,
) -> Result<(), Unspecified> {
    let plaintext = open_leaf(leaf, key, aad)?;
    if plaintext.risky_ref().is_empty() {
        Ok(())
    } else {
        Err(Unspecified)
    }
}

/// Recursively open every leaf into a plaintext tree, drawing one key per leaf
/// from `keys` in the same order [`collect_retrieve_payloads`] produced them.
///
/// This is where the decrypt side re-derives the per-node AADs (the structural
/// [`Decipher`] drive that follows is crypto-free): sequence elements verify
/// under [`Aad::for_sequence_element`], map values under [`Aad::for_map_entry`]
/// of their key, and markers under their respective derivations with an
/// enforced-empty plaintext. Verified empty markers collapse to empty
/// `Sequence`/`Map` nodes so the structural decode sees ordinary containers.
fn decrypt_tree(
    ciphertext: ZeroKmsCipherText,
    keys: &mut impl Iterator<Item = DataKey>,
    aad: &Aad<'_>,
) -> Result<PlaintextTree, Unspecified> {
    match ciphertext {
        CipherText::Single(leaf) => {
            let key = keys.next().ok_or(Unspecified)?;
            Ok(PlaintextTree::Single(open_leaf(leaf, &key, aad)?))
        }
        CipherText::None(leaf) => {
            let key = keys.next().ok_or(Unspecified)?;
            verify_empty_marker(leaf, &key, &aad.for_none())?;
            Ok(PlaintextTree::None)
        }
        CipherText::EmptySequence(leaf) => {
            let key = keys.next().ok_or(Unspecified)?;
            verify_empty_marker(leaf, &key, &aad.for_empty_sequence())?;
            Ok(PlaintextTree::Sequence(Vec::new()))
        }
        CipherText::EmptyMap(leaf) => {
            let key = keys.next().ok_or(Unspecified)?;
            verify_empty_marker(leaf, &key, &aad.for_empty_map())?;
            Ok(PlaintextTree::Map(Vec::new()))
        }
        CipherText::Sequence(items) => {
            // At least one non-passthrough item required: passthrough items
            // authenticate nothing, so an all-passthrough (or entry-less)
            // sequence would verify under any AAD. The encrypt side refuses to
            // produce one; refuse to open one. Emptiness is only provable by
            // the authenticated `EmptySequence` marker.
            if !items
                .iter()
                .any(|i| !matches!(i, CipherText::Passthrough(_)))
            {
                return Err(Unspecified);
            }
            let element_aad = aad.for_sequence_element();
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(decrypt_tree(item, keys, &element_aad)?);
            }
            Ok(PlaintextTree::Sequence(out))
        }
        CipherText::Map(entries) => {
            // Same all-passthrough/entry-less rejection as `Sequence`.
            if !entries
                .iter()
                .any(|(_, v)| !matches!(v, CipherText::Passthrough(_)))
            {
                return Err(Unspecified);
            }
            // Reject duplicate keys before opening anything: two ciphertexts of
            // the same logical record seal a given key's value against the
            // identical `for_map_entry` AAD, so a stale entry appended to a
            // current ciphertext *verifies* — with a last-wins decoder that is
            // a single-field rollback.
            let mut seen = HashSet::with_capacity(entries.len());
            if !entries.iter().all(|(key, _)| seen.insert(key.clone())) {
                return Err(Unspecified);
            }
            let mut out = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let entry_aad = aad.for_map_entry(&k);
                out.push((k, decrypt_tree(v, keys, &entry_aad)?));
            }
            Ok(PlaintextTree::Map(out))
        }
        CipherText::Passthrough(value) => Ok(PlaintextTree::Passthrough(value)),
    }
}

// =============================================================================
// Encrypt side: `Cipher` impl over a `&ZeroKmsCipher` (builds the pending tree)
// =============================================================================

impl<'c, K> Cipher for &'c ZeroKmsCipher<K> {
    type Ok = PendingCipherText;
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
        Ok(PendingCipherText::Single {
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
        Ok(PendingCipherText::None {
            aad: aad.into_aad().for_none(),
        })
    }

    fn passthrough(self, value: Self::Passthrough) -> Result<Self::Ok, Self::Error> {
        Ok(PendingCipherText::Passthrough(value))
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
    cipher: &'c ZeroKmsCipher<K>,
    items: Vec<PendingCipherText>,
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
    type Ok = PendingCipherText;
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
        self.encrypted |= !matches!(pending, PendingCipherText::Passthrough(_));
        self.items.push(pending);
        Ok(self)
    }

    fn passthrough_next(mut self, value: Self::Passthrough) -> Result<Self, Self::Error> {
        self.items.push(PendingCipherText::Passthrough(value));
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        if self.items.is_empty() {
            Ok(PendingCipherText::EmptySequence {
                aad: self.aad.for_empty_sequence(),
            })
        } else if !self.encrypted {
            // Every item is a passthrough: nothing in the container would
            // authenticate the AAD, so refuse to produce it — mirroring
            // `decrypt_tree`'s rejection on open.
            Err(Unspecified)
        } else {
            Ok(PendingCipherText::Sequence(self.items))
        }
    }
}

/// [`MapCipher`] driver: keys are stored in the clear; values become pending
/// sub-trees sealed against [`Aad::for_map_entry`] of the map AAD and their
/// key. Mirrors `AesMapCipher`'s key/value and duplicate-key contract checks.
pub struct PendingMapCipher<'c, K> {
    cipher: &'c ZeroKmsCipher<K>,
    entries: Vec<(String, PendingCipherText)>,
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
    type Ok = PendingCipherText;
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
        self.encrypted |= !matches!(pending, PendingCipherText::Passthrough(_));
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
            .push((key.into_owned(), PendingCipherText::Passthrough(value)));
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        // Finalising with a pending key would silently drop the entry.
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
        if self.entries.is_empty() {
            Ok(PendingCipherText::EmptyMap {
                aad: self.aad.for_empty_map(),
            })
        } else if !self.encrypted {
            // Every entry is a passthrough — see `PendingSeqCipher::end`.
            Err(Unspecified)
        } else {
            Ok(PendingCipherText::Map(self.entries))
        }
    }
}

// =============================================================================
// Decrypt side: a synchronous `Decipher` over already-recovered plaintext
// =============================================================================

/// Plaintext counterpart to [`ZeroKmsCipherText`], produced by [`decrypt_tree`]
/// once every leaf has been opened (and every marker verified). Verified empty
/// markers appear as empty `Sequence`/`Map` nodes.
enum PlaintextTree {
    Single(Protected<Vec<u8>>),
    Sequence(Vec<PlaintextTree>),
    Map(Vec<(String, PlaintextTree)>),
    None,
    Passthrough(BoxedPassthrough),
}

/// A synchronous [`Decipher`] over a fully-decrypted [`PlaintextTree`]. It does
/// no crypto — decryption (including AAD verification) already happened in
/// [`decrypt_tree`] — so it drives the [`DecipherVisitor`] pattern purely
/// structurally and ignores AAD.
struct PlaintextDecipher {
    tree: PlaintextTree,
}

impl<'c> Decipher<'c> for PlaintextDecipher {
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

    fn decrypt_bytes<'a, V, A>(self, visitor: V, _aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        match self.tree {
            PlaintextTree::Single(bytes) => visitor.visit_bytes_vec(bytes),
            _ => Err(Unspecified),
        }
    }

    fn decrypt_seq<'a, V, A>(self, visitor: V, _aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        match self.tree {
            PlaintextTree::Sequence(items) => visitor.visit_seq(PlaintextSeqAccess {
                items: items.into_iter(),
            }),
            _ => Err(Unspecified),
        }
    }

    fn decrypt_map<'a, V, A>(self, visitor: V, _aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        match self.tree {
            PlaintextTree::Map(entries) => visitor.visit_map(PlaintextMapAccess {
                entries: entries.into_iter(),
            }),
            _ => Err(Unspecified),
        }
    }

    fn decrypt_any<'a, V, A>(self, visitor: V, aad: A) -> Self::Ok<V::Value>
    where
        V: DecipherVisitor<'c> + Send + 'c,
        A: IntoAad<'a>,
    {
        match self.tree {
            tree @ PlaintextTree::Single(_) => {
                PlaintextDecipher { tree }.decrypt_bytes(visitor, aad)
            }
            tree @ PlaintextTree::Sequence(_) => {
                PlaintextDecipher { tree }.decrypt_seq(visitor, aad)
            }
            tree @ PlaintextTree::Map(_) => PlaintextDecipher { tree }.decrypt_map(visitor, aad),
            // The marker's AAD binding was verified in `decrypt_tree`.
            PlaintextTree::None => visitor.visit_none(),
            PlaintextTree::Passthrough(boxed) => visitor.visit_passthrough(boxed),
        }
    }

    fn decrypt_passthrough(self) -> Self::Ok<Self::Passthrough> {
        match self.tree {
            PlaintextTree::Passthrough(boxed) => Ok(boxed),
            _ => Err(Unspecified),
        }
    }

    fn decrypt_option<'a, T, A>(self, _aad: A) -> Self::Ok<Option<T>>
    where
        T: Decrypt<'c> + 'c,
        A: IntoAad<'a>,
    {
        match self.tree {
            // The `for_none` marker (tag and enforced-empty plaintext) was
            // verified in `decrypt_tree`.
            PlaintextTree::None => Ok(None),
            // Passthrough must never be decoded as an Option payload.
            PlaintextTree::Passthrough(_) => Err(Unspecified),
            // Any other shape is the `Some` payload — recurse into `T`.
            other => T::decrypt_with_aad(PlaintextDecipher { tree: other }, ()).map(Some),
        }
    }
}

struct PlaintextSeqAccess {
    items: std::vec::IntoIter<PlaintextTree>,
}

impl<'c> SeqAccess<'c> for PlaintextSeqAccess {
    type Error = Unspecified;

    fn next_element<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<T>, Self::Error> {
        match self.items.next() {
            Some(tree) => T::decrypt_with_aad(PlaintextDecipher { tree }, ()).map(Some),
            None => Ok(None),
        }
    }
}

struct PlaintextMapAccess {
    entries: std::vec::IntoIter<(String, PlaintextTree)>,
}

impl<'c> MapAccess<'c> for PlaintextMapAccess {
    type Error = Unspecified;

    fn next_entry<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<(String, T)>, Self::Error> {
        match self.entries.next() {
            Some((key, tree)) => {
                let value = T::decrypt_with_aad(PlaintextDecipher { tree }, ())?;
                Ok(Some((key, value)))
            }
            None => Ok(None),
        }
    }
}
