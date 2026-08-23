//! A vitaminc [`Cipher`]/[`Decipher`] keyed by ZeroKMS data keys, fetched lazily.
//!
//! [`ZeroKmsCipher`] mirrors the structure of `vitaminc_encrypt::Aes256Cipher`:
//! encrypting an [`Encrypt`] value produces a recursive ciphertext tree
//! ([`ZeroKmsCipherText`], the analog of `AesCipherText`). The difference is
//! *where the key comes from*: rather than a single fixed key, every leaf is
//! sealed under its own ZeroKMS data key.
//!
//! Because data-key generation/retrieval is an async ZeroKMS round-trip, the
//! key fetch cannot happen inside the synchronous [`Cipher`]/[`Decipher`] trait
//! methods. It is front-loaded on both sides, and the AES work stays inside the
//! trait drive:
//!
//! * **Encrypt** — driving the [`Cipher`] trait builds a *pending* tree
//!   ([`PendingCipherText`]) that holds plaintext but does no I/O. A single
//!   [`PendingCipherText::seal`] (or the [`ZeroKmsCipher::encrypt`] convenience)
//!   then batches **one** `generate_keys` call for the whole tree and seals
//!   every leaf.
//! * **Decrypt** — [`ZeroKmsCipher::decipher`] batches **one** `retrieve_keys`
//!   call and zips each key onto its leaf, returning a [`ZeroKmsDecipher`]. The
//!   value's [`Decrypt`] impl then drives that decipher exactly as it would
//!   `AesDecipher`: each leaf is opened under the AAD the drive supplies, so
//!   the visitor pattern (arbitrary nested `Vec`/`HashMap`/`Option`/`Protected`
//!   values, and AAD-deriving wrappers such as `vitaminc_aead::Element`) works
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
//! The decrypt side performs the same derivations inside [`ZeroKmsDecipher`]'s
//! `decrypt_seq`/`decrypt_map`/`decrypt_option` as the caller's `Decrypt` impl
//! drives it, so there is a single source of truth for the per-node AAD.
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
use zeroize::Zeroizing;

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
    ///
    /// Thin wrapper over [`decipher`](Self::decipher): one batched
    /// `retrieve_keys` call, then `T`'s [`Decrypt`] impl drives the returned
    /// [`ZeroKmsDecipher`] with `aad` — exactly as `Aes256Cipher::decrypt_with_aad`
    /// drives `AesDecipher`.
    pub async fn decrypt<'a, T, A>(&self, ciphertext: ZeroKmsCipherText, aad: A) -> Result<T, Error>
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
    pub async fn decipher(&self, ciphertext: ZeroKmsCipherText) -> Result<ZeroKmsDecipher, Error> {
        // Collect every leaf's retrieve payload (borrowing the ciphertext), make
        // one batched call, then drop the borrow before consuming the tree.
        let keys = {
            let mut payloads = Vec::new();
            collect_retrieve_payloads(&ciphertext, &mut payloads);
            if payloads.is_empty() {
                Vec::new()
            } else {
                let expected = payloads.len();
                let keys = self
                    .kms
                    .retrieve_keys(payloads, self.keyset_id, None)
                    .await?;
                if keys.len() != expected {
                    return Err(Error::KeyCountMismatch {
                        expected,
                        received: keys.len(),
                    });
                }
                keys
            }
        };

        let mut keys = keys.into_iter();
        let ciphertext = bind_keys(ciphertext, &mut keys)?;
        // Every key must have been consumed; leftovers mean the tree shape and
        // the payload collection disagreed.
        if keys.next().is_some() {
            return Err(Error::Aead);
        }
        Ok(ZeroKmsDecipher { ciphertext })
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
/// leaf (markers included). Must match [`bind_keys`]'s traversal so payloads
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

/// A leaf with its retrieved data key bound alongside. Produced by
/// [`bind_keys`] once the batched `retrieve_keys` call has returned; consumed by
/// [`ZeroKmsDecipher`], which opens it under whatever AAD the driving
/// [`Decrypt`] impl supplies.
struct KeyedLeaf {
    leaf: DataKeyCipherText,
    key: DataKey,
}

/// [`ZeroKmsCipherText`] with a [`DataKey`] zipped onto every keyed leaf.
type KeyedCipherText = CipherText<KeyedLeaf, BoxedPassthrough>;

/// Zip retrieved keys onto the tree in the same depth-first order
/// [`collect_retrieve_payloads`] requested them, so each leaf carries its own
/// key and the subsequent [`Decipher`] drive is free of ordering assumptions.
fn bind_keys(
    ciphertext: ZeroKmsCipherText,
    keys: &mut impl Iterator<Item = DataKey>,
) -> Result<KeyedCipherText, Unspecified> {
    fn bind(
        leaf: DataKeyCipherText,
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

    // The plaintext bytes are overwritten in place by the ciphertext. Until
    // that succeeds the buffer still holds plaintext, so keep it `Zeroizing`:
    // `risky_unwrap` surrenders `Protected`'s wipe-on-drop, and the error path
    // must not leave the plaintext behind on the heap.
    let mut buf = Zeroizing::new(plaintext.risky_unwrap());
    aead.encrypt_in_place(nonce, &aad, &mut *buf)
        .map_err(|_| Unspecified)?;

    Ok(DataKeyCipherText {
        iv,
        tag: key.tag,
        // Now ciphertext; take it out and let the (empty) wrapper zeroize.
        ciphertext: std::mem::take(&mut *buf),
    })
}

/// Open one keyed leaf under `aad`, returning the plaintext bytes.
fn open_leaf(keyed: KeyedLeaf, aad: &Aad<'_>) -> Result<Protected<Vec<u8>>, Unspecified> {
    let KeyedLeaf { leaf, key } = keyed;
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
fn verify_empty_marker(keyed: KeyedLeaf, aad: &Aad<'_>) -> Result<(), Unspecified> {
    let plaintext = open_leaf(keyed, aad)?;
    if plaintext.risky_ref().is_empty() {
        Ok(())
    } else {
        Err(Unspecified)
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

// Decrypt side: a synchronous `Decipher` over a key-bound ciphertext tree
// =============================================================================

/// A [`Decipher`] over a single [`ZeroKmsCipherText`] whose leaves already
/// carry their retrieved data keys, produced by [`ZeroKmsCipher::decipher`].
///
/// Structurally identical to `vitaminc_encrypt::AesDecipher` — the only
/// difference is where each leaf's key comes from. The AAD is supplied per call
/// by [`Decrypt::decrypt_with_aad`] and refined here exactly as the encrypt side
/// refined it: sequence elements under [`Aad::for_sequence_element`], map
/// values under [`Aad::for_map_entry`] of their key, markers under their
/// respective derivations with an enforced-empty plaintext. Because the
/// derivation lives in this drive (not in a pre-pass), `Decrypt` impls that
/// transform the AAD themselves (e.g. `vitaminc_aead::Element`) work unchanged.
pub struct ZeroKmsDecipher {
    ciphertext: KeyedCipherText,
}

impl ZeroKmsDecipher {
    fn over(ciphertext: KeyedCipherText) -> Self {
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

impl<'c> Decipher<'c> for ZeroKmsDecipher {
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
                visitor.visit_seq(ZeroKmsSeqAccess {
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
                visitor.visit_seq(ZeroKmsSeqAccess {
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
                visitor.visit_map(ZeroKmsMapAccess {
                    entries: entries.into_iter(),
                    aad: aad.into_aad(),
                })
            }
            CipherText::EmptyMap(keyed) => {
                let aad = aad.into_aad();
                verify_empty_marker(keyed, &aad.for_empty_map())?;
                // Raw caller AAD, not the marker derivation — see `decrypt_seq`.
                visitor.visit_map(ZeroKmsMapAccess {
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

struct ZeroKmsSeqAccess {
    items: std::vec::IntoIter<KeyedCipherText>,
    /// [`Aad::for_sequence_element`] of the caller's AAD, derived once at
    /// construction and re-supplied per element by borrowing. Mirrors
    /// `PendingSeqCipher::element_aad` on the encrypt side.
    element_aad: Aad<'static>,
}

impl<'c> SeqAccess<'c> for ZeroKmsSeqAccess {
    type Error = Unspecified;

    fn next_element<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<T>, Self::Error> {
        match self.items.next() {
            Some(ct) => T::decrypt_with_aad(ZeroKmsDecipher::over(ct), self.element_aad.as_bytes())
                .map(Some),
            None => Ok(None),
        }
    }
}

struct ZeroKmsMapAccess<'a> {
    entries: std::vec::IntoIter<(String, KeyedCipherText)>,
    aad: Aad<'a>,
}

impl<'c, 'a> MapAccess<'c> for ZeroKmsMapAccess<'a> {
    type Error = Unspecified;

    fn next_entry<T: Decrypt<'c> + 'c>(&mut self) -> Result<Option<(String, T)>, Self::Error> {
        match self.entries.next() {
            Some((key, ct)) => {
                // Mirror `PendingMapCipher::encrypt_value`: the value was sealed
                // against `for_map_entry(key)`, so a swapped or renamed key
                // fails here.
                let entry_aad = self.aad.for_map_entry(&key);
                let value = T::decrypt_with_aad(ZeroKmsDecipher::over(ct), entry_aad)?;
                Ok(Some((key, value)))
            }
            None => Ok(None),
        }
    }
}
