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
//! ## Wire format
//!
//! Each leaf stores the ZeroKMS `iv` and key `tag`. The AES-256-GCM-SIV nonce is
//! the first 12 bytes of the `iv`, and the AEAD AAD is the PAE-encoded tuple
//! `(caller_aad, tag)`. PAE (length-prefixed) encoding is injective, so distinct
//! `(caller_aad, tag)` pairs can never collide on the same AAD bytes. The `tag`
//! is always bound, so the ciphertext is cryptographically tied to its ZeroKMS
//! data key (key binding); a caller AAD (e.g. a
//! [`ContextTag`](vitaminc_aead::ContextTag)) adds a further binding layer.
//!
//! This is a fresh framing and is intentionally **not** byte-compatible with
//! `cipherstash-client`'s `EncryptedRecord` AAD (a raw `descriptor || tag`
//! concatenation). A compatibility module can be added later to read existing
//! records as customers of `cipherstash-client` migrate.

use std::any::Any;
use std::borrow::Cow;

use aes_gcm_siv::aead::AeadInPlace;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce as GcmNonce};
use stack_kms::{DataKey, DataKeySource, DataKeyWithTag, GenerateKeyPayload, RetrieveKeyPayload};
use uuid::Uuid;
use vitaminc_aead::{
    Cipher, Decipher, DecipherVisitor, Decrypt, Encrypt, IntoAad, MapAccess, MapCipher, SeqAccess,
    SeqCipher, Unspecified,
};
use vitaminc_protected::{Controlled, Protected};

/// AES-256-GCM-SIV nonce length in bytes (the leading bytes of the ZeroKMS IV).
const NONCE_LEN: usize = 12;

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
        let caller_aad = aad.into_aad().as_bytes().to_vec();

        // Collect every leaf's retrieve payload (borrowing the ciphertext), make
        // one batched call, then drop the borrow before consuming the tree.
        let keys = {
            let mut payloads = Vec::new();
            ciphertext.collect_retrieve_payloads(&mut payloads);
            if payloads.is_empty() {
                Vec::new()
            } else {
                self.kms
                    .retrieve_keys(payloads, self.keyset_id, None)
                    .await?
            }
        };

        let mut keys = keys.into_iter();
        let plaintext = decrypt_tree(ciphertext, &mut keys, &caller_aad)?;

        // The plaintext is fully recovered; the structural decode is synchronous
        // and ignores AAD (already authenticated above).
        T::decrypt_with_aad(PlaintextDecipher { tree: plaintext }, ()).map_err(Error::from)
    }
}

// =============================================================================
// Sealed ciphertext tree (the `AesCipherText` analog)
// =============================================================================

/// The recursive ciphertext container produced by [`ZeroKmsCipher`]. Its shape
/// mirrors the encrypted plaintext: a scalar yields [`Single`](Self::Single), a
/// `Vec` yields [`Sequence`](Self::Sequence), a `HashMap` or struct yields
/// [`Map`](Self::Map).
pub enum ZeroKmsCipherText {
    /// A single sealed value.
    Single(DataKeyCipherText),
    /// A sequence of ciphertexts (from a `Vec`-shaped plaintext).
    Sequence(Vec<ZeroKmsCipherText>),
    /// A map of (cleartext key, ciphertext value) pairs. Keys are not encrypted.
    Map(Vec<(String, ZeroKmsCipherText)>),
    /// An authenticated absent marker from [`Cipher::encrypt_none`].
    None(DataKeyCipherText),
    /// A typed value passed through unencrypted via [`Cipher::passthrough`].
    Passthrough(Box<dyn Any + Send + 'static>),
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

impl ZeroKmsCipherText {
    /// Walk the tree in depth-first order, pushing one retrieve payload per
    /// keyed leaf. Must match [`decrypt_tree`]'s traversal so payloads and
    /// returned keys line up.
    fn collect_retrieve_payloads<'b>(&'b self, out: &mut Vec<RetrieveKeyPayload<'b>>) {
        match self {
            ZeroKmsCipherText::Single(leaf) | ZeroKmsCipherText::None(leaf) => {
                // Empty descriptor — see the module-level wire-format note.
                out.push(RetrieveKeyPayload::new(leaf.iv, "", &leaf.tag));
            }
            ZeroKmsCipherText::Sequence(items) => {
                for item in items {
                    item.collect_retrieve_payloads(out);
                }
            }
            ZeroKmsCipherText::Map(entries) => {
                for (_, value) in entries {
                    value.collect_retrieve_payloads(out);
                }
            }
            ZeroKmsCipherText::Passthrough(_) => {}
        }
    }
}

// =============================================================================
// Pending tree (`Cipher::Ok`) — built synchronously, sealed asynchronously
// =============================================================================

/// The intermediate result of driving the [`Cipher`] trait: a tree that holds
/// plaintext (and the AAD bound to each leaf) but has done no ZeroKMS I/O.
/// [`seal`](Self::seal) turns it into a [`ZeroKmsCipherText`].
pub enum PendingCipherText {
    /// A scalar awaiting a data key, with its bound caller AAD.
    Single {
        plaintext: Protected<Vec<u8>>,
        aad: Vec<u8>,
    },
    /// A pending sequence.
    Sequence(Vec<PendingCipherText>),
    /// A pending map.
    Map(Vec<(String, PendingCipherText)>),
    /// A pending authenticated-absent marker, with its bound caller AAD.
    None { aad: Vec<u8> },
    /// A passthrough value (needs no key).
    Passthrough(Box<dyn Any + Send + 'static>),
}

impl PendingCipherText {
    /// Number of leaves that need a ZeroKMS data key (everything but passthrough).
    fn key_count(&self) -> usize {
        match self {
            PendingCipherText::Single { .. } | PendingCipherText::None { .. } => 1,
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
        match self {
            PendingCipherText::Single { plaintext, aad } => {
                let key = keys.next().ok_or(Unspecified)?;
                Ok(ZeroKmsCipherText::Single(seal_leaf(plaintext, &aad, key)?))
            }
            PendingCipherText::None { aad } => {
                let key = keys.next().ok_or(Unspecified)?;
                // Seal an empty plaintext so the tag binds the AAD, mirroring
                // `Aes256Cipher::encrypt_none`.
                Ok(ZeroKmsCipherText::None(seal_leaf(
                    Protected::new(Vec::new()),
                    &aad,
                    key,
                )?))
            }
            PendingCipherText::Sequence(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(item.seal_with(keys)?);
                }
                Ok(ZeroKmsCipherText::Sequence(out))
            }
            PendingCipherText::Map(entries) => {
                let mut out = Vec::with_capacity(entries.len());
                for (k, v) in entries {
                    out.push((k, v.seal_with(keys)?));
                }
                Ok(ZeroKmsCipherText::Map(out))
            }
            PendingCipherText::Passthrough(value) => Ok(ZeroKmsCipherText::Passthrough(value)),
        }
    }
}

// =============================================================================
// Leaf crypto
// =============================================================================

/// Compose the AEAD AAD as the PAE-encoded tuple `(caller_aad, tag)`.
///
/// PAE (length-prefixed) encoding is injective, so distinct `(caller_aad, tag)`
/// pairs can never collide on the same AAD bytes — unlike a raw concatenation,
/// which is only unambiguous when the tag has a fixed length. `tag` is always
/// bound, so the leaf is cryptographically tied to its ZeroKMS data key.
fn leaf_aad(caller_aad: &[u8], tag: &[u8]) -> Vec<u8> {
    (caller_aad, tag).into_aad().as_bytes().to_vec()
}

/// Seal one plaintext leaf under a freshly generated data key.
fn seal_leaf(
    plaintext: Protected<Vec<u8>>,
    caller_aad: &[u8],
    key: DataKeyWithTag,
) -> Result<DataKeyCipherText, Unspecified> {
    let iv = key.key.iv;
    let aead = Aes256GcmSiv::new_from_slice(key.key.key()).map_err(|_| Unspecified)?;
    let nonce = GcmNonce::from_slice(&iv[..NONCE_LEN]);
    let aad = leaf_aad(caller_aad, &key.tag);

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
    caller_aad: &[u8],
) -> Result<Vec<u8>, Unspecified> {
    let aead = Aes256GcmSiv::new_from_slice(key.key()).map_err(|_| Unspecified)?;
    let nonce = GcmNonce::from_slice(&leaf.iv[..NONCE_LEN]);
    let aad = leaf_aad(caller_aad, &leaf.tag);

    let mut buf = leaf.ciphertext;
    aead.decrypt_in_place(nonce, &aad, &mut buf)
        .map_err(|_| Unspecified)?;
    Ok(buf)
}

/// Recursively open every leaf into a plaintext tree, drawing one key per leaf
/// from `keys` in the same order [`ZeroKmsCipherText::collect_retrieve_payloads`]
/// produced them. `caller_aad` is applied uniformly to every leaf (matching how
/// the built-in `Encrypt` container impls thread a single AAD to every element).
fn decrypt_tree(
    ciphertext: ZeroKmsCipherText,
    keys: &mut impl Iterator<Item = DataKey>,
    caller_aad: &[u8],
) -> Result<PlaintextTree, Unspecified> {
    match ciphertext {
        ZeroKmsCipherText::Single(leaf) => {
            let key = keys.next().ok_or(Unspecified)?;
            Ok(PlaintextTree::Single(open_leaf(leaf, &key, caller_aad)?))
        }
        ZeroKmsCipherText::None(leaf) => {
            let key = keys.next().ok_or(Unspecified)?;
            // Authenticate the absent marker (verifies the tag) and discard.
            open_leaf(leaf, &key, caller_aad)?;
            Ok(PlaintextTree::None)
        }
        ZeroKmsCipherText::Sequence(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(decrypt_tree(item, keys, caller_aad)?);
            }
            Ok(PlaintextTree::Sequence(out))
        }
        ZeroKmsCipherText::Map(entries) => {
            let mut out = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                out.push((k, decrypt_tree(v, keys, caller_aad)?));
            }
            Ok(PlaintextTree::Map(out))
        }
        ZeroKmsCipherText::Passthrough(value) => Ok(PlaintextTree::Passthrough(value)),
    }
}

// =============================================================================
// Encrypt side: `Cipher` impl over a `&ZeroKmsCipher` (builds the pending tree)
// =============================================================================

impl<'c, K> Cipher for &'c ZeroKmsCipher<K> {
    type Ok = PendingCipherText;
    type Error = Unspecified;
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
            aad: aad.into_aad().as_bytes().to_vec(),
        })
    }

    fn encrypt_seq(self, size_hint: Option<usize>) -> Self::SeqCipher {
        PendingSeqCipher {
            cipher: self,
            items: Vec::with_capacity(size_hint.unwrap_or(0)),
        }
    }

    fn encrypt_map(self) -> Self::MapCipher {
        PendingMapCipher {
            cipher: self,
            entries: Vec::new(),
            current_key: None,
        }
    }

    fn encrypt_none<'a, A>(self, aad: A) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        Ok(PendingCipherText::None {
            aad: aad.into_aad().as_bytes().to_vec(),
        })
    }

    fn passthrough<T>(self, value: T) -> Result<Self::Ok, Self::Error>
    where
        T: Any + Send + 'static,
    {
        Ok(PendingCipherText::Passthrough(Box::new(value)))
    }
}

/// [`SeqCipher`] driver: accumulates a pending sub-tree per element. Holds the
/// cipher only to re-drive nested [`Encrypt`] values (no I/O happens here).
pub struct PendingSeqCipher<'c, K> {
    cipher: &'c ZeroKmsCipher<K>,
    items: Vec<PendingCipherText>,
}

impl<'c, K> SeqCipher for PendingSeqCipher<'c, K> {
    type Ok = PendingCipherText;
    type Error = Unspecified;

    fn encrypt_next<'a, T, A>(mut self, data: T, aad: A) -> Result<Self, Self::Error>
    where
        T: Encrypt,
        A: IntoAad<'a>,
    {
        self.items.push(data.encrypt_with_aad(self.cipher, aad)?);
        Ok(self)
    }

    fn passthrough_next<T>(mut self, value: T) -> Result<Self, Self::Error>
    where
        T: Any + Send + 'static,
    {
        self.items
            .push(PendingCipherText::Passthrough(Box::new(value)));
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(PendingCipherText::Sequence(self.items))
    }
}

/// [`MapCipher`] driver: keys are stored in the clear; values become pending
/// sub-trees. Mirrors `AesMapCipher`'s key/value contract checks.
pub struct PendingMapCipher<'c, K> {
    cipher: &'c ZeroKmsCipher<K>,
    entries: Vec<(String, PendingCipherText)>,
    current_key: Option<&'static str>,
}

impl<'c, K> MapCipher for PendingMapCipher<'c, K> {
    type Ok = PendingCipherText;
    type Error = Unspecified;

    fn encrypt_key(mut self, key: &'static str) -> Result<Self, Self::Error> {
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
        self.current_key = Some(key);
        Ok(self)
    }

    fn encrypt_value<'a, U, A>(mut self, value: U, aad: A) -> Result<Self, Self::Error>
    where
        U: Encrypt,
        A: IntoAad<'a>,
    {
        let key = self.current_key.take().ok_or(Unspecified)?;
        let value = value.encrypt_with_aad(self.cipher, aad)?;
        self.entries.push((key.to_string(), value));
        Ok(self)
    }

    fn passthrough_entry<T>(mut self, key: &'static str, value: T) -> Result<Self, Self::Error>
    where
        T: Any + Send + 'static,
    {
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
        self.entries.push((
            key.to_string(),
            PendingCipherText::Passthrough(Box::new(value)),
        ));
        Ok(self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        if self.current_key.is_some() {
            return Err(Unspecified);
        }
        Ok(PendingCipherText::Map(self.entries))
    }
}

// =============================================================================
// Decrypt side: a synchronous `Decipher` over already-recovered plaintext
// =============================================================================

/// Plaintext counterpart to [`ZeroKmsCipherText`], produced by [`decrypt_tree`]
/// once every leaf has been opened. [`PlaintextDecipher`] walks it structurally.
enum PlaintextTree {
    Single(Vec<u8>),
    Sequence(Vec<PlaintextTree>),
    Map(Vec<(String, PlaintextTree)>),
    None,
    Passthrough(Box<dyn Any + Send + 'static>),
}

/// A synchronous [`Decipher`] over a fully-decrypted [`PlaintextTree`]. It does
/// no crypto — decryption already happened in [`decrypt_tree`] — so it drives
/// the [`DecipherVisitor`] pattern purely structurally and ignores AAD.
struct PlaintextDecipher {
    tree: PlaintextTree,
}

impl<'c> Decipher<'c> for PlaintextDecipher {
    type Ok<T>
        = Result<T, Unspecified>
    where
        T: Send + 'c;

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
            PlaintextTree::Single(bytes) => visitor.visit_bytes_vec(Protected::new(bytes)),
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

    fn decrypt_passthrough<T>(self) -> Self::Ok<T>
    where
        T: Any + Send + 'static,
    {
        match self.tree {
            PlaintextTree::Passthrough(boxed) => {
                boxed.downcast::<T>().map(|b| *b).map_err(|_| Unspecified)
            }
            _ => Err(Unspecified),
        }
    }

    fn decrypt_option<'a, T, A>(self, _aad: A) -> Self::Ok<Option<T>>
    where
        T: Decrypt<'c> + 'c,
        A: IntoAad<'a>,
    {
        match self.tree {
            PlaintextTree::None => Ok(None),
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
