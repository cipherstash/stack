//! Opening a sealed leaf to the plaintext sealed in it.
//!
//! A sealed leaf carries a random AES-GCM nonce, so two ciphertexts of one
//! value never have the same bytes. What a test can compare is the
//! plaintext each leaf was sealed with. [`kept_cipher`] is a cipher over
//! [`DeterministicSource`] that keeps each data key it generates, and
//! [`reveal`] opens leaves with those keys and the engine's leaf AAD.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use stack_encrypt::{CipherText, Ciphertext, SealedValue, StackCipher, StackCipherText};
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, GenerateKeyPayload, IdentifiedBy, IndexKey,
    IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
};
use uuid::Uuid;
use vitaminc_aead::seal::Cipher;
use vitaminc_aead::{Context, FrameWriter, IntoContext, LocalCipherText, Unspecified};
use vitaminc_encrypt::{Aes256Cipher, Key as AesKey};
use vitaminc_protected::{Buffer, Controlled as _, Protected};

use super::{hex, DeterministicSource};

/// The data keys a [`KeptKeys`] source generated, by IV.
pub type Kept = Mutex<HashMap<Vec<u8>, [u8; 32]>>;

/// [`DeterministicSource`], keeping each data key it generates by its IV,
/// so a test can open the leaves sealed under them without the engine.
pub struct KeptKeys {
    inner: DeterministicSource,
    keys: Arc<Kept>,
}

impl stack_kms::KeySourceKind for KeptKeys {
    type Kind = stack_kms::OwnIdentity;
}

impl DataKeySource for KeptKeys {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
        let keys = self
            .inner
            .generate_keys(payloads, keyset_id, unverified_context)
            .await?;
        let mut kept = self.keys.lock().unwrap();
        for key in &keys {
            let _ = kept.insert(key.key.iv.to_vec(), *key.key.key());
        }
        Ok(keys)
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_kms::Error> {
        self.inner
            .retrieve_keys(payloads, keyset_id, unverified_context)
            .await
    }
}

impl IndexKeySource for KeptKeys {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
        self.inner.load_index_key(keyset_id).await
    }
}

/// A cipher over the kept keys of `seed`, and the keys.
pub async fn kept_cipher(seed: [u8; 32]) -> (StackCipher<KeptKeys>, Arc<Kept>) {
    let keys = Arc::default();
    let cipher = StackCipher::builder()
        .kms(KeptKeys {
            inner: DeterministicSource::new(seed),
            keys: Arc::clone(&keys),
        })
        .init()
        .await
        .expect("build cipher");
    (cipher, keys)
}

/// A vitaminc cipher that opens a stored leaf with its kept key, under the
/// AAD the engine binds a leaf to (`stack-encrypt/leaf`, the format version,
/// the keyset, the AAD of the leaf's place and the key tag, as a PAE), and
/// keeps each plaintext it opened, in walk order.
struct Reveal<'k> {
    keys: &'k HashMap<Vec<u8>, [u8; 32]>,
    opened: RefCell<Vec<String>>,
}

impl Cipher for Reveal<'_> {
    type Leaf = SealedValue;
    type Error = Unspecified;

    fn seal(&self, _: Protected<Vec<u8>>, _: &Context<'_>) -> Result<SealedValue, Unspecified> {
        Err(Unspecified)
    }

    fn open(
        &self,
        leaf: SealedValue,
        aad: &Context<'_>,
    ) -> Result<Protected<Vec<u8>>, Unspecified> {
        let (keyset_id, iv, tag, ciphertext) = leaf.into_parts();
        let key = self.keys.get(iv.as_slice()).ok_or(Unspecified)?;
        let aad = Context::pae(&[
            b"stack-encrypt/leaf",
            &[SealedValue::FORMAT_VERSION],
            keyset_id.as_bytes(),
            aad.as_bytes(),
            &tag,
        ]);
        let cipher = Aes256Cipher::new(&AesKey::from(*key))?;
        let plaintext = cipher.open(LocalCipherText::from(ciphertext), &aad)?;
        self.opened.borrow_mut().push(hex(plaintext.risky_ref()));
        Ok(plaintext)
    }
}

/// The plaintext of every leaf of `tree`, sealed under `context`, in walk
/// order: a scalar's tagged bytes, a typed null's padded bytes, and an empty
/// container's marker as the empty string.
pub fn reveal<'c>(
    keys: &Kept,
    tree: StackCipherText,
    context: impl IntoContext<'c>,
) -> Vec<String> {
    let keys = keys.lock().unwrap();
    let reveal = Reveal {
        keys: &keys,
        opened: RefCell::default(),
    };
    let mut out = Buffer::default();
    vitaminc_aead::decrypt_into(
        &reveal,
        tree,
        context.into_context(),
        FrameWriter::new(&mut out),
    )
    .unwrap_or_else(|_| {
        panic!(
            "the leaves open under their kept keys: if every case fails here, \
             the AAD `Reveal` builds no longer mirrors `leaf_aad` in src/cipher.rs"
        )
    });
    reveal.opened.into_inner()
}

/// Everything of a single ciphertext that does not depend on its leaf's
/// nonce. Two ciphertexts of one value, sealed under the same data key and
/// context, have the same parts and different bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct Parts {
    /// The ciphertext's bytes before the leaf's AEAD output, in hex: the
    /// format version, the keyset, the data key's IV, and its tag with the
    /// tag's length.
    pub header: String,
    /// The length of the whole ciphertext in bytes.
    pub len: usize,
    /// The plaintext the leaf was sealed with, in hex: its tag and payload.
    pub leaf: String,
}

/// The parts of `ciphertext`, sealed under `context`, opened with the keys
/// `keys` kept.
pub fn parts<'c>(keys: &Kept, ciphertext: Ciphertext, context: impl IntoContext<'c>) -> Parts {
    let bytes = ciphertext.to_bytes();
    // The leaf's AEAD output is the last part of the bytes: its nonce, the
    // encrypted plaintext and the authentication tag.
    let (_, _, _, sealed) = SealedValue::from(ciphertext.clone()).into_parts();
    let header = hex(&bytes[..bytes.len() - sealed.len()]);
    let leaf = SealedValue::from(ciphertext);
    let mut leaves = reveal(keys, CipherText::Single(leaf), context);
    assert_eq!(leaves.len(), 1, "a ciphertext is one leaf");
    Parts {
        header,
        len: bytes.len(),
        leaf: leaves.remove(0),
    }
}
