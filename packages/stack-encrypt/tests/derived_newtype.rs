//! `keyset.encrypt` encrypts a newtype that derives `Encrypt` exactly as it
//! encrypts the newtype's inner value.
//!
//! A leaf is one sealed value. Each leaf has a random nonce, a number used
//! once. So two ciphertexts of one value never have the same bytes. These
//! tests compare what the nonce does not change:
//!
//! - the plaintext of each leaf, opened with the data key that the key
//!   source generated for it
//! - the length of the stored bytes
//!
//! The tests also check that each ciphertext decrypts into the inner type.

mod common;

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::{hex, DeterministicSource};
use stack_encrypt::{CipherText, Ciphertext, Encrypt, SealedValue, StackCipher};
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, GenerateKeyPayload, IdentifiedBy, IndexKey,
    IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
};
use uuid::Uuid;
use vitaminc_aead::seal::Cipher;
use vitaminc_aead::{Context, FrameWriter, IntoContext, LocalCipherText, Unspecified};
use vitaminc_encrypt::{Aes256Cipher, Key as AesKey};
use vitaminc_protected::{Buffer, Controlled as _, Protected};
use zeroize::Zeroize;

#[derive(Encrypt, Zeroize)]
struct Email(String);

#[derive(Encrypt, Zeroize)]
struct Age(i64);

const SEED: [u8; 32] = *b"stack-encrypt derived newtype v1";

/// The data keys that a [`KeptKeys`] source generated, by initialisation
/// vector (IV).
type Kept = Mutex<HashMap<Vec<u8>, [u8; 32]>>;

/// A [`DeterministicSource`] that also stores each data key it generates,
/// by its IV. A test uses the stored keys to open leaves without the engine.
struct KeptKeys {
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

/// A cipher over a [`KeptKeys`] source, and the keys that the source stores.
async fn kept_cipher() -> (StackCipher<KeptKeys>, Arc<Kept>) {
    let keys = Arc::default();
    let cipher = StackCipher::builder()
        .kms(KeptKeys {
            inner: DeterministicSource::new(SEED),
            keys: Arc::clone(&keys),
        })
        .init()
        .await
        .expect("build cipher");
    (cipher, keys)
}

/// A Vitamin C cipher that opens a stored leaf with the data key stored for
/// it, and records each plaintext it opens.
///
/// The cipher opens the leaf under the associated data (AAD) that the
/// engine seals a leaf under. That AAD is a pre-authentication encoding
/// (PAE) of five parts:
///
/// - the label `stack-encrypt/leaf`
/// - the format version
/// - the keyset
/// - the AAD of the leaf's place in the value
/// - the key tag
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

/// The plaintext of `ciphertext`, as hex, opened under `context`.
fn reveal<'c>(keys: &Kept, ciphertext: Ciphertext, context: impl IntoContext<'c>) -> String {
    let keys = keys.lock().unwrap();
    let reveal = Reveal {
        keys: &keys,
        opened: RefCell::default(),
    };
    let mut out = Buffer::default();
    vitaminc_aead::decrypt_into(
        &reveal,
        CipherText::Single(SealedValue::from(ciphertext)),
        context.into_context(),
        FrameWriter::new(&mut out),
    )
    .unwrap_or_else(|_| {
        panic!(
            "the leaf must open with its stored data key. If every test fails here, \
             the AAD that `Reveal` builds differs from `leaf_aad` in src/cipher.rs"
        )
    });
    let mut opened = reveal.opened.into_inner();
    assert_eq!(opened.len(), 1, "a `Ciphertext` holds one leaf");
    opened.remove(0)
}

#[tokio::test]
async fn a_newtype_over_a_string_seals_the_leaf_a_string_seals() {
    let (cipher, keys) = kept_cipher().await;
    let keyset = cipher.default_keyset();

    let wrapped = keyset
        .encrypt(Email("ada@example.com".into()))
        .await
        .expect("a newtype over a string encrypts");
    let bare = keyset
        .encrypt(String::from("ada@example.com"))
        .await
        .expect("a string encrypts");

    assert_eq!(
        wrapped.to_bytes().len(),
        bare.to_bytes().len(),
        "the newtype's ciphertext is as long as its inner value's"
    );
    let opened: String = keyset
        .decrypt(wrapped.clone())
        .await
        .expect("the newtype's ciphertext decrypts into its inner type");
    assert_eq!(
        opened, "ada@example.com",
        "the newtype's ciphertext decrypts to its inner value"
    );
    assert_eq!(
        reveal(&keys, wrapped, ()),
        reveal(&keys, bare, ()),
        "the newtype's leaf holds the plaintext its inner value's leaf holds"
    );
}

#[tokio::test]
async fn a_newtype_over_an_integer_seals_the_leaf_an_integer_seals() {
    let (cipher, keys) = kept_cipher().await;
    let keyset = cipher.default_keyset();
    let context = ("users", "age");

    let wrapped = keyset
        .encrypt_with_context(Age(37), context)
        .await
        .expect("a newtype over an integer encrypts");
    let bare = keyset
        .encrypt_with_context(37i64, context)
        .await
        .expect("an integer encrypts");

    assert_eq!(
        wrapped.to_bytes().len(),
        bare.to_bytes().len(),
        "the newtype's ciphertext is as long as its inner value's"
    );
    let opened: i64 = keyset
        .decrypt_with_context(wrapped.clone(), context)
        .await
        .expect("the newtype's ciphertext decrypts into its inner type");
    assert_eq!(
        opened, 37,
        "the newtype's ciphertext decrypts to its inner value"
    );
    assert_eq!(
        reveal(&keys, wrapped, context),
        reveal(&keys, bare, context),
        "the newtype's leaf holds the plaintext its inner value's leaf holds"
    );
}
