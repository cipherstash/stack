//! Tests for `OpaqueBlob<T>`, which encrypts a whole value as one
//! ciphertext. They cover round trips, collections of blobs, the stored
//! format shared with the structural writer and the Go SDK, refusals, and
//! cleanup. No service credentials are needed.
//!
//! The file has two parts: the types, constants and helpers the tests
//! share, then the tests, in one module per scenario.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use stack_encrypt::blob::{HEADER, VERSION};
use stack_encrypt::{
    BlobError, CipherText, Ciphertext, Controlled, DecryptFrom, EncryptInto, Error, KeysetCipher,
    OpaqueBlob, SealedValue,
};
use zeroize::{Zeroize, Zeroizing};

mod common;

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// The value most tests encrypt.
#[derive(Serialize, Deserialize, Zeroize, Clone, PartialEq, Debug)]
struct Profile {
    name: String,
    age: u32,
    tags: Vec<String>,
    nickname: Option<String>,
}

fn ada() -> Profile {
    Profile {
        name: "Ada Lovelace".into(),
        age: 36,
        tags: vec!["maths".into(), "engines".into()],
        nickname: Some("ada".into()),
    }
}

fn grace() -> Profile {
    Profile {
        name: "Grace Hopper".into(),
        age: 85,
        tags: vec!["compilers".into()],
        nickname: None,
    }
}

/// A value of a different shape from [`Profile`].
#[derive(Serialize, Deserialize, Zeroize, PartialEq, Debug)]
struct Pair {
    left: String,
    right: u32,
}

/// A later version of [`Profile`] that still reads an old blob: a wider
/// integer, a renamed field with an alias, and two new fields with defaults.
#[derive(Deserialize, Zeroize, PartialEq, Debug)]
struct ProfileV2 {
    name: String,
    age: u64,
    #[serde(alias = "tags")]
    labels: Vec<String>,
    nickname: Option<String>,
    #[serde(default)]
    verified: bool,
    #[serde(default)]
    title: Option<String>,
}

/// A later version of [`Profile`] with a new field and no default, so it
/// cannot read an old blob.
#[derive(Deserialize, Zeroize)]
#[allow(dead_code)]
struct ProfileWithRequiredField {
    name: String,
    age: u8,
    tags: Vec<String>,
    nickname: Option<String>,
    verified: bool,
}

/// [`Profile`] with fewer fields and a narrower integer.
#[derive(Deserialize, Zeroize)]
#[allow(dead_code)]
struct NarrowProfile {
    name: String,
    age: u8,
}

/// A byte string written as bytes, not as a sequence of `u8`.
#[derive(Serialize, Deserialize, Zeroize, PartialEq, Debug)]
struct RawBytes(#[serde(with = "serde_bytes_shim")] Vec<u8>);

/// `serde_bytes` without the dependency: write and read a `Vec<u8>` as bytes.
mod serde_bytes_shim {
    pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        struct BytesVisitor;
        impl serde::de::Visitor<'_> for BytesVisitor {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
        }
        d.deserialize_bytes(BytesVisitor)
    }
}

// ---------------------------------------------------------------------------
// Values that record their own cleanup
// ---------------------------------------------------------------------------

/// A value whose `Serialize` always fails. It records when it is wiped, and
/// panics if it is dropped without being wiped.
struct Refusing {
    secret: String,
    wiped: Arc<AtomicBool>,
}

impl Serialize for Refusing {
    fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            "this value refuses to be written",
        ))
    }
}

impl Zeroize for Refusing {
    fn zeroize(&mut self) {
        self.secret.zeroize();
        self.wiped.store(true, Ordering::SeqCst);
    }
}

impl Drop for Refusing {
    fn drop(&mut self) {
        assert!(
            self.secret.is_empty(),
            "owned source dropped without wiping"
        );
    }
}

fn refusing() -> (OpaqueBlob<Refusing>, Arc<AtomicBool>) {
    let wiped = Arc::new(AtomicBool::new(false));
    let blob = OpaqueBlob::new(Refusing {
        secret: "secret".into(),
        wiped: wiped.clone(),
    });
    (blob, wiped)
}

/// A value that records when it is wiped, and panics if it is dropped
/// without being wiped. Deliberately not `Clone`.
#[derive(Serialize)]
struct Tracked {
    value: String,
    #[serde(skip)]
    wiped: Arc<AtomicBool>,
}

impl Zeroize for Tracked {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.wiped.store(true, Ordering::SeqCst);
    }
}

impl Drop for Tracked {
    fn drop(&mut self) {
        assert!(self.value.is_empty(), "owned source dropped without wiping");
    }
}

fn tracked() -> (OpaqueBlob<Tracked>, Arc<AtomicBool>) {
    let wiped = Arc::new(AtomicBool::new(false));
    let blob = OpaqueBlob::new(Tracked {
        value: "secret".into(),
        wiped: wiped.clone(),
    });
    (blob, wiped)
}

/// [`Tracked`] as it decrypts.
#[derive(Deserialize, Zeroize)]
struct TrackedRead {
    value: String,
}

/// How many times a [`Witness`] has been wiped. Only one test uses it, and
/// nextest runs each test in its own process.
static WITNESS_WIPES: AtomicUsize = AtomicUsize::new(0);

/// A value that counts its wipes in [`WITNESS_WIPES`].
#[derive(Serialize, Deserialize)]
struct Witness {
    value: String,
}

impl Zeroize for Witness {
    fn zeroize(&mut self) {
        self.value.zeroize();
        WITNESS_WIPES.fetch_add(1, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// Pinned bytes
// ---------------------------------------------------------------------------

/// `ada()` as a version 1 storage blob, written by this crate. The Go SDK's
/// `TestOpaqueReadsARustWrittenBlob` (`languages/golang/encrypt/gensupport`)
/// reads the same hex: Rust writes, Go reads.
const RUST_BLOB: &str = "56435301f104000000040000006e616d650a0c000000416461204c6f76656c6163650300000061676506240000000400000074616773f0020000000a050000006d617468730a07000000656e67696e6573080000006e69636b6e616d65f50a03000000616461";

/// `ada()` as the Go SDK writes it, through `vcffi.MarshalStorage`, from a
/// struct with the tags `vc:"name"`, `vc:"age"`, `vc:"tags"` and
/// `vc:"nickname"`, where the nickname is a non-nil `*string`. Go writes a
/// non-nil pointer as the bare value, and Rust writes `Some` with a marker
/// byte, so this is one byte shorter than [`RUST_BLOB`]. The Go test
/// `TestOpaqueReadsARustWrittenBlob` pins the same hex.
const GO_BLOB_SOME: &str = "56435301f104000000040000006e616d650a0c000000416461204c6f76656c6163650300000061676506240000000400000074616773f0020000000a050000006d617468730a07000000656e67696e6573080000006e69636b6e616d650a03000000616461";

/// [`GO_BLOB_SOME`] with the nickname a nil pointer, which Go writes as null.
const GO_BLOB_NONE: &str = "56435301f104000000040000006e616d650a0c000000416461204c6f76656c6163650300000061676506240000000400000074616773f0020000000a050000006d617468730a07000000656e67696e6573080000006e69636b6e616d6500";

/// `OpaqueBlob::new(ada())` sealed under `"users/profile"` through
/// [`FixedKeySource`] by the build that introduced `OpaqueBlob`. Vitamin C
/// chooses the AEAD nonce itself, so a new seal never reproduces these
/// bytes. They are pinned to show that later builds open what this one
/// wrote.
const PINNED_CIPHERTEXT: &str = "010000000000000000000000000000000066697865642d69762d70696e6e6564210d0066697865642d6b65792d7461670232e68c36bf5fa752e06eea1f8625c96dd4aa0ea1eceaf8b2414db5c09282bbc92a653bab98e7e715db1c56b063d461fa50297f1473be2faf29413c7bc9b292e6186a60661dccddd63576fc98e22bf32202f000251b49d1fbdb67bf1bcf1a8c666d4de9dabe7a1cbf5b67834c3ece6c458d7ceb7435ce5dcd68b216c326a4d933cb748c";

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

// ---------------------------------------------------------------------------
// A key source with one fixed data key
// ---------------------------------------------------------------------------

const FIXED_KEY: [u8; 32] = *b"fixed-data-key-for-pinned-blob!!";
const FIXED_IV: [u8; 16] = *b"fixed-iv-pinned!";
const FIXED_TAG: &[u8] = b"fixed-key-tag";

/// Hands out one fixed data key, IV and key tag for every request, so a
/// ciphertext sealed once can be pinned and opened by any later build.
struct FixedKeySource(stack_kms::FakeDataKeySource);

impl stack_kms::DataKeySource for FixedKeySource {
    async fn generate_keys(
        &self,
        payloads: Vec<stack_kms::GenerateKeyPayload<'_>>,
        _: Option<uuid::Uuid>,
        _: Option<std::borrow::Cow<'_, stack_kms::UnverifiedContext>>,
    ) -> Result<Vec<stack_kms::DataKeyWithTag>, stack_kms::Error> {
        Ok(payloads
            .into_iter()
            .map(|payload| stack_kms::DataKeyWithTag {
                key: stack_kms::DataKey {
                    iv: FIXED_IV,
                    key: FIXED_KEY,
                },
                tag: FIXED_TAG.to_vec(),
                decryption_policy: payload.decryption_policy,
            })
            .collect())
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<stack_kms::RetrieveKeyPayload<'_>>,
        _: Option<uuid::Uuid>,
        _: Option<&stack_kms::UnverifiedContext>,
    ) -> Result<Vec<stack_kms::DataKey>, stack_kms::Error> {
        Ok(payloads
            .iter()
            .map(|_| stack_kms::DataKey {
                iv: FIXED_IV,
                key: FIXED_KEY,
            })
            .collect())
    }
}

impl stack_kms::IndexKeySource for FixedKeySource {
    async fn load_index_key(
        &self,
        keyset: Option<stack_kms::IdentifiedBy>,
    ) -> Result<(uuid::Uuid, stack_kms::IndexKey), stack_kms::Error> {
        self.0.load_index_key(keyset).await
    }
}

async fn fixed_cipher() -> stack_encrypt::StackCipher<FixedKeySource> {
    stack_encrypt::StackCipher::builder()
        .kms(FixedKeySource(stack_kms::FakeDataKeySource::new()))
        .init()
        .await
        .expect("build cipher")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Seal `bytes` as one bytes leaf through the structural writer, as the Go
/// engine seals an opaque struct, and return it as a `Ciphertext`.
async fn seal_bytes<K: stack_kms::DataKeySource + stack_kms::IndexKeySource + 'static>(
    keyset: &KeysetCipher<'_, K>,
    bytes: Vec<u8>,
    context: &'static str,
) -> Ciphertext {
    let tree = keyset
        .encrypt_tree(bytes, context)
        .await
        .expect("encrypt bytes");
    let CipherText::Single(leaf) = tree else {
        panic!("a Vec<u8> should seal as one leaf")
    };
    Ciphertext::from(leaf)
}

mod assertions {
    /// `text` names none of `ada()`'s plaintext.
    pub fn shows_no_plaintext(text: &str) {
        for word in ["Ada", "Lovelace", "maths", "engines", "ada"] {
            assert!(!text.contains(word), "{word:?} should not appear in {text}");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

mod round_trip {
    use super::*;

    #[tokio::test]
    async fn without_a_context_returns_the_value() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();

        let ct = keyset.encrypt(OpaqueBlob::new(ada())).await.unwrap();
        let opened: OpaqueBlob<Profile> = keyset.decrypt(ct).await.unwrap();

        assert_eq!(*opened.into_inner(), ada(), "the value should round trip");
    }

    #[tokio::test]
    async fn with_a_context_returns_the_value() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();

        let ct = keyset
            .encrypt_with_context(OpaqueBlob::new(ada()), ("users", "profile"))
            .await
            .unwrap();
        let opened = keyset
            .decrypt_with_context::<OpaqueBlob<Profile>>(ct, ("users", "profile"))
            .await
            .unwrap();

        assert_eq!(opened.get(), &ada(), "the value should round trip");
    }

    #[tokio::test]
    async fn through_the_owned_conversions_returns_the_value() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();

        let ct: Ciphertext = OpaqueBlob::new(ada())
            .encrypt_into_with_context(&keyset, ("users", "profile"))
            .await
            .unwrap();
        let opened =
            OpaqueBlob::<Profile>::decrypt_from_with_context(ct, &keyset, ("users", "profile"))
                .await
                .unwrap();
        assert_eq!(
            *opened.into_inner(),
            ada(),
            "the value should round trip with a context"
        );

        let ct: Ciphertext = OpaqueBlob::new(ada()).encrypt_into(&keyset).await.unwrap();
        let opened = OpaqueBlob::<Profile>::decrypt_from(ct, &keyset)
            .await
            .unwrap();
        assert_eq!(
            *opened.into_inner(),
            ada(),
            "the value should round trip without a context"
        );
    }

    /// One blob is one data key: the whole struct costs one generate call,
    /// where the structural writer would ask for one key per leaf.
    #[tokio::test]
    async fn uses_one_data_key() {
        let (cipher, generates, retrieves) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();

        let ct = keyset.encrypt(OpaqueBlob::new(ada())).await.unwrap();
        assert_eq!(
            generates.load(Ordering::SeqCst),
            1,
            "encrypting should make one generate call"
        );

        let _: OpaqueBlob<Profile> = keyset.decrypt(ct).await.unwrap();
        assert_eq!(
            retrieves.load(Ordering::SeqCst),
            1,
            "decrypting should make one retrieve call"
        );
    }
}

/// A `Vec<OpaqueBlob<T>>` is a collection: each element is its own
/// ciphertext, and the keys for all of them are requested in one batch. An
/// `OpaqueBlob<Vec<T>>` is one ciphertext holding the whole `Vec`.
mod given_a_vec_of_blobs {
    use super::*;

    fn blobs() -> Vec<OpaqueBlob<Profile>> {
        vec![OpaqueBlob::new(ada()), OpaqueBlob::new(grace())]
    }

    #[tokio::test]
    async fn encrypts_each_element_as_its_own_ciphertext() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();

        let cts: Vec<Ciphertext> = blobs()
            .encrypt_into_with_context(&keyset, ("users", "profile"))
            .await
            .unwrap();
        assert_eq!(cts.len(), 2, "there should be one ciphertext per element");

        // Each element opens on its own, as one row would.
        let second = keyset
            .decrypt_with_context::<OpaqueBlob<Profile>>(cts[1].clone(), ("users", "profile"))
            .await
            .unwrap();
        assert_eq!(
            *second.into_inner(),
            grace(),
            "the second element should open alone"
        );

        let opened = Vec::<OpaqueBlob<Profile>>::decrypt_from_with_context(
            cts,
            &keyset,
            ("users", "profile"),
        )
        .await
        .unwrap();
        let opened: Vec<Profile> = opened.into_iter().map(|b| b.get().clone()).collect();
        assert_eq!(
            opened,
            [ada(), grace()],
            "the collection should round trip in order"
        );
    }

    #[tokio::test]
    async fn requests_every_key_in_one_batch() {
        let (cipher, generates, retrieves) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();

        let cts: Vec<Ciphertext> = blobs().encrypt_into(&keyset).await.unwrap();
        assert_eq!(
            generates.load(Ordering::SeqCst),
            1,
            "encrypting two blobs should make one generate call"
        );

        let _ = Vec::<OpaqueBlob<Profile>>::decrypt_from(cts, &keyset)
            .await
            .unwrap();
        assert_eq!(
            retrieves.load(Ordering::SeqCst),
            1,
            "decrypting two blobs should make one retrieve call"
        );
    }

    #[tokio::test]
    async fn a_blob_of_a_vec_is_one_ciphertext() {
        let (cipher, generates, _) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();

        let ct = keyset
            .encrypt(OpaqueBlob::new(vec![ada(), grace()]))
            .await
            .unwrap();
        assert_eq!(
            generates.load(Ordering::SeqCst),
            1,
            "a blob of a Vec should use one data key"
        );

        let opened: OpaqueBlob<Vec<Profile>> = keyset.decrypt(ct).await.unwrap();
        assert_eq!(
            *opened.into_inner(),
            [ada(), grace()],
            "the whole Vec should round trip"
        );
    }
}

/// The stored format: a blob is the storage profile's bytes, sealed as one
/// bytes leaf of the ordinary envelope.
mod stored_format {
    use super::*;

    /// A change here is a change to what every stored blob holds, and to
    /// what Go reads.
    #[test]
    fn the_blob_this_crate_writes_is_pinned() {
        let encoded = OpaqueBlob::new(ada()).encode().unwrap();

        assert_eq!(
            encoded.risky_ref(),
            &unhex(RUST_BLOB),
            "the encoded blob should match RUST_BLOB"
        );
        assert_eq!(VERSION, 1, "this release should write version 1");
        assert_eq!(
            encoded.risky_ref()[3],
            VERSION,
            "the fourth byte should be the version"
        );
    }

    /// What the structural writer seals for a `Vec<u8>` of the encoded
    /// bytes is what `OpaqueBlob` seals, so each opens the other's.
    #[tokio::test]
    async fn the_structural_writer_and_opaque_blob_open_each_other() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();

        let encoded = OpaqueBlob::new(ada()).encode().unwrap();
        assert_eq!(
            &encoded.risky_ref()[..4],
            &HEADER,
            "the blob should start with the header"
        );
        let ct = seal_bytes(&keyset, encoded.risky_ref().clone(), "users/profile").await;
        let opened = keyset
            .decrypt_with_context::<OpaqueBlob<Profile>>(ct, "users/profile")
            .await
            .unwrap();
        assert_eq!(
            *opened.into_inner(),
            ada(),
            "bytes sealed by the structural writer should open as a blob"
        );

        let ct = keyset
            .encrypt_with_context(OpaqueBlob::new(ada()), "users/profile")
            .await
            .unwrap();
        let bytes: Vec<u8> = cipher
            .decrypt(CipherText::Single(SealedValue::from(ct)), "users/profile")
            .await
            .unwrap();
        assert_eq!(
            *OpaqueBlob::<Profile>::decode(&bytes).unwrap().into_inner(),
            ada(),
            "a blob should open as bytes through the structural reader"
        );
    }

    /// The leaf is a plain bytes leaf, holding the encoded blob, never the
    /// raw bytes of the value. Nothing in the leaf marks it as a blob, so a
    /// blob also opens as a `Vec<u8>` and gives back the encoded blob. What
    /// keeps a bare value from being sealed without the wrapper is the
    /// compile-fail half, `tests/ui/opaque_blob_*.rs`.
    #[tokio::test]
    async fn a_blob_of_bytes_holds_the_encoded_blob() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();

        let ct = keyset
            .encrypt(OpaqueBlob::new(RawBytes(b"hello".to_vec())))
            .await
            .unwrap();

        let bytes: Vec<u8> = keyset.decrypt(ct.clone()).await.unwrap();
        assert_eq!(
            &bytes[..4],
            &HEADER,
            "opened as a Vec<u8>, the leaf should hold the encoded blob"
        );
        let opened = keyset.decrypt::<OpaqueBlob<RawBytes>>(ct).await.unwrap();
        assert_eq!(
            *opened.into_inner(),
            RawBytes(b"hello".to_vec()),
            "opened as a blob, the value should round trip"
        );
    }

    /// A ciphertext pinned by an earlier build still opens. Under no
    /// context, or the wrong one, it never reaches the blob.
    #[tokio::test]
    async fn a_pinned_ciphertext_opens() {
        let cipher = fixed_cipher().await;
        let keyset = cipher.default_keyset();
        let bytes = unhex(PINNED_CIPHERTEXT);
        let ct = Ciphertext::from_bytes(&bytes).unwrap();
        assert_eq!(
            ct.key_tag(),
            FIXED_TAG,
            "the key tag should be the fixed one"
        );
        assert_eq!(
            ct.to_bytes(),
            bytes,
            "the ciphertext should re-encode unchanged"
        );

        let opened = keyset
            .decrypt_with_context::<OpaqueBlob<Profile>>(ct.clone(), "users/profile")
            .await
            .unwrap();
        assert_eq!(
            *opened.into_inner(),
            ada(),
            "the pinned ciphertext should open"
        );

        let no_context = keyset.decrypt::<OpaqueBlob<Profile>>(ct.clone()).await;
        assert!(
            matches!(no_context, Err(Error::Aead)),
            "no context should fail the AEAD, got {no_context:?}"
        );
        let wrong_context = keyset
            .decrypt_with_context::<OpaqueBlob<Profile>>(ct, "users/other")
            .await;
        assert!(
            matches!(wrong_context, Err(Error::Aead)),
            "the wrong context should fail the AEAD, got {wrong_context:?}"
        );
    }

    /// The documented disclosure: the ciphertext is the encoded length plus
    /// a fixed overhead, so a present optional field shows in its length.
    #[tokio::test]
    async fn the_ciphertext_length_is_the_encoded_length_plus_a_constant() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let lengths = |profile: Profile| async {
            let blob = OpaqueBlob::new(profile.clone()).encode().unwrap();
            let ct = keyset.encrypt(OpaqueBlob::new(profile)).await.unwrap();
            (blob.risky_ref().len(), ct.to_bytes().len())
        };

        let (with_len, with_ct) = lengths(ada()).await;
        let (without_len, without_ct) = lengths(Profile {
            nickname: None,
            ..ada()
        })
        .await;

        // `Some("ada")` is a marker, a text tag, a u32 length and three
        // bytes. `None` is one null byte.
        assert_eq!(
            with_len - without_len,
            1 + 1 + 4 + 3 - 1,
            "the encoded lengths should differ by the nickname's encoding"
        );
        assert_eq!(
            with_ct - without_ct,
            with_len - without_len,
            "the ciphertexts should differ by as much as the encodings"
        );
        assert_eq!(
            with_ct - with_len,
            without_ct - without_len,
            "the overhead should be the same for both"
        );
    }
}

/// Go writes, Rust reads. The Go engine seals an opaque struct as a bytes
/// leaf under `<context>/value`.
mod given_a_go_written_blob {
    use super::*;

    #[test]
    fn decodes_with_the_optional_field_present_or_absent() {
        let with_nickname = OpaqueBlob::<Profile>::decode(&unhex(GO_BLOB_SOME)).unwrap();
        assert_eq!(
            *with_nickname.into_inner(),
            ada(),
            "Go's bare value should read as Some"
        );

        let without = OpaqueBlob::<Profile>::decode(&unhex(GO_BLOB_NONE)).unwrap();
        assert_eq!(
            *without.into_inner(),
            Profile {
                nickname: None,
                ..ada()
            },
            "Go's null should read as None"
        );
    }

    #[test]
    fn is_one_byte_shorter_than_rusts() {
        assert_eq!(
            unhex(GO_BLOB_SOME).len() + 1,
            unhex(RUST_BLOB).len(),
            "Go writes Some as the bare value; Rust adds one marker byte"
        );
    }

    #[tokio::test]
    async fn opens_from_a_sealed_ciphertext() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let tree = keyset
            .encrypt_tree(unhex(GO_BLOB_SOME), ("users", "value"))
            .await
            .unwrap();
        let CipherText::Single(leaf) = tree else {
            panic!("bytes should seal as one leaf")
        };

        let opened = keyset
            .decrypt_with_context::<OpaqueBlob<Profile>>(Ciphertext::from(leaf), ("users", "value"))
            .await
            .unwrap();

        assert_eq!(
            *opened.into_inner(),
            ada(),
            "the Go blob should open in Rust"
        );
    }
}

/// Tampering is refused by the AEAD before any byte of the blob is read.
/// The leaf's kind is bound too, so a scalar opened as a blob, or a blob as
/// a scalar other than bytes, is a shape refusal of an authentic
/// ciphertext, not a blob error.
mod given_a_ciphertext_that_is_not_this_blob {
    use super::*;

    async fn sealed_profile(keyset: &KeysetCipher<'_, stack_kms::FakeDataKeySource>) -> Ciphertext {
        keyset
            .encrypt_with_context(OpaqueBlob::new(ada()), "users/profile")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_tampered_ciphertext_fails_the_aead() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let mut bytes = sealed_profile(&keyset).await.to_bytes();
        *bytes.last_mut().unwrap() ^= 1;
        let tampered = Ciphertext::from_bytes(&bytes).unwrap();

        let result = keyset
            .decrypt_with_context::<OpaqueBlob<Profile>>(tampered, "users/profile")
            .await;

        assert!(
            matches!(result, Err(Error::Aead)),
            "a tampered ciphertext should fail the AEAD, got {result:?}"
        );
    }

    #[tokio::test]
    async fn the_wrong_context_fails_the_aead() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let ct = sealed_profile(&keyset).await;

        let result = keyset
            .decrypt_with_context::<OpaqueBlob<Profile>>(ct, "users/other")
            .await;

        assert!(
            matches!(result, Err(Error::Aead)),
            "the wrong context should fail the AEAD, got {result:?}"
        );
    }

    #[tokio::test]
    async fn a_blob_opened_as_a_string_is_the_wrong_type() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let ct = sealed_profile(&keyset).await;

        let result = keyset
            .decrypt_with_context::<String>(ct, "users/profile")
            .await;

        assert!(
            matches!(result, Err(Error::OpenedType { .. })),
            "a bytes leaf opened as text should be OpenedType, got {result:?}"
        );
    }

    #[tokio::test]
    async fn a_string_opened_as_a_blob_is_the_wrong_type() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let text = keyset
            .encrypt_with_context("VCS\u{1}".to_owned(), "users/profile")
            .await
            .unwrap();

        let result = keyset
            .decrypt_with_context::<OpaqueBlob<Profile>>(text, "users/profile")
            .await;

        assert!(
            matches!(result, Err(Error::OpenedType { .. })),
            "a text leaf opened as a blob should be OpenedType, got {result:?}"
        );
    }

    /// Bytes that are not a blob this type reads are refused by class. The
    /// ciphertext is authentic in every case, and each refusal comes after
    /// the key was retrieved: authentication first.
    #[tokio::test]
    async fn bytes_that_are_not_a_profile_are_refused_by_class() {
        let (cipher, _, retrieves) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let open = |bytes: Vec<u8>| async {
            let ct = seal_bytes(&keyset, bytes, "users/profile").await;
            keyset
                .decrypt_with_context::<OpaqueBlob<Profile>>(ct, "users/profile")
                .await
                .unwrap_err()
        };
        let blob = OpaqueBlob::new(ada()).encode().unwrap();
        let blob = blob.risky_ref();

        let plain = open(b"hello".to_vec()).await;
        assert!(
            matches!(plain, Error::Blob(BlobError::NotABlob)),
            "plain bytes should be NotABlob, got {plain:?}"
        );
        let json = open(b"{\"name\":\"Ada\"}".to_vec()).await;
        assert!(
            matches!(json, Error::Blob(BlobError::NotABlob)),
            "JSON should be NotABlob, got {json:?}"
        );

        let mut later = blob.clone();
        later[3] = VERSION + 1;
        let later = open(later).await;
        assert!(
            matches!(later, Error::Blob(BlobError::UnsupportedVersion { version }) if version == VERSION + 1),
            "a later version should be UnsupportedVersion, got {later:?}"
        );

        let truncated = open(blob[..blob.len() - 3].to_vec()).await;
        assert!(
            matches!(truncated, Error::Blob(BlobError::Malformed(_))),
            "a truncated blob should be Malformed, got {truncated:?}"
        );
        let mut trailing = blob.clone();
        trailing.push(0);
        let trailing = open(trailing).await;
        assert!(
            matches!(trailing, Error::Blob(BlobError::Malformed(_))),
            "trailing bytes should be Malformed, got {trailing:?}"
        );

        let pair = OpaqueBlob::new(Pair {
            left: "l".into(),
            right: 1,
        })
        .encode()
        .unwrap();
        let mismatch = open(pair.risky_ref().clone()).await;
        assert!(
            matches!(mismatch, Error::Blob(BlobError::Mismatch(_))),
            "another shape should be Mismatch, got {mismatch:?}"
        );

        assert_eq!(
            retrieves.load(Ordering::SeqCst),
            6,
            "every refusal should come after a key retrieval"
        );
        let shown = format!("{mismatch} {mismatch:?}");
        assert!(
            !shown.contains("\"l\""),
            "the refusal should name the field, never the value: {shown}"
        );
    }
}

/// Schema evolution follows serde: a default for a new field, an alias for
/// a renamed one and a wider integer all read an old blob.
mod given_a_later_version_of_the_type {
    use super::*;

    #[tokio::test]
    async fn defaults_aliases_and_wider_integers_read_an_old_blob() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let ct = keyset.encrypt(OpaqueBlob::new(ada())).await.unwrap();

        let later = keyset
            .decrypt::<OpaqueBlob<ProfileV2>>(ct)
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            *later,
            ProfileV2 {
                name: "Ada Lovelace".into(),
                age: 36,
                labels: vec!["maths".into(), "engines".into()],
                nickname: Some("ada".into()),
                verified: false,
                title: None,
            },
            "the old blob should read as the new type"
        );
    }

    #[tokio::test]
    async fn a_new_field_without_a_default_is_a_mismatch() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let ct = keyset.encrypt(OpaqueBlob::new(ada())).await.unwrap();

        let result = keyset
            .decrypt::<OpaqueBlob<ProfileWithRequiredField>>(ct)
            .await;

        assert!(
            matches!(result, Err(Error::Blob(BlobError::Mismatch(_)))),
            "a missing required field should be Mismatch, got {:?}",
            result.as_ref().map(|_| ())
        );
    }

    #[tokio::test]
    async fn a_narrower_integer_reads_a_value_that_fits() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let ct = keyset.encrypt(OpaqueBlob::new(ada())).await.unwrap();

        let narrow = keyset
            .decrypt::<OpaqueBlob<NarrowProfile>>(ct)
            .await
            .unwrap();

        assert_eq!(narrow.get().age, 36, "36 should fit in a u8");
    }
}

/// What is wiped, and when, on encrypt.
mod given_an_owned_source {
    use super::*;

    /// The source is encoded and wiped before `encrypt` returns, so a
    /// pending that is dropped unpolled carries no plaintext and makes no
    /// key request.
    #[tokio::test]
    async fn is_wiped_before_a_pending_is_dropped_unpolled() {
        let (cipher, generates, _) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let (source, wiped) = tracked();

        let pending = keyset.encrypt(source);
        assert!(
            wiped.load(Ordering::SeqCst),
            "encrypt should wipe the source before it returns"
        );
        drop(pending);

        assert_eq!(
            generates.load(Ordering::SeqCst),
            0,
            "an unpolled pending should request no key"
        );
    }

    #[tokio::test]
    async fn is_wiped_before_a_pending_is_awaited() {
        let (cipher, generates, _) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let (source, wiped) = tracked();

        let pending = keyset.encrypt_with_context(source, "users/secret");
        assert!(
            wiped.load(Ordering::SeqCst),
            "encrypt should wipe the source before it returns"
        );
        let ct = pending.await.unwrap();
        assert_eq!(
            generates.load(Ordering::SeqCst),
            1,
            "awaiting should make one generate call"
        );

        let opened = keyset
            .decrypt_with_context::<OpaqueBlob<TrackedRead>>(ct, "users/secret")
            .await
            .unwrap();
        assert_eq!(
            opened.get().value,
            "secret",
            "the value should round trip after the source was wiped"
        );
    }

    #[tokio::test]
    async fn is_wiped_when_the_context_is_refused() {
        let (cipher, generates, _) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let (source, wiped) = tracked();

        let pending = keyset.encrypt_with_context(source, "x".repeat(65536));
        assert!(
            wiped.load(Ordering::SeqCst),
            "a refused context should still wipe the source"
        );
        let result = pending.await;

        assert!(
            matches!(result, Err(Error::DescriptorTooLong { .. })),
            "an over-long context should be refused, got {:?}",
            result.as_ref().map(|_| ())
        );
        assert_eq!(
            generates.load(Ordering::SeqCst),
            0,
            "no key should be requested"
        );
    }

    /// The source's own `Serialize` can refuse. The refusal is the
    /// pending's result, no key is requested, and the source is wiped.
    #[tokio::test]
    async fn is_wiped_when_encoding_fails_and_no_key_is_requested() {
        let (cipher, generates, _) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let (source, wiped) = refusing();

        let pending = keyset.encrypt(source);
        assert!(
            wiped.load(Ordering::SeqCst),
            "an encoding refusal should still wipe the source"
        );
        let result = pending.await;

        assert!(
            matches!(result, Err(Error::Blob(BlobError::Unwritable(_)))),
            "the refusal should be Unwritable, got {:?}",
            result.as_ref().map(|_| ())
        );
        assert_eq!(
            generates.load(Ordering::SeqCst),
            0,
            "no key should be requested"
        );
    }

    /// The context is checked before the value is encoded, as a scalar's
    /// is. A value that would refuse to encode, under a context no request
    /// can carry, is refused for the context, so no encoding ran.
    #[tokio::test]
    async fn the_context_is_refused_before_the_value_is_encoded() {
        let (cipher, generates, _) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let (source, wiped) = refusing();

        let pending = keyset.encrypt_with_context(source, "x".repeat(65536));
        assert!(wiped.load(Ordering::SeqCst), "the source should be wiped");
        let result = pending.await;

        assert!(
            matches!(result, Err(Error::DescriptorTooLong { .. })),
            "the context should be refused first, got {:?}",
            result.as_ref().map(|_| ())
        );
        assert_eq!(
            generates.load(Ordering::SeqCst),
            0,
            "no key should be requested"
        );
    }
}

/// What is wiped, and when, after decrypt.
mod given_a_decrypted_blob {
    use super::*;

    /// The drop witness for the result contract: a decrypted
    /// `OpaqueBlob<T>` is wiped once when it is dropped, through
    /// `T::zeroize`. `into_inner` hands over the guard, so the value it
    /// returns is wiped when that is dropped, and not before.
    #[tokio::test]
    async fn is_wiped_on_drop_and_into_inner_keeps_it_guarded() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let ct = keyset
            .encrypt(OpaqueBlob::new(Witness {
                value: "secret".into(),
            }))
            .await
            .unwrap();
        // Encrypting wiped the source. Count from here.
        let before = WITNESS_WIPES.load(Ordering::SeqCst);

        let opened: OpaqueBlob<Witness> = keyset.decrypt(ct.clone()).await.unwrap();
        assert_eq!(opened.get().value, "secret", "the value should open");
        assert_eq!(
            WITNESS_WIPES.load(Ordering::SeqCst),
            before,
            "an open blob should not be wiped yet"
        );
        drop(opened);
        assert_eq!(
            WITNESS_WIPES.load(Ordering::SeqCst),
            before + 1,
            "dropping the blob should wipe it once"
        );

        let opened: OpaqueBlob<Witness> = keyset.decrypt(ct).await.unwrap();
        let inner: Zeroizing<Witness> = opened.into_inner();
        assert_eq!(inner.value, "secret", "into_inner should give the value");
        assert_eq!(
            WITNESS_WIPES.load(Ordering::SeqCst),
            before + 1,
            "into_inner should not wipe the value"
        );
        drop(inner);
        assert_eq!(
            WITNESS_WIPES.load(Ordering::SeqCst),
            before + 2,
            "dropping the guard should wipe the value once"
        );
    }

    /// The inner `Zeroizing` wipes on drop anyway, so this is the only
    /// place an explicit wipe is visible.
    #[test]
    fn zeroize_wipes_the_value_at_once() {
        let mut blob = OpaqueBlob::new(String::from("secret"));

        blob.zeroize();

        assert!(blob.get().is_empty(), "zeroize should wipe the value now");
    }

    #[tokio::test]
    async fn debug_and_refusals_show_no_plaintext() {
        let blob = OpaqueBlob::new(ada());
        assert_eq!(
            format!("{blob:?}"),
            "OpaqueBlob(***)",
            "Debug should hide the value"
        );

        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let ct = keyset.encrypt(blob).await.unwrap();
        assert!(
            format!("{ct:?}").ends_with("Ciphertext(\"***\")"),
            "Debug of the ciphertext should hide it"
        );

        let error = keyset.decrypt::<OpaqueBlob<Pair>>(ct).await.unwrap_err();
        let shown = format!(
            "{error} / {error:?} / {:?}",
            stack_encrypt::ErrorPayload::payload(&error)
        );
        assertions::shows_no_plaintext(&shown);
    }
}
