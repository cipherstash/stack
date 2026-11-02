//! `OpaqueBlob<T>`: a whole value as one opaque ciphertext. Round trips,
//! the leaf it shares with the structural writer and the Go SDK, fixed
//! vectors, refusals by class after authentication, and the owned source's
//! cleanup. No service credentials are needed.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use stack_encrypt::blob::{HEADER, VERSION};
use stack_encrypt::{
    BlobError, CipherText, Ciphertext, Controlled, DecryptFrom, EncryptInto, Error, OpaqueBlob,
    SealedValue,
};
use zeroize::{Zeroize, Zeroizing};

mod common;

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

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// `ada()` as a version 1 storage blob, written by this crate. The same
/// hex is read by the Go SDK's `TestOpaqueReadsARustWrittenBlob`
/// (`languages/golang/encrypt/gensupport`), which is the other half of the
/// exchange: Rust writes, Go reads.
const RUST_BLOB: &str = "56435301f104000000040000006e616d650a0c000000416461204c6f76656c6163650300000061676506240000000400000074616773f0020000000a050000006d617468730a07000000656e67696e6573080000006e69636b6e616d65f50a03000000616461";

/// `ada()` as the Go SDK writes it, through `vcffi.MarshalStorage` over a
/// struct with `vc:"name"`, `vc:"age"`, `vc:"tags"` and `vc:"nickname"`
/// tags, the nickname a non-nil `*string`. Go writes a non-nil pointer as
/// the bare value, where Rust writes `Some` with its marker: the two blobs
/// differ in one byte, and both readers read both.
const GO_BLOB_SOME: &str = "56435301f104000000040000006e616d650a0c000000416461204c6f76656c6163650300000061676506240000000400000074616773f0020000000a050000006d617468730a07000000656e67696e6573080000006e69636b6e616d650a03000000616461";

/// The same, with the nickname a nil pointer: a null.
const GO_BLOB_NONE: &str = "56435301f104000000040000006e616d650a0c000000416461204c6f76656c6163650300000061676506240000000400000074616773f0020000000a050000006d617468730a07000000656e67696e6573080000006e69636b6e616d6500";

#[tokio::test]
async fn a_struct_round_trips_as_one_ciphertext() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();

    let ct = keyset.encrypt(OpaqueBlob::new(ada())).await.unwrap();
    let opened: OpaqueBlob<Profile> = keyset.decrypt(ct).await.unwrap();
    assert_eq!(opened.into_inner(), ada());

    let ct = keyset
        .encrypt_with_context(OpaqueBlob::new(ada()), ("users", "profile"))
        .await
        .unwrap();
    let opened = keyset
        .decrypt_with_context::<OpaqueBlob<Profile>>(ct.clone(), ("users", "profile"))
        .await
        .unwrap();
    assert_eq!(opened.get(), &ada());

    // The owned conversions are the same path.
    let ct2: Ciphertext = OpaqueBlob::new(ada())
        .encrypt_into_with_context(&keyset, ("users", "profile"))
        .await
        .unwrap();
    let opened =
        OpaqueBlob::<Profile>::decrypt_from_with_context(ct2, &keyset, ("users", "profile"))
            .await
            .unwrap();
    assert_eq!(opened.into_inner(), ada());
    let ct3: Ciphertext = OpaqueBlob::new(ada()).encrypt_into(&keyset).await.unwrap();
    assert_eq!(
        OpaqueBlob::<Profile>::decrypt_from(ct3, &keyset)
            .await
            .unwrap()
            .into_inner(),
        ada()
    );
}

/// One blob is one data key: the whole struct costs one generate call,
/// where the structural writer would mint one per leaf.
#[tokio::test]
async fn a_blob_is_one_data_key() {
    let (cipher, generates, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset.encrypt(OpaqueBlob::new(ada())).await.unwrap();
    assert_eq!(generates.load(Ordering::SeqCst), 1);
    let _: OpaqueBlob<Profile> = keyset.decrypt(ct).await.unwrap();
    assert_eq!(retrieves.load(Ordering::SeqCst), 1);
}

/// The blob is a bytes leaf of the ordinary envelope: what the structural
/// writer seals for a `Vec<u8>` holding the encoded bytes, and what the Go
/// SDK's engine seals for an opaque struct. Each side opens the other's.
#[tokio::test]
async fn a_blob_is_one_bytes_leaf_of_the_structural_writer() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();

    // Structural writer of the encoded bytes -> OpaqueBlob reader.
    let encoded = OpaqueBlob::new(ada()).encode().unwrap();
    assert_eq!(&encoded.risky_ref()[..4], &HEADER);
    let tree = keyset
        .encrypt_tree(encoded.risky_ref().clone(), "users/profile")
        .await
        .unwrap();
    let CipherText::Single(leaf) = tree else {
        panic!("a Vec<u8> is one leaf")
    };
    let opened = keyset
        .decrypt_with_context::<OpaqueBlob<Profile>>(Ciphertext::from(leaf), "users/profile")
        .await
        .unwrap();
    assert_eq!(opened.into_inner(), ada());

    // OpaqueBlob writer -> structural reader of the bytes.
    let ct = keyset
        .encrypt_with_context(OpaqueBlob::new(ada()), "users/profile")
        .await
        .unwrap();
    let bytes: Vec<u8> = cipher
        .decrypt(CipherText::Single(SealedValue::from(ct)), "users/profile")
        .await
        .unwrap();
    assert_eq!(&bytes[..4], &HEADER);
    assert_eq!(
        OpaqueBlob::<Profile>::decode(&bytes).unwrap().into_inner(),
        ada()
    );
}

/// The bytes this crate writes for `ada()` are pinned: a change here is a
/// change to what every stored blob holds, and to what Go reads.
#[test]
fn the_blob_this_crate_writes_is_pinned() {
    let encoded = OpaqueBlob::new(ada()).encode().unwrap();
    assert_eq!(encoded.risky_ref(), &unhex(RUST_BLOB));
    assert_eq!(VERSION, 1);
    assert_eq!(encoded.risky_ref()[3], VERSION);
}

/// Go writes, Rust reads: the Go SDK's bytes for the same struct, both
/// with and without the optional field, read as the Rust value through the
/// codec and through a sealed ciphertext opened as an `OpaqueBlob`. The
/// Go engine seals an opaque struct as a bytes leaf under
/// `<context>/value`, which is what `encrypt_tree` of the bytes does here.
#[tokio::test]
async fn a_go_written_blob_opens_in_rust() {
    let with_nickname = OpaqueBlob::<Profile>::decode(&unhex(GO_BLOB_SOME)).unwrap();
    assert_eq!(with_nickname.into_inner(), ada());
    let without = OpaqueBlob::<Profile>::decode(&unhex(GO_BLOB_NONE)).unwrap();
    assert_eq!(
        without.into_inner(),
        Profile {
            nickname: None,
            ..ada()
        }
    );
    // Go's `Some` is the bare value; Rust's carries the marker. One byte.
    assert_eq!(unhex(GO_BLOB_SOME).len() + 1, unhex(RUST_BLOB).len());

    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let tree = keyset
        .encrypt_tree(unhex(GO_BLOB_SOME), ("users", "value"))
        .await
        .unwrap();
    let CipherText::Single(leaf) = tree else {
        panic!("bytes are one leaf")
    };
    let opened = keyset
        .decrypt_with_context::<OpaqueBlob<Profile>>(Ciphertext::from(leaf), ("users", "value"))
        .await
        .unwrap();
    assert_eq!(opened.into_inner(), ada());
}

/// One fixed data key, IV and key tag for every request, so a ciphertext
/// sealed once can be pinned and opened by any later build.
struct FixedKeySource(stack_kms::FakeDataKeySource);
const FIXED_KEY: [u8; 32] = *b"fixed-data-key-for-pinned-blob!!";
const FIXED_IV: [u8; 16] = *b"fixed-iv-pinned!";
const FIXED_TAG: &[u8] = b"fixed-key-tag";
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
        .unwrap()
}

/// `OpaqueBlob::new(ada())` sealed under `"users/profile"` over
/// [`FixedKeySource`] by the build that introduced `OpaqueBlob`. Vitamin C
/// draws the AEAD nonce itself, so the ciphertext is not reproducible; it is
/// pinned so a later build is shown to open what this one wrote.
const PINNED_CIPHERTEXT: &str = "010000000000000000000000000000000066697865642d69762d70696e6e6564210d0066697865642d6b65792d7461670232e68c36bf5fa752e06eea1f8625c96dd4aa0ea1eceaf8b2414db5c09282bbc92a653bab98e7e715db1c56b063d461fa50297f1473be2faf29413c7bc9b292e6186a60661dccddd63576fc98e22bf32202f000251b49d1fbdb67bf1bcf1a8c666d4de9dabe7a1cbf5b67834c3ece6c458d7ceb7435ce5dcd68b216c326a4d933cb748c";

#[tokio::test]
async fn a_pinned_blob_ciphertext_opens() {
    let cipher = fixed_cipher().await;
    let keyset = cipher.default_keyset();
    let bytes = unhex(PINNED_CIPHERTEXT);
    let ct = Ciphertext::from_bytes(&bytes).unwrap();
    assert_eq!(ct.key_tag(), FIXED_TAG);
    assert_eq!(ct.to_bytes(), bytes);
    let opened = keyset
        .decrypt_with_context::<OpaqueBlob<Profile>>(ct.clone(), "users/profile")
        .await
        .unwrap();
    assert_eq!(opened.into_inner(), ada());
    // Under no context, or the wrong one, it never reaches the blob.
    assert!(matches!(
        keyset.decrypt::<OpaqueBlob<Profile>>(ct.clone()).await,
        Err(Error::Aead)
    ));
    assert!(matches!(
        keyset
            .decrypt_with_context::<OpaqueBlob<Profile>>(ct, "users/other")
            .await,
        Err(Error::Aead)
    ));
}

/// Tampering is refused by the AEAD before any byte of the blob is read,
/// however the bytes would have decoded; and the leaf's kind is bound, so
/// a scalar leaf opened as a blob, or a blob as a scalar, is a shape
/// refusal of an authentic ciphertext, never a blob error.
#[tokio::test]
async fn authentication_comes_before_decoding() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt_with_context(OpaqueBlob::new(ada()), "users/profile")
        .await
        .unwrap();

    let mut bytes = ct.to_bytes();
    *bytes.last_mut().unwrap() ^= 1;
    let tampered = Ciphertext::from_bytes(&bytes).unwrap();
    assert!(matches!(
        keyset
            .decrypt_with_context::<OpaqueBlob<Profile>>(tampered, "users/profile")
            .await,
        Err(Error::Aead)
    ));
    assert!(matches!(
        keyset
            .decrypt_with_context::<OpaqueBlob<Profile>>(ct.clone(), "users/other")
            .await,
        Err(Error::Aead)
    ));

    // A blob opened as a String: the leaf is bytes, not text.
    assert!(matches!(
        keyset
            .decrypt_with_context::<String>(ct, "users/profile")
            .await,
        Err(Error::OpenedType { .. })
    ));
    // A String opened as a blob: the leaf is text, not bytes.
    let text = keyset
        .encrypt_with_context("VCS\u{1}".to_owned(), "users/profile")
        .await
        .unwrap();
    assert!(matches!(
        keyset
            .decrypt_with_context::<OpaqueBlob<Profile>>(text, "users/profile")
            .await,
        Err(Error::OpenedType { .. })
    ));
}

#[derive(Serialize, Deserialize, Zeroize, PartialEq, Debug)]
struct Pair {
    left: String,
    right: u32,
}

/// Bytes sealed as a leaf that are not a blob this type reads are refused
/// by class, each after the leaf authenticated and each retrieving its key
/// once. The classes are the storage profile's, and the ciphertext is
/// genuine in every case: the data was written as something else.
#[tokio::test]
async fn malformed_and_mismatched_blobs_are_refused_by_class_after_authentication() {
    let (cipher, _, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let open = |bytes: Vec<u8>| async {
        let CipherText::Single(leaf) = keyset.encrypt_tree(bytes, "users/profile").await.unwrap()
        else {
            panic!("bytes are one leaf")
        };
        keyset
            .decrypt_with_context::<OpaqueBlob<Profile>>(Ciphertext::from(leaf), "users/profile")
            .await
            .unwrap_err()
    };
    let blob = OpaqueBlob::new(ada()).encode().unwrap();
    let blob = blob.risky_ref();

    assert!(matches!(
        open(b"hello".to_vec()).await,
        Error::Blob(BlobError::NotABlob)
    ));
    assert!(matches!(
        open(b"{\"name\":\"Ada\"}".to_vec()).await,
        Error::Blob(BlobError::NotABlob)
    ));
    let mut later = blob.clone();
    later[3] = VERSION + 1;
    assert!(matches!(
        open(later).await,
        Error::Blob(BlobError::UnsupportedVersion { version }) if version == VERSION + 1
    ));
    assert!(matches!(
        open(blob[..blob.len() - 3].to_vec()).await,
        Error::Blob(BlobError::Malformed(_))
    ));
    let mut trailing = blob.clone();
    trailing.push(0);
    assert!(matches!(
        open(trailing).await,
        Error::Blob(BlobError::Malformed(_))
    ));
    let pair = OpaqueBlob::new(Pair {
        left: "l".into(),
        right: 1,
    })
    .encode()
    .unwrap();
    let mismatch = open(pair.risky_ref().clone()).await;
    assert!(matches!(mismatch, Error::Blob(BlobError::Mismatch(_))));
    // Every refusal came after a retrieval: authentication first.
    assert_eq!(retrieves.load(Ordering::SeqCst), 6);
    // The refusal names the declared field, never the value.
    let shown = format!("{mismatch} {mismatch:?}");
    assert!(!shown.contains("\"l\""), "{shown}");
}

/// The source's own `Serialize` can refuse. The refusal is the pending's
/// result, no key is requested, and the owned source is wiped all the same.
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

#[tokio::test]
async fn an_encoding_refusal_wipes_the_source_and_requests_no_key() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let wiped = Arc::new(AtomicBool::new(false));
    let pending = keyset.encrypt(OpaqueBlob::new(Refusing {
        secret: "secret".into(),
        wiped: wiped.clone(),
    }));
    assert!(wiped.load(Ordering::SeqCst));
    assert!(matches!(
        pending.await,
        Err(Error::Blob(BlobError::Unwritable(_)))
    ));
    assert_eq!(generates.load(Ordering::SeqCst), 0);
}

/// A source that records being wiped; deliberately not `Clone`.
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
    (
        OpaqueBlob::new(Tracked {
            value: "secret".into(),
            wiped: wiped.clone(),
        }),
        wiped,
    )
}

/// The owned source is encoded and wiped before `encrypt` returns, so a
/// pending that is dropped unpolled, or awaited, carries no plaintext of
/// the caller's and makes no key request until it is polled.
#[tokio::test]
async fn the_owned_source_is_wiped_before_await_or_discard() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();

    let (source, wiped) = tracked();
    let pending = keyset.encrypt(source);
    assert!(wiped.load(Ordering::SeqCst));
    assert_eq!(generates.load(Ordering::SeqCst), 0);
    drop(pending);
    assert_eq!(generates.load(Ordering::SeqCst), 0);

    let (source, wiped) = tracked();
    let pending = keyset.encrypt_with_context(source, "users/secret");
    assert!(wiped.load(Ordering::SeqCst));
    let ct = pending.await.unwrap();
    assert_eq!(generates.load(Ordering::SeqCst), 1);
    #[derive(Deserialize, Zeroize)]
    struct Read {
        value: String,
    }
    assert_eq!(
        keyset
            .decrypt_with_context::<OpaqueBlob<Read>>(ct, "users/secret")
            .await
            .unwrap()
            .into_inner()
            .value,
        "secret"
    );
}

#[tokio::test]
async fn the_owned_source_is_wiped_when_context_validation_fails() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let (source, wiped) = tracked();
    let pending = keyset.encrypt_with_context(source, "x".repeat(65536));
    assert!(wiped.load(Ordering::SeqCst));
    assert!(matches!(
        pending.await,
        Err(Error::DescriptorTooLong { .. })
    ));
    assert_eq!(generates.load(Ordering::SeqCst), 0);
}

/// The context is checked before the value is encoded, as a scalar's is: a
/// value that would refuse to encode, under a context no request can
/// carry, is refused for the context, so no encoding ran.
#[tokio::test]
async fn the_context_is_refused_before_the_value_is_encoded() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let wiped = Arc::new(AtomicBool::new(false));
    let pending = keyset.encrypt_with_context(
        OpaqueBlob::new(Refusing {
            secret: "secret".into(),
            wiped: wiped.clone(),
        }),
        "x".repeat(65536),
    );
    assert!(wiped.load(Ordering::SeqCst));
    assert!(matches!(
        pending.await,
        Err(Error::DescriptorTooLong { .. })
    ));
    assert_eq!(generates.load(Ordering::SeqCst), 0);
}

/// `OpaqueBlob<Zeroizing<T>>` is the opt-in drop guard: a `Zeroizing<T>`
/// serializes as its `T`, so the guarded and the unguarded blob store the
/// same bytes and each opens the other's ciphertext.
#[tokio::test]
async fn zeroizing_inside_the_blob_is_the_opt_in_drop_guard() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();

    assert_eq!(
        OpaqueBlob::new(Zeroizing::new(ada()))
            .encode()
            .unwrap()
            .risky_ref(),
        OpaqueBlob::new(ada()).encode().unwrap().risky_ref(),
    );

    let ct = keyset
        .encrypt(OpaqueBlob::new(Zeroizing::new(ada())))
        .await
        .unwrap();
    let guarded: OpaqueBlob<Zeroizing<Profile>> = keyset.decrypt(ct.clone()).await.unwrap();
    assert_eq!(**guarded.get(), ada());
    // The same ciphertext opens unguarded too: the guard is the caller's
    // choice of result type, not part of the stored value.
    let plain: OpaqueBlob<Profile> = keyset.decrypt(ct).await.unwrap();
    assert_eq!(plain.into_inner(), ada());

    let ct = keyset.encrypt(OpaqueBlob::new(ada())).await.unwrap();
    let guarded: OpaqueBlob<Zeroizing<Profile>> = keyset.decrypt(ct).await.unwrap();
    assert_eq!(*guarded.into_inner(), ada());
}

/// Schema evolution is serde's: a default for a new field, an alias for a
/// renamed one, and an `Option` for one that may be absent all read an old
/// blob; a new required field does not.
#[tokio::test]
async fn schema_evolution_follows_serde() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset.encrypt(OpaqueBlob::new(ada())).await.unwrap();

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
    let later = keyset
        .decrypt::<OpaqueBlob<ProfileV2>>(ct.clone())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        later,
        ProfileV2 {
            name: "Ada Lovelace".into(),
            age: 36,
            labels: vec!["maths".into(), "engines".into()],
            nickname: Some("ada".into()),
            verified: false,
            title: None,
        }
    );

    #[derive(Deserialize, Zeroize)]
    #[allow(dead_code)]
    struct Stricter {
        name: String,
        age: u8,
        tags: Vec<String>,
        nickname: Option<String>,
        verified: bool,
    }
    assert!(matches!(
        keyset.decrypt::<OpaqueBlob<Stricter>>(ct.clone()).await,
        Err(Error::Blob(BlobError::Mismatch(_)))
    ));
    #[derive(Deserialize, Zeroize)]
    #[allow(dead_code)]
    struct Narrower {
        name: String,
        age: u8,
    }
    // Narrowing reads values that fit; the blob holds 36.
    assert_eq!(
        keyset
            .decrypt::<OpaqueBlob<Narrower>>(ct)
            .await
            .unwrap()
            .into_inner()
            .age,
        36
    );
}

/// The ciphertext is the encoded length plus a fixed overhead: a present
/// optional field, a longer string, another element each show in it. The
/// documented disclosure, executable.
#[tokio::test]
async fn the_ciphertext_length_is_the_encoded_length_plus_a_constant() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let overhead = |profile: Profile| async {
        let blob = OpaqueBlob::new(profile.clone()).encode().unwrap();
        let ct = keyset.encrypt(OpaqueBlob::new(profile)).await.unwrap();
        (blob.risky_ref().len(), ct.to_bytes().len())
    };
    let (with_len, with_ct) = overhead(ada()).await;
    let (without_len, without_ct) = overhead(Profile {
        nickname: None,
        ..ada()
    })
    .await;
    // `Some("ada")`: marker, text tag, u32 length, three bytes; `None`: one
    // null byte.
    assert_eq!(with_len - without_len, 1 + 1 + 4 + 3 - 1);
    assert_eq!(with_ct - without_ct, with_len - without_len);
    assert_eq!(with_ct - with_len, without_ct - without_len);
}

#[tokio::test]
async fn debug_and_refusals_show_no_plaintext() {
    let blob = OpaqueBlob::new(ada());
    assert_eq!(format!("{blob:?}"), "OpaqueBlob(***)");
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset.encrypt(blob).await.unwrap();
    assert!(format!("{ct:?}").ends_with("Ciphertext(\"***\")"));
    let error = keyset.decrypt::<OpaqueBlob<Pair>>(ct).await.unwrap_err();
    let shown = format!(
        "{error} / {error:?} / {:?}",
        stack_encrypt::ErrorPayload::payload(&error)
    );
    for word in ["Ada", "Lovelace", "maths", "engines", "ada"] {
        assert!(!shown.contains(word), "{shown}");
    }
}

/// A `Vec<u8>` is not a blob and a blob is not a `Vec<u8>`: neither
/// implements the other's capability, so the stored kind is never chosen
/// by accident. (The compile-fail half is `tests/ui/opaque_blob_*.rs`.)
#[tokio::test]
async fn a_blob_of_bytes_is_still_a_blob() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    #[derive(Serialize, Deserialize, Zeroize, PartialEq, Debug)]
    struct Raw(#[serde(with = "serde_bytes_shim")] Vec<u8>);
    mod serde_bytes_shim {
        pub fn serialize<S: serde::Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_bytes(v)
        }
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            struct V;
            impl serde::de::Visitor<'_> for V {
                type Value = Vec<u8>;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("bytes")
                }
                fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                    Ok(v.to_vec())
                }
            }
            d.deserialize_bytes(V)
        }
    }
    let raw = Raw(b"hello".to_vec());
    let ct = keyset.encrypt(OpaqueBlob::new(raw)).await.unwrap();
    // Opened as bytes, the leaf holds a blob, not "hello".
    let bytes: Vec<u8> = cipher
        .decrypt(CipherText::Single(SealedValue::from(ct.clone())), ())
        .await
        .unwrap();
    assert_eq!(&bytes[..4], &HEADER);
    assert_eq!(
        keyset
            .decrypt::<OpaqueBlob<Raw>>(ct)
            .await
            .unwrap()
            .into_inner(),
        Raw(b"hello".to_vec())
    );
}
