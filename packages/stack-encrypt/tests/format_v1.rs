//! Format-1 leaves, written by stack-encrypt 0.2, still open.
//!
//! stack-encrypt 0.2.0 is on crates.io and wrote the format-1 leaf layout
//! (`0x01 ‖ keyset_id ‖ iv ‖ tag_len ‖ tag ‖ ciphertext`, with the AAD
//! binding version 1 and the tag). This crate now writes format 2, and must
//! still read every format-1 leaf a 0.2 deployment stored.
//!
//! The two leaves below are REAL format-1 ciphertext. They were sealed by
//! stack-encrypt at cipherstash/stack 327b4dbce (the 0.2.0 line, before the
//! keyset registry) through its own `KeysetCipher::encrypt`, over a
//! `DataKeySource` that returned a fixed data key: every key is
//! [`DATA_KEY`], the n-th has IV `[n; 16]` and tag `v1-fixture-tag-n`, all
//! in keyset [`FIXTURE_KEYSET`]. The bytes are frozen here as 0.2 wrote
//! them. The AES-GCM nonce inside each is random, so the bytes cannot be
//! regenerated; they can only be read.
//!
//! The provider below answers for exactly those keys, and only under the
//! descriptor each was minted with, as ZeroKMS would.

use stack_encrypt::registry::fake::FakeKeysetRegistry;
use stack_encrypt::registry::{
    Binding, BindingSupport, GeneratedDataKey, IndexKeyMaterial, IndexKeyProvider, KeyId,
    KeyIsolation, KeyProvider, KeyReconstruction, KeysetRef, ProviderProtected, Resolved,
};
use stack_encrypt::{
    nonempty, CipherText, Error, KeysetId, KeysetRegistry, SealedValue, StackCipher,
    StackCipherBuilder, StackCipherText,
};
use std::sync::{Arc, Mutex};

use uuid::Uuid;

/// The keyset 0.2 sealed the fixtures under.
const FIXTURE_KEYSET: Uuid = Uuid::from_u128(0x5e7f_0000_0000_4000_8000_0000_0000_0001);
/// The data key 0.2 sealed the fixtures with.
const DATA_KEY: [u8; 32] = [0x42; 32];

/// `"alice@example.com"` (a `String`), sealed by 0.2 under the context
/// `"users/email"` (a `&str`). IV `[1; 16]`, tag `v1-fixture-tag-1`.
const EMAIL_V1: &str = "015e7f000000004000800000000000000101010101010101010101010101010101100076312d666978747572652d7461672d310153767116f8f0c7450ebd6cf71a4afd93d9d7d037b51a48c3ab9d68480cf3ba4dc5d6a986ccbafb60d629baf402";
/// The descriptor 0.2 minted the email's key under. A single-part `&str`
/// context that holds a `/` renders base64-escaped.
const EMAIL_DESCRIPTOR: &str = "b64:dXNlcnMvZW1haWw=";

/// `42u32`, sealed by 0.2 under `nonempty!("users").with("age")`. IV
/// `[2; 16]`, tag `v1-fixture-tag-2`.
const AGE_V1: &str = "015e7f000000004000800000000000000102020202020202020202020202020202100076312d666978747572652d7461672d320137b0c99a69fdf0bea484b519bbea74aa15fb59a03316bcb1cce19dea007f48af";
const AGE_DESCRIPTOR: &str = "users/age";

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

/// The key id 0.2's n-th key reads as: ZeroKMS's `iv ‖ tag`.
fn v1_key_id(n: u8) -> Vec<u8> {
    let mut key_id = vec![n; 16];
    key_id.extend_from_slice(format!("v1-fixture-tag-{n}").as_bytes());
    key_id
}

/// Answers for the fixture keys, as a ZeroKMS keyset would: the key id is
/// `iv ‖ tag`, and the key comes back only under the descriptor it was
/// minted with. New keys get fresh key ids under the same data key.
#[derive(Clone, Default)]
struct FixtureProvider {
    /// The descriptors keys were minted under since the cipher was built.
    minted: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[derive(Debug, thiserror::Error)]
#[error("the fixture provider has no key {0:?} under that descriptor")]
struct NoSuchKey(Vec<u8>);

impl KeyProvider<32> for FixtureProvider {
    type Error = NoSuchKey;

    const RECONSTRUCTION: KeyReconstruction = KeyReconstruction::ClientAndServer;
    const ISOLATION: KeyIsolation = KeyIsolation::PerValue;
    const BINDING: BindingSupport = BindingSupport::Bound;

    async fn generate_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> Result<Vec<GeneratedDataKey<32>>, Self::Error> {
        let mut minted = self.minted.lock().unwrap();
        Ok(bindings
            .iter()
            .map(|binding| {
                minted.push(binding.as_bytes().to_vec());
                GeneratedDataKey {
                    plaintext: ProviderProtected::new(DATA_KEY),
                    key_id: KeyId::new(v1_key_id(0xff)),
                }
            })
            .collect())
    }

    async fn retrieve_keys(
        &self,
        keys: &[(KeyId, Binding<'_>)],
    ) -> Result<Vec<ProviderProtected<[u8; 32]>>, Self::Error> {
        let minted = self.minted.lock().unwrap();
        let known: Vec<(Vec<u8>, &[u8])> = [
            (v1_key_id(1), EMAIL_DESCRIPTOR.as_bytes()),
            (v1_key_id(2), AGE_DESCRIPTOR.as_bytes()),
        ]
        .into_iter()
        .chain(minted.iter().map(|d| (v1_key_id(0xff), d.as_slice())))
        .collect();
        keys.iter()
            .map(|(key_id, binding)| {
                known
                    .iter()
                    .any(|(id, descriptor)| {
                        id.as_slice() == key_id.as_bytes() && *descriptor == binding.as_bytes()
                    })
                    .then(|| ProviderProtected::new(DATA_KEY))
                    .ok_or_else(|| NoSuchKey(key_id.as_bytes().to_vec()))
            })
            .collect()
    }
}

impl IndexKeyProvider<32> for FixtureProvider {
    type Error = NoSuchKey;

    async fn load_index_key(&self) -> Result<IndexKeyMaterial<32>, Self::Error> {
        Ok(IndexKeyMaterial(ProviderProtected::new([0x11; 32])))
    }
}

/// One keyset, [`FIXTURE_KEYSET`], served by [`FixtureProvider`]. It reads
/// format-1 leaves: it stands in for ZeroKMS, whose key id it shares.
#[derive(Default)]
struct FixtureRegistry(FixtureProvider);

#[derive(Debug, thiserror::Error)]
#[error("unreachable")]
struct Never;

impl KeysetRegistry for FixtureRegistry {
    type Provider = FixtureProvider;
    type Error = Never;
    const READS_V1_LEAVES: bool = true;

    async fn resolve(
        &self,
        _keyset: &KeysetRef,
    ) -> Result<Option<Resolved<Self::Provider>>, Self::Error> {
        Ok(Some(Resolved {
            id: KeysetId::new(FIXTURE_KEYSET),
            name: None,
            provider: self.0.clone(),
        }))
    }
}

async fn fixture_cipher() -> StackCipher<FixtureRegistry> {
    StackCipherBuilder::new()
        .registry(FixtureRegistry::default())
        .init()
        .await
        .expect("build cipher")
}

fn leaf(hex: &str) -> SealedValue {
    SealedValue::from_bytes(&unhex(hex)).expect("a format-1 leaf parses")
}

/// The most important test here: ciphertext 0.2 wrote opens under the new
/// code, to the plaintext 0.2 sealed.
#[tokio::test]
async fn real_format_1_ciphertext_from_0_2_still_decrypts() {
    let cipher = fixture_cipher().await;

    let email: String = cipher
        .decrypt(CipherText::Single(leaf(EMAIL_V1)), "users/email")
        .await
        .expect("a 0.2 leaf opens");
    assert_eq!(email, "alice@example.com");

    let age: u32 = cipher
        .decrypt(
            CipherText::Single(leaf(AGE_V1)),
            nonempty!("users").with("age"),
        )
        .await
        .expect("a 0.2 leaf opens");
    assert_eq!(age, 42);
}

/// The context is still bound: a format-1 leaf opened under another
/// context fails, at the key retrieval (the descriptor differs) or at the
/// AEAD.
#[tokio::test]
async fn a_format_1_leaf_still_binds_its_context() {
    let cipher = fixture_cipher().await;
    let wrong: Result<String, _> = cipher
        .decrypt(CipherText::Single(leaf(EMAIL_V1)), "users/name")
        .await;
    assert!(
        matches!(wrong, Err(Error::Provider(_) | Error::Aead)),
        "{wrong:?}"
    );
}

/// The frozen format-1 fixture decodes field by field, and writes back to
/// the same bytes.
#[test]
fn the_format_1_fixture_decodes_and_round_trips() {
    let bytes = unhex(EMAIL_V1);
    let leaf = SealedValue::from_bytes(&bytes).expect("parses");
    assert_eq!(leaf.format_version(), SealedValue::FORMAT_VERSION_V1);
    assert_eq!(leaf.keyset_id(), KeysetId::new(FIXTURE_KEYSET));
    assert_eq!(leaf.key_id(), v1_key_id(1), "the key id is iv ‖ tag");
    assert_eq!(
        leaf.ciphertext(),
        &bytes[1 + 16 + 16 + 2 + "v1-fixture-tag-1".len()..]
    );
    assert_eq!(leaf.to_bytes(), bytes);
}

/// Every byte of the envelope is authenticated. Relabelling the version,
/// re-pointing the keyset, or changing the IV or the tag in storage stops
/// the leaf opening.
#[tokio::test]
async fn a_tampered_format_1_leaf_does_not_open() {
    let cipher = fixture_cipher().await;
    let original = unhex(EMAIL_V1);
    // version byte, a keyset byte, an IV byte, a tag byte, a ciphertext byte
    for offset in [0, 5, 20, 40, original.len() - 1] {
        let mut bytes = original.clone();
        bytes[offset] ^= 0x01;
        let opened = match SealedValue::from_bytes(&bytes) {
            Ok(leaf) => {
                cipher
                    .decrypt::<String, _>(CipherText::Single(leaf), "users/email")
                    .await
            }
            Err(_) => continue,
        };
        assert!(opened.is_err(), "byte {offset} flipped still opened");
    }
}

/// A format-1 leaf whose keyset resolves through a registry that does not
/// read format 1 fails closed, with the error that says why, before any
/// key is requested. The fake registry stands in for any non-ZeroKMS
/// backend.
#[tokio::test]
async fn a_format_1_leaf_fails_closed_on_a_registry_that_does_not_read_it() {
    const { assert!(!<FakeKeysetRegistry as KeysetRegistry>::READS_V1_LEAVES) };
    let registry = FakeKeysetRegistry::new();
    let (_, default) = registry.default_keyset();
    let cipher = StackCipherBuilder::new()
        .registry(registry)
        .init()
        .await
        .expect("build cipher");

    let opened: Result<String, _> = cipher
        .decrypt(CipherText::Single(leaf(EMAIL_V1)), "users/email")
        .await;
    assert!(
        matches!(
            opened,
            Err(Error::V1LeafNeedsZeroKms { keyset_id }) if keyset_id == KeysetId::new(FIXTURE_KEYSET)
        ),
        "{opened:?}"
    );
    assert_eq!(default.call_counts(), (0, 0), "no key was asked for");
    let (_, fixture_keyset) = cipher
        .registry()
        .keyset(&FIXTURE_KEYSET.to_string())
        .expect("minted");
    assert_eq!(fixture_keyset.call_counts(), (0, 0));

    // In a tree, one format-1 leaf beside format-2 leaves fails the batch.
    let fresh: StackCipherText = cipher
        .default_keyset()
        .encrypt("new".to_string(), "users/email")
        .await
        .expect("seal");
    let tree: StackCipherText =
        CipherText::Sequence(vec![fresh, CipherText::Single(leaf(EMAIL_V1))]);
    let opened: Result<Vec<String>, _> = cipher.decrypt(tree, "users/email").await;
    assert!(
        matches!(opened, Err(Error::V1LeafNeedsZeroKms { .. })),
        "{opened:?}"
    );
}

/// New leaves are format 2, and open; the same cipher opens a format-1
/// leaf and a format-2 leaf under the same context.
#[tokio::test]
async fn new_leaves_are_format_2_beside_format_1() {
    let cipher = fixture_cipher().await;
    let sealed: StackCipherText = cipher
        .default_keyset()
        .encrypt("written now".to_string(), "users/note")
        .await
        .expect("seal");
    let CipherText::Single(new_leaf) = &sealed else {
        panic!("a single leaf");
    };
    assert_eq!(new_leaf.format_version(), SealedValue::FORMAT_VERSION);
    assert_eq!(new_leaf.to_bytes()[0], 0x02);
    let back: String = cipher.decrypt(sealed, "users/note").await.expect("open");
    assert_eq!(back, "written now");

    let fresh: StackCipherText = cipher
        .default_keyset()
        .encrypt("bob@example.com".to_string(), "users/email")
        .await
        .expect("seal");
    let new_email: String = cipher.decrypt(fresh, "users/email").await.expect("open");
    let old_email: String = cipher
        .decrypt(CipherText::Single(leaf(EMAIL_V1)), "users/email")
        .await
        .expect("open");
    assert_eq!(
        [old_email, new_email],
        ["alice@example.com", "bob@example.com"],
        "one cipher reads both formats"
    );
}

/// Through ZeroKMS itself: a format-1 leaf's retrieval reaches ZeroKMS with
/// the IV and the tag 0.2 sent, split back out of the key id, under the
/// descriptor it was minted with. The stub cannot hand back the same data
/// key (that needs the client key 0.2 used), so the open itself fails at
/// the AEAD; what this pins is the request.
#[cfg(all(feature = "zerokms", not(target_arch = "wasm32")))]
#[tokio::test]
async fn a_format_1_leaf_reaches_zerokms_as_its_iv_and_tag() {
    use stack_auth::StaticTokenStrategy;
    use stack_kms::test_connection::{
        key_material, load_keyset_response, random_client_key, TestConnection,
        TestConnectionBuilder, TEST_KEYSET_ID,
    };
    use stack_kms::{ClientOpts, StackKms};
    use zerokms_protocol::{
        IdentifiedBy, LoadKeysetRequest, RetrieveKeyRequest, RetrieveKeyResponse, RetrievedKey,
    };

    type Registry = Arc<StackKms<StaticTokenStrategy, TestConnection>>;
    const { assert!(<Registry as KeysetRegistry>::READS_V1_LEAVES) };

    /// What one retrieve spec sent: keyset, IV, descriptor, tag.
    type Sent = (Option<String>, Vec<u8>, String, Vec<u8>);
    let seen: Arc<Mutex<Vec<Sent>>> = Arc::default();
    let record = Arc::clone(&seen);
    let builder = TestConnectionBuilder::new()
        .add_success_response::<LoadKeysetRequest>(load_keyset_response())
        .add_effect::<RetrieveKeyRequest, _>(move |request| {
            let keyset = match request.keyset_id {
                Some(IdentifiedBy::Uuid(id)) => Some(id.to_string()),
                _ => None,
            };
            for spec in request.keys.iter() {
                record.lock().unwrap().push((
                    keyset.clone(),
                    spec.iv.as_ref().to_vec(),
                    spec.descriptor.to_string(),
                    spec.tag.to_vec(),
                ));
            }
        })
        .add_success_response::<RetrieveKeyRequest>(RetrieveKeyResponse {
            keys: vec![RetrievedKey {
                key_material: key_material(),
            }],
        });
    let kms: Registry = Arc::new(
        StackKms::<_, TestConnection>::connect(
            ClientOpts::new(builder),
            StaticTokenStrategy::new("static-token"),
            random_client_key(),
        )
        .expect("connect over a test connection"),
    );
    let cipher = StackCipherBuilder::new()
        .registry(kms)
        .init()
        .await
        .expect("build cipher");

    // The real 0.2 leaf, re-pointed at the stub's keyset so the cipher
    // needs no second keyset load.
    let (_, key_id, ciphertext) = leaf(EMAIL_V1).into_parts();
    let (iv, tag) = key_id.split_at(16);
    let leaf = SealedValue::from_v1_parts(
        KeysetId::new(TEST_KEYSET_ID),
        iv.try_into().expect("16 bytes"),
        tag.to_vec(),
        ciphertext,
    )
    .expect("parts");

    let opened: Result<String, _> = cipher
        .decrypt(CipherText::Single(leaf), "users/email")
        .await;
    assert!(matches!(opened, Err(Error::Aead)), "{opened:?}");
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(
            Some(TEST_KEYSET_ID.to_string()),
            vec![1; 16],
            EMAIL_DESCRIPTOR.to_owned(),
            b"v1-fixture-tag-1".to_vec(),
        )]
    );
}

/// Index terms do not depend on the leaf format, and the keyset registry did
/// not change how they are derived. Under the same index key, the new code
/// derives exactly the terms 0.2 derived. These values were computed by
/// 0.2 (cipherstash/stack 327b4dbce) under the index key `[0x11; 32]`, the
/// one [`FixtureProvider`] serves, so a stored 0.2 term still matches a
/// query term the new code makes.
#[tokio::test]
async fn terms_derive_as_0_2_derived_them_under_the_same_index_key() {
    use stack_encrypt::sem::DefaultMatch;

    let cipher = fixture_cipher().await;
    let keyset = cipher.default_keyset();

    let equality = keyset
        .equality_term("alice", nonempty!("users/email"))
        .await
        .unwrap();
    assert_eq!(
        hex(equality.as_bytes()),
        "74804bc352df939a17098372b1e2ca386d115c61e84e17648d15f90de0ff0424"
    );

    let matching = keyset
        .match_terms::<DefaultMatch>("alice smith", nonempty!("users/name"))
        .await
        .unwrap();
    assert_eq!(
        matching.positions(),
        [
            17, 34, 43, 46, 47, 62, 79, 95, 106, 110, 134, 137, 139, 149, 159, 167, 173, 180, 199,
            213, 216, 224, 228, 238, 251, 255
        ]
    );

    let ore = keyset
        .ore_term(42u32, nonempty!("users/age"))
        .await
        .unwrap();
    assert_eq!(
        hex(ore.as_ref()),
        "2202ee55c9365705cae9a0fb07a64040813bb4323dee587b0da617ee3b44678c"
    );

    let ope = keyset
        .ope_term(42u32, nonempty!("users/age"))
        .await
        .unwrap();
    assert_eq!(
        hex(ope.as_ref()),
        "00871628f65496b8f8ba1ef74845303a0f1eb579b6a18e7a2bac586e3203ab3e4f"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
