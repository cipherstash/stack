//! Routing by key backend: a sealed leaf names the key backend that sealed
//! it (a v1 leaf names ZeroKMS, a v2 leaf its key vendor backend), and a
//! cipher refuses a leaf that names another backend than its own before
//! any key call, as it refuses a leaf from a foreign keyset.
//!
//! No key vendor backend exists yet, so the "vendor" cipher here is the
//! fake source reporting a vendor backend: what the cipher routes on, and
//! nothing else.

mod common;

use std::sync::atomic::Ordering;

use common::CountingSource;
use stack_encrypt::kms::{KeyBackend, KeyMode, KeyVendor};
use stack_encrypt::{nonempty, CipherText, Error, SealedValue, StackCipher, StackCipherText};
use uuid::Uuid;

const AAD: &[u8] = b"ctx";

async fn cipher_over(
    source: CountingSource,
) -> (
    StackCipher<CountingSource>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let (generates, retrieves) = source.counters();
    let cipher = StackCipher::builder()
        .kms(source)
        .init()
        .await
        .expect("build cipher");
    (cipher, generates, retrieves)
}

fn v2_leaf(vendor: KeyVendor, keyset: Uuid) -> SealedValue {
    SealedValue::from_vendor_parts(
        vendor,
        KeyMode::Wrapped,
        keyset,
        [3; 16],
        vec![9; 8],
        vec![0xDE, 0xAD],
    )
    .expect("v2 leaf")
}

fn v1_leaf(keyset: Uuid) -> SealedValue {
    SealedValue::from_parts(keyset, [3; 16], vec![9; 8], vec![0xDE, 0xAD]).expect("v1 leaf")
}

fn assert_foreign(result: Result<String, Error>, expected: KeyBackend, found: KeyBackend) {
    match result {
        Err(Error::ForeignBackend {
            expected: e,
            found: f,
        }) => {
            assert_eq!((e, f), (expected, found));
        }
        other => panic!("expected ForeignBackend, got {other:?}"),
    }
}

/// A ZeroKMS cipher refuses a v2 leaf before any retrieve, through the
/// client and through a keyset cipher.
#[tokio::test]
async fn a_zerokms_cipher_refuses_a_v2_leaf_before_any_key_call() {
    let (cipher, _, retrieves) = cipher_over(CountingSource::new()).await;
    let keyset = cipher.default_keyset();
    let vendor = KeyBackend::Vendor(KeyVendor::Aws);

    let result = cipher
        .decrypt::<String, _>(
            CipherText::Single(v2_leaf(KeyVendor::Aws, keyset.keyset_id())),
            AAD,
        )
        .await;
    assert_foreign(result, KeyBackend::ZeroKms, vendor);

    let result = keyset
        .decrypt::<String, _>(
            CipherText::Single(v2_leaf(KeyVendor::Aws, keyset.keyset_id())),
            AAD,
        )
        .await;
    assert_foreign(result, KeyBackend::ZeroKms, vendor);

    assert_eq!(retrieves.load(Ordering::SeqCst), 0, "no key call");
}

/// One v2 leaf in a tree of v1 leaves refuses the whole tree, before any
/// retrieve: the v1 leaves are not retrieved first.
#[tokio::test]
async fn one_v2_leaf_refuses_a_whole_tree_before_any_key_call() {
    let (cipher, _, retrieves) = cipher_over(CountingSource::new()).await;
    let keyset = cipher.default_keyset();
    let v1 = keyset
        .encrypt("first".to_string(), AAD)
        .await
        .expect("encrypt");
    let tree: StackCipherText = CipherText::Sequence(vec![
        v1,
        CipherText::Single(v2_leaf(KeyVendor::Vault, keyset.keyset_id())),
    ]);

    let result = cipher.decrypt::<Vec<String>, _>(tree, AAD).await;
    assert!(
        matches!(
            result,
            Err(Error::ForeignBackend {
                found: KeyBackend::Vendor(KeyVendor::Vault),
                ..
            })
        ),
        "{result:?}"
    );
    assert_eq!(retrieves.load(Ordering::SeqCst), 0, "no key call");
}

/// A cipher over a key vendor backend refuses a v1 leaf (which names
/// ZeroKMS) and a v2 leaf of another vendor, before any key call. A v2 leaf
/// of its own vendor passes the routing check and reaches the key source.
#[tokio::test]
async fn a_vendor_cipher_routes_only_its_own_leaves_to_its_key_source() {
    let own = KeyBackend::Vendor(KeyVendor::Static);
    let (cipher, _, retrieves) = cipher_over(CountingSource::with_backend(own)).await;
    let keyset = cipher.default_keyset().keyset_id();

    let result = cipher
        .decrypt::<String, _>(CipherText::Single(v1_leaf(keyset)), AAD)
        .await;
    assert_foreign(result, own, KeyBackend::ZeroKms);

    let result = cipher
        .decrypt::<String, _>(CipherText::Single(v2_leaf(KeyVendor::Gcp, keyset)), AAD)
        .await;
    assert_foreign(result, own, KeyBackend::Vendor(KeyVendor::Gcp));
    assert_eq!(retrieves.load(Ordering::SeqCst), 0, "no key call");

    // The fake holds no key for this made-up leaf, so the retrieve fails;
    // what matters is that the leaf reached the key source.
    let result = cipher
        .decrypt::<String, _>(CipherText::Single(v2_leaf(KeyVendor::Static, keyset)), AAD)
        .await;
    assert!(matches!(result, Err(Error::Kms(_))), "{result:?}");
    assert_eq!(retrieves.load(Ordering::SeqCst), 1, "one key call");
}

/// This build seals v1 leaves only, and a v1 leaf names ZeroKMS: a cipher
/// over a key vendor backend refuses to seal, before any key call, rather
/// than write a leaf that names the wrong backend.
#[tokio::test]
async fn a_vendor_cipher_refuses_to_seal_before_any_key_call() {
    let own = KeyBackend::Vendor(KeyVendor::Azure);
    let (cipher, generates, _) = cipher_over(CountingSource::with_backend(own)).await;

    let result = cipher
        .default_keyset()
        .encrypt("value".to_string(), AAD)
        .await;
    assert!(
        matches!(result, Err(Error::SealUnsupported { backend }) if backend == own),
        "{result:?}"
    );
    assert_eq!(generates.load(Ordering::SeqCst), 0, "no key call");
}

/// A ZeroKMS cipher still seals v1 leaves, and they still open.
#[tokio::test]
async fn a_zerokms_cipher_still_writes_and_opens_v1() {
    let (cipher, _, _) = cipher_over(CountingSource::new()).await;
    let ct = cipher
        .default_keyset()
        .encrypt("value".to_string(), AAD)
        .await
        .expect("encrypt");
    let CipherText::Single(leaf) = &ct else {
        panic!("expected a Single leaf, got {ct:?}");
    };
    assert_eq!(leaf.format_version(), SealedValue::FORMAT_VERSION);
    assert_eq!(leaf.key_backend(), KeyBackend::ZeroKms);
    assert_eq!(leaf.key_mode(), None);
    let pt: String = cipher.decrypt(ct, AAD).await.expect("decrypt");
    assert_eq!(pt, "value");
}

/// `Request::retrieve_leaf_key` carries the leaf's backend, so a
/// hand-built request for a v2 leaf is refused as a tree's would be.
#[tokio::test]
async fn a_hand_built_request_for_a_v2_leaf_is_refused() {
    use stack_encrypt::target::{Pending, Request};

    let (cipher, _, retrieves) = cipher_over(CountingSource::new()).await;
    let keyset = cipher.default_keyset();
    let leaf = v2_leaf(KeyVendor::Aws, keyset.keyset_id());
    let pending: Pending<'_, (), _> = Pending::request(
        &keyset,
        vec![Request::retrieve_leaf_key(&leaf, nonempty!("ctx"))],
        |_| Ok(()),
    );
    let result = pending.await;
    assert!(
        matches!(result, Err(Error::ForeignBackend { .. })),
        "{result:?}"
    );
    assert_eq!(retrieves.load(Ordering::SeqCst), 0, "no key call");
}

/// A source whose keysets are selected per settle: the cipher holds no
/// index key, and asks for it inside each settle that builds a term. The
/// key is the fake source's, so its terms must equal a ZeroKMS-shaped
/// cipher's over the same key, byte for byte.
struct PerSettle {
    inner: stack_encrypt::kms::FakeDataKeySource,
    loads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl stack_encrypt::kms::DataKeySource for PerSettle {
    async fn generate_keys(
        &self,
        payloads: Vec<stack_encrypt::kms::GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<std::borrow::Cow<'_, stack_encrypt::kms::UnverifiedContext>>,
    ) -> Result<Vec<stack_encrypt::kms::DataKeyWithTag>, stack_encrypt::kms::Error> {
        self.inner
            .generate_keys(payloads, keyset_id, unverified_context)
            .await
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<stack_encrypt::kms::RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&stack_encrypt::kms::UnverifiedContext>,
    ) -> Result<Vec<stack_encrypt::kms::DataKey>, stack_encrypt::kms::Error> {
        self.inner
            .retrieve_keys(payloads, keyset_id, unverified_context)
            .await
    }

    async fn load_settle_index_key(
        &self,
        keyset_id: Uuid,
    ) -> Result<stack_encrypt::kms::IndexKey, stack_encrypt::kms::Error> {
        use stack_encrypt::kms::IndexKeySource;
        let _ = self.loads.fetch_add(1, Ordering::SeqCst);
        let (_, key) = self
            .inner
            .load_index_key(Some(stack_encrypt::kms::IdentifiedBy::Uuid(keyset_id)))
            .await?;
        Ok(key)
    }
}

impl stack_encrypt::kms::IndexKeySource for PerSettle {
    async fn load_index_key(
        &self,
        keyset_id: Option<stack_encrypt::kms::IdentifiedBy>,
    ) -> Result<(Uuid, stack_encrypt::kms::IndexKey), stack_encrypt::kms::Error> {
        self.inner.load_index_key(keyset_id).await
    }

    async fn select_keyset(
        &self,
        keyset_id: Option<stack_encrypt::kms::IdentifiedBy>,
    ) -> Result<stack_encrypt::kms::SelectedKeyset, stack_encrypt::kms::Error> {
        let (keyset_id, _) = self.inner.load_index_key(keyset_id).await?;
        Ok(stack_encrypt::kms::SelectedKeyset::PerSettle { keyset_id })
    }
}

#[tokio::test]
async fn a_term_derived_inside_the_settle_equals_one_derived_now() {
    use stack_encrypt::sem::{DefaultMatch, EqualityTerm, MatchTerms, OreTerm};
    use stack_encrypt::target::EncryptInto;

    let loads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let deferred = StackCipher::builder()
        .kms(PerSettle {
            inner: stack_encrypt::kms::FakeDataKeySource::new(),
            loads: std::sync::Arc::clone(&loads),
        })
        .init()
        .await
        .expect("a per-settle default keyset is accepted");
    let eager = StackCipher::builder()
        .kms(stack_encrypt::kms::FakeDataKeySource::new())
        .init()
        .await
        .unwrap();
    let (later, now) = (deferred.default_keyset(), eager.default_keyset());
    assert_eq!(later.keyset_id(), now.keyset_id());
    assert!(later.prf().is_none(), "the handle holds no index key");
    assert!(now.prf().is_some());
    assert_eq!(loads.load(Ordering::SeqCst), 0, "selection loads no key");

    let ctx = nonempty!("users").with("email");
    let borrowed = String::from("alice");
    let a = later.equality_term(borrowed.as_str(), ctx).await.unwrap();
    let b = now.equality_term(borrowed.as_str(), ctx).await.unwrap();
    assert_eq!(a.as_bytes(), b.as_bytes());
    assert_eq!(loads.load(Ordering::SeqCst), 1, "one load for the settle");

    let a = later
        .match_terms::<DefaultMatch>("alice wonderland", ctx)
        .await
        .unwrap();
    let b = now
        .match_terms::<DefaultMatch>("alice wonderland", ctx)
        .await
        .unwrap();
    assert_eq!(a.positions(), b.positions());
    assert_eq!(
        later.ore_term(42u64, ctx).await.unwrap(),
        now.ore_term(42u64, ctx).await.unwrap()
    );
    assert_eq!(
        later.ope_term(42u64, ctx).await.unwrap(),
        now.ope_term(42u64, ctx).await.unwrap()
    );

    // The target-directed path, and several terms in one settle: one load.
    let before = loads.load(Ordering::SeqCst);
    let eq = "bob".encrypt_into_with_context::<EqualityTerm, _>(&later, ctx);
    let mt = "bob builder"
        .to_string()
        .encrypt_into_with_context::<MatchTerms<DefaultMatch>, _>(&later, ctx);
    let ore = 7u64.encrypt_into_with_context::<OreTerm<u64>, _>(&later, ctx);
    let pair = eq.zip(mt).zip(ore);
    let ((eq, mt), ore) = pair.await.unwrap();
    assert_eq!(
        loads.load(Ordering::SeqCst),
        before + 1,
        "one load per settle"
    );
    assert_eq!(
        eq.as_bytes(),
        now.equality_term("bob", ctx).await.unwrap().as_bytes()
    );
    assert_eq!(
        mt.positions(),
        now.match_terms::<DefaultMatch>("bob builder", ctx)
            .await
            .unwrap()
            .positions()
    );
    assert_eq!(ore.into_inner(), now.ore_term(7u64, ctx).await.unwrap());

    // A value still seals and opens through the per-settle keyset.
    let sealed = later.encrypt("v".to_string(), AAD).await.unwrap();
    let opened: String = deferred.decrypt(sealed, AAD).await.unwrap();
    assert_eq!(opened, "v");
}
