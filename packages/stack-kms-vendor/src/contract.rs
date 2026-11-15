//! The shared contract suite every key vendor backend runs.
//!
//! A vendor crate calls [`run`] (or each check alone) from its own tests
//! with a factory for its backend and a vendor key reference it may use.
//! Every check drives the backend through [`VendorKeySource`] and a real
//! [`StackCipher`], so it tests what a customer gets, not the trait alone.
//! A check panics with a message that names the broken rule.
//!
//! ```ignore
//! #[tokio::test]
//! async fn aws_kms_meets_the_contract() {
//!     stack_kms_vendor::contract::run(|| AwsKms::new(localstack()), KEY_ARN).await;
//! }
//! ```
//!
//! The checks:
//!
//! * a value and an index term round-trip, as a v1 leaf with an empty tag,
//!   and a second cipher derives the same term;
//! * a value opened under another context (descriptor) is refused;
//! * a leaf of another key backend does not open, and makes no vendor
//!   call;
//! * ZeroKMS-only inputs are refused, never ignored;
//! * the root key is unwrapped once per TTL;
//! * a batch keeps its order;
//! * a throttled call is retried, and a call still throttled after the last
//!   attempt fails.

// A contract check is a test: it panics with the rule it found broken.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use stack_encrypt::kms::{
    BackendErrorKind, Context, DataKeySource, DecryptionPolicy, Error as KmsError,
    FakeDataKeySource, GenerateKeyPayload, KeyMode, KeyVendor, RetrieveKeyPayload,
    UnverifiedContext, ZeroKmsFeature,
};
use stack_encrypt::{nonempty, CipherText, Error, SealedValue, StackCipher, StackCipherText};

use crate::{KeyBytes, KeyVendorBackend, KeysetRecord, RetryOptions, VendorKeySource};

/// The one key mode this release offers.
const MODE: KeyMode = KeyMode::Derived;

/// Run every check of the contract against the backends `make` builds.
/// `key_ref` names a vendor key the backend may wrap and unwrap under.
pub async fn run<B, F>(make: F, key_ref: &str)
where
    B: KeyVendorBackend + 'static,
    F: Fn() -> B,
{
    round_trip(&make, key_ref).await;
    refuses_another_context(make(), key_ref).await;
    refuses_another_key_backend(make(), key_ref).await;
    refuses_zerokms_features(make(), key_ref).await;
    obeys_the_root_key_ttl(&make, key_ref).await;
    keeps_batch_order(make(), key_ref).await;
    backs_off_when_throttled(&make, key_ref).await;
}

/// A key vendor backend that counts the calls it forwards, and can refuse
/// the next calls as throttled.
pub struct Observed<B> {
    inner: B,
    wraps: Arc<AtomicUsize>,
    unwraps: Arc<AtomicUsize>,
    throttle_next: Arc<AtomicUsize>,
}

/// The counters and the throttle of an [`Observed`] backend, kept by the
/// test after the backend moves into a key source.
#[derive(Clone)]
pub struct Observer {
    wraps: Arc<AtomicUsize>,
    unwraps: Arc<AtomicUsize>,
    throttle_next: Arc<AtomicUsize>,
}

impl Observer {
    /// Wrap calls forwarded so far.
    pub fn wraps(&self) -> usize {
        self.wraps.load(Ordering::SeqCst)
    }

    /// Unwrap calls forwarded so far.
    pub fn unwraps(&self) -> usize {
        self.unwraps.load(Ordering::SeqCst)
    }

    /// Refuse the next `count` calls as throttled, without forwarding them.
    pub fn throttle_next(&self, count: usize) {
        self.throttle_next.store(count, Ordering::SeqCst);
    }
}

impl<B: KeyVendorBackend> Observed<B> {
    /// Observe `inner`.
    pub fn new(inner: B) -> (Self, Observer) {
        let observer = Observer {
            wraps: Arc::default(),
            unwraps: Arc::default(),
            throttle_next: Arc::default(),
        };
        (
            Self {
                inner,
                wraps: Arc::clone(&observer.wraps),
                unwraps: Arc::clone(&observer.unwraps),
                throttle_next: Arc::clone(&observer.throttle_next),
            },
            observer,
        )
    }

    fn throttle(&self) -> Result<(), KmsError> {
        let pending = self
            .throttle_next
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));
        match pending {
            Ok(_) => Err(KmsError::Backend {
                backend: self.inner.vendor().into(),
                kind: BackendErrorKind::Throttled,
                source: "throttled by the contract suite".into(),
            }),
            Err(_) => Ok(()),
        }
    }
}

impl<B: KeyVendorBackend> KeyVendorBackend for Observed<B> {
    fn vendor(&self) -> KeyVendor {
        self.inner.vendor()
    }

    async fn wrap(&self, key_ref: &str, key: &KeyBytes, aad: &[u8]) -> Result<Vec<u8>, KmsError> {
        self.throttle()?;
        let _ = self.wraps.fetch_add(1, Ordering::SeqCst);
        self.inner.wrap(key_ref, key, aad).await
    }

    async fn unwrap(
        &self,
        key_ref: &str,
        wrapped: &[u8],
        aad: &[u8],
    ) -> Result<KeyBytes, KmsError> {
        self.throttle()?;
        let _ = self.unwraps.fetch_add(1, Ordering::SeqCst);
        self.inner.unwrap(key_ref, wrapped, aad).await
    }

    async fn sleep(&self, duration: Duration) {
        self.inner.sleep(duration).await;
    }
}

/// A cipher over one fresh keyset of `backend`, with its record.
async fn cipher_over<B: KeyVendorBackend>(
    backend: B,
    key_ref: &str,
    configure: impl FnOnce(VendorKeySource<Observed<B>>) -> VendorKeySource<Observed<B>>,
) -> (
    StackCipher<VendorKeySource<Observed<B>>>,
    KeysetRecord,
    Observer,
) {
    let (backend, observer) = Observed::new(backend);
    let record = KeysetRecord::create(&backend, key_ref, MODE, Some("contract".into()))
        .await
        .unwrap_or_else(|error| panic!("creating a keyset record failed: {error}"));
    let source = configure(
        VendorKeySource::new(backend, [record.clone()])
            .unwrap_or_else(|error| panic!("loading the record failed: {error}")),
    );
    let cipher = StackCipher::builder()
        .kms(source)
        .init()
        .await
        .unwrap_or_else(|error| panic!("a cipher over a vendor keyset failed to init: {error}"));
    (cipher, record, observer)
}

fn single(ciphertext: &StackCipherText) -> &SealedValue {
    match ciphertext {
        CipherText::Single(leaf) => leaf,
        _ => panic!("a string seals as one leaf"),
    }
}

/// A value and an index term round-trip, the leaf is the v1 leaf with an
/// empty tag, and a second cipher over the same record (a backend from
/// `make`) derives the same term and opens the same value.
pub async fn round_trip<B, F>(make: &F, key_ref: &str)
where
    B: KeyVendorBackend,
    F: Fn() -> B,
{
    let (cipher, record, _) = cipher_over(make(), key_ref, |s| s).await;
    let keyset = cipher.default_keyset();
    assert_eq!(
        keyset.keyset_id(),
        record.id(),
        "the only record is the default keyset"
    );
    let context = nonempty!("users").with("email");

    let sealed = keyset
        .encrypt_tree("alice@example.com".to_string(), context)
        .await
        .unwrap_or_else(|error| panic!("sealing failed: {error}"));
    let leaf = single(&sealed);
    let bytes = leaf.to_bytes();
    assert_eq!(
        bytes.first(),
        Some(&SealedValue::FORMAT_VERSION),
        "a key vendor backend seals the v1 leaf"
    );
    assert_eq!(leaf.keyset_id(), record.id());
    assert!(leaf.tag().is_empty(), "a derived data key has no tag");
    let reread = SealedValue::from_bytes(&bytes).expect("the leaf decodes");
    let opened: String = cipher
        .decrypt(CipherText::Single(reread), context)
        .await
        .unwrap_or_else(|error| panic!("opening failed: {error}"));
    assert_eq!(opened, "alice@example.com");

    let term = keyset
        .equality_term("alice@example.com", context)
        .await
        .unwrap_or_else(|error| panic!("an equality term failed: {error}"));
    let again = keyset
        .equality_term("alice@example.com", context)
        .await
        .expect("a second term");
    assert_eq!(term.as_bytes(), again.as_bytes(), "terms are deterministic");
    let other = keyset
        .equality_term("bob@example.com", context)
        .await
        .expect("a term for another value");
    assert_ne!(term.as_bytes(), other.as_bytes());

    // Another process, with the same record, derives the same term and
    // opens the same value.
    let other = StackCipher::builder()
        .kms(VendorKeySource::new(make(), [record.clone()]).expect("load the record again"))
        .init()
        .await
        .expect("a second cipher");
    let term_elsewhere = other
        .default_keyset()
        .equality_term("alice@example.com", context)
        .await
        .expect("a term in the second cipher");
    assert_eq!(
        term.as_bytes(),
        term_elsewhere.as_bytes(),
        "another cipher with the same record derives the same term"
    );
    let opened: String = other
        .decrypt(sealed, context)
        .await
        .unwrap_or_else(|error| panic!("another cipher must open the value: {error}"));
    assert_eq!(opened, "alice@example.com");

    let ore = keyset
        .ore_term(42u64, context)
        .await
        .unwrap_or_else(|error| panic!("an ORE term failed: {error}"));
    let ore_again = keyset.ore_term(42u64, context).await.expect("ORE again");
    assert_eq!(ore, ore_again);
}

/// A value opened under another context is refused.
pub async fn refuses_another_context<B: KeyVendorBackend>(backend: B, key_ref: &str) {
    let (cipher, _, _) = cipher_over(backend, key_ref, |s| s).await;
    let sealed = cipher
        .default_keyset()
        .encrypt_tree("secret".to_string(), nonempty!("users").with("email"))
        .await
        .expect("seal");
    let result = cipher
        .decrypt::<String, _>(sealed, nonempty!("users").with("phone"))
        .await;
    assert!(
        result.is_err(),
        "a value opened under another descriptor must be refused"
    );
}

/// A leaf of another key backend does not open, and costs no vendor call.
///
/// The leaf names its keyset and no backend. The ZeroKMS leaf's keyset is
/// in no record of this vendor, so the vendor answers "not found" before
/// any call. The vendor's leaf does not open under ZeroKMS either.
pub async fn refuses_another_key_backend<B: KeyVendorBackend>(backend: B, key_ref: &str) {
    let vendor = backend.vendor();
    let (cipher, _, observer) = cipher_over(backend, key_ref, |s| s).await;
    let zerokms = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await
        .expect("a ZeroKMS cipher");
    let sealed = zerokms
        .default_keyset()
        .encrypt_tree("zerokms".to_string(), b"ctx")
        .await
        .expect("seal under ZeroKMS");
    let before = observer.unwraps();
    match cipher.decrypt::<String, _>(sealed, b"ctx").await {
        Err(Error::Kms(KmsError::Backend {
            backend,
            kind: BackendErrorKind::NotFound,
            ..
        })) => assert_eq!(backend, vendor.into()),
        other => panic!("a ZeroKMS leaf must not open, got {other:?}"),
    }
    assert_eq!(observer.unwraps(), before, "refused before any key call");

    // And the other way: a ZeroKMS cipher does not open this vendor's leaf.
    let sealed = cipher
        .default_keyset()
        .encrypt_tree("vendor".to_string(), b"ctx")
        .await
        .expect("seal under the vendor");
    assert!(
        zerokms.decrypt::<String, _>(sealed, b"ctx").await.is_err(),
        "a vendor leaf must not open under ZeroKMS"
    );
}

fn assert_zerokms_only(result: Result<impl std::fmt::Debug, KmsError>, feature: ZeroKmsFeature) {
    match result {
        Err(KmsError::ZeroKmsOnly { feature: found, .. }) => assert_eq!(found, feature),
        other => panic!("expected a ZeroKmsOnly refusal of {feature}, got {other:?}"),
    }
}

/// ZeroKMS-only inputs are refused, never ignored.
pub async fn refuses_zerokms_features<B: KeyVendorBackend>(backend: B, key_ref: &str) {
    let (cipher, record, _) = cipher_over(backend, key_ref, |s| s).await;
    let source = cipher.kms();
    let keyset = Some(record.id());
    let tag = [Context::Tag("tenant".into())];
    assert_zerokms_only(
        source
            .generate_keys(
                vec![GenerateKeyPayload::new("d", Cow::Borrowed(&tag))],
                keyset,
                None,
            )
            .await,
        ZeroKmsFeature::Context,
    );
    assert_zerokms_only(
        source
            .generate_keys(
                vec![GenerateKeyPayload::new("d", Cow::Owned(vec![]))
                    .with_decryption_policy(DecryptionPolicy { conditions: vec![] })],
                keyset,
                None,
            )
            .await,
        ZeroKmsFeature::DecryptionPolicy,
    );
    let mut claims = std::collections::HashMap::new();
    let _ = claims.insert("sub".to_string(), None);
    let unverified = UnverifiedContext(claims);
    assert_zerokms_only(
        source
            .retrieve_keys(
                vec![RetrieveKeyPayload::new([0u8; 16], "d", b"")],
                keyset,
                Some(&unverified),
            )
            .await,
        ZeroKmsFeature::UnverifiedContext,
    );
}

/// The root key is unwrapped once per TTL. The index key is loaded once,
/// when the cipher loads the keyset, and the cipher keeps it: a term costs
/// no vendor call, even with a TTL of zero.
pub async fn obeys_the_root_key_ttl<B, F>(make: &F, key_ref: &str)
where
    B: KeyVendorBackend,
    F: Fn() -> B,
{
    let context = nonempty!("users").with("email");
    let (cipher, _, observer) = cipher_over(make(), key_ref, |s| s).await;
    let keyset = cipher.default_keyset();
    for _ in 0..3 {
        let _ = keyset.equality_term("v", context).await.expect("term");
        let _ = keyset
            .encrypt_tree("v".to_string(), context)
            .await
            .expect("seal");
    }
    assert_eq!(
        observer.unwraps(),
        1,
        "the root key is unwrapped once and kept for its TTL"
    );

    let (cipher, _, observer) = cipher_over(make(), key_ref, |source| {
        source.with_root_key_ttl(Duration::ZERO)
    })
    .await;
    let keyset = cipher.default_keyset();
    assert_eq!(observer.unwraps(), 1, "init loads the index key");
    for settle in 1..=3 {
        let _ = keyset
            .encrypt_tree("v".to_string(), context)
            .await
            .expect("seal");
        assert_eq!(
            observer.unwraps(),
            1 + settle,
            "an expired root key is unwrapped again"
        );
    }
    let _ = keyset.equality_term("v", context).await.expect("term");
    assert_eq!(
        observer.unwraps(),
        4,
        "the cipher keeps the index key, so a term makes no vendor call"
    );
}

/// A batch keeps its order.
pub async fn keeps_batch_order<B: KeyVendorBackend>(backend: B, key_ref: &str) {
    let (cipher, _, _) = cipher_over(backend, key_ref, |s| s).await;
    let values: Vec<String> = (0..25).map(|n| format!("value-{n}")).collect();
    let sealed = cipher
        .default_keyset()
        .encrypt_tree(values.clone(), b"batch")
        .await
        .unwrap_or_else(|error| panic!("sealing a batch failed: {error}"));
    let opened: Vec<String> = cipher
        .decrypt(sealed, b"batch")
        .await
        .unwrap_or_else(|error| panic!("opening a batch failed: {error}"));
    assert_eq!(opened, values, "a batch keeps its order");
}

/// A throttled call is retried; one throttled past the last attempt fails.
pub async fn backs_off_when_throttled<B, F>(make: &F, key_ref: &str)
where
    B: KeyVendorBackend,
    F: Fn() -> B,
{
    let options = RetryOptions {
        max_attempts: 3,
        base_delay: Duration::from_millis(1),
        ..RetryOptions::default()
    };
    let (cipher, _, observer) = cipher_over(make(), key_ref, |source| {
        source
            .with_retry_options(options.clone())
            .with_root_key_ttl(Duration::ZERO)
    })
    .await;
    let keyset = cipher.default_keyset();
    // With a TTL of zero each seal unwraps the root key: one call.
    observer.throttle_next(1);
    let sealed = keyset
        .encrypt_tree("v".to_string(), b"ctx")
        .await
        .unwrap_or_else(|error| panic!("a throttled call must be retried: {error}"));
    let opened: String = cipher.decrypt(sealed, b"ctx").await.expect("open");
    assert_eq!(opened, "v");

    observer.throttle_next(options.max_attempts as usize);
    match keyset.encrypt_tree("v".to_string(), b"ctx").await {
        Err(Error::Kms(KmsError::Backend {
            kind: BackendErrorKind::Throttled,
            ..
        })) => {}
        other => panic!("still throttled after the last attempt must fail, got {other:?}"),
    }
    observer.throttle_next(0);
}
