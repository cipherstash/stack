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
//! The checks, for each key mode the vendor offers:
//!
//! * a value and an index term round-trip, as a v2 leaf that names the
//!   vendor and the mode, and a second cipher derives the same term;
//! * a value opened under another context (descriptor) is refused;
//! * a leaf of another key backend is refused before any key call;
//! * ZeroKMS-only inputs are refused, never ignored;
//! * the key lifetime is obeyed: under wrapped data keys each settle that
//!   builds a term unwraps the index key again and the handle holds none;
//!   under derived data keys the root key is unwrapped once per TTL;
//! * a batch keeps its order;
//! * a vendor with a batch operation wraps and unwraps the wrapped data
//!   keys of a batch in one call per chunk of at most its batch limit;
//! * a throttled call is retried, and a call still throttled after the last
//!   attempt fails the whole batch.
//!
//! Plus, for every vendor: a record refuses a mode the vendor does not
//! offer.

// A contract check is a test: it panics with the rule it found broken.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::borrow::Cow;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use stack_encrypt::kms::{
    BackendErrorKind, Context, DataKeySource, DecryptionPolicy, Error as KmsError,
    FakeDataKeySource, GenerateKeyPayload, KeyBackend, KeyMode, KeyVendor, RetrieveKeyPayload,
    UnverifiedContext, ZeroKmsFeature,
};
use stack_encrypt::{nonempty, CipherText, Error, StackCipher, StackCipherText};

use crate::{
    BatchOptions, KeyBytes, KeyVendorBackend, KeysetRecord, RecordError, UnwrapItem,
    VendorKeySource, WrapItem,
};

/// Run every check of the contract against the backends `make` builds, for
/// each key mode the backend offers. `key_ref` names a vendor key the
/// backend may wrap and unwrap under.
pub async fn run<B, F>(make: F, key_ref: &str)
where
    B: KeyVendorBackend + 'static,
    F: Fn() -> B,
{
    refuses_a_mode_it_does_not_offer(make(), key_ref).await;
    for mode in KeyMode::ALL {
        if !make().supports_mode(mode) {
            continue;
        }
        round_trip(&make, key_ref, mode).await;
        refuses_another_context(make(), key_ref, mode).await;
        refuses_another_key_backend(make(), key_ref, mode).await;
        refuses_zerokms_features(make(), key_ref, mode).await;
        obeys_the_key_lifetime(&make, key_ref, mode).await;
        keeps_batch_order(make(), key_ref, mode).await;
        uses_vendor_batches(make(), key_ref, mode).await;
        backs_off_when_throttled(&make, key_ref, mode).await;
    }
}

/// A key vendor backend that counts the calls it forwards, and can refuse
/// the next calls as throttled.
pub struct Observed<B> {
    inner: B,
    wraps: Arc<AtomicUsize>,
    unwraps: Arc<AtomicUsize>,
    batches: Arc<AtomicUsize>,
    throttle_next: Arc<AtomicUsize>,
}

/// The counters and the throttle of an [`Observed`] backend, kept by the
/// test after the backend moves into a key source.
#[derive(Clone)]
pub struct Observer {
    wraps: Arc<AtomicUsize>,
    unwraps: Arc<AtomicUsize>,
    batches: Arc<AtomicUsize>,
    throttle_next: Arc<AtomicUsize>,
}

impl Observer {
    /// Batch calls forwarded so far ([`KeyVendorBackend::wrap_batch`] and
    /// [`KeyVendorBackend::unwrap_batch`]). Their keys also count as wraps
    /// and unwraps.
    pub fn batches(&self) -> usize {
        self.batches.load(Ordering::SeqCst)
    }

    /// Wrap calls forwarded so far (`generate_wrapped` included).
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
            batches: Arc::default(),
            throttle_next: Arc::default(),
        };
        (
            Self {
                inner,
                wraps: Arc::clone(&observer.wraps),
                unwraps: Arc::clone(&observer.unwraps),
                batches: Arc::clone(&observer.batches),
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

    fn supports_mode(&self, mode: KeyMode) -> bool {
        self.inner.supports_mode(mode)
    }

    fn same_key(&self, a: &str, b: &str) -> bool {
        self.inner.same_key(a, b)
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

    fn batch_limit(&self) -> Option<NonZeroUsize> {
        self.inner.batch_limit()
    }

    async fn wrap_batch(
        &self,
        key_ref: &str,
        items: &[WrapItem<'_>],
    ) -> Result<Vec<Vec<u8>>, KmsError> {
        self.throttle()?;
        let _ = self.batches.fetch_add(1, Ordering::SeqCst);
        let _ = self.wraps.fetch_add(items.len(), Ordering::SeqCst);
        self.inner.wrap_batch(key_ref, items).await
    }

    async fn unwrap_batch(
        &self,
        key_ref: &str,
        items: &[UnwrapItem<'_>],
    ) -> Result<Vec<KeyBytes>, KmsError> {
        self.throttle()?;
        let _ = self.batches.fetch_add(1, Ordering::SeqCst);
        let _ = self.unwraps.fetch_add(items.len(), Ordering::SeqCst);
        self.inner.unwrap_batch(key_ref, items).await
    }

    // `generate_wrapped` is not forwarded: the default (a local key and
    // one `wrap`) is what this suite counts, and a vendor's own override is
    // covered by the round trip.

    async fn sleep(&self, duration: Duration) {
        self.inner.sleep(duration).await;
    }
}

/// A cipher over one fresh keyset of `backend` in `mode`, with its record.
async fn cipher_over<B: KeyVendorBackend>(
    backend: B,
    key_ref: &str,
    mode: KeyMode,
    configure: impl FnOnce(VendorKeySource<Observed<B>>) -> VendorKeySource<Observed<B>>,
) -> (
    StackCipher<VendorKeySource<Observed<B>>>,
    KeysetRecord,
    Observer,
) {
    let (backend, observer) = Observed::new(backend);
    let record = KeysetRecord::create(&backend, key_ref, mode, Some("contract".into()))
        .await
        .unwrap_or_else(|error| panic!("creating a {mode} keyset record failed: {error}"));
    let source = configure(
        VendorKeySource::new(backend, [record.clone()])
            .unwrap_or_else(|error| panic!("loading the {mode} record failed: {error}")),
    );
    let cipher = StackCipher::builder()
        .kms(source)
        .init()
        .await
        .unwrap_or_else(|error| panic!("a cipher over a {mode} keyset failed to init: {error}"));
    (cipher, record, observer)
}

fn single(ciphertext: &StackCipherText) -> &stack_encrypt::SealedValue {
    match ciphertext {
        CipherText::Single(leaf) => leaf,
        _ => panic!("a string seals as one leaf"),
    }
}

/// A value and an index term round-trip, the leaf is v2, and a second
/// cipher over the same record (a backend from `make`) derives the same
/// term and opens the same value.
pub async fn round_trip<B, F>(make: &F, key_ref: &str, mode: KeyMode)
where
    B: KeyVendorBackend,
    F: Fn() -> B,
{
    let backend = make();
    let vendor = backend.vendor();
    let (cipher, record, _) = cipher_over(backend, key_ref, mode, |s| s).await;
    let keyset = cipher.default_keyset();
    assert_eq!(
        keyset.keyset_id(),
        record.id(),
        "the only record is the default keyset"
    );
    let context = nonempty!("users").with("email");

    let sealed = keyset
        .encrypt("alice@example.com".to_string(), context)
        .await
        .unwrap_or_else(|error| panic!("{mode}: sealing failed: {error}"));
    let leaf = single(&sealed);
    assert_eq!(
        leaf.format_version(),
        2,
        "{mode}: a key vendor backend seals v2 leaves"
    );
    assert_eq!(leaf.key_backend(), KeyBackend::Vendor(vendor));
    assert_eq!(leaf.key_mode(), Some(mode));
    assert_eq!(leaf.keyset_id(), record.id());
    match mode {
        KeyMode::Derived => assert!(leaf.tag().is_empty(), "a derived data key has no tag"),
        KeyMode::Wrapped => assert!(!leaf.tag().is_empty(), "the tag holds the wrapped key"),
    }
    let bytes = leaf.to_bytes();
    let reread = stack_encrypt::SealedValue::from_bytes(&bytes).expect("a v2 leaf decodes");
    let opened: String = cipher
        .decrypt(CipherText::Single(reread.clone()), context)
        .await
        .unwrap_or_else(|error| panic!("{mode}: opening failed: {error}"));
    assert_eq!(opened, "alice@example.com");

    let term = keyset
        .equality_term("alice@example.com", context)
        .await
        .unwrap_or_else(|error| panic!("{mode}: an equality term failed: {error}"));
    let again = keyset
        .equality_term("alice@example.com", context)
        .await
        .expect("a second term");
    assert_eq!(
        term.as_bytes(),
        again.as_bytes(),
        "{mode}: terms are deterministic"
    );
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
        "{mode}: another cipher with the same record derives the same term"
    );
    let opened: String = other
        .decrypt(sealed, context)
        .await
        .unwrap_or_else(|error| panic!("{mode}: another cipher must open the value: {error}"));
    assert_eq!(opened, "alice@example.com");

    let ore = keyset
        .ore_term(42u64, context)
        .await
        .unwrap_or_else(|error| panic!("{mode}: an ORE term failed: {error}"));
    let ore_again = keyset.ore_term(42u64, context).await.expect("ORE again");
    assert_eq!(ore, ore_again);
}

/// A value opened under another context is refused.
pub async fn refuses_another_context<B: KeyVendorBackend>(
    backend: B,
    key_ref: &str,
    mode: KeyMode,
) {
    let (cipher, _, _) = cipher_over(backend, key_ref, mode, |s| s).await;
    let sealed = cipher
        .default_keyset()
        .encrypt("secret".to_string(), nonempty!("users").with("email"))
        .await
        .expect("seal");
    let result = cipher
        .decrypt::<String, _>(sealed, nonempty!("users").with("phone"))
        .await;
    assert!(
        result.is_err(),
        "{mode}: a value opened under another descriptor must be refused"
    );
}

/// A leaf of another key backend is refused before any key call.
pub async fn refuses_another_key_backend<B: KeyVendorBackend>(
    backend: B,
    key_ref: &str,
    mode: KeyMode,
) {
    let vendor = backend.vendor();
    let (cipher, _, observer) = cipher_over(backend, key_ref, mode, |s| s).await;
    let zerokms = StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await
        .expect("a ZeroKMS cipher");
    let sealed = zerokms
        .default_keyset()
        .encrypt("zerokms".to_string(), b"ctx")
        .await
        .expect("seal under ZeroKMS");
    let before = observer.unwraps();
    match cipher.decrypt::<String, _>(sealed, b"ctx").await {
        Err(Error::ForeignBackend { expected, found }) => {
            assert_eq!(expected, KeyBackend::Vendor(vendor));
            assert_eq!(found, KeyBackend::ZeroKms);
        }
        other => panic!("{mode}: a ZeroKMS leaf must be refused, got {other:?}"),
    }
    assert_eq!(
        observer.unwraps(),
        before,
        "{mode}: refused before any key call"
    );

    // And the other way: a ZeroKMS cipher refuses this vendor's leaf.
    let sealed = cipher
        .default_keyset()
        .encrypt("vendor".to_string(), b"ctx")
        .await
        .expect("seal under the vendor");
    assert!(matches!(
        zerokms.decrypt::<String, _>(sealed, b"ctx").await,
        Err(Error::ForeignBackend { .. })
    ));
}

fn assert_zerokms_only(result: Result<impl std::fmt::Debug, KmsError>, feature: ZeroKmsFeature) {
    match result {
        Err(KmsError::ZeroKmsOnly { feature: found, .. }) => assert_eq!(found, feature),
        other => panic!("expected a ZeroKmsOnly refusal of {feature}, got {other:?}"),
    }
}

/// ZeroKMS-only inputs are refused, never ignored.
pub async fn refuses_zerokms_features<B: KeyVendorBackend>(
    backend: B,
    key_ref: &str,
    mode: KeyMode,
) {
    let (cipher, record, _) = cipher_over(backend, key_ref, mode, |s| s).await;
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

/// The key lifetime is obeyed.
pub async fn obeys_the_key_lifetime<B, F>(make: &F, key_ref: &str, mode: KeyMode)
where
    B: KeyVendorBackend,
    F: Fn() -> B,
{
    let context = nonempty!("users").with("email");
    match mode {
        KeyMode::Wrapped => {
            let (cipher, record, observer) = cipher_over(make(), key_ref, mode, |s| s).await;
            let selected = cipher.keyset(record.id()).await.expect("select by id");
            assert!(
                selected.prf().is_none(),
                "a wrapped-data-key handle holds no index key"
            );
            let after_select = observer.unwraps();
            let named = cipher
                .keyset(stack_encrypt::kms::IdentifiedBy::Name(
                    "contract".to_string().into(),
                ))
                .await
                .expect("select by name");
            assert_eq!(named.keyset_id(), record.id(), "a name resolves locally");
            assert_eq!(
                observer.unwraps(),
                after_select,
                "selection makes no vendor call"
            );
            for settle in 1..=3 {
                let _ = selected.equality_term("v", context).await.expect("term");
                assert_eq!(
                    observer.unwraps(),
                    after_select + settle,
                    "each settle that builds a term unwraps the index key again"
                );
            }
            // Two terms in one settle share one unwrap.
            let _ = selected
                .equality_term("a", context)
                .zip(selected.equality_term("b", context))
                .await
                .expect("two terms");
            assert_eq!(
                observer.unwraps(),
                after_select + 4,
                "one unwrap per settle"
            );
        }
        KeyMode::Derived => {
            let (cipher, _, observer) = cipher_over(make(), key_ref, mode, |s| s).await;
            let keyset = cipher.default_keyset();
            assert!(keyset.prf().is_none(), "the handle holds no index key");
            for _ in 0..3 {
                let _ = keyset.equality_term("v", context).await.expect("term");
                let _ = keyset
                    .encrypt("v".to_string(), context)
                    .await
                    .expect("seal");
            }
            assert_eq!(
                observer.unwraps(),
                1,
                "the root key is unwrapped once and kept for its TTL"
            );

            let (cipher, _, observer) = cipher_over(make(), key_ref, mode, |source| {
                source.with_root_key_ttl(Duration::ZERO)
            })
            .await;
            let keyset = cipher.default_keyset();
            for settle in 1..=3 {
                let _ = keyset.equality_term("v", context).await.expect("term");
                assert_eq!(
                    observer.unwraps(),
                    settle,
                    "an expired root key is unwrapped again"
                );
            }
        }
    }
}

/// A batch keeps its order.
pub async fn keeps_batch_order<B: KeyVendorBackend>(backend: B, key_ref: &str, mode: KeyMode) {
    let (cipher, _, _) = cipher_over(backend, key_ref, mode, |source| {
        source.with_batch_options(BatchOptions {
            concurrency: std::num::NonZeroUsize::new(4).unwrap_or(std::num::NonZeroUsize::MIN),
            ..BatchOptions::default()
        })
    })
    .await;
    let values: Vec<String> = (0..25).map(|n| format!("value-{n}")).collect();
    let sealed = cipher
        .default_keyset()
        .encrypt(values.clone(), b"batch")
        .await
        .unwrap_or_else(|error| panic!("{mode}: sealing a batch failed: {error}"));
    let opened: Vec<String> = cipher
        .decrypt(sealed, b"batch")
        .await
        .unwrap_or_else(|error| panic!("{mode}: opening a batch failed: {error}"));
    assert_eq!(opened, values, "{mode}: a batch keeps its order");
}

/// A vendor with a batch operation makes one call per chunk of wrapped data
/// keys, under wrapped data keys. Nothing to check for another vendor or
/// mode.
pub async fn uses_vendor_batches<B: KeyVendorBackend>(backend: B, key_ref: &str, mode: KeyMode) {
    let Some(limit) = backend.batch_limit() else {
        return;
    };
    if mode != KeyMode::Wrapped {
        return;
    }
    let limit = limit.get();
    let (cipher, _, observer) = cipher_over(backend, key_ref, mode, |s| s).await;
    let count = 2 * limit + 1;
    let values: Vec<String> = (0..count).map(|n| format!("value-{n}")).collect();
    let before = observer.batches();
    let sealed = cipher
        .default_keyset()
        .encrypt(values.clone(), b"batch")
        .await
        .unwrap_or_else(|error| panic!("{mode}: sealing in vendor batches failed: {error}"));
    assert_eq!(
        observer.batches() - before,
        3,
        "{mode}: {count} values seal in three batch calls of at most {limit}"
    );
    let before = observer.batches();
    let opened: Vec<String> = cipher
        .decrypt(sealed, b"batch")
        .await
        .unwrap_or_else(|error| panic!("{mode}: opening in vendor batches failed: {error}"));
    assert_eq!(opened, values, "{mode}: vendor batches keep their order");
    assert_eq!(
        observer.batches() - before,
        3,
        "{mode}: {count} values open in three batch calls of at most {limit}"
    );
}

/// A throttled call is retried; one throttled past the last attempt fails
/// the batch.
pub async fn backs_off_when_throttled<B, F>(make: &F, key_ref: &str, mode: KeyMode)
where
    B: KeyVendorBackend,
    F: Fn() -> B,
{
    let options = BatchOptions {
        max_attempts: 3,
        base_delay: Duration::from_millis(1),
        ..BatchOptions::default()
    };
    let (cipher, _, observer) = cipher_over(make(), key_ref, mode, |source| {
        source
            .with_batch_options(options.clone())
            .with_root_key_ttl(Duration::ZERO)
    })
    .await;
    let keyset = cipher.default_keyset();
    // Derived data keys make one call per settle (the root key); wrapped
    // data keys one per value. One throttle either way is retried.
    observer.throttle_next(1);
    let sealed = keyset
        .encrypt("v".to_string(), b"ctx")
        .await
        .unwrap_or_else(|error| panic!("{mode}: a throttled call must be retried: {error}"));
    let opened: String = cipher.decrypt(sealed, b"ctx").await.expect("open");
    assert_eq!(opened, "v");

    if mode == KeyMode::Wrapped {
        observer.throttle_next(options.max_attempts as usize);
        match keyset.encrypt("v".to_string(), b"ctx").await {
            Err(Error::Kms(KmsError::Backend {
                kind: BackendErrorKind::Throttled,
                ..
            })) => {}
            other => panic!("{mode}: still throttled must fail the batch, got {other:?}"),
        }
        observer.throttle_next(0);
    }
}

/// A record refuses a mode the vendor does not offer.
pub async fn refuses_a_mode_it_does_not_offer<B: KeyVendorBackend>(backend: B, key_ref: &str) {
    for mode in KeyMode::ALL {
        if backend.supports_mode(mode) {
            continue;
        }
        match KeysetRecord::create(&backend, key_ref, mode, None).await {
            Err(RecordError::ModeUnsupported { mode: refused, .. }) => assert_eq!(refused, mode),
            other => {
                panic!("a record in an unsupported mode {mode} must be refused, got {other:?}")
            }
        }
    }
}
