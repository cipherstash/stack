//! A credential attached to a call reaches every request the call makes,
//! and only those: on encrypt and decrypt, through every public way to
//! make a call, with two callers interleaved on one cipher. A cipher over
//! a key source that takes a credential with each call loads no keyset at
//! `init`: the first call that is awaited loads the default keyset, with
//! its credential. A keyset selected by id or by name is loaded the same
//! way.
//!
//! Every test runs against a fake key source that records the credential
//! each request carried, so none needs the network. The source takes a
//! credential with every request, as a ZeroKMS client does over a
//! `stack_auth::OidcFederationStrategy` built with `credential_per_call`.
//! It has no request without one, so a call that is awaited with no
//! credential does not compile: `tests/ui` holds that case, and the one
//! of a credential passed to a key source with an identity of its own.

use std::borrow::Cow;
use std::future::IntoFuture;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;

use serde_json::json;
use stack_encrypt::json::{JsonDocument, JsonOptions, JsonPlaintext};
use stack_encrypt::kms::{
    CredentialKeySource, DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource,
    GenerateKeyPayload, IdentifiedBy, IndexKey, IndexKeySource, RetrieveKeyError,
    RetrieveKeyPayload, SecretToken, UnverifiedContext,
};
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{
    self, json_document, AeadContext, Borrowed, CallerContext, DecryptSource, Decryption,
    EncryptTarget,
};
use stack_encrypt::{
    nonempty, AuditMetadata, Ciphertext, DecryptFrom, EncryptInto, Encrypted, Error, Pending,
    StackCipher, StackCipherText,
};
use uuid::Uuid;
use zeroize::Zeroize;

/// Which key request was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    Generate,
    Retrieve,
    /// A keyset load: the default keyset's, or a named one's.
    Load,
}

/// One key request as the key source received it: the call, and the
/// credential it carried (`None` when it carried none).
type Sent = (Call, Option<String>);

const ALICE: &str = "alice.jwt";
const BOB: &str = "bob.jwt";

fn alice() -> SecretToken {
    SecretToken::new(ALICE)
}

fn bob() -> SecretToken {
    SecretToken::new(BOB)
}

/// `call`, made with `credential`.
fn with(call: Call, credential: &str) -> Sent {
    (call, Some(credential.to_string()))
}

/// A fake key source that takes a credential with every key request, and
/// records it. Clones share one key store and one record, so two can stand
/// for two processes.
///
/// [`OwnIdentity`] is the same store as a key source with an identity of
/// its own: its requests carry no credential.
#[derive(Clone)]
struct Source {
    inner: Arc<FakeDataKeySource>,
    sent: Arc<Mutex<Vec<Sent>>>,
    /// How many of the next keyset loads to refuse, as ZeroKMS refuses a
    /// credential it does not accept.
    refuse_loads: Arc<AtomicUsize>,
    /// Whether every audited request carried the audit metadata it was
    /// sent with: counted so a test can check both arrive together.
    audited: Arc<AtomicUsize>,
}

impl Source {
    fn new() -> Self {
        Self {
            inner: Arc::new(FakeDataKeySource::new()),
            sent: Arc::default(),
            refuse_loads: Arc::default(),
            audited: Arc::default(),
        }
    }

    /// Refuse the next `count` keyset loads.
    fn refuse_loads(&self, count: usize) {
        self.refuse_loads.store(count, Ordering::SeqCst);
    }

    /// The requests made so far, cleared.
    fn take(&self) -> Vec<Sent> {
        std::mem::take(&mut *self.sent.lock().unwrap())
    }

    /// How many requests so far carried audit metadata.
    fn audited(&self) -> usize {
        self.audited.load(Ordering::SeqCst)
    }

    /// Record the request.
    fn receive(&self, call: Call, credential: Option<&SecretToken>, audited: bool) {
        let credential = credential.map(|credential| credential.as_str().to_string());
        self.sent.lock().unwrap().push((call, credential));
        if audited {
            let _ = self.audited.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn generate(
        &self,
        credential: Option<&SecretToken>,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_encrypt::kms::Error> {
        self.receive(Call::Generate, credential, context.is_some());
        self.inner.generate_keys(payloads, keyset_id, context).await
    }

    async fn retrieve(
        &self,
        credential: Option<&SecretToken>,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_encrypt::kms::Error> {
        self.receive(Call::Retrieve, credential, context.is_some());
        self.inner.retrieve_keys(payloads, keyset_id, context).await
    }

    async fn load(
        &self,
        credential: Option<&SecretToken>,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_encrypt::kms::Error> {
        self.receive(Call::Load, credential, false);
        // A load takes a turn of the runtime, as a real one takes a round
        // trip: callers that arrive together overlap here.
        tokio::task::yield_now().await;
        let refuse = self
            .refuse_loads
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok();
        if refuse {
            return Err(refusal(CREDENTIAL_REFUSED));
        }
        self.inner.load_index_key(keyset_id).await
    }
}

const CREDENTIAL_REFUSED: &str = "the credential was refused";

/// A refusal from the key source, told apart by its text.
fn refusal(why: &str) -> stack_encrypt::kms::Error {
    stack_encrypt::kms::Error::RetrieveKey(RetrieveKeyError::FailedRetrieval(why.to_string()))
}

/// Whether `error` is the key source's refusal `why`.
fn is_refusal(error: &Error, why: &str) -> bool {
    matches!(
        error,
        Error::Kms(stack_encrypt::kms::Error::RetrieveKey(
            RetrieveKeyError::FailedRetrieval(text)
        )) if text == why
    )
}

/// The key store of a [`Source`], as a key source with an identity of its
/// own: every request is made with no credential.
#[derive(Clone)]
struct OwnIdentity(Source);

impl stack_encrypt::kms::KeySourceKind for OwnIdentity {
    type Kind = stack_encrypt::kms::OwnIdentity;
}

impl DataKeySource for OwnIdentity {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_encrypt::kms::Error> {
        self.0
            .generate(None, payloads, keyset_id, unverified_context)
            .await
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_encrypt::kms::Error> {
        self.0
            .retrieve(None, payloads, keyset_id, unverified_context)
            .await
    }
}

impl IndexKeySource for OwnIdentity {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_encrypt::kms::Error> {
        self.0.load(None, keyset_id).await
    }
}

impl stack_encrypt::kms::KeySourceKind for Source {
    type Kind = stack_encrypt::kms::CredentialPerCall;
}

impl CredentialKeySource for Source {
    async fn generate_keys_with_credential(
        &self,
        credential: &SecretToken,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_encrypt::kms::Error> {
        self.generate(Some(credential), payloads, keyset_id, unverified_context)
            .await
    }

    async fn retrieve_keys_with_credential(
        &self,
        credential: &SecretToken,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_encrypt::kms::Error> {
        self.retrieve(Some(credential), payloads, keyset_id, unverified_context)
            .await
    }

    async fn load_index_key_with_credential(
        &self,
        credential: &SecretToken,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_encrypt::kms::Error> {
        self.load(Some(credential), keyset_id).await
    }
}

/// A cipher over a key source that takes a credential with each call, and
/// that key source. `init` had no credential, so it made no request, and
/// the cipher has loaded no keyset.
async fn unloaded() -> (StackCipher<Source>, Source) {
    let source = Source::new();
    let cipher = StackCipher::builder()
        .kms(source.clone())
        .init()
        .await
        .expect("init loads nothing for a key source that takes a credential");
    assert_eq!(source.take(), vec![]);
    (cipher, source)
}

/// Such a cipher once Alice's credential has loaded the default keyset,
/// with the record of that load cleared.
async fn loaded() -> (StackCipher<Source>, Source) {
    let (shared, source) = unloaded().await;
    let _ = shared
        .default_keyset()
        .keyset_id()
        .with_credential(alice())
        .await
        .expect("load");
    assert_eq!(source.take(), vec![with(Call::Load, ALICE)]);
    (shared, source)
}

fn tenant_b() -> IdentifiedBy {
    IdentifiedBy::Name("tenant-b".to_string().into())
}

// ---- building the cipher ---------------------------------------------------

/// A key source that takes a credential with each call has nothing to
/// load the default keyset with at startup. `init` makes no request, and
/// returns the cipher.
#[tokio::test]
async fn init_makes_no_request_for_a_key_source_that_takes_a_credential() {
    let source = Source::new();
    let cipher = StackCipher::builder().kms(source.clone()).init().await;
    assert!(cipher.is_ok(), "init must not fail: {:?}", cipher.err());
    assert_eq!(source.take(), vec![]);
    assert!(format!("{cipher:?}").contains("default_keyset_id: None"));
}

/// Taking a keyset makes no request and cannot fail: the default keyset,
/// or one selected by name. The first call on the handle loads it.
#[tokio::test]
async fn taking_a_keyset_makes_no_request() {
    let (shared, source) = unloaded().await;
    let keyset = shared.default_keyset();
    let tenant = shared.keyset(tenant_b());
    assert_eq!(source.take(), vec![]);
    assert!(format!("{keyset:?}").contains("keyset_id: None"));
    assert!(format!("{tenant:?}").contains("keyset_id: None"));

    let _: Ciphertext = keyset.encrypt(1i64).with_credential(bob()).await.unwrap();
    assert_eq!(
        source.take(),
        vec![with(Call::Load, BOB), with(Call::Generate, BOB)]
    );
    assert!(format!("{keyset:?}").contains("keyset_id: Some("));

    let _: Ciphertext = tenant.encrypt(1i64).with_credential(alice()).await.unwrap();
    assert_eq!(
        source.take(),
        vec![with(Call::Load, ALICE), with(Call::Generate, ALICE)],
        "the keyset selected by name is loaded by its own first call"
    );
    assert!(format!("{tenant:?}").contains("keyset_id: Some("));
}

/// The first call that is awaited loads the default keyset, with the
/// credential of that call, beside its own key request. Every later call
/// finds the keyset loaded and loads nothing.
#[tokio::test]
async fn the_first_call_loads_the_default_keyset_and_later_ones_load_nothing() {
    let (shared, source) = unloaded().await;

    let first = shared.default_keyset();
    let stored: Ciphertext = first.encrypt(7i64).with_credential(bob()).await.unwrap();
    assert_eq!(
        source.take(),
        vec![with(Call::Load, BOB), with(Call::Generate, BOB)]
    );
    let default = first.keyset_id().with_credential(alice()).await.unwrap();

    for credential in [alice(), bob(), alice()] {
        let keyset = shared.default_keyset();
        let id = keyset.keyset_id().with_credential(credential).await;
        assert_eq!(id.unwrap(), default);
    }
    // A handle taken before the load is on the loaded keyset too.
    let back: i64 = first.decrypt(stored).with_credential(bob()).await.unwrap();
    assert_eq!(back, 7);
    assert_eq!(
        source.take(),
        vec![with(Call::Retrieve, BOB)],
        "no load once the default keyset is loaded"
    );
}

/// Reading the keyset's id loads the keyset too, and nothing else. Once
/// the keyset is loaded, reading it makes no request, so it needs no
/// credential.
#[tokio::test]
async fn reading_the_keyset_id_loads_the_default_keyset() {
    let (shared, source) = unloaded().await;
    let keyset = shared.default_keyset();

    let id = keyset.keyset_id().with_credential(bob()).await.unwrap();
    assert_eq!(source.take(), vec![with(Call::Load, BOB)]);
    assert_eq!(
        keyset.keyset_id().with_credential(alice()).await.unwrap(),
        id
    );
    assert_eq!(
        keyset.keyset_name().with_credential(alice()).await.unwrap(),
        None
    );
    assert_eq!(source.take(), vec![], "read from the loaded keyset");
}

/// Callers that arrive together before the default keyset is loaded make
/// one load between them. Each call is still made with its own credential.
#[tokio::test]
async fn callers_arriving_together_make_one_default_keyset_load() {
    let (shared, source) = unloaded().await;
    let (a, b, c) = (
        shared.default_keyset(),
        shared.default_keyset(),
        shared.default_keyset(),
    );

    let (ea, eb, ec) = tokio::join!(
        a.encrypt(1i64).with_credential(alice()).into_future(),
        b.encrypt(2i64).with_credential(bob()).into_future(),
        c.encrypt(3i64).with_credential(alice()).into_future(),
    );
    let _: (Ciphertext, Ciphertext, Ciphertext) = (ea.unwrap(), eb.unwrap(), ec.unwrap());

    let sent = source.take();
    let loads: Vec<&Sent> = sent
        .iter()
        .filter(|(call, _)| *call == Call::Load)
        .collect();
    assert_eq!(
        loads,
        [&with(Call::Load, ALICE)],
        "the first caller loads; the others wait for it"
    );
    let mut generates: Vec<Sent> = sent
        .iter()
        .filter(|(call, _)| *call == Call::Generate)
        .cloned()
        .collect();
    generates.sort_by(|a, b| a.1.cmp(&b.1));
    assert_eq!(
        generates,
        vec![
            with(Call::Generate, ALICE),
            with(Call::Generate, ALICE),
            with(Call::Generate, BOB),
        ]
    );
}

/// A first load that is refused fails that call and loads nothing. The
/// next caller tries again with its own credential.
#[tokio::test]
async fn a_refused_first_load_leaves_the_keyset_unloaded_for_the_next_caller() {
    let (shared, source) = unloaded().await;
    source.refuse_loads(1);

    let refused: Result<Ciphertext, _> = shared
        .default_keyset()
        .encrypt(1i64)
        .with_credential(alice())
        .await;
    assert!(
        refused.is_err_and(|error| is_refusal(&error, CREDENTIAL_REFUSED)),
        "the first caller sees the refusal"
    );
    assert_eq!(
        source.take(),
        vec![with(Call::Load, ALICE)],
        "no data key is requested when the keyset cannot be loaded"
    );

    let _: Ciphertext = shared
        .default_keyset()
        .encrypt(1i64)
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![with(Call::Load, BOB), with(Call::Generate, BOB)]
    );
}

/// A caller that stops waiting for the first load (its request was
/// cancelled) leaves the keyset unloaded, and the load unlocked, for the
/// next caller.
#[tokio::test]
async fn a_caller_that_stops_waiting_leaves_the_keyset_unloaded_for_the_next_caller() {
    let (shared, source) = unloaded().await;

    let keyset = shared.default_keyset();
    let mut first = keyset.keyset_id().with_credential(alice()).into_future();
    let pending =
        std::future::poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx).is_pending())).await;
    assert!(pending, "the first caller is waiting on its load");
    drop(first);

    let _: Ciphertext = shared
        .default_keyset()
        .encrypt(1i64)
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![
            with(Call::Load, ALICE),
            with(Call::Load, BOB),
            with(Call::Generate, BOB),
        ]
    );
}

/// A call loads the keyset it works under, and no other. The first call
/// of a process may be on a tenant's keyset: it makes one load, of that
/// keyset, and the default keyset stays unloaded until a call needs it.
#[tokio::test]
async fn a_first_call_on_a_selected_keyset_does_not_load_the_default_keyset() {
    let (shared, source) = unloaded().await;
    let tenant = shared
        .keyset(tenant_b())
        .keyset_id()
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![with(Call::Load, BOB)],
        "one load, of the keyset selected"
    );
    let shown = format!("{shared:?}");
    assert!(
        shown.contains("default_keyset_id: None"),
        "the default keyset is not loaded, got: {shown}"
    );

    // The selected keyset is kept: a second call on it loads nothing.
    let stored: Ciphertext = shared
        .keyset(tenant_b())
        .encrypt(7i64)
        .with_credential(alice())
        .await
        .unwrap();
    assert_eq!(source.take(), vec![with(Call::Generate, ALICE)]);

    // The first call on the default keyset loads it, as its own caller.
    let default = shared
        .default_keyset()
        .keyset_id()
        .with_credential(alice())
        .await
        .unwrap();
    assert_eq!(source.take(), vec![with(Call::Load, ALICE)]);
    assert_ne!(default, tenant);

    // Both are loaded now, and neither is loaded again.
    for keyset in [shared.default_keyset(), shared.keyset(tenant_b())] {
        let _ = keyset.keyset_id().with_credential(bob()).await.unwrap();
    }
    assert_eq!(source.take(), vec![]);

    // The value was sealed under the tenant's keyset: it opens through
    // that handle.
    let back: i64 = shared
        .keyset(tenant_b())
        .decrypt(stored)
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(back, 7);
    assert_eq!(source.take(), vec![with(Call::Retrieve, BOB)]);
}

/// A record is sealed through a keyset handle. The first one through the
/// default keyset loads it, with its own credential.
#[tokio::test]
async fn a_first_record_through_the_default_keyset_loads_it_with_its_credential() {
    let (shared, source) = unloaded().await;
    let _: EncryptedAccount = account()
        .encrypt_into(&shared.default_keyset())
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![with(Call::Load, BOB), with(Call::Generate, BOB)]
    );
}

/// The default keyset can be selected by its id before it is loaded as
/// the default. The cipher cannot know yet that the two are one keyset, so
/// each selection makes its own load. From then on they are one: both
/// handles read the same keyset, and neither loads again.
#[tokio::test]
async fn the_default_keyset_selected_by_id_before_its_load_is_the_same_keyset_after() {
    // Another process on the same key store tells this one the id.
    let (elsewhere, source) = loaded().await;
    let default_id = elsewhere
        .default_keyset()
        .keyset_id()
        .with_credential(alice())
        .await
        .unwrap();
    let shared = StackCipher::builder()
        .kms(source.clone())
        .init()
        .await
        .unwrap();
    assert_eq!(source.take(), vec![]);

    let by_id = shared.keyset(default_id);
    let stored: Ciphertext = by_id.encrypt(7i64).with_credential(bob()).await.unwrap();
    assert_eq!(
        source.take(),
        vec![with(Call::Load, BOB), with(Call::Generate, BOB)]
    );

    let default = shared.default_keyset();
    assert_eq!(
        default.keyset_id().with_credential(alice()).await.unwrap(),
        default_id
    );
    assert_eq!(source.take(), vec![with(Call::Load, ALICE)]);

    // A value sealed through one handle opens through the other, and a
    // new selection by id finds the keyset loaded.
    let back: i64 = default
        .decrypt(stored)
        .with_credential(alice())
        .await
        .unwrap();
    assert_eq!(back, 7);
    let again: Ciphertext = shared
        .keyset(default_id)
        .encrypt(8i64)
        .with_credential(bob())
        .await
        .unwrap();
    drop(again);
    assert_eq!(
        source.take(),
        vec![with(Call::Retrieve, ALICE), with(Call::Generate, BOB)]
    );
}

/// `init` loads the default keyset at startup for a key source with an
/// identity of its own, so credentials that do not work fail there.
#[tokio::test]
async fn init_still_checks_a_key_source_with_its_own_identity_at_startup() {
    let source = Source::new();
    let cipher = StackCipher::builder()
        .kms(OwnIdentity(source.clone()))
        .init()
        .await
        .unwrap();
    assert_eq!(source.take(), vec![(Call::Load, None)]);
    let keyset = cipher.default_keyset();
    assert!(
        format!("{keyset:?}").contains("keyset_id: Some("),
        "the handle is on the keyset that init loaded"
    );
    let _: Ciphertext = keyset.encrypt(1i64).await.unwrap();
    assert_eq!(
        source.take(),
        vec![(Call::Generate, None)],
        "the default keyset was loaded at init, and is not loaded again"
    );

    let source = Source::new();
    source.refuse_loads(1);
    let refused = StackCipher::builder()
        .kms(OwnIdentity(source.clone()))
        .init()
        .await;
    assert!(refused.is_err_and(|error| is_refusal(&error, CREDENTIAL_REFUSED)));
    assert_eq!(source.take(), vec![(Call::Load, None)]);
}

// ---- a keyset that is not loaded yet ---------------------------------------
//
// Each test builds its calls through a keyset before anything has loaded
// it, awaits them, and compares the results with the same calls built
// after the load.

/// Every term derived through a keyset that is not loaded yet is the term
/// the loaded keyset derives. The first one awaited loads the keyset.
#[tokio::test]
async fn terms_built_before_the_load_are_the_terms_built_after_it() {
    use stack_encrypt::sem::{MatchTerms, OpeTerm, OreBlockTerm, OreTerm};

    let (shared, source) = unloaded().await;
    let early = shared.default_keyset();
    let field = || nonempty!("users").with("email");

    // Built before the load: none of these has a keyset to derive under.
    let equality = String::from("bob@example.com")
        .encrypt_into_with_context::<EqualityTerm, _>(&early, field());
    let refused = true.encrypt_into_with_context::<EqualityTerm, _>(&early, field());
    let matching =
        String::from("bob the builder").encrypt_into_with_context::<MatchTerms, _>(&early, field());
    let ore = 42u32.encrypt_into_with_context::<OreTerm<u32>, _>(&early, field());
    let ope = 42u32.encrypt_into_with_context::<OpeTerm<u32>, _>(&early, field());
    let block = 42u32.encrypt_into_with_context::<OreBlockTerm<u32>, _>(&early, field());
    assert_eq!(source.take(), vec![], "building makes no request");

    let equality = equality.with_credential(bob()).await.unwrap();
    assert_eq!(
        source.take(),
        vec![with(Call::Load, BOB)],
        "the first term awaited loads the keyset, and requests no data key"
    );
    assert!(
        matches!(refused.with_credential(alice()).await, Err(Error::Term(_))),
        "a value with no equality term is refused as it is on a loaded keyset"
    );
    // The keyset is loaded, so the rest make no request and need no
    // credential.
    let (matching, ore, ope, block) = (
        matching.with_credential(alice()).await.unwrap(),
        ore.with_credential(alice()).await.unwrap(),
        ope.with_credential(alice()).await.unwrap(),
        block.with_credential(alice()).await.unwrap(),
    );
    assert_eq!(source.take(), vec![], "the rest find it loaded");

    let late = shared.default_keyset();
    assert_eq!(
        equality,
        String::from("bob@example.com")
            .encrypt_into_with_context::<EqualityTerm, _>(&late, field())
            .with_credential(alice())
            .await
            .unwrap(),
        "the equality term built before the load"
    );
    assert_eq!(
        matching,
        String::from("bob the builder")
            .encrypt_into_with_context::<MatchTerms, _>(&late, field())
            .with_credential(alice())
            .await
            .unwrap(),
        "the match filter built before the load"
    );
    assert_eq!(
        ore,
        42u32
            .encrypt_into_with_context::<OreTerm<u32>, _>(&late, field())
            .with_credential(alice())
            .await
            .unwrap(),
        "the ORE term built before the load"
    );
    assert_eq!(
        ope,
        42u32
            .encrypt_into_with_context::<OpeTerm<u32>, _>(&late, field())
            .with_credential(alice())
            .await
            .unwrap(),
        "the OPE term built before the load"
    );
    let late_block = 42u32
        .encrypt_into_with_context::<OreBlockTerm<u32>, _>(&late, field())
        .with_credential(alice())
        .await
        .unwrap();
    assert!(
        block == late_block,
        "block ORE terms of one value under one keyset compare equal"
    );
    assert!(
        41u32
            .encrypt_into_with_context::<OreBlockTerm<u32>, _>(&late, field())
            .with_credential(alice())
            .await
            .unwrap()
            < block
    );
    assert_eq!(source.take(), vec![]);
}

/// A value sealed through a keyset that is not loaded yet carries the id
/// of the keyset the call loaded, and opens through it: scalars, trees and
/// target declarations.
#[tokio::test]
async fn values_sealed_before_the_load_open_after_it() {
    let (shared, source) = unloaded().await;
    let early = shared.default_keyset();
    let context = || AeadContext::from(nonempty!("users/email"));
    let email = String::from("bob@example.com");

    let scalar = early.encrypt(7i64);
    let tree = early.encrypt_tree(String::from("bob"), "users/name");
    let target = email
        .clone()
        .encrypt_into_with_context::<StackCipherText, _>(&early, context());
    assert_eq!(source.take(), vec![]);

    // One batch: one load, and one request for the three data keys.
    let ((scalar, tree), target): ((Ciphertext, StackCipherText), StackCipherText) = scalar
        .zip(tree)
        .zip(target)
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![with(Call::Load, BOB), with(Call::Generate, BOB)]
    );

    let default = early.keyset_id().with_credential(alice()).await.unwrap();
    let late = shared.default_keyset();
    let back: i64 = late.decrypt(scalar).with_credential(bob()).await.unwrap();
    assert_eq!(back, 7);
    let name: String = late
        .decrypt_tree(tree, "users/name")
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(name, "bob");
    let opening: Decryption<String, _> = target::open(target, context());
    let opened = late.run_decryption(opening).with_credential(bob()).await;
    assert_eq!(opened.unwrap(), email);
    assert_eq!(
        late.keyset_id().with_credential(alice()).await.unwrap(),
        default,
        "sealed under the default keyset"
    );
}

/// An opening built through a keyset that is not loaded yet is confined to
/// that keyset once it is loaded: a value from the default keyset opens,
/// and one from another keyset is refused before its key is retrieved.
#[tokio::test]
async fn an_opening_built_before_the_load_is_confined_to_the_default_keyset() {
    // Another process, over the same key source, seals the values.
    let source = Source::new();
    let writer = StackCipher::builder()
        .kms(source.clone())
        .init()
        .await
        .unwrap();
    let ours: Ciphertext = writer
        .default_keyset()
        .encrypt(7i64)
        .with_credential(alice())
        .await
        .unwrap();
    let tenant = writer.keyset(tenant_b());
    let foreign: Ciphertext = tenant.encrypt(8i64).with_credential(alice()).await.unwrap();
    let other = tenant.keyset_id().with_credential(alice()).await.unwrap();

    let reader = StackCipher::builder()
        .kms(source.clone())
        .init()
        .await
        .unwrap();
    let _ = source.take();
    let early = reader.default_keyset();
    let (opens, refused) = (early.decrypt::<i64>(ours), early.decrypt::<i64>(foreign));

    let refused = refused.with_credential(bob()).await;
    let default = early.keyset_id().with_credential(alice()).await.unwrap();
    assert!(
        matches!(
            refused,
            Err(Error::ForeignKeyset { expected, found }) if expected == default && found == other
        ),
        "{refused:?}"
    );
    assert_eq!(
        source.take(),
        vec![with(Call::Load, BOB)],
        "the keyset is loaded to compare, and the foreign key is not retrieved"
    );
    assert_eq!(opens.with_credential(bob()).await.unwrap(), 7);
    assert_eq!(source.take(), vec![with(Call::Retrieve, BOB)]);
}

/// Two calls built through two keysets that are not loaded yet, merged,
/// are refused when the merged call settles: the two keysets are compared
/// once both are loaded, before any data key is requested. A call merged
/// with one through the client is made under its own keyset.
#[tokio::test]
async fn calls_built_before_the_load_merge_by_the_keysets_they_load() {
    let (shared, source) = unloaded().await;
    let early = shared.default_keyset();
    let tenant = shared.keyset(tenant_b());

    let crossed: Result<(Ciphertext, Ciphertext), _> = early
        .encrypt(1i64)
        .zip(tenant.encrypt(2i64))
        .with_credential(bob())
        .await;
    assert_eq!(
        source.take(),
        vec![with(Call::Load, BOB), with(Call::Load, BOB)],
        "both keysets are loaded to compare, and no data key is requested"
    );
    let (default, other) = (
        early.keyset_id().with_credential(alice()).await.unwrap(),
        tenant.keyset_id().with_credential(alice()).await.unwrap(),
    );
    assert!(
        matches!(
            crossed,
            Err(Error::KeysetMismatch { left, right })
                if (left, right) == (default, other) || (left, right) == (other, default)
        ),
        "{crossed:?}"
    );

    let through_the_client = Pending::ready(&shared, Ok(3i64));
    let (_, three): (Ciphertext, i64) = early
        .encrypt(2i64)
        .zip(through_the_client)
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(three, 3);
    assert_eq!(source.take(), vec![with(Call::Generate, BOB)]);
}

/// The JSON index's selectors, read keys and documents built through a
/// keyset that is not loaded yet are those the loaded keyset builds.
#[tokio::test]
async fn json_terms_and_documents_built_before_the_load_match_those_built_after() {
    use stack_encrypt::json::JsonPath;
    use stack_encrypt::target::{json_document, json_terms, Borrowed, CallerContext};

    let (shared, source) = unloaded().await;
    let early = shared.default_keyset();
    let field = || nonempty!("users").with("profile");
    let context = || CallerContext::from(field());
    let options = JsonOptions::new();
    let path = JsonPath::parse("$.name").unwrap();
    let profile = json!({"name": "Bob", "age": 34});

    let selector = early.json_selector(&path, field());
    let key = early.json_subtree_key(&path, &options, field());
    let terms = early.run(
        json_terms::<_, Borrowed>(options.clone()),
        &profile,
        context(),
    );
    let document = early.run(
        json_document::<_, Borrowed>(options.clone()),
        &profile,
        context(),
    );
    assert_eq!(source.take(), vec![]);

    let selector = selector.with_credential(bob()).await.unwrap();
    assert_eq!(source.take(), vec![with(Call::Load, BOB)]);
    let (key, terms) = (
        key.with_credential(alice()).await.unwrap(),
        terms.with_credential(alice()).await.unwrap(),
    );
    assert_eq!(source.take(), vec![], "derived locally once loaded");
    let document: JsonDocument = document.with_credential(bob()).await.unwrap();
    assert_eq!(source.take(), vec![with(Call::Generate, BOB)]);

    let late = shared.default_keyset();
    assert_eq!(
        selector,
        late.json_selector(&path, field())
            .with_credential(alice())
            .await
            .unwrap(),
        "one selector for one path"
    );
    assert_eq!(
        key.tokens(),
        late.json_subtree_key(&path, &options, field())
            .with_credential(alice())
            .await
            .unwrap()
            .tokens()
    );
    let late_terms = late
        .run(
            json_terms::<_, Borrowed>(options.clone()),
            &profile,
            context(),
        )
        .with_credential(alice())
        .await
        .unwrap();
    assert_eq!(terms.len(), late_terms.len());
    assert_eq!(
        terms.selector(&path),
        late_terms.selector(&path),
        "the same node terms"
    );
    assert_eq!(terms.selector(&path), Some(selector));

    // The document sealed before the load opens, and it names the keyset.
    let opened =
        JsonPlaintext::decrypt_from_with_context(document, &shared, AeadContext::from(field()))
            .with_credential(bob())
            .await
            .unwrap();
    assert_eq!(opened.value(), &profile);
}

/// A keyset selected by name is loaded by the first call on it, with the
/// credential of that call, and then kept for every caller.
#[tokio::test]
async fn a_selected_keyset_is_loaded_by_its_first_call_and_kept_for_every_caller() {
    let (shared, source) = loaded().await;

    let keyset = shared.keyset(tenant_b());
    assert_eq!(source.take(), vec![], "selecting loads nothing");
    let stored: Ciphertext = keyset.encrypt(7i64).with_credential(bob()).await.unwrap();
    assert_eq!(
        source.take(),
        vec![with(Call::Load, BOB), with(Call::Generate, BOB)]
    );

    let same = shared.keyset(tenant_b());
    assert_eq!(
        same.keyset_id().with_credential(alice()).await.unwrap(),
        keyset.keyset_id().with_credential(alice()).await.unwrap()
    );
    let back: i64 = same.decrypt(stored).with_credential(alice()).await.unwrap();
    assert_eq!(back, 7);
    assert_eq!(
        source.take(),
        vec![with(Call::Retrieve, ALICE)],
        "the keyset is loaded once; each caller's key request is its own"
    );
}

// ---- two callers on one cipher ---------------------------------------------

/// One caller's work: store a value and read it back.
async fn store_and_read(
    cipher: &StackCipher<Source>,
    jwt: fn() -> SecretToken,
    value: &str,
) -> String {
    let keyset = cipher.default_keyset();
    let stored: Ciphertext = keyset
        .encrypt(value.to_string())
        .with_credential(jwt())
        .await
        .unwrap();
    tokio::task::yield_now().await;
    keyset.decrypt(stored).with_credential(jwt()).await.unwrap()
}

/// Two callers at once on one cipher. Each key request is made with the
/// credential of the caller whose work it is, and no request is made with
/// none.
#[tokio::test]
async fn two_callers_interleaved_on_one_cipher_each_send_their_own_credential() {
    let (shared, source) = loaded().await;

    let (a, b) = tokio::join!(
        store_and_read(&shared, alice, "alice's key"),
        store_and_read(&shared, bob, "bob's key"),
    );
    assert_eq!((a.as_str(), b.as_str()), ("alice's key", "bob's key"));

    // The order the two callers' requests interleave in is the runtime's.
    // What each caller sent is not.
    let sent = source.take();
    assert_eq!(sent.len(), 4, "{sent:?}");
    for credential in [ALICE, BOB] {
        let calls: Vec<Call> = sent
            .iter()
            .filter(|(_, sent_with)| sent_with.as_deref() == Some(credential))
            .map(|(call, _)| *call)
            .collect();
        assert_eq!(calls, [Call::Generate, Call::Retrieve], "{credential}");
    }
}

/// A value one caller stored is read by another with the reader's
/// credential: the credential is the caller's, not the value's.
#[tokio::test]
async fn a_value_is_read_with_the_readers_credential() {
    let (shared, source) = loaded().await;
    let keyset = shared.default_keyset();

    let stored: Ciphertext = keyset
        .encrypt_with_context(42i64, "users/age")
        .with_credential(alice())
        .await
        .unwrap();
    let age: i64 = keyset
        .decrypt_with_context(stored, "users/age")
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(age, 42);
    assert_eq!(
        source.take(),
        vec![with(Call::Generate, ALICE), with(Call::Retrieve, BOB)]
    );
}

// ---- every way to make a call ----------------------------------------------

#[tokio::test]
async fn trees_send_the_credential_through_a_keyset_and_through_the_client() {
    let (shared, source) = loaded().await;
    let keyset = shared.default_keyset();
    let seal = || {
        keyset
            .encrypt_tree(String::from("bob"), "users/name")
            .with_credential(bob())
    };

    let name: String = keyset
        .decrypt_tree(seal().await.unwrap(), "users/name")
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(name, "bob");

    // Through the client: leaves from any keyset.
    let name: String = shared
        .decrypt(seal().await.unwrap(), "users/name")
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(name, "bob");

    assert_eq!(
        source.take(),
        vec![
            with(Call::Generate, BOB),
            with(Call::Retrieve, BOB),
            with(Call::Generate, BOB),
            with(Call::Retrieve, BOB),
        ]
    );
}

#[tokio::test]
async fn target_declarations_send_the_credential() {
    let (shared, source) = loaded().await;
    let keyset = shared.default_keyset();
    let context = || AeadContext::from(nonempty!("users/email"));
    let email = String::from("bob@example.com");
    let seal = || {
        email
            .clone()
            .encrypt_into_with_context::<StackCipherText, _>(&keyset, context())
            .with_credential(bob())
    };

    let sealed: StackCipherText = seal().await.unwrap();
    let opening: Decryption<String, _> = target::open(sealed, context());
    let opened = keyset.run_decryption(opening).with_credential(bob()).await;
    assert_eq!(opened.unwrap(), email);

    // Through the client.
    let sealed: StackCipherText = seal().await.unwrap();
    let opening: Decryption<String, _> = target::open(sealed, context());
    let opened = shared.run_decryption(opening).with_credential(bob()).await;
    assert_eq!(opened.unwrap(), email);
    let sealed: StackCipherText = seal().await.unwrap();
    let opened = String::decrypt_from_with_context(sealed, &shared, context())
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(opened, email);

    assert_eq!(
        source.take(),
        vec![
            with(Call::Generate, BOB),
            with(Call::Retrieve, BOB),
            with(Call::Generate, BOB),
            with(Call::Retrieve, BOB),
            with(Call::Generate, BOB),
            with(Call::Retrieve, BOB),
        ]
    );
}

/// A record with one field, stored with its equality term.
#[derive(Zeroize)]
struct Account {
    email: String,
}

fn account() -> Account {
    Account {
        email: "bob@example.com".into(),
    }
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Account, scope = "accounts")]
struct EncryptedAccount {
    email: Encrypted<EqualityTerm>,
}

/// A record sends the credential its call ends with, loads the keyset of
/// the handle it is sealed through with it, and opens through the client
/// with it.
#[tokio::test]
async fn records_send_the_credential() {
    let (shared, source) = loaded().await;
    let keyset = shared.default_keyset();

    // The default keyset.
    let written: EncryptedAccount = account()
        .encrypt_into(&keyset)
        .with_credential(bob())
        .await
        .unwrap();
    let term = EncryptedAccount::EMAIL
        .eq("bob@example.com")
        .encrypt(&keyset)
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(written.email.terms, term);
    // The client names no keyset: the opening reads leaves from any keyset.
    let back = Account::decrypt_from(written, &shared)
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(back.email, "bob@example.com");
    assert_eq!(
        source.take(),
        vec![with(Call::Generate, BOB), with(Call::Retrieve, BOB)],
        "a query derives its term locally"
    );

    // A keyset selected by name is loaded with the credential.
    let tenant = shared.keyset(tenant_b());
    let written: EncryptedAccount = account()
        .encrypt_into(&tenant)
        .with_credential(bob())
        .await
        .unwrap();
    let back = Account::decrypt_from(written, &tenant)
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(back.email, "bob@example.com");
    assert_eq!(
        source.take(),
        vec![
            with(Call::Load, BOB),
            with(Call::Generate, BOB),
            with(Call::Retrieve, BOB),
        ]
    );
}

/// A query on a cipher that has loaded no keyset loads the keyset of the
/// handle it is encrypted through, to derive its term, with the credential
/// its call ends with.
#[tokio::test]
async fn a_query_loads_its_keyset_with_the_credential() {
    let (shared, source) = unloaded().await;

    let _ = EncryptedAccount::EMAIL
        .eq("bob@example.com")
        .encrypt(&shared.default_keyset())
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(source.take(), vec![with(Call::Load, BOB)]);
}

/// A customer whose profile is a JSON document, queried by its paths.
#[derive(Zeroize)]
struct Customer {
    profile: JsonPlaintext,
}

#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
#[allow(dead_code)] // only queried
struct EncryptedCustomer {
    #[stash(json(ordered = { "$.age": u32, "$.visits[*].at": u64, "$.visits[*].place": String }))]
    profile: JsonDocument,
}

/// A typed JSON query through a keyset that is not loaded yet derives its
/// operand when it is awaited, and loads the keyset with the credential
/// its call ends with. The operand is the one the same query derives once
/// the keyset is loaded, which needs no request.
#[tokio::test]
async fn a_typed_json_query_loads_its_keyset_with_the_credential() {
    // Two query types have no `==`, so those two are compared as the JSON
    // they send.
    macro_rules! derives_the_same_before_and_after_the_load {
        ($what:literal, $query:expr) => {{
            let (early, late) = derived_before_and_after_the_load!($what, $query);
            assert_eq!(early, late, $what);
        }};
        (as_json: $what:literal, $query:expr) => {{
            let (early, late) = derived_before_and_after_the_load!($what, $query);
            assert!(
                serde_json::to_value(&early).unwrap() == serde_json::to_value(&late).unwrap(),
                $what
            );
        }};
    }
    macro_rules! derived_before_and_after_the_load {
        ($what:literal, $query:expr) => {{
            let (shared, source) = unloaded().await;
            let keyset = shared.default_keyset();
            let early = $query
                .encrypt(&keyset)
                .with_credential(bob())
                .await
                .expect($what);
            assert_eq!(source.take(), vec![with(Call::Load, BOB)], $what);
            let late = $query
                .encrypt(&keyset)
                .with_credential(alice())
                .await
                .expect($what);
            assert_eq!(source.take(), vec![], $what);
            (early, late)
        }};
    }

    let profile = || EncryptedCustomer::PROFILE;
    derives_the_same_before_and_after_the_load!(
        "contains",
        profile().contains(json!({"name": "Ada"}))
    );
    derives_the_same_before_and_after_the_load!("an ordering", profile().at().age().gt(30));
    derives_the_same_before_and_after_the_load!("a selector", profile().at().age().selector());
    derives_the_same_before_and_after_the_load!("children", profile().children("$.visits"));
    derives_the_same_before_and_after_the_load!(
        as_json: "elements",
        profile()
            .elements()
            .visits()
            .place()
            .eq("home")
            .and()
            .at()
            .between(10, 20)
    );
    derives_the_same_before_and_after_the_load!(
        as_json: "a predicate",
        profile().predicate("$.age >= $min").var("min", 30)
    );
}

/// A path that names more than one node is refused by a query for one
/// node's children. Through a keyset that is not loaded yet, the refusal
/// is the call's error, and the call makes no key request but the load.
#[tokio::test]
async fn a_typed_json_query_refused_before_the_load_requests_no_key() {
    let (shared, source) = unloaded().await;
    let keyset = shared.default_keyset();

    let refused = EncryptedCustomer::PROFILE
        .children("$.visits[*]")
        .encrypt(&keyset)
        .with_credential(bob())
        .await;
    assert!(refused.is_err(), "a wildcard names many nodes");
    assert!(
        source.take().iter().all(|(call, _)| *call == Call::Load),
        "no data key is requested for a refused query"
    );
}

/// Each call through a keyset handle sends its own credential: the handle
/// holds none.
#[tokio::test]
async fn each_call_through_a_keyset_handle_sends_its_own_credential() {
    let (shared, source) = loaded().await;
    let keyset = shared.keyset(tenant_b());

    let written: EncryptedAccount = account()
        .encrypt_into(&keyset)
        .with_credential(bob())
        .await
        .unwrap();
    let back = Account::decrypt_from(written, &keyset)
        .with_credential(alice())
        .await
        .unwrap();
    assert_eq!(back.email, "bob@example.com");
    assert_eq!(
        source.take(),
        vec![
            with(Call::Load, BOB),
            with(Call::Generate, BOB),
            with(Call::Retrieve, ALICE),
        ]
    );
}

/// Records zipped into one call take one credential. So do an opening and
/// a query zipped together.
#[tokio::test]
async fn zipped_records_send_the_credential() {
    let (shared, source) = loaded().await;
    let keyset = shared.default_keyset();

    let (a, b): (EncryptedAccount, EncryptedAccount) = account()
        .encrypt_into(&keyset)
        .zip(account().encrypt_into(&keyset))
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(source.take(), vec![with(Call::Generate, BOB)]);

    let (a, term) = Account::decrypt_from(a, &shared)
        .zip(
            EncryptedAccount::EMAIL
                .eq("bob@example.com")
                .encrypt(&keyset),
        )
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(a.email, "bob@example.com");
    assert_eq!(b.email.terms, term);
    assert_eq!(source.take(), vec![with(Call::Retrieve, BOB)]);
}

/// A merged call is one call. It takes one credential, and makes one
/// request of each kind with it.
#[tokio::test]
async fn a_merged_call_makes_its_requests_with_one_credential() {
    let (shared, source) = loaded().await;
    let keyset = shared.default_keyset();

    let _: (Ciphertext, Ciphertext) = keyset
        .encrypt(1i64)
        .zip(keyset.encrypt(2i64))
        .with_credential(bob())
        .await
        .unwrap();
    let stored: Vec<Ciphertext> =
        Pending::all(&keyset, vec![keyset.encrypt(1i64), keyset.encrypt(2i64)])
            .with_credential(alice())
            .await
            .unwrap();
    let openings = stored.into_iter().map(|one| keyset.decrypt(one)).collect();
    let back: Vec<i64> = Pending::all(&keyset, openings)
        .map(|values| values.into_iter().map(|value: i64| value + 1).collect())
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(back, [2, 3]);

    assert_eq!(
        source.take(),
        vec![
            with(Call::Generate, BOB),
            with(Call::Generate, ALICE),
            with(Call::Retrieve, BOB),
        ]
    );
}

/// A JSON document names its keyset. One stored without a sealed root
/// opens from its entries, which takes the keyset's index key. A cipher
/// that has not loaded that keyset loads it when the document opens, in
/// the same await as the data key, and both requests carry the opening
/// caller's credential.
#[tokio::test]
async fn a_json_document_opens_and_loads_its_keyset_with_the_credential() {
    let (shared, source) = loaded().await;
    let open_root = JsonOptions {
        sealed_root: false,
        ..JsonOptions::new()
    };
    let profile = json!({"name": "Bob", "age": 34});

    let doc: JsonDocument = shared
        .keyset(tenant_b())
        .run(
            json_document::<_, Borrowed>(open_root),
            &profile,
            CallerContext::from(nonempty!("users/profile")),
        )
        .with_credential(alice())
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![with(Call::Load, ALICE), with(Call::Generate, ALICE)]
    );

    // Another process over the same ZeroKMS: its cipher has not loaded
    // the document's keyset.
    let elsewhere = StackCipher::builder()
        .kms(source.clone())
        .init()
        .await
        .unwrap();
    let _ = elsewhere
        .default_keyset()
        .keyset_id()
        .with_credential(bob())
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![with(Call::Load, BOB)],
        "init loads nothing; the reader then loads the default keyset"
    );

    let opened = JsonPlaintext::decrypt_from_with_context(
        doc,
        &elsewhere,
        AeadContext::from(nonempty!("users/profile")),
    )
    .with_credential(bob())
    .await
    .unwrap();
    assert_eq!(opened.value(), &profile);
    let mut sent = source.take();
    sent.sort_by_key(|(call, _)| *call as u8);
    assert_eq!(
        sent,
        vec![with(Call::Retrieve, BOB), with(Call::Load, BOB)],
        "the data key and the document's keyset, both as the reader"
    );
}

/// Audit metadata and the credential are both attached to the call, in
/// either order, and both arrive on the same key request: for a call on a
/// keyset, a record and a zipped call.
#[tokio::test]
async fn audit_metadata_and_the_credential_arrive_together() {
    let (shared, source) = loaded().await;
    let keyset = shared.default_keyset();
    let purpose = |why: &str| AuditMetadata::new().with("purpose", why);

    let stored: Ciphertext = keyset
        .encrypt(String::from("sk_live_1234"))
        .audit(purpose("store api key"))
        .with_credential(bob())
        .await
        .unwrap();
    let _: String = keyset
        .decrypt(stored)
        .with_credential(bob())
        .audit(purpose("list issues"))
        .await
        .unwrap();
    assert_eq!(
        source.take(),
        vec![with(Call::Generate, BOB), with(Call::Retrieve, BOB)]
    );
    assert_eq!(source.audited(), 2);

    let record = || account().encrypt_into::<EncryptedAccount, _>(&keyset);
    let _ = record()
        .audit(purpose("sign up"))
        .with_credential(bob())
        .await
        .unwrap();
    let _ = record()
        .with_credential(bob())
        .audit(purpose("sign up"))
        .await
        .unwrap();
    let zipped = || record().zip(record());
    let _ = zipped()
        .audit(purpose("import"))
        .with_credential(bob())
        .await
        .unwrap();
    let _ = zipped()
        .with_credential(bob())
        .audit(purpose("import"))
        .await
        .unwrap();
    assert_eq!(source.take(), vec![with(Call::Generate, BOB); 4]);
    assert_eq!(source.audited(), 6);
}
