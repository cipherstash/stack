//! Keysets: one client, many keysets. Selection, caching, and the
//! keyset-scoped versus client-scoped decrypt paths.

use stack_encrypt::DecryptFrom;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use stack_encrypt::registry::fake::{FakeKeysetRegistry, FakeProvider};
use stack_encrypt::registry::{
    Binding, BindingSupport, GeneratedDataKey, IndexKeyMaterial, IndexKeyProvider, KeyId,
    KeyIsolation, KeyProvider, KeyReconstruction, ProviderProtected, Resolved,
};
use stack_encrypt::target::EncryptInto;
use stack_encrypt::{
    nonempty, CipherText, Error, SealedValue, StackCipher, StackCipherBuilder, StackCipherText,
};
use stack_encrypt::{KeysetId, KeysetRef, KeysetRegistry};
use uuid::Uuid;

/// The fake registry, plus a count of keyset resolutions and a log of the
/// keyset each retrieve call was served by — the two facts the cache and the
/// grouped dispatch are about — and two knobs for the name-lookup races: a
/// name can be *refused*, and the next lookup of a name can be *held* until
/// released, so an answer can be in flight while a later lookup completes.
#[derive(Default)]
struct Observed {
    inner: FakeKeysetRegistry,
    loads: AtomicUsize,
    retrieve_keysets: Arc<Mutex<Vec<KeysetId>>>,
    refused: Mutex<HashMap<String, Refusal>>,
    /// The name whose *next* lookup waits for [`release`](Self::release).
    held: Mutex<Option<String>>,
    released: AtomicBool,
}

/// How a refused name's lookup fails.
///
/// The two are a different *kind* of outcome, not a different error: a
/// registry that knows there is no such keyset has **answered**
/// (`Ok(None)`), and the cache unbinds the name on the strength of it. One
/// that could not reach its backend has not answered at all (`Err`), and the
/// cache must be left exactly as it was.
#[derive(Clone, Copy)]
enum Refusal {
    Unknown,
    Unreachable,
}

/// The registry could not answer — as opposed to answering that there is no
/// such keyset.
#[derive(Debug, thiserror::Error)]
#[error("the keyset registry could not be reached")]
struct Unreachable;

impl Observed {
    fn loads(&self) -> usize {
        self.loads.load(Ordering::Relaxed)
    }

    fn retrieve_keysets(&self) -> Vec<KeysetId> {
        self.retrieve_keysets.lock().expect("lock").clone()
    }

    /// Every lookup of `name` from now on fails as `how` says.
    fn refuse(&self, name: &str, how: Refusal) {
        let _ = self
            .refused
            .lock()
            .expect("lock")
            .insert(name.to_owned(), how);
    }

    fn allow(&self, name: &str) {
        let _ = self.refused.lock().expect("lock").remove(name);
    }

    /// The next lookup of `name` decides its answer on arrival but does not
    /// return it until [`release`](Self::release).
    fn hold(&self, name: &str) {
        *self.held.lock().expect("lock") = Some(name.to_owned());
        self.released.store(false, Ordering::SeqCst);
    }

    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
    }
}

/// A [`FakeProvider`] that notes which keyset served each retrieve, so the
/// grouped dispatch is observable now that the keyset is the provider rather
/// than an argument beside it.
#[derive(Clone)]
struct ObservedProvider {
    inner: FakeProvider,
    id: KeysetId,
    log: Arc<Mutex<Vec<KeysetId>>>,
}

impl KeyProvider<32> for ObservedProvider {
    type Error = <FakeProvider as KeyProvider<32>>::Error;

    const RECONSTRUCTION: KeyReconstruction = <FakeProvider as KeyProvider<32>>::RECONSTRUCTION;
    const ISOLATION: KeyIsolation = <FakeProvider as KeyProvider<32>>::ISOLATION;
    const BINDING: BindingSupport = <FakeProvider as KeyProvider<32>>::BINDING;

    async fn generate_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> Result<Vec<GeneratedDataKey<32>>, Self::Error> {
        self.inner.generate_keys(bindings).await
    }

    async fn retrieve_keys(
        &self,
        keys: &[(KeyId, Binding<'_>)],
    ) -> Result<Vec<ProviderProtected<[u8; 32]>>, Self::Error> {
        self.log.lock().expect("lock").push(self.id);
        self.inner.retrieve_keys(keys).await
    }
}

impl IndexKeyProvider<32> for ObservedProvider {
    type Error = <FakeProvider as IndexKeyProvider<32>>::Error;

    async fn load_index_key(&self) -> Result<IndexKeyMaterial<32>, Self::Error> {
        self.inner.load_index_key().await
    }
}

impl KeysetRegistry for Observed {
    type Provider = ObservedProvider;
    type Error = Unreachable;

    async fn resolve(
        &self,
        keyset: &KeysetRef,
    ) -> Result<Option<Resolved<Self::Provider>>, Self::Error> {
        self.loads.fetch_add(1, Ordering::Relaxed);
        let asked = keyset.name().map(str::to_owned);

        // The answer is decided when the lookup arrives, as the backend
        // would decide it; holding only delays its return.
        let refusal = asked
            .as_deref()
            .and_then(|name| self.refused.lock().expect("lock").get(name).copied());
        let held = {
            let mut held = self.held.lock().expect("lock");
            if held.as_deref() == asked.as_deref() && asked.is_some() {
                *held = None;
                true
            } else {
                false
            }
        };
        if held {
            while !self.released.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        }

        match refusal {
            Some(Refusal::Unknown) => return Ok(None),
            Some(Refusal::Unreachable) => return Err(Unreachable),
            None => {}
        }

        let Some(resolved) = self
            .inner
            .resolve(keyset)
            .await
            .expect("the fake registry does not fail")
        else {
            return Ok(None);
        };

        Ok(Some(Resolved {
            id: resolved.id,
            name: resolved.name,
            provider: ObservedProvider {
                inner: resolved.provider,
                id: resolved.id,
                log: Arc::clone(&self.retrieve_keysets),
            },
        }))
    }
}

async fn cipher() -> StackCipher<Observed> {
    StackCipherBuilder::new()
        .registry(Observed::default())
        .init()
        .await
        .expect("build cipher")
}

// =============================================================================
// Selection and caching
// =============================================================================

#[tokio::test]
async fn init_loads_the_default_keyset_once() {
    let cipher = cipher().await;
    assert_eq!(
        cipher.registry().loads(),
        1,
        "the default keyset loads at init"
    );

    let (expected, _) = FakeKeysetRegistry::new().default_keyset();
    assert_eq!(
        cipher.default_keyset().keyset_id(),
        expected,
        "init resolves the source's own default keyset"
    );
    assert_eq!(
        cipher.default_keyset().keyset_name(),
        None,
        "the client's default is resolved by naming nothing, so it has no name"
    );
    assert_eq!(cipher.registry().loads(), 1, "default_keyset() never loads");
}

/// The default is the client's, and stays the client's. A ZeroKMS
/// administrator sets it; selecting other keysets — however many, however
/// recently — never moves it.
#[tokio::test]
async fn selecting_a_keyset_never_moves_the_default() {
    let cipher = cipher().await;
    let default = cipher.default_keyset().keyset_id();

    let customers = cipher.keyset("customers").await.expect("select");
    assert_ne!(customers.keyset_id(), default, "a distinct keyset");
    assert_eq!(
        cipher.default_keyset().keyset_id(),
        default,
        "the default is unchanged by a selection"
    );

    let _ = cipher.keyset("acme").await.expect("select another");
    assert_eq!(
        cipher.default_keyset().keyset_id(),
        default,
        "and by any number of them"
    );
    assert_eq!(
        cipher.default_keyset().keyset_name(),
        None,
        "the client's default is never a name the caller chose"
    );
}

#[tokio::test]
async fn a_keyset_loads_on_first_selection_and_is_cached_after() {
    let cipher = cipher().await;
    let first = cipher.keyset("acme").await.expect("select");
    assert_eq!(cipher.registry().loads(), 2, "first selection loads");
    assert_eq!(
        first.keyset_name(),
        Some("acme"),
        "a keyset selected by name reports the name it was selected by"
    );

    let again = cipher.keyset("acme").await.expect("select again");
    let by_id = cipher
        .keyset(first.keyset_id())
        .await
        .expect("select by id");
    assert_eq!(cipher.registry().loads(), 2, "later selections are lookups");
    assert_eq!(
        again.keyset_id(),
        first.keyset_id(),
        "the second selection by name is the same keyset"
    );
    assert_eq!(
        by_id.keyset_id(),
        first.keyset_id(),
        "and so is the selection by the id it resolved to"
    );
    assert_eq!(
        by_id.keyset_name(),
        Some("acme"),
        "the cached state keeps the name"
    );
}

#[tokio::test]
async fn a_keyset_selected_by_id_is_not_known_by_name() {
    let cipher = cipher().await;
    let by_id = cipher.keyset(Uuid::from_u128(42)).await.expect("select");
    assert_eq!(
        by_id.keyset_name(),
        None,
        "a selection by id knows no name to report"
    );
    assert_eq!(
        cipher.registry().loads(),
        2,
        "default + the selected keyset"
    );
}

#[tokio::test]
async fn an_evicted_keyset_reloads_on_its_next_selection() {
    let cipher = StackCipherBuilder::new()
        .registry(Observed::default())
        .keyset_cache_size(NonZeroUsize::new(1).expect("non-zero"))
        .init()
        .await
        .expect("build cipher");

    let a = cipher.keyset(Uuid::from_u128(101)).await.expect("a");
    let _b = cipher.keyset(Uuid::from_u128(102)).await.expect("b");
    assert_eq!(cipher.registry().loads(), 3, "default + a + b");

    // `a` was evicted by `b`; selecting it again is a load. The handle taken
    // earlier is unaffected: it holds its own state.
    let a_again = cipher.keyset(Uuid::from_u128(101)).await.expect("a again");
    assert_eq!(
        cipher.registry().loads(),
        4,
        "an evicted keyset is loaded again on its next selection"
    );
    assert_eq!(
        a_again.keyset_id(),
        a.keyset_id(),
        "the reload is the same keyset"
    );

    // The default never evicts, however small the cache.
    let _ = cipher.default_keyset();
    let _ = cipher
        .keyset(cipher.default_keyset().keyset_id())
        .await
        .expect("default by id");
    assert_eq!(
        cipher.registry().loads(),
        4,
        "the default never evicts, however small the cache"
    );
}

/// A name is a lookup, not an identity: past the window, selecting a keyset
/// by name asks ZeroKMS again, while selecting by id never does.
#[tokio::test]
async fn a_name_selection_is_re_resolved_after_its_window() {
    let cipher = StackCipherBuilder::new()
        .registry(Observed::default())
        .keyset_name_ttl(Duration::ZERO)
        .init()
        .await
        .expect("build cipher");
    assert_eq!(
        cipher.registry().loads(),
        1,
        "init loads the default keyset"
    );

    let acme = cipher.keyset("acme").await.expect("acme");
    let _ = cipher.keyset("acme").await.expect("acme again");
    assert_eq!(
        cipher.registry().loads(),
        3,
        "every selection by name asks again"
    );

    let _ = cipher.keyset(acme.keyset_id()).await.expect("acme by id");
    let _ = cipher
        .keyset(acme.keyset_id())
        .await
        .expect("acme by id again");
    assert_eq!(
        cipher.registry().loads(),
        3,
        "an id is identity and is never re-asked"
    );

    let _ = cipher.keyset("primary").await.expect("primary");
    assert_eq!(cipher.registry().loads(), 4, "another name, another ask");
    let _ = cipher
        .keyset(cipher.default_keyset().keyset_id())
        .await
        .expect("default by id");
    assert_eq!(
        cipher.registry().loads(),
        4,
        "the client's default is seeded by id, and an id is never re-asked"
    );
}

/// ZeroKMS's own answer that no keyset has a name reaches the caller as it
/// is, and a request that got no answer as a request failure. Neither
/// touches what is cached by id: the name was answered, not the keyset. A
/// zero window, so every selection by name asks ZeroKMS and can be refused.
#[tokio::test]
async fn a_refused_name_is_zerokms_answer_and_leaves_the_keyset_cached_by_id() {
    let cipher = StackCipherBuilder::new()
        .registry(Observed::default())
        .keyset_name_ttl(Duration::ZERO)
        .init()
        .await
        .expect("build cipher");
    let acme = cipher.keyset("acme").await.expect("acme");
    assert_eq!(cipher.registry().loads(), 2, "init and acme");

    cipher.registry().refuse("acme", Refusal::Unknown);
    let error = cipher.keyset("acme").await.expect_err("refused");
    assert!(
        matches!(error, Error::UnknownKeyset { .. }),
        "the registry's own denial reaches the caller as UnknownKeyset, got {error:?}"
    );
    let by_id = cipher.keyset(acme.keyset_id()).await.expect("acme by id");
    assert_eq!(
        cipher.registry().loads(),
        3,
        "the keyset is still cached by id: only the name was answered"
    );
    assert_eq!(by_id.keyset_id(), acme.keyset_id());

    cipher.registry().refuse("acme", Refusal::Unreachable);
    let error = cipher.keyset("acme").await.expect_err("failed");
    assert!(
        matches!(error, Error::Registry(_)),
        "a lookup that got no answer surfaces as a registry failure, got {error:?}"
    );

    cipher.registry().allow("acme");
    let again = cipher.keyset("acme").await.expect("acme once more");
    assert_eq!(
        again.keyset_id(),
        acme.keyset_id(),
        "the fake resolves a name deterministically"
    );
}

/// The race the negative answer exists for, end to end: a lookup for `acme`
/// is in flight when ZeroKMS tells a later lookup that no keyset has the
/// name. The earlier answer still reaches its own caller, but it binds
/// nothing — a selection after it asks ZeroKMS, instead of being routed to
/// the keyset the name no longer means for a whole window.
#[tokio::test]
async fn an_answer_in_flight_does_not_rebind_a_name_zerokms_has_since_refused() {
    let cipher = cipher().await;
    cipher.registry().hold("acme");
    let earlier = cipher.keyset("acme");
    let meanwhile = async {
        cipher.registry().refuse("acme", Refusal::Unknown);
        let refused = cipher.keyset("acme").await;
        cipher.registry().release();
        refused
    };
    // `join!` polls in order: the earlier lookup takes its ticket and parks
    // on the hold, the later one is refused, and the release lets the
    // earlier answer land last.
    let (earlier, refused) = tokio::join!(earlier, meanwhile);
    let earlier = earlier.expect("the earlier lookup's own answer stands for its caller");
    assert!(
        matches!(refused, Err(Error::UnknownKeyset { .. })),
        "the later lookup was refused, got {refused:?}"
    );
    assert_eq!(
        cipher.registry().loads(),
        3,
        "init, the held lookup, the refused one"
    );

    cipher.registry().allow("acme");
    let later = cipher.keyset("acme").await.expect("acme afterwards");
    assert_eq!(
        cipher.registry().loads(),
        4,
        "the earlier answer bound nothing: a selection by the name asks ZeroKMS"
    );
    assert_eq!(
        later.keyset_id(),
        earlier.keyset_id(),
        "the fake resolves a name deterministically; what differs is that it was asked"
    );
}

/// The mirror of the race above: the later lookup gets no answer at all.
/// That says nothing about the name, so the earlier answer binds it as
/// usual and the next selection is served from the binding. This is the
/// line between ZeroKMS's own not-found and a request that failed to reach
/// it — only the former is an answer.
#[tokio::test]
async fn a_lookup_that_got_no_answer_forgets_nothing() {
    let cipher = cipher().await;
    cipher.registry().hold("acme");
    let earlier = cipher.keyset("acme");
    let meanwhile = async {
        cipher.registry().refuse("acme", Refusal::Unreachable);
        let failed = cipher.keyset("acme").await;
        cipher.registry().release();
        failed
    };
    let (earlier, failed) = tokio::join!(earlier, meanwhile);
    let earlier = earlier.expect("the earlier lookup's answer stands");
    assert!(
        matches!(failed, Err(Error::Registry(_))),
        "the later lookup got no answer, got {failed:?}"
    );
    assert_eq!(
        cipher.registry().loads(),
        3,
        "init, the held lookup, the failed one"
    );

    cipher.registry().allow("acme");
    let later = cipher.keyset("acme").await.expect("acme afterwards");
    assert_eq!(
        cipher.registry().loads(),
        3,
        "a failure to get an answer forgot nothing: the earlier answer bound the name and serves"
    );
    assert_eq!(later.keyset_id(), earlier.keyset_id());
}

#[tokio::test]
async fn keysets_derive_distinct_index_keys() {
    let cipher = cipher().await;
    let a = cipher.keyset(Uuid::from_u128(101)).await.expect("a");
    let b = cipher.keyset(Uuid::from_u128(102)).await.expect("b");

    let term_a = a
        .equality_term(7u32, nonempty!("users/age"))
        .await
        .expect("term");
    let term_b = b
        .equality_term(7u32, nonempty!("users/age"))
        .await
        .expect("term");
    let term_a_again = a
        .equality_term(7u32, nonempty!("users/age"))
        .await
        .expect("term");

    assert_ne!(term_a, term_b, "different keysets, different index keys");
    assert_eq!(
        term_a, term_a_again,
        "the same keyset derives the same term"
    );
}

// =============================================================================
// The leaf carries its keyset
// =============================================================================

fn leaf_of(tree: StackCipherText) -> SealedValue {
    match tree {
        CipherText::Single(leaf) => leaf,
        _ => panic!("a scalar seals to a single leaf"),
    }
}

#[tokio::test]
async fn a_sealed_leaf_names_the_keyset_it_was_sealed_under() {
    let cipher = cipher().await;
    let tenant = cipher.keyset("acme").await.expect("select");

    let sealed = tenant
        .encrypt("hello".to_string(), "greeting")
        .await
        .expect("seal");
    assert_eq!(
        leaf_of(sealed).keyset_id(),
        tenant.keyset_id(),
        "a leaf carries the keyset it was sealed under"
    );

    let sealed = cipher
        .default_keyset()
        .encrypt("hello".to_string(), "greeting")
        .await
        .expect("seal");
    assert_eq!(
        leaf_of(sealed).keyset_id(),
        cipher.default_keyset().keyset_id(),
        "and so does one sealed through the default keyset"
    );
}

// =============================================================================
// Decrypting: the client opens any keyset, a keyset handle only its own
// =============================================================================

#[tokio::test]
async fn the_client_opens_a_leaf_from_any_keyset() {
    let cipher = cipher().await;
    let tenant = cipher.keyset("acme").await.expect("select");
    let sealed = tenant
        .encrypt("hello".to_string(), "greeting")
        .await
        .expect("seal");

    let opened: String = cipher.decrypt(sealed, "greeting").await.expect("open");
    assert_eq!(opened, "hello", "the client opens another keyset's leaf");
    assert_eq!(
        cipher.registry().retrieve_keysets(),
        vec![tenant.keyset_id()],
        "the retrieve names the leaf's keyset, not the default"
    );
}

#[tokio::test]
async fn a_keyset_handle_opens_its_own_leaves() {
    let cipher = cipher().await;
    let tenant = cipher.keyset("acme").await.expect("select");
    let sealed = tenant
        .encrypt("hello".to_string(), "greeting")
        .await
        .expect("seal");

    let opened: String = tenant.decrypt(sealed, "greeting").await.expect("open");
    assert_eq!(opened, "hello", "a keyset handle opens its own leaf");
}

#[tokio::test]
async fn a_keyset_handle_refuses_another_keysets_leaf_before_any_retrieve() {
    let cipher = cipher().await;
    let acme = cipher.keyset("acme").await.expect("acme");
    let globex = cipher.keyset("globex").await.expect("globex");
    let sealed = acme
        .encrypt("hello".to_string(), "greeting")
        .await
        .expect("seal");

    let result: Result<String, _> = globex.decrypt(sealed, "greeting").await;
    assert!(
        matches!(
            result,
            Err(Error::ForeignKeyset { expected, found })
                if expected == globex.keyset_id() && found == acme.keyset_id()
        ),
        "{result:?}"
    );
    assert!(
        cipher.registry().retrieve_keysets().is_empty(),
        "refused before any key was retrieved"
    );
}

#[tokio::test]
async fn the_target_path_through_a_keyset_handle_is_constrained_too() {
    let cipher = cipher().await;
    let acme = cipher.keyset("acme").await.expect("acme");
    let globex = cipher.keyset("globex").await.expect("globex");
    // A ciphertext tree is not `Clone`; seal three, one per path.
    let seal = || async {
        let sealed: StackCipherText = 34u32
            .encrypt_into_with_context(&acme, nonempty!("users/age"))
            .await
            .expect("seal");
        sealed
    };

    let opened: u32 = seal()
        .await
        .decrypt_into(&acme, nonempty!("users/age"))
        .await
        .expect("own keyset opens");
    assert_eq!(opened, 34, "the sealing keyset opens its own leaf");

    let opened: u32 = seal()
        .await
        .decrypt_into(&cipher, nonempty!("users/age"))
        .await
        .expect("the client opens");
    assert_eq!(opened, 34, "and so does the client it belongs to");

    let result: Result<u32, _> = seal()
        .await
        .decrypt_into(&globex, nonempty!("users/age"))
        .await;
    assert!(
        matches!(result, Err(Error::ForeignKeyset { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn a_mixed_keyset_column_opens_through_the_client_in_one_call_per_keyset() {
    let cipher = cipher().await;
    let acme = cipher.keyset("acme").await.expect("acme");
    let globex = cipher.keyset("globex").await.expect("globex");

    // A column whose rows belong to two tenants, interleaved.
    let mut column: Vec<StackCipherText> = Vec::new();
    for (i, tenant) in [(1u32, &acme), (2, &globex), (3, &acme)] {
        let sealed: StackCipherText = i
            .encrypt_into_with_context(tenant, nonempty!("users/age"))
            .await
            .expect("seal");
        column.push(sealed);
    }

    let opened: Vec<u32> = column
        .decrypt_into(&cipher, nonempty!("users/age"))
        .await
        .expect("open");
    assert_eq!(
        opened,
        vec![1, 2, 3],
        "a two-tenant column opens in row order"
    );
    assert_eq!(
        cipher.registry().retrieve_keysets(),
        vec![acme.keyset_id(), globex.keyset_id()],
        "one retrieve per keyset, first seen first"
    );
}

#[tokio::test]
async fn a_mixed_keyset_column_does_not_open_through_a_keyset_handle() {
    let cipher = cipher().await;
    let acme = cipher.keyset("acme").await.expect("acme");
    let globex = cipher.keyset("globex").await.expect("globex");
    let mut column: Vec<StackCipherText> = Vec::new();
    for tenant in [&acme, &globex] {
        let sealed: StackCipherText = 1u32
            .encrypt_into_with_context(tenant, nonempty!("users/age"))
            .await
            .expect("seal");
        column.push(sealed);
    }

    let result: Result<Vec<u32>, _> = column.decrypt_into(&acme, nonempty!("users/age")).await;
    assert!(
        matches!(result, Err(Error::ForeignKeyset { .. })),
        "{result:?}"
    );
    assert!(
        cipher.registry().retrieve_keysets().is_empty(),
        "refused before any key was retrieved"
    );
}

/// Both cipher handles carry key material: `StackCipher` its keyset cache
/// and, through the registry, the client key; `KeysetCipher` the keyset's
/// index-key PRF. Their `Debug` shows the keyset's *identity* — which every
/// sealed leaf carries in the clear already, and which ZeroKMS logs — and
/// nothing else. Pinned, because a `Debug` that grew a field is the kind of
/// change that looks harmless in review and puts a key in a log line.
#[tokio::test]
async fn the_cipher_handles_print_their_keyset_and_no_key_material() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let default_id = keyset.keyset_id().to_string();

    for (what, printed) in [
        ("StackCipher", format!("{cipher:?}")),
        ("KeysetCipher", format!("{keyset:?}")),
    ] {
        assert!(
            printed.starts_with(what),
            "{what} must name itself: {printed}"
        );
        assert!(
            printed.contains(&default_id),
            "{what} must name the keyset it is bound to: {printed}"
        );
        assert!(
            printed.contains(".."),
            "{what} must stay non-exhaustive, so a new field is opt-in: {printed}"
        );
        // The registry appears as a *type name*, never a value — a value
        // would drag the client key and the access token into the output.
        assert!(
            printed.contains("Observed"),
            "{what} must name the registry type: {printed}"
        );
        for secret in ["Protected", "Prf", "index_key", "prf"] {
            assert!(
                !printed.contains(secret),
                "{what} printed {secret:?}: {printed}"
            );
        }
    }
}
