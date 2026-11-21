//! Keysets: one client, many keysets. Selection, caching, and the
//! keyset-scoped versus client-scoped decrypt paths.

use std::borrow::Cow;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use stack_encrypt::{
    nonempty, CipherText, DecryptFrom, EncryptInto, Error, SealedValue, StackCipher,
    StackCipherText,
};
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource, GenerateKeyPayload, IdentifiedBy,
    IndexKey, IndexKeySource, LoadKeysetError, RetrieveKeyPayload, UnverifiedContext,
};
use uuid::Uuid;
use zerokms_protocol::{ViturRequestError, ViturRequestErrorKind};

/// The fake, plus a count of keyset loads and a log of the keyset each
/// retrieve call named — the two facts the cache and the grouped dispatch
/// are about — and two knobs for the name-lookup races: a name can be
/// *refused* (ZeroKMS answers the lookup with an error) and the next lookup
/// of a name can be *held* until released, so an answer can be in flight
/// while a later lookup completes.
#[derive(Default)]
struct Observed {
    inner: FakeDataKeySource,
    loads: AtomicUsize,
    retrieve_keysets: Mutex<Vec<Option<Uuid>>>,
    refused: Mutex<HashMap<String, Refusal>>,
    /// The name whose *next* lookup waits for [`release`](Self::release).
    held: Mutex<Option<String>>,
    released: AtomicBool,
    /// Names that were given to another keyset: a lookup of the key is
    /// answered with the keyset of the value.
    renamed: Mutex<HashMap<String, String>>,
}

/// How a refused name's lookup fails: with ZeroKMS's own answer that no
/// keyset has the name, or with no answer at all.
#[derive(Clone, Copy)]
enum Refusal {
    Unknown,
    Unreachable,
}

impl Observed {
    fn loads(&self) -> usize {
        self.loads.load(Ordering::Relaxed)
    }

    fn retrieve_keysets(&self) -> Vec<Option<Uuid>> {
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

    /// From now on `name` means the keyset that `other` names, as when a
    /// keyset is renamed in ZeroKMS and another takes its old name.
    fn rename(&self, name: &str, other: &str) {
        let _ = self
            .renamed
            .lock()
            .expect("lock")
            .insert(name.to_owned(), other.to_owned());
    }
}

impl DataKeySource for Observed {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
        self.inner
            .generate_keys(payloads, keyset_id, unverified_context)
            .await
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_kms::Error> {
        self.retrieve_keysets.lock().expect("lock").push(keyset_id);
        self.inner
            .retrieve_keys(payloads, keyset_id, unverified_context)
            .await
    }
}

impl IndexKeySource for Observed {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
        self.loads.fetch_add(1, Ordering::Relaxed);
        let asked = match &keyset_id {
            Some(IdentifiedBy::Name(name)) => Some(name.to_string()),
            Some(IdentifiedBy::Uuid(_)) | None => None,
        };
        // The answer is decided when the lookup arrives, as ZeroKMS would
        // decide it; holding only delays its return.
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
            Some(how) => {
                let (kind, message) = match how {
                    Refusal::Unknown => {
                        (ViturRequestErrorKind::NotFound, "no keyset has this name")
                    }
                    Refusal::Unreachable => (ViturRequestErrorKind::SendRequest, "no answer"),
                };
                Err(stack_kms::Error::from(LoadKeysetError::from(
                    ViturRequestError::new(kind, message, std::io::Error::other(message)),
                )))
            }
            None => {
                let renamed = asked
                    .as_deref()
                    .and_then(|name| self.renamed.lock().expect("lock").get(name).cloned());
                let keyset_id = match renamed {
                    Some(other) => Some(name(&other)),
                    None => keyset_id,
                };
                self.inner.load_index_key(keyset_id).await
            }
        }
    }
}

fn name(name: &str) -> IdentifiedBy {
    IdentifiedBy::Name(name.to_string().into())
}

/// Select a keyset and load it now, as the first call on its handle does.
/// A test that counts loads, or reads what a load answered, starts here.
async fn load<K>(
    cipher: &StackCipher<K>,
    keyset: impl Into<IdentifiedBy>,
) -> Result<stack_encrypt::KeysetCipher<'_, K>, Error>
where
    K: stack_kms::DataKeySource + stack_kms::IndexKeySource + Sync,
{
    let keyset = cipher.keyset(keyset);
    keyset.keyset_id().await?;
    Ok(keyset)
}

async fn cipher() -> StackCipher<Observed> {
    StackCipher::builder()
        .kms(Observed::default())
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
    assert_eq!(cipher.kms().loads(), 1, "the default keyset loads at init");

    let expected = FakeDataKeySource::new()
        .load_index_key(None)
        .await
        .expect("resolve")
        .0;
    assert_eq!(
        cipher.default_keyset().keyset_id().await.unwrap(),
        expected,
        "init resolves the source's own default keyset"
    );
    assert_eq!(
        cipher.default_keyset().keyset_name().await.unwrap(),
        None,
        "the client's default is resolved by naming nothing, so it has no name"
    );
    assert_eq!(cipher.kms().loads(), 1, "default_keyset() never loads");
}

/// The default is the client's, and stays the client's. A ZeroKMS
/// administrator sets it; selecting other keysets — however many, however
/// recently — never moves it.
#[tokio::test]
async fn selecting_a_keyset_never_moves_the_default() {
    let cipher = cipher().await;
    let default = cipher.default_keyset().keyset_id().await.unwrap();

    let customers = load(&cipher, name("customers")).await.expect("select");
    assert_ne!(
        customers.keyset_id().await.unwrap(),
        default,
        "a distinct keyset"
    );
    assert_eq!(
        cipher.default_keyset().keyset_id().await.unwrap(),
        default,
        "the default is unchanged by a selection"
    );

    let _ = load(&cipher, name("acme")).await.expect("select another");
    assert_eq!(
        cipher.default_keyset().keyset_id().await.unwrap(),
        default,
        "and by any number of them"
    );
    assert_eq!(
        cipher.default_keyset().keyset_name().await.unwrap(),
        None,
        "the client's default is never a name the caller chose"
    );
}

#[tokio::test]
async fn a_keyset_loads_on_first_selection_and_is_cached_after() {
    let cipher = cipher().await;
    let first = load(&cipher, name("acme")).await.expect("select");
    assert_eq!(cipher.kms().loads(), 2, "first selection loads");
    assert_eq!(
        first.keyset_name().await.unwrap().as_deref(),
        Some("acme"),
        "a keyset selected by name reports the name it was selected by"
    );

    let again = load(&cipher, name("acme")).await.expect("select again");
    let by_id = load(&cipher, first.keyset_id().await.unwrap())
        .await
        .expect("select by id");
    assert_eq!(cipher.kms().loads(), 2, "later selections are lookups");
    assert_eq!(
        again.keyset_id().await.unwrap(),
        first.keyset_id().await.unwrap(),
        "the second selection by name is the same keyset"
    );
    assert_eq!(
        by_id.keyset_id().await.unwrap(),
        first.keyset_id().await.unwrap(),
        "and so is the selection by the id it resolved to"
    );
    assert_eq!(
        by_id.keyset_name().await.unwrap().as_deref(),
        Some("acme"),
        "the cached state keeps the name"
    );
}

#[tokio::test]
async fn a_keyset_selected_by_id_is_not_known_by_name() {
    let cipher = cipher().await;
    let by_id = load(&cipher, Uuid::from_u128(42)).await.expect("select");
    assert_eq!(
        by_id.keyset_name().await.unwrap(),
        None,
        "a selection by id knows no name to report"
    );
    assert_eq!(cipher.kms().loads(), 2, "default + the selected keyset");
}

#[tokio::test]
async fn an_evicted_keyset_reloads_on_its_next_selection() {
    let cipher = StackCipher::builder()
        .kms(Observed::default())
        .keyset_cache_size(NonZeroUsize::new(1).expect("non-zero"))
        .init()
        .await
        .expect("build cipher");

    let a = load(&cipher, Uuid::from_u128(1)).await.expect("a");
    let _b = load(&cipher, Uuid::from_u128(2)).await.expect("b");
    assert_eq!(cipher.kms().loads(), 3, "default + a + b");

    // `a` was evicted by `b`; selecting it again is a load. The handle taken
    // earlier is unaffected: it holds its own state.
    let a_again = load(&cipher, Uuid::from_u128(1)).await.expect("a again");
    assert_eq!(
        cipher.kms().loads(),
        4,
        "an evicted keyset is loaded again on its next selection"
    );
    assert_eq!(
        a_again.keyset_id().await.unwrap(),
        a.keyset_id().await.unwrap(),
        "the reload is the same keyset"
    );

    // The default never evicts, however small the cache.
    let _ = cipher.default_keyset();
    let _ = load(&cipher, cipher.default_keyset().keyset_id().await.unwrap())
        .await
        .expect("default by id");
    assert_eq!(
        cipher.kms().loads(),
        4,
        "the default never evicts, however small the cache"
    );
}

/// A name is a lookup, not an identity: past the window, selecting a keyset
/// by name asks ZeroKMS again, while selecting by id never does.
#[tokio::test]
async fn a_name_selection_is_re_resolved_after_its_window() {
    let cipher = StackCipher::builder()
        .kms(Observed::default())
        .keyset_name_ttl(Duration::ZERO)
        .init()
        .await
        .expect("build cipher");
    assert_eq!(cipher.kms().loads(), 1, "init loads the default keyset");

    let acme = load(&cipher, name("acme")).await.expect("acme");
    let _ = load(&cipher, name("acme")).await.expect("acme again");
    assert_eq!(
        cipher.kms().loads(),
        3,
        "every selection by name asks again"
    );

    let _ = load(&cipher, acme.keyset_id().await.unwrap())
        .await
        .expect("acme by id");
    let _ = load(&cipher, acme.keyset_id().await.unwrap())
        .await
        .expect("acme by id again");
    assert_eq!(
        cipher.kms().loads(),
        3,
        "an id is identity and is never re-asked"
    );

    let _ = load(&cipher, name("primary")).await.expect("primary");
    assert_eq!(cipher.kms().loads(), 4, "another name, another ask");
    let _ = load(&cipher, cipher.default_keyset().keyset_id().await.unwrap())
        .await
        .expect("default by id");
    assert_eq!(
        cipher.kms().loads(),
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
    let cipher = StackCipher::builder()
        .kms(Observed::default())
        .keyset_name_ttl(Duration::ZERO)
        .init()
        .await
        .expect("build cipher");
    let acme = load(&cipher, name("acme")).await.expect("acme");
    assert_eq!(cipher.kms().loads(), 2, "init and acme");

    cipher.kms().refuse("acme", Refusal::Unknown);
    let error = load(&cipher, name("acme")).await.expect_err("refused");
    assert!(
        matches!(
            error,
            Error::Kms(stack_kms::Error::LoadKeyset(
                LoadKeysetError::KeysetNotFound(_)
            ))
        ),
        "ZeroKMS's not-found reaches the caller as it is, got {error:?}"
    );
    let by_id = load(&cipher, acme.keyset_id().await.unwrap())
        .await
        .expect("acme by id");
    assert_eq!(
        cipher.kms().loads(),
        3,
        "the keyset is still cached by id: only the name was answered"
    );
    assert_eq!(
        by_id.keyset_id().await.unwrap(),
        acme.keyset_id().await.unwrap()
    );

    cipher.kms().refuse("acme", Refusal::Unreachable);
    let error = load(&cipher, name("acme")).await.expect_err("failed");
    assert!(
        matches!(
            error,
            Error::Kms(stack_kms::Error::LoadKeyset(
                LoadKeysetError::RequestFailed(_)
            ))
        ),
        "a request that got no answer is a request failure, got {error:?}"
    );

    cipher.kms().allow("acme");
    let again = load(&cipher, name("acme")).await.expect("acme once more");
    assert_eq!(
        again.keyset_id().await.unwrap(),
        acme.keyset_id().await.unwrap(),
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
    cipher.kms().hold("acme");
    let earlier = load(&cipher, name("acme"));
    let meanwhile = async {
        cipher.kms().refuse("acme", Refusal::Unknown);
        let refused = load(&cipher, name("acme")).await;
        cipher.kms().release();
        refused
    };
    // `join!` polls in order: the earlier lookup takes its ticket and parks
    // on the hold, the later one is refused, and the release lets the
    // earlier answer land last.
    let (earlier, refused) = tokio::join!(earlier, meanwhile);
    let earlier = earlier.expect("the earlier lookup's own answer stands for its caller");
    assert!(
        matches!(
            refused,
            Err(Error::Kms(stack_kms::Error::LoadKeyset(
                LoadKeysetError::KeysetNotFound(_)
            )))
        ),
        "the later lookup was refused, got {refused:?}"
    );
    assert_eq!(
        cipher.kms().loads(),
        3,
        "init, the held lookup, the refused one"
    );

    cipher.kms().allow("acme");
    let later = load(&cipher, name("acme")).await.expect("acme afterwards");
    assert_eq!(
        cipher.kms().loads(),
        4,
        "the earlier answer bound nothing: a selection by the name asks ZeroKMS"
    );
    assert_eq!(
        later.keyset_id().await.unwrap(),
        earlier.keyset_id().await.unwrap(),
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
    cipher.kms().hold("acme");
    let earlier = load(&cipher, name("acme"));
    let meanwhile = async {
        cipher.kms().refuse("acme", Refusal::Unreachable);
        let failed = load(&cipher, name("acme")).await;
        cipher.kms().release();
        failed
    };
    let (earlier, failed) = tokio::join!(earlier, meanwhile);
    let earlier = earlier.expect("the earlier lookup's answer stands");
    assert!(
        matches!(
            failed,
            Err(Error::Kms(stack_kms::Error::LoadKeyset(
                LoadKeysetError::RequestFailed(_)
            )))
        ),
        "the later lookup got no answer, got {failed:?}"
    );
    assert_eq!(
        cipher.kms().loads(),
        3,
        "init, the held lookup, the failed one"
    );

    cipher.kms().allow("acme");
    let later = load(&cipher, name("acme")).await.expect("acme afterwards");
    assert_eq!(
        cipher.kms().loads(),
        3,
        "a failure to get an answer forgot nothing: the earlier answer bound the name and serves"
    );
    assert_eq!(
        later.keyset_id().await.unwrap(),
        earlier.keyset_id().await.unwrap()
    );
}

#[tokio::test]
async fn keysets_derive_distinct_index_keys() {
    let cipher = cipher().await;
    let a = load(&cipher, Uuid::from_u128(1)).await.expect("a");
    let b = load(&cipher, Uuid::from_u128(2)).await.expect("b");

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
    let tenant = load(&cipher, name("acme")).await.expect("select");

    let sealed = tenant
        .encrypt_tree("hello".to_string(), "greeting")
        .await
        .expect("seal");
    assert_eq!(
        leaf_of(sealed).keyset_id(),
        tenant.keyset_id().await.unwrap(),
        "a leaf carries the keyset it was sealed under"
    );

    let sealed = cipher
        .default_keyset()
        .encrypt_tree("hello".to_string(), "greeting")
        .await
        .expect("seal");
    assert_eq!(
        leaf_of(sealed).keyset_id(),
        cipher.default_keyset().keyset_id().await.unwrap(),
        "and so does one sealed through the default keyset"
    );
}

/// A handle is one keyset. Calls built through a handle before its keyset
/// is loaded all settle under the keyset the first of them loaded. A name
/// that comes to mean another keyset in between changes nothing for the
/// handle: no call mints a key under one keyset and names another in its
/// leaf. A new selection by the name gets the other keyset.
#[tokio::test]
async fn calls_built_before_the_load_settle_under_the_keyset_their_handle_keeps() {
    use stack_encrypt::sem::EqualityTerm;

    // No name is trusted, so every lookup of a name asks.
    let cipher = StackCipher::builder()
        .kms(Observed::default())
        .keyset_name_ttl(Duration::ZERO)
        .init()
        .await
        .expect("build cipher");
    let acme = cipher.keyset(name("acme"));
    let field = || nonempty!("users").with("email");

    // Built before anything has loaded the keyset.
    let first = acme.encrypt_tree("hello".to_string(), "greeting");
    let second = acme.encrypt_tree("hello".to_string(), "greeting");
    let third = acme.encrypt_tree("hello".to_string(), "greeting");
    let term = acme.equality_term(String::from("a@example.com"), field());

    let first = first.await.expect("seal");
    let kept = acme.keyset_id().await.unwrap();
    assert_eq!(leaf_of(first).keyset_id(), kept);
    let loads = cipher.kms().loads();

    cipher.kms().rename("acme", "globex");
    let elsewhere = load(&cipher, name("acme"))
        .await
        .expect("the name, selected again");
    let other = elsewhere.keyset_id().await.unwrap();
    assert_ne!(other, kept, "the name now means another keyset");
    assert_eq!(cipher.kms().loads(), loads + 1);

    let (second, third) = second.zip(third).await.expect("seal");
    assert_eq!(
        leaf_of(third).keyset_id(),
        kept,
        "the leaf names the handle's keyset"
    );
    let opened: String = acme
        .decrypt_tree(second, "greeting")
        .await
        .expect("its key was minted under the keyset the leaf names");
    assert_eq!(opened, "hello");

    let term: EqualityTerm = term.await.expect("term");
    let same = acme
        .equality_term(String::from("a@example.com"), field())
        .await
        .expect("term");
    assert_eq!(term, same, "derived under the handle's keyset");
    let under_the_other = elsewhere
        .equality_term(String::from("a@example.com"), field())
        .await
        .expect("term");
    assert_ne!(term, under_the_other);
    assert_eq!(
        cipher.kms().loads(),
        loads + 1,
        "no call through the handle resolved the name again"
    );
}

// =============================================================================
// Decrypting: the client opens any keyset, a keyset handle only its own
// =============================================================================

#[tokio::test]
async fn the_client_opens_a_leaf_from_any_keyset() {
    let cipher = cipher().await;
    let tenant = load(&cipher, name("acme")).await.expect("select");
    let sealed = tenant
        .encrypt_tree("hello".to_string(), "greeting")
        .await
        .expect("seal");

    let opened: String = cipher.decrypt(sealed, "greeting").await.expect("open");
    assert_eq!(opened, "hello", "the client opens another keyset's leaf");
    assert_eq!(
        cipher.kms().retrieve_keysets(),
        vec![Some(tenant.keyset_id().await.unwrap())],
        "the retrieve names the leaf's keyset, not the default"
    );
}

#[tokio::test]
async fn a_keyset_handle_opens_its_own_leaves() {
    let cipher = cipher().await;
    let tenant = load(&cipher, name("acme")).await.expect("select");
    let sealed = tenant
        .encrypt_tree("hello".to_string(), "greeting")
        .await
        .expect("seal");

    let opened: String = tenant.decrypt_tree(sealed, "greeting").await.expect("open");
    assert_eq!(opened, "hello", "a keyset handle opens its own leaf");
}

#[tokio::test]
async fn a_keyset_handle_refuses_another_keysets_leaf_before_any_retrieve() {
    let cipher = cipher().await;
    let acme = load(&cipher, name("acme")).await.expect("acme");
    let globex = load(&cipher, name("globex")).await.expect("globex");
    let sealed = acme
        .encrypt_tree("hello".to_string(), "greeting")
        .await
        .expect("seal");

    let result: Result<String, _> = globex.decrypt_tree(sealed, "greeting").await;
    assert!(
        matches!(
            result,
            Err(Error::ForeignKeyset { expected, found })
                if expected == globex.keyset_id().await.unwrap() && found == acme.keyset_id().await.unwrap()
        ),
        "{result:?}"
    );
    assert!(
        cipher.kms().retrieve_keysets().is_empty(),
        "refused before any key was retrieved"
    );
}

#[tokio::test]
async fn the_target_path_through_a_keyset_handle_is_constrained_too() {
    let cipher = cipher().await;
    let acme = load(&cipher, name("acme")).await.expect("acme");
    let globex = load(&cipher, name("globex")).await.expect("globex");
    // A ciphertext tree is not `Clone`; seal three, one per path.
    let seal = || async {
        let sealed: StackCipherText = 34u32
            .encrypt_into_with_context(&acme, nonempty!("users/age"))
            .await
            .expect("seal");
        sealed
    };

    let opened: u32 = u32::decrypt_from_with_context(seal().await, &acme, nonempty!("users/age"))
        .await
        .expect("own keyset opens");
    assert_eq!(opened, 34, "the sealing keyset opens its own leaf");

    let opened: u32 = u32::decrypt_from_with_context(seal().await, &cipher, nonempty!("users/age"))
        .await
        .expect("the client opens");
    assert_eq!(opened, 34, "and so does the client it belongs to");

    let result: Result<u32, _> =
        u32::decrypt_from_with_context(seal().await, &globex, nonempty!("users/age")).await;
    assert!(
        matches!(result, Err(Error::ForeignKeyset { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn a_mixed_keyset_column_opens_through_the_client_in_one_call_per_keyset() {
    let cipher = cipher().await;
    let acme = load(&cipher, name("acme")).await.expect("acme");
    let globex = load(&cipher, name("globex")).await.expect("globex");

    // A column whose rows belong to two tenants, interleaved.
    let mut column: Vec<StackCipherText> = Vec::new();
    for (i, tenant) in [(1u32, &acme), (2, &globex), (3, &acme)] {
        let sealed: StackCipherText = i
            .encrypt_into_with_context(tenant, nonempty!("users/age"))
            .await
            .expect("seal");
        column.push(sealed);
    }

    let opened: Vec<u32> =
        Vec::<u32>::decrypt_from_with_context(column, &cipher, nonempty!("users/age"))
            .await
            .expect("open");
    assert_eq!(
        opened,
        vec![1, 2, 3],
        "a two-tenant column opens in row order"
    );
    assert_eq!(
        cipher.kms().retrieve_keysets(),
        vec![
            Some(acme.keyset_id().await.unwrap()),
            Some(globex.keyset_id().await.unwrap())
        ],
        "one retrieve per keyset, first seen first"
    );
}

#[tokio::test]
async fn a_mixed_keyset_column_does_not_open_through_a_keyset_handle() {
    let cipher = cipher().await;
    let acme = load(&cipher, name("acme")).await.expect("acme");
    let globex = load(&cipher, name("globex")).await.expect("globex");
    let mut column: Vec<StackCipherText> = Vec::new();
    for tenant in [&acme, &globex] {
        let sealed: StackCipherText = 1u32
            .encrypt_into_with_context(tenant, nonempty!("users/age"))
            .await
            .expect("seal");
        column.push(sealed);
    }

    let result: Result<Vec<u32>, _> =
        Vec::<u32>::decrypt_from_with_context(column, &acme, nonempty!("users/age")).await;
    assert!(
        matches!(result, Err(Error::ForeignKeyset { .. })),
        "{result:?}"
    );
    assert!(
        cipher.kms().retrieve_keysets().is_empty(),
        "refused before any key was retrieved"
    );
}

// =============================================================================
// A JSON document with its root open
// =============================================================================

/// The deterministic source, which re-derives a data key in any process,
/// with a count of keyset loads: what a reader in another process holds.
struct Reader {
    inner: stack_kms::DeterministicSource,
    loads: AtomicUsize,
}

impl Reader {
    fn new() -> Self {
        Self {
            inner: stack_kms::DeterministicSource::new([7; 32]),
            loads: AtomicUsize::new(0),
        }
    }

    fn loads(&self) -> usize {
        self.loads.load(Ordering::Relaxed)
    }
}

impl DataKeySource for Reader {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
        self.inner
            .generate_keys(payloads, keyset_id, unverified_context)
            .await
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

impl IndexKeySource for Reader {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
        let _ = self.loads.fetch_add(1, Ordering::Relaxed);
        self.inner.load_index_key(keyset_id).await
    }
}

async fn reader() -> StackCipher<Reader> {
    StackCipher::builder()
        .kms(Reader::new())
        .init()
        .await
        .expect("build cipher")
}

/// Opening a JSON document whose root is open walks its chain from the
/// root's token, which takes the index key of the keyset it was sealed
/// under. A cipher that has not loaded that keyset loads it, once, as
/// selecting it would, and opens the document; after that it is a lookup.
/// A document with its root sealed opens from its root alone and loads
/// nothing.
#[tokio::test]
async fn opening_an_open_root_json_document_loads_its_keyset_once() {
    use serde_json::json;
    use stack_encrypt::json::{JsonDocument, JsonOptions, JsonPlaintext};
    use stack_encrypt::target::{json_document, AeadContext, Borrowed, CallerContext};

    let value = json!({"a": [1, {"b": "two"}], "c": null});
    let seal = |sealed_root: bool| {
        let value = value.clone();
        async move {
            let writer = reader().await;
            let tenant = load(&writer, name("acme")).await.expect("select");
            tenant
                .run(
                    json_document::<_, Borrowed>(JsonOptions {
                        sealed_root,
                        ..JsonOptions::new()
                    }),
                    &value,
                    CallerContext::from(nonempty!("users").with("profile")),
                )
                .await
                .expect("seals")
        }
    };
    let aead = || AeadContext::from(nonempty!("users").with("profile"));

    let reader = reader().await;
    assert_eq!(reader.kms().loads(), 1, "the reader has its default only");
    let sealed: JsonDocument = seal(true).await;
    let opened = JsonPlaintext::decrypt_from_with_context(sealed, &reader, aead())
        .await
        .expect("a sealed root opens");
    assert_eq!(opened.value(), &value);
    assert_eq!(reader.kms().loads(), 1, "a sealed root needs no index key");

    let open: JsonDocument = seal(false).await;
    for _ in 0..2 {
        let opened = JsonPlaintext::decrypt_from_with_context(open.clone(), &reader, aead())
            .await
            .expect("an open root opens through a cipher that had not loaded its keyset");
        assert_eq!(opened.value(), &value);
    }
    assert_eq!(
        reader.kms().loads(),
        2,
        "the document's keyset loads on the first open and is cached after"
    );
    let acme = load(&reader, name("acme")).await.expect("select");
    assert_eq!(acme.keyset_id().await.unwrap(), open.header().keyset_id());
    let opened = JsonPlaintext::decrypt_from_with_context(open.clone(), &acme, aead())
        .await
        .expect("and through the keyset's own cipher");
    assert_eq!(opened.value(), &value);
}
