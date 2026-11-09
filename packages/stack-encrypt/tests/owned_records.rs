//! Tests of owned record declarations: `#[derive(EncryptTarget,
//! DecryptSource)]` over a plaintext struct. The tests cover passthrough
//! fields, nested records, renamed source fields, a stored context, and one
//! batch for each collection. The mixed-record and searchable-record programs
//! from the public docs run here against the in-memory key source, so no
//! service credentials are needed.
//!
//! The plaintext types in these tests derive `Debug`, `PartialEq`, and `Clone`
//! so that the tests can compare results. The public examples do not, because
//! those traits print, compare, and copy plaintext.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use stack_encrypt::sem::{EqualityTerm, MatchTerms, OreTerm};
use stack_encrypt::target::{
    AcceptsContext, AeadContext, DecryptField, DecryptSource, Decryptable, Decryption,
    EncryptTarget, Encryption, NoCallerContext, OptionalContext, Owned, RequiredContext,
    ScalarContext,
};
use stack_encrypt::{
    nonempty, Ciphertext, Controlled, DecryptFrom, EncryptInto, Encrypted, Error, NonEmpty,
    Protected, StackCipherText,
};
use zeroize::Zeroize;
mod common;

// --- The public mixed-record program ---------------------------------------

#[derive(Debug, PartialEq, Clone, Zeroize)]
struct User {
    id: u64,
    name: String,
    email: String,
    created_at: i64,
}

/// `id` and `created_at` are stored in the clear. `name` and `email` are each
/// sealed on their own, under `("users", "name")` and `("users", "email")`.
#[derive(EncryptTarget, DecryptSource, Serialize, Deserialize)]
#[stash(struct = User, scope = "users")]
struct EncryptedUser {
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,
    email: Ciphertext,
    #[stash(passthrough)]
    created_at: i64,
}

fn alice() -> User {
    User {
        id: 42,
        name: "Alice".to_owned(),
        email: "alice@example.com".to_owned(),
        created_at: 1_700_000_000,
    }
}
fn bob() -> User {
    User {
        id: 43,
        name: "Bob".to_owned(),
        email: "bob@example.com".to_owned(),
        created_at: 1_700_000_100,
    }
}

#[tokio::test]
async fn a_mixed_record_round_trips_through_serde_with_its_passthrough_fields() {
    let (cipher, sent) = common::recording_cipher().await;
    let keyset = cipher.default_keyset();
    let user = alice();

    let encrypted: EncryptedUser = user.clone().encrypt_into(&keyset).await.unwrap();
    assert_eq!(encrypted.id, user.id);
    assert_eq!(encrypted.created_at, user.created_at);
    // One conversion makes one batched key request, with one data key for each
    // sealed field.
    let generated = sent.lock().unwrap().generate.clone();
    assert_eq!(generated, vec![vec!["users/name", "users/email"]]);

    // Store the typed output and read it back. Plaintext fields are stored as
    // themselves, and ciphertext fields as Base64 envelopes.
    let json = serde_json::to_value(&encrypted).unwrap();
    assert_eq!(json["id"], 42);
    assert_eq!(json["created_at"], 1_700_000_000);
    assert!(json["name"].is_string() && json["email"].is_string());
    let loaded: EncryptedUser = serde_json::from_value(json).unwrap();

    let restored = User::decrypt_from(loaded, &cipher).await.unwrap();
    assert_eq!(restored, user);
    let retrieved = sent.lock().unwrap().retrieve.clone();
    assert_eq!(retrieved, vec![vec!["users/name", "users/email"]]);
}

#[tokio::test]
async fn each_sealed_field_is_an_ordinary_ciphertext_under_its_pair() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let encrypted: EncryptedUser = alice().encrypt_into(&keyset).await.unwrap();
    assert_eq!(
        keyset
            .decrypt_with_context::<String>(encrypted.name.clone(), ("users", "name"))
            .await
            .unwrap(),
        "Alice"
    );
    assert_eq!(
        String::decrypt_from_with_context(encrypted.email.clone(), &keyset, ("users", "email"))
            .await
            .unwrap(),
        "alice@example.com"
    );
    // The field's context is part of the ciphertext's associated data, so a
    // field moved to the other column is refused.
    assert!(matches!(
        keyset
            .decrypt_with_context::<String>(encrypted.name, ("users", "email"))
            .await,
        Err(Error::Aead)
    ));
}

// --- Ownership: sealed fields wiped, passthrough fields moved -------------

/// A passthrough field type whose `Clone` fails the test. The borrowed form of
/// the record would copy it. The owned conversion must move it into the output
/// and back instead.
#[derive(Debug, PartialEq, Zeroize)]
struct Handle(u64);
impl Clone for Handle {
    fn clone(&self) -> Self {
        panic!("a passthrough field is moved by the owned conversion, never cloned")
    }
}

/// A sealed field type that records when it is wiped, and fails the test if it
/// is dropped without being wiped.
struct Secret {
    value: String,
    wiped: Arc<AtomicBool>,
}
impl Zeroize for Secret {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.wiped.store(true, Ordering::SeqCst);
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        assert!(self.value.is_empty(), "sealed plaintext dropped unwiped");
    }
}
struct SecretCiphertext(Ciphertext);
impl EncryptTarget<Secret> for SecretCiphertext {
    type ContextInput = OptionalContext<ScalarContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Secret, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext::<String, K>()
            .project(|secret: &Secret| &secret.value)
            .map(Self)
    }
}
impl DecryptSource<Secret> for SecretCiphertext {
    type ContextInput = OptionalContext<ScalarContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<Secret, K> {
        self.0.decryption(context).map(|value: String| Secret {
            value,
            wiped: Arc::default(),
        })
    }
}
// A hand-written target used as a record field must declare two things. It
// must declare that it contains ciphertext that can be decrypted. It must also
// declare how it decrypts under the context the record gives it. A
// hand-written structural target declares the same.
impl Decryptable for SecretCiphertext {
    const DECRYPTABLE: bool = true;
}
impl<Ctx: Into<OptionalContext<ScalarContext>>> DecryptField<Secret, Ctx> for SecretCiphertext {
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<Secret, K>> {
        Some(self.decryption(context.into()))
    }
}

#[derive(Zeroize)]
struct Tracked {
    handle: Handle,
    secret: Secret,
}
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Tracked, scope = "tracked")]
struct EncryptedTracked {
    #[stash(passthrough)]
    handle: Handle,
    secret: SecretCiphertext,
}

#[tokio::test]
async fn the_owned_record_wipes_sealed_fields_and_moves_passthrough_fields() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let wiped = Arc::new(AtomicBool::new(false));
    let tracked = Tracked {
        handle: Handle(7),
        secret: Secret {
            value: "secret".to_owned(),
            wiped: wiped.clone(),
        },
    };
    let pending = tracked.encrypt_into::<EncryptedTracked, _>(&keyset);
    assert!(
        wiped.load(Ordering::SeqCst),
        "the sealed field is wiped before any await"
    );
    assert_eq!(generates.load(Ordering::SeqCst), 0);
    let encrypted = pending.await.unwrap();
    assert_eq!(
        encrypted.handle,
        Handle(7),
        "the passthrough field is moved"
    );
    let opened = Tracked::decrypt_from(encrypted, &keyset).await.unwrap();
    assert_eq!(opened.handle, Handle(7));
    assert_eq!(opened.secret.value, "secret");
    // The caller owns the recovered plaintext. Wipe it, or `Secret::drop`
    // fails the test.
    let mut opened = opened;
    opened.secret.zeroize();
}

#[tokio::test]
async fn a_record_decrypts_straight_into_a_protected_that_wipes_it_on_drop() {
    let (cipher, _, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let tracked = || Tracked {
        handle: Handle(7),
        secret: Secret {
            value: "secret".to_owned(),
            wiped: Arc::default(),
        },
    };
    let encrypted: EncryptedTracked = tracked().encrypt_into(&keyset).await.unwrap();
    let opened = Protected::<Tracked>::decrypt_from(encrypted, &keyset)
        .await
        .unwrap();
    assert_eq!(opened.risky_ref().secret.value, "secret");
    // `Secret::drop` fails the test unless the `Protected` wiped it.
    drop(opened);

    // A column decrypts into one `Protected` per row.
    let column: Vec<EncryptedTracked> = vec![tracked(), tracked()]
        .encrypt_into(&keyset)
        .await
        .unwrap();
    let rows = Vec::<Protected<Tracked>>::decrypt_from(column, &keyset)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    drop(rows);
}

/// A record nested under a context too long for a ZeroKMS descriptor. A
/// record that contains another passes it its field's context through
/// `Encryption::under`, as this target does. The key request is refused.
struct Oversized;
impl EncryptTarget<Tracked> for Oversized {
    type ContextInput = NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Tracked, Self, K, Self::ContextInput> {
        unreachable!("the test runs the owned form only")
    }
    fn owned_encryption<'s, K: 'static>(
    ) -> Encryption<'s, Tracked, Self, K, Self::ContextInput, Owned> {
        // Longer than the 512-byte limit of a ZeroKMS descriptor.
        <EncryptedTracked as EncryptTarget<Tracked>>::owned_encryption()
            .under(NonEmpty::new("x".repeat(65536)).unwrap())
            .map(|_: EncryptedTracked| Self)
            .accepting()
    }
}

#[tokio::test]
async fn the_owned_record_wipes_sealed_fields_when_the_context_is_refused() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let wiped = Arc::new(AtomicBool::new(false));
    let tracked = Tracked {
        handle: Handle(7),
        secret: Secret {
            value: "secret".to_owned(),
            wiped: wiped.clone(),
        },
    };
    let pending = tracked.encrypt_into::<Oversized, _>(&keyset);
    assert!(wiped.load(Ordering::SeqCst));
    assert!(pending.await.is_err());
    assert_eq!(generates.load(Ordering::SeqCst), 0);
}

// --- A refused context drops no copy of a sealed plaintext unwiped ---------

/// A sealed plaintext that the borrowed form of a `StackCipherText` leaf would
/// clone. Its `Drop` records whether it still held its value. So a copy that
/// is dropped without being wiped is seen, whichever copy it is.
struct Probe {
    value: String,
    leaked: Arc<AtomicBool>,
}
impl Clone for Probe {
    fn clone(&self) -> Self {
        Probe {
            value: self.value.clone(),
            leaked: self.leaked.clone(),
        }
    }
}
impl Zeroize for Probe {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        if !self.value.is_empty() {
            self.leaked.store(true, Ordering::SeqCst);
        }
    }
}
impl stack_encrypt::Encrypt for Probe {
    fn visit<S: vitaminc_aead::Sink>(mut self, sink: S) -> Result<S::Ok, S::Error> {
        std::mem::take(&mut self.value).visit(sink)
    }
}
fn probe(leaked: &Arc<AtomicBool>) -> Probe {
    Probe {
        value: "secret".to_owned(),
        leaked: leaked.clone(),
    }
}
/// A context longer than a ZeroKMS descriptor can hold.
fn too_long() -> NonEmpty<String> {
    NonEmpty::new("x".repeat(65536)).unwrap()
}

#[derive(Zeroize)]
struct ProbeRow {
    secret: Probe,
}
#[allow(dead_code)] // These tests only encrypt.
#[derive(EncryptTarget)]
#[stash(struct = ProbeRow, scope = "rows")]
struct EncryptedProbeRow {
    secret: StackCipherText,
}
/// The scope literal is longer than a ZeroKMS descriptor can hold. The
/// derive does not check its length, so the key request is refused at run
/// time.
#[allow(dead_code)] // These tests only encrypt.
#[derive(EncryptTarget)]
#[stash(struct = ProbeRow, scope = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")]
struct LongScopeProbeRow {
    secret: StackCipherText,
}
#[derive(Zeroize)]
struct ProbeOuter {
    inner: ProbeRow,
}
#[allow(dead_code)] // These tests only encrypt.
#[derive(EncryptTarget)]
#[stash(struct = ProbeOuter, scope = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")]
struct LongScopeProbeOuter {
    inner: EncryptedProbeRow,
}
#[allow(dead_code)] // These tests only encrypt.
#[derive(EncryptTarget)]
#[stash(plaintext = Probe)]
struct SealedProbe {
    c: StackCipherText,
}
#[allow(dead_code)] // These tests only encrypt.
#[derive(EncryptTarget)]
#[stash(plaintext = Probe)]
struct StoredContextProbe {
    #[stash(context_field)]
    identifier: &'static str,
    c: StackCipherText,
}
#[derive(Zeroize)]
struct ProbeColumn {
    secrets: Vec<Probe>,
}
#[allow(dead_code)] // These tests only encrypt.
#[derive(EncryptTarget)]
#[stash(struct = ProbeColumn, scope = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")]
struct LongScopeProbeColumn {
    secrets: Vec<StackCipherText>,
}

/// Run `encrypt` over a probe that a refused context must not leak. The test
/// fails if the encryption succeeds, or if any copy of the plaintext is
/// dropped while it still holds its value.
async fn assert_refused_without_a_leak<T, F>(encrypt: F)
where
    F: for<'a> FnOnce(
        &Arc<AtomicBool>,
        &'a stack_encrypt::KeysetCipher<'a, common::CountingSource>,
    ) -> stack_encrypt::target::Pending<'a, T, common::CountingSource>,
{
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let leaked = Arc::new(AtomicBool::new(false));
    let result = encrypt(&leaked, &keyset).await;
    assert!(result.is_err(), "the context is refused");
    assert!(
        !leaked.load(Ordering::SeqCst),
        "a copy of the sealed plaintext was dropped unwiped"
    );
    assert_eq!(generates.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_sealed_field_is_not_leaked_when_the_scope_is_refused() {
    // The control: the same record under a scope that fits leaks nothing.
    let (cipher, _, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let leaked = Arc::new(AtomicBool::new(false));
    let row = ProbeRow {
        secret: probe(&leaked),
    };
    assert!(row
        .encrypt_into::<EncryptedProbeRow, _>(&keyset)
        .await
        .is_ok());
    assert!(!leaked.load(Ordering::SeqCst));

    assert_refused_without_a_leak(|leaked, keyset| {
        ProbeRow {
            secret: probe(leaked),
        }
        .encrypt_into::<LongScopeProbeRow, _>(keyset)
    })
    .await;
}

#[tokio::test]
async fn a_nested_sealed_field_is_not_leaked_when_the_outer_scope_is_refused() {
    assert_refused_without_a_leak(|leaked, keyset| {
        ProbeOuter {
            inner: ProbeRow {
                secret: probe(leaked),
            },
        }
        .encrypt_into::<LongScopeProbeOuter, _>(keyset)
    })
    .await;
}

#[tokio::test]
async fn a_plaintext_record_is_not_leaked_when_the_caller_context_is_refused() {
    assert_refused_without_a_leak(|leaked, keyset| {
        probe(leaked).encrypt_into_with_context::<SealedProbe, _>(keyset, too_long())
    })
    .await;
}

#[tokio::test]
async fn a_plaintext_record_is_not_leaked_when_the_stored_context_is_refused() {
    let identifier: &'static str = Box::leak("x".repeat(65536).into_boxed_str());
    assert_refused_without_a_leak(|leaked, keyset| {
        probe(leaked).encrypt_into_with_context::<StoredContextProbe, _>(
            keyset,
            NonEmpty::new(identifier).unwrap(),
        )
    })
    .await;
}

#[tokio::test]
async fn a_sealed_column_is_not_leaked_when_the_scope_is_refused() {
    assert_refused_without_a_leak(|leaked, keyset| {
        ProbeColumn {
            secrets: vec![probe(leaked), probe(leaked)],
        }
        .encrypt_into::<LongScopeProbeColumn, _>(keyset)
    })
    .await;
}

#[tokio::test]
async fn a_stack_ciphertext_is_not_leaked_when_the_context_is_refused() {
    assert_refused_without_a_leak(|leaked, keyset| {
        probe(leaked).encrypt_into_with_context::<StackCipherText, _>(keyset, too_long())
    })
    .await;
}

#[tokio::test]
async fn a_vec_of_stack_ciphertext_is_not_leaked_when_the_context_is_refused() {
    assert_refused_without_a_leak(|leaked, keyset| {
        vec![probe(leaked), probe(leaked)]
            .encrypt_into_with_context::<Vec<StackCipherText>, _>(keyset, too_long())
    })
    .await;
}

#[tokio::test]
async fn a_searchable_ciphertext_is_not_leaked_when_the_context_is_refused() {
    // The ciphertext and the equality term each take the plaintext. The
    // term's scheme consumes its copy. The refused ciphertext must not drop
    // its copy unwiped.
    assert_refused_without_a_leak(|leaked, keyset| {
        probe(leaked).encrypt_into_with_context::<Encrypted<EqualityTerm>, _>(keyset, too_long())
    })
    .await;
}

#[derive(Zeroize)]
struct Pair {
    first: Secret,
    second: Secret,
}
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Pair, scope = "pairs")]
struct EncryptedPair {
    first: SecretCiphertext,
    second: SecretCiphertext,
}

#[tokio::test]
async fn a_field_opened_before_a_later_field_is_refused_is_wiped() {
    let (cipher, _, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let secret = |value: &str| Secret {
        value: value.to_owned(),
        wiped: Arc::default(),
    };
    let encrypted: EncryptedPair = Pair {
        first: secret("opened first"),
        second: secret("never opened"),
    }
    .encrypt_into(&keyset)
    .await
    .unwrap();
    // `second` contains the ciphertext sealed under the context of `first`. So
    // `second` is refused only once its key arrives, after `first` has been
    // decrypted. `Secret::drop` fails the test if `first` is then dropped
    // without being wiped.
    let moved = EncryptedPair {
        second: SecretCiphertext(encrypted.first.0.clone()),
        first: encrypted.first,
    };
    let result = Pair::decrypt_from(moved, &keyset).await;
    assert!(matches!(result, Err(Error::Aead)));
    assert_eq!(retrieves.load(Ordering::SeqCst), 1, "both keys in one call");
}

// --- A panic while declaring wipes what has not been handed over -----------

// A sealed field type with no drop check of its own. A value dropped without
// being wiped during an unwind is detected through the flag, not as an abort.
struct Flagged {
    value: String,
    wiped: Arc<AtomicBool>,
}
impl Zeroize for Flagged {
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.wiped.store(true, Ordering::SeqCst);
    }
}
fn flagged(value: &str) -> (Flagged, Arc<AtomicBool>) {
    let wiped = Arc::new(AtomicBool::new(false));
    let source = Flagged {
        value: value.to_owned(),
        wiped: wiped.clone(),
    };
    (source, wiped)
}

/// Seals a `Flagged`, and panics while declaring the `Flagged` whose plaintext
/// is `"panics"`. The panic happens inside the default owned guard, while the
/// field's description runs.
// These tests only encrypt, so the ciphertext is never read.
struct FlaggedCiphertext(#[allow(dead_code)] Ciphertext);
impl EncryptTarget<Flagged> for FlaggedCiphertext {
    type ContextInput = OptionalContext<ScalarContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Flagged, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext::<String, K>()
            .project(|source: &Flagged| {
                assert!(source.value != "panics", "field declaration failed");
                &source.value
            })
            .map(Self)
    }
}
impl Decryptable for FlaggedCiphertext {
    const DECRYPTABLE: bool = false;
}

#[derive(Zeroize)]
struct Trio {
    first: Flagged,
    #[zeroize(skip)]
    handle: u64,
    third: Flagged,
    fourth: Flagged,
}
// This record is only encrypted, and the encryption never completes, so its
// fields are never read.
#[allow(dead_code)]
#[derive(EncryptTarget)]
#[stash(struct = Trio, scope = "trios")]
struct EncryptedTrio {
    first: FlaggedCiphertext,
    #[stash(passthrough)]
    handle: u64,
    third: FlaggedCiphertext,
    fourth: FlaggedCiphertext,
}

#[tokio::test]
async fn a_panicking_field_declaration_wipes_the_sealed_fields_after_it() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    // This covers the outer `split`, where the first field panics and the
    // other fields wait as one part. It also covers a nested `split`, where
    // the third field panics and the fourth waits on its own.
    for panicking in ["first", "third"] {
        let value = |field: &'static str| if field == panicking { "panics" } else { field };
        let (first, first_wiped) = flagged(value("first"));
        let (third, third_wiped) = flagged(value("third"));
        let (fourth, fourth_wiped) = flagged(value("fourth"));
        let trio = Trio {
            first,
            handle: 7,
            third,
            fourth,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(trio.encrypt_into::<EncryptedTrio, _>(&keyset));
        }));
        assert!(
            result.is_err(),
            "the {panicking} field's declaration panicked"
        );
        assert!(
            first_wiped.load(Ordering::SeqCst) && third_wiped.load(Ordering::SeqCst),
            "the fields handed over are wiped by their own guards ({panicking} panicked)"
        );
        assert!(
            fourth_wiped.load(Ordering::SeqCst),
            "the sealed fields not yet handed over are wiped during the unwind ({panicking} panicked)"
        );
    }
}

/// Seals a `Flagged` through a declaration that panics while it is built. At
/// that point, `encrypt_into` is holding only the plaintext.
struct UnconstructedCiphertext(#[allow(dead_code)] Ciphertext);
impl EncryptTarget<Flagged> for UnconstructedCiphertext {
    type ContextInput = OptionalContext<ScalarContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Flagged, Self, K, Self::ContextInput> {
        FlaggedCiphertext::encryption().map(|FlaggedCiphertext(c)| Self(c))
    }
    fn owned_encryption<'s, K: 'static>(
    ) -> Encryption<'s, Flagged, Self, K, Self::ContextInput, stack_encrypt::target::Owned> {
        panic!("declaration construction failed")
    }
}

#[tokio::test]
async fn a_declaration_that_panics_while_constructed_wipes_the_plaintext() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let (source, wiped) = flagged("secret");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drop(source.encrypt_into::<UnconstructedCiphertext, _>(&keyset));
    }));
    assert!(
        result.is_err(),
        "the declaration panicked while constructed"
    );
    assert!(
        wiped.load(Ordering::SeqCst),
        "the plaintext is wiped during the unwind, with the context omitted"
    );

    let (source, wiped) = flagged("secret");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drop(source.encrypt_into_with_context::<UnconstructedCiphertext, _>(&keyset, "rows"));
    }));
    assert!(
        result.is_err(),
        "the declaration panicked while constructed"
    );
    assert!(
        wiped.load(Ordering::SeqCst),
        "the plaintext is wiped during the unwind, with a context supplied"
    );
}

// --- The public searchable-record program, as one batch --------------------

/// A scalar target that the application defines: the ciphertext and an
/// equality term, under the one context the record or the caller supplies.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct SearchableEmail {
    ciphertext: Ciphertext,
    equality: EqualityTerm,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users")]
struct SearchableUser {
    #[stash(passthrough)]
    id: u64,
    name: Ciphertext,
    email: SearchableEmail,
    #[stash(passthrough)]
    created_at: i64,
}

#[tokio::test]
async fn a_searchable_column_is_one_batch_and_its_terms_match_a_query_term() {
    let (cipher, generates, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let users = vec![alice(), bob()];

    // One collection conversion makes one batched key request for both users:
    // two keys for the names and two keys for the email addresses.
    let encrypted: Vec<SearchableUser> = users.clone().encrypt_into(&keyset).await.unwrap();
    assert_eq!(generates.load(Ordering::SeqCst), 1);
    assert_eq!(encrypted.len(), 2);

    // Later, another cipher builds a query under the same keyset, field
    // context, and operation. This is how a query in another process derives
    // it.
    let reader = common::stack_cipher().await;
    let query: EqualityTerm = "alice@example.com"
        .to_owned()
        .encrypt_into_with_context(&reader.default_keyset(), nonempty!("users").with("email"))
        .await
        .unwrap();
    // A scan of the stored rows in memory takes the place of a database index.
    let matches: Vec<SearchableUser> = encrypted
        .into_iter()
        .filter(|row| row.email.equality == query)
        .collect();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].id, 42);

    // The matching rows are decrypted in one batch.
    let restored = Vec::<User>::decrypt_from(matches, &cipher).await.unwrap();
    assert_eq!(restored, &users[..1]);
    assert_eq!(retrieves.load(Ordering::SeqCst), 1);
}

#[test]
fn each_owned_term_target_names_its_index() {
    use stack_encrypt::sem::{DefaultMatch, MatchConfig, OpeTerm, OreBlockTerm};
    use stack_encrypt::IndexSpec;
    assert_eq!(
        <EqualityTerm as EncryptTarget<String>>::indexes(),
        [IndexSpec::Equality]
    );
    assert_eq!(
        <MatchTerms<DefaultMatch> as EncryptTarget<String>>::indexes(),
        [IndexSpec::Match(DefaultMatch::options())]
    );
    assert_eq!(
        <OreTerm<String> as EncryptTarget<String>>::indexes(),
        [IndexSpec::Ore]
    );
    assert_eq!(
        <OpeTerm<String> as EncryptTarget<String>>::indexes(),
        [IndexSpec::Ope]
    );
    assert_eq!(
        <OreBlockTerm<u32> as EncryptTarget<u32>>::indexes(),
        [IndexSpec::OreBlock]
    );
}

#[tokio::test]
async fn a_searchable_email_standalone_requires_its_context() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let sealed: SearchableEmail = "alice@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .await
        .unwrap();
    // The record's indexes are the indexes of its terms.
    assert_eq!(
        <SearchableEmail as EncryptTarget<String>>::indexes(),
        vec![stack_encrypt::IndexSpec::Equality]
    );
    assert_eq!(
        String::decrypt_from_with_context(sealed, &keyset, nonempty!("users/email"))
            .await
            .unwrap(),
        "alice@example.com"
    );
}

// --- Nested records, renamed sources, pinned identities --------------------

#[derive(Debug, PartialEq, Clone, Zeroize)]
struct Address {
    street: String,
    city: String,
}
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Address, scope = "addresses")]
struct EncryptedAddress {
    street: Ciphertext,
    city: Ciphertext,
}

#[derive(Debug, PartialEq, Clone, Zeroize)]
struct Account {
    account_id: u64,
    holder: String,
    address: Address,
    opened: i64,
}
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Account, scope = "accounts")]
struct EncryptedAccount {
    /// A passthrough field with another name.
    #[stash(passthrough, from = account_id)]
    id: u64,
    /// A sealed field with another name. Its context uses the name of the
    /// plaintext field.
    #[stash(from = holder)]
    owner: Ciphertext,
    /// A sealed field whose context uses a fixed segment.
    #[stash(from = opened, identity = "opened_at")]
    opened: Ciphertext,
    /// A nested record. Its fields have their own contexts, extended by the
    /// context of this field.
    address: EncryptedAddress,
}

#[tokio::test]
async fn nested_renamed_and_pinned_fields_compose_their_contexts() {
    let (cipher, sent) = common::recording_cipher().await;
    let keyset = cipher.default_keyset();
    let account = Account {
        account_id: 9,
        holder: "Carol".to_owned(),
        address: Address {
            street: "1 Main St".to_owned(),
            city: "Springfield".to_owned(),
        },
        opened: 1_600_000_000,
    };
    let encrypted: EncryptedAccount = account.clone().encrypt_into(&keyset).await.unwrap();
    assert_eq!(encrypted.id, 9);
    assert_eq!(
        sent.lock().unwrap().generated(),
        vec![
            "accounts/holder",
            "accounts/opened_at",
            "(addresses/street)/(accounts/address)",
            "(addresses/city)/(accounts/address)",
        ]
    );
    let restored = Account::decrypt_from(encrypted, &keyset).await.unwrap();
    assert_eq!(restored, account);
}

// --- A record that stores its context -------------------------------------

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct TextEq {
    #[stash(context_field)]
    identifier: &'static str,
    c: Ciphertext,
    hm: EqualityTerm,
}

#[tokio::test]
async fn a_stored_context_opens_as_stored_and_checks_an_expectation() {
    let (cipher, _, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let value = "alice@example.com".to_owned();
    let encrypted: TextEq = value
        .clone()
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .await
        .unwrap();
    assert_eq!(encrypted.identifier, "users/email");
    let generator = common::stack_cipher().await;
    let hm: EqualityTerm = value
        .clone()
        .encrypt_into_with_context(&generator.default_keyset(), nonempty!("users/email"))
        .await
        .unwrap();
    assert_eq!(encrypted.hm, hm);

    // With no expected context, the record decrypts under the stored
    // identifier.
    let again = TextEq {
        identifier: encrypted.identifier,
        c: encrypted.c.clone(),
        hm: encrypted.hm.clone(),
    };
    assert_eq!(String::decrypt_from(again, &keyset).await.unwrap(), value);
    // With an expected context, the stored identifier must equal it. The check
    // runs before any key request.
    let moved = TextEq {
        identifier: "users/name",
        c: encrypted.c.clone(),
        hm: encrypted.hm.clone(),
    };
    let before = retrieves.load(Ordering::SeqCst);
    assert!(matches!(
        String::decrypt_from_with_context(moved, &keyset, nonempty!("users/email")).await,
        Err(Error::ContextMismatch { .. })
    ));
    assert_eq!(retrieves.load(Ordering::SeqCst), before);
    assert_eq!(
        String::decrypt_from_with_context(encrypted, &keyset, nonempty!("users/email"))
            .await
            .unwrap(),
        value
    );
}

// --- Plaintext records over the structural leaves and a fixed context -----

/// The hand-written composite in `target.rs`, as an owned record. Its fields
/// are the structural leaves. They take the same required context.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = u32)]
struct EncryptedAge {
    c: StackCipherText,
    hm: EqualityTerm,
    ob: OreTerm<u32>,
}

/// A record made only of ciphertexts accepts an AEAD-only context. A term
/// beside them would be a compile error at its field (`tests/ui`).
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String, context_type = AeadContext)]
struct SealedName {
    #[stash(decrypt)]
    c: StackCipherText,
    #[allow(dead_code)]
    shadow: Ciphertext,
}

/// The ciphertext with its terms, as one structural leaf of an owned record.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct Indexed {
    email: Encrypted<(EqualityTerm, MatchTerms)>,
}

/// Generic over the plaintext: any plaintext that every field accepts.
#[derive(EncryptTarget, DecryptSource)]
struct SearchableText {
    c: Ciphertext,
    hm: EqualityTerm,
    m: MatchTerms,
}

#[tokio::test]
async fn plaintext_records_compose_structural_and_opaque_leaves() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();
    let generator = common::stack_cipher().await;
    let generator = generator.default_keyset();

    let age: EncryptedAge = 42u32
        .encrypt_into_with_context(&keyset, nonempty!("users/age"))
        .await
        .unwrap();
    let hm: EqualityTerm = 42u32
        .encrypt_into_with_context(&generator, nonempty!("users/age"))
        .await
        .unwrap();
    assert_eq!(age.hm, hm);
    assert_eq!(
        <EncryptedAge as EncryptTarget<u32>>::indexes(),
        vec![
            stack_encrypt::IndexSpec::Equality,
            stack_encrypt::IndexSpec::Ore
        ]
    );
    assert_eq!(
        u32::decrypt_from_with_context(age, &keyset, nonempty!("users/age"))
            .await
            .unwrap(),
        42
    );

    let name: SealedName = "Dana"
        .to_owned()
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
        .await
        .unwrap();
    assert!(matches!(
        String::decrypt_from_with_context(name, &keyset, nonempty!("users/name")).await,
        Ok(opened) if opened == "Dana"
    ));

    let indexed: Indexed = "alice@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .await
        .unwrap();
    assert_eq!(
        <Indexed as EncryptTarget<String>>::indexes().len(),
        2,
        "equality and match"
    );
    assert_eq!(
        String::decrypt_from_with_context(indexed, &keyset, nonempty!("users/email"))
            .await
            .unwrap(),
        "alice@example.com"
    );

    let text: SearchableText = "alice"
        .to_owned()
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
        .await
        .unwrap();
    let m: MatchTerms = "alice"
        .to_owned()
        .encrypt_into_with_context(&generator, nonempty!("users/name"))
        .await
        .unwrap();
    assert_eq!(text.m, m);
    assert_eq!(
        String::decrypt_from_with_context(text, &keyset, nonempty!("users/name"))
            .await
            .unwrap(),
        "alice"
    );
}

// --- A field whose target declares its whole context ----------------------

/// A target that supplies every context itself can be a field of a `plaintext`
/// record only if that record also takes no context. Here it is used on its
/// own, and in a column.
struct FixedInteger(Ciphertext);
impl EncryptTarget<i32> for FixedInteger {
    type ContextInput = NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, i32, Self, K, Self::ContextInput> {
        stack_encrypt::target::scalar_ciphertext()
            .map(Self)
            .under(nonempty!("users/fixed-age"))
            .accepting()
    }
}
impl DecryptSource<i32> for FixedInteger {
    type ContextInput = NoCallerContext;
    fn decryption<K: 'static>(self, _: Self::ContextInput) -> Decryption<i32, K> {
        self.0
            .decryption(OptionalContext::<ScalarContext>::supplied(
                "users/fixed-age".into(),
            ))
    }
}

#[tokio::test]
async fn an_owned_record_is_a_field_of_a_structural_record_and_a_plan() {
    use stack_encrypt::plan::pick;
    use stack_encrypt::target::legacy::EncryptInto as _;
    use stack_encrypt::{EncryptFrom, Plan};

    #[derive(Clone)]
    struct Profile {
        user: User,
        age: u32,
    }
    /// A structural record with an owned record as a field. The owned derive
    /// also implements `EncryptFrom` with a `DeclaredContext`, so this works.
    #[derive(EncryptFrom)]
    #[stash(struct = Profile, scope = "profiles")]
    struct EncryptedProfile {
        user: EncryptedUser,
        #[allow(dead_code)]
        age: EncryptedAge,
    }

    let (cipher, sent) = common::recording_cipher().await;
    let keyset = cipher.default_keyset();
    let profile = Profile {
        user: alice(),
        age: 34,
    };
    let encrypted: EncryptedProfile = profile.encrypt_into(&keyset).await.unwrap();
    assert_eq!(encrypted.user.id, 42);
    assert_eq!(
        sent.lock().unwrap().generated(),
        vec![
            "(users/name)/(profiles/user)",
            "(users/email)/(profiles/user)",
            "profiles/age"
        ]
    );

    // The owned record also works as a typed field of a plan, for the same
    // reason.
    let plan = Plan::context("profiles")
        .fields::<Profile, _>()
        .encrypt_into::<EncryptedUser, _>(pick("user", |p: &Profile| &p.user))
        .target::<Ciphertext, _>(pick("age", |p: &Profile| &p.age))
        .build()
        .unwrap();
    let profile = Profile {
        user: bob(),
        age: 51,
    };
    let mut values = cipher.encrypt(&profile).using(&plan).await.unwrap();
    let user: EncryptedUser = values.take("user").unwrap();
    assert_eq!(user.id, 43);
    let age: Ciphertext = values.take("age").unwrap();
    assert_eq!(
        keyset
            .decrypt_with_context::<u32>(age, ("profiles", "age"))
            .await
            .unwrap(),
        51
    );
    let _ = (
        FixedInteger::encryption::<common::CountingSource>,
        RequiredContext::<u64>::into_inner,
    );
}
