//! `#[derive(EncryptFrom)]` / `#[derive(DecryptInto)]`: the derived impls are the
//! hand-written composite in `target.rs`, emitted — same terms, same decrypt
//! mirror, same one-batched-call settlement — plus what only a derive makes
//! cheap: sources listed or left generic, rows derived field by field, and
//! fields that are not derived at all.

mod common;

use std::sync::atomic::Ordering as AtomicOrdering;

use cllw_ore::CllwOreEncrypt;
use common::{counting_cipher, stack_cipher};
use stack_encrypt::sem::{EqualityTerm, MatchTerm, OreTerm};
use stack_encrypt::target::{DecryptFrom, EncryptInto};
use stack_encrypt::{
    DecryptField, DecryptInto, DecryptTarget, Decryptable, EncryptFrom, Error, Pending,
    StackCipher, StackCipherText,
};

// --- Records: every field from one plaintext, under one context -------------

/// The hand-written record in `target.rs`, derived: an encrypted `u32`
/// stored as its ciphertext plus an equality term and an ORE term.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32)]
struct EncryptedAge {
    c: StackCipherText,
    hm: EqualityTerm,
    ob: OreTerm<u32>,
}

#[tokio::test]
async fn a_derived_record_is_the_hand_written_one() {
    let cipher = stack_cipher().await;
    let generator = stack_cipher().await;

    let record: EncryptedAge = 42u32
        .encrypt_into_with_context(&cipher, "users/age")
        .await
        .unwrap();

    // Each term is what the leaf derives on its own, so query terms built
    // leaf-by-leaf find records encrypted as composites.
    let hm: EqualityTerm = 42u32
        .encrypt_into_with_context(&generator, "users/age")
        .await
        .unwrap();
    let ob: OreTerm<u32> = 42u32
        .encrypt_into_with_context(&generator, "users/age")
        .await
        .unwrap();
    assert_eq!(record.hm, hm);
    assert_eq!(record.ob, ob);

    // And the decrypt mirror opens the ciphertext field.
    let age: u32 = record.decrypt_into(&cipher, "users/age").await.unwrap();
    assert_eq!(age, 42);
}

/// No `plaintext`: one impl generic over it, accepting whatever every leaf
/// accepts — here any text type, since `MatchTerm` wants `AsRef<str>` — and
/// decrypting to whatever the ciphertext field opens to.
#[derive(EncryptFrom, DecryptInto)]
struct SearchableText {
    c: StackCipherText,
    hm: EqualityTerm,
    m: MatchTerm,
}

/// Tuple structs assign by index.
#[derive(EncryptFrom)]
struct Pair(StackCipherText, EqualityTerm);

/// The record's own generics (and their bounds) are carried through, and the
/// where clause makes `Tagged<T>` accept exactly `T` — the ORE term is typed
/// by its source. A generic record's one-ciphertext check runs when the
/// record is first used rather than where it is defined.
#[derive(EncryptFrom, DecryptInto)]
struct Tagged<T: CllwOreEncrypt> {
    c: StackCipherText,
    ob: OreTerm<T>,
}

#[tokio::test]
async fn a_generic_plaintext_record_accepts_what_its_leaves_accept() {
    let cipher = stack_cipher().await;
    let generator = stack_cipher().await;

    let record: SearchableText = "alice"
        .to_string()
        .encrypt_into_with_context(&cipher, "users/name")
        .await
        .unwrap();
    let hm: EqualityTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&generator, "users/name")
        .await
        .unwrap();
    let m: MatchTerm = "alice"
        .to_string()
        .encrypt_into_with_context(&generator, "users/name")
        .await
        .unwrap();
    assert_eq!(record.hm, hm);
    assert_eq!(record.m, m);
    let name: String = record.decrypt_into(&cipher, "users/name").await.unwrap();
    assert_eq!(name, "alice");

    let pair: Pair = "bob"
        .encrypt_into_with_context(&cipher, "users/name")
        .await
        .unwrap();
    let hm: EqualityTerm = "bob"
        .encrypt_into_with_context(&generator, "users/name")
        .await
        .unwrap();
    assert_eq!(pair.1, hm);
    let name: String = pair.0.decrypt_into(&cipher, "users/name").await.unwrap();
    assert_eq!(name, "bob");

    let tagged: Tagged<u32> = 7u32
        .encrypt_into_with_context(&cipher, "users/score")
        .await
        .unwrap();
    let ob: OreTerm<u32> = 7u32
        .encrypt_into_with_context(&generator, "users/score")
        .await
        .unwrap();
    assert_eq!(tagged.ob, ob);
    let score: u32 = tagged.decrypt_into(&cipher, "users/score").await.unwrap();
    assert_eq!(score, 7);
}

/// Two ciphertexts in one record: the type system cannot pick, so
/// `#[stash(decrypt)]` does. Only marked fields are considered, and the
/// others need not be `Decryptable` at all.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32)]
struct Doubled {
    #[stash(decrypt)]
    c: StackCipherText,
    #[stash(context = "doubled/shadow")]
    shadow: StackCipherText,
}

/// Fields that are collections or optional follow their content: a record
/// of a `Vec<u32>` has one decryptable field, its `Vec<StackCipherText>`.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = Vec<u32>)]
struct Numbers {
    c: Vec<StackCipherText>,
    hm: Vec<EqualityTerm>,
}

#[tokio::test]
async fn decrypt_marks_the_field_when_the_types_cannot_choose() {
    let cipher = stack_cipher().await;

    let doubled: Doubled = 9u32
        .encrypt_into_with_context(&cipher, "doubled")
        .await
        .unwrap();
    let opened: u32 = doubled.decrypt_into(&cipher, "doubled").await.unwrap();
    assert_eq!(opened, 9);
    // The unmarked ciphertext is still a ciphertext, just not the record's.
    let doubled: Doubled = 9u32
        .encrypt_into_with_context(&cipher, "doubled")
        .await
        .unwrap();
    let shadow: u32 = doubled
        .shadow
        .decrypt_into(&cipher, "doubled/shadow")
        .await
        .unwrap();
    assert_eq!(shadow, 9);

    let numbers: Numbers = vec![1u32, 2, 3]
        .encrypt_into_with_context(&cipher, "numbers")
        .await
        .unwrap();
    assert_eq!(numbers.hm.len(), 3);
    let opened: Vec<u32> = numbers.decrypt_into(&cipher, "numbers").await.unwrap();
    assert_eq!(opened, vec![1, 2, 3]);
}

/// An index term type from outside this crate that predates `Decryptable`:
/// it implements `EncryptFrom` only, wrapping a term of ours.
#[derive(PartialEq)]
struct OpaqueTerm(EqualityTerm);

impl<S, K, Ctx> EncryptFrom<S, StackCipher<K>, Ctx> for OpaqueTerm
where
    EqualityTerm: EncryptFrom<S, StackCipher<K>, Ctx>,
{
    fn encrypt_from<'a>(
        source: &'a S,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        EqualityTerm::encrypt_from(source, cipher, context).map(OpaqueTerm)
    }
}

/// The documented explicit-mode shape: `#[stash(decrypt)]` frees the *other*
/// field types from `Decryptable`, so the paired derive must compile with an
/// opaque field — including the `Decryptable` impl `EncryptFrom` emits.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32)]
struct WithOpaque {
    #[stash(decrypt)]
    c: StackCipherText,
    o: OpaqueTerm,
}

/// And the marked record is decryptable outright, so it still nests in rows.
#[allow(clippy::assertions_on_constants)] // the constant is the point
const _: () = assert!(<WithOpaque as Decryptable>::DECRYPTABLE);

#[tokio::test]
async fn explicit_mode_supports_opaque_fields_in_the_paired_derive() {
    let cipher = stack_cipher().await;
    let generator = stack_cipher().await;

    let record: WithOpaque = 5u32
        .encrypt_into_with_context(&cipher, "opaque")
        .await
        .unwrap();
    let hm: EqualityTerm = 5u32
        .encrypt_into_with_context(&generator, "opaque")
        .await
        .unwrap();
    assert!(record.o == OpaqueTerm(hm));

    let opened: u32 = record.decrypt_into(&cipher, "opaque").await.unwrap();
    assert_eq!(opened, 5);
}

/// A third-party field type that breaks the `DecryptField` contract:
/// `DECRYPTABLE` says decryption opens it, but `decrypt_field` passes it
/// over anyway.
struct Lying;

impl Decryptable for Lying {
    const DECRYPTABLE: bool = true;
}

impl<P, C: DecryptTarget, Ctx> DecryptField<P, C, Ctx> for Lying {
    fn decrypt_field<'a>(self, _cipher: &'a C, _context: Ctx) -> Option<C::Output<'a, P>>
    where
        Self: 'a,
        P: 'a,
    {
        None
    }
}

#[derive(DecryptInto)]
struct LyingRecord {
    l: Lying,
}

#[derive(Debug, PartialEq)]
struct Held {
    value: u32,
}

#[derive(DecryptInto)]
#[stash(plaintext = Held)]
struct LyingRow {
    #[stash(from = value, context = "held/value")]
    value: Lying,
}

#[tokio::test]
async fn a_broken_decrypt_field_contract_is_not_opened_never_a_panic() {
    let cipher = stack_cipher().await;

    // The compile-time check accepted `Lying` (its `DECRYPTABLE` is `true`),
    // so the broken contract only shows at decrypt time: `Error::NotOpened`
    // as a failed pending, for the record and for the row alike.
    let result: Result<u32, _> = LyingRecord { l: Lying }.decrypt_into(&cipher, "l").await;
    assert!(matches!(result, Err(Error::NotOpened)));

    let result: Result<Held, _> = LyingRow { value: Lying }.decrypt_into(&cipher, ()).await;
    assert!(matches!(result, Err(Error::NotOpened)));
}

/// Listed plaintexts: one impl each, and nothing else is accepted.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32, plaintext = String)]
struct EncryptedValue {
    c: StackCipherText,
    hm: EqualityTerm,
}

#[tokio::test]
async fn listed_plaintexts_each_get_their_own_impl() {
    let cipher = stack_cipher().await;

    let number: EncryptedValue = 7u32
        .encrypt_into_with_context(&cipher, "t/n")
        .await
        .unwrap();
    let text: EncryptedValue = "seven"
        .to_string()
        .encrypt_into_with_context(&cipher, "t/t")
        .await
        .unwrap();
    let hm: EqualityTerm = 7u32
        .encrypt_into_with_context(&cipher, "t/n")
        .await
        .unwrap();
    assert_eq!(number.hm, hm);

    let number: u32 = number.decrypt_into(&cipher, "t/n").await.unwrap();
    let text: String = text.decrypt_into(&cipher, "t/t").await.unwrap();
    assert_eq!((number, text.as_str()), (7, "seven"));
}

#[tokio::test]
async fn a_failed_field_fails_the_derived_record_before_any_io() {
    let (cipher, generates, _) = counting_cipher().await;

    // An empty context fails every leaf during the synchronous build; the
    // derived record is the zip of those, so it fails the same way and never
    // mints the data key its ciphertext field would have wanted.
    let result: Result<SearchableText, _> = "alice"
        .to_string()
        .encrypt_into_with_context(&cipher, "")
        .await;
    assert!(matches!(result, Err(Error::EmptyContext)));
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 0);
}

// --- Rows: each field from one field of the plaintext, under its own context

#[derive(Debug, Clone, PartialEq, Eq)]
struct User {
    age: u32,
    email: String,
}

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = User)]
struct EncryptedUser {
    /// A record inside a row: recursion, not a second mechanism.
    #[stash(from = age, context = "users/age")]
    age: EncryptedAge,
    #[stash(from = email, context = "users/email")]
    email: StackCipherText,
    /// A second field from the same plaintext field — a term alongside the
    /// ciphertext, not opened on decrypt.
    #[stash(from = email, context = "users/email")]
    email_eq: EqualityTerm,
    /// Not derived: filled in, never encrypted.
    #[stash(default = 3)]
    version: u8,
}

fn user() -> User {
    User {
        age: 42,
        email: "alice@example.com".to_string(),
    }
}

#[tokio::test]
async fn a_row_is_one_batched_call_and_rebuilds_its_plaintext() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let generator = stack_cipher().await;

    // Every field has its own context, so the row needs none from the
    // caller: the context-free forms are the whole call, both ways.
    let row: EncryptedUser = user().encrypt_into(&cipher).await.unwrap();
    assert_eq!(
        generates.load(AtomicOrdering::SeqCst),
        1,
        "a two-ciphertext row must be ONE generate_keys call"
    );
    assert_eq!(row.version, 3);

    // Each field's terms are what a query site derives under the column's
    // literal context.
    let age_hm: EqualityTerm = 42u32
        .encrypt_into_with_context(&generator, "users/age")
        .await
        .unwrap();
    assert_eq!(row.age.hm, age_hm);
    let email_hm: EqualityTerm = user()
        .email
        .encrypt_into_with_context(&generator, "users/email")
        .await
        .unwrap();
    assert_eq!(row.email_eq, email_hm);

    // Decryption rebuilds the plaintext field by field: one batched call.
    let recovered = User::decrypt_from(row, &cipher).await.unwrap();
    assert_eq!(recovered, user());
    assert_eq!(
        retrieves.load(AtomicOrdering::SeqCst),
        1,
        "opening a two-ciphertext row must be ONE retrieve_keys call"
    );
}

#[tokio::test]
async fn a_column_of_rows_is_still_one_call_each_way() {
    let (cipher, generates, retrieves) = counting_cipher().await;

    let users: Vec<User> = (0..4)
        .map(|i| User {
            age: 30 + i,
            email: format!("user{i}@example.com"),
        })
        .collect();

    let rows: Vec<EncryptedUser> = users.encrypt_into(&cipher).await.unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 1);

    let recovered = Vec::<User>::decrypt_from(rows, &cipher).await.unwrap();
    assert_eq!(recovered, users);
    assert_eq!(retrieves.load(AtomicOrdering::SeqCst), 1);
}

#[tokio::test]
async fn a_row_field_opened_under_the_wrong_context_fails() {
    let cipher = stack_cipher().await;

    let row: EncryptedUser = user().encrypt_into(&cipher).await.unwrap();
    // The literal contexts are baked into the impl, so a transplanted field
    // is caught by the AAD exactly as for a leaf.
    let transplanted: Result<u32, _> = row.age.c.decrypt_into(&cipher, "users/height").await;
    assert!(matches!(transplanted, Err(Error::Aead)));
}

/// A row inside a row. The inner row carries its own contexts, so the outer
/// field needs no `context` of its own: a `from` field with none is handed
/// `()`, which is exactly what a row accepts — and the outer row stays
/// context-free too.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Account {
    user: User,
    plan: String,
}

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = Account)]
struct EncryptedAccount {
    #[stash(from = user)]
    user: EncryptedUser,
    #[stash(from = plan, context = "accounts/plan")]
    plan: StackCipherText,
}

#[tokio::test]
async fn a_row_nests_in_a_row_without_a_context() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let generator = stack_cipher().await;

    let account = Account {
        user: user(),
        plan: "pro".to_string(),
    };
    let row: EncryptedAccount = account.encrypt_into(&cipher).await.unwrap();
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 1);

    // The inner row's fields are still under their own literals.
    let age_hm: EqualityTerm = 42u32
        .encrypt_into_with_context(&generator, "users/age")
        .await
        .unwrap();
    assert_eq!(row.user.age.hm, age_hm);

    let recovered = Account::decrypt_from(row, &cipher).await.unwrap();
    assert_eq!(recovered, account);
    assert_eq!(retrieves.load(AtomicOrdering::SeqCst), 1);
}

/// A tuple-struct plaintext is reached by index: `from = 0`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reading(u32, String);

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = Reading)]
struct EncryptedReading {
    #[stash(from = 0, context = "readings/value")]
    value: EncryptedAge,
    #[stash(from = 1, context = "readings/unit")]
    unit: StackCipherText,
}

#[tokio::test]
async fn a_tuple_plaintext_row_is_reached_and_rebuilt_by_index() {
    let cipher = stack_cipher().await;
    let generator = stack_cipher().await;

    let reading = Reading(21, "celsius".into());
    let row: EncryptedReading = reading.encrypt_into(&cipher).await.unwrap();

    let hm: EqualityTerm = 21u32
        .encrypt_into_with_context(&generator, "readings/value")
        .await
        .unwrap();
    assert_eq!(row.value.hm, hm);

    let recovered = Reading::decrypt_from(row, &cipher).await.unwrap();
    assert_eq!(recovered, reading);
}
