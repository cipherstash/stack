//! `#[derive(Encrypted)]` / `#[derive(Decrypted)]`: the derived impls are the
//! hand-written composite in `target.rs`, emitted — same terms, same decrypt
//! mirror, same one-batched-call settlement — plus what only a derive makes
//! cheap: sources listed or left generic, rows derived field by field, and
//! fields that are not derived at all.

mod common;

use std::sync::atomic::Ordering as AtomicOrdering;

use cllw_ore::CllwOreEncrypt;
use common::{counting_cipher, stack_cipher};
use stack_encrypt::sem::{EqualityTerm, MatchTerm, OreTerm};
use stack_encrypt::target::{DecryptExt, EncryptExt};
use stack_encrypt::{Decrypted, Encrypted, Error, StackCipherText};

// --- Records: every field from one source, under one context ----------------

/// The hand-written record in `target.rs`, derived: an encrypted `u32`
/// stored as its ciphertext plus an equality term and an ORE term.
#[derive(Encrypted, Decrypted)]
#[encrypted(source = u32)]
struct EncryptedAge {
    #[encrypted(decrypt)]
    c: StackCipherText,
    hm: EqualityTerm,
    ob: OreTerm<u32>,
}

#[tokio::test]
async fn a_derived_record_is_the_hand_written_one() {
    let cipher = stack_cipher().await;
    let generator = stack_cipher().await;

    let record: EncryptedAge = 42u32.encrypt_into(&cipher, "users/age").await.unwrap();

    // Each term is what the leaf derives on its own, so query terms built
    // leaf-by-leaf find records encrypted as composites.
    let hm: EqualityTerm = 42u32.encrypt_into(&generator, "users/age").await.unwrap();
    let ob: OreTerm<u32> = 42u32.encrypt_into(&generator, "users/age").await.unwrap();
    assert_eq!(record.hm, hm);
    assert_eq!(record.ob, ob);

    // And the decrypt mirror opens the ciphertext field.
    let age: u32 = record.decrypt_into(&cipher, "users/age").await.unwrap();
    assert_eq!(age, 42);
}

/// No `source`: one impl generic over it, accepting whatever every leaf
/// accepts — here any text type, since `MatchTerm` wants `AsRef<str>`.
#[derive(Encrypted)]
struct SearchableText {
    c: StackCipherText,
    hm: EqualityTerm,
    m: MatchTerm,
}

/// Tuple structs assign by index.
#[derive(Encrypted)]
struct Pair(StackCipherText, EqualityTerm);

/// The record's own generics (and their bounds) are carried through, and the
/// where clause makes `Tagged<T>` accept exactly `T` — the ORE term is typed
/// by its source.
#[derive(Encrypted)]
struct Tagged<T: CllwOreEncrypt> {
    c: StackCipherText,
    ob: OreTerm<T>,
}

#[tokio::test]
async fn a_generic_source_record_accepts_what_its_leaves_accept() {
    let cipher = stack_cipher().await;
    let generator = stack_cipher().await;

    let record: SearchableText = "alice"
        .to_string()
        .encrypt_into(&cipher, "users/name")
        .await
        .unwrap();
    let hm: EqualityTerm = "alice"
        .to_string()
        .encrypt_into(&generator, "users/name")
        .await
        .unwrap();
    let m: MatchTerm = "alice"
        .to_string()
        .encrypt_into(&generator, "users/name")
        .await
        .unwrap();
    assert_eq!(record.hm, hm);
    assert_eq!(record.m, m);
    let name: String = record.c.decrypt_into(&cipher, "users/name").await.unwrap();
    assert_eq!(name, "alice");

    let pair: Pair = "bob".encrypt_into(&cipher, "users/name").await.unwrap();
    let hm: EqualityTerm = "bob".encrypt_into(&generator, "users/name").await.unwrap();
    assert_eq!(pair.1, hm);
    let name: String = pair.0.decrypt_into(&cipher, "users/name").await.unwrap();
    assert_eq!(name, "bob");

    let tagged: Tagged<u32> = 7u32.encrypt_into(&cipher, "users/score").await.unwrap();
    let ob: OreTerm<u32> = 7u32.encrypt_into(&generator, "users/score").await.unwrap();
    assert_eq!(tagged.ob, ob);
    let score: u32 = tagged.c.decrypt_into(&cipher, "users/score").await.unwrap();
    assert_eq!(score, 7);
}

/// Listed sources: one impl each, and nothing else is accepted.
#[derive(Encrypted, Decrypted)]
#[encrypted(source = u32, source = String)]
struct EncryptedValue {
    #[encrypted(decrypt)]
    c: StackCipherText,
    hm: EqualityTerm,
}

#[tokio::test]
async fn listed_sources_each_get_their_own_impl() {
    let cipher = stack_cipher().await;

    let number: EncryptedValue = 7u32.encrypt_into(&cipher, "t/n").await.unwrap();
    let text: EncryptedValue = "seven"
        .to_string()
        .encrypt_into(&cipher, "t/t")
        .await
        .unwrap();
    let hm: EqualityTerm = 7u32.encrypt_into(&cipher, "t/n").await.unwrap();
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
    let result: Result<SearchableText, _> = "alice".to_string().encrypt_into(&cipher, "").await;
    assert!(matches!(result, Err(Error::EmptyContext)));
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 0);
}

// --- Rows: each field from one field of the source, under its own context ---

#[derive(Debug, Clone, PartialEq, Eq)]
struct User {
    age: u32,
    email: String,
}

#[derive(Encrypted, Decrypted)]
#[encrypted(source = User)]
struct EncryptedUser {
    /// A record inside a row: recursion, not a second mechanism.
    #[encrypted(from = age, context = "users/age", decrypt)]
    age: EncryptedAge,
    #[encrypted(from = email, context = "users/email", decrypt)]
    email: StackCipherText,
    /// A second field from the same source field — a term alongside the
    /// ciphertext, not opened on decrypt.
    #[encrypted(from = email, context = "users/email")]
    email_eq: EqualityTerm,
    /// Not derived: filled in, never encrypted.
    #[encrypted(default = 3)]
    version: u8,
}

fn user() -> User {
    User {
        age: 42,
        email: "alice@example.com".to_string(),
    }
}

#[tokio::test]
async fn a_row_is_one_batched_call_and_rebuilds_its_source() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let generator = stack_cipher().await;

    // Every field has its own context, so the row's is unused: `()` is fine.
    let row: EncryptedUser = user().encrypt_into(&cipher, ()).await.unwrap();
    assert_eq!(
        generates.load(AtomicOrdering::SeqCst),
        1,
        "a two-ciphertext row must be ONE generate_keys call"
    );
    assert_eq!(row.version, 3);

    // Each field's terms are what a query site derives under the column's
    // literal context.
    let age_hm: EqualityTerm = 42u32.encrypt_into(&generator, "users/age").await.unwrap();
    assert_eq!(row.age.hm, age_hm);
    let email_hm: EqualityTerm = user()
        .email
        .encrypt_into(&generator, "users/email")
        .await
        .unwrap();
    assert_eq!(row.email_eq, email_hm);

    // Decryption rebuilds the source field by field: one batched call.
    let recovered: User = row.decrypt_into(&cipher, ()).await.unwrap();
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

    let rows: Vec<EncryptedUser> = users.encrypt_into(&cipher, ()).await.unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 1);

    let recovered: Vec<User> = rows.decrypt_into(&cipher, ()).await.unwrap();
    assert_eq!(recovered, users);
    assert_eq!(retrieves.load(AtomicOrdering::SeqCst), 1);
}

#[tokio::test]
async fn a_row_field_opened_under_the_wrong_context_fails() {
    let cipher = stack_cipher().await;

    let row: EncryptedUser = user().encrypt_into(&cipher, ()).await.unwrap();
    // The literal contexts are baked into the impl, so a transplanted field
    // is caught by the AAD exactly as for a leaf.
    let transplanted: Result<u32, _> = row.age.c.decrypt_into(&cipher, "users/height").await;
    assert!(matches!(transplanted, Err(Error::Aead)));
}
