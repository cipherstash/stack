//! Tests for a target that takes its context from a field of the plaintext,
//! through `Encryption::context_from`.
//!
//! The caller supplies no context. The plaintext contains the context it is
//! stored under, such as the column of a value decrypted from an older
//! format. The target stores the context in the row, so opening the value
//! never needs its plaintext. These tests need no service credentials.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptSource, EncryptTarget, Encryption, NoCallerContext};
use stack_encrypt::{DecryptFrom, EncryptInto, Error, NonEmpty, StackCipherText};
use zeroize::Zeroize;
mod common;

/// A value and the column it belongs to. Records when its value is wiped.
struct Placed {
    column: String,
    value: String,
    wiped: Arc<AtomicBool>,
}
impl Zeroize for Placed {
    // The column is not secret.
    fn zeroize(&mut self) {
        self.value.zeroize();
        self.wiped.store(true, Ordering::SeqCst);
    }
}
fn placed(column: &str, value: &str) -> (Placed, Arc<AtomicBool>) {
    let wiped = Arc::new(AtomicBool::new(false));
    let placed = Placed {
        column: column.to_owned(),
        value: value.to_owned(),
        wiped: wiped.clone(),
    };
    (placed, wiped)
}

/// The stored form: the column in the clear, the ciphertext, and its term.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct Stored {
    #[stash(context_field)]
    column: String,
    c: StackCipherText,
    hm: EqualityTerm,
}

/// `Stored`, encrypted from a `Placed`, under the column in the `Placed`.
struct FromPlaced(Stored);
impl EncryptTarget<Placed> for FromPlaced {
    type ContextInput = NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Placed, Self, K, NoCallerContext> {
        <Stored as EncryptTarget<String>>::encryption()
            .project(|placed: &Placed| &placed.value)
            .context_from(|placed: &Placed| &placed.column)
            .map(FromPlaced)
    }
}

fn column(name: &str) -> NonEmpty<String> {
    NonEmpty::new(name.to_owned()).unwrap()
}

#[tokio::test]
async fn the_value_is_stored_under_the_column_it_carries() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();

    let (source, wiped) = placed("users/email", "ada@example.com");
    let FromPlaced(stored) = source.encrypt_into(&keyset).await.unwrap();
    assert!(wiped.load(Ordering::SeqCst), "the plaintext is wiped");
    assert_eq!(stored.column, "users/email", "the column is stored");

    let direct: Stored = "ada@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, column("users/email"))
        .await
        .unwrap();
    assert_eq!(stored.hm, direct.hm, "the same term as passing the column");

    // The value opens from the row alone, and under the column the row names.
    let opened = String::decrypt_from_with_context(stored, &keyset, column("users/email"))
        .await
        .unwrap();
    assert_eq!(opened, "ada@example.com");
    let opened = String::decrypt_from(direct, &keyset).await.unwrap();
    assert_eq!(opened, "ada@example.com");
}

#[tokio::test]
async fn another_column_derives_another_term_and_does_not_open_as_the_first() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();

    let (email, _) = placed("users/email", "ada@example.com");
    let (name, _) = placed("users/name", "ada@example.com");
    let FromPlaced(email) = email.encrypt_into(&keyset).await.unwrap();
    let FromPlaced(name) = name.encrypt_into(&keyset).await.unwrap();
    assert_ne!(email.hm, name.hm);

    let result = String::decrypt_from_with_context(name, &keyset, column("users/email")).await;
    assert!(
        matches!(result, Err(Error::ContextMismatch { .. })),
        "{:?}",
        result.err()
    );
}

#[tokio::test]
async fn an_empty_column_is_refused_before_any_key_is_requested() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();

    let (source, wiped) = placed("", "ada@example.com");
    let result = source.encrypt_into::<FromPlaced, _>(&keyset).await;
    assert!(matches!(result, Err(Error::Other(_))));
    assert_eq!(generates.load(Ordering::SeqCst), 0, "no key was requested");
    assert!(
        wiped.load(Ordering::SeqCst),
        "the refused plaintext is wiped"
    );
}

// Each row has its own column. The rows are encrypted in one batch.
#[tokio::test]
async fn each_row_of_a_column_is_sealed_under_its_own_column() {
    let (cipher, sent) = common::recording_cipher().await;
    let keyset = cipher.default_keyset();

    let rows: Vec<FromPlaced> = vec![
        placed("email", "ada@example.com").0,
        placed("name", "Ada").0,
    ]
    .encrypt_into(&keyset)
    .await
    .unwrap();
    let sent = sent.lock().unwrap().clone();
    assert_eq!(sent.generate.len(), 1, "one batch");
    assert_eq!(sent.generated(), ["email", "name"]);

    let columns: Vec<&str> = rows.iter().map(|FromPlaced(s)| s.column.as_str()).collect();
    assert_eq!(columns, ["email", "name"]);
}

#[tokio::test]
async fn one_row_with_an_empty_column_refuses_the_whole_column() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();

    let (first, first_wiped) = placed("users/email", "ada@example.com");
    let (second, second_wiped) = placed("", "Ada");
    let result = vec![first, second]
        .encrypt_into::<Vec<FromPlaced>, _>(&keyset)
        .await;
    assert!(matches!(result, Err(Error::Other(_))));
    assert_eq!(generates.load(Ordering::SeqCst), 0, "no key was requested");
    assert!(first_wiped.load(Ordering::SeqCst) && second_wiped.load(Ordering::SeqCst));
}
