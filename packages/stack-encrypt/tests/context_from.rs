//! A target that takes its context from the plaintext it encrypts
//! (`Encryption::context_from`). The caller supplies no context: the
//! plaintext carries the one it is stored under, such as a value decrypted
//! from an older format together with its column. No service credentials are
//! needed.
use std::sync::atomic::Ordering;

use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{EncryptTarget, Encryption, NoCallerContext};
use stack_encrypt::{nonempty, EncryptInto, Error, NonEmpty, StackCipherText};
use zeroize::Zeroize;
mod common;

/// A value and the context it belongs under.
#[derive(Clone)]
struct Placed {
    context: String,
    value: String,
}
impl Zeroize for Placed {
    // The context is not secret.
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}
fn placed(context: &str, value: &str) -> Placed {
    Placed {
        context: context.to_owned(),
        value: value.to_owned(),
    }
}

/// The context `placed` carries, refused if it is empty.
fn context_of<C: From<NonEmpty<String>>>(placed: &Placed) -> Result<C, Error> {
    NonEmpty::new(placed.context.clone())
        .map(C::from)
        .map_err(|e| Error::Other(Box::new(e)))
}

/// An equality term, under the context the value carries.
struct PlacedTerm(EqualityTerm);
impl EncryptTarget<Placed> for PlacedTerm {
    type ContextInput = NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Placed, Self, K, NoCallerContext> {
        <EqualityTerm as EncryptTarget<String>>::encryption()
            .project(|placed: &Placed| &placed.value)
            .context_from(context_of)
            .map(PlacedTerm)
    }
}

/// A ciphertext, sealed under the context the value carries.
struct PlacedCiphertext(StackCipherText);
impl EncryptTarget<Placed> for PlacedCiphertext {
    type ContextInput = NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Placed, Self, K, NoCallerContext> {
        <StackCipherText as EncryptTarget<String>>::encryption()
            .project(|placed: &Placed| &placed.value)
            .context_from(context_of)
            .map(PlacedCiphertext)
    }
}

#[tokio::test]
async fn a_term_is_derived_under_the_context_the_plaintext_carries() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();

    let PlacedTerm(term) = placed("users/email", "ada@example.com")
        .encrypt_into(&keyset)
        .await
        .unwrap();
    let direct: EqualityTerm = "ada@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, nonempty!("users/email"))
        .await
        .unwrap();
    assert_eq!(term, direct, "the same term as passing the context");

    let PlacedTerm(elsewhere) = placed("users/name", "ada@example.com")
        .encrypt_into(&keyset)
        .await
        .unwrap();
    assert_ne!(term, elsewhere, "another context derives another term");
}

#[tokio::test]
async fn a_ciphertext_is_sealed_under_the_context_the_plaintext_carries() {
    let cipher = common::stack_cipher().await;
    let keyset = cipher.default_keyset();

    let seal = || async {
        let PlacedCiphertext(sealed) = placed("users/email", "ada@example.com")
            .encrypt_into(&keyset)
            .await
            .unwrap();
        sealed
    };
    let opened: String = cipher
        .decrypt(seal().await, nonempty!("users/email"))
        .await
        .unwrap();
    assert_eq!(opened, "ada@example.com");
    assert!(matches!(
        cipher
            .decrypt::<String, _>(seal().await, nonempty!("users/name"))
            .await,
        Err(Error::Aead)
    ));
}

#[tokio::test]
async fn a_context_that_cannot_be_read_fails_before_any_key_is_requested() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();

    let result = placed("", "ada@example.com")
        .encrypt_into::<PlacedCiphertext, _>(&keyset)
        .await;
    assert!(matches!(result, Err(Error::Other(_))));
    assert_eq!(generates.load(Ordering::SeqCst), 0, "no key was requested");
}

// Each row carries its own context, and the column still makes one batch.
#[tokio::test]
async fn each_row_of_a_column_is_sealed_under_its_own_context() {
    let (cipher, generates, _) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();

    let column: Vec<PlacedCiphertext> = vec![
        placed("users/email", "ada@example.com"),
        placed("users/name", "Ada"),
    ]
    .encrypt_into(&keyset)
    .await
    .unwrap();
    assert_eq!(generates.load(Ordering::SeqCst), 1, "one batch");

    let [PlacedCiphertext(email), PlacedCiphertext(name)] =
        <[_; 2]>::try_from(column).ok().unwrap();
    let email: String = cipher
        .decrypt(email, nonempty!("users/email"))
        .await
        .unwrap();
    let name: String = cipher.decrypt(name, nonempty!("users/name")).await.unwrap();
    assert_eq!((email.as_str(), name.as_str()), ("ada@example.com", "Ada"));
}
