//! Tests of the crate's encrypt and decrypt against the engine's typed
//! Rust API. Each side decrypts the other's ciphertexts. So the tests show
//! that the crate writes the engine's bytes.

use stack_encrypt::dynamic::ValueFrame;
use stack_encrypt::kms::DeterministicSource;
use stack_encrypt::StackCipher;

use crate::cipher::{open_in, seal, unseal, Confined, Engine};
use crate::value::OneValue;

const SEED: [u8; 32] = [7; 32];

async fn engine() -> StackCipher<DeterministicSource> {
    StackCipher::builder()
        .kms(DeterministicSource::new(SEED))
        .init()
        .await
        .unwrap()
}

fn one(text: &str) -> OneValue {
    OneValue::new(ValueFrame::of(text).unwrap()).unwrap()
}

/// Encrypts `values` through the crate, with the test keys.
async fn sdk_seal(values: Vec<OneValue>) -> Vec<stack_encrypt::Ciphertext> {
    seal(&engine().await.default_keyset(), values)
        .await
        .unwrap()
}

#[tokio::test]
async fn the_engine_opens_what_the_sdk_sealed() {
    let sealed = sdk_seal(vec![one("from the sdk")]).await.remove(0);
    let stored = stack_encrypt::Ciphertext::from_bytes(&sealed.to_bytes()).unwrap();
    let opened: String = engine()
        .await
        .default_keyset()
        .decrypt(stored)
        .await
        .unwrap();
    assert_eq!(opened, "from the sdk");
}

#[tokio::test]
async fn the_sdk_opens_what_the_engine_sealed() {
    let cipher = engine().await;
    let sealed = cipher
        .default_keyset()
        .encrypt("from the engine".to_owned())
        .await
        .unwrap();
    let opened = unseal(&cipher, vec![sealed]).await.unwrap().remove(0);
    assert_eq!(opened, ValueFrame::of("from the engine").unwrap());
}

#[tokio::test]
async fn an_altered_ciphertext_does_not_open() {
    let mut bytes = sdk_seal(vec![one("intact")]).await.remove(0).to_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let altered = stack_encrypt::Ciphertext::from_bytes(&bytes).unwrap();
    let error = unseal(&engine().await, vec![altered]).await.unwrap_err();
    assert_eq!(error.code, "stack_encrypt::aead");
    assert!(!error.message.contains("intact"));
}

#[tokio::test]
async fn a_ciphertext_of_another_seed_does_not_open() {
    let other = StackCipher::builder()
        .kms(DeterministicSource::new([1; 32]))
        .init()
        .await
        .unwrap();
    let sealed = sdk_seal(vec![one("elsewhere")]).await;
    assert!(unseal(&other, sealed).await.is_err());
}

/// `keyset.decrypt` is confined to its keyset and `cipher.decrypt` is not.
/// The two differ only in the `Confined` they pass to `open_in`.
#[tokio::test]
async fn a_keyset_refuses_another_keysets_ciphertext_and_the_cipher_opens_it() {
    let cipher = engine().await;
    let other = cipher.keyset(stack_encrypt::kms::IdentifiedBy::Name(
        "another-keyset".to_owned().into(),
    ));
    let sealed = seal(&other, vec![one("in another keyset")]).await.unwrap();
    let engine = Engine::Testing(Box::new(cipher));

    let refused = open_in(&engine, sealed.clone(), Confined::ToDefault)
        .await
        .unwrap_err();
    assert_eq!(refused.code, "stack_encrypt::foreign_keyset");

    let opened = open_in(&engine, sealed, Confined::No)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(opened, ValueFrame::of("in another keyset").unwrap());
}
