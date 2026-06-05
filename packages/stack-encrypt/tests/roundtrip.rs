//! End-to-end encrypt/decrypt tests for `ZeroKmsCipher` against the deterministic
//! `FakeDataKeySource` — no ZeroKMS credentials or network required.

use std::collections::HashMap;

use stack_encrypt::{ContextTag, ZeroKmsCipher};
use stack_kms::FakeDataKeySource;
use vitaminc_protected::{Controlled, Protected};

fn cipher() -> ZeroKmsCipher<FakeDataKeySource> {
    ZeroKmsCipher::new(FakeDataKeySource::new())
}

#[tokio::test]
async fn scalar_roundtrips_with_no_aad() {
    let cipher = cipher();
    let ct = cipher
        .encrypt("hello world".to_string(), ())
        .await
        .expect("encrypt");
    let pt: String = cipher.decrypt(ct, ()).await.expect("decrypt");
    assert_eq!(pt, "hello world");
}

#[tokio::test]
async fn scalar_roundtrips_with_matching_aad() {
    let cipher = cipher();
    let aad = b"public-context".as_slice();
    let ct = cipher
        .encrypt("secret".to_string(), aad)
        .await
        .expect("encrypt");
    let pt: String = cipher.decrypt(ct, aad).await.expect("decrypt");
    assert_eq!(pt, "secret");
}

#[tokio::test]
async fn decrypt_fails_with_wrong_aad() {
    let cipher = cipher();
    let ct = cipher
        .encrypt("secret".to_string(), b"aad-a".as_slice())
        .await
        .expect("encrypt");
    let result: Result<String, _> = cipher.decrypt(ct, b"aad-b".as_slice()).await;
    assert!(result.is_err(), "mismatched AAD must not decrypt");
}

#[tokio::test]
async fn decrypt_fails_when_aad_omitted() {
    let cipher = cipher();
    let ct = cipher
        .encrypt("secret".to_string(), b"bound".as_slice())
        .await
        .expect("encrypt");
    // The leaf bound `aad || tag`; dropping the caller AAD changes the bytes.
    let result: Result<String, _> = cipher.decrypt(ct, ()).await;
    assert!(result.is_err(), "omitting the bound AAD must not decrypt");
}

#[tokio::test]
async fn vec_roundtrips() {
    let cipher = cipher();
    let items = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let ct = cipher.encrypt(items.clone(), ()).await.expect("encrypt");
    let pt: Vec<String> = cipher.decrypt(ct, ()).await.expect("decrypt");
    assert_eq!(pt, items);
}

#[tokio::test]
async fn map_roundtrips() {
    let cipher = cipher();
    // Encrypt side keys are `&'static str`; decrypt side yields `String` keys.
    let mut input: HashMap<&'static str, String> = HashMap::new();
    input.insert("name", "alice".to_string());
    input.insert("role", "admin".to_string());

    let ct = cipher.encrypt(input, ()).await.expect("encrypt");
    let pt: HashMap<String, String> = cipher.decrypt(ct, ()).await.expect("decrypt");

    assert_eq!(pt.get("name"), Some(&"alice".to_string()));
    assert_eq!(pt.get("role"), Some(&"admin".to_string()));
    assert_eq!(pt.len(), 2);
}

#[tokio::test]
async fn option_some_roundtrips() {
    let cipher = cipher();
    let ct = cipher
        .encrypt(Some("present".to_string()), ())
        .await
        .expect("encrypt");
    let pt: Option<String> = cipher.decrypt(ct, ()).await.expect("decrypt");
    assert_eq!(pt, Some("present".to_string()));
}

#[tokio::test]
async fn option_none_roundtrips() {
    let cipher = cipher();
    let ct = cipher
        .encrypt(Option::<String>::None, ())
        .await
        .expect("encrypt");
    let pt: Option<String> = cipher.decrypt(ct, ()).await.expect("decrypt");
    assert_eq!(pt, None);
}

#[tokio::test]
async fn protected_roundtrip() {
    // Exercises the `Protected` Decrypt impl, the sole user of `Decipher::map_ok`.
    // (`Vec<u8>` would encrypt element-wise as a sequence of `u8`, not as bytes,
    // so a string leaf is used here.)
    let cipher = cipher();
    let secret = Protected::new("classified".to_string());
    let ct = cipher.encrypt(secret, ()).await.expect("encrypt");
    let pt: Protected<String> = cipher.decrypt(ct, ()).await.expect("decrypt");
    assert_eq!(pt.risky_unwrap(), "classified".to_string());
}

#[tokio::test]
async fn nested_vec_roundtrips() {
    let cipher = cipher();
    let nested = vec![
        vec!["a".to_string(), "b".to_string()],
        vec!["c".to_string()],
    ];
    let ct = cipher.encrypt(nested.clone(), ()).await.expect("encrypt");
    let pt: Vec<Vec<String>> = cipher.decrypt(ct, ()).await.expect("decrypt");
    assert_eq!(pt, nested);
}

#[tokio::test]
async fn context_tag_binds_and_roundtrips() {
    let cipher = cipher();
    let ct = cipher
        .encrypt(ContextTag::new("token".to_string(), "user:42"), ())
        .await
        .expect("encrypt");

    // Matching context recovers the value.
    let pt: String = cipher
        .decrypt(ct, ContextTag::aad("user:42"))
        .await
        .expect("decrypt");
    assert_eq!(pt, "token");
}

#[tokio::test]
async fn context_tag_wrong_context_fails() {
    let cipher = cipher();
    let ct = cipher
        .encrypt(ContextTag::new("token".to_string(), "user:42"), ())
        .await
        .expect("encrypt");

    let result: Result<String, _> = cipher.decrypt(ct, ContextTag::aad("user:99")).await;
    assert!(result.is_err(), "wrong context tag must not decrypt");
}

#[tokio::test]
async fn wrong_shape_fails() {
    // A scalar ciphertext must not decode as a sequence.
    let cipher = cipher();
    let ct = cipher
        .encrypt("scalar".to_string(), ())
        .await
        .expect("encrypt");
    let result: Result<Vec<String>, _> = cipher.decrypt(ct, ()).await;
    assert!(result.is_err(), "scalar must not decode as a Vec");
}
