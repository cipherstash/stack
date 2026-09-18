//! End-to-end encrypt/decrypt tests for `StackCipher` against the in-memory
//! `FakeDataKeySource` — no ZeroKMS credentials or network required. The fake
//! hands out random key material and remembers it by `(iv, tag)`, so
//! generate → retrieve round-trips within a test but nothing is reproducible
//! across processes.

use std::collections::HashMap;

use stack_encrypt::{CipherText, ContextTag, Element, SealedValue, StackCipher};
use stack_kms::FakeDataKeySource;
use vitaminc_protected::{Controlled, Protected};

async fn cipher() -> StackCipher<FakeDataKeySource> {
    StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await
        .expect("build cipher")
}

#[tokio::test]
async fn scalar_roundtrips_with_no_aad() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt("hello world".to_string(), ())
        .await
        .expect("encrypt");
    let pt: String = cipher.decrypt(ct, ()).await.expect("decrypt");
    assert_eq!(pt, "hello world");
}

#[tokio::test]
async fn scalar_roundtrips_with_matching_aad() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let aad = b"public-context".as_slice();
    let ct = keyset
        .encrypt("secret".to_string(), aad)
        .await
        .expect("encrypt");
    let pt: String = cipher.decrypt(ct, aad).await.expect("decrypt");
    assert_eq!(pt, "secret");
}

#[tokio::test]
async fn decrypt_fails_with_wrong_aad() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt("secret".to_string(), b"aad-a".as_slice())
        .await
        .expect("encrypt");
    let result: Result<String, _> = cipher.decrypt(ct, b"aad-b".as_slice()).await;
    assert!(result.is_err(), "mismatched AAD must not decrypt");
}

#[tokio::test]
async fn decrypt_fails_when_aad_omitted() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt("secret".to_string(), b"bound".as_slice())
        .await
        .expect("encrypt");
    // The leaf bound the PAE-encoded tuple `(aad, tag)`; dropping the caller
    // AAD changes the encoding.
    let result: Result<String, _> = cipher.decrypt(ct, ()).await;
    assert!(result.is_err(), "omitting the bound AAD must not decrypt");
}

#[tokio::test]
async fn vec_roundtrips() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let items = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let ct = keyset.encrypt(items.clone(), ()).await.expect("encrypt");
    let pt: Vec<String> = cipher.decrypt(ct, ()).await.expect("decrypt");
    assert_eq!(pt, items);
}

#[tokio::test]
async fn map_roundtrips() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    // Encrypt side keys are `&'static str`; decrypt side yields `String` keys.
    let mut input: HashMap<&'static str, String> = HashMap::new();
    input.insert("name", "alice".to_string());
    input.insert("role", "admin".to_string());

    let ct = keyset.encrypt(input, ()).await.expect("encrypt");
    let pt: HashMap<String, String> = cipher.decrypt(ct, ()).await.expect("decrypt");

    assert_eq!(pt.get("name"), Some(&"alice".to_string()));
    assert_eq!(pt.get("role"), Some(&"admin".to_string()));
    assert_eq!(pt.len(), 2);
}

#[tokio::test]
async fn option_some_roundtrips() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt(Some("present".to_string()), ())
        .await
        .expect("encrypt");
    let pt: Option<String> = cipher.decrypt(ct, ()).await.expect("decrypt");
    assert_eq!(pt, Some("present".to_string()));
}

#[tokio::test]
async fn option_none_roundtrips() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
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
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let secret = Protected::new("classified".to_string());
    let ct = keyset.encrypt(secret, ()).await.expect("encrypt");
    let pt: Protected<String> = cipher.decrypt(ct, ()).await.expect("decrypt");
    assert_eq!(pt.risky_unwrap(), "classified".to_string());
}

#[tokio::test]
async fn nested_vec_roundtrips() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let nested = vec![
        vec!["a".to_string(), "b".to_string()],
        vec!["c".to_string()],
    ];
    let ct = keyset.encrypt(nested.clone(), ()).await.expect("encrypt");
    let pt: Vec<Vec<String>> = cipher.decrypt(ct, ()).await.expect("decrypt");
    assert_eq!(pt, nested);
}

#[tokio::test]
async fn context_tag_binds_and_roundtrips() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
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
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt(ContextTag::new("token".to_string(), "user:42"), ())
        .await
        .expect("encrypt");

    let result: Result<String, _> = cipher.decrypt(ct, ContextTag::aad("user:99")).await;
    assert!(result.is_err(), "wrong context tag must not decrypt");
}

#[tokio::test]
async fn empty_vec_roundtrips() {
    // An empty sequence seals an authenticated marker, so emptiness is provable.
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt(Vec::<String>::new(), ())
        .await
        .expect("encrypt");
    let pt: Vec<String> = cipher.decrypt(ct, ()).await.expect("decrypt");
    assert!(pt.is_empty());
}

#[tokio::test]
async fn empty_map_roundtrips() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt(HashMap::<&'static str, String>::new(), ())
        .await
        .expect("encrypt");
    let pt: HashMap<String, String> = cipher.decrypt(ct, ()).await.expect("decrypt");
    assert!(pt.is_empty());
}

#[tokio::test]
async fn empty_marker_does_not_decode_under_wrong_aad() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt(Vec::<String>::new(), b"bound".as_slice())
        .await
        .expect("encrypt");
    let result: Result<Vec<String>, _> = cipher.decrypt(ct, ()).await;
    assert!(result.is_err(), "empty marker must authenticate its AAD");
}

#[tokio::test]
async fn renamed_map_key_fails() {
    // Map keys travel in the clear but are bound into their value's AAD, so
    // renaming a key in the stored ciphertext must fail decryption.
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let mut input: HashMap<&'static str, String> = HashMap::new();
    input.insert("name", "alice".to_string());

    let ct = keyset.encrypt(input, ()).await.expect("encrypt");
    let tampered = match ct {
        CipherText::Map(entries) => CipherText::Map(
            entries
                .into_iter()
                .map(|(_, v)| ("role".to_string(), v))
                .collect(),
        ),
        other => other,
    };

    let result: Result<HashMap<String, String>, _> = cipher.decrypt(tampered, ()).await;
    assert!(result.is_err(), "renamed map key must not decrypt");
}

#[tokio::test]
async fn sequence_element_cannot_be_rehomed_as_scalar() {
    // Elements are sealed under the `for_sequence_element` derivation, so a
    // leaf spliced out of a sequence must not verify as a top-level scalar.
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt(vec!["a".to_string()], ())
        .await
        .expect("encrypt");
    let element = match ct {
        CipherText::Sequence(mut items) => items.remove(0),
        other => other,
    };

    let result: Result<String, _> = cipher.decrypt(element, ()).await;
    assert!(
        result.is_err(),
        "re-homed sequence element must not decrypt"
    );
}

#[tokio::test]
async fn element_roundtrips_under_bare_caller_aad() {
    // `Element<T>` derives `for_sequence_element` inside its own Encrypt/Decrypt
    // impls. Both sides must honour that derivation: the decipher opens the leaf
    // under the AAD the Decrypt drive supplies, not a pre-derived one.
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt(Element("row".to_string()), b"users".as_slice())
        .await
        .expect("encrypt");
    let pt: Element<String> = cipher
        .decrypt(ct, b"users".as_slice())
        .await
        .expect("Element must round-trip under the bare caller AAD");
    assert_eq!(pt.into_inner(), "row");
}

#[tokio::test]
async fn element_interchanges_with_vec_element() {
    // A row sealed as one element of a `Vec` decrypts alone as `Element<T>`
    // under the same caller AAD (Element's documented use-case), and a lone
    // `Element` ciphertext decrypts as a one-element `Vec`.
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let aad = b"users".as_slice();

    let ct = keyset
        .encrypt(vec!["a".to_string(), "b".to_string()], aad)
        .await
        .expect("encrypt");
    let second = match ct {
        CipherText::Sequence(mut items) => items.remove(1),
        other => other,
    };
    let pt: Element<String> = cipher
        .decrypt(second, aad)
        .await
        .expect("spliced element must decrypt as Element");
    assert_eq!(pt.into_inner(), "b");

    let lone = keyset
        .encrypt(Element("c".to_string()), aad)
        .await
        .expect("encrypt");
    let wrapped = CipherText::Sequence(vec![lone]);
    let pt: Vec<String> = cipher
        .decrypt(wrapped, aad)
        .await
        .expect("lone Element must decrypt as a one-element Vec");
    assert_eq!(pt, vec!["c".to_string()]);
}

#[tokio::test]
async fn element_fails_under_wrong_caller_aad() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt(Element("row".to_string()), b"users".as_slice())
        .await
        .expect("encrypt");
    let result: Result<Element<String>, _> = cipher.decrypt(ct, b"orders".as_slice()).await;
    assert!(
        result.is_err(),
        "Element under the wrong caller AAD must not decrypt"
    );
}

/// The derivation that binds a sequence element to its position is the
/// library's, applied by `Element<T>` itself — there is no entry point that
/// lets a caller retrieve keys under one context and authenticate under
/// another, so a batched row is read back by naming the type, not by
/// reconstructing the AAD.
#[tokio::test]
async fn a_batched_element_opens_by_naming_the_type() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt(Element("row".to_string()), b"users".as_slice())
        .await
        .expect("encrypt");
    let opened: Element<String> = cipher
        .decrypt(ct, b"users".as_slice())
        .await
        .expect("Element applies its own derivation on open");
    assert_eq!(opened.into_inner(), "row");
}

#[tokio::test]
async fn wrong_shape_fails() {
    // A scalar ciphertext must not decode as a sequence.
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt("scalar".to_string(), ())
        .await
        .expect("encrypt");
    let result: Result<Vec<String>, _> = cipher.decrypt(ct, ()).await;
    assert!(result.is_err(), "scalar must not decode as a Vec");
}

#[tokio::test]
async fn leaf_survives_persistence_via_parts() {
    // A leaf can be decomposed into (keyset_id, iv, tag, ciphertext), stored,
    // and rebuilt
    // — the in-memory original need not be retained to decrypt.
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt("durable".to_string(), b"ctx".as_slice())
        .await
        .expect("encrypt");
    let leaf = match ct {
        CipherText::Single(leaf) => leaf,
        other => panic!("expected a Single leaf, got {other:?}"),
    };
    let (keyset_id, iv, tag, bytes) = leaf.into_parts();
    let rebuilt = SealedValue::from_parts(keyset_id, iv, tag, bytes).expect("rebuild leaf");

    let pt: String = cipher
        .decrypt(CipherText::Single(rebuilt), b"ctx".as_slice())
        .await
        .expect("rebuilt leaf must decrypt");
    assert_eq!(pt, "durable");
}

#[tokio::test]
async fn leaf_survives_persistence_via_serde() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt("durable".to_string(), ())
        .await
        .expect("encrypt");
    let leaf = match ct {
        CipherText::Single(leaf) => leaf,
        other => panic!("expected a Single leaf, got {other:?}"),
    };
    let json = serde_json::to_string(&leaf).expect("serialise leaf");
    let restored: SealedValue = serde_json::from_str(&json).expect("deserialise leaf");
    assert_eq!(restored.keyset_id(), leaf.keyset_id());
    assert_eq!(restored.iv(), leaf.iv());
    assert_eq!(restored.tag(), leaf.tag());
    assert_eq!(restored.ciphertext(), leaf.ciphertext());

    let pt: String = cipher
        .decrypt(CipherText::Single(restored), ())
        .await
        .expect("restored leaf must decrypt");
    assert_eq!(pt, "durable");
}

#[tokio::test]
async fn tampered_leaf_bytes_fail() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt("durable".to_string(), ())
        .await
        .expect("encrypt");
    let leaf = match ct {
        CipherText::Single(leaf) => leaf,
        other => panic!("expected a Single leaf, got {other:?}"),
    };
    let (keyset_id, iv, tag, mut bytes) = leaf.into_parts();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let tampered = SealedValue::from_parts(keyset_id, iv, tag, bytes).expect("rebuild leaf");

    let result: Result<String, _> = cipher.decrypt(CipherText::Single(tampered), ()).await;
    assert!(result.is_err(), "a flipped ciphertext bit must not decrypt");
}
