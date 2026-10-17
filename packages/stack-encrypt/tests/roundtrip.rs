//! End-to-end encrypt/decrypt tests for `StackCipher` against the in-memory
//! `FakeDataKeySource` — no ZeroKMS credentials or network required. The fake
//! hands out random key material and remembers it by `(iv, tag)`, so
//! generate → retrieve round-trips within a test but nothing is reproducible
//! across processes.

use std::collections::HashMap;

use stack_encrypt::{CipherText, ContextTag, Encrypt, PassthroughFrame, SealedValue, StackCipher};
use stack_kms::FakeDataKeySource;
use vitaminc_aead::plaintext::{MapSink, Sink};
use vitaminc_aead::Decrypt;
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
    // Exercises the `Protected` Decrypt impl, which builds the value inside
    // the wrapper.
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

/// The context a `ContextTag` binds is an AAD like any other: a value
/// sealed under `ContextTag::aad(tag)` opens under the same, and only the
/// same, tag.
#[tokio::test]
async fn context_tag_binds_and_roundtrips() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt("token".to_string(), ContextTag::aad("user:42"))
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
        .encrypt("token".to_string(), ContextTag::aad("user:42"))
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

/// A hand-written record carrying one field in the clear, through the
/// sink's passthrough.
struct Row {
    id: u32,
    email: String,
    repeat_id: bool,
}

impl Row {
    fn once() -> Self {
        Self {
            id: 7,
            email: "a@x".to_string(),
            repeat_id: false,
        }
    }

    fn with_duplicate_id() -> Self {
        Self {
            repeat_id: true,
            ..Self::once()
        }
    }
}

impl Encrypt for Row {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        let mut map = sink.map(None)?;
        map.entry("id")?.passthrough(self.id)?;
        if self.repeat_id {
            map.entry("id")?.passthrough(self.id)?;
        }
        self.email.visit(map.entry("email")?)?;
        map.end()
    }
}

/// A passthrough payload: the frame of `value`, in the clear.
fn clear(value: u32) -> PassthroughFrame {
    PassthroughFrame(
        vitaminc_aead::to_frame(value)
            .expect("a u32 frames")
            .risky_unwrap(),
    )
}

/// A passthrough entry lands in the map as given, beside the sealed ones;
/// a key given twice is refused like any repeated map key, since a map the
/// cipher would refuse to open must never be produced.
#[tokio::test]
async fn a_passthrough_map_entry_is_stored_in_the_clear_once() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset.encrypt(Row::once(), ()).await.expect("encrypt");
    let CipherText::Map(entries) = ct else {
        panic!("a record encrypts as a map: {ct:?}");
    };
    let entry = |name: &str| entries.iter().find(|(key, _)| key == name).map(|(_, v)| v);
    let Some(CipherText::Passthrough(id)) = entry("id") else {
        panic!("the id rides in the clear: {entries:?}");
    };
    let id = id
        .parse()
        .expect("one frame")
        .visit(u32::sink())
        .expect("a u32");
    assert_eq!(id, 7, "the passthrough carries the value as given");
    assert!(
        matches!(entry("email"), Some(CipherText::Single(_))),
        "{entries:?}"
    );

    let result = keyset.encrypt(Row::with_duplicate_id(), ()).await;
    assert!(result.is_err(), "a passthrough key given twice is refused");
}

/// A container is authenticated by the sealed nodes inside it, so one with
/// none — no entries at all, or only passthroughs, which carry no tag —
/// would verify under *any* AAD. The encrypt side never produces one
/// (emptiness is the authenticated `Empty*` marker); the decrypt side must
/// refuse to open one, on the tree's shape, before any sink sees it.
#[tokio::test]
async fn a_container_with_nothing_sealed_in_it_does_not_open() {
    let cipher = cipher().await;
    let aad = b"users".as_slice();

    let result: Result<Vec<String>, _> = cipher.decrypt(CipherText::Sequence(vec![]), aad).await;
    assert!(result.is_err(), "an entry-less sequence proves nothing");
    let result: Result<HashMap<String, String>, _> =
        cipher.decrypt(CipherText::Map(vec![]), aad).await;
    assert!(result.is_err(), "an entry-less map proves nothing");

    let result: Result<Vec<u32>, _> = cipher
        .decrypt(
            CipherText::Sequence(vec![
                CipherText::Passthrough(clear(1)),
                CipherText::Passthrough(clear(2)),
            ]),
            aad,
        )
        .await;
    assert!(
        result.is_err(),
        "an all-passthrough sequence proves nothing"
    );
    let result: Result<HashMap<String, u32>, _> = cipher
        .decrypt(
            CipherText::Map(vec![("id".to_string(), CipherText::Passthrough(clear(1)))]),
            aad,
        )
        .await;
    assert!(result.is_err(), "an all-passthrough map proves nothing");
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
