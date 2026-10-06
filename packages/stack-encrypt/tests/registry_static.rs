//! `StaticKeysetRegistry`: a vendor deployment's keysets, end to end through
//! `StackCipher`.
//!
//! Each keyset is served the way a vendor keyset is: a data key source bound
//! to one backend key, wrapped in `FixedIndexKeySource` with the `KeyId` of
//! an index key provisioned once. `FakeKeyProvider` stands in for the vendor
//! source. It binds each key to its descriptor and refuses a key id it did
//! not mint, so the index key here really is the provisioned key.

use stack_encrypt::registry::{
    Binding, FixedIndexKeySource, IndexKeyProvider, KeyId, KeyProvider, ProviderProtected,
    StaticKeyset, StaticKeysetRegistry,
};
use stack_encrypt::{
    nonempty, CipherText, Error, KeysetId, KeysetRegistry, SealedValue, StackCipher,
    StackCipherBuilder, StackCipherText,
};
use uuid::Uuid;
use vitaminc_kms::provider::FakeKeyProvider;
use vitaminc_protected_kms::Controlled;

type Source = FixedIndexKeySource<FakeKeyProvider<32>>;

const MAIN: Uuid = Uuid::from_u128(0x0a);
const ACME: Uuid = Uuid::from_u128(0x0b);

/// A vendor keyset as a deployment configures it: the source, and the
/// `KeyId` of the index key it provisioned once.
async fn provisioned(seed: u8) -> (Source, KeyId) {
    // The fake's own index key is never used: `FixedIndexKeySource` asks the
    // source for the provisioned key instead.
    let source = FakeKeyProvider::with_index_key(ProviderProtected::new([seed; 32]));
    let index_key_id = source
        .generate_keys(&[Binding::EMPTY])
        .await
        .expect("mint the index key")
        .remove(0)
        .key_id;
    (
        FixedIndexKeySource::new(source, index_key_id.clone()),
        index_key_id,
    )
}

async fn cipher() -> StackCipher<StaticKeysetRegistry<Source>> {
    let (main, _) = provisioned(1).await;
    let (acme, _) = provisioned(2).await;
    let registry = StaticKeysetRegistry::new(StaticKeyset::new(MAIN, main).named("main"))
        .with_keyset(StaticKeyset::new(ACME, acme).named("acme"))
        .expect("distinct ids and names");
    StackCipherBuilder::new()
        .registry(registry)
        .init()
        .await
        .expect("build cipher")
}

/// The index key a keyset serves is the key its source minted for the
/// provisioned `KeyId`, retrieved under the empty binding, and the shared
/// provider the registry hands out serves that same key.
#[tokio::test]
async fn the_index_key_is_the_provisioned_key() {
    let (source, index_key_id) = provisioned(1).await;
    let minted = source
        .retrieve_keys(&[(index_key_id, Binding::EMPTY)])
        .await
        .expect("the source minted it")
        .remove(0);

    let registry = StaticKeysetRegistry::new(StaticKeyset::new(MAIN, source));
    let resolved = registry
        .resolve(&MAIN.into())
        .await
        .expect("infallible")
        .expect("known");
    let served = resolved.provider.load_index_key().await.expect("index key");
    assert_eq!(served.0.risky_unwrap(), minted.risky_unwrap());
    let _: &Source = resolved.provider.inner();
}

/// A value sealed under a keyset selected by name opens again, and the leaf
/// names the keyset by its id.
#[tokio::test]
async fn a_value_round_trips_under_each_keyset() {
    let cipher = cipher().await;

    for (selector, id) in [("main", MAIN), ("acme", ACME)] {
        let keyset = cipher.keyset(selector).await.expect("known keyset");
        assert_eq!(keyset.keyset_id(), KeysetId::new(id));
        let sealed: StackCipherText = keyset
            .encrypt("hello".to_string(), nonempty!("greeting"))
            .await
            .expect("seal");
        let CipherText::Single(leaf) = &sealed else {
            panic!("a scalar seals to one leaf");
        };
        assert_eq!(leaf.keyset_id(), KeysetId::new(id));

        let opened: String = cipher
            .decrypt(sealed, nonempty!("greeting"))
            .await
            .expect("open");
        assert_eq!(opened, "hello");
    }

    let by_default: StackCipherText = cipher
        .default_keyset()
        .encrypt(7u32, nonempty!("count"))
        .await
        .expect("seal");
    let opened: u32 = cipher
        .keyset(KeysetId::new(MAIN))
        .await
        .expect("known by id")
        .decrypt(by_default, nonempty!("count"))
        .await
        .expect("the default keyset is MAIN");
    assert_eq!(opened, 7);
}

/// Two keysets have two index keys. One shared index key would make every
/// keyset's terms comparable with every other's.
#[tokio::test]
async fn each_keyset_serves_its_own_index_key() {
    let cipher = cipher().await;
    let registry = cipher.registry();
    let mut keys = Vec::new();
    for selector in ["main", "acme"] {
        let resolved = registry
            .resolve(&selector.into())
            .await
            .expect("infallible")
            .expect("known");
        let key = resolved.provider.load_index_key().await.expect("index key");
        keys.push(key.0.risky_unwrap());
    }
    assert_ne!(keys[0], keys[1]);
}

/// A keyset the table does not hold is the registry's own "no", which the
/// cipher reports as `UnknownKeyset`.
#[tokio::test]
async fn an_unknown_keyset_is_refused() {
    let cipher = cipher().await;
    for selector in [
        stack_encrypt::KeysetRef::from("other"),
        stack_encrypt::KeysetRef::from(Uuid::from_u128(0x0c)),
    ] {
        let refused = cipher.keyset(selector).await.map(|_| ());
        assert!(
            matches!(refused, Err(Error::UnknownKeyset { .. })),
            "{refused:?}"
        );
    }
}

/// `"alice@example.com"`, sealed by stack-encrypt 0.2 in the format-1 layout
/// under keyset `5e7f0000-0000-4000-8000-000000000001` (the fixture in
/// `tests/format_v1.rs`).
const EMAIL_V1: &str = "015e7f000000004000800000000000000101010101010101010101010101010101100076312d666978747572652d7461672d310153767116f8f0c7450ebd6cf71a4afd93d9d7d037b51a48c3ab9d68480cf3ba4dc5d6a986ccbafb60d629baf402";
const V1_KEYSET: Uuid = Uuid::from_u128(0x5e7f_0000_0000_4000_8000_0000_0000_0001);

/// Only ZeroKMS wrote format-1 leaves, so a vendor registry refuses one with
/// the error that says why, even when it holds a keyset with that id.
#[tokio::test]
async fn a_format_1_leaf_is_refused() {
    let (main, _) = provisioned(1).await;
    let (v1, _) = provisioned(3).await;
    let registry = StaticKeysetRegistry::new(StaticKeyset::new(MAIN, main))
        .with_keyset(StaticKeyset::new(V1_KEYSET, v1))
        .expect("distinct ids");
    let cipher = StackCipherBuilder::new()
        .registry(registry)
        .init()
        .await
        .expect("build cipher");

    let bytes: Vec<u8> = (0..EMAIL_V1.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&EMAIL_V1[i..i + 2], 16).expect("hex"))
        .collect();
    let leaf = SealedValue::from_bytes(&bytes).expect("a format-1 leaf parses");
    let opened: Result<String, _> = cipher
        .decrypt(CipherText::Single(leaf), "users/email")
        .await;
    assert!(
        matches!(
            opened,
            Err(Error::V1LeafNeedsZeroKms { keyset_id }) if keyset_id == KeysetId::new(V1_KEYSET)
        ),
        "{opened:?}"
    );
}
