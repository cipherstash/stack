//! ZeroKMS and one key vendor backend in one cipher, keyset records as
//! config, and the root key TTL in real time.

use std::time::Duration;

use stack_encrypt::kms::{
    BackendErrorKind, Error as KmsError, FakeDataKeySource, IdentifiedBy, KeyMode, KeyVendor,
};
use stack_encrypt::{nonempty, CipherText, Error, SealedValue, StackCipher, StackCipherText};
use stack_kms_vendor::contract::Observed;
use stack_kms_vendor::{
    FakeVendor, KeyRouter, KeysetRecord, RecordError, StaticKeyVendor, VendorKeySource,
};
use uuid::Uuid;
use vitaminc::protected::Protected;

const DERIVED: KeyMode = KeyMode::Derived;

/// The one leaf a string seals as: the v1 leaf, which names its keyset
/// and no key backend.
fn leaf(sealed: &StackCipherText) -> &SealedValue {
    match sealed {
        CipherText::Single(leaf) => leaf,
        _ => panic!("one leaf"),
    }
}

fn keyset_of(sealed: &StackCipherText) -> Uuid {
    let leaf = leaf(sealed);
    assert_eq!(
        leaf.to_bytes().first(),
        Some(&SealedValue::FORMAT_VERSION),
        "every backend seals the v1 leaf"
    );
    leaf.keyset_id()
}

#[tokio::test]
async fn one_cipher_routes_between_zerokms_and_one_vendor() {
    let vendor = FakeVendor::new(KeyVendor::Aws);
    let named = KeysetRecord::create(&vendor, FakeVendor::KEY_REF, DERIVED, Some("acme".into()))
        .await
        .unwrap();
    let unnamed = KeysetRecord::create(&vendor, FakeVendor::KEY_REF, DERIVED, None)
        .await
        .unwrap();
    let texts = [named.to_string(), unnamed.to_string()];
    let source = VendorKeySource::from_texts(vendor, texts.iter().map(String::as_str)).unwrap();
    let cipher = StackCipher::builder()
        .kms(KeyRouter::new(FakeDataKeySource::new(), source))
        .init()
        .await
        .unwrap();
    let context = nonempty!("users").with("email");

    // Naming no keyset is ZeroKMS's default keyset.
    let zerokms = cipher
        .default_keyset()
        .encrypt_tree("z".to_string(), context)
        .await
        .unwrap();
    assert_eq!(keyset_of(&zerokms), cipher.default_keyset().keyset_id());

    // A record's name and id select the vendor.
    let acme = cipher
        .keyset(IdentifiedBy::Name("acme".to_string().into()))
        .await
        .unwrap();
    assert_eq!(acme.keyset_id(), named.id());
    let sealed_named = acme.encrypt_tree("n".to_string(), context).await.unwrap();
    assert_eq!(keyset_of(&sealed_named), named.id());
    let other = cipher.keyset(unnamed.id()).await.unwrap();
    let sealed_unnamed = other.encrypt_tree("u".to_string(), context).await.unwrap();
    assert_eq!(keyset_of(&sealed_unnamed), unnamed.id());
    assert!(leaf(&sealed_unnamed).tag().is_empty());

    // Each leaf opens through the backend that holds its keyset.
    for (sealed, expected) in [(zerokms, "z"), (sealed_named, "n"), (sealed_unnamed, "u")] {
        let opened: String = cipher.decrypt(sealed, context).await.unwrap();
        assert_eq!(opened, expected);
    }

    // A term through a vendor keyset differs from the ZeroKMS keyset's
    // term for the same value.
    let vendor_term = acme.equality_term("x", context).await.unwrap();
    let zerokms_term = cipher
        .default_keyset()
        .equality_term("x", context)
        .await
        .unwrap();
    assert_ne!(vendor_term.as_bytes(), zerokms_term.as_bytes());
}

/// A leaf of a keyset that no loaded record names goes to ZeroKMS, which
/// does not hold it: the leaf does not open, and the vendor gets no call.
#[tokio::test]
async fn a_leaf_of_an_unloaded_vendor_keyset_goes_to_zerokms_and_does_not_open() {
    let vendor = FakeVendor::new(KeyVendor::Vault);
    let record = KeysetRecord::create(&vendor, FakeVendor::KEY_REF, DERIVED, None)
        .await
        .unwrap();
    let sealer = StackCipher::builder()
        .kms(VendorKeySource::new(vendor, [record]).unwrap())
        .init()
        .await
        .unwrap();
    let sealed = sealer
        .default_keyset()
        .encrypt_tree("v".to_string(), b"ctx")
        .await
        .unwrap();

    let (backend, observer) = Observed::new(FakeVendor::new(KeyVendor::Vault));
    let other = KeysetRecord::create(&backend, FakeVendor::KEY_REF, DERIVED, None)
        .await
        .unwrap();
    let cipher = StackCipher::builder()
        .kms(KeyRouter::new(
            FakeDataKeySource::new(),
            VendorKeySource::new(backend, [other]).unwrap(),
        ))
        .init()
        .await
        .unwrap();
    let before = observer.unwraps();
    assert!(
        cipher.decrypt::<String, _>(sealed, b"ctx").await.is_err(),
        "the leaf's keyset is in no loaded record"
    );
    assert_eq!(observer.unwraps(), before, "the vendor got no call");
}

#[tokio::test]
async fn records_of_two_vendors_are_refused() {
    let aws = FakeVendor::new(KeyVendor::Aws);
    let vault = FakeVendor::new(KeyVendor::Vault);
    let a = KeysetRecord::create(&aws, FakeVendor::KEY_REF, DERIVED, None)
        .await
        .unwrap();
    let v = KeysetRecord::create(&vault, FakeVendor::KEY_REF, DERIVED, None)
        .await
        .unwrap();
    match VendorKeySource::new(aws, [a.clone(), v.clone()]) {
        Err(RecordError::SecondVendor { first, second }) => {
            assert_eq!((first, second), (KeyVendor::Aws, KeyVendor::Vault));
        }
        other => panic!("expected SecondVendor, got {other:?}"),
    }
    match VendorKeySource::new(vault, [a]) {
        Err(RecordError::ForeignVendor {
            expected, found, ..
        }) => assert_eq!((expected, found), (KeyVendor::Vault, KeyVendor::Aws)),
        other => panic!("expected ForeignVendor, got {other:?}"),
    }
}

#[tokio::test]
async fn a_record_edited_in_its_bound_fields_does_not_unwrap() {
    let vendor = FakeVendor::new(KeyVendor::Aws);
    let record = KeysetRecord::create(&vendor, FakeVendor::KEY_REF, DERIVED, None)
        .await
        .unwrap();
    let moved = KeysetRecord::from_parts(
        uuid::Uuid::new_v4(),
        None,
        record.vendor(),
        record.mode(),
        record.key_ref().into(),
        record.wrapped_key().to_vec(),
    )
    .unwrap();
    // Init loads the default keyset's index key, which unwraps the root key.
    match StackCipher::builder()
        .kms(VendorKeySource::new(vendor, [moved]).unwrap())
        .init()
        .await
        .map(|_| ())
    {
        Err(Error::Kms(KmsError::Backend {
            kind: BackendErrorKind::InvalidCiphertext,
            ..
        })) => {}
        other => panic!("a record moved to another id must not unwrap, got {other:?}"),
    }
}

/// Seal one value and derive one term under `record`, rewrap the record to
/// `new_ref`, and check the old value opens and the term is the same.
async fn rewrap_keeps_old_values<B: stack_kms_vendor::KeyVendorBackend>(
    make: impl Fn() -> B,
    record: KeysetRecord,
    new_ref: &str,
) {
    let old = StackCipher::builder()
        .kms(VendorKeySource::new(make(), [record.clone()]).unwrap())
        .init()
        .await
        .unwrap();
    let sealed = old
        .default_keyset()
        .encrypt_tree("v".to_string(), b"ctx")
        .await
        .unwrap();
    let term = old
        .default_keyset()
        .equality_term("v", nonempty!("ctx"))
        .await
        .unwrap();

    let rewrapped = record.rewrap(&make(), new_ref).await.unwrap();
    assert_eq!(rewrapped.id(), record.id());
    assert_eq!(rewrapped.mode(), record.mode());
    assert_eq!(rewrapped.key_ref(), new_ref);
    let new = StackCipher::builder()
        .kms(VendorKeySource::new(make(), [rewrapped]).unwrap())
        .init()
        .await
        .unwrap();
    let opened: String = new.decrypt(sealed, b"ctx").await.unwrap();
    assert_eq!(opened, "v", "a value sealed before the rewrap opens");
    let again = new
        .default_keyset()
        .equality_term("v", nonempty!("ctx"))
        .await
        .unwrap();
    assert_eq!(
        term.as_bytes(),
        again.as_bytes(),
        "the index key did not change"
    );
}

#[tokio::test]
async fn a_derived_record_rewraps_to_another_key_and_keeps_old_values() {
    let vendor = || {
        StaticKeyVendor::new("key-a", Protected::new([1u8; 32]))
            .with_key("key-b", Protected::new([2u8; 32]))
    };
    let record = KeysetRecord::create(&vendor(), "key-a", DERIVED, None)
        .await
        .unwrap();
    rewrap_keeps_old_values(vendor, record.clone(), "key-b").await;

    // The fake vendor too, which reports itself as a remote vendor.
    let fake = || FakeVendor::new(KeyVendor::Aws).with_key("next/v2", Protected::new([2u8; 32]));
    let record = KeysetRecord::create(&fake(), FakeVendor::KEY_REF, DERIVED, None)
        .await
        .unwrap();
    rewrap_keeps_old_values(fake, record, "next/v2").await;
}

#[tokio::test]
async fn an_expired_root_key_is_unwrapped_again() {
    let (backend, observer) = Observed::new(FakeVendor::new(KeyVendor::Gcp));
    let record = KeysetRecord::create(&backend, FakeVendor::KEY_REF, DERIVED, None)
        .await
        .unwrap();
    let cipher = StackCipher::builder()
        .kms(
            VendorKeySource::new(backend, [record])
                .unwrap()
                .with_root_key_ttl(Duration::from_millis(100)),
        )
        .init()
        .await
        .unwrap();
    let keyset = cipher.default_keyset();
    let _ = keyset.encrypt_tree("v".to_string(), b"ctx").await.unwrap();
    let _ = keyset.encrypt_tree("v".to_string(), b"ctx").await.unwrap();
    assert_eq!(observer.unwraps(), 1, "kept within its TTL");
    tokio::time::sleep(Duration::from_millis(150)).await;
    let _ = keyset.encrypt_tree("v".to_string(), b"ctx").await.unwrap();
    assert_eq!(observer.unwraps(), 2, "unwrapped again after its TTL");
}

#[tokio::test]
async fn several_records_need_a_named_default() {
    let vendor = FakeVendor::new(KeyVendor::Aws);
    let a = KeysetRecord::create(&vendor, FakeVendor::KEY_REF, DERIVED, None)
        .await
        .unwrap();
    let b = KeysetRecord::create(&vendor, FakeVendor::KEY_REF, DERIVED, None)
        .await
        .unwrap();
    let source = VendorKeySource::new(vendor, [a.clone(), b]).unwrap();
    assert!(
        StackCipher::builder().kms(source).init().await.is_err(),
        "no default keyset among several records"
    );

    let vendor = FakeVendor::new(KeyVendor::Aws);
    let source = VendorKeySource::new(vendor, [a.clone()])
        .unwrap()
        .with_default_keyset(a.id())
        .unwrap();
    let cipher = StackCipher::builder().kms(source).init().await.unwrap();
    assert_eq!(cipher.default_keyset().keyset_id(), a.id());
    assert!(matches!(
        VendorKeySource::new(FakeVendor::new(KeyVendor::Aws), [a])
            .unwrap()
            .with_default_keyset(uuid::Uuid::nil()),
        Err(RecordError::UnknownDefault)
    ));
}

/// A client with a key vendor backend and no ZeroKMS: naming no keyset is
/// the vendor's default keyset, and anything else goes to the ZeroKMS side.
#[tokio::test]
async fn a_vendor_default_router_selects_the_vendor_for_no_keyset() {
    let vendor = FakeVendor::new(KeyVendor::Aws);
    let record = KeysetRecord::create(&vendor, FakeVendor::KEY_REF, DERIVED, None)
        .await
        .unwrap();
    let source = VendorKeySource::new(vendor, [record.clone()]).unwrap();
    let router = KeyRouter::new(FakeDataKeySource::new(), source).with_vendor_default();
    let cipher = StackCipher::builder().kms(router).init().await.unwrap();
    assert_eq!(cipher.default_keyset().keyset_id(), record.id());
    let context = nonempty!("users").with("email");
    let sealed = cipher
        .default_keyset()
        .encrypt_tree("v".to_string(), context)
        .await
        .unwrap();
    assert_eq!(keyset_of(&sealed), record.id());
    let opened: String = cipher.decrypt(sealed, context).await.unwrap();
    assert_eq!(opened, "v");
}

/// A router with no vendor sends every request to ZeroKMS, the default
/// keyset included, even when it is told to prefer the vendor.
#[tokio::test]
async fn a_router_with_no_vendor_sends_everything_to_zerokms() {
    let router =
        KeyRouter::<_, FakeVendor>::zerokms_only(FakeDataKeySource::new()).with_vendor_default();
    assert!(router.vendor().is_none());
    let cipher = StackCipher::builder().kms(router).init().await.unwrap();
    let context = nonempty!("users").with("email");
    let sealed = cipher
        .default_keyset()
        .encrypt_tree("z".to_string(), context)
        .await
        .unwrap();
    assert_eq!(keyset_of(&sealed), cipher.default_keyset().keyset_id());
    let opened: String = cipher.decrypt(sealed, context).await.unwrap();
    assert_eq!(opened, "z");
}
