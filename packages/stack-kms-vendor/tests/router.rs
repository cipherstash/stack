//! ZeroKMS and one key vendor backend in one cipher, keyset records as
//! config, and the root key TTL in real time.

use std::time::Duration;

use stack_encrypt::kms::{
    BackendErrorKind, Error as KmsError, FakeDataKeySource, IdentifiedBy, KeyBackend, KeyMode,
    KeyVendor,
};
use stack_encrypt::{nonempty, CipherText, Error, StackCipher, StackCipherText};
use stack_kms_vendor::contract::Observed;
use stack_kms_vendor::{
    FakeVendor, KeyRouter, KeysetRecord, RecordError, StaticKeyVendor, VendorKeySource,
};
use vitaminc::protected::Protected;

fn leaf_backend(sealed: &StackCipherText) -> (KeyBackend, Option<KeyMode>) {
    match sealed {
        CipherText::Single(leaf) => (leaf.key_backend(), leaf.key_mode()),
        _ => panic!("one leaf"),
    }
}

#[tokio::test]
async fn one_cipher_routes_between_zerokms_and_one_vendor() {
    let vendor = FakeVendor::new(KeyVendor::Aws);
    let wrapped = KeysetRecord::create(
        &vendor,
        FakeVendor::KEY_REF,
        KeyMode::Wrapped,
        Some("acme".into()),
    )
    .await
    .unwrap();
    let derived = KeysetRecord::create(&vendor, FakeVendor::KEY_REF, KeyMode::Derived, None)
        .await
        .unwrap();
    let texts = [wrapped.to_string(), derived.to_string()];
    let source = VendorKeySource::from_texts(vendor, texts.iter().map(String::as_str)).unwrap();
    let cipher = StackCipher::builder()
        .kms(KeyRouter::new(FakeDataKeySource::new(), source))
        .init()
        .await
        .unwrap();
    let context = nonempty!("users").with("email");

    // Naming no keyset is ZeroKMS's default keyset, and seals v1.
    let zerokms = cipher
        .default_keyset()
        .encrypt("z".to_string(), context)
        .await
        .unwrap();
    assert_eq!(leaf_backend(&zerokms), (KeyBackend::ZeroKms, None));
    assert!(cipher.default_keyset().prf().is_some());

    // A record's name and id select the vendor, and seal v2.
    let acme = cipher
        .keyset(IdentifiedBy::Name("acme".to_string().into()))
        .await
        .unwrap();
    assert_eq!(acme.keyset_id(), wrapped.id());
    let sealed_wrapped = acme.encrypt("w".to_string(), context).await.unwrap();
    assert_eq!(
        leaf_backend(&sealed_wrapped),
        (KeyBackend::Vendor(KeyVendor::Aws), Some(KeyMode::Wrapped))
    );
    let other = cipher.keyset(derived.id()).await.unwrap();
    let sealed_derived = other.encrypt("d".to_string(), context).await.unwrap();
    assert_eq!(
        leaf_backend(&sealed_derived),
        (KeyBackend::Vendor(KeyVendor::Aws), Some(KeyMode::Derived))
    );

    // Each leaf opens through the backend that sealed it.
    for (sealed, expected) in [(zerokms, "z"), (sealed_wrapped, "w"), (sealed_derived, "d")] {
        let opened: String = cipher.decrypt(sealed, context).await.unwrap();
        assert_eq!(opened, expected);
    }

    // A term through a vendor keyset is derived inside the settle, and
    // differs from the ZeroKMS keyset's term for the same value.
    let vendor_term = acme.equality_term("x", context).await.unwrap();
    let zerokms_term = cipher
        .default_keyset()
        .equality_term("x", context)
        .await
        .unwrap();
    assert_ne!(vendor_term.as_bytes(), zerokms_term.as_bytes());
}

#[tokio::test]
async fn a_vendor_leaf_relabelled_as_zerokms_is_refused() {
    let vendor = FakeVendor::new(KeyVendor::Vault);
    let record = KeysetRecord::create(&vendor, FakeVendor::KEY_REF, KeyMode::Derived, None)
        .await
        .unwrap();
    let cipher = StackCipher::builder()
        .kms(KeyRouter::new(
            FakeDataKeySource::new(),
            VendorKeySource::new(vendor, [record.clone()]).unwrap(),
        ))
        .init()
        .await
        .unwrap();
    let keyset = cipher.keyset(record.id()).await.unwrap();
    let sealed = keyset.encrypt("v".to_string(), b"ctx").await.unwrap();
    let CipherText::Single(leaf) = sealed else {
        panic!("one leaf")
    };
    let (keyset_id, iv, tag, ct) = leaf.into_parts();
    let v1 = stack_encrypt::SealedValue::from_parts(keyset_id, iv, tag, ct).unwrap();
    match cipher
        .decrypt::<String, _>(CipherText::Single(v1), b"ctx")
        .await
    {
        Err(Error::ForeignBackend { expected, found }) => {
            assert_eq!(expected, KeyBackend::Vendor(KeyVendor::Vault));
            assert_eq!(found, KeyBackend::ZeroKms);
        }
        other => panic!("expected ForeignBackend, got {other:?}"),
    }
}

#[tokio::test]
async fn records_of_two_vendors_are_refused() {
    let aws = FakeVendor::new(KeyVendor::Aws);
    let vault = FakeVendor::new(KeyVendor::Vault);
    let a = KeysetRecord::create(&aws, FakeVendor::KEY_REF, KeyMode::Derived, None)
        .await
        .unwrap();
    let v = KeysetRecord::create(&vault, FakeVendor::KEY_REF, KeyMode::Derived, None)
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
async fn the_static_backend_refuses_wrapped_data_keys() {
    let vendor = StaticKeyVendor::new("k", Protected::new([1u8; 32]));
    assert!(matches!(
        KeysetRecord::create(&vendor, "k", KeyMode::Wrapped, None).await,
        Err(RecordError::ModeUnsupported {
            vendor: KeyVendor::Static,
            mode: KeyMode::Wrapped
        })
    ));
    let forged = KeysetRecord::from_parts(
        uuid::Uuid::new_v4(),
        None,
        KeyVendor::Static,
        KeyMode::Wrapped,
        "k".into(),
        vec![1; 60],
    )
    .unwrap();
    assert!(matches!(
        VendorKeySource::new(vendor, [forged]),
        Err(RecordError::ModeUnsupported { .. })
    ));
}

#[tokio::test]
async fn a_record_edited_in_its_bound_fields_does_not_unwrap() {
    let vendor = FakeVendor::new(KeyVendor::Aws);
    let record = KeysetRecord::create(&vendor, FakeVendor::KEY_REF, KeyMode::Derived, None)
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
    let cipher = StackCipher::builder()
        .kms(VendorKeySource::new(vendor, [moved]).unwrap())
        .init()
        .await
        .unwrap();
    match cipher
        .default_keyset()
        .encrypt("v".to_string(), b"ctx")
        .await
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
        .encrypt("v".to_string(), b"ctx")
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
async fn a_wrapped_record_does_not_rewrap_to_another_key() {
    let vendor = FakeVendor::new(KeyVendor::Aws).with_key("next/v2", Protected::new([2u8; 32]));
    let record = KeysetRecord::create(&vendor, FakeVendor::KEY_REF, KeyMode::Wrapped, None)
        .await
        .unwrap();
    let before = vendor.calls();
    match record.rewrap(&vendor, "next/v2").await {
        Err(RecordError::RewrapToAnotherKey { keyset, from, to }) => {
            assert_eq!(keyset, record.id());
            assert_eq!(from, FakeVendor::KEY_REF);
            assert_eq!(to, "next/v2");
        }
        other => panic!("a wrapped record must not move to another key, got {other:?}"),
    }
    assert_eq!(vendor.calls(), before, "refused before any vendor call");
}

#[tokio::test]
async fn a_wrapped_record_rewraps_under_its_own_key_and_keeps_old_values() {
    let vendor = || FakeVendor::new(KeyVendor::Aws);
    let record = KeysetRecord::create(&vendor(), FakeVendor::KEY_REF, KeyMode::Wrapped, None)
        .await
        .unwrap();
    rewrap_keeps_old_values(vendor, record, FakeVendor::KEY_REF).await;
}

#[tokio::test]
async fn a_derived_record_rewraps_to_another_key_and_keeps_old_values() {
    let vendor = || {
        StaticKeyVendor::new("key-a", Protected::new([1u8; 32]))
            .with_key("key-b", Protected::new([2u8; 32]))
    };
    let record = KeysetRecord::create(&vendor(), "key-a", KeyMode::Derived, None)
        .await
        .unwrap();
    rewrap_keeps_old_values(vendor, record.clone(), "key-b").await;

    // The fake vendor too, so a wrapped-capable vendor is covered.
    let fake = || FakeVendor::new(KeyVendor::Aws).with_key("next/v2", Protected::new([2u8; 32]));
    let record = KeysetRecord::create(&fake(), FakeVendor::KEY_REF, KeyMode::Derived, None)
        .await
        .unwrap();
    rewrap_keeps_old_values(fake, record, "next/v2").await;
}

#[tokio::test]
async fn an_expired_root_key_is_unwrapped_again() {
    let (backend, observer) = Observed::new(FakeVendor::new(KeyVendor::Gcp));
    let record = KeysetRecord::create(&backend, FakeVendor::KEY_REF, KeyMode::Derived, None)
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
    let _ = keyset.equality_term("v", nonempty!("ctx")).await.unwrap();
    let _ = keyset.equality_term("v", nonempty!("ctx")).await.unwrap();
    assert_eq!(observer.unwraps(), 1, "kept within its TTL");
    tokio::time::sleep(Duration::from_millis(150)).await;
    let _ = keyset.equality_term("v", nonempty!("ctx")).await.unwrap();
    assert_eq!(observer.unwraps(), 2, "unwrapped again after its TTL");
}

#[tokio::test]
async fn several_records_need_a_named_default() {
    let vendor = FakeVendor::new(KeyVendor::Aws);
    let a = KeysetRecord::create(&vendor, FakeVendor::KEY_REF, KeyMode::Derived, None)
        .await
        .unwrap();
    let b = KeysetRecord::create(&vendor, FakeVendor::KEY_REF, KeyMode::Derived, None)
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
    let record = KeysetRecord::create(&vendor, FakeVendor::KEY_REF, KeyMode::Derived, None)
        .await
        .unwrap();
    let source = VendorKeySource::new(vendor, [record.clone()]).unwrap();
    let router = KeyRouter::new(FakeDataKeySource::new(), source).with_vendor_default();
    assert_eq!(
        stack_encrypt::kms::DataKeySource::key_backend(&router),
        KeyBackend::Vendor(KeyVendor::Aws)
    );
    let cipher = StackCipher::builder().kms(router).init().await.unwrap();
    assert_eq!(cipher.default_keyset().keyset_id(), record.id());
    let context = nonempty!("users").with("email");
    let sealed = cipher
        .default_keyset()
        .encrypt("v".to_string(), context)
        .await
        .unwrap();
    assert_eq!(
        leaf_backend(&sealed),
        (KeyBackend::Vendor(KeyVendor::Aws), Some(KeyMode::Derived))
    );
    let opened: String = cipher.decrypt(sealed, context).await.unwrap();
    assert_eq!(opened, "v");
}
