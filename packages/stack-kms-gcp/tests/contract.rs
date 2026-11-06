//! The shared contract suite, run against the Cloud KMS backend over an
//! in-process emulation of the Cloud KMS API, in both key modes.
//!
//! The suite generates random keys and keyset ids, so fixed exchanges
//! cannot answer it; the emulator does (see `common::KmsEmulator`). The
//! request shapes are pinned by `tests/fixtures.rs`, and real Cloud KMS is
//! exercised by `tests/live.rs`.

mod common;

use common::{fixture_client, test_only_service_account, KmsEmulator, KEY};
use stack_encrypt::StackCipher;
use stack_kms::KeyMode;
use stack_kms::{BackendErrorKind, Error};
use stack_kms_gcp::{wrapped_key_version, CachedToken, GcpKms, GcpKmsConfig, ServiceAccountLogin};
use stack_kms_vendor::derive::wrapped_data_key_aad;
use stack_kms_vendor::{contract, KeyVendorBackend, KeysetRecord, RecordError, VendorKeySource};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};

fn kind_of(error: Error) -> BackendErrorKind {
    match error {
        Error::Backend { backend, kind, .. } => {
            assert_eq!(backend.name(), "gcp-kms");
            kind
        }
        other => panic!("not a backend error: {other:?}"),
    }
}

#[tokio::test]
async fn gcp_kms_meets_the_contract() {
    let emulator = KmsEmulator::new();
    contract::run(|| fixture_client(emulator.clone()), KEY).await;
}

#[tokio::test]
async fn gcp_kms_meets_the_contract_with_service_account_credentials() {
    let emulator = KmsEmulator::new();
    contract::run(
        || {
            GcpKms::new(
                GcpKmsConfig::new(),
                emulator.clone(),
                CachedToken::new(ServiceAccountLogin::new(
                    test_only_service_account(),
                    emulator.clone(),
                )),
            )
        },
        KEY,
    )
    .await;
    // Each client caches its own token.
    assert!(emulator.exchanges() >= 1);
}

#[tokio::test]
async fn a_wrapped_key_opens_only_under_its_own_aad() {
    let emulator = KmsEmulator::new();
    let kms = fixture_client(emulator.clone());
    let id = Uuid::from_u128(1);
    let aad = wrapped_data_key_aad(id, &[1u8; 16], "users/email");
    let wrapped = kms
        .wrap(KEY, &Protected::new([9u8; 32]), &aad)
        .await
        .unwrap();
    assert_eq!(
        kms.unwrap(KEY, &wrapped, &aad).await.unwrap().risky_ref(),
        &[9u8; 32]
    );
    let other = wrapped_data_key_aad(id, &[1u8; 16], "users/name");
    let error = kms.unwrap(KEY, &wrapped, &other).await.unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::InvalidCiphertext);
    // The associated data travels whole.
    let requests = emulator.requests();
    let (_, path, body) = &requests[0];
    assert_eq!(path, &format!("{KEY}:encrypt"));
    assert_eq!(
        body["additionalAuthenticatedData"],
        <base64ct::Base64 as base64ct::Encoding>::encode_string(&aad)
    );
}

#[tokio::test]
async fn rotation_needs_no_change_to_the_key_reference() {
    let emulator = KmsEmulator::new();
    let kms = fixture_client(emulator.clone());
    let old = kms
        .wrap(KEY, &Protected::new([5u8; 32]), b"aad")
        .await
        .unwrap();
    assert_eq!(wrapped_key_version(&old), Some(1));
    emulator.rotate(KEY);
    let new = kms
        .wrap(KEY, &Protected::new([6u8; 32]), b"aad")
        .await
        .unwrap();
    assert_eq!(wrapped_key_version(&new), Some(2));
    assert_eq!(
        kms.unwrap(KEY, &old, b"aad").await.unwrap().risky_ref(),
        &[5u8; 32]
    );
    assert_eq!(
        kms.unwrap(KEY, &new, b"aad").await.unwrap().risky_ref(),
        &[6u8; 32]
    );
}

#[tokio::test]
async fn a_missing_key_is_not_found() {
    let emulator = KmsEmulator::new();
    let kms = fixture_client(emulator);
    let missing = "projects/test-only-project/locations/global/keyRings/r/cryptoKeys/missing";
    let error = kms
        .wrap(missing, &Protected::new([1u8; 32]), b"a")
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::NotFound);
}

/// Seal a value under `record`, then rewrap the record to `new_ref` and
/// open the value through the rewrapped record.
async fn rewrap_and_open(emulator: &KmsEmulator, record: KeysetRecord, new_ref: &str) {
    let old = StackCipher::builder()
        .kms(VendorKeySource::new(fixture_client(emulator.clone()), [record.clone()]).unwrap())
        .init()
        .await
        .unwrap();
    let sealed = old
        .default_keyset()
        .encrypt_tree("v".to_string(), b"ctx")
        .await
        .unwrap();
    emulator.rotate(KEY);
    let rewrapped = record
        .rewrap(&fixture_client(emulator.clone()), new_ref)
        .await
        .unwrap();
    assert_eq!(wrapped_key_version(rewrapped.wrapped_key()), Some(2));
    let new = StackCipher::builder()
        .kms(VendorKeySource::new(fixture_client(emulator.clone()), [rewrapped]).unwrap())
        .init()
        .await
        .unwrap();
    let opened: String = new.decrypt(sealed, b"ctx").await.unwrap();
    assert_eq!(opened, "v");
}

#[test]
fn the_same_crypto_key_ignores_the_version() {
    let kms = fixture_client(KmsEmulator::new());
    let v2 = format!("{KEY}/cryptoKeyVersions/2");
    let v7 = format!("{KEY}/cryptoKeyVersions/7");
    assert!(kms.same_key(KEY, KEY));
    assert!(kms.same_key(KEY, &v2));
    assert!(kms.same_key(&v2, &v7));
    let other = KEY.replace("fixture-key", "other-key");
    assert!(!kms.same_key(KEY, &other));
    assert!(!kms.same_key(&v2, &format!("{other}/cryptoKeyVersions/2")));
    assert!(!kms.same_key(KEY, "not a key name"));
}

#[tokio::test]
async fn a_wrapped_record_rewraps_to_a_new_version_and_keeps_old_values() {
    for new_ref in [KEY.to_owned(), format!("{KEY}/cryptoKeyVersions/2")] {
        let emulator = KmsEmulator::new();
        let record = KeysetRecord::create(
            &fixture_client(emulator.clone()),
            KEY,
            KeyMode::Wrapped,
            None,
        )
        .await
        .unwrap();
        rewrap_and_open(&emulator, record, &new_ref).await;
    }
}

#[tokio::test]
async fn a_wrapped_record_does_not_rewrap_to_another_crypto_key() {
    let emulator = KmsEmulator::new();
    let other = KEY.replace("fixture-key", "other-key");
    emulator.add_key(&other);
    let kms = fixture_client(emulator.clone());
    let record = KeysetRecord::create(&kms, KEY, KeyMode::Wrapped, None)
        .await
        .unwrap();
    let before = emulator.requests().len();
    assert!(matches!(
        record.rewrap(&kms, other.as_str()).await,
        Err(RecordError::RewrapToAnotherKey { .. })
    ));
    assert_eq!(emulator.requests().len(), before, "no vendor call");

    // A derived record may move to another crypto key.
    let record = KeysetRecord::create(&kms, KEY, KeyMode::Derived, None)
        .await
        .unwrap();
    let moved = record.rewrap(&kms, other.as_str()).await.unwrap();
    assert_eq!(moved.key_ref(), other);
}
