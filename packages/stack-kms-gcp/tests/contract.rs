//! The shared contract suite, run against the Cloud KMS backend over an
//! in-process emulation of the Cloud KMS API, in both key modes.
//!
//! The suite generates random keys and keyset ids, so fixed exchanges
//! cannot answer it; the emulator does (see `common::KmsEmulator`). The
//! request shapes are pinned by `tests/fixtures.rs`, and real Cloud KMS is
//! exercised by `tests/live.rs`.

mod common;

use common::{fixture_client, test_only_service_account, KmsEmulator, KEY};
use stack_kms::{BackendErrorKind, Error};
use stack_kms_gcp::{wrapped_key_version, CachedToken, GcpKms, GcpKmsConfig, ServiceAccountLogin};
use stack_kms_vendor::derive::wrapped_data_key_aad;
use stack_kms_vendor::{contract, KeyVendorBackend};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};

fn kind_of(error: Error) -> BackendErrorKind {
    match error {
        Error::Backend { vendor, kind, .. } => {
            assert_eq!(vendor, "gcp-kms");
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
