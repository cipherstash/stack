//! The shared contract suite, run against the AWS KMS backend over an
//! in-process emulation of the AWS KMS JSON API.
//!
//! The suite generates random keys and keyset ids, so recorded exchanges
//! cannot answer it; the emulator does (see `common::KmsEmulator`). The
//! request shapes are pinned by `tests/fixtures.rs`, and the real service
//! is exercised by `tests/localstack.rs`.

mod common;

use common::{fixture_client, KmsEmulator, KEY_ARN};
use stack_kms::{BackendErrorKind, Error, KeyMode, KeyVendor};
use stack_kms_aws::encryption_context;
use stack_kms_vendor::derive::record_key_aad;
use stack_kms_vendor::{contract, KeyVendorBackend};
use uuid::Uuid;
use vitaminc::protected::Protected;

#[tokio::test]
async fn aws_kms_meets_the_contract() {
    let emulator = KmsEmulator::with_key(KEY_ARN);
    contract::run(|| fixture_client(emulator.clone()), KEY_ARN).await;
}

#[tokio::test]
async fn a_wrapped_key_opens_only_under_its_own_context_and_key() {
    let emulator = KmsEmulator::with_key(KEY_ARN);
    let kms = fixture_client(emulator.clone());
    let aad = record_key_aad(Uuid::from_u128(1), KeyVendor::Aws, KeyMode::Derived);
    let wrapped = kms
        .wrap(KEY_ARN, &Protected::new([1u8; 32]), &aad)
        .await
        .unwrap();

    let other = record_key_aad(Uuid::from_u128(2), KeyVendor::Aws, KeyMode::Derived);
    assert_ne!(encryption_context(&aad), encryption_context(&other));
    let error = kms.unwrap(KEY_ARN, &wrapped, &other).await.unwrap_err();
    assert!(matches!(
        error,
        Error::Backend {
            kind: BackendErrorKind::InvalidCiphertext,
            ..
        }
    ));

    let error = kms.unwrap("no-such-key", &wrapped, &aad).await.unwrap_err();
    assert!(matches!(
        error,
        Error::Backend {
            kind: BackendErrorKind::InvalidCiphertext,
            ..
        }
    ));
    assert_eq!(kms.vendor(), KeyVendor::Aws);
}
