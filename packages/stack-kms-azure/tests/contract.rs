//! The shared contract suite, run against the Azure backend over an
//! in-process emulation of the Managed HSM key API, for an `oct-HSM` key
//! (A256KW).
//!
//! The suite generates random keys and keyset ids, so fixed exchanges
//! cannot answer it; the emulator does (see `common::ManagedHsmEmulator`).
//! The request shapes are pinned by `tests/fixtures.rs`. `tests/live.rs`
//! is the test against a real Managed HSM, and it is off until a live
//! instance is available.

mod common;

use common::{fixture_client, ManagedHsmEmulator, CLIENT_ID, CLIENT_SECRET, OCT_KEY, TENANT};
use stack_encrypt::StackCipher;
use stack_kms::{BackendErrorKind, Error, KeyMode, KeyVendor};
use stack_kms_azure::{wrapped_key_version, AzureManagedHsm, CachedToken, ClientSecretLogin};
use stack_kms_vendor::derive::record_key_aad;
use stack_kms_vendor::{contract, KeyVendorBackend, KeysetRecord, VendorKeySource};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};

fn kind_of(error: Error) -> BackendErrorKind {
    match error {
        Error::Backend { backend, kind, .. } => {
            assert_eq!(backend.name(), "azure-managed-hsm");
            kind
        }
        other => panic!("not a backend error: {other:?}"),
    }
}

#[tokio::test]
async fn a_managed_hsm_oct_key_meets_the_contract() {
    let emulator = ManagedHsmEmulator::new();
    contract::run(|| fixture_client(emulator.clone()), OCT_KEY).await;
}

#[tokio::test]
async fn the_contract_holds_with_client_secret_credentials() {
    let emulator = ManagedHsmEmulator::new();
    let make = || {
        AzureManagedHsm::new(
            emulator.clone(),
            CachedToken::new(
                ClientSecretLogin::new(TENANT, CLIENT_ID, CLIENT_SECRET, emulator.clone()).unwrap(),
            ),
        )
    };
    contract::run(make, OCT_KEY).await;
    // The emulator checks the audience of each exchanged token.
    assert!(emulator.exchanges() >= 1);
}

#[tokio::test]
async fn a_wrapped_key_opens_only_under_its_own_aad() {
    {
        let key = OCT_KEY;
        let emulator = ManagedHsmEmulator::new();
        let kms = fixture_client(emulator.clone());
        let id = Uuid::from_u128(1);
        let aad = record_key_aad(id, KeyVendor::Azure, KeyMode::Derived);
        let wrapped = kms
            .wrap(key, &Protected::new([9u8; 32]), &aad)
            .await
            .unwrap();
        assert_eq!(
            kms.unwrap(key, &wrapped, &aad).await.unwrap().risky_ref(),
            &[9u8; 32]
        );
        // Azure unwraps it (it sees no associated data); the client refuses.
        let other = record_key_aad(Uuid::from_u128(2), KeyVendor::Azure, KeyMode::Derived);
        let error = kms.unwrap(key, &wrapped, &other).await.unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::InvalidCiphertext);
        // A damaged ciphertext does not unwrap at Azure.
        let mut damaged = wrapped.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        let error = kms.unwrap(key, &damaged, &aad).await.unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::InvalidCiphertext);
    }
}

#[tokio::test]
async fn rotation_needs_no_change_to_the_key_reference() {
    let emulator = ManagedHsmEmulator::new();
    let old = fixture_client(emulator.clone())
        .wrap(OCT_KEY, &Protected::new([5u8; 32]), b"aad")
        .await
        .unwrap();
    let new_version = emulator.rotate(OCT_KEY);
    // A new client reads the key again and wraps under the new version.
    let kms = fixture_client(emulator.clone());
    let new = kms
        .wrap(OCT_KEY, &Protected::new([6u8; 32]), b"aad")
        .await
        .unwrap();
    assert_ne!(wrapped_key_version(&old), wrapped_key_version(&new));
    assert_eq!(wrapped_key_version(&new), Some(new_version.as_str()));
    assert_eq!(
        kms.unwrap(OCT_KEY, &old, b"aad").await.unwrap().risky_ref(),
        &[5u8; 32]
    );
    assert_eq!(
        kms.unwrap(OCT_KEY, &new, b"aad").await.unwrap().risky_ref(),
        &[6u8; 32]
    );
}

#[tokio::test]
async fn a_failed_wrap_reads_the_key_again() {
    let emulator = ManagedHsmEmulator::new();
    let kms = fixture_client(emulator.clone());
    let first = kms
        .wrap(OCT_KEY, &Protected::new([1u8; 32]), b"a")
        .await
        .unwrap();
    let old_version = wrapped_key_version(&first).unwrap().to_owned();
    // An operator rotates the key and disables the old version.
    let new_version = emulator.rotate(OCT_KEY);
    emulator.disable(OCT_KEY, &old_version);
    let error = kms
        .wrap(OCT_KEY, &Protected::new([2u8; 32]), b"a")
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::Unavailable);
    let next = kms
        .wrap(OCT_KEY, &Protected::new([2u8; 32]), b"a")
        .await
        .unwrap();
    assert_eq!(wrapped_key_version(&next), Some(new_version.as_str()));
    // The old wrapped key does not unwrap while its version is disabled.
    let error = kms.unwrap(OCT_KEY, &first, b"a").await.unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::Unavailable);
}

#[tokio::test]
async fn a_throttle_waits_for_retry_after_then_reports_throttled() {
    let emulator = ManagedHsmEmulator::new();
    let kms = fixture_client(emulator.clone());
    emulator.throttle(1);
    let error = kms
        .wrap(OCT_KEY, &Protected::new([1u8; 32]), b"a")
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::Throttled);
    assert_eq!(emulator.sleeps(), [std::time::Duration::from_secs(2)]);
    // The adapter retries a throttle; the next call goes through.
    let wrapped = kms
        .wrap(OCT_KEY, &Protected::new([1u8; 32]), b"a")
        .await
        .unwrap();
    assert!(wrapped_key_version(&wrapped).is_some());
}

#[tokio::test]
async fn a_missing_key_is_not_found() {
    let emulator = ManagedHsmEmulator::new();
    let kms = fixture_client(emulator);
    let missing = "https://cipherstash-fixture.managedhsm.azure.net/keys/missing";
    let error = kms
        .wrap(missing, &Protected::new([1u8; 32]), b"a")
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::NotFound);
}

#[tokio::test]
async fn a_record_rewraps_to_a_new_version_and_keeps_old_values() {
    {
        let key = OCT_KEY;
        for pin in [false, true] {
            let emulator = ManagedHsmEmulator::new();
            let record = KeysetRecord::create(
                &fixture_client(emulator.clone()),
                key,
                KeyMode::Derived,
                None,
            )
            .await
            .unwrap();
            let old = StackCipher::builder()
                .kms(
                    VendorKeySource::new(fixture_client(emulator.clone()), [record.clone()])
                        .unwrap(),
                )
                .init()
                .await
                .unwrap();
            let sealed = old
                .default_keyset()
                .encrypt_tree("v".to_string(), b"ctx")
                .await
                .unwrap();
            let version = emulator.rotate(key);
            let new_ref = if pin {
                format!("{key}/{version}")
            } else {
                key.to_owned()
            };
            // A new client, so it reads the current version.
            let rewrapped = record
                .rewrap(&fixture_client(emulator.clone()), new_ref)
                .await
                .unwrap();
            assert_eq!(
                wrapped_key_version(rewrapped.wrapped_key()),
                Some(version.as_str())
            );
            let new = StackCipher::builder()
                .kms(VendorKeySource::new(fixture_client(emulator.clone()), [rewrapped]).unwrap())
                .init()
                .await
                .unwrap();
            let opened: String = new.decrypt(sealed, b"ctx").await.unwrap();
            assert_eq!(opened, "v");
        }
    }
}

#[tokio::test]
async fn a_record_may_rewrap_to_another_key() {
    let emulator = ManagedHsmEmulator::new();
    let other = OCT_KEY.replace("fixture-oct-key", "other-oct-key");
    emulator.add_key(&other);
    let kms = fixture_client(emulator.clone());
    let record = KeysetRecord::create(&kms, OCT_KEY, KeyMode::Derived, None)
        .await
        .unwrap();
    let moved = record.rewrap(&kms, other.as_str()).await.unwrap();
    assert_eq!(moved.key_ref(), other);
}
