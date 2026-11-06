//! The shared contract suite, run against the Azure backend over an
//! in-process emulation of the Key Vault key API, in both key modes, for a
//! Key Vault RSA key (RSA-OAEP-256) and a Managed HSM `oct-HSM` key
//! (A256KW).
//!
//! The suite generates random keys and keyset ids, so fixed exchanges
//! cannot answer it; the emulator does (see `common::KeyVaultEmulator`).
//! The request shapes are pinned by `tests/fixtures.rs`, and real Azure Key
//! Vault is exercised by `tests/live.rs`.

mod common;

use common::{
    fixture_client, KeyVaultEmulator, CLIENT_ID, CLIENT_SECRET, OCT_KEY, RSA_KEY, RSA_OLD_VERSION,
    RSA_VERSION, TENANT,
};
use stack_encrypt::StackCipher;
use stack_kms::KeyMode;
use stack_kms::{BackendErrorKind, Error};
use stack_kms_azure::{
    wrapped_key_version, AzureKeyVault, AzureKeyVaultConfig, CachedToken, ClientSecretLogin,
};
use stack_kms_vendor::derive::wrapped_data_key_aad;
use stack_kms_vendor::{contract, KeyVendorBackend, KeysetRecord, RecordError, VendorKeySource};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};

fn kind_of(error: Error) -> BackendErrorKind {
    match error {
        Error::Backend { backend, kind, .. } => {
            assert_eq!(backend.name(), "azure-key-vault");
            kind
        }
        other => panic!("not a backend error: {other:?}"),
    }
}

#[tokio::test]
async fn a_key_vault_rsa_key_meets_the_contract() {
    let emulator = KeyVaultEmulator::new();
    contract::run(|| fixture_client(emulator.clone()), RSA_KEY).await;
}

#[tokio::test]
async fn a_managed_hsm_oct_key_meets_the_contract() {
    let emulator = KeyVaultEmulator::new();
    contract::run(|| fixture_client(emulator.clone()), OCT_KEY).await;
}

#[tokio::test]
async fn both_flavours_meet_the_contract_with_client_secret_credentials() {
    let emulator = KeyVaultEmulator::new();
    let make = || {
        AzureKeyVault::new(
            AzureKeyVaultConfig::new(),
            emulator.clone(),
            CachedToken::new(
                ClientSecretLogin::new(TENANT, CLIENT_ID, CLIENT_SECRET, emulator.clone()).unwrap(),
            ),
        )
    };
    contract::run(make, RSA_KEY).await;
    contract::run(make, OCT_KEY).await;
    // The emulator checks the audience: a vault token does not open the HSM.
    assert!(emulator.exchanges() >= 2);
}

#[tokio::test]
async fn a_wrapped_key_opens_only_under_its_own_aad() {
    for key in [RSA_KEY, OCT_KEY] {
        let emulator = KeyVaultEmulator::new();
        let kms = fixture_client(emulator.clone());
        let id = Uuid::from_u128(1);
        let aad = wrapped_data_key_aad(id, &[1u8; 16], "users/email");
        let wrapped = kms
            .wrap(key, &Protected::new([9u8; 32]), &aad)
            .await
            .unwrap();
        assert_eq!(
            kms.unwrap(key, &wrapped, &aad).await.unwrap().risky_ref(),
            &[9u8; 32]
        );
        // Azure unwraps it (it sees no associated data); the client refuses.
        let other = wrapped_data_key_aad(id, &[1u8; 16], "users/name");
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
    let emulator = KeyVaultEmulator::new();
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
    let emulator = KeyVaultEmulator::new();
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
    let emulator = KeyVaultEmulator::new();
    let kms = fixture_client(emulator.clone());
    emulator.throttle(1);
    let error = kms
        .wrap(RSA_KEY, &Protected::new([1u8; 32]), b"a")
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::Throttled);
    assert_eq!(emulator.sleeps(), [std::time::Duration::from_secs(2)]);
    // The adapter retries a throttle; the next call goes through.
    let wrapped = kms
        .wrap(RSA_KEY, &Protected::new([1u8; 32]), b"a")
        .await
        .unwrap();
    assert!(wrapped_key_version(&wrapped).is_some());
}

#[tokio::test]
async fn a_missing_key_is_not_found() {
    let emulator = KeyVaultEmulator::new();
    let kms = fixture_client(emulator);
    let missing = "https://cipherstash-fixture.vault.azure.net/keys/missing";
    let error = kms
        .wrap(missing, &Protected::new([1u8; 32]), b"a")
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::NotFound);
}

#[test]
fn the_same_key_ignores_the_version() {
    let kms = fixture_client(KeyVaultEmulator::new());
    let v1 = format!("{RSA_KEY}/{RSA_VERSION}");
    let v2 = format!("{RSA_KEY}/{RSA_OLD_VERSION}");
    assert!(kms.same_key(RSA_KEY, RSA_KEY));
    assert!(kms.same_key(RSA_KEY, &v1));
    assert!(kms.same_key(&v1, &v2));
    // The host is case-insensitive.
    assert!(kms.same_key(
        RSA_KEY,
        &RSA_KEY.replace("cipherstash-fixture", "CIPHERSTASH-FIXTURE")
    ));
    assert!(!kms.same_key(RSA_KEY, OCT_KEY));
    assert!(!kms.same_key(RSA_KEY, &RSA_KEY.replace("fixture-rsa-key", "other-key")));
    assert!(!kms.same_key(
        RSA_KEY,
        &RSA_KEY.replace("cipherstash-fixture.vault", "other-vault.vault")
    ));
    assert!(!kms.same_key(RSA_KEY, "not a key identifier"));
}

#[tokio::test]
async fn a_wrapped_record_rewraps_to_a_new_version_and_keeps_old_values() {
    for key in [RSA_KEY, OCT_KEY] {
        for pin in [false, true] {
            let emulator = KeyVaultEmulator::new();
            let record = KeysetRecord::create(
                &fixture_client(emulator.clone()),
                key,
                KeyMode::Wrapped,
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
                .encrypt("v".to_string(), b"ctx")
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
async fn a_wrapped_record_does_not_rewrap_to_another_key() {
    let emulator = KeyVaultEmulator::new();
    let other = RSA_KEY.replace("fixture-rsa-key", "other-rsa-key");
    emulator.add_key(&other, true);
    let kms = fixture_client(emulator.clone());
    let record = KeysetRecord::create(&kms, RSA_KEY, KeyMode::Wrapped, None)
        .await
        .unwrap();
    let before = emulator.requests().len();
    assert!(matches!(
        record.rewrap(&kms, other.as_str()).await,
        Err(RecordError::RewrapToAnotherKey { .. })
    ));
    assert_eq!(emulator.requests().len(), before, "no vendor call");

    // A derived record may move to another key.
    let record = KeysetRecord::create(&kms, RSA_KEY, KeyMode::Derived, None)
        .await
        .unwrap();
    let moved = record.rewrap(&kms, other.as_str()).await.unwrap();
    assert_eq!(moved.key_ref(), other);
}
