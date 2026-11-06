//! The shared contract suite, run against the Vault Transit backend over an
//! in-process emulation of the Transit API, in both key modes, for a
//! derived and a non-derived key.
//!
//! The suite generates random keys and keyset ids, so recorded exchanges
//! cannot answer it; the emulator does (see `common::TransitEmulator`). The
//! request shapes are pinned by `tests/fixtures.rs`, and a real Vault is
//! exercised by `tests/vault_dev.rs`.

mod common;

use std::num::NonZeroUsize;

use common::{fixture_client, TransitEmulator, ADDRESS, DERIVED_KEY, KEY, TOKEN};
use stack_kms::{BackendErrorKind, Error, KeyMode, KeyVendor};
use stack_kms_vault::{KeyDerivation, VaultConfig, VaultToken, VaultTransit};
use stack_kms_vendor::derive::wrapped_data_key_aad;
use stack_kms_vendor::{contract, KeyVendorBackend};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};

fn client_with(
    emulator: &TransitEmulator,
    derivation: KeyDerivation,
) -> VaultTransit<TransitEmulator, VaultToken> {
    VaultTransit::new(
        VaultConfig::new(ADDRESS)
            .unwrap()
            .with_batch_size(NonZeroUsize::new(4).unwrap())
            .with_key_derivation(derivation),
        emulator.clone(),
        VaultToken::new(TOKEN),
    )
}

fn kind_of(error: Error) -> BackendErrorKind {
    match error {
        Error::Backend { backend, kind, .. } => {
            assert_eq!(backend.name(), "vault-transit");
            kind
        }
        other => panic!("not a backend error: {other:?}"),
    }
}

#[tokio::test]
async fn vault_transit_meets_the_contract_with_a_non_derived_key() {
    let emulator = TransitEmulator::new();
    contract::run(|| client_with(&emulator, KeyDerivation::Detect), KEY).await;
}

#[tokio::test]
async fn vault_transit_meets_the_contract_with_a_derived_key() {
    let emulator = TransitEmulator::new();
    contract::run(
        || client_with(&emulator, KeyDerivation::Detect),
        DERIVED_KEY,
    )
    .await;
}

#[tokio::test]
async fn vault_transit_meets_the_contract_with_the_derivation_configured() {
    let emulator = TransitEmulator::new();
    contract::run(
        || client_with(&emulator, KeyDerivation::Derived),
        DERIVED_KEY,
    )
    .await;
    contract::run(|| client_with(&emulator, KeyDerivation::NotDerived), KEY).await;
}

#[tokio::test]
async fn a_wrapped_key_opens_only_under_its_own_aad() {
    let emulator = TransitEmulator::new();
    // A non-derived key configured as derived: Vault ignores the context,
    // so only the bound key refuses other associated data.
    for (key, derivation) in [
        (KEY, KeyDerivation::Detect),
        (DERIVED_KEY, KeyDerivation::Detect),
        (KEY, KeyDerivation::Derived),
    ] {
        let vault = client_with(&emulator, derivation);
        let id = Uuid::from_u128(1);
        let aad = wrapped_data_key_aad(id, &[1u8; 16], "users/email");
        let wrapped = vault
            .wrap(key, &Protected::new([9u8; 32]), &aad)
            .await
            .unwrap();
        assert_eq!(
            vault.unwrap(key, &wrapped, &aad).await.unwrap().risky_ref(),
            &[9u8; 32]
        );
        let other = wrapped_data_key_aad(id, &[1u8; 16], "users/name");
        let error = vault.unwrap(key, &wrapped, &other).await.unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::InvalidCiphertext, "{key}");
    }
}

#[tokio::test]
async fn a_derived_key_gets_the_aad_as_context_and_another_key_gets_none() {
    let emulator = TransitEmulator::new();
    let vault = client_with(&emulator, KeyDerivation::Detect);
    let aad = b"the associated data";
    let _ = vault
        .wrap(DERIVED_KEY, &Protected::new([1u8; 32]), aad)
        .await
        .unwrap();
    let _ = vault
        .wrap(KEY, &Protected::new([1u8; 32]), aad)
        .await
        .unwrap();
    let requests = emulator.requests();
    let encrypts: Vec<_> = requests
        .iter()
        .filter(|(_, path, _)| path.starts_with("transit/encrypt/"))
        .collect();
    assert_eq!(encrypts.len(), 2);
    assert_eq!(
        encrypts[0].2["batch_input"][0]["context"],
        "dGhlIGFzc29jaWF0ZWQgZGF0YQ=="
    );
    assert!(encrypts[1].2["batch_input"][0].get("context").is_none());
    // The key's derivation is read once per key.
    let reads = requests
        .iter()
        .filter(|(method, path, _)| method == "GET" && path.starts_with("transit/keys/"))
        .count();
    assert_eq!(reads, 2);
    let _ = vault
        .wrap(KEY, &Protected::new([1u8; 32]), aad)
        .await
        .unwrap();
    assert_eq!(
        emulator
            .requests()
            .iter()
            .filter(|(method, _, _)| method == "GET")
            .count(),
        2
    );
}

#[tokio::test]
async fn detect_refuses_a_missing_key_and_a_key_that_is_not_an_aead() {
    let emulator = TransitEmulator::new();
    emulator.add_key("rsa", false, "rsa-2048");
    let vault = client_with(&emulator, KeyDerivation::Detect);
    let error = vault
        .wrap("no-such-key", &Protected::new([1u8; 32]), b"a")
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::NotFound);
    let error = vault
        .wrap("rsa", &Protected::new([1u8; 32]), b"a")
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::AccessDenied);
    // Nothing was encrypted.
    assert!(emulator
        .requests()
        .iter()
        .all(|(_, path, _)| !path.contains("/encrypt/")));
}

#[tokio::test]
async fn a_key_reference_that_is_not_a_key_name_is_refused_before_any_call() {
    let emulator = TransitEmulator::new();
    let vault = client_with(&emulator, KeyDerivation::NotDerived);
    for bad in ["", "a/b", "..", "a?b", "a b", "../../sys/seal"] {
        let error = vault
            .wrap(bad, &Protected::new([1u8; 32]), b"a")
            .await
            .unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::NotFound, "{bad:?}");
    }
    assert!(emulator.requests().is_empty());
}

#[tokio::test]
async fn a_wrapped_key_that_is_not_one_is_refused_before_any_call() {
    let emulator = TransitEmulator::new();
    let vault = client_with(&emulator, KeyDerivation::NotDerived);
    for bad in [&b""[..], b"vault:v1:AAAA", &[2, 0, 0, 0, 1, 7]] {
        let error = vault.unwrap(KEY, bad, b"a").await.unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::InvalidCiphertext);
    }
    assert!(emulator.requests().is_empty());
}

#[tokio::test]
async fn rewrap_keeps_the_key_and_its_binding() {
    let emulator = TransitEmulator::new();
    for key in [KEY, DERIVED_KEY] {
        let vault = client_with(&emulator, KeyDerivation::Detect);
        let wrapped = vault
            .wrap(key, &Protected::new([4u8; 32]), b"aad")
            .await
            .unwrap();
        let rewrapped = vault.rewrap(key, &wrapped, b"aad").await.unwrap();
        assert_eq!(
            vault
                .unwrap(key, &rewrapped, b"aad")
                .await
                .unwrap()
                .risky_ref(),
            &[4u8; 32]
        );
        assert!(vault.unwrap(key, &rewrapped, b"other").await.is_err());
    }
}

#[tokio::test]
async fn the_namespace_is_sent_on_every_request() {
    let emulator = TransitEmulator::new().with_namespace("admin/team-a");
    let vault = VaultTransit::new(
        VaultConfig::new(ADDRESS)
            .unwrap()
            .with_namespace("admin/team-a")
            .unwrap(),
        emulator.clone(),
        VaultToken::new(TOKEN),
    );
    let wrapped = vault
        .wrap(KEY, &Protected::new([3u8; 32]), b"a")
        .await
        .unwrap();
    let _ = vault.unwrap(KEY, &wrapped, b"a").await.unwrap();
    // The emulator asserts the header on each request.
    assert_eq!(emulator.requests().len(), 3);
}

#[tokio::test]
async fn the_backend_reports_vault_and_batches_and_sleeps_on_its_transport() {
    let emulator = TransitEmulator::new();
    let vault = fixture_client(emulator.clone());
    assert_eq!(vault.vendor(), KeyVendor::Vault);
    assert!(vault.supports_mode(KeyMode::Wrapped));
    assert!(vault.supports_mode(KeyMode::Derived));
    assert_eq!(vault.batch_limit().unwrap().get(), 250);
    vault.sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(emulator.sleeps(), [std::time::Duration::from_millis(50)]);
}
