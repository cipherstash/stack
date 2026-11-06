//! Each Vault call and each error mapping, against HTTP exchanges recorded
//! from `vault server -dev` 1.20 (`tests/fixtures/*.json`).
//!
//! Every fixture was recorded by `tests/vault_dev.rs`'s
//! `records_the_fixtures`, except `kubernetes_login.json` (a dev server has
//! no Kubernetes; the response is the AppRole login response in the
//! Kubernetes auth shape) and the errors whose name says "written by hand".
//! Each request side is pinned: the URL, the headers and the body, which
//! includes the bound key and the context.

mod common;

use common::{fixture_client, load, Fixture, FixtureResponse, Replay, DERIVED_KEY, KEY, TOKEN};
use serde::Deserialize;
use stack_kms::{BackendErrorKind, Error, KeyMode, KeyVendor};
use stack_kms_vault::{
    AppRoleLogin, AuthError, CachedToken, KeyDerivation, KubernetesLogin, TokenProvider,
    VaultConfig, VaultToken, VaultTransit,
};
use stack_kms_vendor::derive::{record_key_aad, wrapped_data_key_aad};
use stack_kms_vendor::{
    KeyVendorBackend, TransportError, UnwrapItem, VendorRequest, VendorResponse, VendorTransport,
    WrapItem,
};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};

const KEYSET: Uuid = Uuid::from_u128(0x0f1e2d3c_4b5a_6978_8796_a5b4c3d2e1f0);

fn record_aad() -> Vec<u8> {
    record_key_aad(KEYSET, KeyVendor::Vault, KeyMode::Wrapped)
}

fn data_aads() -> Vec<Vec<u8>> {
    (0u8..3)
        .map(|n| wrapped_data_key_aad(KEYSET, &[n; 16], "users/email"))
        .collect()
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

fn replay(name: &str) -> Replay {
    Replay::new().expect_all(load(name))
}

/// The stored wrapped key of the `index`th ciphertext a fixture's last
/// response returns.
fn wrapped_of(name: &str, index: usize) -> Vec<u8> {
    let fixtures: Vec<Fixture> = load(name);
    let body = &fixtures.last().unwrap().response.body;
    let text = body["data"]["batch_results"][index]["ciphertext"]
        .as_str()
        .unwrap();
    stack_kms_vault::compact_ciphertext(text).unwrap()
}

async fn check_single(prefix: &str, key: &str) {
    let vault = fixture_client(replay(&format!("{prefix}encrypt.json")));
    let wrapped = vault
        .wrap(key, &Protected::new([0x42u8; 32]), &record_aad())
        .await
        .unwrap();
    assert_eq!(wrapped, wrapped_of(&format!("{prefix}encrypt.json"), 0));
    assert!(vault.transport().is_done());

    let vault = fixture_client(replay(&format!("{prefix}decrypt.json")));
    let opened = vault.unwrap(key, &wrapped, &record_aad()).await.unwrap();
    assert_eq!(opened.risky_ref(), &[0x42u8; 32]);
    assert!(vault.transport().is_done());
}

async fn check_batch(prefix: &str, key: &str) {
    let aads = data_aads();
    let keys: Vec<_> = (0u8..3).map(|n| Protected::new([0x40 + n; 32])).collect();
    let vault = fixture_client(replay(&format!("{prefix}encrypt_batch.json")));
    let items: Vec<_> = keys
        .iter()
        .zip(&aads)
        .map(|(key, aad)| WrapItem { key, aad })
        .collect();
    let wrapped = vault.wrap_batch(key, &items).await.unwrap();
    assert_eq!(wrapped.len(), 3);
    for (index, wrapped) in wrapped.iter().enumerate() {
        assert_eq!(
            wrapped,
            &wrapped_of(&format!("{prefix}encrypt_batch.json"), index)
        );
    }

    let vault = fixture_client(replay(&format!("{prefix}decrypt_batch.json")));
    let items: Vec<_> = wrapped
        .iter()
        .zip(&aads)
        .map(|(wrapped, aad)| UnwrapItem { wrapped, aad })
        .collect();
    let opened = vault.unwrap_batch(key, &items).await.unwrap();
    for (n, key) in opened.iter().enumerate() {
        assert_eq!(key.risky_ref(), &[0x40 + n as u8; 32]);
    }
    assert!(vault.transport().is_done());
}

#[tokio::test]
async fn encrypt_and_decrypt_with_a_non_derived_key() {
    check_single("", KEY).await;
}

#[tokio::test]
async fn encrypt_and_decrypt_with_a_derived_key() {
    check_single("derived_", DERIVED_KEY).await;
}

#[tokio::test]
async fn a_batch_is_one_call() {
    check_batch("", KEY).await;
}

#[tokio::test]
async fn a_batch_with_a_derived_key_is_one_call() {
    check_batch("derived_", DERIVED_KEY).await;
}

#[tokio::test]
async fn the_fixture_ciphertexts_name_the_key_version() {
    let fixtures: Vec<Fixture> = load("encrypt.json");
    let text = fixtures[1].response.body["data"]["batch_results"][0]["ciphertext"]
        .as_str()
        .unwrap();
    assert!(text.starts_with("vault:v1:"));
}

#[tokio::test]
async fn a_decrypt_under_other_associated_data_is_refused_by_the_bound_key() {
    // Vault decrypts it (a non-derived key has no context to check); the
    // bound key does not open under other associated data.
    let wrapped = wrapped_of("encrypt.json", 0);
    let other = record_key_aad(KEYSET, KeyVendor::Vault, KeyMode::Derived);
    let fixtures: Vec<Fixture> = load("decrypt.json");
    let vault = VaultTransit::new(
        VaultConfig::new(common::ADDRESS)
            .unwrap()
            .with_key_derivation(KeyDerivation::NotDerived),
        Replay::new().answer(fixtures[1].response.to_response()),
        VaultToken::new(TOKEN),
    );
    let error = vault.unwrap(KEY, &wrapped, &other).await.unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::InvalidCiphertext);
}

#[tokio::test]
async fn rewrap_moves_to_the_latest_version() {
    let fixtures: Vec<Fixture> = load("rewrap.json");
    let text = fixtures[0].request.body["batch_input"][0]["ciphertext"]
        .as_str()
        .unwrap();
    let wrapped = stack_kms_vault::compact_ciphertext(text).unwrap();
    let vault = VaultTransit::new(
        VaultConfig::new(common::ADDRESS)
            .unwrap()
            .with_key_derivation(KeyDerivation::NotDerived),
        Replay::new().expect_all(fixtures),
        VaultToken::new(TOKEN),
    );
    let rewrapped = vault.rewrap(KEY, &wrapped, &record_aad()).await.unwrap();
    assert_eq!(&wrapped[1..5], &1u32.to_be_bytes());
    assert_eq!(&rewrapped[1..5], &2u32.to_be_bytes());
}

#[tokio::test]
async fn approle_login() {
    let login = AppRoleLogin::new(
        &VaultConfig::new(common::ADDRESS).unwrap(),
        replay("approle_login.json"),
        "fixture-role-id",
        "fixture-secret-id",
    );
    let token = login.token().await.unwrap();
    assert!(token.token().starts_with("hvs."));
    assert_eq!(token.lease(), Some(std::time::Duration::from_secs(20 * 60)));
    assert!(login.transport().is_done());
}

#[tokio::test]
async fn kubernetes_login_reads_the_token_file_and_sends_the_namespace() {
    let path = std::env::temp_dir().join(format!("stack-kms-vault-jwt-{}", Uuid::new_v4()));
    std::fs::write(&path, "fixture.jwt.token\n").unwrap();
    let config = VaultConfig::new(common::ADDRESS)
        .unwrap()
        .with_namespace("admin")
        .unwrap();
    let login = KubernetesLogin::new(&config, replay("kubernetes_login.json"), "cipherstash")
        .with_token_path(&path);
    let token = login.token().await.unwrap();
    assert_eq!(token.token(), "hvs.fixture-kubernetes-token");
    assert_eq!(token.lease(), Some(std::time::Duration::from_secs(3600)));
    std::fs::remove_file(&path).unwrap();

    let error = login.token().await.unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::AccessDenied);
    assert!(!error.to_string().contains("fixture.jwt.token"));
}

#[tokio::test]
async fn a_refused_login_is_access_denied_and_says_why() {
    let login = AppRoleLogin::new(
        &VaultConfig::new(common::ADDRESS).unwrap(),
        Replay::new().answer(VendorResponse::new(
            400,
            br#"{"errors":["invalid role or secret ID"]}"#.to_vec(),
        )),
        "role",
        "the-secret-id",
    );
    let error = login.token().await.unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::AccessDenied);
    assert!(error.to_string().contains("invalid role or secret ID"));
    assert!(!error.to_string().contains("the-secret-id"));

    for (status, kind) in [
        (429, BackendErrorKind::Throttled),
        (503, BackendErrorKind::Unavailable),
    ] {
        let login = AppRoleLogin::new(
            &VaultConfig::new(common::ADDRESS).unwrap(),
            Replay::new().answer(VendorResponse::new(status, b"{}".to_vec())),
            "role",
            "secret",
        );
        assert_eq!(login.token().await.unwrap_err().kind(), kind);
    }
}

#[derive(Deserialize)]
struct ErrorCase {
    name: String,
    response: FixtureResponse,
    kind: String,
}

#[tokio::test]
async fn every_recorded_error_maps_to_its_kind() {
    let cases: Vec<ErrorCase> = load("errors.json");
    assert!(cases.len() >= 12);
    let wrapped = wrapped_of("encrypt.json", 0);
    for case in cases {
        let vault = VaultTransit::new(
            VaultConfig::new(common::ADDRESS)
                .unwrap()
                .with_key_derivation(KeyDerivation::NotDerived),
            Replay::new().answer(case.response.to_response()),
            VaultToken::new(TOKEN),
        );
        let error = vault
            .unwrap(KEY, &wrapped, &record_aad())
            .await
            .unwrap_err();
        let message = format!("{error:?}");
        assert_eq!(
            format!("{:?}", kind_of(error)),
            case.kind,
            "{}: {message}",
            case.name
        );
    }
}

/// A transport that never gets a response.
struct Down;

impl VendorTransport for Down {
    async fn send(&self, _request: VendorRequest) -> Result<VendorResponse, TransportError> {
        Err(TransportError("connection refused".into()))
    }

    async fn sleep(&self, _duration: std::time::Duration) {}
}

#[tokio::test]
async fn no_response_is_unavailable() {
    let error = fixture_client(Down)
        .unwrap(KEY, &wrapped_of("encrypt.json", 0), &record_aad())
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::Unavailable);
}

struct NoToken;

impl TokenProvider for NoToken {
    async fn token(&self) -> Result<VaultToken, AuthError> {
        Err(AuthError::access_denied("none configured"))
    }
}

#[tokio::test]
async fn no_token_is_access_denied_and_sends_nothing() {
    let vault = VaultTransit::new(
        VaultConfig::new(common::ADDRESS).unwrap(),
        Replay::new(),
        NoToken,
    );
    let error = vault
        .wrap(KEY, &Protected::new([1u8; 32]), &record_aad())
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::AccessDenied);
}

#[tokio::test]
async fn an_unreadable_success_is_unavailable() {
    let wrapped = wrapped_of("encrypt.json", 0);
    for body in [
        b"not json".to_vec(),
        br#"{"data":null}"#.to_vec(),
        br#"{"data":{"batch_results":[]}}"#.to_vec(),
        br#"{"data":{"batch_results":[{"plaintext":"not base64!"}]}}"#.to_vec(),
        br#"{"data":{"batch_results":[{}]}}"#.to_vec(),
    ] {
        let vault = VaultTransit::new(
            VaultConfig::new(common::ADDRESS)
                .unwrap()
                .with_key_derivation(KeyDerivation::NotDerived),
            Replay::new().answer(VendorResponse::new(200, body)),
            VaultToken::new(TOKEN),
        );
        let error = vault
            .unwrap(KEY, &wrapped, &record_aad())
            .await
            .unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::Unavailable);
    }
    for body in [
        br#"{"data":{"batch_results":[{"ciphertext":"not a vault ciphertext"}]}}"#.to_vec(),
        br#"{"data":{"batch_results":[{}]}}"#.to_vec(),
    ] {
        let vault = VaultTransit::new(
            VaultConfig::new(common::ADDRESS)
                .unwrap()
                .with_key_derivation(KeyDerivation::NotDerived),
            Replay::new().answer(VendorResponse::new(200, body)),
            VaultToken::new(TOKEN),
        );
        let error = vault
            .wrap(KEY, &Protected::new([1u8; 32]), b"a")
            .await
            .unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::Unavailable);
    }
}

#[tokio::test]
async fn a_plaintext_that_is_not_a_bound_key_is_refused() {
    // 32 bytes: a bare key, not a bound key this crate wrapped.
    let body = br#"{"data":{"batch_results":[{"plaintext":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}]}}"#;
    let vault = VaultTransit::new(
        VaultConfig::new(common::ADDRESS)
            .unwrap()
            .with_key_derivation(KeyDerivation::NotDerived),
        Replay::new().answer(VendorResponse::new(200, body.to_vec())),
        VaultToken::new(TOKEN),
    );
    let error = vault
        .unwrap(KEY, &wrapped_of("encrypt.json", 0), &record_aad())
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::InvalidCiphertext);
}

#[tokio::test]
async fn a_403_drops_the_cached_token() {
    let emulator = common::TransitEmulator::new();
    let config = VaultConfig::new(common::ADDRESS).unwrap();
    let vault = VaultTransit::new(
        config.clone(),
        emulator.clone(),
        CachedToken::new(AppRoleLogin::new(
            &config,
            emulator.clone(),
            "fixture-role-id",
            "fixture-secret-id",
        )),
    );
    let wrapped = vault
        .wrap(KEY, &Protected::new([2u8; 32]), b"a")
        .await
        .unwrap();
    assert_eq!(emulator.logins(), 1);
    emulator.revoke_tokens();
    let error = vault.unwrap(KEY, &wrapped, b"a").await.unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::AccessDenied);
    // The next call logs in again.
    let opened = vault.unwrap(KEY, &wrapped, b"a").await.unwrap();
    assert_eq!(opened.risky_ref(), &[2u8; 32]);
    assert_eq!(emulator.logins(), 2);
}
