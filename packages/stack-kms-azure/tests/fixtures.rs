//! Each Managed HSM call, each credential exchange and each error mapping,
//! against fixed HTTP exchanges (`tests/fixtures/*.json`).
//!
//! Microsoft publishes no Managed HSM emulator, and we have no live
//! instance, so no fixture was recorded from Azure. Every response is
//! written by hand in the documented Managed HSM, Entra ID and managed
//! identity shapes. Every request side was computed by a separate script,
//! independently of this client (base64url, the associated data frame, the
//! bound key digest, the form bodies), and the client must send exactly
//! those bytes. The A256KW ciphertexts were made by an RFC 3394
//! implementation over `openssl enc -aes-256-ecb`, under the RFC's example
//! key, which is no one's key. `tests/live.rs` is the test against a real
//! Managed HSM, and it is off until a live instance is available.

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64ct::{Base64UrlUnpadded, Encoding};
use common::{
    fixture_client, issued_at, kw_unwrap, kw_wrap, load, replay, Fixture, FixtureResponse,
    ManagedHsmEmulator, Replay, CLIENT_ID, CLIENT_SECRET, OCT_KEY, OCT_OLD_VERSION, OCT_VERSION,
    TENANT, TEST_ONLY_VENDOR_KEY, TOKEN,
};
use serde::Deserialize;
use stack_kms::{BackendErrorKind, Error, KeyMode, KeyVendor};
use stack_kms_azure::{
    compact_ciphertext, split_wrapped_key, wrap_plaintext, wrapped_key_version, AccessToken,
    AuthError, AzureManagedHsm, CachedToken, ClientSecretLogin, DefaultCredentials, EnvLookup,
    ManagedIdentityLogin, TokenProvider, WorkloadIdentityLogin, MANAGED_HSM_SCOPE,
};
use stack_kms_vendor::derive::record_key_aad;
use stack_kms_vendor::{
    KeyVendorBackend, TransportError, VendorRequest, VendorResponse, VendorTransport,
};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};

const KEYSET: Uuid = Uuid::from_u128(0x0f1e2d3c_4b5a_6978_8796_a5b4c3d2e1f0);

/// The associated data of the root key of keyset `KEYSET + n`.
fn data_aad(n: u8) -> Vec<u8> {
    let keyset = Uuid::from_u128(KEYSET.as_u128() + u128::from(n));
    record_key_aad(keyset, KeyVendor::Azure, KeyMode::Derived)
}

fn kind_of(error: Error) -> BackendErrorKind {
    match error {
        Error::Backend { backend, kind, .. } => {
            assert_eq!(backend.name(), "azure-managed-hsm");
            kind
        }
        other => panic!("not a backend error: {other:?}"),
    }
}

fn b64(value: &serde_json::Value) -> Vec<u8> {
    Base64UrlUnpadded::decode_vec(value.as_str().unwrap()).unwrap()
}

/// The stored wrapped key of a fixture's last (wrapkey) exchange.
fn wrapped_of(name: &str, version: &str) -> Vec<u8> {
    let fixtures: Vec<Fixture> = load(name);
    let body = &fixtures.last().unwrap().response.body;
    compact_ciphertext(version, &b64(&body["value"]))
}

fn hsm_wrapped() -> Vec<u8> {
    wrapped_of("hsm_wrap.json", OCT_VERSION)
}

#[tokio::test]
async fn an_oct_hsm_key_wraps_with_a256kw_and_unwraps() {
    let kms = fixture_client(replay("hsm_wrap.json"));
    let wrapped = kms
        .wrap(OCT_KEY, &Protected::new([0x44u8; 32]), &data_aad(2))
        .await
        .unwrap();
    assert_eq!(wrapped, hsm_wrapped());
    assert_eq!(wrapped_key_version(&wrapped), Some(OCT_VERSION));
    // 72 bytes wrapped by A256KW are 80.
    assert_eq!(split_wrapped_key(&wrapped).unwrap().ciphertext.len(), 80);
    assert!(kms.transport().is_done());

    let kms = fixture_client(replay("hsm_unwrap.json"));
    let opened = kms.unwrap(OCT_KEY, &wrapped, &data_aad(2)).await.unwrap();
    assert_eq!(opened.risky_ref(), &[0x44u8; 32]);
    assert!(kms.transport().is_done());

    // The unwrap names the stored version, whatever the key reference pins.
    let kms = fixture_client(replay("hsm_unwrap.json"));
    let pinned = format!("{OCT_KEY}/{OCT_OLD_VERSION}");
    let opened = kms.unwrap(&pinned, &wrapped, &data_aad(2)).await.unwrap();
    assert_eq!(opened.risky_ref(), &[0x44u8; 32]);
}

#[tokio::test]
async fn the_key_is_read_once_per_client() {
    let fixtures: Vec<Fixture> = load("hsm_wrap.json");
    let wrap_again = fixtures[1].clone();
    let kms = fixture_client(
        Replay::new()
            .expect_all(fixtures)
            .expect_all(vec![wrap_again]),
    );
    for _ in 0..2 {
        let wrapped = kms
            .wrap(OCT_KEY, &Protected::new([0x44u8; 32]), &data_aad(2))
            .await
            .unwrap();
        assert_eq!(wrapped, hsm_wrapped());
    }
    assert!(kms.transport().is_done());
}

#[tokio::test]
async fn a_pinned_version_reads_no_key() {
    let fixtures: Vec<Fixture> = load("hsm_wrap.json");
    let kms = fixture_client(Replay::new().expect_all(vec![fixtures[1].clone()]));
    let pinned = format!("{OCT_KEY}/{OCT_VERSION}");
    let wrapped = kms
        .wrap(&pinned, &Protected::new([0x44u8; 32]), &data_aad(2))
        .await
        .unwrap();
    assert_eq!(wrapped, hsm_wrapped());
    assert!(kms.transport().is_done());
}

/// The fixture ciphertexts are real: the test-only key opens them to the
/// plaintext the client sends, and the emulator's key wrap is RFC 3394's.
#[test]
fn the_fixture_ciphertexts_open_under_the_test_only_keys() {
    let fixtures: Vec<Fixture> = load("hsm_wrap.json");
    let plaintext = b64(&fixtures[1].request.body["value"]);
    assert_eq!(
        plaintext,
        wrap_plaintext(&Protected::new([0x44u8; 32]), &data_aad(2)).to_vec()
    );
    let ciphertext = b64(&fixtures[1].response.body["value"]);
    assert_eq!(
        kw_unwrap(&TEST_ONLY_VENDOR_KEY, &ciphertext).unwrap(),
        plaintext
    );
    assert_eq!(kw_wrap(&TEST_ONLY_VENDOR_KEY, &plaintext), ciphertext);

    // RFC 3394, 4.6: 256 bits of key data with a 256-bit key (the vendor key).
    let key_data: Vec<u8> = (0..16u8)
        .map(|i| i * 0x11)
        .chain(0..16u8)
        .collect::<Vec<_>>();
    let expected = [
        0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4, 0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8,
        0x26, 0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26, 0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99,
        0xF4, 0x3B, 0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
    ];
    assert_eq!(kw_wrap(&TEST_ONLY_VENDOR_KEY, &key_data), expected);
    assert_eq!(
        kw_unwrap(&TEST_ONLY_VENDOR_KEY, &expected).unwrap(),
        key_data
    );
}

fn fixed_clock() -> stack_kms_azure::Clock {
    Arc::new(issued_at)
}

#[tokio::test]
async fn a_client_secret_is_exchanged_for_a_token() {
    let login = ClientSecretLogin::new(
        TENANT,
        CLIENT_ID,
        CLIENT_SECRET,
        replay("client_secret_token.json"),
    )
    .unwrap();
    let token = login.token(MANAGED_HSM_SCOPE).await.unwrap();
    assert_eq!(token.token(), "fixture-client-secret-token");
    assert_eq!(token.expires_in(), Some(Duration::from_secs(3599)));
    assert!(login.transport().is_done());
}

#[tokio::test]
async fn a_federated_token_is_exchanged_for_a_token() {
    let path = std::env::temp_dir().join(format!("stack-kms-azure-fed-{}", Uuid::new_v4()));
    std::fs::write(&path, "fixture.federated.token\n").unwrap();
    let login = WorkloadIdentityLogin::new(
        TENANT,
        CLIENT_ID,
        &path,
        replay("workload_identity_token.json"),
    )
    .unwrap();
    let token = login.token(MANAGED_HSM_SCOPE).await.unwrap();
    assert_eq!(token.token(), "fixture-workload-identity-token");
    assert!(login.transport().is_done());

    std::fs::remove_file(&path).unwrap();
    let error = login.token(MANAGED_HSM_SCOPE).await.unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::AccessDenied);
    assert!(error.to_string().contains("cannot read"));
}

#[tokio::test]
async fn imds_gives_a_user_assigned_identity_token() {
    let login = ManagedIdentityLogin::imds(replay("imds_token.json"))
        .with_client_id("test-only-user-assigned-id");
    let token = login.token(MANAGED_HSM_SCOPE).await.unwrap();
    assert_eq!(token.token(), "fixture-imds-token");
    assert_eq!(token.expires_in(), Some(Duration::from_secs(86399)));
    assert!(login.transport().is_done());
}

#[tokio::test]
async fn app_service_gives_a_token_that_expires_on_a_time() {
    let login = ManagedIdentityLogin::app_service(
        "http://127.0.0.1:41056/msi/token",
        "fixture-identity-header",
        replay("app_service_token.json"),
    )
    .unwrap()
    .with_clock(fixed_clock());
    let token = login.token(MANAGED_HSM_SCOPE).await.unwrap();
    assert_eq!(token.token(), "fixture-app-service-token");
    assert_eq!(token.expires_in(), Some(Duration::from_secs(3600)));
    assert!(login.transport().is_done());
}

#[tokio::test]
async fn a_refused_secret_is_access_denied_and_says_why() {
    let login = ClientSecretLogin::new(
        TENANT,
        CLIENT_ID,
        "the-wrong-secret",
        Replay::new().answer(VendorResponse::new(
            401,
            br#"{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}"#.to_vec(),
        )),
    )
    .unwrap();
    let error = login.token(MANAGED_HSM_SCOPE).await.unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::AccessDenied);
    assert!(error.to_string().contains("AADSTS7000215"));
    assert!(!error.to_string().contains("the-wrong-secret"));
}

fn env(pairs: &[(&str, &str)]) -> EnvLookup {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    Arc::new(move |name| map.get(name).cloned())
}

#[tokio::test]
async fn the_default_credentials_come_from_the_environment() {
    let secret = [
        ("AZURE_TENANT_ID", TENANT),
        ("AZURE_CLIENT_ID", CLIENT_ID),
        ("AZURE_CLIENT_SECRET", CLIENT_SECRET),
    ];

    let credentials = DefaultCredentials::from_env_lookup(
        ManagedHsmEmulator::new(),
        &env(&[
            ("AZURE_MANAGED_HSM_ACCESS_TOKEN", "static-token"),
            secret[0],
            secret[1],
            secret[2],
        ]),
    )
    .unwrap();
    assert!(matches!(credentials, DefaultCredentials::Token(_)));
    assert_eq!(
        credentials.token(MANAGED_HSM_SCOPE).await.unwrap().token(),
        "static-token"
    );

    let emulator = ManagedHsmEmulator::new();
    let credentials = DefaultCredentials::from_env_lookup(emulator.clone(), &env(&secret)).unwrap();
    assert!(matches!(credentials, DefaultCredentials::ClientSecret(_)));
    assert_eq!(
        credentials.token(MANAGED_HSM_SCOPE).await.unwrap().token(),
        "fixture-exchanged-token-1"
    );
    // Cached per scope.
    let _ = credentials.token(MANAGED_HSM_SCOPE).await.unwrap();
    assert_eq!(emulator.exchanges(), 1);
    let _ = credentials
        .token("https://managedhsm.azure.cn/.default")
        .await
        .unwrap();
    assert_eq!(emulator.exchanges(), 2);

    let credentials = DefaultCredentials::from_env_lookup(
        ManagedHsmEmulator::new(),
        &env(&[
            ("AZURE_TENANT_ID", TENANT),
            ("AZURE_CLIENT_ID", CLIENT_ID),
            ("AZURE_FEDERATED_TOKEN_FILE", "/var/run/secrets/token"),
        ]),
    )
    .unwrap();
    assert!(matches!(
        credentials,
        DefaultCredentials::WorkloadIdentity(_)
    ));

    let error = DefaultCredentials::from_env_lookup(
        ManagedHsmEmulator::new(),
        &env(&[
            ("AZURE_TENANT_ID", TENANT),
            ("AZURE_CLIENT_ID", CLIENT_ID),
            ("AZURE_CLIENT_CERTIFICATE_PATH", "/tmp/cert.pem"),
        ]),
    )
    .unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::AccessDenied);
    assert!(error.to_string().contains("not supported"));

    let credentials = DefaultCredentials::from_env_lookup(
        ManagedHsmEmulator::new(),
        &env(&[
            ("IDENTITY_ENDPOINT", "http://127.0.0.1:41056/msi/token"),
            ("IDENTITY_HEADER", "h"),
        ]),
    )
    .unwrap();
    let DefaultCredentials::ManagedIdentity(login) = credentials else {
        panic!("not a managed identity");
    };
    assert!(login
        .inner()
        .url(MANAGED_HSM_SCOPE)
        .starts_with("http://127.0.0.1:41056/msi/token?api-version=2019-08-01"));

    let credentials = DefaultCredentials::from_env_lookup(
        ManagedHsmEmulator::new(),
        &env(&[("AZURE_CLIENT_ID", "user-assigned")]),
    )
    .unwrap();
    let DefaultCredentials::ManagedIdentity(login) = credentials else {
        panic!("not a managed identity");
    };
    assert_eq!(
        login.inner().url(MANAGED_HSM_SCOPE),
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01\
         &resource=https%3A%2F%2Fmanagedhsm.azure.net&client_id=user-assigned"
    );

    for bad in [
        vec![
            ("IDENTITY_ENDPOINT", "http://evil.example/token"),
            ("IDENTITY_HEADER", "h"),
        ],
        vec![
            ("AZURE_TENANT_ID", "a/b"),
            ("AZURE_CLIENT_ID", CLIENT_ID),
            ("AZURE_CLIENT_SECRET", CLIENT_SECRET),
        ],
        vec![
            secret[0],
            secret[1],
            secret[2],
            ("AZURE_AUTHORITY_HOST", "http://login.example"),
        ],
    ] {
        let error =
            DefaultCredentials::from_env_lookup(ManagedHsmEmulator::new(), &env(&bad)).unwrap_err();
        assert_eq!(error.kind(), BackendErrorKind::AccessDenied, "{bad:?}");
    }
}

#[derive(Deserialize)]
struct ErrorCase {
    name: String,
    response: FixtureResponse,
    kind: String,
}

#[tokio::test]
async fn every_written_error_maps_to_its_kind() {
    let cases: Vec<ErrorCase> = load("errors.json");
    assert!(cases.len() >= 13);
    let wrapped = hsm_wrapped();
    for case in cases {
        let kms = fixture_client(Replay::new().answer(case.response.to_response()));
        let error = kms
            .unwrap(OCT_KEY, &wrapped, &data_aad(0))
            .await
            .unwrap_err();
        let message = format!("{error:?}");
        assert!(!message.contains(TOKEN), "{message}");
        assert_eq!(
            format!("{:?}", kind_of(error)),
            case.kind,
            "{}: {message}",
            case.name
        );
    }
}

#[tokio::test]
async fn a_throttle_waits_for_retry_after_first() {
    let cases: Vec<ErrorCase> = load("errors.json");
    let throttled = cases.iter().find(|case| case.name == "throttled").unwrap();
    let kms = fixture_client(Replay::new().answer(throttled.response.to_response()));
    let error = kms
        .unwrap(OCT_KEY, &hsm_wrapped(), &data_aad(0))
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::Throttled);
    assert_eq!(kms.transport().sleeps(), [Duration::from_secs(1)]);

    // A 503 with Retry-After does not wait: the adapter does not retry it.
    let unavailable = cases
        .iter()
        .find(|case| case.name == "service unavailable")
        .unwrap();
    let kms = fixture_client(Replay::new().answer(unavailable.response.to_response()));
    let _ = kms
        .unwrap(OCT_KEY, &hsm_wrapped(), &data_aad(0))
        .await
        .unwrap_err();
    assert!(kms.transport().sleeps().is_empty());
}

/// A transport that never gets a response.
struct Down;

impl VendorTransport for Down {
    async fn send(&self, _request: VendorRequest) -> Result<VendorResponse, TransportError> {
        Err(TransportError("connection refused".into()))
    }

    async fn sleep(&self, _duration: Duration) {}
}

#[tokio::test]
async fn no_response_is_unavailable() {
    let error = fixture_client(Down)
        .unwrap(OCT_KEY, &hsm_wrapped(), &data_aad(0))
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::Unavailable);
    let error = ManagedIdentityLogin::imds(Down)
        .token(MANAGED_HSM_SCOPE)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::Unavailable);
}

struct NoToken;

impl TokenProvider for NoToken {
    async fn token(&self, _scope: &str) -> Result<AccessToken, AuthError> {
        Err(AuthError::access_denied("none configured"))
    }
}

#[tokio::test]
async fn no_token_is_access_denied_and_sends_nothing() {
    let kms = AzureManagedHsm::new(Replay::new(), NoToken);
    let error = kms
        .wrap(OCT_KEY, &Protected::new([1u8; 32]), &data_aad(0))
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::AccessDenied);
}

#[tokio::test]
async fn a_key_reference_that_is_not_a_key_id_is_refused_before_any_call() {
    let emulator = ManagedHsmEmulator::new();
    let kms = fixture_client(emulator.clone());
    for bad in [
        "",
        "fixture-oct-key",
        "https://evil.example/keys/fixture-oct-key",
        "https://cipherstash-fixture.managedhsm.azure.net/keys/fixture-oct-key/v1/unwrapkey",
        "https://cipherstash-fixture.managedhsm.azure.net/keys/fixture-oct-key?x=1",
        "http://cipherstash-fixture.managedhsm.azure.net/keys/fixture-oct-key",
        // Azure Key Vault is not supported.
        "https://cipherstash-fixture.vault.azure.net/keys/fixture-rsa-key",
    ] {
        let error = kms
            .wrap(bad, &Protected::new([1u8; 32]), b"a")
            .await
            .unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::NotFound, "{bad:?}");
        let error = kms.unwrap(bad, &hsm_wrapped(), b"a").await.unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::NotFound, "{bad:?}");
    }
    assert!(emulator.requests().is_empty());
}

#[tokio::test]
async fn a_wrapped_key_that_is_not_one_is_refused_before_any_call() {
    let emulator = ManagedHsmEmulator::new();
    let kms = fixture_client(emulator.clone());
    for bad in [&b""[..], &[1, 1, b'a'], &[2, 1, b'a', 7], b"CiQA"] {
        let error = kms.unwrap(OCT_KEY, bad, b"a").await.unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::InvalidCiphertext);
    }
    assert!(emulator.requests().is_empty());
}

fn ok_json(body: serde_json::Value) -> VendorResponse {
    VendorResponse::new(200, body.to_string().into_bytes())
}

fn key_bundle(kid: &str, kty: &str) -> VendorResponse {
    ok_json(serde_json::json!({ "key": { "kid": kid, "kty": kty } }))
}

#[tokio::test]
async fn a_key_read_that_cannot_be_used_is_refused() {
    let current = format!("{OCT_KEY}/{OCT_VERSION}");
    for (response, kind) in [
        // Managed HSM also holds RSA and EC keys; only an oct-HSM key wraps.
        (
            key_bundle(&current, "RSA-HSM"),
            BackendErrorKind::AccessDenied,
        ),
        (
            key_bundle(&current, "EC-HSM"),
            BackendErrorKind::AccessDenied,
        ),
        (key_bundle(&current, "oct"), BackendErrorKind::AccessDenied),
        (
            ok_json(serde_json::json!({ "key": { "kid": current } })),
            BackendErrorKind::AccessDenied,
        ),
        (
            key_bundle(
                "https://other.managedhsm.azure.net/keys/fixture-oct-key/abc",
                "oct-HSM",
            ),
            BackendErrorKind::Unavailable,
        ),
        (
            key_bundle(OCT_KEY, "oct-HSM"),
            BackendErrorKind::Unavailable,
        ),
        (
            ok_json(serde_json::json!({})),
            BackendErrorKind::Unavailable,
        ),
        (
            VendorResponse::new(200, b"not json".to_vec()),
            BackendErrorKind::Unavailable,
        ),
    ] {
        let kms = fixture_client(Replay::new().answer(response));
        let error = kms
            .wrap(OCT_KEY, &Protected::new([1u8; 32]), b"a")
            .await
            .unwrap_err();
        assert_eq!(kind_of(error), kind);
    }
}

#[tokio::test]
async fn a_wrap_response_that_cannot_be_trusted_is_unavailable() {
    let current = format!("{OCT_KEY}/{OCT_VERSION}");
    for body in [
        serde_json::json!({ "kid": current, "value": "" }),
        serde_json::json!({ "kid": current, "value": "+/+/" }),
        serde_json::json!({ "kid": current }),
        serde_json::json!({ "kid": OCT_KEY, "value": "AQID" }),
        serde_json::json!({ "kid": format!("{OCT_KEY}/{OCT_OLD_VERSION}"), "value": "AQID" }),
        serde_json::json!({ "value": "AQID" }),
    ] {
        let kms = fixture_client(
            Replay::new()
                .answer(key_bundle(&current, "oct-HSM"))
                .answer(ok_json(body.clone())),
        );
        let error = kms
            .wrap(OCT_KEY, &Protected::new([1u8; 32]), b"a")
            .await
            .unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::Unavailable, "{body}");
    }
}

#[tokio::test]
async fn an_unwrap_response_that_cannot_be_trusted_is_refused() {
    let plaintext = wrap_plaintext(&Protected::new([7u8; 32]), &data_aad(0));
    let mut padding = plaintext.to_vec();
    padding[71] = 1;
    for (value, kind) in [
        (None, BackendErrorKind::Unavailable),
        (Some("+/+/".to_owned()), BackendErrorKind::Unavailable),
        (
            Some(Base64UrlUnpadded::encode_string(&[7u8; 32])),
            BackendErrorKind::InvalidCiphertext,
        ),
        (
            Some(Base64UrlUnpadded::encode_string(&padding)),
            BackendErrorKind::InvalidCiphertext,
        ),
        (
            Some(Base64UrlUnpadded::encode_string(&wrap_plaintext(
                &Protected::new([7u8; 32]),
                &data_aad(1),
            ))),
            BackendErrorKind::InvalidCiphertext,
        ),
    ] {
        let body = match &value {
            Some(value) => serde_json::json!({ "kid": OCT_KEY, "value": value }),
            None => serde_json::json!({ "kid": OCT_KEY }),
        };
        let kms = fixture_client(Replay::new().answer(ok_json(body)));
        let error = kms
            .unwrap(OCT_KEY, &hsm_wrapped(), &data_aad(0))
            .await
            .unwrap_err();
        assert_eq!(kind_of(error), kind, "{value:?}");
    }
    // The right plaintext, padded or not on the wire, opens.
    let kms = fixture_client(Replay::new().answer(ok_json(serde_json::json!({
        "kid": OCT_KEY,
        "value": format!("{}=", Base64UrlUnpadded::encode_string(&plaintext)),
    }))));
    let opened = kms
        .unwrap(OCT_KEY, &hsm_wrapped(), &data_aad(0))
        .await
        .unwrap();
    assert_eq!(opened.risky_ref(), &[7u8; 32]);
}

#[tokio::test]
async fn a_401_drops_the_cached_token() {
    let emulator = ManagedHsmEmulator::new();
    let kms = AzureManagedHsm::new(
        emulator.clone(),
        CachedToken::new(
            ClientSecretLogin::new(TENANT, CLIENT_ID, CLIENT_SECRET, emulator.clone()).unwrap(),
        ),
    );
    let wrapped = kms
        .wrap(OCT_KEY, &Protected::new([2u8; 32]), b"a")
        .await
        .unwrap();
    assert_eq!(emulator.exchanges(), 1);
    emulator.revoke_tokens();
    let error = kms.unwrap(OCT_KEY, &wrapped, b"a").await.unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::AccessDenied);
    // The next call gets a new token.
    let opened = kms.unwrap(OCT_KEY, &wrapped, b"a").await.unwrap();
    assert_eq!(opened.risky_ref(), &[2u8; 32]);
    assert_eq!(emulator.exchanges(), 2);
}

#[tokio::test]
async fn the_backend_reports_azure_and_sleeps_on_its_transport() {
    let emulator = ManagedHsmEmulator::new();
    let kms = fixture_client(emulator.clone());
    assert_eq!(kms.vendor(), KeyVendor::Azure);
    kms.sleep(Duration::from_millis(50)).await;
    assert_eq!(emulator.sleeps(), [Duration::from_millis(50)]);
}
