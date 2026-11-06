//! Each Cloud KMS call, each credential exchange and each error mapping,
//! against fixed HTTP exchanges (`tests/fixtures/*.json`).
//!
//! Google publishes no Cloud KMS emulator, so no fixture was recorded from
//! Google Cloud. Every response is written by hand in the documented
//! Cloud KMS and OAuth 2.0 shapes. Every request side was computed by a
//! separate script, independently of this client (base64, CRC32C, the
//! associated data frame, and the JWT signed by `openssl dgst -sha256
//! -sign`), and the client must send exactly those bytes. The key that
//! signs the JWT is a TEST-ONLY RSA key generated for these tests
//! (`tests/fixtures/test_only_rsa_key.pkcs8.b64`); it is no one's service
//! account key. `tests/live.rs` runs against real Cloud KMS.

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64ct::{Base64, Encoding};
use common::{
    fixture_client, issued_at, load, replay, test_only_key_pem, test_only_service_account,
    test_only_service_account_json, Fixture, FixtureResponse, KmsEmulator, Replay, EMAIL, KEY,
    KEY_ID,
};
use serde::Deserialize;
use stack_kms::{BackendErrorKind, Error, KeyMode, KeyVendor};
use stack_kms_gcp::crc32c::crc32c;
use stack_kms_gcp::{
    compact_ciphertext, wrapped_key_version, AccessToken, AuthError, CachedToken, Clock,
    DefaultCredentials, EnvLookup, GcpKms, GcpKmsConfig, MetadataServerLogin, ServiceAccountKey,
    ServiceAccountLogin, TokenProvider, CLOUD_KMS_SCOPE,
};
use stack_kms_vendor::derive::wrapped_data_key_aad;
use stack_kms_vendor::{
    KeyVendorBackend, TransportError, VendorRequest, VendorResponse, VendorTransport,
};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};

const KEYSET: Uuid = Uuid::from_u128(0x0f1e2d3c_4b5a_6978_8796_a5b4c3d2e1f0);

fn data_aad(n: u8) -> Vec<u8> {
    wrapped_data_key_aad(KEYSET, &[n; 16], "users/email")
}

fn kind_of(error: Error) -> BackendErrorKind {
    match error {
        Error::Backend { vendor, kind, .. } => {
            assert_eq!(vendor, "gcp-kms");
            kind
        }
        other => panic!("not a backend error: {other:?}"),
    }
}

/// The stored wrapped key of a fixture's encrypt response.
fn wrapped_of(name: &str) -> Vec<u8> {
    let fixtures: Vec<Fixture> = load(name);
    let body = &fixtures[0].response.body;
    let ciphertext = Base64::decode_vec(body["ciphertext"].as_str().unwrap()).unwrap();
    let version = body["name"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    compact_ciphertext(version, &ciphertext)
}

fn fixed_clock() -> Clock {
    Arc::new(issued_at)
}

#[tokio::test]
async fn encrypt_and_decrypt() {
    let kms = fixture_client(replay("encrypt.json"));
    let wrapped = kms
        .wrap(KEY, &Protected::new([0x42u8; 32]), &data_aad(0))
        .await
        .unwrap();
    assert_eq!(wrapped, wrapped_of("encrypt.json"));
    assert_eq!(wrapped_key_version(&wrapped), Some(3));
    assert!(kms.transport().is_done());

    let kms = fixture_client(replay("decrypt.json"));
    let opened = kms.unwrap(KEY, &wrapped, &data_aad(0)).await.unwrap();
    assert_eq!(opened.risky_ref(), &[0x42u8; 32]);
    assert!(kms.transport().is_done());
}

#[tokio::test]
async fn a_version_name_pins_encrypt_and_decrypt_uses_the_key() {
    let pinned = format!("{KEY}/cryptoKeyVersions/2");
    let kms = fixture_client(replay("encrypt_pinned_version.json"));
    let wrapped = kms
        .wrap(&pinned, &Protected::new([0x43u8; 32]), &data_aad(1))
        .await
        .unwrap();
    assert_eq!(wrapped, wrapped_of("encrypt_pinned_version.json"));
    assert_eq!(wrapped_key_version(&wrapped), Some(2));

    // Decrypt names the crypto key, not the version, with either key_ref.
    for key_ref in [KEY, pinned.as_str()] {
        let kms = fixture_client(replay("decrypt_old_version.json"));
        let opened = kms.unwrap(key_ref, &wrapped, &data_aad(1)).await.unwrap();
        assert_eq!(opened.risky_ref(), &[0x43u8; 32]);
        assert!(kms.transport().is_done());
    }
}

#[test]
fn the_jwt_assertion_is_the_openssl_known_answer() {
    let expected = std::fs::read_to_string(format!(
        "{}/tests/fixtures/test_only_jwt_assertion.txt",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let key = test_only_service_account();
    let assertion = key.assertion(CLOUD_KMS_SCOPE, issued_at()).unwrap();
    assert_eq!(assertion.as_str(), expected.trim());
    // And it verifies with the public key.
    let (header, claims) = common::verify_jwt(&assertion).unwrap();
    assert_eq!(header["kid"], KEY_ID);
    assert_eq!(claims["iss"], EMAIL);
    assert_eq!(claims["iat"], 1_793_880_000u64);
    assert_eq!(claims["exp"], 1_793_883_600u64);
}

#[tokio::test]
async fn a_service_account_key_is_exchanged_for_a_token() {
    let login = ServiceAccountLogin::new(
        test_only_service_account(),
        replay("service_account_token.json"),
    )
    .with_clock(fixed_clock());
    let token = login.token().await.unwrap();
    assert_eq!(token.token(), "fixture-service-account-token");
    assert_eq!(token.expires_in(), Some(Duration::from_secs(3599)));
    assert!(login.transport().is_done());
}

#[tokio::test]
async fn the_metadata_server_gives_a_token() {
    let login = MetadataServerLogin::new(replay("metadata_token.json"));
    let token = login.token().await.unwrap();
    assert_eq!(token.token(), "fixture-metadata-token");
    assert_eq!(token.expires_in(), Some(Duration::from_secs(3420)));
    assert!(login.transport().is_done());
}

#[tokio::test]
async fn a_refused_exchange_is_access_denied_and_says_why() {
    let login = ServiceAccountLogin::new(
        test_only_service_account(),
        Replay::new().answer(VendorResponse::new(
            400,
            br#"{"error":"invalid_grant","error_description":"Invalid JWT Signature."}"#.to_vec(),
        )),
    );
    let error = login.token().await.unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::AccessDenied);
    assert!(error.to_string().contains("Invalid JWT Signature."));
    assert!(!error.to_string().contains("PRIVATE KEY"));
}

#[test]
fn a_service_account_key_file_is_checked() {
    let key = test_only_service_account();
    assert_eq!(key.client_email(), EMAIL);
    assert_eq!(key.private_key_id(), Some(KEY_ID));
    assert_eq!(key.token_uri(), "https://oauth2.googleapis.com/token");
    let debug = format!("{key:?}");
    assert!(debug.contains(EMAIL));
    assert!(!debug.contains("PRIVATE KEY"));

    let pem = test_only_key_pem();
    let file = |fields: serde_json::Value| serde_json::to_vec(&fields).unwrap();
    for (json, says) in [
        (b"not json".to_vec(), "not JSON"),
        (
            file(serde_json::json!({ "type": "authorized_user", "refresh_token": "x" })),
            "\"authorized_user\" is not supported",
        ),
        (
            file(serde_json::json!({ "client_email": EMAIL, "private_key": pem })),
            "no \"type\"",
        ),
        (
            file(serde_json::json!({ "type": "service_account", "private_key": pem })),
            "no client_email",
        ),
        (
            file(serde_json::json!({ "type": "service_account", "client_email": EMAIL })),
            "no private_key",
        ),
        (
            file(serde_json::json!({
                "type": "service_account", "client_email": EMAIL, "private_key": "nope"
            })),
            "not an RSA PKCS #8 PEM key",
        ),
        (
            file(serde_json::json!({
                "type": "service_account", "client_email": EMAIL, "private_key": pem,
                "token_uri": "http://oauth2.googleapis.com/token"
            })),
            "not an HTTPS URL",
        ),
    ] {
        let error = ServiceAccountKey::from_json(&json).unwrap_err();
        assert_eq!(error.kind(), BackendErrorKind::AccessDenied);
        assert!(error.to_string().contains(says), "{error}");
        assert!(!error.to_string().contains("PRIVATE KEY"));
    }

    // No token_uri means Google's.
    let key = ServiceAccountKey::from_json(&file(serde_json::json!({
        "type": "service_account", "client_email": EMAIL, "private_key": pem
    })))
    .unwrap();
    assert_eq!(key.token_uri(), "https://oauth2.googleapis.com/token");
    assert_eq!(key.private_key_id(), None);
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
    let path = std::env::temp_dir().join(format!("stack-kms-gcp-sa-{}.json", Uuid::new_v4()));
    std::fs::write(&path, test_only_service_account_json()).unwrap();
    let path_text = path.to_str().unwrap();

    let credentials = DefaultCredentials::from_env_lookup(
        KmsEmulator::new(),
        &env(&[
            ("GOOGLE_OAUTH_ACCESS_TOKEN", "static-token"),
            ("GOOGLE_APPLICATION_CREDENTIALS", path_text),
        ]),
    )
    .unwrap();
    assert!(matches!(credentials, DefaultCredentials::Token(_)));
    assert_eq!(credentials.token().await.unwrap().token(), "static-token");

    let emulator = KmsEmulator::new();
    let credentials = DefaultCredentials::from_env_lookup(
        emulator.clone(),
        &env(&[("GOOGLE_APPLICATION_CREDENTIALS", path_text)]),
    )
    .unwrap();
    assert!(matches!(credentials, DefaultCredentials::ServiceAccount(_)));
    let token = credentials.token().await.unwrap();
    assert_eq!(token.token(), "fixture-exchanged-token-1");
    // Cached.
    let _ = credentials.token().await.unwrap();
    assert_eq!(emulator.exchanges(), 1);

    let emulator = KmsEmulator::new();
    let credentials = DefaultCredentials::from_env_lookup(emulator.clone(), &env(&[])).unwrap();
    assert!(matches!(credentials, DefaultCredentials::MetadataServer(_)));
    assert_eq!(
        credentials.token().await.unwrap().token(),
        "fixture-metadata-token-1"
    );

    let error = DefaultCredentials::from_env_lookup(
        KmsEmulator::new(),
        &env(&[("GCE_METADATA_HOST", "evil/path")]),
    )
    .unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::AccessDenied);

    std::fs::remove_file(&path).unwrap();
    let error = DefaultCredentials::from_env_lookup(
        KmsEmulator::new(),
        &env(&[("GOOGLE_APPLICATION_CREDENTIALS", path_text)]),
    )
    .unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::AccessDenied);
    assert!(error.to_string().contains("cannot read"));
}

#[test]
fn the_metadata_host_comes_from_the_environment() {
    let login =
        MetadataServerLogin::from_env_lookup((), &env(&[("GCE_METADATA_HOST", "127.0.0.1:8080")]))
            .unwrap();
    assert_eq!(
        login.url(),
        "http://127.0.0.1:8080/computeMetadata/v1/instance/service-accounts/default/token"
    );
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
    let wrapped = wrapped_of("encrypt.json");
    for case in cases {
        let kms = fixture_client(Replay::new().answer(case.response.to_response()));
        let error = kms.unwrap(KEY, &wrapped, &data_aad(0)).await.unwrap_err();
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

    async fn sleep(&self, _duration: Duration) {}
}

#[tokio::test]
async fn no_response_is_unavailable() {
    let error = fixture_client(Down)
        .unwrap(KEY, &wrapped_of("encrypt.json"), &data_aad(0))
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::Unavailable);
    let error = MetadataServerLogin::new(Down).token().await.unwrap_err();
    assert_eq!(error.kind(), BackendErrorKind::Unavailable);
}

struct NoToken;

impl TokenProvider for NoToken {
    async fn token(&self) -> Result<AccessToken, AuthError> {
        Err(AuthError::access_denied("none configured"))
    }
}

#[tokio::test]
async fn no_token_is_access_denied_and_sends_nothing() {
    let kms = GcpKms::new(GcpKmsConfig::new(), Replay::new(), NoToken);
    let error = kms
        .wrap(KEY, &Protected::new([1u8; 32]), &data_aad(0))
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::AccessDenied);
}

#[tokio::test]
async fn a_key_reference_that_is_not_a_key_name_is_refused_before_any_call() {
    let emulator = KmsEmulator::new();
    let kms = fixture_client(emulator.clone());
    for bad in [
        "",
        "key",
        "projects/p/locations/l/keyRings/r",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k:decrypt",
        "projects/p/locations/l/keyRings/../cryptoKeys/k",
        "projects/p/locations/l/keyRings/r/cryptoKeys/k?alt=media",
    ] {
        let error = kms
            .wrap(bad, &Protected::new([1u8; 32]), b"a")
            .await
            .unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::NotFound, "{bad:?}");
        let error = kms
            .unwrap(bad, &[1, 0, 0, 0, 1, 9], b"a")
            .await
            .unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::NotFound, "{bad:?}");
    }
    assert!(emulator.requests().is_empty());
}

#[tokio::test]
async fn a_wrapped_key_that_is_not_one_is_refused_before_any_call() {
    let emulator = KmsEmulator::new();
    let kms = fixture_client(emulator.clone());
    for bad in [&b""[..], &[1, 0, 0, 0, 3], &[2, 0, 0, 0, 1, 7], b"CiQA"] {
        let error = kms.unwrap(KEY, bad, b"a").await.unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::InvalidCiphertext);
    }
    assert!(emulator.requests().is_empty());
}

fn encrypt_response(fields: serde_json::Value) -> VendorResponse {
    VendorResponse::new(200, fields.to_string().into_bytes())
}

#[tokio::test]
async fn an_encrypt_response_that_cannot_be_trusted_is_unavailable() {
    let ciphertext = b"some ciphertext";
    let good = serde_json::json!({
        "name": format!("{KEY}/cryptoKeyVersions/1"),
        "ciphertext": Base64::encode_string(ciphertext),
        "ciphertextCrc32c": crc32c(ciphertext).to_string(),
        "verifiedPlaintextCrc32c": true,
        "verifiedAdditionalAuthenticatedDataCrc32c": true,
    });
    // The good one is accepted, with the CRC32C as a string or a number.
    let mut as_number = good.clone();
    as_number["ciphertextCrc32c"] = serde_json::json!(crc32c(ciphertext));
    for body in [good.clone(), as_number] {
        let kms = fixture_client(Replay::new().answer(encrypt_response(body)));
        let wrapped = kms
            .wrap(KEY, &Protected::new([1u8; 32]), b"a")
            .await
            .unwrap();
        assert_eq!(wrapped, compact_ciphertext(1, ciphertext));
    }
    let mut bad_bodies = Vec::new();
    for (field, value) in [
        ("ciphertextCrc32c", serde_json::json!("1")),
        ("ciphertextCrc32c", serde_json::Value::Null),
        ("verifiedPlaintextCrc32c", serde_json::json!(false)),
        (
            "verifiedAdditionalAuthenticatedDataCrc32c",
            serde_json::Value::Null,
        ),
        ("ciphertext", serde_json::json!("not base64!")),
        ("ciphertext", serde_json::json!("")),
        ("ciphertext", serde_json::Value::Null),
        ("name", serde_json::Value::Null),
        ("name", serde_json::json!(KEY)),
        (
            "name",
            serde_json::json!(
                "projects/p/locations/global/keyRings/r/cryptoKeys/other/cryptoKeyVersions/1"
            ),
        ),
    ] {
        let mut body = good.clone();
        body[field] = value;
        bad_bodies.push(body.to_string().into_bytes());
    }
    bad_bodies.push(b"not json".to_vec());
    for body in bad_bodies {
        let kms = fixture_client(Replay::new().answer(VendorResponse::new(200, body.clone())));
        let error = kms
            .wrap(KEY, &Protected::new([1u8; 32]), b"a")
            .await
            .unwrap_err();
        assert_eq!(
            kind_of(error),
            BackendErrorKind::Unavailable,
            "{}",
            String::from_utf8_lossy(&body)
        );
    }
}

#[tokio::test]
async fn a_decrypt_response_that_cannot_be_trusted_is_refused() {
    let wrapped = wrapped_of("encrypt.json");
    let key = [7u8; 32];
    let short = [7u8; 16];
    for (body, kind) in [
        (
            serde_json::json!({ "plaintext": Base64::encode_string(&key), "plaintextCrc32c": "1" }),
            BackendErrorKind::Unavailable,
        ),
        (
            serde_json::json!({ "plaintext": Base64::encode_string(&key) }),
            BackendErrorKind::Unavailable,
        ),
        (
            serde_json::json!({ "plaintextCrc32c": "0" }),
            BackendErrorKind::Unavailable,
        ),
        (
            serde_json::json!({ "plaintext": "not base64!", "plaintextCrc32c": "0" }),
            BackendErrorKind::Unavailable,
        ),
        (
            serde_json::json!({
                "plaintext": Base64::encode_string(&short),
                "plaintextCrc32c": crc32c(&short).to_string(),
            }),
            BackendErrorKind::InvalidCiphertext,
        ),
    ] {
        let kms = fixture_client(Replay::new().answer(encrypt_response(body.clone())));
        let error = kms.unwrap(KEY, &wrapped, &data_aad(0)).await.unwrap_err();
        assert_eq!(kind_of(error), kind, "{body}");
    }
}

#[tokio::test]
async fn a_401_drops_the_cached_token() {
    let emulator = KmsEmulator::new();
    let kms = GcpKms::new(
        GcpKmsConfig::new(),
        emulator.clone(),
        CachedToken::new(ServiceAccountLogin::new(
            test_only_service_account(),
            emulator.clone(),
        )),
    );
    let wrapped = kms
        .wrap(KEY, &Protected::new([2u8; 32]), b"a")
        .await
        .unwrap();
    assert_eq!(emulator.exchanges(), 1);
    emulator.revoke_tokens();
    let error = kms.unwrap(KEY, &wrapped, b"a").await.unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::AccessDenied);
    // The next call gets a new token.
    let opened = kms.unwrap(KEY, &wrapped, b"a").await.unwrap();
    assert_eq!(opened.risky_ref(), &[2u8; 32]);
    assert_eq!(emulator.exchanges(), 2);
}

#[tokio::test]
async fn the_backend_reports_gcp_and_sleeps_on_its_transport() {
    let emulator = KmsEmulator::new();
    let kms = fixture_client(emulator.clone());
    assert_eq!(kms.vendor(), KeyVendor::Gcp);
    assert!(kms.supports_mode(KeyMode::Wrapped));
    assert!(kms.supports_mode(KeyMode::Derived));
    assert_eq!(kms.batch_limit(), None);
    kms.sleep(Duration::from_millis(50)).await;
    assert_eq!(emulator.sleeps(), [Duration::from_millis(50)]);
}
