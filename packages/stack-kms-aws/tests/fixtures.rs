//! Each AWS KMS call and each error mapping, against recorded HTTP
//! exchanges (`tests/fixtures/*.json`).
//!
//! Every fixture request is signed at 2026-11-05T12:00:00Z with the AWS
//! documentation example key, so its bytes, signature included, are fixed.
//! The SigV4 algorithm itself is tested against the AWS test suite in
//! `src/sigv4.rs`; these fixtures pin the KMS request shape on top of it.

mod common;

use common::{fixture_client, load, Fixture, FixtureResponse, Replay, KEY_ARN};
use serde::Deserialize;
use stack_kms::{BackendErrorKind, Error, KeyMode, KeyVendor};
use stack_kms_aws::{AwsKms, AwsKmsConfig, Credentials, CredentialsError, CredentialsProvider};
use stack_kms_vendor::derive::{record_key_aad, wrapped_data_key_aad};
use stack_kms_vendor::{
    KeyVendorBackend, TransportError, VendorRequest, VendorResponse, VendorTransport,
};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};

const KEYSET: Uuid = Uuid::from_u128(0x0f1e2d3c_4b5a_6978_8796_a5b4c3d2e1f0);

fn record_aad() -> Vec<u8> {
    record_key_aad(KEYSET, KeyVendor::Aws, KeyMode::Wrapped)
}

fn kind_of(error: Error) -> BackendErrorKind {
    match error {
        Error::Backend { vendor, kind, .. } => {
            assert_eq!(vendor, "aws-kms");
            kind
        }
        other => panic!("not a backend error: {other:?}"),
    }
}

/// The ciphertext blob of a fixture's response.
fn blob_of(fixture: &str) -> Vec<u8> {
    let fixture: Fixture = load(fixture);
    let blob = fixture.response.body["CiphertextBlob"].as_str().unwrap();
    <base64ct::Base64 as base64ct::Encoding>::decode_vec(blob).unwrap()
}

#[tokio::test]
async fn generate_data_key() {
    let transport = Replay::new().expect(load("generate_data_key.json"));
    let kms = fixture_client(transport);
    let aad = wrapped_data_key_aad(KEYSET, &[7u8; 16], "users/email");
    let (key, wrapped) = kms.generate_wrapped(KEY_ARN, &aad).await.unwrap();
    let expected: Vec<u8> = (0u8..32).collect();
    assert_eq!(key.risky_ref().as_slice(), expected.as_slice());
    assert_eq!(wrapped, blob_of("generate_data_key.json"));
}

#[tokio::test]
async fn encrypt() {
    let transport = Replay::new().expect(load("encrypt.json"));
    let kms = fixture_client(transport);
    let wrapped = kms
        .wrap(KEY_ARN, &Protected::new([0x42u8; 32]), &record_aad())
        .await
        .unwrap();
    assert_eq!(wrapped, blob_of("encrypt.json"));
}

#[tokio::test]
async fn decrypt() {
    let transport = Replay::new().expect(load("decrypt.json"));
    let kms = fixture_client(transport);
    let key = kms
        .unwrap(KEY_ARN, &blob_of("encrypt.json"), &record_aad())
        .await
        .unwrap();
    assert_eq!(key.risky_ref(), &[0x42u8; 32]);
}

#[tokio::test]
async fn decrypt_with_a_session_token() {
    let transport = Replay::new().expect(load("decrypt_with_session_token.json"));
    let kms = AwsKms::new(
        AwsKmsConfig::new("us-east-1").unwrap(),
        transport,
        Credentials::new(
            "ASIAEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            Some("IQoJb3JpZ2luX2VjEXAMPLESESSIONTOKEN".to_owned()),
        ),
    )
    .with_clock(common::fixture_clock());
    let key = kms
        .unwrap(KEY_ARN, &blob_of("encrypt.json"), &record_aad())
        .await
        .unwrap();
    assert_eq!(key.risky_ref(), &[0x42u8; 32]);
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
    assert!(cases.len() >= 10);
    for case in cases {
        let kms = fixture_client(Replay::new().answer(case.response.to_response()));
        let error = kms
            .unwrap(KEY_ARN, b"blob", &record_aad())
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
        .unwrap(KEY_ARN, b"blob", &record_aad())
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::Unavailable);
}

struct NoCredentials;

impl CredentialsProvider for NoCredentials {
    async fn credentials(&self) -> Result<Credentials, CredentialsError> {
        Err(CredentialsError::access_denied("none configured"))
    }
}

#[tokio::test]
async fn missing_credentials_are_access_denied_and_send_nothing() {
    let kms = AwsKms::new(
        AwsKmsConfig::new("us-east-1").unwrap(),
        Replay::new(),
        NoCredentials,
    );
    let error = kms
        .unwrap(KEY_ARN, b"blob", &record_aad())
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::AccessDenied);
}

#[tokio::test]
async fn an_unreadable_success_is_unavailable() {
    for body in [
        b"not json".to_vec(),
        br#"{"KeyId":"k"}"#.to_vec(),
        br#"{"Plaintext":"not base64!"}"#.to_vec(),
    ] {
        let kms = fixture_client(Replay::new().answer(VendorResponse::new(200, body)));
        let error = kms
            .unwrap(KEY_ARN, b"blob", &record_aad())
            .await
            .unwrap_err();
        assert_eq!(kind_of(error), BackendErrorKind::Unavailable);
    }
    let kms = fixture_client(
        Replay::new().answer(VendorResponse::new(200, br#"{"KeyId":"k"}"#.to_vec())),
    );
    let error = kms
        .wrap(KEY_ARN, &Protected::new([1u8; 32]), b"a")
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::Unavailable);
}

#[tokio::test]
async fn a_plaintext_that_is_not_a_256_bit_key_is_refused() {
    // 16 bytes: an AES_128 data key, not one this crate asked for.
    let body = br#"{"KeyId":"k","Plaintext":"AAECAwQFBgcICQoLDA0ODw=="}"#.to_vec();
    let kms = fixture_client(Replay::new().answer(VendorResponse::new(200, body)));
    let error = kms
        .unwrap(KEY_ARN, b"blob", &record_aad())
        .await
        .unwrap_err();
    assert_eq!(kind_of(error), BackendErrorKind::InvalidCiphertext);
}

#[tokio::test]
async fn the_backend_reports_aws_and_sleeps_on_its_transport() {
    let emulator = common::KmsEmulator::default();
    let kms = fixture_client(emulator.clone());
    assert_eq!(kms.vendor(), KeyVendor::Aws);
    assert!(kms.supports_mode(KeyMode::Wrapped));
    assert!(kms.supports_mode(KeyMode::Derived));
    kms.sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(emulator.sleeps(), [std::time::Duration::from_millis(50)]);
}
