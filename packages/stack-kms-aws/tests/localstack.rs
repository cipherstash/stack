//! The AWS KMS backend against LocalStack, over the native transport.
//!
//! Runs only when `STACK_KMS_AWS_LOCALSTACK_ENDPOINT` is set (for example
//! `http://localhost:4566`); otherwise each test passes at once and says it
//! was skipped. CI runs LocalStack as a service and sets the variable.
//!
//! ```sh
//! docker run -d --rm -p 4566:4566 -e SERVICES=kms localstack/localstack:4.4
//! STACK_KMS_AWS_LOCALSTACK_ENDPOINT=http://localhost:4566 \
//!   cargo nextest run -p stack-kms-aws --all-features --test localstack
//! ```

#![cfg(not(target_arch = "wasm32"))]

use serde_json::Value;
use stack_kms::{BackendErrorKind, Error, KeyMode, KeyVendor};
use stack_kms_aws::{AwsKms, AwsKmsConfig, Credentials};
use stack_kms_vendor::derive::record_key_aad;
use stack_kms_vendor::{contract, HttpVendorTransport, KeyVendorBackend};
use uuid::Uuid;
use vitaminc::protected::Protected;
use zeroize::Zeroizing;

const ENDPOINT_VAR: &str = "STACK_KMS_AWS_LOCALSTACK_ENDPOINT";

type Client = AwsKms<HttpVendorTransport, Credentials>;

fn client(endpoint: &str) -> Client {
    let config = AwsKmsConfig::new("us-east-1")
        .unwrap()
        .with_endpoint(endpoint)
        .unwrap();
    // LocalStack accepts any credentials; these are its documented ones.
    AwsKms::new(
        config,
        HttpVendorTransport::new().unwrap(),
        Credentials::new("test", "test", None),
    )
}

fn endpoint() -> Option<String> {
    let endpoint = std::env::var(ENDPOINT_VAR).ok().filter(|e| !e.is_empty());
    if endpoint.is_none() {
        eprintln!("skipped: set {ENDPOINT_VAR} to run against LocalStack");
    }
    endpoint
}

/// A new symmetric AWS KMS key in LocalStack; its ARN.
async fn create_key(kms: &Client) -> String {
    let body = br#"{"KeySpec":"SYMMETRIC_DEFAULT","KeyUsage":"ENCRYPT_DECRYPT","Description":"stack-kms-aws test"}"#;
    let created: Value = kms
        .send_json("CreateKey", Zeroizing::new(body.to_vec()))
        .await
        .unwrap();
    created["KeyMetadata"]["Arn"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn aws_kms_meets_the_contract_on_localstack() {
    let Some(endpoint) = endpoint() else { return };
    let key_arn = create_key(&client(&endpoint)).await;
    contract::run(|| client(&endpoint), &key_arn).await;
}

#[tokio::test]
async fn localstack_errors_map_to_kinds() {
    let Some(endpoint) = endpoint() else { return };
    let kms = client(&endpoint);
    let key_arn = create_key(&kms).await;
    let aad = record_key_aad(Uuid::new_v4(), KeyVendor::Aws, KeyMode::Derived);
    let key = Protected::new([3u8; 32]);
    let wrapped = kms.wrap(&key_arn, &key, &aad).await.unwrap();

    let kind = |error: Error| match error {
        Error::Backend { kind, .. } => kind,
        other => panic!("{other:?}"),
    };

    // Another encryption context.
    let other = record_key_aad(Uuid::new_v4(), KeyVendor::Aws, KeyMode::Derived);
    let error = kms.unwrap(&key_arn, &wrapped, &other).await.unwrap_err();
    assert_eq!(kind(error), BackendErrorKind::InvalidCiphertext);

    // A damaged ciphertext. (LocalStack answers bytes that are not its
    // blob format at all with HTTP 500, not InvalidCiphertextException, so
    // the last byte of a real blob is changed instead. The fixtures cover
    // the AWS answer.)
    let mut damaged = wrapped.clone();
    if let Some(last) = damaged.last_mut() {
        *last ^= 1;
    }
    let error = kms.unwrap(&key_arn, &damaged, &aad).await.unwrap_err();
    assert_eq!(kind(error), BackendErrorKind::InvalidCiphertext);

    // A key that does not exist.
    let missing = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000";
    let error = kms.wrap(missing, &key, &aad).await.unwrap_err();
    assert_eq!(kind(error), BackendErrorKind::NotFound);
}
