//! Shared test support: the fixture time and credentials, and an in-process
//! emulation of the AWS KMS JSON API. The fixture and replay harness is
//! `stack_kms_vendor::replay`, shared by every vendor crate.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64ct::{Base64, Encoding};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use stack_kms_aws::{AwsKms, AwsKmsConfig, Clock, Credentials};
// Each test binary uses a different part of the harness.
#[allow(unused_imports)]
pub use stack_kms_vendor::replay::{Fixture, FixtureRequest, FixtureResponse, Fixtures, Replay};
use stack_kms_vendor::{TransportError, VendorRequest, VendorResponse, VendorTransport};
use web_time::{SystemTime, UNIX_EPOCH};

/// The key the fixtures use.
pub const KEY_ARN: &str =
    "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
/// 2026-11-05T12:00:00Z, the signing time of every fixture.
pub const FIXTURE_TIME: u64 = 1_793_880_000;

pub fn fixture_clock() -> Clock {
    Arc::new(|| UNIX_EPOCH + Duration::from_secs(FIXTURE_TIME))
}

/// The credentials of every fixture: the AWS documentation example key.
pub fn fixture_credentials() -> Credentials {
    Credentials::new(
        "AKIDEXAMPLE",
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        None,
    )
}

/// The fixtures of this crate.
pub const FIXTURES: Fixtures =
    Fixtures::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"));

pub fn load<T: DeserializeOwned>(name: &str) -> T {
    FIXTURES.load(name)
}

/// A client over `transport` with the fixture time and credentials.
pub fn fixture_client<T: VendorTransport + Send + Sync>(transport: T) -> AwsKms<T, Credentials> {
    AwsKms::new(
        AwsKmsConfig::new("us-east-1").unwrap(),
        transport,
        fixture_credentials(),
    )
    .with_clock(fixture_clock())
}

/// An in-process emulation of the AWS KMS JSON API: `CreateKey`,
/// `GenerateDataKey`, `Encrypt` and `Decrypt`, with the encryption context
/// bound by AES-256-GCM, and the AWS error shapes. It checks that each
/// request is signed for the fixture access key and the `kms` service.
///
/// The contract suite uses random keys and ids, so recorded bytes cannot
/// serve it: this answers it instead. Clones share one key store.
#[derive(Clone, Default)]
pub struct KmsEmulator {
    keys: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    sleeps: Arc<Mutex<Vec<Duration>>>,
}

impl KmsEmulator {
    pub fn with_key(key_id: &str) -> Self {
        let emulator = Self::default();
        emulator
            .keys
            .lock()
            .unwrap()
            .insert(key_id.to_owned(), rand_key());
        emulator
    }

    pub fn sleeps(&self) -> Vec<Duration> {
        self.sleeps.lock().unwrap().clone()
    }

    fn error(code: &str, message: &str) -> VendorResponse {
        VendorResponse::new(
            400,
            serde_json::to_vec(&json!({"__type": code, "message": message})).unwrap(),
        )
        .header("content-type", "application/x-amz-json-1.1")
    }

    fn ok(body: Value) -> VendorResponse {
        VendorResponse::new(200, serde_json::to_vec(&body).unwrap())
            .header("content-type", "application/x-amz-json-1.1")
    }

    fn seal(key_id: &str, key: &[u8; 32], context: &Value, plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
        let nonce = rand_key();
        let aad = serde_json::to_vec(context).unwrap();
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&nonce[..12]),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        let mut blob = vec![key_id.len() as u8];
        blob.extend_from_slice(key_id.as_bytes());
        blob.extend_from_slice(&nonce[..12]);
        blob.extend_from_slice(&sealed);
        blob
    }

    fn handle(&self, operation: &str, body: &Value) -> VendorResponse {
        let context = body.get("EncryptionContext").cloned().unwrap_or(json!({}));
        // A BTreeMap gives one byte form per context.
        let context: BTreeMap<String, String> = serde_json::from_value(context).unwrap();
        let context = serde_json::to_value(context).unwrap();
        let key_id = body.get("KeyId").and_then(Value::as_str).unwrap_or("");
        let keys = self.keys.lock().unwrap();
        match operation {
            "CreateKey" => {
                drop(keys);
                let id = format!("emulated-{}", self.keys.lock().unwrap().len());
                self.keys.lock().unwrap().insert(id.clone(), rand_key());
                Self::ok(json!({"KeyMetadata": {"KeyId": id, "Arn": id}}))
            }
            "GenerateDataKey" | "Encrypt" => {
                let Some(key) = keys.get(key_id) else {
                    return Self::error("NotFoundException", "no such key");
                };
                let (plaintext, give_back) = if operation == "Encrypt" {
                    let encoded = body.get("Plaintext").and_then(Value::as_str).unwrap();
                    (Base64::decode_vec(encoded).unwrap(), false)
                } else {
                    assert_eq!(body.get("KeySpec"), Some(&json!("AES_256")));
                    (rand_key().to_vec(), true)
                };
                let blob = Self::seal(key_id, key, &context, &plaintext);
                let mut answer = json!({
                    "KeyId": key_id,
                    "CiphertextBlob": Base64::encode_string(&blob),
                });
                if give_back {
                    answer["Plaintext"] = json!(Base64::encode_string(&plaintext));
                }
                Self::ok(answer)
            }
            "Decrypt" => {
                let blob = body
                    .get("CiphertextBlob")
                    .and_then(Value::as_str)
                    .and_then(|blob| Base64::decode_vec(blob).ok())
                    .unwrap_or_default();
                let Some((&len, rest)) = blob.split_first() else {
                    return Self::error("InvalidCiphertextException", "empty");
                };
                let len = usize::from(len);
                if rest.len() < len + 12 {
                    return Self::error("InvalidCiphertextException", "short");
                }
                let (blob_key, rest) = rest.split_at(len);
                if blob_key != key_id.as_bytes() {
                    return Self::error("IncorrectKeyException", "another key");
                }
                let Some(key) = keys.get(key_id) else {
                    return Self::error("NotFoundException", "no such key");
                };
                let (nonce, sealed) = rest.split_at(12);
                let aad = serde_json::to_vec(&context).unwrap();
                match Aes256Gcm::new_from_slice(key).unwrap().decrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: sealed,
                        aad: &aad,
                    },
                ) {
                    Ok(plaintext) => Self::ok(json!({
                        "KeyId": key_id,
                        "Plaintext": Base64::encode_string(&plaintext),
                    })),
                    Err(_) => Self::error("InvalidCiphertextException", "does not open"),
                }
            }
            other => Self::error("UnknownOperationException", other),
        }
    }
}

fn rand_key() -> [u8; 32] {
    use vitaminc::random::{Generatable, SafeRand};
    let mut rng = SafeRand::from_entropy().unwrap();
    <[u8; 32]>::random(&mut rng).unwrap()
}

impl VendorTransport for KmsEmulator {
    async fn send(&self, request: VendorRequest) -> Result<VendorResponse, TransportError> {
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.header_value("content-type"),
            Some("application/x-amz-json-1.1")
        );
        let authorization = request.header_value("authorization").unwrap_or("");
        assert!(
            authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
                && authorization.contains("/us-east-1/kms/aws4_request, SignedHeaders="),
            "unsigned or wrongly scoped request: {authorization}"
        );
        let operation = request
            .header_value("x-amz-target")
            .and_then(|target| target.strip_prefix("TrentService."))
            .expect("an X-Amz-Target of TrentService")
            .to_owned();
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        Ok(self.handle(&operation, &body))
    }

    async fn sleep(&self, duration: Duration) {
        self.sleeps.lock().unwrap().push(duration);
    }
}

/// The time now, for tests that do not pin it.
pub fn now() -> SystemTime {
    SystemTime::now()
}
