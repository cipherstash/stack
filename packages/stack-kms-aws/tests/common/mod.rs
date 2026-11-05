//! Shared test support: recorded fixtures, a replaying transport, and an
//! in-process emulation of the AWS KMS JSON API.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64ct::{Base64, Encoding};
use serde::Deserialize;
use serde_json::{json, Value};
use stack_kms_aws::{AwsKms, AwsKmsConfig, Clock, Credentials};
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

#[derive(Deserialize)]
pub struct FixtureRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

#[derive(Clone, Deserialize)]
pub struct FixtureResponse {
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

impl FixtureResponse {
    pub fn to_response(&self) -> VendorResponse {
        let body = match &self.body {
            Value::String(text) => text.clone().into_bytes(),
            other => serde_json::to_vec(other).unwrap(),
        };
        let mut response = VendorResponse::new(self.status, body);
        for (name, value) in &self.headers {
            response = response.header(name, value);
        }
        response
    }
}

#[derive(Deserialize)]
pub struct Fixture {
    pub request: FixtureRequest,
    pub response: FixtureResponse,
}

pub fn load<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// A transport that checks each request against a recorded one and
/// answers with the recorded response.
#[derive(Default)]
pub struct Replay {
    exchanges: Mutex<VecDeque<(Option<FixtureRequest>, VendorResponse)>>,
}

impl Replay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Expect `fixture`'s request and answer with its response.
    pub fn expect(self, fixture: Fixture) -> Self {
        let response = fixture.response.to_response();
        self.exchanges
            .lock()
            .unwrap()
            .push_back((Some(fixture.request), response));
        self
    }

    /// Answer the next request, whatever it is, with `response`.
    pub fn answer(self, response: VendorResponse) -> Self {
        self.exchanges.lock().unwrap().push_back((None, response));
        self
    }

    pub fn is_done(&self) -> bool {
        self.exchanges.lock().unwrap().is_empty()
    }
}

impl VendorTransport for Replay {
    async fn send(&self, request: VendorRequest) -> Result<VendorResponse, TransportError> {
        let (expected, response) = self
            .exchanges
            .lock()
            .unwrap()
            .pop_front()
            .expect("a request the fixtures do not expect");
        if let Some(expected) = expected {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let actual = json!({
                "method": request.method,
                "url": request.url,
                "headers": request.headers,
                "body": body,
            });
            let wanted = json!({
                "method": expected.method,
                "url": expected.url,
                "headers": expected.headers,
                "body": expected.body,
            });
            assert_eq!(
                actual,
                wanted,
                "the request differs from the fixture; actual:\n{}",
                serde_json::to_string_pretty(&actual).unwrap()
            );
        }
        Ok(response)
    }

    async fn sleep(&self, _duration: Duration) {}
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
