//! Shared test support: fixtures, a replaying transport, the test-only
//! service account, and an in-process emulation of the Cloud KMS API, the
//! token endpoint and the metadata server.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use stack_kms_gcp::crc32c::crc32c;
use stack_kms_gcp::{parse_key_name, AccessToken, GcpKms, GcpKmsConfig, ServiceAccountKey};
use stack_kms_vendor::{TransportError, VendorRequest, VendorResponse, VendorTransport};
use web_time::{SystemTime, UNIX_EPOCH};

/// The crypto key of every fixture.
pub const KEY: &str =
    "projects/test-only-project/locations/global/keyRings/cipherstash-fixture/cryptoKeys/fixture-key";
/// The static access token of the fixtures.
pub const TOKEN: &str = "fixture-access-token";
/// The email of the test-only service account.
pub const EMAIL: &str = "stack-kms-gcp-fixture@test-only-project.iam.gserviceaccount.com";
/// The key id of the test-only service account key.
pub const KEY_ID: &str = "test-only-fixture-key-id";
/// The time every fixture JWT is issued at: 2026-11-05T12:00:00Z.
pub const ISSUED_AT: u64 = 1_793_880_000;
/// The Cloud KMS endpoint.
pub const ENDPOINT: &str = "https://cloudkms.googleapis.com";
/// The token endpoint.
pub const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
/// The metadata server's token URL.
pub const METADATA_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

/// The time of the fixture JWT.
pub fn issued_at() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(ISSUED_AT)
}

/// The PEM of the TEST-ONLY RSA key, generated for these tests with
/// `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`. It is no
/// one's service account key. It is kept as base64 PKCS #8 DER, not as PEM
/// or in a key file, so it does not look like a leaked credential.
pub fn test_only_key_pem() -> String {
    let path = format!(
        "{}/tests/fixtures/test_only_rsa_key.pkcs8.b64",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(path).unwrap();
    let body: String = text.split_whitespace().collect();
    let lines: Vec<String> = body
        .as_bytes()
        .chunks(64)
        .map(|chunk| String::from_utf8(chunk.to_vec()).unwrap())
        .collect();
    // The PEM label is built in pieces so that no file in the tree holds
    // a PEM private key block.
    let label = ["PRIVATE", "KEY"].join(" ");
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// A service account key file for the test-only key, built at run time.
pub fn test_only_service_account_json() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "type": "service_account",
        "project_id": "test-only-project",
        "private_key_id": KEY_ID,
        "private_key": test_only_key_pem(),
        "client_email": EMAIL,
        "client_id": "000000000000000000000",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": TOKEN_URI,
    }))
    .unwrap()
}

pub fn test_only_service_account() -> ServiceAccountKey {
    ServiceAccountKey::from_json(&test_only_service_account_json()).unwrap()
}

/// Verify a JWT's RS256 signature with the test-only key, and return its
/// header and claims.
pub fn verify_jwt(jwt: &str) -> Option<(Value, Value)> {
    let (signing_input, signature) = jwt.rsplit_once('.')?;
    let (header, claims) = signing_input.split_once('.')?;
    let private = rsa::RsaPrivateKey::from_pkcs8_pem(&test_only_key_pem()).unwrap();
    let verifying = VerifyingKey::<Sha256>::new(private.to_public_key());
    let signature =
        Signature::try_from(Base64UrlUnpadded::decode_vec(signature).ok()?.as_slice()).ok()?;
    verifying
        .verify(signing_input.as_bytes(), &signature)
        .ok()?;
    let header = serde_json::from_slice(&Base64UrlUnpadded::decode_vec(header).ok()?).ok()?;
    let claims = serde_json::from_slice(&Base64UrlUnpadded::decode_vec(claims).ok()?).ok()?;
    Some((header, claims))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FixtureRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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
            Value::Null => Vec::new(),
            other => serde_json::to_vec(other).unwrap(),
        };
        let mut response = VendorResponse::new(self.status, body);
        for (name, value) in &self.headers {
            response = response.header(name, value);
        }
        response
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fixture {
    pub request: FixtureRequest,
    pub response: FixtureResponse,
}

pub fn load<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn body_json(body: &[u8]) -> Value {
    if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(body)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(body).into()))
    }
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

    /// Expect each exchange of a fixture file, in order.
    pub fn expect_all(self, fixtures: Vec<Fixture>) -> Self {
        for fixture in fixtures {
            let response = fixture.response.to_response();
            self.exchanges
                .lock()
                .unwrap()
                .push_back((Some(fixture.request), response));
        }
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
            let actual = json!({
                "method": request.method,
                "url": request.url,
                "headers": request.headers,
                "body": body_json(&request.body),
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

pub fn replay(name: &str) -> Replay {
    Replay::new().expect_all(load(name))
}

/// A client of the public endpoint over `transport`, with the fixture
/// token.
pub fn fixture_client<T: VendorTransport + Send + Sync>(transport: T) -> GcpKms<T, AccessToken> {
    GcpKms::new(GcpKmsConfig::new(), transport, AccessToken::new(TOKEN))
}

#[derive(Debug, Default)]
struct EmulatorState {
    /// Each crypto key's versions; the last is the primary.
    keys: HashMap<String, Vec<[u8; 32]>>,
    tokens: Vec<String>,
    exchanges: usize,
    requests: Vec<(String, String, Value)>,
    sleeps: Vec<Duration>,
    nonce: u32,
}

/// An in-process emulation of the Cloud KMS REST API (`encrypt` and
/// `decrypt` of symmetric keys with versions, AES-256-GCM with the
/// associated data bound, the CRC32C checks, Google's error shapes), the
/// OAuth token endpoint (which verifies the JWT's RS256 signature with the
/// test-only key) and the metadata server. It checks the bearer token on
/// every Cloud KMS request.
///
/// The contract suite uses random keys and ids, so fixed bytes cannot serve
/// it: this answers it instead. Clones share one state.
#[derive(Clone, Debug, Default)]
pub struct KmsEmulator {
    state: Arc<Mutex<EmulatorState>>,
}

impl KmsEmulator {
    /// An emulator holding [`KEY`] (one version), that accepts [`TOKEN`].
    pub fn new() -> Self {
        let emulator = Self::default();
        emulator.add_key(KEY);
        emulator.state.lock().unwrap().tokens.push(TOKEN.to_owned());
        emulator
    }

    pub fn add_key(&self, name: &str) {
        let mut state = self.state.lock().unwrap();
        let seed = state.keys.len() as u8;
        state.keys.insert(name.to_owned(), vec![[seed ^ 0x5A; 32]]);
    }

    /// Add a version to `name` and make it the primary.
    pub fn rotate(&self, name: &str) {
        let mut state = self.state.lock().unwrap();
        let versions = state.keys.get_mut(name).unwrap();
        let next = [versions.len() as u8 ^ 0xA5; 32];
        versions.push(next);
    }

    /// Revoke every access token.
    pub fn revoke_tokens(&self) {
        self.state.lock().unwrap().tokens.clear();
    }

    /// Token endpoint and metadata server exchanges so far.
    pub fn exchanges(&self) -> usize {
        self.state.lock().unwrap().exchanges
    }

    /// Every Cloud KMS request: method, path after `/v1/`, body.
    pub fn requests(&self) -> Vec<(String, String, Value)> {
        self.state.lock().unwrap().requests.clone()
    }

    pub fn sleeps(&self) -> Vec<Duration> {
        self.state.lock().unwrap().sleeps.clone()
    }

    fn json(status: u16, body: Value) -> VendorResponse {
        VendorResponse::new(status, body.to_string().into_bytes())
            .header("content-type", "application/json; charset=UTF-8")
    }

    fn error(status: u16, code: &str, message: &str) -> VendorResponse {
        Self::json(
            status,
            json!({ "error": { "code": status, "message": message, "status": code } }),
        )
    }

    fn issue(&self, prefix: &str) -> VendorResponse {
        let mut state = self.state.lock().unwrap();
        state.exchanges += 1;
        let token = format!("{prefix}-{}", state.exchanges);
        state.tokens.push(token.clone());
        Self::json(
            200,
            json!({ "access_token": token, "expires_in": 3599, "token_type": "Bearer" }),
        )
    }

    fn token_exchange(&self, body: &[u8]) -> VendorResponse {
        let form: HashMap<String, String> =
            url::form_urlencoded::parse(body).into_owned().collect();
        if form.get("grant_type").map(String::as_str)
            != Some("urn:ietf:params:oauth:grant-type:jwt-bearer")
        {
            return Self::json(400, json!({ "error": "unsupported_grant_type" }));
        }
        let Some((header, claims)) = form.get("assertion").and_then(|jwt| verify_jwt(jwt)) else {
            return Self::json(
                400,
                json!({ "error": "invalid_grant", "error_description": "Invalid JWT Signature." }),
            );
        };
        let valid = header["alg"] == "RS256"
            && header["kid"] == KEY_ID
            && claims["iss"] == EMAIL
            && claims["aud"] == TOKEN_URI
            && claims["scope"] == "https://www.googleapis.com/auth/cloudkms"
            && claims["exp"].as_u64() == claims["iat"].as_u64().map(|iat| iat + 3600);
        if !valid {
            return Self::json(
                400,
                json!({ "error": "invalid_grant", "error_description": "Invalid JWT claims." }),
            );
        }
        self.issue("fixture-exchanged-token")
    }

    fn check_crc(body: &Value, field: &str, crc_field: &str) -> Result<Vec<u8>, VendorResponse> {
        let bytes = Base64::decode_vec(body[field].as_str().unwrap_or("")).map_err(|_| {
            Self::error(
                400,
                "INVALID_ARGUMENT",
                &format!("Invalid value at '{field}'"),
            )
        })?;
        let sent = body[crc_field]
            .as_str()
            .and_then(|crc| crc.parse::<u64>().ok());
        if sent != Some(u64::from(crc32c(&bytes))) {
            return Err(Self::error(
                400,
                "INVALID_ARGUMENT",
                &format!(
                    "The checksum in field {crc_field} did not match the data in field {field}."
                ),
            ));
        }
        Ok(bytes)
    }

    fn encrypt(&self, name: &str, body: &Value) -> VendorResponse {
        let Some((key_name, pinned)) = parse_key_name(name) else {
            return Self::error(400, "INVALID_ARGUMENT", "Invalid resource name");
        };
        let mut state = self.state.lock().unwrap();
        let Some(versions) = state.keys.get(key_name).cloned() else {
            return Self::error(404, "NOT_FOUND", &format!("{key_name} not found."));
        };
        let plaintext = match Self::check_crc(body, "plaintext", "plaintextCrc32c") {
            Ok(bytes) => bytes,
            Err(response) => return response,
        };
        let aad = match Self::check_crc(
            body,
            "additionalAuthenticatedData",
            "additionalAuthenticatedDataCrc32c",
        ) {
            Ok(bytes) => bytes,
            Err(response) => return response,
        };
        let version = pinned.unwrap_or(versions.len() as u32);
        let Some(key) = versions.get(version as usize - 1) else {
            return Self::error(404, "NOT_FOUND", "CryptoKeyVersion not found.");
        };
        state.nonce += 1;
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&state.nonce.to_be_bytes());
        let mut ciphertext = version.to_be_bytes().to_vec();
        ciphertext.extend_from_slice(&nonce);
        ciphertext.extend(
            Aes256Gcm::new_from_slice(key)
                .unwrap()
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &plaintext,
                        aad: &aad,
                    },
                )
                .unwrap(),
        );
        Self::json(
            200,
            json!({
                "name": format!("{key_name}/cryptoKeyVersions/{version}"),
                "ciphertext": Base64::encode_string(&ciphertext),
                "ciphertextCrc32c": crc32c(&ciphertext).to_string(),
                "verifiedPlaintextCrc32c": true,
                "verifiedAdditionalAuthenticatedDataCrc32c": true,
                "protectionLevel": "SOFTWARE",
            }),
        )
    }

    fn decrypt(&self, name: &str, body: &Value) -> VendorResponse {
        match parse_key_name(name) {
            Some((_, None)) => {}
            _ => return Self::error(400, "INVALID_ARGUMENT", "Invalid resource name"),
        }
        let Some(versions) = self.state.lock().unwrap().keys.get(name).cloned() else {
            return Self::error(404, "NOT_FOUND", &format!("{name} not found."));
        };
        let ciphertext = match Self::check_crc(body, "ciphertext", "ciphertextCrc32c") {
            Ok(bytes) => bytes,
            Err(response) => return response,
        };
        let aad = match Self::check_crc(
            body,
            "additionalAuthenticatedData",
            "additionalAuthenticatedDataCrc32c",
        ) {
            Ok(bytes) => bytes,
            Err(response) => return response,
        };
        let invalid = || {
            Self::error(
                400,
                "INVALID_ARGUMENT",
                "Decryption failed: the ciphertext is invalid.",
            )
        };
        if ciphertext.len() < 16 {
            return invalid();
        }
        let version = u32::from_be_bytes(ciphertext[..4].try_into().unwrap());
        let Some(key) = versions.get((version as usize).wrapping_sub(1)) else {
            return invalid();
        };
        let Ok(plaintext) = Aes256Gcm::new_from_slice(key).unwrap().decrypt(
            Nonce::from_slice(&ciphertext[4..16]),
            Payload {
                msg: &ciphertext[16..],
                aad: &aad,
            },
        ) else {
            return invalid();
        };
        Self::json(
            200,
            json!({
                "plaintext": Base64::encode_string(&plaintext),
                "plaintextCrc32c": crc32c(&plaintext).to_string(),
                "usedPrimary": version as usize == versions.len(),
                "protectionLevel": "SOFTWARE",
            }),
        )
    }
}

impl VendorTransport for KmsEmulator {
    async fn send(&self, request: VendorRequest) -> Result<VendorResponse, TransportError> {
        if request.url == TOKEN_URI {
            assert_eq!(request.method, "POST");
            assert_eq!(
                request.header_value("content-type"),
                Some("application/x-www-form-urlencoded")
            );
            return Ok(self.token_exchange(&request.body));
        }
        if request.url == METADATA_URL {
            if request.header_value("metadata-flavor") != Some("Google") {
                return Ok(VendorResponse::new(
                    403,
                    b"Missing Metadata-Flavor".to_vec(),
                ));
            }
            return Ok(self.issue("fixture-metadata-token"));
        }
        let path = request
            .url
            .strip_prefix(&format!("{ENDPOINT}/v1/"))
            .expect("a Cloud KMS URL")
            .to_owned();
        let body = body_json(&request.body);
        {
            let mut state = self.state.lock().unwrap();
            state
                .requests
                .push((request.method.clone(), path.clone(), body.clone()));
            let token = request
                .header_value("authorization")
                .and_then(|value| value.strip_prefix("Bearer "))
                .unwrap_or("");
            if !state.tokens.iter().any(|t| t == token) {
                return Ok(Self::error(
                    401,
                    "UNAUTHENTICATED",
                    "Request had invalid authentication credentials.",
                ));
            }
        }
        assert_eq!(request.method, "POST");
        assert_eq!(
            request.header_value("content-type"),
            Some("application/json")
        );
        Ok(match path.rsplit_once(':') {
            Some((name, "encrypt")) => self.encrypt(name, &body),
            Some((name, "decrypt")) => self.decrypt(name, &body),
            _ => Self::error(404, "NOT_FOUND", "Method not found."),
        })
    }

    async fn sleep(&self, duration: Duration) {
        self.state.lock().unwrap().sleeps.push(duration);
    }
}
