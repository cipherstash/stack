//! Shared test support: recorded fixtures, a replaying transport, a
//! recording transport, and an in-process emulation of the Vault Transit
//! API.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use stack_kms_vault::{VaultConfig, VaultToken, VaultTransit};
use stack_kms_vendor::{TransportError, VendorRequest, VendorResponse, VendorTransport};

/// The address of every fixture: a local `vault server -dev`.
pub const ADDRESS: &str = "http://127.0.0.1:8200";
/// The dev root token of every fixture.
pub const TOKEN: &str = "fixture-root-token";
/// The non-derived Transit key of the fixtures.
pub const KEY: &str = "cipherstash-fixture";
/// The derived Transit key of the fixtures.
pub const DERIVED_KEY: &str = "cipherstash-fixture-derived";

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

pub fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

pub fn load<T: for<'de> Deserialize<'de>>(name: &str) -> T {
    let path = fixture_path(name);
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

    /// Expect `fixture`'s request and answer with its response.
    pub fn expect(self, fixture: Fixture) -> Self {
        let response = fixture.response.to_response();
        self.exchanges
            .lock()
            .unwrap()
            .push_back((Some(fixture.request), response));
        self
    }

    /// Expect each exchange of a recorded sequence, in order.
    pub fn expect_all(mut self, fixtures: Vec<Fixture>) -> Self {
        for fixture in fixtures {
            self = self.expect(fixture);
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

/// A transport that sends through `inner` and keeps every exchange, to
/// write fixtures.
pub struct Recording<T> {
    pub inner: T,
    pub exchanges: Mutex<Vec<Fixture>>,
}

impl<T> Recording<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            exchanges: Mutex::new(Vec::new()),
        }
    }

    /// The exchanges so far, and forget them.
    pub fn take(&self) -> Vec<Fixture> {
        std::mem::take(&mut *self.exchanges.lock().unwrap())
    }
}

impl<T: VendorTransport + Send + Sync> VendorTransport for Recording<T> {
    async fn send(&self, request: VendorRequest) -> Result<VendorResponse, TransportError> {
        let recorded = FixtureRequest {
            method: request.method.clone(),
            url: request.url.clone(),
            headers: request.headers.clone(),
            body: body_json(&request.body),
        };
        let response = self.inner.send(request).await?;
        let headers = response
            .header_value("content-type")
            .map(|value| vec![("content-type".to_owned(), value.to_owned())])
            .unwrap_or_default();
        self.exchanges.lock().unwrap().push(Fixture {
            request: recorded,
            response: FixtureResponse {
                status: response.status,
                headers,
                body: body_json(&response.body),
            },
        });
        Ok(response)
    }

    async fn sleep(&self, duration: Duration) {
        self.inner.sleep(duration).await;
    }
}

/// A client over `transport` with the fixture address and token.
pub fn fixture_client<T: VendorTransport + Send + Sync>(
    transport: T,
) -> VaultTransit<T, VaultToken> {
    VaultTransit::new(
        VaultConfig::new(ADDRESS).unwrap(),
        transport,
        VaultToken::new(TOKEN),
    )
}

#[derive(Clone)]
struct EmulatedKey {
    key: [u8; 32],
    derived: bool,
    key_type: &'static str,
}

/// An in-process emulation of the Vault Transit API: key reads, `encrypt`,
/// `decrypt` and `rewrap` with `batch_input`, derived keys (which require
/// `context`, while other keys ignore it, as Vault does), AppRole and
/// Kubernetes logins, and Vault's error shapes. It checks the token and
/// the namespace on every request.
///
/// The contract suite uses random keys and ids, so recorded bytes cannot
/// serve it: this answers it instead. Clones share one state.
#[derive(Clone, Default)]
pub struct TransitEmulator {
    keys: Arc<Mutex<HashMap<String, EmulatedKey>>>,
    tokens: Arc<Mutex<Vec<String>>>,
    logins: Arc<Mutex<usize>>,
    login_lease: Arc<Mutex<u64>>,
    namespace: Arc<Mutex<Option<String>>>,
    requests: Arc<Mutex<Vec<(String, String, Value)>>>,
    sleeps: Arc<Mutex<Vec<Duration>>>,
}

impl TransitEmulator {
    /// An emulator holding the non-derived [`KEY`] and the derived
    /// [`DERIVED_KEY`], that accepts [`TOKEN`].
    pub fn new() -> Self {
        let emulator = Self::default();
        emulator.add_key(KEY, false, "aes256-gcm96");
        emulator.add_key(DERIVED_KEY, true, "aes256-gcm96");
        emulator.tokens.lock().unwrap().push(TOKEN.to_owned());
        *emulator.login_lease.lock().unwrap() = 3600;
        emulator
    }

    pub fn add_key(&self, name: &str, derived: bool, key_type: &'static str) {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = (i as u8) ^ name.len() as u8 ^ u8::from(derived);
        }
        self.keys.lock().unwrap().insert(
            name.to_owned(),
            EmulatedKey {
                key,
                derived,
                key_type,
            },
        );
    }

    /// Require the `X-Vault-Namespace` header `namespace`.
    pub fn with_namespace(self, namespace: &str) -> Self {
        *self.namespace.lock().unwrap() = Some(namespace.to_owned());
        self
    }

    /// Revoke every token.
    pub fn revoke_tokens(&self) {
        self.tokens.lock().unwrap().clear();
    }

    pub fn logins(&self) -> usize {
        *self.logins.lock().unwrap()
    }

    /// Every request: method, path after `/v1/`, body.
    pub fn requests(&self) -> Vec<(String, String, Value)> {
        self.requests.lock().unwrap().clone()
    }

    pub fn sleeps(&self) -> Vec<Duration> {
        self.sleeps.lock().unwrap().clone()
    }

    fn error(status: u16, message: &str) -> VendorResponse {
        VendorResponse::new(
            status,
            json!({ "errors": [message] }).to_string().into_bytes(),
        )
        .header("content-type", "application/json")
    }

    fn ok(data: Value) -> VendorResponse {
        VendorResponse::new(
            200,
            json!({ "request_id": "emulated", "data": data })
                .to_string()
                .into_bytes(),
        )
        .header("content-type", "application/json")
    }

    fn cipher(key: &EmulatedKey, context: Option<&str>) -> Result<Aes256Gcm, String> {
        let key_bytes = if key.derived {
            let context = context.filter(|c| !c.is_empty()).ok_or(
                "missing 'context' for key derivation; the key was created using a derived key",
            )?;
            let mut hasher = Sha256::new();
            hasher.update(key.key);
            hasher.update(
                Base64::decode_vec(context).map_err(|_| "failed to base64-decode context")?,
            );
            hasher.finalize().into()
        } else {
            key.key
        };
        Ok(Aes256Gcm::new_from_slice(&key_bytes).unwrap())
    }

    fn encrypt(key: &EmulatedKey, item: &Value, counter: &mut u8) -> Value {
        let cipher = match Self::cipher(key, item["context"].as_str()) {
            Ok(cipher) => cipher,
            Err(error) => return json!({ "error": error }),
        };
        let Ok(plaintext) = Base64::decode_vec(item["plaintext"].as_str().unwrap_or("")) else {
            return json!({ "error": "failed to base64-decode plaintext" });
        };
        *counter = counter.wrapping_add(1);
        let nonce = [*counter; 12];
        let mut out = nonce.to_vec();
        out.extend(
            cipher
                .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
                .unwrap(),
        );
        json!({ "ciphertext": format!("vault:v1:{}", Base64::encode_string(&out)), "key_version": 1 })
    }

    fn decrypt(key: &EmulatedKey, item: &Value) -> Result<Vec<u8>, String> {
        let cipher = Self::cipher(key, item["context"].as_str())?;
        let text = item["ciphertext"].as_str().unwrap_or("");
        let encoded = text
            .strip_prefix("vault:v1:")
            .ok_or("invalid ciphertext: no prefix")?;
        let bytes = Base64::decode_vec(encoded)
            .map_err(|_| "invalid ciphertext: could not decode base64")?;
        if bytes.len() < 12 {
            return Err("invalid ciphertext length".into());
        }
        let (nonce, ct) = bytes.split_at(12);
        cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| "cipher: message authentication failed".into())
    }

    fn login(&self, path: &str, body: &Value) -> VendorResponse {
        let ok = match path {
            "auth/approle/login" => {
                body["role_id"] == "fixture-role-id" && body["secret_id"] == "fixture-secret-id"
            }
            "auth/kubernetes/login" => {
                body["role"] == "cipherstash" && body["jwt"] == "fixture.jwt.token"
            }
            _ => return Self::error(404, "no handler for route"),
        };
        if !ok {
            return Self::error(400, "invalid role or secret ID");
        }
        let mut logins = self.logins.lock().unwrap();
        *logins += 1;
        let token = format!("hvs.emulated-{logins}");
        self.tokens.lock().unwrap().push(token.clone());
        VendorResponse::new(
            200,
            json!({
                "auth": {
                    "client_token": token,
                    "lease_duration": *self.login_lease.lock().unwrap(),
                    "renewable": true
                }
            })
            .to_string()
            .into_bytes(),
        )
    }
}

impl VendorTransport for TransitEmulator {
    async fn send(&self, request: VendorRequest) -> Result<VendorResponse, TransportError> {
        let path = request
            .url
            .split_once("/v1/")
            .map(|(_, path)| path.to_owned())
            .expect("a /v1/ URL");
        let body = body_json(&request.body);
        self.requests
            .lock()
            .unwrap()
            .push((request.method.clone(), path.clone(), body.clone()));
        let namespace = self.namespace.lock().unwrap().clone();
        assert_eq!(
            request.header_value("x-vault-namespace").map(str::to_owned),
            namespace,
            "the namespace header"
        );
        assert_eq!(request.header_value("x-vault-request"), Some("true"));
        if path.starts_with("auth/") {
            return Ok(self.login(&path, &body));
        }
        let token = request
            .header_value("x-vault-token")
            .unwrap_or("")
            .to_owned();
        if !self.tokens.lock().unwrap().contains(&token) {
            return Ok(Self::error(403, "permission denied"));
        }
        let mut parts = path.splitn(3, '/');
        let (Some("transit"), Some(operation), Some(name)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Ok(Self::error(404, "no handler for route"));
        };
        let key = self.keys.lock().unwrap().get(name).cloned();
        if operation == "keys" && request.method == "GET" {
            let Some(key) = key else {
                return Ok(Self::error(404, ""));
            };
            return Ok(Self::ok(json!({
                "name": name,
                "derived": key.derived,
                "type": key.key_type,
                "supports_encryption": true,
                "supports_decryption": true,
                "latest_version": 1
            })));
        }
        let Some(key) = key else {
            return Ok(Self::error(400, "encryption key not found"));
        };
        let items = body["batch_input"].as_array().cloned().unwrap_or_default();
        let has_context = items.iter().filter(|i| i.get("context").is_some()).count();
        if has_context != 0 && has_context != items.len() {
            return Ok(Self::error(
                400,
                "context should be set either in all the request blocks or in none",
            ));
        }
        let mut counter = 0u8;
        let results: Vec<Value> = match operation {
            "encrypt" => items
                .iter()
                .map(|i| Self::encrypt(&key, i, &mut counter))
                .collect(),
            "decrypt" => items
                .iter()
                .map(|i| match Self::decrypt(&key, i) {
                    Ok(plaintext) => json!({ "plaintext": Base64::encode_string(&plaintext) }),
                    Err(error) => json!({ "plaintext": "", "error": error }),
                })
                .collect(),
            "rewrap" => items
                .iter()
                .map(|i| match Self::decrypt(&key, i) {
                    Ok(plaintext) => {
                        let mut item = i.clone();
                        item["plaintext"] = Value::String(Base64::encode_string(&plaintext));
                        Self::encrypt(&key, &item, &mut counter)
                    }
                    Err(error) => json!({ "error": error }),
                })
                .collect(),
            _ => return Ok(Self::error(404, "no handler for route")),
        };
        let failed = results.iter().any(|r| r.get("error").is_some());
        let mut response = Self::ok(json!({ "batch_results": results }));
        if failed {
            response.status = 400;
        }
        Ok(response)
    }

    async fn sleep(&self, duration: Duration) {
        self.sleeps.lock().unwrap().push(duration);
    }
}
