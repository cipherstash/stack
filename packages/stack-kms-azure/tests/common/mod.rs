//! Shared test support: the test-only RSA key, an RFC 3394 key wrap, and an
//! in-process emulation of the Key Vault and Managed HSM key API and the
//! Entra ID token endpoint. The fixture and replay harness is
//! `stack_kms_vendor::replay`, shared by every vendor crate.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::{Oaep, RsaPrivateKey};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use stack_kms_azure::{AccessToken, AzureKeyVault, AzureKeyVaultConfig, KeyId};
use stack_kms_vendor::replay::body_json;
// Each test binary uses a different part of the harness.
#[allow(unused_imports)]
pub use stack_kms_vendor::replay::{Fixture, FixtureRequest, FixtureResponse, Fixtures, Replay};
use stack_kms_vendor::{TransportError, VendorRequest, VendorResponse, VendorTransport};
use web_time::{SystemTime, UNIX_EPOCH};

/// The Key Vault of the fixtures.
pub const VAULT: &str = "https://cipherstash-fixture.vault.azure.net";
/// The Managed HSM of the fixtures.
pub const HSM: &str = "https://cipherstash-fixture.managedhsm.azure.net";
/// The Key Vault RSA key of the fixtures (no version).
pub const RSA_KEY: &str = "https://cipherstash-fixture.vault.azure.net/keys/fixture-rsa-key";
/// Its current version in the fixtures.
pub const RSA_VERSION: &str = "1a2b3c4d5e6f708192a3b4c5d6e7f801";
/// An older version, which `vault_wrap_pinned.json` names.
pub const RSA_OLD_VERSION: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
/// The Managed HSM `oct-HSM` key of the fixtures (no version).
pub const OCT_KEY: &str = "https://cipherstash-fixture.managedhsm.azure.net/keys/fixture-oct-key";
/// Its current version in the fixtures.
pub const OCT_VERSION: &str = "5c6d7e8f90a1b2c3d4e5f60718293a4b";
/// The static access token of the fixtures.
pub const TOKEN: &str = "fixture-access-token";
/// The fixture service principal.
pub const TENANT: &str = "test-only-tenant";
pub const CLIENT_ID: &str = "test-only-client-id";
pub const CLIENT_SECRET: &str = "fixture-client-secret";
/// The Entra ID token endpoint of the fixture tenant.
pub const TOKEN_URL: &str = "https://login.microsoftonline.com/test-only-tenant/oauth2/v2.0/token";
/// The time of the credential fixtures: 2026-11-05T12:00:00Z.
pub const ISSUED_AT: u64 = 1_793_880_000;

pub fn issued_at() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(ISSUED_AT)
}

/// The TEST-ONLY 256-bit AES key of the fixture `oct-HSM` key version: the
/// RFC 3394 example key (`00 01 .. 1F`). It is no one's key.
pub const TEST_ONLY_VENDOR_KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// The TEST-ONLY 2048-bit RSA key of the fixture RSA key, generated for
/// these tests with `openssl genpkey -algorithm RSA -pkeyopt
/// rsa_keygen_bits:2048`. It is no one's key. It is kept as base64 PKCS #8
/// DER, not as PEM or in a key file, so it does not look like a leaked
/// credential.
pub fn test_only_rsa_key() -> RsaPrivateKey {
    let path = format!(
        "{}/tests/fixtures/test_only_rsa_key.pkcs8.b64",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(path).unwrap();
    let body: String = text.split_whitespace().collect();
    RsaPrivateKey::from_pkcs8_der(&Base64::decode_vec(&body).unwrap()).unwrap()
}

const KW_IV: [u8; 8] = [0xA6; 8];

/// AES key wrap (RFC 3394) under a 256-bit key: an implementation for the
/// emulator, pinned by the RFC's own example in `tests/fixtures.rs`.
pub fn kw_wrap(vendor_key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    assert!(plaintext.len().is_multiple_of(8) && plaintext.len() >= 16);
    let cipher = Aes256::new(GenericArray::from_slice(vendor_key));
    let n = plaintext.len() / 8;
    let mut a = KW_IV;
    let mut r: Vec<[u8; 8]> = plaintext.chunks(8).map(|c| c.try_into().unwrap()).collect();
    for j in 0..6 {
        for (i, block) in r.iter_mut().enumerate() {
            let mut b = GenericArray::clone_from_slice(&[a, *block].concat());
            cipher.encrypt_block(&mut b);
            let t = (n * j + i + 1) as u64;
            a = (u64::from_be_bytes(b[..8].try_into().unwrap()) ^ t).to_be_bytes();
            block.copy_from_slice(&b[8..]);
        }
    }
    let mut out = a.to_vec();
    for block in r {
        out.extend_from_slice(&block);
    }
    out
}

/// AES key unwrap (RFC 3394). `None` when the integrity check fails.
pub fn kw_unwrap(vendor_key: &[u8; 32], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if !ciphertext.len().is_multiple_of(8) || ciphertext.len() < 24 {
        return None;
    }
    let cipher = Aes256::new(GenericArray::from_slice(vendor_key));
    let n = ciphertext.len() / 8 - 1;
    let mut a: [u8; 8] = ciphertext[..8].try_into().unwrap();
    let mut r: Vec<[u8; 8]> = ciphertext[8..]
        .chunks(8)
        .map(|c| c.try_into().unwrap())
        .collect();
    for j in (0..6).rev() {
        for i in (0..n).rev() {
            let t = (n * j + i + 1) as u64;
            let a_t = (u64::from_be_bytes(a) ^ t).to_be_bytes();
            let mut b = GenericArray::clone_from_slice(&[a_t, r[i]].concat());
            cipher.decrypt_block(&mut b);
            a.copy_from_slice(&b[..8]);
            r[i].copy_from_slice(&b[8..]);
        }
    }
    (a == KW_IV).then(|| r.concat())
}

/// The fixtures of this crate.
pub const FIXTURES: Fixtures =
    Fixtures::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"));

pub fn load<T: DeserializeOwned>(name: &str) -> T {
    FIXTURES.load(name)
}

pub fn replay(name: &str) -> Replay {
    FIXTURES.replay(name)
}

/// A client with the default configuration over `transport`, with the
/// fixture token.
pub fn fixture_client<T: VendorTransport + Send + Sync>(
    transport: T,
) -> AzureKeyVault<T, AccessToken> {
    AzureKeyVault::new(
        AzureKeyVaultConfig::new(),
        transport,
        AccessToken::new(TOKEN),
    )
}

/// The key material of one key version in the emulator.
#[derive(Clone)]
enum Material {
    /// The test-only RSA key: every RSA version uses it.
    Rsa,
    Aes([u8; 32]),
}

#[derive(Clone)]
struct EmulatedKey {
    rsa: bool,
    enabled: bool,
    /// Versions, oldest first; the last is current.
    versions: Vec<(String, Material, bool)>,
}

#[derive(Default)]
struct EmulatorState {
    /// Keys by `{vault}/keys/{name}`.
    keys: HashMap<String, EmulatedKey>,
    /// Access tokens and their scope (`None`: every scope).
    tokens: HashMap<String, Option<String>>,
    exchanges: usize,
    requests: Vec<(String, String, Value)>,
    sleeps: Vec<Duration>,
    throttle: usize,
    versions: u32,
}

/// An in-process emulation of the Key Vault and Managed HSM key API (`GET
/// /keys`, `wrapkey`, `unwrapkey`; RSA-OAEP-256 with the test-only RSA key,
/// A256KW with per-version AES keys; versions, rotation and disabled
/// versions; Azure's error shapes) and of the Entra ID token endpoint (the
/// client credentials grant with [`CLIENT_SECRET`]). It checks the bearer
/// token and its scope on every key request.
///
/// The contract suite uses random keys and ids, so fixed exchanges cannot
/// serve it: this answers it instead. Clones share one state.
#[derive(Clone)]
pub struct KeyVaultEmulator {
    state: Arc<Mutex<EmulatorState>>,
    rsa: Arc<RsaPrivateKey>,
}

impl std::fmt::Debug for KeyVaultEmulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyVaultEmulator")
    }
}

impl Default for KeyVaultEmulator {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyVaultEmulator {
    /// An emulator holding [`RSA_KEY`] and [`OCT_KEY`] (one version each),
    /// that accepts [`TOKEN`] for every scope.
    pub fn new() -> Self {
        let emulator = Self {
            state: Arc::default(),
            rsa: Arc::new(test_only_rsa_key()),
        };
        emulator.add_key(RSA_KEY, true);
        emulator.add_key(OCT_KEY, false);
        let _ = emulator
            .state
            .lock()
            .unwrap()
            .tokens
            .insert(TOKEN.to_owned(), None);
        emulator
    }

    /// Add a key (`{vault}/keys/{name}`) with one version.
    pub fn add_key(&self, key: &str, rsa: bool) {
        let _ = self.state.lock().unwrap().keys.insert(
            key.to_owned(),
            EmulatedKey {
                rsa,
                enabled: true,
                versions: Vec::new(),
            },
        );
        self.rotate(key);
    }

    /// Add a version to `key` and make it current. Returns the version.
    pub fn rotate(&self, key: &str) -> String {
        let mut state = self.state.lock().unwrap();
        state.versions += 1;
        let version = format!("{:032x}", 0xabc0_0000u64 + u64::from(state.versions));
        let seed = state.versions as u8;
        let entry = state.keys.get_mut(key).unwrap();
        let material = if entry.rsa {
            Material::Rsa
        } else {
            Material::Aes([seed ^ 0x5A; 32])
        };
        entry.versions.push((version.clone(), material, true));
        version
    }

    /// Disable one version of `key`.
    pub fn disable(&self, key: &str, version: &str) {
        let mut state = self.state.lock().unwrap();
        for entry in &mut state.keys.get_mut(key).unwrap().versions {
            if entry.0 == version {
                entry.2 = false;
            }
        }
    }

    /// Answer the next `n` key requests with HTTP 429 and `Retry-After: 2`.
    pub fn throttle(&self, n: usize) {
        self.state.lock().unwrap().throttle = n;
    }

    /// Revoke every access token.
    pub fn revoke_tokens(&self) {
        self.state.lock().unwrap().tokens.clear();
    }

    /// Token endpoint exchanges so far.
    pub fn exchanges(&self) -> usize {
        self.state.lock().unwrap().exchanges
    }

    /// Every key request: method, URL, body.
    pub fn requests(&self) -> Vec<(String, String, Value)> {
        self.state.lock().unwrap().requests.clone()
    }

    pub fn sleeps(&self) -> Vec<Duration> {
        self.state.lock().unwrap().sleeps.clone()
    }

    fn json(status: u16, body: Value) -> VendorResponse {
        VendorResponse::new(status, body.to_string().into_bytes())
            .header("content-type", "application/json; charset=utf-8")
    }

    fn error(status: u16, code: &str, inner: Option<&str>, message: &str) -> VendorResponse {
        let mut error = json!({ "code": code, "message": message });
        if let Some(inner) = inner {
            error["innererror"] = json!({ "code": inner });
        }
        Self::json(status, json!({ "error": error }))
    }

    fn token_exchange(&self, body: &[u8]) -> VendorResponse {
        let form: HashMap<String, String> =
            url::form_urlencoded::parse(body).into_owned().collect();
        let field = |name: &str| form.get(name).map(String::as_str);
        if field("grant_type") != Some("client_credentials")
            || field("client_id") != Some(CLIENT_ID)
        {
            return Self::json(400, json!({ "error": "unauthorized_client" }));
        }
        if field("client_secret") != Some(CLIENT_SECRET) {
            return Self::json(
                401,
                json!({
                    "error": "invalid_client",
                    "error_description": "AADSTS7000215: Invalid client secret provided.",
                }),
            );
        }
        let Some(scope) = field("scope").map(str::to_owned) else {
            return Self::json(400, json!({ "error": "invalid_scope" }));
        };
        let mut state = self.state.lock().unwrap();
        state.exchanges += 1;
        let token = format!("fixture-exchanged-token-{}", state.exchanges);
        let _ = state.tokens.insert(token.clone(), Some(scope));
        Self::json(
            200,
            json!({ "token_type": "Bearer", "expires_in": 3599, "access_token": token }),
        )
    }

    fn get_key(&self, key: &str, version: Option<&str>) -> VendorResponse {
        let state = self.state.lock().unwrap();
        let Some(entry) = state.keys.get(key) else {
            return Self::error(
                404,
                "KeyNotFound",
                None,
                "A key with (name/id) was not found.",
            );
        };
        let found = match version {
            Some(version) => entry.versions.iter().find(|v| v.0 == version),
            None => entry.versions.last(),
        };
        let Some((version, _, enabled)) = found else {
            return Self::error(
                404,
                "KeyNotFound",
                None,
                "A key with (name/id) was not found.",
            );
        };
        let kty = if entry.rsa { "RSA" } else { "oct-HSM" };
        Self::json(
            200,
            json!({
                "key": {
                    "kid": format!("{key}/{version}"),
                    "kty": kty,
                    "key_ops": ["wrapKey", "unwrapKey"],
                },
                "attributes": { "enabled": *enabled && entry.enabled },
            }),
        )
    }

    fn key_operation(
        &self,
        key: &str,
        version: &str,
        operation: &str,
        body: &Value,
    ) -> VendorResponse {
        let (rsa, material, enabled) = {
            let state = self.state.lock().unwrap();
            let Some(entry) = state.keys.get(key) else {
                return Self::error(
                    404,
                    "KeyNotFound",
                    None,
                    "A key with (name/id) was not found.",
                );
            };
            let Some((_, material, enabled)) = entry.versions.iter().find(|v| v.0 == version)
            else {
                return Self::error(
                    404,
                    "KeyNotFound",
                    None,
                    "A key with (name/id) was not found.",
                );
            };
            (entry.rsa, material.clone(), *enabled)
        };
        if !enabled {
            return Self::error(
                403,
                "Forbidden",
                Some("KeyDisabled"),
                "Operation is not allowed on a disabled key.",
            );
        }
        let expected_alg = if rsa { "RSA-OAEP-256" } else { "A256KW" };
        if body["alg"] != expected_alg {
            return Self::error(400, "BadParameter", None, "Invalid algorithm for this key.");
        }
        let Some(value) = body["value"]
            .as_str()
            .and_then(|v| Base64UrlUnpadded::decode_vec(v).ok())
        else {
            return Self::error(
                400,
                "BadParameter",
                None,
                "Property value is not base64url.",
            );
        };
        let result = match (operation, &material) {
            ("wrapkey", Material::Rsa) => Some(
                self.rsa
                    .to_public_key()
                    .encrypt(&mut rand_core::OsRng, Oaep::new::<Sha256>(), &value)
                    .unwrap(),
            ),
            ("unwrapkey", Material::Rsa) => self.rsa.decrypt(Oaep::new::<Sha256>(), &value).ok(),
            ("wrapkey", Material::Aes(vendor_key)) => (value.len().is_multiple_of(8)
                && value.len() >= 16)
                .then(|| kw_wrap(vendor_key, &value)),
            ("unwrapkey", Material::Aes(vendor_key)) => kw_unwrap(vendor_key, &value),
            _ => None,
        };
        match result {
            Some(out) => Self::json(
                200,
                json!({
                    "kid": format!("{key}/{version}"),
                    "value": Base64UrlUnpadded::encode_string(&out),
                }),
            ),
            None => Self::error(
                400,
                "BadParameter",
                None,
                "The value could not be unwrapped.",
            ),
        }
    }
}

impl VendorTransport for KeyVaultEmulator {
    async fn send(&self, request: VendorRequest) -> Result<VendorResponse, TransportError> {
        if request.url == TOKEN_URL {
            assert_eq!(request.method, "POST");
            return Ok(self.token_exchange(&request.body));
        }
        let (path, query) = request.url.split_once('?').expect("an api-version");
        assert_eq!(query, "api-version=7.4");
        let body = body_json(&request.body);
        let (kid, operation) = match path.rsplit_once('/') {
            Some((kid, op @ ("wrapkey" | "unwrapkey"))) => (kid, Some(op)),
            _ => (path, None),
        };
        let id = KeyId::parse(kid).expect("a key identifier");
        {
            let mut state = self.state.lock().unwrap();
            state
                .requests
                .push((request.method.clone(), request.url.clone(), body.clone()));
            let token = request
                .header_value("authorization")
                .and_then(|value| value.strip_prefix("Bearer "))
                .unwrap_or("");
            match state.tokens.get(token) {
                Some(None) => {}
                Some(Some(scope)) if scope == id.scope() => {}
                Some(Some(_)) => {
                    return Ok(Self::error(
                        401,
                        "Unauthorized",
                        None,
                        "AKV10022: Invalid audience.",
                    ))
                }
                None => {
                    return Ok(Self::error(
                        401,
                        "Unauthorized",
                        None,
                        "AKV10032: Invalid issuer.",
                    ))
                }
            }
            if state.throttle > 0 {
                state.throttle -= 1;
                return Ok(Self::error(429, "Throttled", None, "Too many requests.")
                    .header("retry-after", "2"));
            }
        }
        let key = format!("{}/keys/{}", id.vault(), id.name());
        Ok(match (request.method.as_str(), operation) {
            ("GET", None) => self.get_key(&key, id.version()),
            ("POST", Some(operation)) => {
                assert_eq!(
                    request.header_value("content-type"),
                    Some("application/json")
                );
                self.key_operation(&key, id.version().expect("a version"), operation, &body)
            }
            _ => Self::error(405, "MethodNotAllowed", None, "Method not allowed."),
        })
    }

    async fn sleep(&self, duration: Duration) {
        self.state.lock().unwrap().sleeps.push(duration);
    }
}
