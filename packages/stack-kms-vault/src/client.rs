//! The Vault Transit client and its [`KeyVendorBackend`] implementation.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use base64ct::{Base64, Encoding};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use stack_kms::{BackendErrorKind, Error, KeyVendor};
use stack_kms_vendor::bound::{bind_key, open_bound_key};
use stack_kms_vendor::{
    classify_status, KeyBytes, KeyVendorBackend, TransportError, VendorRequest, VendorResponse,
    VendorTransport,
};
use zeroize::Zeroizing;

use crate::auth::{AuthError, TokenProvider};
use crate::config::{is_segment, KeyDerivation, VaultConfig};

/// This client's vendor: what [`KeyVendorBackend::vendor`] answers and what its errors name.
const VENDOR: KeyVendor = KeyVendor::Vault;

/// The first byte of a wrapped key this client stores: the format of the
/// rest (`version(4, BE) ‖ Vault ciphertext bytes`).
pub const WRAPPED_KEY_FORMAT: u8 = 1;

/// The Transit key types whose encryption is an AEAD. The client binds the
/// associated data inside the plaintext
/// ([`stack_kms_vendor::bound`]), which is sound only under a
/// non-malleable cipher, so [`KeyDerivation::Detect`] refuses other types.
pub const AEAD_KEY_TYPES: [&str; 3] = ["aes256-gcm96", "aes128-gcm96", "chacha20-poly1305"];

/// The text in a Vault HTTP 400 error that means "this ciphertext does not
/// open" ([`BackendErrorKind::InvalidCiphertext`]), lower case. Checked
/// after [`NOT_FOUND_MARKERS`].
pub const INVALID_CIPHERTEXT_MARKERS: [&str; 6] = [
    "invalid ciphertext",
    "message authentication failed",
    "unable to decrypt",
    "could not decode",
    "ciphertext version",
    "version is too new",
];

/// The text in a Vault HTTP 400 error that means "no such key"
/// ([`BackendErrorKind::NotFound`]), lower case.
pub const NOT_FOUND_MARKERS: [&str; 2] = ["encryption key not found", "key not found"];

/// A failure of a Vault call. It is the `source` of the [`Error::Backend`]
/// the client returns; the kind is on the `Error::Backend`.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// Vault answered with an error.
    #[error("Vault {operation} failed with HTTP {status}: {message}")]
    Service {
        /// The operation (`decrypt`).
        operation: &'static str,
        /// The HTTP status.
        status: u16,
        /// Vault's error text.
        message: String,
    },
    /// The request got no response.
    #[error("Vault {operation} got no response: {source}")]
    Transport {
        /// The operation.
        operation: &'static str,
        /// The transport failure.
        source: TransportError,
    },
    /// No token could be got.
    #[error(transparent)]
    Auth(#[from] AuthError),
    /// Vault answered with a success that this client cannot read.
    #[error("Vault {operation} returned a response this client cannot read: {reason}")]
    InvalidResponse {
        /// The operation.
        operation: &'static str,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The client refused the call before or after it reached Vault.
    #[error("{0}")]
    Refused(&'static str),
}

fn backend(kind: BackendErrorKind, error: VaultError) -> Error {
    Error::Backend {
        backend: VENDOR.into(),
        kind,
        source: Box::new(error),
    }
}

fn invalid(operation: &'static str, reason: &'static str) -> Error {
    backend(
        BackendErrorKind::Unavailable,
        VaultError::InvalidResponse { operation, reason },
    )
}

fn refused(kind: BackendErrorKind, reason: &'static str) -> Error {
    backend(kind, VaultError::Refused(reason))
}

/// The failure kind of a Vault error response.
///
/// * 401 and 403: `AccessDenied`. 404: `NotFound` (a mount or key that does
///   not exist). 429: `Throttled` (a rate limit quota). 5xx: `Unavailable`
///   (503 is a sealed or standby Vault).
/// * 400: by the error text, lower case. [`NOT_FOUND_MARKERS`] first
///   (`NotFound`), then [`INVALID_CIPHERTEXT_MARKERS`]
///   (`InvalidCiphertext`). Any other 400 is a request Vault refused
///   (`AccessDenied`), for example a derived key with no `context`.
/// * Any other 4xx: `AccessDenied`.
pub fn error_kind(status: u16, message: &str) -> BackendErrorKind {
    if status == 400 {
        let message = message.to_ascii_lowercase();
        return if NOT_FOUND_MARKERS.iter().any(|m| message.contains(m)) {
            BackendErrorKind::NotFound
        } else if INVALID_CIPHERTEXT_MARKERS
            .iter()
            .any(|m| message.contains(m))
        {
            BackendErrorKind::InvalidCiphertext
        } else {
            BackendErrorKind::AccessDenied
        };
    }
    match classify_status(status) {
        // Another 4xx is a refused request, not a damaged ciphertext.
        Some(BackendErrorKind::InvalidCiphertext) => BackendErrorKind::AccessDenied,
        Some(kind) => kind,
        None => BackendErrorKind::Unavailable,
    }
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    errors: Vec<String>,
    data: Option<BatchData>,
}

/// Vault's error text: the error of the first failed `batch_input` item,
/// else the `errors` list.
fn failure_message(body: &[u8]) -> String {
    let Ok(body) = serde_json::from_slice::<ErrorBody>(body) else {
        return String::new();
    };
    body.data
        .and_then(|data| {
            data.batch_results
                .into_iter()
                .find_map(|result| result.error.filter(|e| !e.is_empty()))
        })
        .unwrap_or_else(|| body.errors.join("; "))
}

fn service_error(operation: &'static str, status: u16, message: String) -> Error {
    backend(
        error_kind(status, &message),
        VaultError::Service {
            operation,
            status,
            message,
        },
    )
}

#[derive(Deserialize)]
struct BatchResponse {
    data: Option<BatchData>,
}

#[derive(Deserialize)]
struct BatchData {
    #[serde(default)]
    batch_results: Vec<BatchResult>,
}

#[derive(Deserialize)]
struct BatchResult {
    ciphertext: Option<String>,
    plaintext: Option<String>,
    error: Option<String>,
}

/// A request body with one `batch_input` item. The client sends one item
/// in each call, but uses the batch form so that every Transit answer has
/// one shape.
#[derive(Serialize)]
struct BatchRequest<'a, I> {
    batch_input: [&'a I; 1],
}

#[derive(Serialize)]
struct EncryptItem {
    #[serde(serialize_with = "serialize_secret")]
    plaintext: Zeroizing<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
}

fn serialize_secret<S: serde::Serializer>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value)
}

#[derive(Serialize)]
struct CiphertextItem {
    ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
}

#[derive(Deserialize)]
struct KeyRead {
    data: Option<KeyData>,
}

#[derive(Deserialize)]
struct KeyData {
    #[serde(default)]
    derived: bool,
    #[serde(rename = "type")]
    key_type: Option<String>,
    #[serde(default)]
    supports_encryption: bool,
    #[serde(default)]
    supports_decryption: bool,
}

/// The stored form of a Vault ciphertext (`vault:v<n>:<base64>`):
/// [`WRAPPED_KEY_FORMAT`], the key version (4 bytes, big-endian), and the
/// decoded bytes. About 40 bytes shorter than the text.
pub fn compact_ciphertext(ciphertext: &str) -> Option<Vec<u8>> {
    let rest = ciphertext.strip_prefix("vault:v")?;
    let (version, encoded) = rest.split_once(':')?;
    if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let version: u32 = version.parse().ok()?;
    let bytes = Base64::decode_vec(encoded).ok()?;
    if bytes.is_empty() || Base64::encode_string(&bytes) != encoded {
        return None;
    }
    let mut out = Vec::with_capacity(5 + bytes.len());
    out.push(WRAPPED_KEY_FORMAT);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&bytes);
    Some(out)
}

/// The Vault ciphertext text of a stored wrapped key. `None` if the bytes
/// are not one.
pub fn expand_ciphertext(wrapped: &[u8]) -> Option<String> {
    let (&format, rest) = wrapped.split_first()?;
    if format != WRAPPED_KEY_FORMAT {
        return None;
    }
    let (version, bytes) = rest.split_at_checked(4)?;
    if bytes.is_empty() {
        return None;
    }
    let version = u32::from_be_bytes(version.try_into().ok()?);
    Some(format!("vault:v{version}:{}", Base64::encode_string(bytes)))
}

/// A HashiCorp Vault Transit client, and the Vault Transit key vendor
/// backend ([`KeyVendor::Vault`]).
///
/// It speaks the Transit secrets engine API (`encrypt`, `decrypt` and
/// `rewrap`) over a [`VendorTransport`], so the same code runs on native
/// Rust and in the WASI guest. Each call sends one key, as a `batch_input`
/// of one item.
///
/// * `key_ref` (from the keyset record) is the Transit key name. Vault
///   ciphertexts name the key version (`vault:v3:`), so rotation needs no
///   change to the record. [`rewrap`](Self::rewrap) moves a wrapped key to
///   the latest version.
/// * **Calls.** The client calls Vault for keyset records only. One
///   `encrypt` call creates or rewraps a record. One `decrypt` call unwraps
///   the root key of a keyset, once for each root key TTL. No call is made
///   for each value.
/// * **Associated data.** The client always encrypts a bound key
///   ([`stack_kms_vendor::bound`]): the digest of the associated data and
///   the key. For a derived key (`derived=true`) it also sends the
///   associated data as `context`. Vault requires it, and it binds the
///   keyset id in Vault's own key derivation. The client learns which keys
///   are derived from [`KeyDerivation`].
/// * Errors map to [`BackendErrorKind`] by [`error_kind`]. A 403 also tells
///   the token provider to drop its token ([`TokenProvider::invalidate`]).
pub struct VaultTransit<T, A> {
    config: VaultConfig,
    transport: T,
    auth: A,
    /// Whether each key is derived, for [`KeyDerivation::Detect`].
    derived: Mutex<HashMap<String, bool>>,
}

impl<T, A> std::fmt::Debug for VaultTransit<T, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultTransit")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<T: VendorTransport + Send + Sync, A: TokenProvider> VaultTransit<T, A> {
    /// A client for `config`, sending through `transport`, with the tokens
    /// of `auth`.
    pub fn new(config: VaultConfig, transport: T, auth: A) -> Self {
        Self {
            config,
            transport,
            auth,
            derived: Mutex::new(HashMap::new()),
        }
    }

    /// The configuration.
    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    /// The transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// The token provider.
    pub fn auth(&self) -> &A {
        &self.auth
    }

    /// Send one request to the API path `path` (`transit/keys/my-key`, no
    /// `v1/`), with a token, and return the response of a success.
    async fn request(
        &self,
        operation: &'static str,
        method: &str,
        path: &str,
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<VendorResponse, Error> {
        let token = self.auth.token().await.map_err(|error| {
            let kind = error.kind();
            backend(kind, VaultError::Auth(error))
        })?;
        let mut request = VendorRequest::new(method, self.config.url(path))
            .header("x-vault-token", token.token())
            .header("x-vault-request", "true");
        if let Some(namespace) = self.config.namespace() {
            request = request.header("x-vault-namespace", namespace);
        }
        if let Some(body) = body {
            request = request.header("content-type", "application/json");
            request.body = body;
        }
        let response = self.transport.send(request).await.map_err(|source| {
            backend(
                BackendErrorKind::Unavailable,
                VaultError::Transport { operation, source },
            )
        })?;
        if classify_status(response.status).is_some() {
            if response.status == 403 {
                self.auth.invalidate();
            }
            return Err(service_error(
                operation,
                response.status,
                failure_message(&response.body),
            ));
        }
        Ok(response)
    }

    /// Send one request to the API path `path` (no leading `/`, no `v1/`)
    /// and read the JSON of a success. `method` is the HTTP method. Any
    /// Vault API can be called this way (for example to enable the Transit
    /// engine in a test); [`KeyVendorBackend`] uses `encrypt`, `decrypt` and
    /// `keys`. The body is wiped after it is sent.
    pub async fn send_json<R: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<R, Error> {
        let response = self.request("request", method, path, body).await?;
        serde_json::from_slice(&response.body).map_err(|_| invalid("request", "invalid JSON"))
    }

    /// The API path of `operation` on the key `key_ref`.
    fn key_path(&self, operation: &str, key_ref: &str) -> Result<String, Error> {
        if !is_segment(key_ref) {
            return Err(refused(
                BackendErrorKind::NotFound,
                "the key reference is not a Vault Transit key name",
            ));
        }
        Ok(format!("{}/{operation}/{key_ref}", self.config.mount()))
    }

    /// Whether the key `key_ref` is derived: from the config, or read from
    /// Vault once per key ([`KeyDerivation::Detect`]).
    pub async fn is_derived(&self, key_ref: &str) -> Result<bool, Error> {
        match self.config.key_derivation() {
            KeyDerivation::Derived => return Ok(true),
            KeyDerivation::NotDerived => return Ok(false),
            KeyDerivation::Detect => {}
        }
        let path = self.key_path("keys", key_ref)?;
        if let Some(derived) = self
            .derived
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key_ref)
        {
            return Ok(*derived);
        }
        let response = self.request("read key", "GET", &path, None).await?;
        let read: KeyRead = serde_json::from_slice(&response.body)
            .map_err(|_| invalid("read key", "invalid JSON"))?;
        let data = read.data.ok_or_else(|| invalid("read key", "no data"))?;
        let aead = data
            .key_type
            .as_deref()
            .is_some_and(|key_type| AEAD_KEY_TYPES.contains(&key_type));
        if !aead || !data.supports_encryption || !data.supports_decryption {
            return Err(refused(
                BackendErrorKind::AccessDenied,
                "the Transit key is not an AEAD encryption key \
                 (aes256-gcm96, aes128-gcm96 or chacha20-poly1305)",
            ));
        }
        let _ = self
            .derived
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key_ref.to_owned(), data.derived);
        Ok(data.derived)
    }

    /// Send `item` to `operation` on `key_ref`, as a `batch_input` of one
    /// item, and return its result.
    async fn call<I: Serialize>(
        &self,
        operation: &'static str,
        key_ref: &str,
        item: &I,
    ) -> Result<BatchResult, Error> {
        let path = self.key_path(operation, key_ref)?;
        let body = Zeroizing::new(
            serde_json::to_vec(&BatchRequest {
                batch_input: [item],
            })
            .map_err(|_| invalid(operation, "unserializable request"))?,
        );
        let response = self.request(operation, "POST", &path, Some(body)).await?;
        let parsed: BatchResponse = serde_json::from_slice(&response.body)
            .map_err(|_| invalid(operation, "invalid JSON"))?;
        let mut results = parsed
            .data
            .ok_or_else(|| invalid(operation, "no data"))?
            .batch_results;
        if let Some(error) = results
            .iter()
            .find_map(|result| result.error.as_deref().filter(|e| !e.is_empty()))
        {
            return Err(service_error(operation, 400, error.to_owned()));
        }
        match (results.pop(), results.is_empty()) {
            (Some(result), true) => Ok(result),
            _ => Err(invalid(operation, "not exactly one batch result")),
        }
    }

    /// The `context` of `aad` for a derived key.
    fn context(derived: bool, aad: &[u8]) -> Option<String> {
        derived.then(|| Base64::encode_string(aad))
    }

    /// Move a wrapped key to the latest version of its Transit key
    /// (`rewrap`), without the key leaving Vault. `aad` is the associated
    /// data it was wrapped with. Old versions can then be retired with the
    /// key's `min_decryption_version`.
    pub async fn rewrap(
        &self,
        key_ref: &str,
        wrapped: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let derived = self.is_derived(key_ref).await?;
        let item = CiphertextItem {
            ciphertext: expand(wrapped)?,
            context: Self::context(derived, aad),
        };
        let result = self.call("rewrap", key_ref, &item).await?;
        stored("rewrap", result)
    }
}

/// The Vault ciphertext of a stored wrapped key.
fn expand(wrapped: &[u8]) -> Result<String, Error> {
    expand_ciphertext(wrapped).ok_or_else(|| {
        refused(
            BackendErrorKind::InvalidCiphertext,
            "the wrapped key is not a Vault Transit wrapped key",
        )
    })
}

/// The stored form of the ciphertext of a result.
fn stored(operation: &'static str, result: BatchResult) -> Result<Vec<u8>, Error> {
    let ciphertext = result
        .ciphertext
        .ok_or_else(|| invalid(operation, "no ciphertext"))?;
    compact_ciphertext(&ciphertext)
        .ok_or_else(|| invalid(operation, "the ciphertext is not a Vault ciphertext"))
}

impl<T: VendorTransport + Send + Sync, A: TokenProvider> KeyVendorBackend for VaultTransit<T, A> {
    fn vendor(&self) -> KeyVendor {
        VENDOR
    }

    async fn wrap(&self, key_ref: &str, key: &KeyBytes, aad: &[u8]) -> Result<Vec<u8>, Error> {
        let derived = self.is_derived(key_ref).await?;
        let bound = bind_key(key, aad);
        let item = EncryptItem {
            plaintext: Zeroizing::new(Base64::encode_string(&bound)),
            context: Self::context(derived, aad),
        };
        let result = self.call("encrypt", key_ref, &item).await?;
        stored("encrypt", result)
    }

    async fn unwrap(&self, key_ref: &str, wrapped: &[u8], aad: &[u8]) -> Result<KeyBytes, Error> {
        let derived = self.is_derived(key_ref).await?;
        let item = CiphertextItem {
            ciphertext: expand(wrapped)?,
            context: Self::context(derived, aad),
        };
        let result = self.call("decrypt", key_ref, &item).await?;
        let encoded = Zeroizing::new(
            result
                .plaintext
                .ok_or_else(|| invalid("decrypt", "no plaintext"))?,
        );
        let bound = Zeroizing::new(
            Base64::decode_vec(&encoded)
                .map_err(|_| invalid("decrypt", "the plaintext is not base64"))?,
        );
        open_bound_key(&bound, aad).map_err(|_| {
            refused(
                BackendErrorKind::InvalidCiphertext,
                "the wrapped key does not belong to this associated data",
            )
        })
    }

    async fn sleep(&self, duration: Duration) {
        self.transport.sleep(duration).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_map_by_status_and_text() {
        for (status, message, kind) in [
            (400, "encryption key not found", BackendErrorKind::NotFound),
            (
                400,
                "invalid ciphertext: no prefix",
                BackendErrorKind::InvalidCiphertext,
            ),
            (
                400,
                "cipher: message authentication failed",
                BackendErrorKind::InvalidCiphertext,
            ),
            (
                400,
                "invalid ciphertext: could not decode base64",
                BackendErrorKind::InvalidCiphertext,
            ),
            (
                400,
                "invalid ciphertext: version is too new",
                BackendErrorKind::InvalidCiphertext,
            ),
            (
                400,
                "ciphertext version is disallowed by policy (too old)",
                BackendErrorKind::InvalidCiphertext,
            ),
            (
                400,
                "missing 'context' for key derivation",
                BackendErrorKind::AccessDenied,
            ),
            (403, "permission denied", BackendErrorKind::AccessDenied),
            (401, "", BackendErrorKind::AccessDenied),
            (404, "", BackendErrorKind::NotFound),
            (
                429,
                "rate limit quota exceeded",
                BackendErrorKind::Throttled,
            ),
            (500, "", BackendErrorKind::Unavailable),
            (503, "Vault is sealed", BackendErrorKind::Unavailable),
            (412, "", BackendErrorKind::AccessDenied),
        ] {
            assert_eq!(error_kind(status, message), kind, "{status} {message}");
        }
    }

    #[test]
    fn the_message_comes_from_a_failed_item_or_the_errors() {
        assert_eq!(
            failure_message(br#"{"errors":["a","b"]}"#),
            "a; b".to_owned()
        );
        assert_eq!(
            failure_message(
                br#"{"data":{"batch_results":[{"plaintext":"x"},{"error":"cipher: message authentication failed"}]}}"#
            ),
            "cipher: message authentication failed"
        );
        assert_eq!(failure_message(b"not json"), "");
    }

    #[test]
    fn ciphertexts_compact_and_expand_losslessly() {
        let text = "vault:v12:uN5CE4+rarIuFgLc3Etlpo1eG8jFreK4KUzYvlTMZQ==";
        let compact = compact_ciphertext(text).unwrap();
        assert_eq!(compact[0], WRAPPED_KEY_FORMAT);
        assert_eq!(&compact[1..5], &12u32.to_be_bytes());
        assert_eq!(expand_ciphertext(&compact).unwrap(), text);
        for bad in [
            "vault:v1:",
            "vault:1:AAAA",
            "vault:v:AAAA",
            "vault:v-1:AAAA",
            "vault:v1:!!!!",
            "vault:v1:AAA",
            "vault:v99999999999:AAAA",
            "AAAA",
        ] {
            assert_eq!(compact_ciphertext(bad), None, "{bad}");
        }
        for bad in [
            &[][..],
            &[2, 0, 0, 0, 1, 9],
            &[1, 0, 0, 1],
            &[1, 0, 0, 0, 1],
        ] {
            assert_eq!(expand_ciphertext(bad), None, "{bad:?}");
        }
    }
}
