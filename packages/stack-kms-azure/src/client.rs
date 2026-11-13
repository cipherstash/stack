//! The Managed HSM client and its [`KeyVendorBackend`] implementation.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use stack_kms::{BackendErrorKind, Error, KeyVendor};
use stack_kms_vendor::bound::{bind_key, open_bound_key, BOUND_KEY_LEN};
use stack_kms_vendor::{
    classify_status, KeyBytes, KeyVendorBackend, TransportError, VendorRequest, VendorResponse,
    VendorTransport,
};
use zeroize::Zeroizing;

use crate::auth::{AuthError, TokenProvider};
use crate::config::{is_version, KeyId, KEY_TYPE, MAX_VERSION_LEN, WRAP_ALGORITHM};

/// This client's vendor: what [`KeyVendorBackend::vendor`] answers and what its errors name.
const VENDOR: KeyVendor = KeyVendor::Azure;

/// The first byte of a wrapped key this client stores: the format of the
/// rest (`version length(1) ‖ version ‖ Azure ciphertext`).
pub const WRAPPED_KEY_FORMAT: u8 = 1;

/// The length of the plaintext the client wraps: the bound key
/// ([`BOUND_KEY_LEN`], 65 bytes) and 7 zero bytes. A256KW needs a multiple
/// of 8 bytes and at least 16.
pub const WRAP_PLAINTEXT_LEN: usize = 72;

/// The longest `Retry-After` the client waits for before it reports
/// `Throttled`. The adapter then backs off on its own as well.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

/// A failure of a Managed HSM call. It is the `source` of the
/// [`Error::Backend`] the client returns; the kind is on the
/// `Error::Backend`.
#[derive(Debug, thiserror::Error)]
pub enum AzureManagedHsmError {
    /// Managed HSM answered with an error.
    #[error("Azure Managed HSM {operation} failed with HTTP {status}: {code}: {message}")]
    Service {
        /// The operation (`unwrapkey`).
        operation: &'static str,
        /// The HTTP status.
        status: u16,
        /// The error code (`Forbidden`), with the inner code after a `/`
        /// when there is one (`Forbidden/KeyDisabled`), or `unknown`.
        code: String,
        /// Azure's error message.
        message: String,
    },
    /// The request got no response.
    #[error("Azure Managed HSM {operation} got no response: {source}")]
    Transport {
        /// The operation.
        operation: &'static str,
        /// The transport failure.
        source: TransportError,
    },
    /// No access token could be got.
    #[error(transparent)]
    Auth(#[from] AuthError),
    /// Managed HSM answered with a success that this client cannot read or
    /// does not trust.
    #[error("Azure Managed HSM {operation} returned a response this client cannot read: {reason}")]
    InvalidResponse {
        /// The operation.
        operation: &'static str,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The client refused the call before or after it reached Managed HSM.
    #[error("{0}")]
    Refused(&'static str),
}

fn backend(kind: BackendErrorKind, error: AzureManagedHsmError) -> Error {
    Error::Backend {
        backend: VENDOR.into(),
        kind,
        source: Box::new(error),
    }
}

fn invalid(operation: &'static str, reason: &'static str) -> Error {
    backend(
        BackendErrorKind::Unavailable,
        AzureManagedHsmError::InvalidResponse { operation, reason },
    )
}

fn refused(kind: BackendErrorKind, reason: &'static str) -> Error {
    backend(kind, AzureManagedHsmError::Refused(reason))
}

/// The error codes (`error.code`, or `error.innererror.code`) that mean a
/// key is disabled, expired or not yet valid. They map to `Unavailable`, as
/// AWS KMS's `DisabledException` does: the key exists, and an operator can
/// enable it again.
pub const KEY_STATE_CODES: [&str; 3] = ["KeyDisabled", "KeyExpired", "KeyNotYetValid"];

/// The failure kind of a Managed HSM error response, by the HTTP `status`
/// and the error codes `codes` (`error.code` and `error.innererror.code`).
/// `unwrap` is true for an `unwrapkey` call.
///
/// * The codes of [`KEY_STATE_CODES`]: `Unavailable`.
/// * 429, or `Throttled`: `Throttled` (the client first waits for
///   `Retry-After`, up to [`MAX_RETRY_AFTER`]).
/// * 401, 403, `Unauthorized`, `Forbidden`: `AccessDenied` (a 401 also
///   drops the cached token).
/// * 404, `KeyNotFound`, `NotFound`: `NotFound`.
/// * 5xx: `Unavailable`.
/// * 400 `BadParameter` on an `unwrapkey`: `InvalidCiphertext` (Azure
///   could not decrypt the bytes: damaged, or wrapped by another key or
///   version).
/// * Any other 4xx is a request Managed HSM refused (`AccessDenied`), as for
///   AWS KMS, Vault and Cloud KMS.
pub fn error_kind(status: u16, codes: &[&str], unwrap: bool) -> BackendErrorKind {
    let has = |wanted: &[&str]| codes.iter().any(|code| wanted.contains(code));
    if has(&KEY_STATE_CODES) {
        return BackendErrorKind::Unavailable;
    }
    if status == 429 || has(&["Throttled"]) {
        return BackendErrorKind::Throttled;
    }
    if matches!(status, 401 | 403) || has(&["Unauthorized", "Forbidden"]) {
        return BackendErrorKind::AccessDenied;
    }
    if status == 404 || has(&["KeyNotFound", "NotFound"]) {
        return BackendErrorKind::NotFound;
    }
    if unwrap && status == 400 && has(&["BadParameter"]) {
        return BackendErrorKind::InvalidCiphertext;
    }
    match classify_status(status) {
        Some(BackendErrorKind::InvalidCiphertext) | None => BackendErrorKind::AccessDenied,
        Some(kind) => kind,
    }
}

#[derive(Deserialize)]
struct ErrorBody {
    error: Option<ErrorDetail>,
}

#[derive(Deserialize)]
struct ErrorDetail {
    code: Option<String>,
    message: Option<String>,
    innererror: Option<InnerError>,
}

#[derive(Deserialize)]
struct InnerError {
    code: Option<String>,
}

fn service_error(operation: &'static str, response: &VendorResponse) -> Error {
    let detail = serde_json::from_slice::<ErrorBody>(&response.body)
        .ok()
        .and_then(|body| body.error);
    let (code, inner, message) = match detail {
        Some(detail) => (
            detail.code,
            detail.innererror.and_then(|inner| inner.code),
            detail.message.unwrap_or_default(),
        ),
        None => (None, None, String::new()),
    };
    let codes: Vec<&str> = [code.as_deref(), inner.as_deref()]
        .into_iter()
        .flatten()
        .collect();
    let kind = error_kind(response.status, &codes, operation == "unwrapkey");
    let code = match codes.as_slice() {
        [] => "unknown".to_owned(),
        codes => codes.join("/"),
    };
    backend(
        kind,
        AzureManagedHsmError::Service {
            operation,
            status: response.status,
            code,
            message,
        },
    )
}

/// The seconds of a `Retry-After` header, capped at [`MAX_RETRY_AFTER`].
/// `None` when there is none or it is not a number of seconds.
pub fn retry_after(response: &VendorResponse) -> Option<Duration> {
    let seconds: u64 = response.header_value("retry-after")?.trim().parse().ok()?;
    Some(Duration::from_secs(seconds).min(MAX_RETRY_AFTER))
}

/// Decode base64url, with or without padding (Azure sends none).
fn decode_base64url(text: &str) -> Option<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(text.trim_end_matches('=')).ok()
}

fn serialize_secret<S: serde::Serializer>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value)
}

#[derive(Serialize)]
struct KeyOperationRequest {
    alg: &'static str,
    #[serde(serialize_with = "serialize_secret")]
    value: Zeroizing<String>,
}

#[derive(Deserialize)]
struct KeyOperationResponse {
    kid: Option<String>,
    value: Option<String>,
}

#[derive(Deserialize)]
struct KeyBundle {
    key: Option<JsonWebKey>,
}

#[derive(Deserialize)]
struct JsonWebKey {
    kid: Option<String>,
    kty: Option<String>,
}

/// The stored form of an Azure wrapped key: [`WRAPPED_KEY_FORMAT`], the
/// length of the key version (1 byte), the key version (ASCII), and the
/// A256KW ciphertext.
///
/// A version is at most [`MAX_VERSION_LEN`] bytes ([`is_version`]); a
/// longer one is cut, and the result then does not split.
pub fn compact_ciphertext(version: &str, ciphertext: &[u8]) -> Vec<u8> {
    let version = &version.as_bytes()[..version.len().min(MAX_VERSION_LEN)];
    let mut out = Vec::with_capacity(2 + version.len() + ciphertext.len());
    out.push(WRAPPED_KEY_FORMAT);
    out.push(version.len() as u8);
    out.extend_from_slice(version);
    out.extend_from_slice(ciphertext);
    out
}

/// A stored wrapped key, split into its parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrappedKeyParts<'a> {
    /// The key version that wrapped it.
    pub version: &'a str,
    /// The A256KW ciphertext.
    pub ciphertext: &'a [u8],
}

/// The parts of a stored wrapped key. `None` if the bytes are not one.
pub fn split_wrapped_key(wrapped: &[u8]) -> Option<WrappedKeyParts<'_>> {
    let (&format, rest) = wrapped.split_first()?;
    if format != WRAPPED_KEY_FORMAT {
        return None;
    }
    let (&len, rest) = rest.split_first()?;
    let (version, ciphertext) = rest.split_at_checked(usize::from(len))?;
    let version = std::str::from_utf8(version).ok()?;
    if !is_version(version) || ciphertext.is_empty() {
        return None;
    }
    Some(WrappedKeyParts {
        version,
        ciphertext,
    })
}

/// The key version that wrapped `wrapped`, or `None` if the bytes are not a
/// wrapped key of this client. Use it to find which versions stored keys
/// still need before you disable a version.
pub fn wrapped_key_version(wrapped: &[u8]) -> Option<&str> {
    split_wrapped_key(wrapped).map(|parts| parts.version)
}

/// The plaintext the client wraps: the bound key of `key` under `aad`,
/// padded to [`WRAP_PLAINTEXT_LEN`] with zeros.
pub fn wrap_plaintext(key: &KeyBytes, aad: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut plaintext = bind_key(key, aad);
    plaintext.resize(WRAP_PLAINTEXT_LEN, 0);
    plaintext
}

/// The key in an unwrapped plaintext, if it is one this client made under
/// `aad`. Anything else is `InvalidCiphertext`.
fn open_plaintext(plaintext: &[u8], aad: &[u8]) -> Result<KeyBytes, Error> {
    if plaintext.len() != WRAP_PLAINTEXT_LEN
        || plaintext[BOUND_KEY_LEN..].iter().any(|&byte| byte != 0)
    {
        return Err(refused(
            BackendErrorKind::InvalidCiphertext,
            "the unwrapped key is not a bound key of this client",
        ));
    }
    open_bound_key(&plaintext[..BOUND_KEY_LEN], aad).map_err(|_| {
        refused(
            BackendErrorKind::InvalidCiphertext,
            "the wrapped key belongs to other associated data",
        )
    })
}

/// An Azure Key Vault Managed HSM client, and the Azure key vendor backend
/// ([`KeyVendor::Azure`]).
///
/// It speaks the Key Vault REST API, which Managed HSM serves
/// ([`API_VERSION`](crate::API_VERSION): `GET /keys/{name}`, `wrapkey` and
/// `unwrapkey`), with an Entra ID access token, over a [`VendorTransport`],
/// so the same code runs on native Rust and in the WASI guest.
///
/// * `key_ref` (from the keyset record) is the key identifier,
///   `https://{hsm}.managedhsm.azure.net/keys/{name}`, optionally with
///   `/{version}`. The key must be an `oct-HSM` (AES-256) key; every wrap
///   is A256KW (RFC 3394). Azure Key Vault (`vault.azure.net`) is not
///   supported: a vault holds only RSA and EC keys, and anyone with an RSA
///   public key can wrap a key, so an RSA wrap would not prove that the
///   key vendor made the keyset record.
/// * **Versions.** Azure needs the key version to unwrap, so every stored
///   wrapped key names the version that wrapped it
///   ([`wrapped_key_version`]). An unwrap reads no key. With no version in
///   `key_ref`, the client reads the key once (`GET /keys/{name}`) to learn
///   its current version and to check its type, and wraps under that
///   version for the life of the client. After a failed wrap it reads the
///   key again, so a disabled old version is left behind. With a version,
///   wraps use that version and read no key.
/// * **Associated data.** `wrapkey` takes no associated data. The client
///   wraps a bound key ([`stack_kms_vendor::bound`]): a SHA-256 digest of
///   the whole associated data (the keyset id, the vendor and the key
///   mode) beside the key, which an unwrap checks. This is sound because
///   only a caller that the HSM lets use the AES key can make a wrapped
///   key, and AES key wrap is non-malleable and checks its own integrity.
///   It is the Azure trade-off: Azure does not see or log the binding, so a
///   wrapped key moved to another keyset record unwraps at Azure (and is
///   then refused here as `InvalidCiphertext`).
/// * **Calls.** The client wraps only a keyset's root key. One `wrapkey`
///   creates a keyset record or rewraps it, and one `unwrapkey` unwraps the
///   root key for each root key TTL
///   ([`DEFAULT_ROOT_KEY_TTL`](stack_kms_vendor::DEFAULT_ROOT_KEY_TTL)).
/// * Errors map to [`BackendErrorKind`] by [`error_kind`]. A 401 also tells
///   the token provider to drop its tokens ([`TokenProvider::invalidate`]).
/// * **Not tested against a live HSM.** The tests run against hand-written
///   fixtures and an in-process emulator only.
pub struct AzureManagedHsm<T, A> {
    transport: T,
    auth: A,
    /// The current key version of each unversioned key reference.
    resolved: Mutex<HashMap<String, String>>,
}

impl<T, A> std::fmt::Debug for AzureManagedHsm<T, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureManagedHsm").finish_non_exhaustive()
    }
}

/// The key identifier of `key_ref`.
fn key_id(key_ref: &str) -> Result<KeyId, Error> {
    KeyId::parse(key_ref).ok_or_else(|| {
        refused(
            BackendErrorKind::NotFound,
            "the key reference is not an Azure Managed HSM key identifier",
        )
    })
}

fn to_json<S: Serialize>(operation: &'static str, value: &S) -> Result<Zeroizing<Vec<u8>>, Error> {
    serde_json::to_vec(value)
        .map(Zeroizing::new)
        .map_err(|_| invalid(operation, "unserializable request"))
}

impl<T: VendorTransport + Send + Sync, A: TokenProvider> AzureManagedHsm<T, A> {
    /// A client sending through `transport`, with the access tokens of
    /// `auth`.
    pub fn new(transport: T, auth: A) -> Self {
        Self {
            transport,
            auth,
            resolved: Mutex::new(HashMap::new()),
        }
    }

    /// The transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// The token provider.
    pub fn auth(&self) -> &A {
        &self.auth
    }

    /// Send one request to `url` with a token for `scope`, and return the
    /// response of a success.
    async fn request(
        &self,
        operation: &'static str,
        method: &str,
        url: String,
        scope: &str,
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<VendorResponse, Error> {
        let token = self.auth.token(scope).await.map_err(|error| {
            let kind = error.kind();
            backend(kind, AzureManagedHsmError::Auth(error))
        })?;
        let mut request = VendorRequest::new(method, url)
            .header("authorization", format!("Bearer {}", token.token()));
        if let Some(body) = body {
            request = request.header("content-type", "application/json");
            request.body = body;
        }
        let response = self.transport.send(request).await.map_err(|source| {
            backend(
                BackendErrorKind::Unavailable,
                AzureManagedHsmError::Transport { operation, source },
            )
        })?;
        if classify_status(response.status).is_some() {
            if response.status == 401 {
                self.auth.invalidate();
            }
            if response.status == 429 {
                if let Some(wait) = retry_after(&response) {
                    self.transport.sleep(wait).await;
                }
            }
            return Err(service_error(operation, &response));
        }
        Ok(response)
    }

    /// Send one request to the key identifier `key_ref` (with no
    /// operation: the key itself), and read the JSON of a success. With
    /// `operation` (`wrapkey`, `create`, `rotate`) it posts to
    /// `{key}/{operation}`. Any key operation can be called this way (for
    /// example `create` in a test); [`KeyVendorBackend`] uses `GET`,
    /// `wrapkey` and `unwrapkey`. The body is wiped after it is sent.
    pub async fn send_json<R: DeserializeOwned>(
        &self,
        method: &str,
        key_ref: &str,
        operation: Option<&str>,
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<R, Error> {
        let id = key_id(key_ref)?;
        if operation.is_some_and(|op| !op.bytes().all(|b| b.is_ascii_lowercase())) {
            return Err(refused(
                BackendErrorKind::AccessDenied,
                "an operation is lower-case letters only",
            ));
        }
        let response = self
            .request("request", method, id.url(operation), id.scope(), body)
            .await?;
        serde_json::from_slice(&response.body).map_err(|_| invalid("request", "invalid JSON"))
    }

    /// The key version a wrap under `id` uses: the pinned one, else the
    /// current one from one key read, kept for the life of the client. The
    /// read also checks that the key is an `oct-HSM` key.
    async fn resolve(&self, key_ref: &str, id: &KeyId) -> Result<String, Error> {
        if let Some(version) = id.version() {
            return Ok(version.to_owned());
        }
        if let Some(version) = self
            .resolved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key_ref)
        {
            return Ok(version.clone());
        }
        let response = self
            .request("get key", "GET", id.url(None), id.scope(), None)
            .await?;
        let bundle: KeyBundle = serde_json::from_slice(&response.body)
            .map_err(|_| invalid("get key", "invalid JSON"))?;
        let key = bundle
            .key
            .ok_or_else(|| invalid("get key", "no key in the response"))?;
        let version = key
            .kid
            .as_deref()
            .and_then(KeyId::parse)
            .filter(|kid| kid.hsm() == id.hsm() && kid.name() == id.name())
            .and_then(|kid| kid.version().map(str::to_owned))
            .ok_or_else(|| invalid("get key", "the kid is not a version of the key"))?;
        if key.kty.as_deref() != Some(KEY_TYPE) {
            return Err(refused(
                BackendErrorKind::AccessDenied,
                "the key cannot wrap keys here (use an oct-HSM key)",
            ));
        }
        let _ = self
            .resolved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key_ref.to_owned(), version.clone());
        Ok(version)
    }

    async fn wrap_resolved(
        &self,
        id: &KeyId,
        version: &str,
        key: &KeyBytes,
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let plaintext = wrap_plaintext(key, aad);
        let body = to_json(
            "wrapkey",
            &KeyOperationRequest {
                alg: WRAP_ALGORITHM,
                value: Zeroizing::new(Base64UrlUnpadded::encode_string(&plaintext)),
            },
        )?;
        let versioned = id.with_version(version);
        let response = self
            .request(
                "wrapkey",
                "POST",
                versioned.url(Some("wrapkey")),
                id.scope(),
                Some(body),
            )
            .await?;
        let parsed: KeyOperationResponse = serde_json::from_slice(&response.body)
            .map_err(|_| invalid("wrapkey", "invalid JSON"))?;
        let kid = parsed.kid.as_deref().and_then(KeyId::parse);
        if kid.as_ref() != Some(&versioned) {
            return Err(invalid(
                "wrapkey",
                "the kid is not the version of the key that was asked for",
            ));
        }
        let ciphertext = parsed
            .value
            .as_deref()
            .and_then(decode_base64url)
            .filter(|ciphertext| !ciphertext.is_empty())
            .ok_or_else(|| invalid("wrapkey", "no base64url wrapped key"))?;
        Ok(compact_ciphertext(version, &ciphertext))
    }
}

impl<T: VendorTransport + Send + Sync, A: TokenProvider> KeyVendorBackend
    for AzureManagedHsm<T, A>
{
    fn vendor(&self) -> KeyVendor {
        VENDOR
    }

    async fn wrap(&self, key_ref: &str, key: &KeyBytes, aad: &[u8]) -> Result<Vec<u8>, Error> {
        let id = key_id(key_ref)?;
        let version = self.resolve(key_ref, &id).await?;
        let result = self.wrap_resolved(&id, &version, key, aad).await;
        if result.is_err() {
            // The version may be disabled or gone: read the key again next
            // time.
            let _ = self
                .resolved
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(key_ref);
        }
        result
    }

    async fn unwrap(&self, key_ref: &str, wrapped: &[u8], aad: &[u8]) -> Result<KeyBytes, Error> {
        let id = key_id(key_ref)?;
        let parts = split_wrapped_key(wrapped).ok_or_else(|| {
            refused(
                BackendErrorKind::InvalidCiphertext,
                "the wrapped key is not an Azure Managed HSM wrapped key",
            )
        })?;
        let body = to_json(
            "unwrapkey",
            &KeyOperationRequest {
                alg: WRAP_ALGORITHM,
                value: Zeroizing::new(Base64UrlUnpadded::encode_string(parts.ciphertext)),
            },
        )?;
        let versioned = id.with_version(parts.version);
        let response = self
            .request(
                "unwrapkey",
                "POST",
                versioned.url(Some("unwrapkey")),
                id.scope(),
                Some(body),
            )
            .await?;
        let parsed: KeyOperationResponse = serde_json::from_slice(&response.body)
            .map_err(|_| invalid("unwrapkey", "invalid JSON"))?;
        let encoded = Zeroizing::new(
            parsed
                .value
                .ok_or_else(|| invalid("unwrapkey", "no unwrapped key"))?,
        );
        let plaintext = Zeroizing::new(
            decode_base64url(&encoded)
                .ok_or_else(|| invalid("unwrapkey", "the unwrapped key is not base64url"))?,
        );
        open_plaintext(&plaintext, aad)
    }

    async fn sleep(&self, duration: Duration) {
        self.transport.sleep(duration).await;
    }
}

#[cfg(test)]
mod tests {
    use vitaminc::protected::{Controlled, Protected};

    use super::*;

    #[test]
    fn errors_map_by_code_then_status() {
        use BackendErrorKind::*;
        for (status, codes, unwrap, kind) in [
            (403, &["Forbidden"][..], false, AccessDenied),
            (
                403,
                &["Forbidden", "ForbiddenByPolicy"],
                false,
                AccessDenied,
            ),
            (403, &["Forbidden", "KeyDisabled"], false, Unavailable),
            (400, &["BadParameter", "KeyExpired"], true, Unavailable),
            (401, &["Unauthorized"], false, AccessDenied),
            (401, &[], false, AccessDenied),
            (404, &["KeyNotFound"], false, NotFound),
            (404, &[], true, NotFound),
            (429, &["Throttled"], false, Throttled),
            (429, &[], false, Throttled),
            (503, &["ServiceUnavailable"], false, Unavailable),
            (500, &[], true, Unavailable),
            (400, &["BadParameter"], true, InvalidCiphertext),
            (400, &["BadParameter"], false, AccessDenied),
            (400, &["BadRequest"], true, AccessDenied),
            (409, &["Conflict"], false, AccessDenied),
            (302, &[], false, AccessDenied),
        ] {
            assert_eq!(
                error_kind(status, codes, unwrap),
                kind,
                "{status} {codes:?} {unwrap}"
            );
        }
    }

    #[test]
    fn service_errors_read_both_codes() {
        let response = VendorResponse::new(
            403,
            br#"{"error":{"code":"Forbidden","message":"Operation wrapKey is not allowed on a disabled key.","innererror":{"code":"KeyDisabled"}}}"#.to_vec(),
        );
        let error = service_error("wrapkey", &response);
        let Error::Backend { kind, source, .. } = error else {
            panic!("not a backend error");
        };
        assert_eq!(kind, BackendErrorKind::Unavailable);
        assert_eq!(
            source.to_string(),
            "Azure Managed HSM wrapkey failed with HTTP 403: Forbidden/KeyDisabled: \
             Operation wrapKey is not allowed on a disabled key."
        );
        let error = service_error("unwrapkey", &VendorResponse::new(502, b"<html>".to_vec()));
        let Error::Backend { kind, source, .. } = error else {
            panic!("not a backend error");
        };
        assert_eq!(kind, BackendErrorKind::Unavailable);
        assert!(source.to_string().contains("HTTP 502: unknown"));
    }

    #[test]
    fn retry_after_is_read_and_capped() {
        let response =
            |value: &str| VendorResponse::new(429, Vec::new()).header("retry-after", value);
        assert_eq!(retry_after(&response("3")), Some(Duration::from_secs(3)));
        assert_eq!(retry_after(&response("3600")), Some(MAX_RETRY_AFTER));
        assert_eq!(
            retry_after(&response("Wed, 21 Oct 2015 07:28:00 GMT")),
            None
        );
        assert_eq!(retry_after(&VendorResponse::new(429, Vec::new())), None);
    }

    #[test]
    fn wrapped_keys_split_losslessly() {
        let version = "0123456789abcdef0123456789abcdef";
        let wrapped = compact_ciphertext(version, b"ciphertext");
        assert_eq!(&wrapped[..2], &[WRAPPED_KEY_FORMAT, 32]);
        assert_eq!(
            split_wrapped_key(&wrapped),
            Some(WrappedKeyParts {
                version,
                ciphertext: b"ciphertext",
            })
        );
        assert_eq!(wrapped_key_version(&wrapped), Some(version));
        for bad in [
            &[][..],
            &[1],
            &[1, 1],
            &[1, 1, b'a'],
            &[2, 1, b'a', 9],
            &[1, 0, 9],
            &[1, 1, b'-', 9],
            &[1, 5, b'a', 9],
            &[1, 1, 0xff, 9],
        ] {
            assert_eq!(split_wrapped_key(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_plaintext_is_a_padded_bound_key() {
        let key = Protected::new([5u8; 32]);
        let plaintext = wrap_plaintext(&key, b"aad");
        assert_eq!(plaintext.len(), WRAP_PLAINTEXT_LEN);
        assert_eq!(plaintext.len() % 8, 0);
        assert_eq!(
            &plaintext[..BOUND_KEY_LEN],
            bind_key(&key, b"aad").as_slice()
        );
        assert_eq!(&plaintext[BOUND_KEY_LEN..], &[0u8; 7]);
        assert_eq!(
            open_plaintext(&plaintext, b"aad").unwrap().risky_ref(),
            &[5u8; 32]
        );
        let kind = |result: Result<KeyBytes, Error>| match result {
            Err(Error::Backend { kind, .. }) => kind,
            _ => panic!("not refused"),
        };
        assert_eq!(
            kind(open_plaintext(&plaintext, b"other")),
            BackendErrorKind::InvalidCiphertext
        );
        assert_eq!(
            kind(open_plaintext(&plaintext[..BOUND_KEY_LEN], b"aad")),
            BackendErrorKind::InvalidCiphertext
        );
        let mut padded = plaintext.to_vec();
        padded[WRAP_PLAINTEXT_LEN - 1] = 1;
        assert_eq!(
            kind(open_plaintext(&padded, b"aad")),
            BackendErrorKind::InvalidCiphertext
        );
    }

    #[test]
    fn base64url_decodes_with_or_without_padding() {
        assert_eq!(decode_base64url("AQI"), Some(vec![1, 2]));
        assert_eq!(decode_base64url("AQI="), Some(vec![1, 2]));
        assert_eq!(decode_base64url("+/8"), None);
    }
}
