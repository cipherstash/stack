//! The Cloud KMS client and its [`KeyVendorBackend`] implementation.

use std::time::Duration;

use base64ct::{Base64, Encoding};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use stack_kms::{BackendErrorKind, Error, KeyVendor};
use stack_kms_vendor::{
    classify_status, KeyBytes, KeyVendorBackend, TransportError, VendorRequest, VendorResponse,
    VendorTransport,
};
use vitaminc::protected::{Controlled, Protected};
use zeroize::Zeroizing;

use crate::auth::{AuthError, TokenProvider};
use crate::config::{parse_key_name, GcpKmsConfig};
use crate::crc32c::crc32c;

/// The vendor name in errors ([`KeyVendor::name`] of [`KeyVendor::Gcp`]).
const VENDOR: &str = "gcp-kms";

/// The first byte of a wrapped key this client stores: the format of the
/// rest (`key version(4, BE) ‖ Cloud KMS ciphertext`).
pub const WRAPPED_KEY_FORMAT: u8 = 1;

/// The text in an `INVALID_ARGUMENT` error that means "this ciphertext does
/// not open" ([`BackendErrorKind::InvalidCiphertext`]), lower case. Cloud
/// KMS says `Decryption failed: the ciphertext is invalid.` for damaged
/// bytes and other associated data, and `Decryption failed: verify that
/// 'name' refers to the correct CryptoKey.` for another key.
pub const INVALID_CIPHERTEXT_MARKERS: [&str; 2] = ["decryption failed", "ciphertext is invalid"];

/// The text in an `INVALID_ARGUMENT` error that means "a CRC32C did not
/// match the data" ([`BackendErrorKind::Unavailable`]), lower case: the
/// request was damaged on the way, so the same request can succeed later.
pub const CHECKSUM_MARKERS: [&str; 2] = ["checksum", "crc32c"];

/// A failure of a Cloud KMS call. It is the `source` of the
/// [`Error::Backend`] the client returns; the kind is on the
/// `Error::Backend`.
#[derive(Debug, thiserror::Error)]
pub enum GcpKmsError {
    /// Cloud KMS answered with an error.
    #[error("Cloud KMS {operation} failed with HTTP {status}: {code}: {message}")]
    Service {
        /// The operation (`decrypt`).
        operation: &'static str,
        /// The HTTP status.
        status: u16,
        /// The `google.rpc.Code` name (`PERMISSION_DENIED`), or `unknown`.
        code: String,
        /// Google's error message.
        message: String,
    },
    /// The request got no response.
    #[error("Cloud KMS {operation} got no response: {source}")]
    Transport {
        /// The operation.
        operation: &'static str,
        /// The transport failure.
        source: TransportError,
    },
    /// No access token could be got.
    #[error(transparent)]
    Auth(#[from] AuthError),
    /// Cloud KMS answered with a success that this client cannot read or
    /// does not trust (a CRC32C that does not match).
    #[error("Cloud KMS {operation} returned a response this client cannot read: {reason}")]
    InvalidResponse {
        /// The operation.
        operation: &'static str,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The client refused the call before or after it reached Cloud KMS.
    #[error("{0}")]
    Refused(&'static str),
}

fn backend(kind: BackendErrorKind, error: GcpKmsError) -> Error {
    Error::Backend {
        vendor: VENDOR,
        kind,
        source: Box::new(error),
    }
}

fn invalid(operation: &'static str, reason: &'static str) -> Error {
    backend(
        BackendErrorKind::Unavailable,
        GcpKmsError::InvalidResponse { operation, reason },
    )
}

fn refused(kind: BackendErrorKind, reason: &'static str) -> Error {
    backend(kind, GcpKmsError::Refused(reason))
}

/// The failure kind of a Cloud KMS error response: by the `google.rpc.Code`
/// name in `error.status` (`code`), then by the HTTP status.
///
/// * `PERMISSION_DENIED`, `UNAUTHENTICATED`: `AccessDenied`. Note that Cloud
///   KMS answers `PERMISSION_DENIED`, not `NOT_FOUND`, for a key the caller
///   may not see.
/// * `NOT_FOUND`: `NotFound`.
/// * `RESOURCE_EXHAUSTED`: `Throttled` (a quota; the adapter backs off).
/// * `UNAVAILABLE`, `DEADLINE_EXCEEDED`, `INTERNAL`, `UNKNOWN`, `ABORTED`,
///   `CANCELLED`: `Unavailable`. `FAILED_PRECONDITION` (a disabled or
///   destroyed key version, a key with no primary version) is `Unavailable`
///   too, as AWS KMS's `DisabledException` is.
/// * `INVALID_ARGUMENT`: by the message, lower case. [`CHECKSUM_MARKERS`]
///   first (`Unavailable`), then [`INVALID_CIPHERTEXT_MARKERS`]
///   (`InvalidCiphertext`). Any other `INVALID_ARGUMENT` is a request Cloud
///   KMS refused (`AccessDenied`), as for AWS KMS and Vault.
/// * No or another code: the HTTP status (401 and 403 `AccessDenied`, 404
///   `NotFound`, 429 `Throttled`, 5xx `Unavailable`); any other 4xx is
///   `AccessDenied`.
pub fn error_kind(status: u16, code: &str, message: &str) -> BackendErrorKind {
    match code {
        "PERMISSION_DENIED" | "UNAUTHENTICATED" => BackendErrorKind::AccessDenied,
        "NOT_FOUND" => BackendErrorKind::NotFound,
        "RESOURCE_EXHAUSTED" => BackendErrorKind::Throttled,
        "UNAVAILABLE"
        | "DEADLINE_EXCEEDED"
        | "INTERNAL"
        | "UNKNOWN"
        | "ABORTED"
        | "CANCELLED"
        | "FAILED_PRECONDITION" => BackendErrorKind::Unavailable,
        "INVALID_ARGUMENT" => {
            let message = message.to_ascii_lowercase();
            if CHECKSUM_MARKERS.iter().any(|m| message.contains(m)) {
                BackendErrorKind::Unavailable
            } else if INVALID_CIPHERTEXT_MARKERS
                .iter()
                .any(|m| message.contains(m))
            {
                BackendErrorKind::InvalidCiphertext
            } else {
                BackendErrorKind::AccessDenied
            }
        }
        _ => match classify_status(status) {
            // Another 4xx is a refused request, not a damaged ciphertext.
            Some(BackendErrorKind::InvalidCiphertext) => BackendErrorKind::AccessDenied,
            Some(kind) => kind,
            None => BackendErrorKind::Unavailable,
        },
    }
}

#[derive(Deserialize)]
struct ErrorBody {
    error: Option<ErrorStatus>,
}

#[derive(Deserialize)]
struct ErrorStatus {
    message: Option<String>,
    status: Option<String>,
}

fn service_error(operation: &'static str, response: &VendorResponse) -> Error {
    let status = serde_json::from_slice::<ErrorBody>(&response.body)
        .ok()
        .and_then(|body| body.error);
    let (code, message) = match status {
        Some(status) => (
            status.status.unwrap_or_else(|| "unknown".to_owned()),
            status.message.unwrap_or_default(),
        ),
        None => ("unknown".to_owned(), String::new()),
    };
    backend(
        error_kind(response.status, &code, &message),
        GcpKmsError::Service {
            operation,
            status: response.status,
            code,
            message,
        },
    )
}

/// An `int64` of a JSON response: protobuf's JSON form is a string, but a
/// number is accepted too.
fn read_u64(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::String(text) => text.parse().ok(),
        serde_json::Value::Number(number) => number.as_u64(),
        _ => None,
    }
}

fn serialize_secret<S: serde::Serializer>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptRequest {
    #[serde(serialize_with = "serialize_secret")]
    plaintext: Zeroizing<String>,
    additional_authenticated_data: String,
    plaintext_crc32c: String,
    additional_authenticated_data_crc32c: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptResponse {
    name: Option<String>,
    ciphertext: Option<String>,
    ciphertext_crc32c: Option<serde_json::Value>,
    #[serde(default)]
    verified_plaintext_crc32c: bool,
    #[serde(default)]
    verified_additional_authenticated_data_crc32c: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DecryptRequest {
    ciphertext: String,
    additional_authenticated_data: String,
    ciphertext_crc32c: String,
    additional_authenticated_data_crc32c: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecryptResponse {
    plaintext: Option<String>,
    plaintext_crc32c: Option<serde_json::Value>,
}

/// The stored form of a Cloud KMS ciphertext: [`WRAPPED_KEY_FORMAT`], the
/// number of the key version that encrypted it (4 bytes, big-endian), and
/// the ciphertext.
pub fn compact_ciphertext(version: u32, ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + ciphertext.len());
    out.push(WRAPPED_KEY_FORMAT);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(ciphertext);
    out
}

/// The key version and the Cloud KMS ciphertext of a stored wrapped key.
/// `None` if the bytes are not one.
pub fn split_wrapped_key(wrapped: &[u8]) -> Option<(u32, &[u8])> {
    let (&format, rest) = wrapped.split_first()?;
    if format != WRAPPED_KEY_FORMAT {
        return None;
    }
    let (version, ciphertext) = rest.split_at_checked(4)?;
    if ciphertext.is_empty() {
        return None;
    }
    Some((u32::from_be_bytes(version.try_into().ok()?), ciphertext))
}

/// The number of the crypto key version that wrapped `wrapped`, or `None`
/// if the bytes are not a wrapped key of this client. Use it to find which
/// versions stored keys still need before you disable or destroy one.
pub fn wrapped_key_version(wrapped: &[u8]) -> Option<u32> {
    split_wrapped_key(wrapped).map(|(version, _)| version)
}

/// A Google Cloud KMS client, and the Google Cloud KMS key vendor backend
/// ([`KeyVendor::Gcp`]).
///
/// It speaks the Cloud KMS REST API v1 (`cryptoKeys.encrypt` and
/// `cryptoKeys.decrypt`) with an OAuth 2.0 access token, over a
/// [`VendorTransport`], so the same code runs on native Rust and in the
/// WASI guest.
///
/// * `key_ref` (from the keyset record) is the crypto key name,
///   `projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}`, of a
///   symmetric `ENCRYPT_DECRYPT` key. Each `encrypt` uses the key's primary
///   version, and the client stores that version's number in the wrapped
///   key ([`wrapped_key_version`]); `decrypt` finds the version from the
///   ciphertext, so rotation needs no change to the record. A
///   `…/cryptoKeyVersions/{n}` name pins `encrypt` to that version.
/// * **Associated data.** The whole associated data (it holds the keyset
///   id and, for a wrapped data key, the iv and the descriptor) is sent as
///   `additionalAuthenticatedData`. Cloud KMS refuses a `decrypt` under
///   other associated data.
/// * **Integrity.** Every request carries the CRC32C of each field it
///   sends, and the client checks the CRC32C of each field Cloud KMS
///   returns, and that Cloud KMS verified the ones it was sent.
/// * Cloud KMS has no data key generation and no batch operation: each
///   wrapped data key is a key from the local CSPRNG and one `encrypt`.
/// * Errors map to [`BackendErrorKind`] by [`error_kind`]. A 401 also tells
///   the token provider to drop its token ([`TokenProvider::invalidate`]).
pub struct GcpKms<T, A> {
    config: GcpKmsConfig,
    transport: T,
    auth: A,
}

impl<T, A> std::fmt::Debug for GcpKms<T, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpKms")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<T: VendorTransport + Send + Sync, A: TokenProvider> GcpKms<T, A> {
    /// A client for `config`, sending through `transport`, with the access
    /// tokens of `auth`.
    pub fn new(config: GcpKmsConfig, transport: T, auth: A) -> Self {
        Self {
            config,
            transport,
            auth,
        }
    }

    /// The configuration.
    pub fn config(&self) -> &GcpKmsConfig {
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

    /// Send one request to the API path `path` (after `/v1/`), with an
    /// access token, and return the response of a success.
    async fn request(
        &self,
        operation: &'static str,
        method: &str,
        path: &str,
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<VendorResponse, Error> {
        let token = self.auth.token().await.map_err(|error| {
            let kind = error.kind();
            backend(kind, GcpKmsError::Auth(error))
        })?;
        let mut request =
            VendorRequest::new(method, format!("{}/v1/{path}", self.config.endpoint()))
                .header("authorization", format!("Bearer {}", token.token()));
        if let Some(body) = body {
            request = request.header("content-type", "application/json");
            request.body = body;
        }
        let response = self.transport.send(request).await.map_err(|source| {
            backend(
                BackendErrorKind::Unavailable,
                GcpKmsError::Transport { operation, source },
            )
        })?;
        if classify_status(response.status).is_some() {
            if response.status == 401 {
                self.auth.invalidate();
            }
            return Err(service_error(operation, &response));
        }
        Ok(response)
    }

    /// Send one request to the API path `path` (after `/v1/`, for example
    /// `projects/p/locations/global/keyRings/r/cryptoKeys/k`) and read the
    /// JSON of a success. `method` is the HTTP method. Any Cloud KMS method
    /// can be called this way (for example `cryptoKeys.get` in a test);
    /// [`KeyVendorBackend`] uses `encrypt` and `decrypt`. The body is wiped
    /// after it is sent.
    pub async fn send_json<R: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<R, Error> {
        let response = self.request("request", method, path, body).await?;
        serde_json::from_slice(&response.body).map_err(|_| invalid("request", "invalid JSON"))
    }
}

/// The crypto key name and the pinned version of `key_ref`.
fn key_name(key_ref: &str) -> Result<(&str, Option<u32>), Error> {
    parse_key_name(key_ref).ok_or_else(|| {
        refused(
            BackendErrorKind::NotFound,
            "the key reference is not a Cloud KMS crypto key name",
        )
    })
}

fn to_json<S: Serialize>(operation: &'static str, value: &S) -> Result<Zeroizing<Vec<u8>>, Error> {
    serde_json::to_vec(value)
        .map(Zeroizing::new)
        .map_err(|_| invalid(operation, "unserializable request"))
}

impl<T: VendorTransport + Send + Sync, A: TokenProvider> KeyVendorBackend for GcpKms<T, A> {
    fn vendor(&self) -> KeyVendor {
        KeyVendor::Gcp
    }

    async fn wrap(&self, key_ref: &str, key: &KeyBytes, aad: &[u8]) -> Result<Vec<u8>, Error> {
        let (crypto_key, _) = key_name(key_ref)?;
        let body = to_json(
            "encrypt",
            &EncryptRequest {
                plaintext: Zeroizing::new(Base64::encode_string(key.risky_ref())),
                additional_authenticated_data: Base64::encode_string(aad),
                plaintext_crc32c: crc32c(key.risky_ref()).to_string(),
                additional_authenticated_data_crc32c: crc32c(aad).to_string(),
            },
        )?;
        let response = self
            .request("encrypt", "POST", &format!("{key_ref}:encrypt"), Some(body))
            .await?;
        let parsed: EncryptResponse = serde_json::from_slice(&response.body)
            .map_err(|_| invalid("encrypt", "invalid JSON"))?;
        if !parsed.verified_plaintext_crc32c
            || !parsed.verified_additional_authenticated_data_crc32c
        {
            return Err(invalid(
                "encrypt",
                "Cloud KMS did not verify the CRC32C of the request",
            ));
        }
        let ciphertext = Base64::decode_vec(
            parsed
                .ciphertext
                .as_deref()
                .ok_or_else(|| invalid("encrypt", "no ciphertext"))?,
        )
        .map_err(|_| invalid("encrypt", "the ciphertext is not base64"))?;
        if ciphertext.is_empty() {
            return Err(invalid("encrypt", "an empty ciphertext"));
        }
        let expected = parsed
            .ciphertext_crc32c
            .as_ref()
            .and_then(read_u64)
            .ok_or_else(|| invalid("encrypt", "no ciphertext CRC32C"))?;
        if u64::from(crc32c(&ciphertext)) != expected {
            return Err(invalid("encrypt", "the ciphertext CRC32C does not match"));
        }
        let version = match parsed.name.as_deref().and_then(parse_key_name) {
            Some((name, Some(version))) if name == crypto_key => version,
            _ => {
                return Err(invalid(
                    "encrypt",
                    "the response does not name a version of the key",
                ))
            }
        };
        Ok(compact_ciphertext(version, &ciphertext))
    }

    async fn unwrap(&self, key_ref: &str, wrapped: &[u8], aad: &[u8]) -> Result<KeyBytes, Error> {
        let (crypto_key, _) = key_name(key_ref)?;
        let (_, ciphertext) = split_wrapped_key(wrapped).ok_or_else(|| {
            refused(
                BackendErrorKind::InvalidCiphertext,
                "the wrapped key is not a Cloud KMS wrapped key",
            )
        })?;
        let body = to_json(
            "decrypt",
            &DecryptRequest {
                ciphertext: Base64::encode_string(ciphertext),
                additional_authenticated_data: Base64::encode_string(aad),
                ciphertext_crc32c: crc32c(ciphertext).to_string(),
                additional_authenticated_data_crc32c: crc32c(aad).to_string(),
            },
        )?;
        let response = self
            .request(
                "decrypt",
                "POST",
                &format!("{crypto_key}:decrypt"),
                Some(body),
            )
            .await?;
        let parsed: DecryptResponse = serde_json::from_slice(&response.body)
            .map_err(|_| invalid("decrypt", "invalid JSON"))?;
        let encoded = Zeroizing::new(
            parsed
                .plaintext
                .ok_or_else(|| invalid("decrypt", "no plaintext"))?,
        );
        let plaintext = Zeroizing::new(
            Base64::decode_vec(&encoded)
                .map_err(|_| invalid("decrypt", "the plaintext is not base64"))?,
        );
        let expected = parsed
            .plaintext_crc32c
            .as_ref()
            .and_then(read_u64)
            .ok_or_else(|| invalid("decrypt", "no plaintext CRC32C"))?;
        if u64::from(crc32c(&plaintext)) != expected {
            return Err(invalid("decrypt", "the plaintext CRC32C does not match"));
        }
        let key: [u8; 32] = plaintext.as_slice().try_into().map_err(|_| {
            refused(
                BackendErrorKind::InvalidCiphertext,
                "the wrapped key does not hold a 256-bit key",
            )
        })?;
        Ok(Protected::new(key))
    }

    async fn sleep(&self, duration: Duration) {
        self.transport.sleep(duration).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_map_by_code_then_status() {
        use BackendErrorKind::*;
        for (status, code, message, kind) in [
            (403, "PERMISSION_DENIED", "Permission denied", AccessDenied),
            (401, "UNAUTHENTICATED", "", AccessDenied),
            (404, "NOT_FOUND", "CryptoKey not found.", NotFound),
            (429, "RESOURCE_EXHAUSTED", "Quota exceeded", Throttled),
            (503, "UNAVAILABLE", "", Unavailable),
            (504, "DEADLINE_EXCEEDED", "", Unavailable),
            (500, "INTERNAL", "", Unavailable),
            (500, "UNKNOWN", "", Unavailable),
            (409, "ABORTED", "", Unavailable),
            (499, "CANCELLED", "", Unavailable),
            (400, "FAILED_PRECONDITION", "is not enabled", Unavailable),
            (
                400,
                "INVALID_ARGUMENT",
                "Decryption failed: the ciphertext is invalid.",
                InvalidCiphertext,
            ),
            (
                400,
                "INVALID_ARGUMENT",
                "Decryption failed: verify that 'name' refers to the correct CryptoKey.",
                InvalidCiphertext,
            ),
            (
                400,
                "INVALID_ARGUMENT",
                "The checksum in field ciphertext_crc32c did not match the data in field ciphertext.",
                Unavailable,
            ),
            (
                400,
                "INVALID_ARGUMENT",
                "Plaintext must be at most 65536 bytes.",
                AccessDenied,
            ),
            (403, "unknown", "", AccessDenied),
            (404, "unknown", "", NotFound),
            (429, "unknown", "", Throttled),
            (502, "unknown", "", Unavailable),
            (412, "unknown", "", AccessDenied),
            (302, "unknown", "", AccessDenied),
        ] {
            assert_eq!(
                error_kind(status, code, message),
                kind,
                "{status} {code} {message}"
            );
        }
    }

    #[test]
    fn wrapped_keys_split_losslessly() {
        let wrapped = compact_ciphertext(7, b"ciphertext");
        assert_eq!(wrapped[0], WRAPPED_KEY_FORMAT);
        assert_eq!(&wrapped[1..5], &7u32.to_be_bytes());
        assert_eq!(split_wrapped_key(&wrapped), Some((7, &b"ciphertext"[..])));
        assert_eq!(wrapped_key_version(&wrapped), Some(7));
        for bad in [&[][..], &[1, 0, 0, 0, 7], &[2, 0, 0, 0, 7, 1], &[1, 0, 0]] {
            assert_eq!(split_wrapped_key(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn integers_read_from_strings_and_numbers() {
        assert_eq!(
            read_u64(&serde_json::json!("4294967295")),
            Some(4_294_967_295)
        );
        assert_eq!(read_u64(&serde_json::json!(12)), Some(12));
        assert_eq!(read_u64(&serde_json::json!("x")), None);
        assert_eq!(read_u64(&serde_json::json!(null)), None);
    }
}
