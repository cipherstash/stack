//! The AWS KMS client and its [`KeyVendorBackend`] implementation.

use std::collections::BTreeMap;
use std::time::Duration;

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use stack_kms::{BackendErrorKind, Error, KeyVendor};
use stack_kms_vendor::derive::describe_aad;
use stack_kms_vendor::{
    classify_status, KeyBytes, KeyVendorBackend, VendorRequest, VendorResponse, VendorTransport,
};
use vitaminc::protected::Protected;
use zeroize::Zeroizing;

use crate::config::AwsKmsConfig;
use crate::credentials::{CredentialsError, CredentialsProvider};
use crate::sigv4::{sign, SigningParams};
use crate::time::{system_clock, Clock};

/// This client's vendor: what [`KeyVendorBackend::vendor`] answers and what its errors name.
const VENDOR: KeyVendor = KeyVendor::Aws;
/// The AWS KMS JSON protocol content type.
const CONTENT_TYPE: &str = "application/x-amz-json-1.1";
/// The SigV4 signing name of AWS KMS.
const SERVICE: &str = "kms";

/// The encryption context key that binds the whole associated data.
pub const CONTEXT_AAD: &str = "cipherstash:aad";
/// The encryption context key of the keyset id.
pub const CONTEXT_KEYSET_ID: &str = "cipherstash:keyset-id";
/// The encryption context key of what the key is. It is `root-key`, the
/// key in a keyset record.
pub const CONTEXT_PURPOSE: &str = "cipherstash:purpose";

/// A failure of an AWS KMS call. It is the `source` of the
/// [`Error::Backend`] the client returns; the kind is on the
/// `Error::Backend`.
#[derive(Debug, thiserror::Error)]
pub enum AwsKmsError {
    /// AWS KMS answered with an error.
    #[error("AWS KMS {operation} failed with HTTP {status}: {code}: {message}")]
    Service {
        /// The operation (`Decrypt`).
        operation: &'static str,
        /// The HTTP status.
        status: u16,
        /// The AWS error code (`ThrottlingException`), or `unknown`.
        code: String,
        /// The AWS error message.
        message: String,
    },
    /// The request got no response.
    #[error("AWS KMS {operation} got no response: {source}")]
    Transport {
        /// The operation.
        operation: &'static str,
        /// The transport failure.
        source: stack_kms_vendor::TransportError,
    },
    /// The credentials could not be got.
    #[error(transparent)]
    Credentials(#[from] CredentialsError),
    /// The request could not be signed.
    #[error(transparent)]
    Signing(#[from] crate::sigv4::SigningError),
    /// AWS KMS answered with a success that this client cannot read.
    #[error("AWS KMS {operation} returned a response this client cannot read: {reason}")]
    InvalidResponse {
        /// The operation.
        operation: &'static str,
        /// What is wrong with it.
        reason: &'static str,
    },
}

fn backend(kind: BackendErrorKind, error: AwsKmsError) -> Error {
    Error::Backend {
        backend: VENDOR.into(),
        kind,
        source: Box::new(error),
    }
}

/// The failure kind of an AWS KMS error code. `None` for a code with no
/// fixed kind: the HTTP status decides.
pub fn error_kind(code: &str) -> Option<BackendErrorKind> {
    Some(match code {
        "ThrottlingException" => BackendErrorKind::Throttled,
        "AccessDeniedException"
        | "UnrecognizedClientException"
        | "InvalidSignatureException"
        | "IncompleteSignature"
        | "ExpiredTokenException"
        | "MissingAuthenticationToken"
        | "InvalidClientTokenId" => BackendErrorKind::AccessDenied,
        "NotFoundException" => BackendErrorKind::NotFound,
        "InvalidCiphertextException" | "IncorrectKeyException" | "InvalidKeyUsageException" => {
            BackendErrorKind::InvalidCiphertext
        }
        "KMSInternalException"
        | "DependencyTimeoutException"
        | "KeyUnavailableException"
        | "DisabledException"
        | "KMSInvalidStateException"
        | "ServiceUnavailable"
        | "InternalFailure" => BackendErrorKind::Unavailable,
        _ => return None,
    })
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(rename = "__type")]
    kind: Option<String>,
    #[serde(alias = "Message")]
    message: Option<String>,
}

/// The error of a failed AWS KMS response.
fn service_error(operation: &'static str, response: &VendorResponse) -> Error {
    let body: Option<ErrorBody> = serde_json::from_slice(&response.body).ok();
    // `__type` may carry a namespace (`com.amazonaws.kms#NotFoundException`);
    // the `x-amzn-ErrorType` header may carry a suffix after a colon.
    let code = body
        .as_ref()
        .and_then(|body| body.kind.as_deref())
        .or_else(|| response.header_value("x-amzn-errortype"))
        .map(|code| {
            let code = code.rsplit('#').next().unwrap_or(code);
            code.split(':').next().unwrap_or(code).to_owned()
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let message = body.and_then(|body| body.message).unwrap_or_default();
    // A 4xx with an unknown code is a request AWS KMS refused
    // (`classify_status`), not a damaged ciphertext.
    let kind = error_kind(&code)
        .or_else(|| classify_status(response.status))
        .unwrap_or(BackendErrorKind::Unavailable);
    backend(
        kind,
        AwsKmsError::Service {
            operation,
            status: response.status,
            code,
            message,
        },
    )
}

/// The encryption context that binds `aad`.
///
/// The context always holds the whole associated data. When `aad` is the
/// associated data of a keyset record key, the context also holds the
/// purpose and the keyset id in a readable form. CloudTrail shows these
/// fields, and a key policy can use them in `kms:EncryptionContext:`
/// conditions.
pub fn encryption_context(aad: &[u8]) -> BTreeMap<&'static str, String> {
    let mut context = BTreeMap::new();
    let _ = context.insert(CONTEXT_AAD, Base64UrlUnpadded::encode_string(aad));
    if let Some(description) = describe_aad(aad) {
        let _ = context.insert(CONTEXT_PURPOSE, description.purpose.to_owned());
        let _ = context.insert(CONTEXT_KEYSET_ID, description.keyset_id.to_string());
    }
    context
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct EncryptRequest<'a> {
    key_id: &'a str,
    plaintext: &'a str,
    encryption_context: &'a BTreeMap<&'static str, String>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DecryptRequest<'a> {
    key_id: &'a str,
    ciphertext_blob: &'a str,
    encryption_context: &'a BTreeMap<&'static str, String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct KeyResponse {
    ciphertext_blob: Option<String>,
    plaintext: Option<String>,
}

/// An AWS KMS client, and the AWS KMS key vendor backend
/// ([`KeyVendor::Aws`]).
///
/// It speaks the AWS KMS JSON API (`TrentService.Encrypt` and `Decrypt`).
/// It signs each request with SigV4 in-crate. It sends each request through
/// a [`VendorTransport`], so the same code runs on native Rust and in the
/// WASI guest.
///
/// * `key_ref` (from the keyset record) is the AWS KMS key: a key ARN, a
///   key id, or an alias ARN. AWS KMS keys rotate behind one ARN, so the
///   ARN is the versioned reference. Prefer the key ARN, because an alias
///   can be repointed.
/// * The associated data is bound as the encryption context
///   ([`encryption_context`]). AWS KMS refuses a `Decrypt` whose context is
///   not the one the key was encrypted under.
/// * The derived data key mode only. One `Encrypt` call creates or rewraps
///   a keyset record. One `Decrypt` call unwraps the root key of a keyset,
///   once for each root key TTL. No call is made for each value.
/// * Errors map to [`BackendErrorKind`] by the AWS error code
///   ([`error_kind`]), then by HTTP status.
pub struct AwsKms<T, C> {
    config: AwsKmsConfig,
    transport: T,
    credentials: C,
    clock: Clock,
}

impl<T, C> std::fmt::Debug for AwsKms<T, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKms")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<T: VendorTransport + Send + Sync, C: CredentialsProvider> AwsKms<T, C> {
    /// A client for `config`, sending through `transport`, signing with the
    /// credentials of `credentials`.
    pub fn new(config: AwsKmsConfig, transport: T, credentials: C) -> Self {
        Self {
            config,
            transport,
            credentials,
            clock: system_clock(),
        }
    }

    /// Read the signing time from `clock`. For tests with recorded
    /// requests.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// The configuration.
    pub fn config(&self) -> &AwsKmsConfig {
        &self.config
    }

    /// Sign and send one AWS KMS JSON request.
    ///
    /// `operation` is the `TrentService` operation (`Decrypt`). The body
    /// is wiped after it is sent. Any AWS KMS operation can be sent this
    /// way (for example `CreateKey` in a test). [`KeyVendorBackend`] uses
    /// `Encrypt` and `Decrypt` only.
    pub async fn send_json<R: DeserializeOwned>(
        &self,
        operation: &'static str,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<R, Error> {
        let credentials = self.credentials.credentials().await.map_err(|error| {
            let kind = error.kind();
            backend(kind, AwsKmsError::Credentials(error))
        })?;
        let mut request = VendorRequest {
            method: "POST".to_owned(),
            url: self.config.endpoint().to_owned(),
            headers: vec![
                ("content-type".to_owned(), CONTENT_TYPE.to_owned()),
                (
                    "x-amz-target".to_owned(),
                    format!("TrentService.{operation}"),
                ),
            ],
            body,
        };
        sign(
            &mut request,
            &SigningParams {
                credentials: &credentials,
                region: self.config.region(),
                service: SERVICE,
                time: (self.clock)(),
            },
        )
        .map_err(|error| backend(BackendErrorKind::Unavailable, error.into()))?;
        let response = self.transport.send(request).await.map_err(|source| {
            backend(
                BackendErrorKind::Unavailable,
                AwsKmsError::Transport { operation, source },
            )
        })?;
        if classify_status(response.status).is_some() {
            return Err(service_error(operation, &response));
        }
        serde_json::from_slice(&response.body).map_err(|_| invalid(operation, "invalid JSON"))
    }

    async fn call<Q: Serialize>(
        &self,
        operation: &'static str,
        request: &Q,
    ) -> Result<KeyResponse, Error> {
        let body = Zeroizing::new(
            serde_json::to_vec(request)
                .map_err(|_| invalid(operation, "unserializable request"))?,
        );
        self.send_json(operation, body).await
    }
}

fn invalid(operation: &'static str, reason: &'static str) -> Error {
    backend(
        BackendErrorKind::Unavailable,
        AwsKmsError::InvalidResponse { operation, reason },
    )
}

/// The ciphertext blob of a response, decoded.
fn ciphertext(operation: &'static str, response: &KeyResponse) -> Result<Vec<u8>, Error> {
    let blob = response
        .ciphertext_blob
        .as_deref()
        .ok_or_else(|| invalid(operation, "no CiphertextBlob"))?;
    Base64::decode_vec(blob).map_err(|_| invalid(operation, "CiphertextBlob is not base64"))
}

/// The 256-bit plaintext key of a response, decoded. Every copy is wiped.
fn plaintext_key(operation: &'static str, response: KeyResponse) -> Result<KeyBytes, Error> {
    let encoded = Zeroizing::new(
        response
            .plaintext
            .ok_or_else(|| invalid(operation, "no Plaintext"))?,
    );
    let decoded = Zeroizing::new(
        Base64::decode_vec(&encoded).map_err(|_| invalid(operation, "Plaintext is not base64"))?,
    );
    let mut key = Zeroizing::new([0u8; 32]);
    if decoded.len() != key.len() {
        // A key of another size is not a key this crate wrapped.
        return Err(backend(
            BackendErrorKind::InvalidCiphertext,
            AwsKmsError::InvalidResponse {
                operation,
                reason: "the plaintext is not a 256-bit key",
            },
        ));
    }
    key.copy_from_slice(&decoded);
    Ok(Protected::new(*key))
}

impl<T: VendorTransport + Send + Sync, C: CredentialsProvider> KeyVendorBackend for AwsKms<T, C> {
    fn vendor(&self) -> KeyVendor {
        VENDOR
    }

    async fn wrap(&self, key_ref: &str, key: &KeyBytes, aad: &[u8]) -> Result<Vec<u8>, Error> {
        use vitaminc::protected::Controlled;
        let context = encryption_context(aad);
        let plaintext = Zeroizing::new(Base64::encode_string(key.risky_ref()));
        let response = self
            .call(
                "Encrypt",
                &EncryptRequest {
                    key_id: key_ref,
                    plaintext: &plaintext,
                    encryption_context: &context,
                },
            )
            .await?;
        ciphertext("Encrypt", &response)
    }

    async fn unwrap(&self, key_ref: &str, wrapped: &[u8], aad: &[u8]) -> Result<KeyBytes, Error> {
        let context = encryption_context(aad);
        let blob = Base64::encode_string(wrapped);
        let response = self
            .call(
                "Decrypt",
                &DecryptRequest {
                    key_id: key_ref,
                    ciphertext_blob: &blob,
                    encryption_context: &context,
                },
            )
            .await?;
        plaintext_key("Decrypt", response)
    }

    async fn sleep(&self, duration: Duration) {
        self.transport.sleep(duration).await;
    }
}

#[cfg(test)]
mod tests {
    use stack_kms::KeyMode;
    use stack_kms_vendor::derive::record_key_aad;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn the_context_binds_the_aad_and_names_its_fields() {
        let id = Uuid::from_u128(1);
        let aad = record_key_aad(id, KeyVendor::Aws, KeyMode::Derived);
        let context = encryption_context(&aad);
        assert_eq!(
            context.get(CONTEXT_AAD).unwrap(),
            &Base64UrlUnpadded::encode_string(&aad)
        );
        assert_eq!(context.get(CONTEXT_PURPOSE).unwrap(), "root-key");
        assert_eq!(context.get(CONTEXT_KEYSET_ID).unwrap(), &id.to_string());
        assert_eq!(context.len(), 3);

        let context = encryption_context(b"other");
        assert_eq!(context.len(), 1);
    }

    #[test]
    fn error_codes_map_to_kinds() {
        for (code, kind) in [
            ("ThrottlingException", BackendErrorKind::Throttled),
            ("AccessDeniedException", BackendErrorKind::AccessDenied),
            ("NotFoundException", BackendErrorKind::NotFound),
            (
                "InvalidCiphertextException",
                BackendErrorKind::InvalidCiphertext,
            ),
            ("IncorrectKeyException", BackendErrorKind::InvalidCiphertext),
            ("KMSInternalException", BackendErrorKind::Unavailable),
            ("DependencyTimeoutException", BackendErrorKind::Unavailable),
            ("DisabledException", BackendErrorKind::Unavailable),
        ] {
            assert_eq!(error_kind(code), Some(kind), "{code}");
        }
        assert_eq!(error_kind("ValidationException"), None);
    }

    fn kind_of(response: VendorResponse) -> BackendErrorKind {
        match service_error("Decrypt", &response) {
            Error::Backend { kind, .. } => kind,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_code_comes_from_the_body_or_the_header() {
        let namespaced = VendorResponse::new(
            400,
            br#"{"__type":"com.amazonaws.kms#NotFoundException","message":"m"}"#.to_vec(),
        );
        assert_eq!(kind_of(namespaced), BackendErrorKind::NotFound);
        let header = VendorResponse::new(400, vec![]).header(
            "x-amzn-ErrorType",
            "ThrottlingException:http://internal.amazon.com/coral/",
        );
        assert_eq!(kind_of(header), BackendErrorKind::Throttled);
        // No code: the status decides, and an unknown 4xx is a refused
        // request.
        assert_eq!(
            kind_of(VendorResponse::new(503, b"busy".to_vec())),
            BackendErrorKind::Unavailable
        );
        assert_eq!(
            kind_of(VendorResponse::new(
                400,
                br#"{"__type":"ValidationException"}"#.to_vec()
            )),
            BackendErrorKind::AccessDenied
        );
        assert_eq!(
            kind_of(VendorResponse::new(403, vec![])),
            BackendErrorKind::AccessDenied
        );
    }

    #[test]
    fn the_error_message_names_the_operation_and_code_only() {
        let error = service_error(
            "Decrypt",
            &VendorResponse::new(
                400,
                br#"{"__type":"InvalidCiphertextException","Message":"bad"}"#.to_vec(),
            ),
        );
        let Error::Backend { source, .. } = error else {
            panic!()
        };
        assert_eq!(
            source.to_string(),
            "AWS KMS Decrypt failed with HTTP 400: InvalidCiphertextException: bad"
        );
    }
}
