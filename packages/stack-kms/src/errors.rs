use miette::Diagnostic;
use stack_auth::diagnostic::{payload, ErrorPayload};
use thiserror::Error;
use vitaminc::random::RandomError;
use zerokms_protocol::{ViturRequestError, ViturRequestErrorKind};

/// The fields a failed ZeroKMS request contributes: the request kind
/// (`NotFound`, `SendRequest`, ...), and nothing from the response body.
fn request_payload(error: &ViturRequestError) -> serde_json::Map<String, serde_json::Value> {
    payload([("request_kind", format!("{:?}", error.kind).into())])
}

/// The fields of a key-count mismatch.
fn count_payload(expected: usize, received: usize) -> serde_json::Map<String, serde_json::Value> {
    payload([("expected", expected.into()), ("received", received.into())])
}

/// Key material returned by ZeroKMS failed up-front validation before key
/// derivation — e.g. a truncated or corrupt response whose material is not the
/// exact length the keyset's block permutation covers. The material is
/// network-supplied, so this must surface as an error, never a panic.
#[derive(Diagnostic, Error, Debug)]
#[error("Invalid keyset key material: {0}")]
#[diagnostic(code(stack_kms::invalid_key_material))]
pub struct InvalidKeyMaterialError(#[from] pub recipher::errors::RecipherError);

impl ErrorPayload for InvalidKeyMaterialError {}

#[derive(Diagnostic, Error, Debug)]
pub enum RetrieveKeyError {
    // `ViturRequestError`'s Display is its kind and a static message; the
    // response it carries stays behind `source()`.
    #[error("Failed to send request: {0}")]
    #[diagnostic(code(stack_kms::retrieve_key_failed))]
    RequestFailed(#[from] ViturRequestError),
    #[error("Received an invalid number of keys from request. Expected {expected} but received {received}")]
    #[diagnostic(code(stack_kms::retrieved_key_count))]
    InvalidNumberOfKeys { expected: usize, received: usize },

    /// Represents an error that occurs when a single key retrieval fails.
    /// May be part of a batch retrieval operation.
    ///
    /// The string is ZeroKMS's own reason for the one key, kept for a caller
    /// in this process to inspect. It is response text, so the message does
    /// not repeat it (see [`ErrorPayload`] for the rule).
    #[error("Failed to retrieve key")]
    #[diagnostic(
        code(stack_kms::key_not_retrieved),
        help("ZeroKMS returned no data key for this value. Check it is opened under the context it was sealed with.")
    )]
    FailedRetrieval(String),

    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidKeyMaterial(#[from] InvalidKeyMaterialError),
}

#[derive(Diagnostic, Error, Debug)]
pub enum GenerateKeyError {
    #[error("Request not authorized")]
    #[diagnostic(
        code(stack_kms::generate_key_unauthorized),
        help("ZeroKMS refused the access token. Refresh the credential and retry.")
    )]
    Unauthorized,
    #[error("Request forbidden due to insufficient permissions")]
    #[diagnostic(
        code(stack_kms::generate_key_forbidden),
        help("The client is not allowed to generate keys in this keyset: check the keyset's grants, and that it is enabled.")
    )]
    Forbidden,
    // The random source's own message is not repeated; it is the source.
    #[error("Failed to generate IV")]
    #[diagnostic(code(stack_kms::generate_iv))]
    GenerateIv(#[source] RandomError),
    #[error("Received an invalid number of keys from request. Expected {expected} but received {received}")]
    #[diagnostic(code(stack_kms::generated_key_count))]
    InvalidNumberOfKeys { expected: usize, received: usize },

    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidKeyMaterial(#[from] InvalidKeyMaterialError),
    // Catch-all for any `ViturRequestError` not classified as Forbidden /
    // Unauthorized above. Display surfaces the `kind` (operational enum
    // — `SendRequest`, `Other`, `ParseResponse`, ...) and `message`
    // (`&'static str`, build-time only, no dynamic data) so the bare
    // failure mode is visible. The dynamic `error: ShareableError` field
    // is reachable through `Error::source()` via `#[source]`, so callers
    // using anyhow chain formatting (`{:?}` / `{:#}`) or `tracing` get the
    // underlying transport / response error; the Display string itself
    // stays free of dynamic data.
    #[error("Unexpected error ({}: {})", .0.kind, .0.message)]
    #[diagnostic(code(stack_kms::generate_key_failed))]
    RequestFailed(#[source] ViturRequestError),
}

impl ErrorPayload for RetrieveKeyError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            Self::RequestFailed(error) => request_payload(error),
            Self::InvalidNumberOfKeys { expected, received } => count_payload(*expected, *received),
            Self::FailedRetrieval(_) => serde_json::Map::new(),
            Self::InvalidKeyMaterial(error) => error.payload(),
        }
    }
}

impl ErrorPayload for GenerateKeyError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            Self::RequestFailed(error) => request_payload(error),
            Self::InvalidNumberOfKeys { expected, received } => count_payload(*expected, *received),
            Self::InvalidKeyMaterial(error) => error.payload(),
            Self::Unauthorized | Self::Forbidden | Self::GenerateIv(_) => serde_json::Map::new(),
        }
    }
}

impl From<ViturRequestError> for GenerateKeyError {
    fn from(err: ViturRequestError) -> Self {
        match err.kind {
            ViturRequestErrorKind::Forbidden => Self::Forbidden,
            ViturRequestErrorKind::Unauthorized => Self::Unauthorized,
            _ => Self::RequestFailed(err),
        }
    }
}

#[derive(Diagnostic, Error, Debug)]
pub enum LoadKeysetError {
    // `Unauthorized` / `Forbidden` carry the underlying request error (unlike
    // `GenerateKeyError`'s unit variants) because `load-keyset` has 403
    // responses that mean different things: the server rejects a *disabled*
    // keyset with a 403 whose body says "Keyset disabled: ...". Display stays
    // static (no dynamic data); the distinguishing server response is
    // reachable through `source()`.
    #[error("Request not authorized")]
    #[diagnostic(
        code(stack_kms::load_keyset_unauthorized),
        help("ZeroKMS refused the access token. Refresh the credential and retry.")
    )]
    Unauthorized(#[source] ViturRequestError),
    #[error("Request forbidden due to insufficient permissions")]
    #[diagnostic(
        code(stack_kms::load_keyset_forbidden),
        help("The client is not granted this keyset, or the keyset is disabled.")
    )]
    Forbidden(#[source] ViturRequestError),
    // `load-keyset` uniquely takes a caller-supplied keyset id or name, so a
    // server 404 is an expected, user-actionable outcome — e.g. a typo'd
    // name — not an "unexpected error". Note the server also responds 404
    // when the *client* is unknown or has no default keyset, so a 404 does
    // not prove the named keyset is missing: inspect `source()` for the
    // server's response body before treating this as "create the keyset".
    #[error("Keyset not found (or the client is unknown or has no default keyset)")]
    #[diagnostic(
        code(stack_kms::keyset_not_found),
        help("ZeroKMS answers 404 when no keyset has this id or name, and also when the client is unknown or has no default keyset. Check the client ID and the keyset's name before creating a keyset.")
    )]
    KeysetNotFound(#[source] ViturRequestError),
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidKeyMaterial(#[from] InvalidKeyMaterialError),
    // Same shape as `GenerateKeyError::RequestFailed`: Display carries only the
    // static kind/message; the dynamic error stays behind `source()`.
    #[error("Unexpected error ({}: {})", .0.kind, .0.message)]
    #[diagnostic(code(stack_kms::load_keyset_failed))]
    RequestFailed(#[source] ViturRequestError),
}

impl ErrorPayload for LoadKeysetError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            Self::Unauthorized(error)
            | Self::Forbidden(error)
            | Self::KeysetNotFound(error)
            | Self::RequestFailed(error) => request_payload(error),
            Self::InvalidKeyMaterial(error) => error.payload(),
        }
    }
}

impl From<ViturRequestError> for LoadKeysetError {
    fn from(err: ViturRequestError) -> Self {
        match err.kind {
            ViturRequestErrorKind::Forbidden => Self::Forbidden(err),
            ViturRequestErrorKind::Unauthorized => Self::Unauthorized(err),
            ViturRequestErrorKind::NotFound => Self::KeysetNotFound(err),
            _ => Self::RequestFailed(err),
        }
    }
}

/// Every miette code an error from this crate can carry. The variants that
/// carry a `stack_auth` error carry its code instead, so those are in
/// `stack_auth::ERROR_CODES`. A test builds every variant and checks its code
/// is here, so renaming a code means editing this list on purpose.
pub const ERROR_CODES: &[&str] = &[
    "stack_kms::invalid_key_material",
    "stack_kms::retrieve_key_failed",
    "stack_kms::retrieved_key_count",
    "stack_kms::key_not_retrieved",
    "stack_kms::generate_key_unauthorized",
    "stack_kms::generate_key_forbidden",
    "stack_kms::generate_iv",
    "stack_kms::generated_key_count",
    "stack_kms::generate_key_failed",
    "stack_kms::load_keyset_unauthorized",
    "stack_kms::load_keyset_forbidden",
    "stack_kms::keyset_not_found",
    "stack_kms::load_keyset_failed",
    "stack_kms::connection_init",
    "stack_kms::invalid_endpoint",
    "stack_kms::unexpected",
    "stack_kms::endpoint_not_url",
    "stack_kms::endpoint_no_host",
    "stack_kms::endpoint_scheme",
    "stack_kms::endpoint_query_or_fragment",
    "stack_kms::endpoint_userinfo",
    "stack_kms::client_key_not_configured",
    "stack_kms::invalid_client_key",
    "stack_kms::client_key_load",
    "stack_kms::invalid_client_opts",
    "stack_kms::base_url_unresolved",
    "stack_kms::unexpected_content_type",
    "stack_kms::failure_response",
    "stack_kms::http_client_init",
];

#[cfg(test)]
mod codes {
    use std::collections::BTreeSet;

    use stack_auth::diagnostic::is_code_of;

    use super::*;
    use crate::connection::{BaseUrlUnresolved, FailureResponse, UnexpectedContentType};
    use crate::endpoint::InvalidEndpoint;
    use crate::key_provider::KeyProviderError;

    fn vitur(kind: ViturRequestErrorKind) -> ViturRequestError {
        ViturRequestError::new(kind, "boom", std::io::Error::other("detail"))
    }

    fn material() -> InvalidKeyMaterialError {
        recipher::errors::RecipherError::InvalidInputLength {
            expected: 32,
            received: 3,
        }
        .into()
    }

    /// One of every variant of every error type here. A transparent
    /// variant is built once, to show the code it forwards is listed
    /// somewhere.
    fn every_variant() -> Vec<Box<dyn Diagnostic>> {
        let mut errors: Vec<Box<dyn Diagnostic>> = vec![
            Box::new(material()),
            Box::new(RetrieveKeyError::RequestFailed(vitur(
                ViturRequestErrorKind::SendRequest,
            ))),
            Box::new(RetrieveKeyError::InvalidNumberOfKeys {
                expected: 2,
                received: 1,
            }),
            Box::new(RetrieveKeyError::FailedRetrieval("no key".into())),
            Box::new(RetrieveKeyError::InvalidKeyMaterial(material())),
            Box::new(GenerateKeyError::Unauthorized),
            Box::new(GenerateKeyError::Forbidden),
            Box::new(GenerateKeyError::GenerateIv(RandomError::GenerationFailed)),
            Box::new(GenerateKeyError::InvalidNumberOfKeys {
                expected: 2,
                received: 1,
            }),
            Box::new(GenerateKeyError::InvalidKeyMaterial(material())),
            Box::new(GenerateKeyError::RequestFailed(vitur(
                ViturRequestErrorKind::Other,
            ))),
            Box::new(LoadKeysetError::Unauthorized(vitur(
                ViturRequestErrorKind::Unauthorized,
            ))),
            Box::new(LoadKeysetError::Forbidden(vitur(
                ViturRequestErrorKind::Forbidden,
            ))),
            Box::new(LoadKeysetError::KeysetNotFound(vitur(
                ViturRequestErrorKind::NotFound,
            ))),
            Box::new(LoadKeysetError::InvalidKeyMaterial(material())),
            Box::new(LoadKeysetError::RequestFailed(vitur(
                ViturRequestErrorKind::Conflict,
            ))),
            Box::new(Error::GenerateKey(GenerateKeyError::Forbidden)),
            Box::new(Error::RetrieveKey(RetrieveKeyError::FailedRetrieval(
                "no key".into(),
            ))),
            Box::new(Error::LoadKeyset(LoadKeysetError::KeysetNotFound(vitur(
                ViturRequestErrorKind::NotFound,
            )))),
            Box::new(Error::Auth(stack_auth::AuthError::TokenExpired(
                stack_auth::TokenExpired,
            ))),
            Box::new(Error::ConnectionInit(Box::new(std::io::Error::other("no")))),
            Box::new(Error::InvalidEndpoint(InvalidEndpoint::Userinfo)),
            Box::new(Error::Unexpected("unexpected".into())),
            Box::new(InvalidEndpoint::Parse(url::ParseError::EmptyHost)),
            Box::new(InvalidEndpoint::NoHost("localhost:8080".into())),
            Box::new(InvalidEndpoint::Scheme("ftp".into())),
            Box::new(InvalidEndpoint::QueryOrFragment("https://x/?q".into())),
            Box::new(InvalidEndpoint::Userinfo),
            Box::new(KeyProviderError::NotConfigured("unset".into())),
            Box::new(KeyProviderError::InvalidKey("not hex".into())),
            Box::new(KeyProviderError::LoadError("disk".into())),
            Box::new(BaseUrlUnresolved),
            Box::new(UnexpectedContentType {
                received: Some("text/html".into()),
                expected: "application/json",
                body: None,
                headers: Default::default(),
            }),
            Box::new(FailureResponse {
                status: 500,
                body: None,
                headers: Default::default(),
            }),
        ];
        if let Err(error) = crate::ClientOpts::new(()).with_max_keys_per_req(0) {
            errors.push(Box::new(error));
        }
        #[cfg(feature = "http")]
        {
            use crate::builder::StackKmsBuilderError;
            let reqwest_error = reqwest::Client::new()
                .get("not a url")
                .build()
                .expect_err("not a URL");
            errors.push(Box::new(crate::ConnectionInitError::from(reqwest_error)));
            errors.push(Box::new(StackKmsBuilderError::InvalidEndpoint {
                env_var: "CS_ZEROKMS_HOST",
                source: InvalidEndpoint::Userinfo,
            }));
            errors.push(Box::new(StackKmsBuilderError::ClientInit(
                Error::Unexpected("x".into()),
            )));
            errors.push(Box::new(StackKmsBuilderError::KeyProvider(
                KeyProviderError::NotConfigured("unset".into()),
            )));
        }
        errors
    }

    #[test]
    fn every_variant_has_a_listed_code() {
        let mut seen = BTreeSet::new();
        for error in every_variant() {
            let code = error
                .code()
                .unwrap_or_else(|| panic!("{error:?} has no code"))
                .to_string();
            if code.starts_with("stack_auth::") {
                assert!(stack_auth::ERROR_CODES.contains(&code.as_str()), "{code}");
                continue;
            }
            assert!(is_code_of("stack_kms", &code), "{code}");
            assert!(ERROR_CODES.contains(&code.as_str()), "{code} is unlisted");
            seen.insert(code);
        }
        // `http_client_init` needs the `http` feature to be built.
        let listed: BTreeSet<String> = ERROR_CODES
            .iter()
            .filter(|code| cfg!(feature = "http") || **code != "stack_kms::http_client_init")
            .map(|code| code.to_string())
            .collect();
        assert_eq!(seen, listed, "every listed code is produced");
    }

    /// A ZeroKMS failure gives its request kind, never the response it
    /// carried: the detail behind `source()` stays out of the payload too.
    #[test]
    fn a_request_failure_gives_the_kind_and_not_the_response() {
        let error = Error::LoadKeyset(LoadKeysetError::KeysetNotFound(vitur(
            ViturRequestErrorKind::NotFound,
        )));
        let fields = error.payload();
        assert_eq!(fields["request_kind"], "NotFound");
        assert!(!format!("{fields:?}").contains("detail"), "{fields:?}");
        assert!(error
            .help()
            .is_some_and(|help| help.to_string().contains("client is unknown")));
    }

    #[test]
    fn no_endpoint_message_repeats_the_url() {
        for error in [
            InvalidEndpoint::NoHost("marker://user:pass@".into()),
            InvalidEndpoint::QueryOrFragment("https://x/?marker".into()),
        ] {
            assert!(!error.to_string().contains("marker"), "{error}");
        }
    }
}

/// Shared scaffolding for the `From<ViturRequestError>` mapping tests below:
/// one place for the fixture error and the assertions both mappings need, so
/// a new error type doesn't copy another 80 lines.
#[cfg(test)]
mod vitur_error_mapping_support {
    use super::*;

    pub(super) const SOURCE_DETAIL: &str = "transport-detail-7f3a";

    pub(super) fn err(kind: ViturRequestErrorKind) -> ViturRequestError {
        ViturRequestError::new(kind, "boom", std::io::Error::other(SOURCE_DETAIL))
    }

    /// Every kind in `kinds` must map to the catch-all RequestFailed variant
    /// carrying the same kind (checked via `is_request_failed_with_kind`).
    pub(super) fn assert_kinds_map_to_request_failed<E: std::fmt::Debug>(
        kinds: impl IntoIterator<Item = ViturRequestErrorKind>,
        from: impl Fn(ViturRequestError) -> E,
        is_request_failed_with_kind: impl Fn(&E, &str) -> bool,
    ) {
        for kind in kinds {
            // `ViturRequestErrorKind` has no `PartialEq`; compare by Debug name.
            let name = format!("{kind:?}");
            let mapped = from(err(kind));
            assert!(
                is_request_failed_with_kind(&mapped, &name),
                "{name} must map to RequestFailed carrying the same kind, got: {mapped:?}"
            );
        }
    }

    /// The catch-all's Display must name the kind and static message while
    /// keeping the dynamic source out; the source stays reachable through the
    /// error chain.
    pub(super) fn assert_request_failed_display(mapped: &impl std::error::Error) {
        let shown = mapped.to_string();
        assert!(shown.contains("SendRequest"), "{shown}");
        assert!(shown.contains("boom"), "{shown}");
        assert!(
            !shown.contains(SOURCE_DETAIL),
            "the dynamic source error must stay out of Display: {shown}"
        );
        assert!(
            mapped.source().is_some(),
            "the source must still be reachable through the error chain"
        );
    }
}

#[cfg(test)]
mod generate_key_error_from_vitur_request_error {
    use super::vitur_error_mapping_support::*;
    use super::*;

    #[test]
    fn forbidden_maps_to_forbidden() {
        assert!(matches!(
            GenerateKeyError::from(err(ViturRequestErrorKind::Forbidden)),
            GenerateKeyError::Forbidden
        ));
    }

    #[test]
    fn unauthorized_maps_to_unauthorized() {
        assert!(matches!(
            GenerateKeyError::from(err(ViturRequestErrorKind::Unauthorized)),
            GenerateKeyError::Unauthorized
        ));
    }

    #[test]
    fn every_other_kind_maps_to_request_failed_keeping_the_kind() {
        assert_kinds_map_to_request_failed(
            [
                ViturRequestErrorKind::PrepareRequest,
                ViturRequestErrorKind::SendRequest,
                ViturRequestErrorKind::NotFound,
                ViturRequestErrorKind::Conflict,
                ViturRequestErrorKind::FailureResponse,
                ViturRequestErrorKind::ParseResponse,
                ViturRequestErrorKind::Other,
            ],
            GenerateKeyError::from,
            |mapped, name| matches!(mapped, GenerateKeyError::RequestFailed(e) if format!("{:?}", e.kind) == name),
        );
    }

    #[test]
    fn request_failed_display_names_the_kind_and_message_but_not_the_source() {
        assert_request_failed_display(&GenerateKeyError::from(err(
            ViturRequestErrorKind::SendRequest,
        )));
    }
}

#[cfg(test)]
mod load_keyset_error_from_vitur_request_error {
    use super::vitur_error_mapping_support::*;
    use super::*;

    #[test]
    fn forbidden_maps_to_forbidden_keeping_the_source() {
        let mapped = LoadKeysetError::from(err(ViturRequestErrorKind::Forbidden));
        assert!(matches!(mapped, LoadKeysetError::Forbidden(_)));
        assert!(
            std::error::Error::source(&mapped).is_some(),
            "the server response (e.g. 'Keyset disabled') must stay reachable"
        );
    }

    #[test]
    fn unauthorized_maps_to_unauthorized_keeping_the_source() {
        let mapped = LoadKeysetError::from(err(ViturRequestErrorKind::Unauthorized));
        assert!(matches!(mapped, LoadKeysetError::Unauthorized(_)));
        assert!(std::error::Error::source(&mapped).is_some());
    }

    #[test]
    fn not_found_maps_to_keyset_not_found() {
        let mapped = LoadKeysetError::from(err(ViturRequestErrorKind::NotFound));
        assert!(matches!(mapped, LoadKeysetError::KeysetNotFound(_)));
        assert!(std::error::Error::source(&mapped).is_some());
    }

    #[test]
    fn every_other_kind_maps_to_request_failed_keeping_the_kind() {
        assert_kinds_map_to_request_failed(
            [
                ViturRequestErrorKind::PrepareRequest,
                ViturRequestErrorKind::SendRequest,
                ViturRequestErrorKind::Conflict,
                ViturRequestErrorKind::FailureResponse,
                ViturRequestErrorKind::ParseResponse,
                ViturRequestErrorKind::Other,
            ],
            LoadKeysetError::from,
            |mapped, name| matches!(mapped, LoadKeysetError::RequestFailed(e) if format!("{:?}", e.kind) == name),
        );
    }

    #[test]
    fn display_never_leaks_the_dynamic_source() {
        for kind in [
            ViturRequestErrorKind::Forbidden,
            ViturRequestErrorKind::Unauthorized,
            ViturRequestErrorKind::NotFound,
            ViturRequestErrorKind::SendRequest,
        ] {
            let mapped = LoadKeysetError::from(err(kind));
            let shown = mapped.to_string();
            assert!(
                !shown.contains(SOURCE_DETAIL),
                "the dynamic source error must stay out of Display: {shown}"
            );
        }
    }

    #[test]
    fn request_failed_display_names_the_kind_and_message() {
        assert_request_failed_display(&LoadKeysetError::from(err(
            ViturRequestErrorKind::SendRequest,
        )));
    }
}

/// Top-level error for high-level [`StackKms`](crate::StackKms) key operations.
#[derive(Error, Debug, Diagnostic)]
pub enum Error {
    #[error(transparent)]
    #[diagnostic(transparent)]
    GenerateKey(#[from] GenerateKeyError),

    #[error(transparent)]
    #[diagnostic(transparent)]
    RetrieveKey(#[from] RetrieveKeyError),

    #[error(transparent)]
    #[diagnostic(transparent)]
    LoadKeyset(#[from] LoadKeysetError),

    #[error(transparent)]
    #[diagnostic(transparent)]
    Auth(#[from] stack_auth::AuthError),

    /// The [`ZeroKMSConnection`](crate::ZeroKMSConnection) failed to
    /// initialise. Boxed because the error type belongs to whichever
    /// connection the client was built over.
    #[error("Failed to initialize the ZeroKMS connection")]
    #[diagnostic(code(stack_kms::connection_init))]
    ConnectionInit(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The ZeroKMS endpoint named by the token's `services` claim is unusable.
    #[error("Invalid ZeroKMS endpoint in the token's services claim: {0}")]
    #[diagnostic(
        code(stack_kms::invalid_endpoint),
        help("Configure the ZeroKMS endpoint explicitly (`CS_ZEROKMS_HOST`), or use a token whose services claim names a usable one.")
    )]
    InvalidEndpoint(
        #[from]
        #[diagnostic_source]
        crate::endpoint::InvalidEndpoint,
    ),

    #[error("Unexpected error: {0}")]
    #[diagnostic(code(stack_kms::unexpected))]
    Unexpected(String),
}

impl ErrorPayload for Error {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            Self::GenerateKey(error) => error.payload(),
            Self::RetrieveKey(error) => error.payload(),
            Self::LoadKeyset(error) => error.payload(),
            Self::Auth(error) => error.payload(),
            Self::ConnectionInit(_) | Self::InvalidEndpoint(_) | Self::Unexpected(_) => {
                serde_json::Map::new()
            }
        }
    }
}
