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

#[cfg(test)]
mod codes {
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

    /// One row per variant of an enum, written `pattern => value`. The
    /// patterns are the arms of a match with no wildcard, so a variant with
    /// no row fails to compile, and each value must match its own pattern.
    macro_rules! variants {
        ($($pattern:pat => $value:expr),+ $(,)?) => {{
            let rows = vec![$({
                let value = $value;
                assert!(matches!(value, $pattern), "{value:?} is not {}", stringify!($pattern));
                value
            }),+];
            for row in &rows {
                match row {
                    $($pattern => {})+
                }
            }
            rows
        }};
    }

    fn boxed<E: Diagnostic + 'static>(rows: Vec<E>) -> impl Iterator<Item = Box<dyn Diagnostic>> {
        rows.into_iter()
            .map(|error| Box::new(error) as Box<dyn Diagnostic>)
    }

    /// One of every variant of every error type here.
    fn every_variant() -> Vec<Box<dyn Diagnostic>> {
        let mut errors: Vec<Box<dyn Diagnostic>> = vec![
            Box::new(material()),
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
        errors.extend(boxed(variants![
            RetrieveKeyError::RequestFailed(_) => {
                RetrieveKeyError::RequestFailed(vitur(ViturRequestErrorKind::SendRequest))
            },
            RetrieveKeyError::InvalidNumberOfKeys { .. } => RetrieveKeyError::InvalidNumberOfKeys {
                expected: 2,
                received: 1,
            },
            RetrieveKeyError::FailedRetrieval(_) => {
                RetrieveKeyError::FailedRetrieval("no key".into())
            },
            RetrieveKeyError::InvalidKeyMaterial(_) => {
                RetrieveKeyError::InvalidKeyMaterial(material())
            },
        ]));
        errors.extend(boxed(variants![
            GenerateKeyError::Unauthorized => GenerateKeyError::Unauthorized,
            GenerateKeyError::Forbidden => GenerateKeyError::Forbidden,
            GenerateKeyError::GenerateIv(_) => {
                GenerateKeyError::GenerateIv(RandomError::GenerationFailed)
            },
            GenerateKeyError::InvalidNumberOfKeys { .. } => GenerateKeyError::InvalidNumberOfKeys {
                expected: 2,
                received: 1,
            },
            GenerateKeyError::InvalidKeyMaterial(_) => {
                GenerateKeyError::InvalidKeyMaterial(material())
            },
            GenerateKeyError::RequestFailed(_) => {
                GenerateKeyError::RequestFailed(vitur(ViturRequestErrorKind::Other))
            },
        ]));
        errors.extend(boxed(variants![
            LoadKeysetError::Unauthorized(_) => {
                LoadKeysetError::Unauthorized(vitur(ViturRequestErrorKind::Unauthorized))
            },
            LoadKeysetError::Forbidden(_) => {
                LoadKeysetError::Forbidden(vitur(ViturRequestErrorKind::Forbidden))
            },
            LoadKeysetError::KeysetNotFound(_) => {
                LoadKeysetError::KeysetNotFound(vitur(ViturRequestErrorKind::NotFound))
            },
            LoadKeysetError::InvalidKeyMaterial(_) => {
                LoadKeysetError::InvalidKeyMaterial(material())
            },
            LoadKeysetError::RequestFailed(_) => {
                LoadKeysetError::RequestFailed(vitur(ViturRequestErrorKind::Conflict))
            },
        ]));
        // A variant that wraps another of this crate's errors, or a
        // stack-auth error, forwards that error's code.
        errors.extend(boxed(variants![
            Error::GenerateKey(_) => Error::GenerateKey(GenerateKeyError::Forbidden),
            Error::RetrieveKey(_) => {
                Error::RetrieveKey(RetrieveKeyError::FailedRetrieval("no key".into()))
            },
            Error::LoadKeyset(_) => Error::LoadKeyset(LoadKeysetError::KeysetNotFound(vitur(
                ViturRequestErrorKind::NotFound,
            ))),
            Error::Auth(_) => {
                Error::Auth(stack_auth::AuthError::TokenExpired(stack_auth::TokenExpired))
            },
            Error::ConnectionInit(_) => {
                Error::ConnectionInit(Box::new(std::io::Error::other("no")))
            },
            Error::InvalidEndpoint(_) => Error::InvalidEndpoint(InvalidEndpoint::Userinfo),
            Error::Unexpected(_) => Error::Unexpected("unexpected".into()),
        ]));
        errors.extend(boxed(variants![
            InvalidEndpoint::Parse(_) => InvalidEndpoint::Parse(url::ParseError::EmptyHost),
            InvalidEndpoint::NoHost(_) => InvalidEndpoint::NoHost("localhost:8080".into()),
            InvalidEndpoint::Scheme(_) => InvalidEndpoint::Scheme("ftp".into()),
            InvalidEndpoint::QueryOrFragment(_) => {
                InvalidEndpoint::QueryOrFragment("https://x/?q".into())
            },
            InvalidEndpoint::Userinfo => InvalidEndpoint::Userinfo,
        ]));
        errors.extend(boxed(variants![
            KeyProviderError::NotConfigured(_) => KeyProviderError::NotConfigured("unset".into()),
            KeyProviderError::InvalidKey(_) => KeyProviderError::InvalidKey("not hex".into()),
            KeyProviderError::LoadError(_) => KeyProviderError::LoadError("disk".into()),
        ]));
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
            errors.extend(boxed(variants![
                StackKmsBuilderError::InvalidEndpoint { .. } => {
                    StackKmsBuilderError::InvalidEndpoint {
                        env_var: "CS_ZEROKMS_HOST",
                        source: InvalidEndpoint::Userinfo,
                    }
                },
                StackKmsBuilderError::ClientInit(_) => {
                    StackKmsBuilderError::ClientInit(Error::Unexpected("x".into()))
                },
                StackKmsBuilderError::Auth(_) => StackKmsBuilderError::Auth(
                    stack_auth::AuthError::TokenExpired(stack_auth::TokenExpired)
                ),
                StackKmsBuilderError::InvalidConfig(_) => StackKmsBuilderError::InvalidConfig(
                    crate::ClientOpts::new(())
                        .with_max_keys_per_req(0)
                        .err()
                        .expect("zero keys per request is refused"),
                ),
                StackKmsBuilderError::KeyProvider(_) => StackKmsBuilderError::KeyProvider(
                    KeyProviderError::NotConfigured("unset".into()),
                ),
            ]));
        }
        errors
    }

    /// Every variant has a code in this crate's namespace and `snake_case`,
    /// save one that carries a stack-auth error, whose code is that error's.
    #[test]
    fn every_variant_has_a_code_of_this_crate() {
        for error in every_variant() {
            let code = error
                .code()
                .unwrap_or_else(|| panic!("{error:?} has no code"))
                .to_string();
            assert!(
                is_code_of("stack_kms", &code) || is_code_of("stack_auth", &code),
                "{code}"
            );
        }
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
