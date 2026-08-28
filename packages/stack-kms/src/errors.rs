use miette::Diagnostic;
use thiserror::Error;
use vitaminc::random::RandomError;
use zerokms_protocol::{ViturRequestError, ViturRequestErrorKind};

/// Key material returned by ZeroKMS failed up-front validation before key
/// derivation — e.g. a truncated or corrupt response whose material is not the
/// exact length the keyset's block permutation covers. The material is
/// network-supplied, so this must surface as an error, never a panic.
#[derive(Diagnostic, Error, Debug)]
#[error("Invalid keyset key material: {0}")]
pub struct InvalidKeyMaterialError(#[from] pub recipher::errors::RecipherError);

#[derive(Diagnostic, Error, Debug)]
pub enum RetrieveKeyError {
    #[error("Failed to send request: {0}")]
    RequestFailed(#[from] ViturRequestError),
    #[error("Received an invalid number of keys from request. Expected {expected} but received {received}")]
    InvalidNumberOfKeys { expected: usize, received: usize },

    /// Represents an error that occurs when a single key retrieval fails.
    /// May be part of a batch retrieval operation.
    #[error("Failed to retrieve key: {0}")]
    FailedRetrieval(String),

    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidKeyMaterial(#[from] InvalidKeyMaterialError),
}

#[derive(Diagnostic, Error, Debug)]
pub enum GenerateKeyError {
    #[error("Request not authorized")]
    Unauthorized,
    #[error("Request forbidden due to insufficient permissions")]
    Forbidden,
    #[error("Failed to generate IV: {0}")]
    GenerateIv(RandomError),
    #[error("Received an invalid number of keys from request. Expected {expected} but received {received}")]
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
    RequestFailed(#[source] ViturRequestError),
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
    Unauthorized(#[source] ViturRequestError),
    #[error("Request forbidden due to insufficient permissions")]
    Forbidden(#[source] ViturRequestError),
    // `load-keyset` uniquely takes a caller-supplied keyset id or name, so a
    // server 404 is an expected, user-actionable outcome — e.g. a typo'd
    // name — not an "unexpected error". Note the server also responds 404
    // when the *client* is unknown or has no default keyset, so a 404 does
    // not prove the named keyset is missing: inspect `source()` for the
    // server's response body before treating this as "create the keyset".
    #[error("Keyset not found (or the client is unknown or has no default keyset)")]
    KeysetNotFound(#[source] ViturRequestError),
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidKeyMaterial(#[from] InvalidKeyMaterialError),
    // Same shape as `GenerateKeyError::RequestFailed`: Display carries only the
    // static kind/message; the dynamic error stays behind `source()`.
    #[error("Unexpected error ({}: {})", .0.kind, .0.message)]
    RequestFailed(#[source] ViturRequestError),
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
    #[error("Failed to initialize the ZeroKMS connection: {0}")]
    ConnectionInit(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The ZeroKMS endpoint named by the token's `services` claim is unusable.
    #[error("Invalid ZeroKMS endpoint in the token's services claim: {0}")]
    InvalidEndpoint(#[from] crate::endpoint::InvalidEndpoint),

    #[error("Unexpected error: {0}")]
    Unexpected(String),
}
