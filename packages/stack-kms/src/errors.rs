use miette::Diagnostic;
use thiserror::Error;
use vitaminc::random::RandomError;
use zerokms_protocol::{ViturRequestError, ViturRequestErrorKind};

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

#[cfg(test)]
mod generate_key_error_from_vitur_request_error {
    use super::*;

    const SOURCE_DETAIL: &str = "transport-detail-7f3a";

    fn err(kind: ViturRequestErrorKind) -> ViturRequestError {
        ViturRequestError::new(kind, "boom", std::io::Error::other(SOURCE_DETAIL))
    }

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
        for kind in [
            ViturRequestErrorKind::PrepareRequest,
            ViturRequestErrorKind::SendRequest,
            ViturRequestErrorKind::NotFound,
            ViturRequestErrorKind::Conflict,
            ViturRequestErrorKind::FailureResponse,
            ViturRequestErrorKind::ParseResponse,
            ViturRequestErrorKind::Other,
        ] {
            // `ViturRequestErrorKind` has no `PartialEq`; compare by Debug name.
            let name = format!("{kind:?}");
            let mapped = GenerateKeyError::from(err(kind));
            assert!(
                matches!(&mapped, GenerateKeyError::RequestFailed(e) if format!("{:?}", e.kind) == name),
                "{name} must map to RequestFailed carrying the same kind, got: {mapped:?}"
            );
        }
    }

    #[test]
    fn request_failed_display_names_the_kind_and_message_but_not_the_source() {
        let mapped = GenerateKeyError::from(err(ViturRequestErrorKind::SendRequest));
        let shown = mapped.to_string();
        assert!(shown.contains("SendRequest"), "{shown}");
        assert!(shown.contains("boom"), "{shown}");
        assert!(
            !shown.contains(SOURCE_DETAIL),
            "the dynamic source error must stay out of Display: {shown}"
        );
        assert!(
            std::error::Error::source(&mapped).is_some(),
            "the source must still be reachable through the error chain"
        );
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
    // `load-keyset` uniquely takes a caller-supplied keyset id or name, so an
    // unknown keyset (server 404) is an expected, user-actionable outcome —
    // e.g. a typo'd name or a load-or-create flow — not an "unexpected error".
    #[error("Keyset not found")]
    KeysetNotFound(#[source] ViturRequestError),
    #[error("Invalid keyset key material: expected {expected} bytes but received {received}")]
    InvalidKeyMaterial { expected: usize, received: usize },
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

#[cfg(test)]
mod load_keyset_error_from_vitur_request_error {
    use super::*;

    const SOURCE_DETAIL: &str = "transport-detail-7f3a";

    fn err(kind: ViturRequestErrorKind) -> ViturRequestError {
        ViturRequestError::new(kind, "boom", std::io::Error::other(SOURCE_DETAIL))
    }

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
        for kind in [
            ViturRequestErrorKind::PrepareRequest,
            ViturRequestErrorKind::SendRequest,
            ViturRequestErrorKind::Conflict,
            ViturRequestErrorKind::FailureResponse,
            ViturRequestErrorKind::ParseResponse,
            ViturRequestErrorKind::Other,
        ] {
            // `ViturRequestErrorKind` has no `PartialEq`; compare by Debug name.
            let name = format!("{kind:?}");
            let mapped = LoadKeysetError::from(err(kind));
            assert!(
                matches!(&mapped, LoadKeysetError::RequestFailed(e) if format!("{:?}", e.kind) == name),
                "{name} must map to RequestFailed carrying the same kind, got: {mapped:?}"
            );
        }
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
        let mapped = LoadKeysetError::from(err(ViturRequestErrorKind::SendRequest));
        let shown = mapped.to_string();
        assert!(shown.contains("SendRequest"), "{shown}");
        assert!(shown.contains("boom"), "{shown}");
        assert!(
            std::error::Error::source(&mapped).is_some(),
            "the source must still be reachable through the error chain"
        );
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

    #[error(transparent)]
    ConnectionInit(#[from] crate::connection::ConnectionInitError),

    /// The ZeroKMS endpoint named by the token's `services` claim is unusable.
    #[error("Invalid ZeroKMS endpoint in the token's services claim: {0}")]
    InvalidEndpoint(#[from] crate::endpoint::InvalidEndpoint),

    #[error("Unexpected error: {0}")]
    Unexpected(String),
}
