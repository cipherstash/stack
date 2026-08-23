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
    Auth(#[from] stack_auth::AuthError),

    #[error(transparent)]
    ConnectionInit(#[from] crate::connection::ConnectionInitError),

    #[error("Unexpected error: {0}")]
    Unexpected(String),
}
