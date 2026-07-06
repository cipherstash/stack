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
