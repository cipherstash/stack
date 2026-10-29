//! The credentials a `Cipher` is built with, found as every SDK finds them.
//!
//! `stack_auth::AutoStrategy` reads `CS_CLIENT_ACCESS_KEY` and
//! `CS_WORKSPACE_CRN`, then the profile store (`~/.cipherstash`, or
//! `CS_CONFIG_PATH`). It makes no request. The Python tests cover it: a
//! Rust test would set environment variables that other tests in the same
//! process read.

use stack_auth::{AutoStrategy, HttpRequest, HttpResponse, HttpTransport, RequestError};

use crate::refusal::Refusal;

/// Check that the credentials are there.
///
/// The strategy `AutoStrategy` finds is built over [`NoRequest`], so no HTTP
/// client is built, and nothing is kept. stack-auth's `http` feature is off
/// (`Cargo.toml`), so none is compiled either. The ticket that makes the
/// first request turns it on and keeps a strategy with a real transport.
///
/// # Errors
///
/// The engine's refusal, such as `stack_auth_not_authenticated` when there
/// are no credentials.
pub fn detect() -> Result<(), Refusal> {
    AutoStrategy::builder()
        .transport(NoRequest)
        .detect()
        .map(drop)
        .map_err(|error| Refusal::of(&error))
}

/// A transport that sends nothing. A strategy cannot be built without one.
struct NoRequest;

impl HttpTransport for NoRequest {
    async fn send(&self, _request: HttpRequest) -> Result<HttpResponse, RequestError> {
        Err(RequestError(Box::new(Refused)))
    }
}

#[derive(Debug)]
struct Refused;

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("this strategy only checks that the credentials exist; it sends no request")
    }
}

impl std::error::Error for Refused {}
