//! The credentials a `Cipher` is built with, found as every SDK finds them.
//!
//! `stack_auth::AutoStrategy` reads `CS_CLIENT_ACCESS_KEY` and
//! `CS_WORKSPACE_CRN`, then the profile store (`~/.cipherstash`, or
//! `CS_CONFIG_PATH`). With a profile and no access key, it reads and parses
//! the profile's token file. It makes no request. The Python tests cover it:
//! a Rust test would set environment variables that other tests in the same
//! process read.

use stack_auth::{AuthError, AutoStrategy, HttpRequest, HttpResponse, HttpTransport, RequestError};

use crate::refusal::Refusal;

/// Check that the credentials are there.
///
/// The strategy `AutoStrategy` finds is built over [`NoRequest`], so no HTTP
/// client, TLS configuration or root store is built, and nothing is kept.
/// stack-auth's `http` feature is off (`Cargo.toml`), so none is compiled
/// either. The ticket that makes the first request turns it on and keeps a
/// strategy with a real transport. The work here is the environment, the
/// service URL for the CRN's region, and one small file where there is a
/// profile.
///
/// # Errors
///
/// The engine's refusal, such as `stack_auth_not_authenticated` when there
/// are no credentials. The message names the variable or file to fix, for
/// a Python user.
pub fn detect() -> Result<(), Refusal> {
    AutoStrategy::builder()
        .transport(NoRequest)
        .detect()
        .map(drop)
        .map_err(|error| {
            let refused = Refusal::of(&error);
            Refusal {
                message: message(&error).unwrap_or(refused.message.clone()),
                ..refused
            }
        })
}

/// The message for a Python user, where the engine's names a Rust API or
/// no variable at all. `None` keeps the engine's message and help.
fn message(error: &AuthError) -> Option<String> {
    let text = match error {
        AuthError::NotAuthenticated(_) => "no credentials were found. Set CS_CLIENT_ACCESS_KEY \
             and CS_WORKSPACE_CRN, or log in with `stash auth login`."
            .to_owned(),
        AuthError::MissingWorkspaceCrn(_) => {
            "CS_CLIENT_ACCESS_KEY is set and CS_WORKSPACE_CRN is not. Set both.".to_owned()
        }
        AuthError::InvalidAccessKey(_) => {
            format!("{error}. An access key has the form CSAK<key-id>.<secret>.")
        }
        AuthError::InvalidCrn(_) => format!(
            "{error}. CS_WORKSPACE_CRN has the form crn:<region>:<workspace-id>, \
             such as crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY."
        ),
        AuthError::Region(_) => {
            format!("{error}. The region is the middle part of CS_WORKSPACE_CRN.")
        }
        AuthError::InvalidUrl(_) => format!("{error}. CS_CTS_HOST, when set, must be a URL."),
        AuthError::Store(_) => format!(
            "{error}. The profile is in ~/.cipherstash, or in CS_CONFIG_PATH when set. \
             Log in again with `stash auth login`, or set CS_CLIENT_ACCESS_KEY."
        ),
        _ => return None,
    };
    Some(text)
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
