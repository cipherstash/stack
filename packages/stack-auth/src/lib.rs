#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
#![doc = include_str!("../README.md")]
// Security lints
#![deny(unsafe_code)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::panic)]
// Prevent mem::forget from bypassing ZeroizeOnDrop
#![warn(clippy::mem_forget)]
// Prevent accidental data leaks via output
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]
#![warn(clippy::dbg_macro)]
// Code quality
#![warn(unreachable_pub)]
#![warn(unused_results)]
#![warn(clippy::todo)]
#![warn(clippy::unimplemented)]
// Relax in tests
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::panic))]
#![cfg_attr(test, allow(unused_results))]

use std::convert::Infallible;
use std::future::Future;
#[cfg(not(any(test, feature = "test-utils")))]
use std::time::Duration;

use vitaminc::protected::OpaqueDebug;
use zeroize::ZeroizeOnDrop;

mod access_key;
mod access_key_refresher;
mod access_key_strategy;
mod auto_refresh;
mod auto_strategy;
mod device_client;
mod device_code;
mod oauth_refresher;
mod oauth_strategy;
mod refresher;
mod service_token;
mod token;

#[cfg(any(test, feature = "test-utils"))]
mod static_token_strategy;

pub use access_key::{AccessKey, InvalidAccessKey};
pub use access_key_strategy::{AccessKeyStrategy, AccessKeyStrategyBuilder};
pub use auto_strategy::{AutoStrategy, AutoStrategyBuilder};
pub use device_code::{DeviceCodeStrategy, DeviceCodeStrategyBuilder, PendingDeviceCode};
pub use oauth_strategy::{OAuthStrategy, OAuthStrategyBuilder};
pub use service_token::ServiceToken;
#[cfg(any(test, feature = "test-utils"))]
pub use static_token_strategy::StaticTokenStrategy;
pub use token::Token;

pub use device_client::{bind_client_device, DeviceClientError};

// Re-exports from stack-profile for backward compatibility.
pub use stack_profile::DeviceIdentity;

/// A strategy for obtaining access tokens.
///
/// Implementations handle all details of authentication, token caching, and
/// refresh. Callers just call [`get_token`](AuthStrategy::get_token) whenever
/// they need a valid token.
///
/// The trait is designed to be implemented for `&T`, so that callers can use
/// shared references (e.g. `&OAuthStrategy`) without consuming the strategy.
///
/// # Token refresh
///
/// All strategies that cache tokens ([`AccessKeyStrategy`], [`OAuthStrategy`],
/// [`AutoStrategy`]) share the same internal refresh engine. Understanding the
/// refresh model helps predict how [`get_token`](AuthStrategy::get_token)
/// behaves under concurrent access.
///
/// ## Expiry vs usability
///
/// A token has two time thresholds:
///
/// - **Expired** — the token is within **90 seconds** of its `expires_at`
///   timestamp. This triggers a preemptive refresh attempt.
/// - **Usable** — the token has **not yet reached** its `expires_at` timestamp.
///   A token can be "expired" (in the preemptive sense) but still "usable"
///   (the server will still accept it).
///
/// ## Concurrent refresh strategies
///
/// The gap between "expired" and "unusable" enables two refresh modes:
///
/// 1. **Expiring but still usable** — The first caller triggers a background
///    refresh. Concurrent callers receive the current (still-valid) token
///    immediately without blocking.
/// 2. **Fully expired** — The first caller blocks while refreshing. Concurrent
///    callers wait until the refresh completes, then all receive the new token.
///
/// Only one refresh runs at a time, regardless of how many callers request a
/// token concurrently.
///
/// ## Flow diagram
///
/// ```mermaid
/// flowchart TD
///     Start["get_token()"] --> Lock["Acquire lock"]
///     Lock --> Cached{Token cached?}
///     Cached -- No --> InitAuth["Authenticate
///     (lock held)"]
///     InitAuth -- OK --> ReturnNew["Return new token"]
///     InitAuth -- NotFound --> ErrNotFound["NotAuthenticated"]
///     InitAuth -- Err --> ErrAuth["Return error"]
///     Cached -- Yes --> CheckRefresh{Expired?}
///
///     CheckRefresh -- "No (fresh)" --> ReturnOk["Return cached token"]
///
///     CheckRefresh -- "Yes (needs refresh)" --> InProgress{Refresh in progress?}
///     InProgress -- Yes --> WaitOrReturn["Return token if usable,
///     else wait for refresh"]
///     WaitOrReturn -- OK --> ReturnOk
///     WaitOrReturn -- "refresh failed" --> ErrExpired["TokenExpired"]
///
///     InProgress -- No --> HasCred{Refresh credential?}
///     HasCred -- None --> CheckUsable["Return token if usable,
///     else TokenExpired"]
///
///     HasCred -- Yes --> Usable{Still usable?}
///
///     Usable -- "Yes (preemptive)" --> NonBlocking["Refresh in background
///     (lock released)"]
///     NonBlocking --> ReturnOld["Return current token"]
///
///     Usable -- "No (fully expired)" --> Blocking["Refresh
///     (lock held)"]
///     Blocking -- OK --> ReturnNew2["Return new token"]
///     Blocking -- Err --> ErrExpired["TokenExpired"]
/// ```
#[cfg_attr(doc, aquamarine::aquamarine)]
pub trait AuthStrategy: Send {
    /// Retrieve a valid access token, refreshing or re-authenticating as needed.
    fn get_token(self) -> impl Future<Output = Result<ServiceToken, AuthError>> + Send;
}

/// A sensitive token string that is zeroized on drop and hidden from debug output.
///
/// `SecretToken` wraps a `String` and enforces two invariants:
///
/// - **Zeroized on drop**: the backing memory is overwritten with zeros when
///   the token goes out of scope, preventing it from lingering in memory.
/// - **Opaque debug**: the [`Debug`] implementation prints `"***"` instead of
///   the actual value, so tokens won't leak into logs or error messages.
///
/// Use [`SecretToken::new`] to wrap a string value (e.g. an access key
/// loaded from configuration or an environment variable).
#[derive(Clone, OpaqueDebug, ZeroizeOnDrop, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct SecretToken(String);

impl SecretToken {
    /// Create a new `SecretToken` from a string value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Expose the inner token string for FFI boundaries.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Errors that can occur during an authentication flow.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum AuthError {
    /// The HTTP request to the auth server failed (network error, timeout, etc.).
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    /// The user denied the authorization request.
    #[error("Authorization was denied")]
    AccessDenied,
    /// The grant type was rejected by the server.
    #[error("Invalid grant")]
    InvalidGrant,
    /// The client ID is not recognized.
    #[error("Invalid client")]
    InvalidClient,
    /// A URL could not be parsed.
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    /// The requested region is not supported.
    #[error("Unsupported region: {0}")]
    Region(#[from] cts_common::RegionError),
    /// The workspace CRN could not be parsed.
    #[error("Invalid workspace CRN: {0}")]
    InvalidCrn(cts_common::InvalidCrn),
    /// An access key was provided but the workspace CRN is missing.
    ///
    /// Set the `CS_WORKSPACE_CRN` environment variable or call
    /// [`AutoStrategyBuilder::with_workspace_crn`](crate::AutoStrategyBuilder::with_workspace_crn).
    #[error("Workspace CRN is required when using an access key — set CS_WORKSPACE_CRN or call AutoStrategyBuilder::with_workspace_crn")]
    MissingWorkspaceCrn,
    /// No credentials are available (e.g. not logged in, no access key configured).
    #[error("Not authenticated")]
    NotAuthenticated,
    /// A token (access token or device code) has expired.
    #[error("Token expired")]
    TokenExpired,
    /// The access key string is malformed (e.g. missing `CSAK` prefix or `.` separator).
    #[error("Invalid access key: {0}")]
    InvalidAccessKey(#[from] access_key::InvalidAccessKey),
    /// The JWT could not be decoded or its claims are malformed.
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    /// An unexpected error was returned by the auth server.
    #[error("Server error: {0}")]
    Server(String),
    /// A token store operation failed.
    #[error("Token store error: {0}")]
    Store(#[from] stack_profile::ProfileError),
}

impl From<Infallible> for AuthError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

/// Read the `CS_CTS_HOST` environment variable and parse it as a URL.
///
/// Returns `Ok(None)` if the variable is not set or empty.
/// Returns `Ok(Some(url))` if the variable is set and valid.
/// Returns `Err(_)` if the variable is set but not a valid URL.
pub(crate) fn cts_base_url_from_env() -> Result<Option<url::Url>, AuthError> {
    match std::env::var("CS_CTS_HOST") {
        Ok(val) if !val.is_empty() => Ok(Some(val.parse()?)),
        _ => Ok(None),
    }
}

/// Ensure a URL has a trailing slash so that `Url::join` with relative paths
/// appends to the path rather than replacing the last segment.
pub(crate) fn ensure_trailing_slash(mut url: url::Url) -> url::Url {
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    url
}

/// Create a [`reqwest::Client`] with standard timeouts.
///
/// In test builds, timeouts are omitted so that `tokio::test(start_paused = true)`
/// does not auto-advance time past the connect timeout before the mock server
/// can respond.
pub(crate) fn http_client() -> reqwest::Client {
    #[cfg(any(test, feature = "test-utils"))]
    {
        reqwest::Client::builder()
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    }
}
