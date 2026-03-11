//! Authenticate with [CipherStash](https://cipherstash.com) services using the
//! [OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628).
//!
//! This crate implements the device code flow, which lets CLI tools and other
//! browserless applications obtain an access token by having the user authorize
//! in a browser on another device.
//!
//! # Usage
//!
//! ```no_run
//! use stack_auth::DeviceCodeStrategy;
//! use cts_common::Region;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Create a strategy for your region and client ID
//! let region = Region::aws("ap-southeast-2")?;
//! let strategy = DeviceCodeStrategy::new(region, "my-client-id")?;
//!
//! // 2. Begin the device code flow
//! let pending = strategy.begin().await?;
//!
//! // 3. Show the user their code and where to enter it
//! println!("Go to: {}", pending.verification_uri_complete());
//! println!("Code:  {}", pending.user_code());
//!
//! // Or open the browser directly:
//! pending.open_in_browser();
//!
//! // 4. Poll until the user authorizes (or the code expires)
//! let token = pending.poll_for_token().await?;
//!
//! // 5. Use the access token to call CipherStash APIs
//! println!("Authenticated! Token expires in {}s", token.expires_in());
//! # Ok(())
//! # }
//! ```
//!
//! # Security
//!
//! Sensitive values ([`SecretToken`]) are automatically zeroized when dropped
//! and are masked in [`Debug`](std::fmt::Debug) output to prevent accidental
//! leaks in logs.

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

mod access_key_refresher;
mod access_key_strategy;
mod auto_refresh;
mod auto_strategy;
mod device_code;
mod oauth_refresher;
mod oauth_strategy;
mod refresher;
mod token;

#[cfg(any(test, feature = "test-utils"))]
mod static_token_strategy;

pub use access_key_strategy::{AccessKeyStrategy, AccessKeyStrategyBuilder};
pub use auto_strategy::AutoStrategy;
pub use device_code::{DeviceCodeStrategy, DeviceCodeStrategyBuilder, PendingDeviceCode};
pub use oauth_strategy::{OAuthStrategy, OAuthStrategyBuilder};
#[cfg(any(test, feature = "test-utils"))]
pub use static_token_strategy::StaticTokenStrategy;
pub use token::Token;

// Re-exports from stack-profile for backward compatibility.
pub use stack_profile::DeviceIdentity;

/// A profile store for persisting auth tokens and related files.
pub type TokenStore = stack_profile::ProfileStore;

/// Error type for profile-store operations.
pub type TokenStoreError = stack_profile::ProfileError;

/// Default filename for the auth token file.
pub(crate) const AUTH_FILENAME: &str = "auth.json";

/// A strategy for obtaining access tokens.
///
/// Implementations handle all details of authentication, token caching, and
/// refresh. Callers just call [`get_token`](AuthStrategy::get_token) whenever
/// they need a valid token.
///
/// The trait is designed to be implemented for `&T`, so that callers can use
/// shared references (e.g. `&OAuthStrategy`) without consuming the strategy.
pub trait AuthStrategy: Send {
    /// Retrieve a valid access token, refreshing or re-authenticating as needed.
    fn get_token(self) -> impl Future<Output = Result<SecretToken, AuthError>> + Send;
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
    /// No credentials are available (e.g. not logged in, no access key configured).
    #[error("Not authenticated")]
    NotAuthenticated,
    /// A token (access token or device code) has expired.
    #[error("Token expired")]
    TokenExpired,
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

/// Returns a token store at the default profile directory: `~/.cipherstash`.
pub fn default_token_store() -> Result<TokenStore, TokenStoreError> {
    TokenStore::resolve(None)
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
        reqwest::Client::new()
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    }
}
