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
use std::time::{SystemTime, UNIX_EPOCH};

use vitaminc::protected::OpaqueDebug;
use zeroize::ZeroizeOnDrop;

mod device_code;
mod token_store;

pub use device_code::{DeviceCodeStrategy, PendingDeviceCode};
pub use token_store::{TokenStore, TokenStoreError};

/// A sensitive token string that is zeroized on drop and hidden from debug output.
///
/// `SecretToken` wraps a `String` and enforces two invariants:
///
/// - **Zeroized on drop**: the backing memory is overwritten with zeros when
///   the token goes out of scope, preventing it from lingering in memory.
/// - **Opaque debug**: the [`Debug`] implementation prints `"***"` instead of
///   the actual value, so tokens won't leak into logs or error messages.
///
/// You cannot construct a `SecretToken` directly — it is returned by the
/// authentication flow via [`Token::access_token`].
#[derive(OpaqueDebug, ZeroizeOnDrop, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct SecretToken(String);

impl SecretToken {
    /// Create a new `SecretToken` from a string value.
    #[cfg(test)]
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Expose the inner token string for FFI boundaries.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An access token returned by a successful authentication flow.
///
/// The token contains a [`SecretToken`] (the bearer credential), a token type
/// (typically `"Bearer"`), and an absolute expiry timestamp.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Token {
    access_token: SecretToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<SecretToken>,
    token_type: String,
    expires_at: u64,
}

impl Token {
    /// Returns a reference to the access token credential.
    ///
    /// The returned [`SecretToken`] is opaque — its [`Debug`] output is masked.
    /// Pass it to API clients that need the raw bearer token.
    pub fn access_token(&self) -> &SecretToken {
        &self.access_token
    }

    /// The token type (e.g. `"Bearer"`).
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// The absolute epoch timestamp when the token expires.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// How many seconds until the token expires (computed from the current time).
    pub fn expires_in(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.expires_at.saturating_sub(now)
    }

    /// Returns `true` if the token has expired (with 60 seconds of leeway).
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now + 60 >= self.expires_at
    }

    /// Returns a reference to the refresh token, if one was provided.
    pub fn refresh_token(&self) -> Option<&SecretToken> {
        self.refresh_token.as_ref()
    }
}

/// Errors that can occur during an authentication flow.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// The HTTP request to the auth server failed (network error, timeout, etc.).
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    /// The user denied the authorization request.
    #[error("Authorization was denied")]
    AccessDenied,
    /// The device code expired before the user authorized.
    #[error("Device code expired")]
    ExpiredToken,
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
    /// An unexpected error was returned by the auth server.
    #[error("Server error: {0}")]
    Server(String),
}

impl From<Infallible> for AuthError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_token_debug_does_not_leak() {
        let token = SecretToken("super_secret_value".to_string());
        let debug = format!("{:?}", token);
        assert!(
            !debug.contains("super_secret_value"),
            "SecretToken Debug should not contain the secret, got: {debug}"
        );
    }
}
