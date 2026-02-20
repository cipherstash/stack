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

use std::borrow::Cow;
use std::convert::Infallible;
#[cfg(not(test))]
use std::time::Duration;

use vitaminc::protected::OpaqueDebug;
use zeroize::ZeroizeOnDrop;

mod device_code;
mod token;
mod token_store;
mod token_store_strategy;

pub use device_code::{DeviceCodeStrategy, PendingDeviceCode};
pub use token::Token;
pub use token_store::{TokenStore, TokenStoreError};
pub use token_store_strategy::TokenStoreStrategy;

/// A strategy for obtaining a [`SecretToken`] for authenticating with CipherStash services.
///
/// Implementors provide a single method, [`get_token`](AuthStrategy::get_token), which
/// returns a valid access token. The strategy is responsible for managing token
/// lifecycle concerns such as caching, refreshing, or re-authenticating as needed.
///
/// The lifetime `'a` ties the returned reference to the data that owns the token,
/// allowing the same strategy to be called multiple times (e.g. by implementing
/// the trait for `&'a T`).
pub trait AuthStrategy<'a> {
    /// The error type returned when token retrieval fails.
    type Error;

    /// Retrieve a valid access token.
    ///
    /// Returns `Cow::Borrowed` for strategies that own a stable token, or
    /// `Cow::Owned` for strategies that clone the token out from behind a lock.
    fn get_token(
        self,
    ) -> impl std::future::Future<Output = Result<Cow<'a, SecretToken>, Self::Error>> + Send;
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
/// You cannot construct a `SecretToken` directly — it is returned by the
/// authentication flow via [`Token::access_token`].
#[derive(Clone, OpaqueDebug, ZeroizeOnDrop, serde::Deserialize, serde::Serialize)]
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
    /// The token does not contain a refresh token.
    #[error("No refresh token available")]
    NoRefreshToken,
    /// An unexpected error was returned by the auth server.
    #[error("Server error: {0}")]
    Server(String),
}

impl From<Infallible> for AuthError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

/// Create a [`reqwest::Client`] with standard timeouts.
///
/// In test builds, timeouts are omitted so that `tokio::test(start_paused = true)`
/// does not auto-advance time past the connect timeout before the mock server
/// can respond.
pub(crate) fn http_client() -> reqwest::Client {
    #[cfg(test)]
    {
        reqwest::Client::new()
    }
    #[cfg(not(test))]
    {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    }
}
