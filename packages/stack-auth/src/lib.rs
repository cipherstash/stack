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

use vitaminc::protected::OpaqueDebug;
use zeroize::ZeroizeOnDrop;

mod device_code;

pub use device_code::{DeviceCodeStrategy, PendingDeviceCode};

/// A sensitive token string that is zeroized on drop and hidden from debug output.
#[derive(OpaqueDebug, ZeroizeOnDrop, serde::Deserialize)]
#[serde(transparent)]
pub struct SecretToken(String);

/// An access token returned by an authentication flow.
#[derive(Debug)]
pub struct Token {
    access_token: SecretToken,
    token_type: String,
    expires_in: u64,
}

impl Token {
    pub fn access_token(&self) -> &SecretToken {
        &self.access_token
    }

    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    pub fn expires_in(&self) -> u64 {
        self.expires_in
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Authorization was denied")]
    AccessDenied,
    #[error("Device code expired")]
    ExpiredToken,
    #[error("Invalid grant")]
    InvalidGrant,
    #[error("Invalid client")]
    InvalidClient,
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("Unsupported region: {0}")]
    Region(#[from] cts_common::RegionError),
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
