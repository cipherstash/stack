#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::convert::Infallible;
use std::future::Future;

use vitaminc::protected::OpaqueDebug;
use zeroize::ZeroizeOnDrop;

mod device_code;

pub use device_code::{DeviceCodeStrategy, PendingDeviceCode};

/// Strategy for authenticating with CTS.
pub trait AuthStrategy {
    fn authenticate(self) -> impl Future<Output = Result<Token, AuthError>> + Send;
}

/// An access token returned by an authentication flow.
#[derive(OpaqueDebug, ZeroizeOnDrop)]
pub struct Token {
    access_token: String,
    #[zeroize(skip)]
    token_type: String,
    #[zeroize(skip)]
    expires_in: u64,
}

impl Token {
    pub fn access_token(&self) -> &str {
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
pub enum AuthError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Authorization was denied")]
    AccessDenied,
    #[error("Device code expired")]
    ExpiredToken,
    #[error("Invalid grant type")]
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
