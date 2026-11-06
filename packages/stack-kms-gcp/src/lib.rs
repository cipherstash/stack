#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
//! The Google Cloud KMS key vendor backend for Stack Encrypt (ADR-0009,
//! ADR-0011).
//!
//! [`GcpKms`] is a small, hand-written client for the Cloud KMS REST API v1:
//! `cryptoKeys.encrypt` and `cryptoKeys.decrypt`, with the associated data
//! as `additionalAuthenticatedData` and CRC32C integrity checks on every
//! field. It sends through a
//! [`VendorTransport`](stack_kms_vendor::VendorTransport) and implements
//! [`KeyVendorBackend`](stack_kms_vendor::KeyVendorBackend), so
//! [`VendorKeySource`](stack_kms_vendor::VendorKeySource) builds both key
//! modes on it. No Google SDK crate is used, so this crate also builds for
//! wasm32-wasip1, the Go module's WASI guest.
//!
//! Cloud KMS has no data key generation and no batch operation: under
//! wrapped data keys each value's data key comes from the local CSPRNG and
//! costs one `encrypt` call.
//!
//! # Native Rust
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use stack_kms_gcp::GcpKms;
//! use stack_kms_vendor::{KeysetRecord, VendorKeySource};
//! use stack_kms::KeyMode;
//!
//! // GOOGLE_APPLICATION_CREDENTIALS (a service account key file), or the
//! // metadata server on Google Cloud.
//! let kms = GcpKms::from_env()?;
//! let record = KeysetRecord::create(
//!     &kms,
//!     "projects/my-project/locations/global/keyRings/cipherstash/cryptoKeys/users",
//!     KeyMode::Wrapped,
//!     Some("users".to_owned()),
//! )
//! .await?;
//! let source = VendorKeySource::new(kms, [record])?;
//! # let _ = source;
//! # Ok(())
//! # }
//! ```
//!
//! # IAM
//!
//! The service account needs `roles/cloudkms.cryptoKeyEncrypterDecrypter` on
//! the crypto key (the permissions `cloudkms.cryptoKeyVersions.useToEncrypt`
//! and `useToDecrypt`). The key must be a symmetric `ENCRYPT_DECRYPT` key.
//! Rotate it in Cloud KMS: stored keys name the version that wrapped them
//! ([`wrapped_key_version`]), and decrypt still works under an old version
//! until you disable or destroy it.
//!
//! # The WASI guest
//!
//! The guest builds [`GcpKms::new`] with its host transport and a
//! [`TokenProvider`] over a host import. The metadata server and key files
//! are native only: in the guest, the host's own credentials supply the
//! token.

#![deny(unsafe_code)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::panic)]
#![warn(clippy::mem_forget)]
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]
#![warn(clippy::dbg_macro)]
#![warn(unreachable_pub)]
#![warn(unused_results)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::panic))]
#![cfg_attr(test, allow(unused_results))]

pub mod auth;
mod client;
mod config;
pub mod crc32c;
mod time;

#[cfg(all(feature = "service-account", not(target_arch = "wasm32")))]
pub use auth::DefaultCredentials;
#[cfg(not(target_arch = "wasm32"))]
pub use auth::MetadataServerLogin;
pub use auth::{
    AccessToken, AuthError, CachedToken, TokenProvider, CLOUD_KMS_SCOPE,
    DEFAULT_REFRESH_BEFORE_EXPIRY,
};
#[cfg(feature = "service-account")]
pub use auth::{ServiceAccountKey, ServiceAccountLogin, DEFAULT_TOKEN_URI};
pub use client::{
    compact_ciphertext, error_kind, split_wrapped_key, wrapped_key_version, GcpKms, GcpKmsError,
    CHECKSUM_MARKERS, INVALID_CIPHERTEXT_MARKERS, WRAPPED_KEY_FORMAT,
};
pub use config::{
    parse_key_name, process_env, ConfigError, EnvLookup, GcpKmsConfig, DEFAULT_ENDPOINT,
};
pub use time::{system_clock, Clock};

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
mod native {
    use std::time::Duration;

    use stack_kms_vendor::{HttpVendorTransport, HttpVendorTransportOptions};

    use crate::auth::DefaultCredentials;
    use crate::{GcpKms, GcpKmsConfig};

    /// [`GcpKms::from_env`] failed.
    #[derive(Debug, thiserror::Error)]
    pub enum FromEnvError {
        /// The credentials.
        #[error(transparent)]
        Auth(#[from] crate::AuthError),
        /// The HTTP client.
        #[error(transparent)]
        Transport(#[from] stack_kms_vendor::TransportError),
    }

    /// The client [`GcpKms::from_env`] builds.
    pub type DefaultGcpKms = GcpKms<HttpVendorTransport, DefaultCredentials<HttpVendorTransport>>;

    impl DefaultGcpKms {
        /// A client of the public Cloud KMS endpoint, with the credentials
        /// of [`DefaultCredentials::from_env`]. Native only.
        ///
        /// The credentials transport opens connections with a 1 second
        /// limit, so that off Google Cloud the metadata server probe fails
        /// fast.
        pub fn from_env() -> Result<Self, FromEnvError> {
            Self::from_env_with(GcpKmsConfig::new())
        }

        /// As [`from_env`](Self::from_env), with `config` (for example
        /// another endpoint).
        pub fn from_env_with(config: GcpKmsConfig) -> Result<Self, FromEnvError> {
            let credentials_transport =
                HttpVendorTransport::with_options(HttpVendorTransportOptions {
                    timeout: Duration::from_secs(10),
                    connect_timeout: Some(Duration::from_secs(1)),
                })?;
            let auth = DefaultCredentials::from_env(credentials_transport)?;
            Ok(GcpKms::new(config, HttpVendorTransport::new()?, auth))
        }
    }
}

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use native::{DefaultGcpKms, FromEnvError};
