#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
//! The AWS KMS key vendor backend for Stack Encrypt (ADR-0013, ADR-0014).
//!
//! [`AwsKms`] is a small, hand-written AWS KMS client. It has the JSON API
//! (`Encrypt` and `Decrypt`), SigV4 signing in-crate ([`sigv4`]), and a
//! [`VendorTransport`](stack_kms_vendor::VendorTransport) for the HTTP. It
//! implements [`KeyVendorBackend`](stack_kms_vendor::KeyVendorBackend), so
//! [`VendorKeySource`](stack_kms_vendor::VendorKeySource) builds the
//! derived data key mode on it.
//!
//! The client calls AWS KMS for keyset records only. One `Encrypt` call
//! creates or rewraps a record. One `Decrypt` call unwraps the root key of
//! a keyset, once for each root key TTL. The data keys and index keys are
//! derived from the root key locally, so no call is made for each value.
//!
//! No AWS SDK crate is used. The AWS SDK crates need tokio and hyper, and
//! this crate also builds for wasm32-wasip1, the Go module's WASI guest.
//!
//! # Native Rust
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use stack_kms_aws::AwsKms;
//! use stack_kms_vendor::{KeysetRecord, VendorKeySource};
//! use stack_kms::KeyMode;
//!
//! // AWS_REGION, and credentials from the default chain: environment
//! // variables, IRSA, the container endpoint or IMDSv2.
//! let kms = AwsKms::from_env()?;
//! let record = KeysetRecord::create(
//!     &kms,
//!     "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
//!     KeyMode::Derived,
//!     Some("users".to_owned()),
//! )
//! .await?;
//! let source = VendorKeySource::new(kms, [record])?;
//! # let _ = source;
//! # Ok(())
//! # }
//! ```
//!
//! # Capabilities and limits
//!
//! The [capability matrix](stack_kms_vendor#capability-matrix) of
//! `stack-kms-vendor` compares this backend with ZeroKMS and the other
//! key vendor backends: key lifetime, vendor calls, what the vendor sees
//! and can refuse, credentials, rotation and known limits.
//!
//! # The WASI guest
//!
//! The guest builds [`AwsKms::new`] with its host transport and a
//! [`CredentialsProvider`] over a host import. The workload identity
//! providers (IRSA, the container endpoint, IMDS) are native only: in the
//! guest, the host's own credential chain supplies the credentials.

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

mod client;
mod config;
pub mod credentials;
pub mod sigv4;
mod time;

pub use client::{
    encryption_context, error_kind, AwsKms, AwsKmsError, CONTEXT_AAD, CONTEXT_KEYSET_ID,
    CONTEXT_PURPOSE,
};
pub use config::{AwsKmsConfig, ConfigError};
pub use credentials::{
    AwsCredentials, CachedCredentials, Credentials, CredentialsError, CredentialsProvider,
    DEFAULT_REFRESH_BEFORE_EXPIRY,
};
pub use time::{system_clock, Clock};

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
mod native {
    use std::time::Duration;

    use stack_kms_vendor::{HttpVendorTransport, HttpVendorTransportOptions};

    use crate::credentials::{DefaultCredentials, DefaultCredentialsSource};
    use crate::{AwsKms, AwsKmsConfig};

    /// [`AwsKms::from_env`] failed.
    #[derive(Debug, thiserror::Error)]
    pub enum FromEnvError {
        /// The region or endpoint.
        #[error(transparent)]
        Config(#[from] crate::ConfigError),
        /// The credentials.
        #[error(transparent)]
        Credentials(#[from] crate::CredentialsError),
        /// The HTTP client.
        #[error(transparent)]
        Transport(#[from] stack_kms_vendor::TransportError),
    }

    /// The client [`AwsKms::from_env`] builds.
    pub type DefaultAwsKms = AwsKms<HttpVendorTransport, DefaultCredentials<HttpVendorTransport>>;

    impl DefaultAwsKms {
        /// A client configured from the environment, as the AWS SDKs are:
        /// the region and endpoint from [`AwsKmsConfig::from_env`], and the
        /// credentials from the default chain
        /// ([`DefaultCredentialsSource`]), cached. Native only.
        ///
        /// The credentials transport opens connections with a 1 second
        /// limit, so that off EC2 the IMDS probe fails fast.
        pub fn from_env() -> Result<Self, FromEnvError> {
            let config = AwsKmsConfig::from_env()?;
            let transport = HttpVendorTransport::new()?;
            let credentials_transport =
                HttpVendorTransport::with_options(HttpVendorTransportOptions {
                    timeout: Duration::from_secs(10),
                    connect_timeout: Some(Duration::from_secs(1)),
                })?;
            let credentials = DefaultCredentialsSource::cached_from_env(
                credentials_transport,
                Some(config.region()),
            )?;
            Ok(AwsKms::new(config, transport, credentials))
        }
    }
}

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use native::{DefaultAwsKms, FromEnvError};
