#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
//! The Azure Key Vault and Managed HSM key vendor backend for Stack Encrypt
//! (ADR-0009, ADR-0011).
//!
//! [`AzureKeyVault`] is a small, hand-written client for the Key Vault REST
//! API ([`API_VERSION`]): `wrapkey` and `unwrapkey`, with RSA-OAEP-256 for a
//! Key Vault RSA key and A256KW for a Managed HSM `oct-HSM` key. It sends
//! through a [`VendorTransport`](stack_kms_vendor::VendorTransport) and
//! implements [`KeyVendorBackend`](stack_kms_vendor::KeyVendorBackend), so
//! [`VendorKeySource`](stack_kms_vendor::VendorKeySource) builds both key
//! modes on it. No Azure SDK crate is used, so this crate also builds for
//! wasm32-wasip1, the Go module's WASI guest. It does no RSA itself: Azure
//! holds the key and does the RSA operation.
//!
//! Key Vault has no data key generation, no batch operation and **no
//! associated data** on `wrapkey`. Each wrapped data key is a key from the
//! local CSPRNG and one `wrapkey` call, and the associated data is bound by
//! a digest inside the wrapped plaintext ([`stack_kms_vendor::bound`]); see
//! [`AzureKeyVault`] for the trade-off.
//!
//! # Native Rust
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use stack_kms_azure::AzureKeyVault;
//! use stack_kms_vendor::{KeysetRecord, VendorKeySource};
//! use stack_kms::KeyMode;
//!
//! // AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET, workload
//! // identity, or the managed identity on Azure.
//! let kms = AzureKeyVault::from_env()?;
//! let record = KeysetRecord::create(
//!     &kms,
//!     "https://my-vault.vault.azure.net/keys/cipherstash-users",
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
//! # Capabilities and limits
//!
//! The [capability matrix](stack_kms_vendor#capability-matrix) of
//! `stack-kms-vendor` compares this backend with ZeroKMS and the other
//! key vendor backends: key lifetime, vendor calls, what the vendor sees
//! and can refuse, credentials, rotation and known limits.
//!
//! # Access
//!
//! The identity needs the `wrapKey` and `unwrapKey` key permissions and,
//! unless the key identifier names a version and
//! [`AzureKeyVaultConfig::with_algorithm`] is set, `get`. With Azure RBAC,
//! the built-in role "Key Vault Crypto Service Encryption User" has all
//! three (on Managed HSM, "Managed HSM Crypto Service Encryption User"). The
//! key's permitted operations must include `wrapKey` and `unwrapKey`.
//! Rotate the key in Key Vault: stored keys name the version that wrapped
//! them ([`wrapped_key_version`]), and an unwrap still works under an old
//! version until you disable it.
//!
//! # The WASI guest
//!
//! The guest builds [`AzureKeyVault::new`] with its host transport and a
//! [`TokenProvider`] over a host import. Workload identity and managed
//! identity are native only: in the guest, the host's own credentials
//! supply the token.

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
mod time;

pub use auth::{
    AccessToken, AuthError, AzureCredentials, CachedToken, ClientSecretLogin, TokenProvider,
    ACCESS_TOKEN_VARIABLE, DEFAULT_AUTHORITY_HOST, DEFAULT_REFRESH_BEFORE_EXPIRY,
};
#[cfg(not(target_arch = "wasm32"))]
pub use auth::{DefaultCredentials, ManagedIdentityLogin, WorkloadIdentityLogin};
pub use client::{
    compact_ciphertext, error_kind, retry_after, split_wrapped_key, wrap_plaintext,
    wrapped_key_version, AzureKeyVault, AzureKeyVaultError, WrappedKeyParts, KEY_STATE_CODES,
    MAX_RETRY_AFTER, WRAPPED_KEY_FORMAT, WRAP_PLAINTEXT_LEN,
};
pub use config::{
    is_version, process_env, AzureKeyVaultConfig, EnvLookup, Flavour, KeyId, WrapAlgorithm,
    API_VERSION, KEY_VAULT_SCOPE, KNOWN_SUFFIXES, MANAGED_HSM_SCOPE, MAX_VERSION_LEN,
};
pub use time::{system_clock, Clock};

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
mod native {
    use std::time::Duration;

    use stack_kms_vendor::{HttpVendorTransport, HttpVendorTransportOptions};

    use crate::auth::DefaultCredentials;
    use crate::{AzureKeyVault, AzureKeyVaultConfig};

    /// [`AzureKeyVault::from_env`] failed.
    #[derive(Debug, thiserror::Error)]
    pub enum FromEnvError {
        /// The credentials.
        #[error(transparent)]
        Auth(#[from] crate::AuthError),
        /// The HTTP client.
        #[error(transparent)]
        Transport(#[from] stack_kms_vendor::TransportError),
    }

    /// The client [`AzureKeyVault::from_env`] builds.
    pub type DefaultAzureKeyVault =
        AzureKeyVault<HttpVendorTransport, DefaultCredentials<HttpVendorTransport>>;

    impl DefaultAzureKeyVault {
        /// A client with the credentials of [`DefaultCredentials::from_env`].
        /// Native only.
        ///
        /// The credentials transport opens connections with a 1 second
        /// limit, so that off Azure the IMDS probe fails fast.
        pub fn from_env() -> Result<Self, FromEnvError> {
            Self::from_env_with(AzureKeyVaultConfig::new())
        }

        /// As [`from_env`](Self::from_env), with `config`.
        pub fn from_env_with(config: AzureKeyVaultConfig) -> Result<Self, FromEnvError> {
            let credentials_transport =
                HttpVendorTransport::with_options(HttpVendorTransportOptions {
                    timeout: Duration::from_secs(10),
                    connect_timeout: Some(Duration::from_secs(1)),
                })?;
            let auth = DefaultCredentials::from_env(credentials_transport)?;
            Ok(AzureKeyVault::new(
                config,
                HttpVendorTransport::new()?,
                auth,
            ))
        }
    }
}

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use native::{DefaultAzureKeyVault, FromEnvError};
