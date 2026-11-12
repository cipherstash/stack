#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
//! The HashiCorp Vault Transit key vendor backend for Stack Encrypt
//! (ADR-0013, ADR-0014).
//!
//! [`VaultTransit`] is a small, hand-written client for the Transit secrets
//! engine: `encrypt`, `decrypt`, `rewrap` and a key read. It sends through
//! a [`VendorTransport`](stack_kms_vendor::VendorTransport) and implements
//! [`KeyVendorBackend`](stack_kms_vendor::KeyVendorBackend), so
//! [`VendorKeySource`](stack_kms_vendor::VendorKeySource) builds the
//! derived data key mode on it. No Vault SDK crate is used, so this crate
//! also builds for wasm32-wasip1, the Go module's WASI guest.
//!
//! The client calls Vault for keyset records only. One `encrypt` call
//! creates or rewraps a record. One `decrypt` call unwraps the root key of
//! a keyset, once for each root key TTL. The data keys and index keys are
//! derived from the root key locally, so no call is made for each value.
//!
//! # Native Rust
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use stack_kms_vault::VaultTransit;
//! use stack_kms_vendor::{KeysetRecord, VendorKeySource};
//! use stack_kms::KeyMode;
//!
//! // VAULT_ADDR, VAULT_NAMESPACE, and a token from VAULT_TOKEN, AppRole
//! // or Kubernetes auth.
//! let vault = VaultTransit::from_env()?;
//! let record = KeysetRecord::create(
//!     &vault,
//!     "cipherstash-users",
//!     KeyMode::Derived,
//!     Some("users".to_owned()),
//! )
//! .await?;
//! let source = VendorKeySource::new(vault, [record])?;
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
//! # Vault policy
//!
//! The token needs `update` on `<mount>/encrypt/<key>` and
//! `<mount>/decrypt/<key>`, and (with the default
//! [`KeyDerivation::Detect`]) `read` on `<mount>/keys/<key>`. Give it
//! `update` on `<mount>/rewrap/<key>` to use [`VaultTransit::rewrap`]. Do
//! not give it `create` on `<mount>/encrypt/<key>`: with it, Transit
//! creates a missing key on the first `encrypt`.
//!
//! # The WASI guest
//!
//! The guest builds [`VaultTransit::new`] with its host transport and a
//! [`TokenProvider`] over a host import. Kubernetes auth reads a file and is
//! native only: in the guest, the host's own auth supplies the token.

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
    AppRoleLogin, AuthError, CachedToken, TokenProvider, VaultAuth, VaultToken,
    DEFAULT_APPROLE_MOUNT, DEFAULT_REFRESH_BEFORE_EXPIRY,
};
#[cfg(not(target_arch = "wasm32"))]
pub use auth::{DefaultAuth, KubernetesLogin};
pub use client::{
    compact_ciphertext, error_kind, expand_ciphertext, VaultError, VaultTransit, AEAD_KEY_TYPES,
    INVALID_CIPHERTEXT_MARKERS, NOT_FOUND_MARKERS, WRAPPED_KEY_FORMAT,
};
pub use config::{process_env, ConfigError, EnvLookup, KeyDerivation, VaultConfig, DEFAULT_MOUNT};
pub use time::{system_clock, Clock};

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
mod native {
    use stack_kms_vendor::HttpVendorTransport;

    use crate::auth::DefaultAuth;
    use crate::{VaultConfig, VaultTransit};

    /// [`VaultTransit::from_env`] failed.
    #[derive(Debug, thiserror::Error)]
    pub enum FromEnvError {
        /// The address, namespace or mount.
        #[error(transparent)]
        Config(#[from] crate::ConfigError),
        /// The auth method.
        #[error(transparent)]
        Auth(#[from] crate::AuthError),
        /// The HTTP client.
        #[error(transparent)]
        Transport(#[from] stack_kms_vendor::TransportError),
    }

    /// The client [`VaultTransit::from_env`] builds.
    pub type DefaultVaultTransit =
        VaultTransit<HttpVendorTransport, DefaultAuth<HttpVendorTransport>>;

    impl DefaultVaultTransit {
        /// A client configured from the environment: the address, namespace
        /// and mount from [`VaultConfig::from_env`], and the auth method
        /// from [`DefaultAuth::from_env`]. Native only.
        pub fn from_env() -> Result<Self, FromEnvError> {
            let config = VaultConfig::from_env()?;
            let auth = DefaultAuth::from_env(&config, HttpVendorTransport::new()?)?;
            Ok(VaultTransit::new(config, HttpVendorTransport::new()?, auth))
        }
    }
}

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use native::{DefaultVaultTransit, FromEnvError};
