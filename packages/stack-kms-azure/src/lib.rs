#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
//! The Azure Key Vault Managed HSM key vendor backend for Stack Encrypt
//! (ADR-0013, ADR-0014).
//!
//! [`AzureManagedHsm`] is a small, hand-written client for the Key Vault REST
//! API that Managed HSM serves ([`API_VERSION`]): `wrapkey` and `unwrapkey`
//! with A256KW (RFC 3394) under a Managed HSM `oct-HSM` (AES-256) key. It
//! sends through a [`VendorTransport`](stack_kms_vendor::VendorTransport)
//! and implements [`KeyVendorBackend`](stack_kms_vendor::KeyVendorBackend),
//! so [`VendorKeySource`](stack_kms_vendor::VendorKeySource) builds the
//! derived key mode on it. No Azure SDK crate is used, so this crate also
//! builds for wasm32-wasip1, the Go module's WASI guest.
//!
//! **Azure Key Vault (vaults on `vault.azure.net`) is not supported.** A
//! vault holds only RSA and EC keys. Anyone with an RSA public key can wrap
//! a key, so an RSA wrap does not prove that the key vendor made a keyset
//! record: whoever can write the records could put in a root key that they
//! know. Only a caller that the HSM lets use an AES key can wrap under it.
//!
//! **Not tested against a live Managed HSM.** Microsoft has no Managed HSM
//! emulator, and we have no live instance. The tests run against
//! hand-written fixtures in the documented shapes and an in-process
//! emulator. The live test (`tests/live.rs`) and its workflow stay off
//! until a live instance is available.
//!
//! Managed HSM wraps only the root key of a keyset. One `wrapkey` call
//! creates a keyset record or rewraps it. One `unwrapkey` call unwraps the
//! root key, one time for each root key TTL
//! ([`DEFAULT_ROOT_KEY_TTL`](stack_kms_vendor::DEFAULT_ROOT_KEY_TTL)).
//! Each value's data key is derived from the root key locally, so a value
//! costs no Managed HSM call.
//!
//! `wrapkey` has **no associated data**. The client binds the associated
//! data with a digest inside the wrapped plaintext
//! ([`stack_kms_vendor::bound`]); see [`AzureManagedHsm`] for the trade-off.
//!
//! # Native Rust
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use stack_kms_azure::AzureManagedHsm;
//! use stack_kms_vendor::{KeysetRecord, VendorKeySource};
//! use stack_kms::KeyMode;
//!
//! // AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET, workload
//! // identity, or the managed identity on Azure.
//! let kms = AzureManagedHsm::from_env()?;
//! let record = KeysetRecord::create(
//!     &kms,
//!     "https://my-hsm.managedhsm.azure.net/keys/cipherstash-users",
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
//! # Access
//!
//! The identity needs the `wrapKey` and `unwrapKey` key permissions and,
//! unless the key identifier names a version, `get`. With Managed HSM local
//! RBAC, the built-in role "Managed HSM Crypto Service Encryption User" has
//! all three. The key must be an `oct-HSM` key whose permitted operations
//! include `wrapKey` and `unwrapKey`. Rotate the key in Managed HSM: a
//! keyset record names the version that wrapped its root key
//! ([`wrapped_key_version`]), and an unwrap still works under an old
//! version until you disable it.
//!
//! # The WASI guest
//!
//! The guest builds [`AzureManagedHsm::new`] with its host transport and a
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
    wrapped_key_version, AzureManagedHsm, AzureManagedHsmError, WrappedKeyParts, KEY_STATE_CODES,
    MAX_RETRY_AFTER, WRAPPED_KEY_FORMAT, WRAP_PLAINTEXT_LEN,
};
pub use config::{
    is_version, process_env, EnvLookup, KeyId, API_VERSION, KEY_TYPE, KNOWN_SUFFIXES,
    MANAGED_HSM_SCOPE, MAX_VERSION_LEN, WRAP_ALGORITHM,
};
pub use time::{system_clock, Clock};

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
mod native {
    use std::time::Duration;

    use stack_kms_vendor::{HttpVendorTransport, HttpVendorTransportOptions};

    use crate::auth::DefaultCredentials;
    use crate::AzureManagedHsm;

    /// [`AzureManagedHsm::from_env`] failed.
    #[derive(Debug, thiserror::Error)]
    pub enum FromEnvError {
        /// The credentials.
        #[error(transparent)]
        Auth(#[from] crate::AuthError),
        /// The HTTP client.
        #[error(transparent)]
        Transport(#[from] stack_kms_vendor::TransportError),
    }

    /// The client [`AzureManagedHsm::from_env`] builds.
    pub type DefaultAzureManagedHsm =
        AzureManagedHsm<HttpVendorTransport, DefaultCredentials<HttpVendorTransport>>;

    impl DefaultAzureManagedHsm {
        /// A client with the credentials of [`DefaultCredentials::from_env`].
        /// Native only.
        ///
        /// The credentials transport opens connections with a 1 second
        /// limit, so that off Azure the IMDS probe fails fast.
        pub fn from_env() -> Result<Self, FromEnvError> {
            let credentials_transport =
                HttpVendorTransport::with_options(HttpVendorTransportOptions {
                    timeout: Duration::from_secs(10),
                    connect_timeout: Some(Duration::from_secs(1)),
                })?;
            let auth = DefaultCredentials::from_env(credentials_transport)?;
            Ok(AzureManagedHsm::new(HttpVendorTransport::new()?, auth))
        }
    }
}

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use native::{DefaultAzureManagedHsm, FromEnvError};
