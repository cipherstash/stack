#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
//! `stack-kms` is a focused client for ZeroKMS **data key** operations:
//! generating new data keys and retrieving existing ones.
//!
//! It is an extraction of the key-generation/retrieval slice of
//! `cipherstash-client`'s `zerokms` module into a standalone crate. This first
//! cut deliberately covers only:
//!
//! * [`StackKms::generate_keys`] — derive fresh data keys (with tags) from ZeroKMS
//! * [`StackKms::retrieve_keys`] / [`StackKms::retrieve_keys_fallible`] — re-derive
//!   data keys for previously encrypted records
//! * [`StackKms::load_keyset`] — load a keyset and derive its deterministic
//!   [`IndexKey`], used to generate index terms (Searchable Encrypted Metadata)
//!
//! Encryption/decryption, keyset and client management, and config save/load
//! all remain in `cipherstash-client` for now.
//!
//! # Quick start
//!
// The quick start goes through `StackKmsBuilder`, which configures the default
// reqwest transport and so only exists with `http`. Without the feature the
// entry point is `StackKms::connect` over the host's own `ZeroKMSConnection`.
#![cfg_attr(
    feature = "http",
    doc = r#"```no_run
use stack_kms::{StackKmsBuilder, GenerateKeyPayload};
use std::borrow::Cow;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
// Credentials + client key are discovered from the environment:
//   CS_CLIENT_ID / CS_CLIENT_KEY for the key, AutoStrategy for the token.
let kms = StackKmsBuilder::auto()?
    .with_key_provider(stack_kms::EnvKeyProvider)
    .build()
    .await?;

let keys = kms
    .generate_keys(
        [GenerateKeyPayload::new("users/email", Cow::Owned(vec![]))],
        None,
        None,
    )
    .await?;

assert_eq!(keys.len(), 1);
# Ok(())
# }
```"#
)]
#![cfg_attr(
    not(feature = "http"),
    doc = "Without the `http` feature the crate ships no transport: implement\
 [`ZeroKMSConnection`] over the host's own HTTP and build the client with\
 [`StackKms::connect`]. Enable `http` for the bundled reqwest transport and its\
 `StackKmsBuilder`."
)]
// Security lints — see `.claude/skills/rust-security`. This crate handles
// ZeroKMS key material, so `mem::forget` (which would bypass `ZeroizeOnDrop`)
// and any accidental console output are denied/warned against.
#![deny(unsafe_code)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::panic)]
#![warn(clippy::mem_forget)]
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

#[cfg(feature = "http")]
mod builder;
mod client;
mod connection;
mod endpoint;
mod errors;
mod futures;
mod key;
mod key_provider;
mod key_source;
mod maybe_send;
mod payload;
mod secret_key;
#[cfg(feature = "http")]
mod user_agent;
pub mod vars;

// Builder (configures the default HTTP transport)
#[cfg(feature = "http")]
pub use builder::{StackKmsBuilder, StackKmsBuilderError, WithKeyProvider};

// Clients
pub use client::{
    Client, ClientOpts, FallibleDataKeyVec, InvalidClientOpts, StackKms, DEFAULT_CONCURRENT_REQS,
    DEFAULT_KEYS_PER_REQ,
};

// Transport
#[cfg(feature = "http")]
pub use connection::{ConnectionInitError, HttpConnection, HttpConnectionOpts};
pub use connection::{ZeroKMSConnection, ZeroKMSConnectionInit};
// Transport-independent response classification, shared by `HttpConnection`
// and by hosts that bring their own transport (the WASI guest).
pub use connection::{
    classify_response, is_json_content_type, BaseUrlUnresolved, FailureResponse,
    UnexpectedContentType,
};
pub use endpoint::{InvalidEndpoint, ZeroKmsEndpoint};

// The native/wasm32 Send split for the async traits' returned futures
pub use maybe_send::MaybeSend;

// Errors
pub use errors::{
    Error, GenerateKeyError, InvalidKeyMaterialError, LoadKeysetError, RetrieveKeyError,
};

// Key material
pub use key::{ClientKey, DataKey, DataKeyWithTag, IndexKey, V1KeySet};

// Key source abstractions (production = `StackKms`; tests = `FakeDataKeySource`)
#[cfg(feature = "test-support")]
pub use key_source::FakeDataKeySource;
pub use key_source::{DataKeySource, IndexKeySource};

// Key providers
pub use key_provider::{
    EnvKeyProvider, FallbackKeyProvider, KeyProvider, KeyProviderError, StaticKeyProvider,
};
pub use secret_key::SecretKey;
// `KeyProvider` is implemented for `ProfileStore` (the CLI's on-disk profile),
// so callers need to be able to name it without depending on `stack-profile`.
#[cfg(all(feature = "profile", not(target_arch = "wasm32")))]
pub use stack_profile::ProfileStore;

// Operation payloads
pub use payload::{GenerateKeyPayload, RetrieveKeyPayload};

// Commonly needed re-exports from the protocol / crypto layers
pub use recipher::key::{GenRandom, Iv};
pub use zerokms_protocol::{
    Context, DecryptionPolicy, IdentifiedBy, KeyId, Keyset, UnverifiedContext, ViturKeyMaterial,
    MAX_DESCRIPTOR_LEN,
};

/// Process-wide environment guard for tests that set or clear env vars.
///
/// `cargo nextest` runs each test in its own process, but plain `cargo test`
/// runs them as threads of one process, so env-mutating tests serialise on a
/// global lock and restore the prior values on drop.
#[cfg(test)]
pub(crate) mod test_env {
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    pub(crate) struct ScopedEnv {
        previous: Vec<(&'static str, Option<String>)>,
        _guard: MutexGuard<'static, ()>,
    }

    impl ScopedEnv {
        /// Lock the environment, then set (`Some`) or clear (`None`) each
        /// variable for the lifetime of the returned guard.
        pub(crate) fn new(vars: &[(&'static str, Option<&str>)]) -> Self {
            let guard = ENV_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let previous = vars
                .iter()
                .map(|(name, value)| {
                    let prior = std::env::var(name).ok();
                    match value {
                        Some(v) => std::env::set_var(name, v),
                        None => std::env::remove_var(name),
                    }
                    (*name, prior)
                })
                .collect();
            Self {
                previous,
                _guard: guard,
            }
        }
    }

    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            for (name, prior) in self.previous.drain(..) {
                match prior {
                    Some(v) => std::env::set_var(name, v),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}
