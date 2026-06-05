#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
//! `stack-kms` is a focused client for ZeroKMS **data key** operations:
//! generating new data keys and retrieving existing ones.
//!
//! It is an extraction of the key-generation/retrieval slice of
//! `cipherstash-client`'s `zerokms` module into a standalone crate. This first
//! cut deliberately covers only the two operations:
//!
//! * [`StackKms::generate_keys`] — derive fresh data keys (with tags) from ZeroKMS
//! * [`StackKms::retrieve_keys`] / [`StackKms::retrieve_keys_fallible`] — re-derive
//!   data keys for previously encrypted records
//!
//! Encryption/decryption, keyset and client management, and config save/load
//! all remain in `cipherstash-client` for now.
//!
//! # Quick start
//!
//! ```no_run
//! use stack_kms::{StackKmsBuilder, GenerateKeyPayload};
//! use std::borrow::Cow;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Credentials + client key are discovered from the environment:
//! //   CS_CLIENT_ID / CS_CLIENT_KEY for the key, AutoStrategy for the token.
//! let kms = StackKmsBuilder::auto()?
//!     .with_key_provider(stack_kms::EnvKeyProvider)
//!     .build()
//!     .await?;
//!
//! let keys = kms
//!     .generate_keys(
//!         [GenerateKeyPayload::new("users/email", Cow::Owned(vec![]))],
//!         None,
//!         None,
//!     )
//!     .await?;
//!
//! assert_eq!(keys.len(), 1);
//! # Ok(())
//! # }
//! ```

mod builder;
mod client;
mod connection;
mod errors;
mod futures;
mod key;
mod key_provider;
mod payload;
mod secret_key;
mod user_agent;
pub mod vars;

// Builder
pub use builder::{StackKmsBuilder, StackKmsBuilderError, WithKeyProvider};

// Clients
pub use client::{Client, ClientOpts, FallibleDataKeyVec, StackKms};

// Transport
pub use connection::{
    ConnectionInitError, HttpConnection, HttpConnectionOpts, ZeroKMSConnection,
    ZeroKMSConnectionInit,
};

// Errors
pub use errors::{Error, GenerateKeyError, RetrieveKeyError};

// Key material
pub use key::{ClientKey, DataKey, DataKeyWithTag, V1KeySet};

// Key providers
pub use key_provider::{
    EnvKeyProvider, FallbackKeyProvider, KeyProvider, KeyProviderError, StaticKeyProvider,
};
pub use secret_key::SecretKey;

// Operation payloads
pub use payload::{GenerateKeyPayload, RetrieveKeyPayload};

// Commonly needed re-exports from the protocol / crypto layers
pub use recipher::key::{GenRandom, Iv};
pub use zerokms_protocol::{Context, DecryptionPolicy, KeyId, UnverifiedContext, ViturKeyMaterial};
