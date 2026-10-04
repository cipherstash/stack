//! Trait and implementations for loading a [`ClientKey`] from various sources.
//!
//! A [`KeyProvider`] is the single required input when building a key client that needs
//! to generate or retrieve data keys. Each provider yields a complete [`ClientKey`]
//! (client ID + key material) from a self-contained source.
//!
//! # Built-in providers
//!
//! | Provider | Source |
//! |----------|--------|
//! | [`EnvKeyProvider`] | `CS_CLIENT_ID` + `CS_CLIENT_KEY` environment variables |
//! | [`StaticKeyProvider`] | Wraps a [`ClientKey`] directly |
//! | [`FallbackKeyProvider`] | Tries a primary provider, falls back on [`KeyProviderError::NotConfigured`] |
//!
//! # Example
//!
//! A common pattern is to check for explicit env vars, derive an `Option<SecretKey>`,
//! and fall back to [`EnvKeyProvider`] when they are absent:
//!
//! ```no_run
//! use stack_kms::{
//!     SecretKey, FallbackKeyProvider, EnvKeyProvider, KeyProvider,
//! };
//!
//! # async fn example() {
//! let explicit_key = SecretKey::from_env().expect("invalid key material in env");
//!
//! // If `explicit_key` is None the fallback provider kicks in.
//! let provider = FallbackKeyProvider::new(explicit_key, EnvKeyProvider);
//! let client_key = provider.client_key().await.unwrap();
//! # }
//! ```

use crate::vars::{CS_CLIENT_ID, CS_CLIENT_KEY};
use std::future::Future;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::key::ClientKey;
use crate::secret_key::decode_client_key_material;

/// Errors that can occur when loading a [`ClientKey`] from a [`KeyProvider`].
#[derive(Debug, Error)]
pub enum KeyProviderError {
    /// The provider has no key configured (e.g. env vars not set).
    ///
    /// [`FallbackKeyProvider`] uses this variant to decide whether to try the next provider.
    #[error("Client key not configured: {0}")]
    NotConfigured(String),

    /// Key material was found but is invalid (e.g. bad hex encoding).
    #[error("Invalid client key: {0}")]
    InvalidKey(String),

    /// An I/O or other runtime error prevented loading the key.
    #[error("Failed to load client key: {0}")]
    LoadError(String),
}

/// A source of [`ClientKey`] credentials for ZeroKMS.
///
/// Implementations must be `Send + Sync + 'static` so they can be stored in the builder
/// and used across async contexts.
///
/// # Example
///
/// ```
/// use stack_kms::{KeyProvider, KeyProviderError, ClientKey, StaticKeyProvider};
/// use uuid::Uuid;
///
/// # async fn example() -> Result<(), KeyProviderError> {
/// let client_key = ClientKey::from_hex_v1(
///     Uuid::nil(),
///     // ... hex-encoded key material
/// #   "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
/// ).unwrap();
///
/// let provider = StaticKeyProvider::new(client_key);
/// let key = provider.client_key().await?;
/// # Ok(())
/// # }
/// ```
pub trait KeyProvider: Send + Sync + 'static {
    /// Load a [`ClientKey`] from this provider.
    fn client_key(&self) -> impl Future<Output = Result<ClientKey, KeyProviderError>> + Send;
}

/// Loads a [`ClientKey`] from `CS_CLIENT_ID` and `CS_CLIENT_KEY` environment variables.
///
/// Returns [`KeyProviderError::NotConfigured`] if either variable is unset,
/// or [`KeyProviderError::InvalidKey`] if the values cannot be parsed.
///
/// # Example
///
/// ```no_run
/// use stack_kms::{EnvKeyProvider, KeyProvider};
///
/// # async fn example() {
/// let provider = EnvKeyProvider;
/// let key = provider.client_key().await.expect("env vars must be set");
/// # }
/// ```
pub struct EnvKeyProvider;

impl EnvKeyProvider {
    /// Parse `CS_CLIENT_ID` and `CS_CLIENT_KEY`. `CS_CLIENT_KEY` is decoded leniently:
    /// either hex (the historical format) or standard padded base64 (the form that
    /// `secretkey.json` writes to disk) is accepted.
    fn parse(client_id: &str, client_key: &str) -> Result<ClientKey, KeyProviderError> {
        let uuid = Uuid::parse_str(client_id)
            .map_err(|e| KeyProviderError::InvalidKey(format!("invalid {CS_CLIENT_ID}: {e}")))?;

        let mut bytes = decode_client_key_material(client_key)
            .map_err(|e| KeyProviderError::InvalidKey(format!("invalid {CS_CLIENT_KEY}: {e}")))?;

        let result = ClientKey::from_bytes(uuid, &bytes)
            .map_err(|e| KeyProviderError::InvalidKey(format!("invalid {CS_CLIENT_KEY}: {e}")));
        bytes.zeroize();
        result
    }
}

impl KeyProvider for EnvKeyProvider {
    async fn client_key(&self) -> Result<ClientKey, KeyProviderError> {
        let client_id = std::env::var(CS_CLIENT_ID).map_err(|_| {
            KeyProviderError::NotConfigured(format!("{CS_CLIENT_ID} environment variable not set"))
        })?;

        let mut client_key = std::env::var(CS_CLIENT_KEY).map_err(|_| {
            KeyProviderError::NotConfigured(format!("{CS_CLIENT_KEY} environment variable not set"))
        })?;

        tracing::debug!("loading client key from environment variables");
        let result = Self::parse(&client_id, &client_key);
        client_key.zeroize();
        result
    }
}

/// Wraps an existing [`ClientKey`] as a [`KeyProvider`].
///
/// Useful for tests or when the key is already available programmatically.
///
/// # Example
///
/// ```
/// use stack_kms::{StaticKeyProvider, KeyProvider, ClientKey};
/// use uuid::Uuid;
///
/// # async fn example() {
/// # let client_key = ClientKey::from_hex_v1(
/// #   Uuid::nil(),
/// #   "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
/// # ).unwrap();
/// let provider = StaticKeyProvider::new(client_key);
/// let key = provider.client_key().await.unwrap();
/// # }
/// ```
pub struct StaticKeyProvider(ClientKey);

impl StaticKeyProvider {
    /// Create a new [`StaticKeyProvider`] wrapping the given key.
    pub fn new(key: ClientKey) -> Self {
        Self(key)
    }
}

impl KeyProvider for StaticKeyProvider {
    async fn client_key(&self) -> Result<ClientKey, KeyProviderError> {
        Ok(self.0.clone())
    }
}

/// Wraps an `Option<T>` as a [`KeyProvider`].
///
/// - `Some(provider)` delegates to the inner provider.
/// - `None` returns [`KeyProviderError::NotConfigured`], which makes it compose
///   naturally with [`FallbackKeyProvider`] — a `None` primary triggers the fallback.
///
/// # Example
///
/// ```
/// use stack_kms::{
///     FallbackKeyProvider, StaticKeyProvider, KeyProvider, ClientKey,
/// };
/// use uuid::Uuid;
///
/// # async fn example() {
/// # let fallback_key = ClientKey::from_hex_v1(
/// #   Uuid::nil(),
/// #   "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
/// # ).unwrap();
/// // None means "no explicit key" — falls through to the profile store
/// let explicit_key: Option<StaticKeyProvider> = None;
/// let provider = FallbackKeyProvider::new(
///     explicit_key,
///     StaticKeyProvider::new(fallback_key),
/// );
/// let key = provider.client_key().await.unwrap();
/// # }
/// ```
impl<T: KeyProvider> KeyProvider for Option<T> {
    async fn client_key(&self) -> Result<ClientKey, KeyProviderError> {
        match self {
            Some(provider) => provider.client_key().await,
            None => Err(KeyProviderError::NotConfigured(
                "no explicit key provided".into(),
            )),
        }
    }
}

/// Tries a primary [`KeyProvider`], falling back to a secondary provider
/// when the primary returns [`KeyProviderError::NotConfigured`].
///
/// Other error variants ([`KeyProviderError::InvalidKey`], [`KeyProviderError::LoadError`])
/// are **not** retried — they indicate the provider was found but broken.
///
/// # Example
///
/// ```
/// use stack_kms::{
///     EnvKeyProvider, StaticKeyProvider, FallbackKeyProvider, KeyProvider, ClientKey,
/// };
/// use uuid::Uuid;
///
/// # async fn example() {
/// # let fallback_key = ClientKey::from_hex_v1(
/// #   Uuid::nil(),
/// #   "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
/// # ).unwrap();
/// // Try env vars first, fall back to a static key
/// let provider = FallbackKeyProvider::new(
///     EnvKeyProvider,
///     StaticKeyProvider::new(fallback_key),
/// );
/// let key = provider.client_key().await.unwrap();
/// # }
/// ```
pub struct FallbackKeyProvider<P, F> {
    primary: P,
    fallback: F,
}

impl<P: KeyProvider, F: KeyProvider> FallbackKeyProvider<P, F> {
    /// Create a new [`FallbackKeyProvider`] with the given primary and fallback providers.
    pub fn new(primary: P, fallback: F) -> Self {
        Self { primary, fallback }
    }
}

impl<P: KeyProvider, F: KeyProvider> KeyProvider for FallbackKeyProvider<P, F> {
    async fn client_key(&self) -> Result<ClientKey, KeyProviderError> {
        match self.primary.client_key().await {
            Ok(key) => {
                tracing::debug!("using primary key provider");
                Ok(key)
            }
            Err(KeyProviderError::NotConfigured(_)) => {
                tracing::debug!("primary key provider not configured, trying fallback");
                self.fallback.client_key().await
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use recipher::keyset::{EncryptionKeySet, ProxyKeySet};

    fn random_client_key() -> ClientKey {
        let ek_a = EncryptionKeySet::generate().unwrap();
        let ek_b = EncryptionKeySet::generate().unwrap();
        let keyset = ProxyKeySet::generate(&ek_a, &ek_b);
        ClientKey::new_v1(Uuid::new_v4(), keyset)
    }

    /// A [`KeyProvider`] that always returns [`KeyProviderError::NotConfigured`].
    struct NotConfiguredProvider;

    impl KeyProvider for NotConfiguredProvider {
        async fn client_key(&self) -> Result<ClientKey, KeyProviderError> {
            Err(KeyProviderError::NotConfigured("not configured".into()))
        }
    }

    /// A [`KeyProvider`] that always returns [`KeyProviderError::InvalidKey`].
    struct InvalidKeyProvider;

    impl KeyProvider for InvalidKeyProvider {
        async fn client_key(&self) -> Result<ClientKey, KeyProviderError> {
            Err(KeyProviderError::InvalidKey("bad key".into()))
        }
    }

    mod static_provider {
        use super::*;

        #[tokio::test]
        async fn returns_the_wrapped_key() {
            let expected_id = Uuid::new_v4();
            let ek_a = EncryptionKeySet::generate().unwrap();
            let ek_b = EncryptionKeySet::generate().unwrap();
            let keyset = ProxyKeySet::generate(&ek_a, &ek_b);
            let client_key = ClientKey::new_v1(expected_id, keyset);

            let provider = StaticKeyProvider::new(client_key);
            let result = provider.client_key().await.unwrap();

            assert_eq!(
                result.key_id, expected_id,
                "should return the same key_id that was provided"
            );
        }
    }

    mod env_provider_parse {
        use super::*;

        #[test]
        fn returns_client_key_for_valid_inputs() {
            let key = random_client_key();
            let uuid = key.key_id;
            let hex = key.to_hex_v1().unwrap();

            let result = EnvKeyProvider::parse(&uuid.to_string(), &hex).unwrap();

            assert_eq!(
                result.key_id, uuid,
                "parsed key should have the same client_id"
            );
        }

        mod given_invalid_uuid {
            use super::*;

            #[test]
            fn returns_invalid_key_error() {
                let err = EnvKeyProvider::parse("not-a-uuid", "deadbeef").unwrap_err();

                assert!(
                    matches!(err, KeyProviderError::InvalidKey(_)),
                    "expected InvalidKey for bad UUID, got: {err:?}"
                );
            }
        }

        mod given_valid_uuid_but_wrong_key_length {
            use super::*;

            #[test]
            fn returns_invalid_key_error() {
                let uuid = Uuid::new_v4();
                // Valid hex but too short to be a valid keyset
                let err = EnvKeyProvider::parse(&uuid.to_string(), "deadbeef").unwrap_err();

                assert!(
                    matches!(err, KeyProviderError::InvalidKey(_)),
                    "expected InvalidKey for truncated key material, got: {err:?}"
                );
            }
        }

        mod given_invalid_encoding {
            use super::*;

            #[test]
            fn returns_invalid_key_error() {
                let uuid = Uuid::new_v4();
                // `!!` is rejected by both hex and base64 decoders
                let err =
                    EnvKeyProvider::parse(&uuid.to_string(), "not-valid-anything!!").unwrap_err();

                assert!(
                    matches!(err, KeyProviderError::InvalidKey(_)),
                    "expected InvalidKey for unrecognised encoding, got: {err:?}"
                );
            }
        }

        mod given_base64_encoded_key {
            use super::*;
            use base64ct::Encoding;

            #[test]
            fn returns_client_key_matching_hex_form() {
                let key = random_client_key();
                let uuid = key.key_id;
                let hex = key.to_hex_v1().unwrap();
                let bytes = base16ct::mixed::decode_vec(&hex).unwrap();
                let b64 = base64ct::Base64::encode_string(&bytes);

                let from_b64 = EnvKeyProvider::parse(&uuid.to_string(), &b64).unwrap();

                assert_eq!(
                    from_b64.key_id, uuid,
                    "base64 input should decode to the same client_id"
                );
                assert_eq!(
                    from_b64.to_hex_v1().unwrap(),
                    hex,
                    "base64 input should decode to the same key material as hex"
                );
            }
        }
    }

    mod fallback_provider {
        use super::*;

        mod given_primary_succeeds {
            use super::*;

            #[tokio::test]
            async fn returns_primary_key() {
                let primary_key = random_client_key();
                let primary_id = primary_key.key_id;
                let fallback_key = random_client_key();

                let provider = FallbackKeyProvider::new(
                    StaticKeyProvider::new(primary_key),
                    StaticKeyProvider::new(fallback_key),
                );

                let result = provider.client_key().await.unwrap();

                assert_eq!(
                    result.key_id, primary_id,
                    "should return the primary provider's key"
                );
            }
        }

        mod given_primary_not_configured {
            use super::*;

            #[tokio::test]
            async fn returns_fallback_key() {
                let fallback_key = random_client_key();
                let fallback_id = fallback_key.key_id;

                let provider = FallbackKeyProvider::new(
                    NotConfiguredProvider,
                    StaticKeyProvider::new(fallback_key),
                );

                let result = provider.client_key().await.unwrap();

                assert_eq!(
                    result.key_id, fallback_id,
                    "should fall through to the secondary provider"
                );
            }
        }

        mod given_primary_returns_invalid_key {
            use super::*;

            #[tokio::test]
            async fn does_not_fall_through() {
                let fallback_key = random_client_key();

                let provider = FallbackKeyProvider::new(
                    InvalidKeyProvider,
                    StaticKeyProvider::new(fallback_key),
                );

                let err = provider.client_key().await.unwrap_err();

                assert!(
                    matches!(err, KeyProviderError::InvalidKey(_)),
                    "should propagate InvalidKey without trying fallback, got: {err:?}"
                );
            }
        }
    }

    mod option_provider {
        use super::*;

        #[tokio::test]
        async fn some_delegates_to_inner() {
            let key = random_client_key();
            let expected_id = key.key_id;
            let provider: Option<StaticKeyProvider> = Some(StaticKeyProvider::new(key));

            let result = provider.client_key().await.unwrap();

            assert_eq!(
                result.key_id, expected_id,
                "Some(provider) should delegate to the inner provider"
            );
        }

        #[tokio::test]
        async fn none_returns_not_configured() {
            let provider: Option<StaticKeyProvider> = None;

            let err = provider.client_key().await.unwrap_err();

            assert!(
                matches!(err, KeyProviderError::NotConfigured(_)),
                "None should return NotConfigured, got: {err:?}"
            );
        }

        #[tokio::test]
        async fn none_triggers_fallback() {
            let fallback_key = random_client_key();
            let fallback_id = fallback_key.key_id;

            let provider = FallbackKeyProvider::new(
                Option::<StaticKeyProvider>::None,
                StaticKeyProvider::new(fallback_key),
            );

            let result = provider.client_key().await.unwrap();

            assert_eq!(
                result.key_id, fallback_id,
                "None primary should trigger fallback"
            );
        }

        #[tokio::test]
        async fn some_prevents_fallback() {
            let primary_key = random_client_key();
            let primary_id = primary_key.key_id;
            let fallback_key = random_client_key();

            let provider = FallbackKeyProvider::new(
                Some(StaticKeyProvider::new(primary_key)),
                StaticKeyProvider::new(fallback_key),
            );

            let result = provider.client_key().await.unwrap();

            assert_eq!(
                result.key_id, primary_id,
                "Some primary should prevent fallback"
            );
        }
    }
}
