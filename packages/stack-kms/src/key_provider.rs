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
//! | `ProfileKeyProvider` | `secretkey.json` in the CLI's profile directory, for one workspace. Native targets with the `profile` feature. |
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
///
/// The strings are written by this crate and never hold key material: a
/// decoding failure names the encoding, not the bytes it refused.
#[derive(Debug, Error, miette::Diagnostic)]
pub enum KeyProviderError {
    /// The provider has no key configured (e.g. env vars not set).
    ///
    /// [`FallbackKeyProvider`] uses this variant to decide whether to try the next provider.
    #[error("Client key not configured: {0}")]
    #[diagnostic(
        code(stack_kms::client_key_not_configured),
        help("Set `CS_CLIENT_ID` and `CS_CLIENT_KEY`, or log in with `stash auth login`.")
    )]
    NotConfigured(String),

    /// Key material was found but is invalid (e.g. bad hex encoding).
    #[error("Invalid client key: {0}")]
    #[diagnostic(
        code(stack_kms::invalid_client_key),
        help("`CS_CLIENT_KEY` is a hex or base64 client key, and `CS_CLIENT_ID` the UUID of the client it belongs to.")
    )]
    InvalidKey(String),

    /// An I/O or other runtime error prevented loading the key.
    #[error("Failed to load client key: {0}")]
    #[diagnostic(code(stack_kms::client_key_load))]
    LoadError(String),
}

impl stack_auth::ErrorPayload for KeyProviderError {}

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

/// Loads a [`ClientKey`] from `secretkey.json` in the CLI's profile
/// directory.
///
/// `npx stash auth login` writes one `secretkey.json` for each workspace.
/// The profile directory is `~/.cipherstash`, unless `CS_CONFIG_PATH` names
/// another. Choose the workspace with a constructor:
///
/// - [`for_workspace`](Self::for_workspace) reads the key of the workspace
///   you name.
/// - [`for_detected_workspace`](Self::for_detected_workspace) reads the key
///   of the workspace this process is configured for.
///
/// Read the client key from the same workspace as the auth strategy's
/// tokens. ZeroKMS refuses a request whose token and client key come from
/// different workspaces.
///
/// A workspace with no `secretkey.json` is
/// [`KeyProviderError::NotConfigured`], so the provider can be either side
/// of a [`FallbackKeyProvider`]. The provider never reads the key of another
/// workspace in its place.
///
/// # Example
///
/// ```no_run
/// use stack_kms::{EnvKeyProvider, FallbackKeyProvider, KeyProvider, ProfileKeyProvider};
///
/// # async fn example() -> Result<(), stack_kms::KeyProviderError> {
/// // Use `CS_CLIENT_ID` and `CS_CLIENT_KEY` if they are set. Otherwise use
/// // the key the CLI saved.
/// let provider =
///     FallbackKeyProvider::new(EnvKeyProvider, ProfileKeyProvider::for_detected_workspace());
/// let client_key = provider.client_key().await?;
/// # Ok(())
/// # }
/// ```
#[cfg(all(feature = "profile", not(target_arch = "wasm32")))]
pub struct ProfileKeyProvider {
    /// `None` when the profile directory could not be resolved.
    store: Option<stack_profile::ProfileStore>,
    workspace: ProfileWorkspace,
}

/// The workspace whose `secretkey.json` a [`ProfileKeyProvider`] reads.
#[cfg(all(feature = "profile", not(target_arch = "wasm32")))]
enum ProfileWorkspace {
    /// The workspace with this id.
    Id(String),
    /// The CLI's current workspace.
    Current,
    /// `CS_WORKSPACE_CRN` is set to a value that is not a CRN.
    InvalidCrn,
}

#[cfg(all(feature = "profile", not(target_arch = "wasm32")))]
impl ProfileKeyProvider {
    /// Reads the client key of the workspace `crn` names.
    pub fn for_workspace(crn: &stack_auth::Crn) -> Self {
        Self {
            store: stack_profile::ProfileStore::resolve(None).ok(),
            workspace: ProfileWorkspace::Id(crn.workspace_id.to_string()),
        }
    }

    /// Reads the client key of the workspace this process is configured
    /// for.
    ///
    /// The workspace is the one `CS_WORKSPACE_CRN` names, if that variable
    /// is set. Otherwise the workspace is the CLI's current workspace.
    /// `stack_auth::AutoStrategy::detect` and
    /// `stack_auth::OidcFederationStrategy::with_detected_workspace` choose
    /// the workspace the same way, so the key and the tokens come from one
    /// workspace.
    ///
    /// If `CS_WORKSPACE_CRN` is set to a value that is not a CRN,
    /// [`client_key`](KeyProvider::client_key) returns
    /// [`KeyProviderError::LoadError`].
    pub fn for_detected_workspace() -> Self {
        Self::detected(
            std::env::var(crate::vars::CS_WORKSPACE_CRN).ok().as_deref(),
            stack_profile::ProfileStore::resolve(None).ok(),
        )
    }

    /// Does the work of [`for_detected_workspace`](Self::for_detected_workspace)
    /// on a variable and a profile directory that are already read.
    fn detected(env_crn: Option<&str>, store: Option<stack_profile::ProfileStore>) -> Self {
        let workspace = match env_crn.map(str::parse::<stack_auth::Crn>) {
            Some(Ok(crn)) => ProfileWorkspace::Id(crn.workspace_id.to_string()),
            Some(Err(_)) => ProfileWorkspace::InvalidCrn,
            None => ProfileWorkspace::Current,
        };
        Self { store, workspace }
    }
}

#[cfg(all(feature = "profile", not(target_arch = "wasm32")))]
impl KeyProvider for ProfileKeyProvider {
    async fn client_key(&self) -> Result<ClientKey, KeyProviderError> {
        use crate::SecretKey;

        let Some(store) = &self.store else {
            return Err(KeyProviderError::NotConfigured(
                "no profile directory: run `npx stash auth login`".into(),
            ));
        };
        match &self.workspace {
            ProfileWorkspace::Id(workspace) => {
                let workspace_store = store
                    .workspace_store(workspace)
                    .map_err(|e| KeyProviderError::LoadError(e.to_string()))?;
                if !workspace_store.exists_profile::<SecretKey>() {
                    return Err(KeyProviderError::NotConfigured(format!(
                        "no client key for workspace {workspace}: run `npx stash auth login` for that workspace"
                    )));
                }
                let secret_key: SecretKey = workspace_store
                    .load_profile()
                    .map_err(|e| KeyProviderError::LoadError(e.to_string()))?;
                secret_key.client_key().await
            }
            ProfileWorkspace::Current => store.client_key().await,
            ProfileWorkspace::InvalidCrn => Err(KeyProviderError::LoadError(format!(
                "{} is not a workspace CRN",
                crate::vars::CS_WORKSPACE_CRN
            ))),
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

    #[cfg(all(feature = "profile", not(target_arch = "wasm32")))]
    mod profile_provider {
        use super::*;
        use crate::SecretKey;
        use stack_profile::ProfileStore;

        /// The CLI's current workspace in the profiles below.
        const CURRENT: &str = "ZVATKW3VHMFG27DY";
        /// Another workspace in the same profile.
        const OTHER: &str = "AAAAAAAAAAAAAAAA";
        const OTHER_CRN: &str = "crn:ap-southeast-2.aws:AAAAAAAAAAAAAAAA";

        /// A profile with the workspaces `OTHER` and `CURRENT`, where only
        /// `CURRENT` has a client key. Returns that key's client id.
        fn profile_with_a_key_in_the_current_workspace(
            dir: &std::path::Path,
        ) -> (ProfileStore, Uuid) {
            let store = ProfileStore::new(dir);
            store.init_workspace(OTHER).unwrap();
            store.init_workspace(CURRENT).unwrap(); // now current
            let client_key = random_client_key();
            let secret_key = SecretKey::from_hex(
                client_key.key_id.to_string(),
                client_key.to_hex_v1().unwrap(),
            )
            .unwrap();
            store
                .current_workspace_store()
                .unwrap()
                .save_profile(&secret_key)
                .unwrap();
            (store, client_key.key_id)
        }

        #[tokio::test]
        async fn a_named_workspace_never_uses_the_current_workspaces_key() {
            let dir = tempfile::tempdir().unwrap();
            let (store, _) = profile_with_a_key_in_the_current_workspace(dir.path());
            let provider = ProfileKeyProvider::detected(Some(OTHER_CRN), Some(store));

            let error = provider.client_key().await.map(|_| ()).unwrap_err();

            assert!(
                matches!(&error, KeyProviderError::NotConfigured(message) if message.contains(OTHER)),
                "expected NotConfigured naming the workspace, got {error:?}"
            );
        }

        #[tokio::test]
        async fn a_named_workspace_with_a_key_returns_it() {
            let dir = tempfile::tempdir().unwrap();
            let (store, client_id) = profile_with_a_key_in_the_current_workspace(dir.path());
            let crn = format!("crn:ap-southeast-2.aws:{CURRENT}");
            let provider = ProfileKeyProvider::detected(Some(&crn), Some(store));

            let key = provider.client_key().await.unwrap();

            assert_eq!(
                key.key_id, client_id,
                "the named workspace's key is returned"
            );
        }

        #[tokio::test]
        async fn without_the_variable_the_current_workspaces_key_is_returned() {
            let dir = tempfile::tempdir().unwrap();
            let (store, client_id) = profile_with_a_key_in_the_current_workspace(dir.path());
            let provider = ProfileKeyProvider::detected(None, Some(store));

            let key = provider.client_key().await.unwrap();

            assert_eq!(
                key.key_id, client_id,
                "the current workspace's key is returned"
            );
        }

        #[tokio::test]
        async fn a_variable_that_is_not_a_crn_is_a_load_error() {
            let dir = tempfile::tempdir().unwrap();
            let (store, _) = profile_with_a_key_in_the_current_workspace(dir.path());
            let provider = ProfileKeyProvider::detected(Some("not-a-crn"), Some(store));

            let error = provider.client_key().await.map(|_| ()).unwrap_err();

            assert!(
                matches!(&error, KeyProviderError::LoadError(message) if message.contains("CS_WORKSPACE_CRN")),
                "the current workspace's key must not be used, got {error:?}"
            );
        }

        #[tokio::test]
        async fn no_profile_directory_is_not_configured() {
            let provider = ProfileKeyProvider::detected(None, None);

            let error = provider.client_key().await.map(|_| ()).unwrap_err();

            assert!(
                matches!(error, KeyProviderError::NotConfigured(_)),
                "expected NotConfigured, got {error:?}"
            );
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
