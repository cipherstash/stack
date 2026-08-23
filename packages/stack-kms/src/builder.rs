use crate::client::{
    ClientOpts, InvalidClientOpts, StackKms, DEFAULT_CONCURRENT_REQS, DEFAULT_KEYS_PER_REQ,
};
use crate::connection::HttpConnectionOpts;
use crate::key::ClientKey;
use crate::key_provider::{KeyProvider, KeyProviderError};
use stack_auth::{AuthStrategy, AuthStrategyBounds};
use thiserror::Error;
use url::Url;

/// Error type for [`StackKmsBuilder`] operations.
#[derive(Debug, Error, miette::Diagnostic)]
pub enum StackKmsBuilderError {
    /// Failed to initialize the underlying client.
    #[error("Failed to initialize client: {0}")]
    ClientInit(#[from] crate::errors::Error),

    /// Authentication strategy failed to initialize.
    #[error("Auth strategy error: {0}")]
    Auth(#[from] stack_auth::AuthError),

    /// Key provider failed to load a client key.
    #[error("Key provider error: {0}")]
    KeyProvider(#[from] KeyProviderError),

    /// A builder option was set to an invalid value (e.g. a zero concurrency
    /// or keys-per-request limit).
    #[error(transparent)]
    InvalidConfig(#[from] InvalidClientOpts),
}

/// A builder for creating [`StackKms`] clients.
///
/// A [`ClientKey`] is **required** — key generation and retrieval can't happen
/// without one — so the terminal [`build`](Self::build) only exists once a key
/// (via [`with_client_key`](Self::with_client_key)) or a
/// [`KeyProvider`](crate::KeyProvider) (via
/// [`with_key_provider`](Self::with_key_provider)) has been supplied.
///
/// The ZeroKMS endpoint is resolved in this order:
/// 1. Explicit URL via [`with_base_url`](Self::with_base_url)
/// 2. `CS_ZEROKMS_HOST` (or legacy `CS_VITUR_HOST`) environment variable
/// 3. Automatically from the token's `services` claim
///
/// # Example
///
/// ```no_run
/// use stack_kms::{StackKmsBuilder, ClientKey};
/// use stack_auth::AutoStrategy;
/// use uuid::Uuid;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let strategy = AutoStrategy::detect()?;
/// let client_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?;
/// let client_key = ClientKey::from_hex_v1(client_id, "a4627031...")?;
///
/// let kms = StackKmsBuilder::new(strategy)
///     .with_client_key(client_key)
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct StackKmsBuilder<C, ClientKeyState = ()> {
    credentials: C,
    request_timeout: Option<u64>,
    connect_timeout: Option<u64>,
    pool_idle_timeout: Option<u64>,
    max_keys_per_req: usize,
    max_concurrent_reqs: usize,
    client_key: ClientKeyState,
    base_url_override: Option<Url>,
}

impl StackKmsBuilder<stack_auth::AutoStrategy, ()> {
    /// Create a [`StackKmsBuilder`] that automatically detects credentials from the environment.
    ///
    /// ```no_run
    /// use stack_kms::StackKmsBuilder;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let builder = StackKmsBuilder::auto()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn auto() -> Result<Self, StackKmsBuilderError> {
        let strategy = stack_auth::AutoStrategy::detect()?;
        Ok(Self::new(strategy))
    }
}

impl<C> StackKmsBuilder<C, ()>
where
    C: AuthStrategyBounds,
    for<'a> &'a C: AuthStrategy,
{
    /// Create a new [`StackKmsBuilder`].
    ///
    /// # Arguments
    ///
    /// * `credentials` - Credentials provider for obtaining access tokens
    pub fn new(credentials: C) -> Self {
        Self {
            credentials,
            request_timeout: None,
            connect_timeout: None,
            pool_idle_timeout: None,
            max_keys_per_req: DEFAULT_KEYS_PER_REQ,
            max_concurrent_reqs: DEFAULT_CONCURRENT_REQS,
            client_key: (),
            base_url_override: None,
        }
    }

    /// Add a [`KeyProvider`] to load a client key asynchronously at build time.
    ///
    /// This transforms the builder into one that builds via an async
    /// [`build()`](StackKmsBuilder::build) call.
    pub fn with_key_provider<K: KeyProvider>(
        self,
        provider: K,
    ) -> StackKmsBuilder<C, WithKeyProvider<K>> {
        StackKmsBuilder {
            credentials: self.credentials,
            request_timeout: self.request_timeout,
            connect_timeout: self.connect_timeout,
            pool_idle_timeout: self.pool_idle_timeout,
            max_keys_per_req: self.max_keys_per_req,
            max_concurrent_reqs: self.max_concurrent_reqs,
            client_key: WithKeyProvider(provider),
            base_url_override: self.base_url_override,
        }
    }

    /// Add a client key directly.
    pub fn with_client_key(self, client_key: ClientKey) -> StackKmsBuilder<C, ClientKey> {
        StackKmsBuilder {
            credentials: self.credentials,
            request_timeout: self.request_timeout,
            connect_timeout: self.connect_timeout,
            pool_idle_timeout: self.pool_idle_timeout,
            max_keys_per_req: self.max_keys_per_req,
            max_concurrent_reqs: self.max_concurrent_reqs,
            client_key,
            base_url_override: self.base_url_override,
        }
    }
}

// Configuration setters live on the state-agnostic impl so they can be called
// in any order relative to `with_client_key`/`with_key_provider` — chaining a
// setter *after* the key would otherwise fail to compile.
impl<C, S> StackKmsBuilder<C, S> {
    /// Set the **total request timeout** in seconds. Defaults to 10 seconds.
    pub fn with_request_timeout(mut self, timeout_secs: u64) -> Self {
        self.request_timeout = Some(timeout_secs);
        self
    }

    /// Set the **connect timeout** in seconds (TCP connect + TLS handshake only).
    pub fn with_connect_timeout(mut self, timeout_secs: u64) -> Self {
        self.connect_timeout = Some(timeout_secs);
        self
    }

    /// Set the **pool idle timeout** in seconds.
    pub fn with_pool_idle_timeout(mut self, timeout_secs: u64) -> Self {
        self.pool_idle_timeout = Some(timeout_secs);
        self
    }

    /// Set the maximum number of keys per request. Defaults to 500. Must be at
    /// least 1 (validated at [`build`](Self::build) time).
    pub fn with_max_keys_per_req(mut self, max_keys: usize) -> Self {
        self.max_keys_per_req = max_keys;
        self
    }

    /// Set the maximum number of concurrent requests. Defaults to 5. Must be at
    /// least 1 (validated at [`build`](Self::build) time).
    pub fn with_max_concurrent_reqs(mut self, max_concurrent: usize) -> Self {
        self.max_concurrent_reqs = max_concurrent;
        self
    }

    /// Override the base URL for the ZeroKMS service.
    ///
    /// This bypasses resolving the URL from the token's `services` claim and connects
    /// directly to the specified URL.
    pub fn with_base_url(mut self, base_url: Url) -> Self {
        self.base_url_override = Some(base_url);
        self
    }

    fn build_opts(self) -> Result<(ClientOpts<HttpConnectionOpts>, C, S), StackKmsBuilderError> {
        let base_url = self.base_url_override.or_else(Self::base_url_from_env);
        let mut connection_opts = HttpConnectionOpts::new(base_url);
        if let Some(timeout) = self.request_timeout {
            connection_opts = connection_opts.with_request_timeout(timeout);
        }
        if let Some(connect_timeout) = self.connect_timeout {
            connection_opts = connection_opts.with_connect_timeout(connect_timeout);
        }
        if let Some(pool_idle_timeout) = self.pool_idle_timeout {
            connection_opts = connection_opts.with_pool_idle_timeout(pool_idle_timeout);
        }

        // `ClientOpts` rejects degenerate limits (0 keys-per-req would panic
        // `slice::chunks`; 0 concurrent-reqs would leave the request stream
        // pending forever) so they never reach `map_async_chunked`.
        let opts = ClientOpts::new(connection_opts)
            .with_max_keys_per_req(self.max_keys_per_req)?
            .with_max_concurrent_reqs(self.max_concurrent_reqs)?;

        Ok((opts, self.credentials, self.client_key))
    }

    /// Resolve the ZeroKMS base URL from the `CS_ZEROKMS_HOST` environment
    /// variable (or legacy `CS_VITUR_HOST`).
    fn base_url_from_env() -> Option<Url> {
        use crate::vars::CS_ZEROKMS_HOST;

        for name in CS_ZEROKMS_HOST {
            if let Ok(value) = std::env::var(name) {
                match value.parse() {
                    Ok(url) => return Some(url),
                    Err(err) => {
                        tracing::warn!(
                            target: "stack_kms",
                            %err,
                            env_var = name,
                            "Ignoring invalid URL in environment variable"
                        );
                    }
                }
            }
        }

        None
    }
}

impl<C> StackKmsBuilder<C, ClientKey>
where
    C: AuthStrategyBounds,
    for<'a> &'a C: AuthStrategy,
{
    /// Build a [`StackKms`] client.
    pub fn build(self) -> Result<StackKms<C>, StackKmsBuilderError> {
        let (opts, credentials, client_key) = self.build_opts()?;
        Ok(StackKms::connect(opts, credentials, client_key)?)
    }
}

/// Newtype wrapper that marks a [`KeyProvider`] in the builder's type state.
///
/// This avoids coherence issues — [`ClientKey`] does not implement [`KeyProvider`],
/// and `WithKeyProvider` keeps the two `build()` signatures unambiguous.
pub struct WithKeyProvider<K: KeyProvider>(K);

impl<C, K> StackKmsBuilder<C, WithKeyProvider<K>>
where
    C: AuthStrategyBounds,
    for<'a> &'a C: AuthStrategy,
    K: KeyProvider,
{
    /// Build a [`StackKms`] client by loading the key from the provider.
    ///
    /// This is an async method because the key provider may need to perform I/O.
    pub async fn build(self) -> Result<StackKms<C>, StackKmsBuilderError> {
        let (opts, credentials, provider) = self.build_opts()?;
        let client_key = provider.0.client_key().await?;
        Ok(StackKms::connect(opts, credentials, client_key)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::ScopedEnv;
    use stack_auth::{AuthError, AuthStrategyFn, ServiceToken};

    type NeverStrategy =
        AuthStrategyFn<fn() -> std::future::Ready<Result<ServiceToken, AuthError>>>;

    fn never_get_token() -> std::future::Ready<Result<ServiceToken, AuthError>> {
        unreachable!("builder tests never fetch a token")
    }

    fn builder() -> StackKmsBuilder<NeverStrategy, ()> {
        StackKmsBuilder::new(AuthStrategyFn::new(never_get_token as fn() -> _))
    }

    fn random_client_key() -> ClientKey {
        use recipher::keyset::{EncryptionKeySet, ProxyKeySet};
        let ek_a = EncryptionKeySet::generate().unwrap();
        let ek_b = EncryptionKeySet::generate().unwrap();
        ClientKey::new_v1(uuid::Uuid::new_v4(), ProxyKeySet::generate(&ek_a, &ek_b))
    }

    mod invalid_config {
        use super::*;

        #[test]
        fn rejects_zero_max_keys_per_req() {
            let err = builder()
                .with_max_keys_per_req(0)
                .with_client_key(random_client_key())
                .build()
                .err()
                .expect("zero keys-per-req must be rejected");
            assert!(
                matches!(err, StackKmsBuilderError::InvalidConfig(_)),
                "expected InvalidConfig, got: {err:?}"
            );
            assert!(err.to_string().contains("max_keys_per_req"), "{err}");
        }

        #[test]
        fn rejects_zero_max_concurrent_reqs() {
            let err = builder()
                .with_max_concurrent_reqs(0)
                .with_client_key(random_client_key())
                .build()
                .err()
                .expect("zero concurrent-reqs must be rejected");
            assert!(
                matches!(err, StackKmsBuilderError::InvalidConfig(_)),
                "expected InvalidConfig, got: {err:?}"
            );
            assert!(err.to_string().contains("max_concurrent_reqs"), "{err}");
        }

        #[test]
        fn accepts_the_defaults() {
            builder()
                .with_client_key(random_client_key())
                .build()
                .expect("default limits are valid");
        }
    }

    mod base_url_from_env {
        use super::*;

        // Pinned by name rather than read from `vars::CS_ZEROKMS_HOST` so a
        // reordering of that list (which changes precedence) fails these tests.
        const PRIMARY: &str = "CS_ZEROKMS_HOST";
        const LEGACY: &str = "CS_VITUR_HOST";

        #[test]
        fn the_primary_variable_is_listed_first() {
            assert_eq!(crate::vars::CS_ZEROKMS_HOST, &[PRIMARY, LEGACY]);
        }

        #[test]
        fn returns_none_when_neither_variable_is_set() {
            let _env = ScopedEnv::new(&[(PRIMARY, None), (LEGACY, None)]);
            assert!(StackKmsBuilder::<NeverStrategy>::base_url_from_env().is_none());
        }

        #[test]
        fn parses_the_primary_variable() {
            let _env = ScopedEnv::new(&[
                (PRIMARY, Some("https://primary.example")),
                (LEGACY, Some("https://legacy.example")),
            ]);
            let url = StackKmsBuilder::<NeverStrategy>::base_url_from_env().unwrap();
            assert_eq!(url.as_str(), "https://primary.example/");
        }

        #[test]
        fn falls_back_to_the_legacy_variable() {
            let _env = ScopedEnv::new(&[(PRIMARY, None), (LEGACY, Some("https://legacy.example"))]);
            let url = StackKmsBuilder::<NeverStrategy>::base_url_from_env().unwrap();
            assert_eq!(url.as_str(), "https://legacy.example/");
        }

        #[test]
        fn skips_an_invalid_primary_and_uses_the_legacy_variable() {
            let _env = ScopedEnv::new(&[
                (PRIMARY, Some("not a url")),
                (LEGACY, Some("https://legacy.example")),
            ]);
            let url = StackKmsBuilder::<NeverStrategy>::base_url_from_env().unwrap();
            assert_eq!(url.as_str(), "https://legacy.example/");
        }

        #[test]
        fn returns_none_when_every_candidate_is_invalid() {
            let _env = ScopedEnv::new(&[(PRIMARY, Some("not a url")), (LEGACY, Some("also not"))]);
            assert!(StackKmsBuilder::<NeverStrategy>::base_url_from_env().is_none());
        }
    }
}
