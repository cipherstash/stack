use crate::client::{
    ClientOpts, InvalidClientOpts, StackKms, DEFAULT_CONCURRENT_REQS, DEFAULT_KEYS_PER_REQ,
};
use crate::connection::HttpConnectionOpts;
use crate::endpoint::{InvalidEndpoint, ZeroKmsEndpoint};
use crate::key::ClientKey;
use crate::key_provider::{KeyProvider, KeyProviderError};
use stack_auth::{AuthStrategy, AuthStrategyBounds};
use thiserror::Error;

/// Error type for [`StackKmsBuilder`] operations.
///
/// The variants that carry another error from this crate or `stack-auth`
/// are diagnostic-transparent: their code and help are that error's.
#[derive(Debug, Error, miette::Diagnostic)]
pub enum StackKmsBuilderError {
    /// Failed to initialize the underlying client.
    #[error("Failed to initialize client: {0}")]
    #[diagnostic(transparent)]
    ClientInit(#[from] crate::errors::Error),

    /// Authentication strategy failed to initialize.
    #[error("Auth strategy error: {0}")]
    #[diagnostic(transparent)]
    Auth(#[from] stack_auth::AuthError),

    /// Key provider failed to load a client key.
    #[error("Key provider error: {0}")]
    #[diagnostic(transparent)]
    KeyProvider(#[from] KeyProviderError),

    /// A builder option was set to an invalid value (e.g. a zero concurrency
    /// or keys-per-request limit).
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidConfig(#[from] InvalidClientOpts),

    /// The ZeroKMS endpoint in the named environment variable is not usable.
    /// Unlike a missing variable this is not skipped: falling through to the
    /// token's `services` claim would silently send key operations somewhere
    /// the operator did not configure.
    #[error("Invalid ZeroKMS endpoint in {env_var}: {source}")]
    #[diagnostic(
        code(stack_kms::invalid_endpoint),
        help("Set {env_var} to an `http://` or `https://` URL with a host and no query, or unset it to use the endpoint the token names.")
    )]
    InvalidEndpoint {
        env_var: &'static str,
        #[source]
        #[diagnostic_source]
        source: InvalidEndpoint,
    },
}

impl stack_auth::ErrorPayload for StackKmsBuilderError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            Self::ClientInit(error) => error.payload(),
            Self::Auth(error) => error.payload(),
            Self::KeyProvider(_) | Self::InvalidConfig(_) => serde_json::Map::new(),
            Self::InvalidEndpoint { env_var, .. } => {
                stack_auth::diagnostic::payload([("env_var", (*env_var).into())])
            }
        }
    }
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
/// 1. Explicit [`ZeroKmsEndpoint`] via [`with_base_url`](Self::with_base_url)
/// 2. `CS_ZEROKMS_HOST` (or legacy `CS_VITUR_HOST`) environment variable —
///    the first one that is *set* is used, and an invalid value is an error
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
    connection: HttpConnectionOpts,
    max_keys_per_req: usize,
    max_concurrent_reqs: usize,
    client_key: ClientKeyState,
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
            connection: HttpConnectionOpts::new(None),
            max_keys_per_req: DEFAULT_KEYS_PER_REQ,
            max_concurrent_reqs: DEFAULT_CONCURRENT_REQS,
            client_key: (),
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
            connection: self.connection,
            max_keys_per_req: self.max_keys_per_req,
            max_concurrent_reqs: self.max_concurrent_reqs,
            client_key: WithKeyProvider(provider),
        }
    }

    /// Add a client key directly.
    pub fn with_client_key(self, client_key: ClientKey) -> StackKmsBuilder<C, ClientKey> {
        StackKmsBuilder {
            credentials: self.credentials,
            connection: self.connection,
            max_keys_per_req: self.max_keys_per_req,
            max_concurrent_reqs: self.max_concurrent_reqs,
            client_key,
        }
    }
}

// Configuration setters live on the state-agnostic impl so they can be called
// in any order relative to `with_client_key`/`with_key_provider` — chaining a
// setter *after* the key would otherwise fail to compile.
//
// The transport knobs delegate to `HttpConnectionOpts` (which documents each
// one, including the wasm32 caveats) rather than duplicating its fields here.
impl<C, S> StackKmsBuilder<C, S> {
    /// Set the **total request timeout** in seconds. Defaults to 10 seconds.
    /// See [`HttpConnectionOpts::with_request_timeout`].
    pub fn with_request_timeout(mut self, timeout_secs: u64) -> Self {
        self.connection = self.connection.with_request_timeout(timeout_secs);
        self
    }

    /// Set the **connect timeout** in seconds (TCP connect + TLS handshake only).
    /// See [`HttpConnectionOpts::with_connect_timeout`].
    pub fn with_connect_timeout(mut self, timeout_secs: u64) -> Self {
        self.connection = self.connection.with_connect_timeout(timeout_secs);
        self
    }

    /// Set the **pool idle timeout** in seconds.
    /// See [`HttpConnectionOpts::with_pool_idle_timeout`].
    pub fn with_pool_idle_timeout(mut self, timeout_secs: u64) -> Self {
        self.connection = self.connection.with_pool_idle_timeout(timeout_secs);
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

    /// Pin the ZeroKMS endpoint, bypassing both the environment and the
    /// token's `services` claim.
    ///
    /// Takes an already-validated [`ZeroKmsEndpoint`] (parse one with
    /// `"https://…".parse()?`), so a bad URL is rejected where it is written
    /// rather than on the first request.
    pub fn with_base_url(mut self, base_url: ZeroKmsEndpoint) -> Self {
        self.connection = self.connection.with_base_url(base_url);
        self
    }

    fn build_opts(self) -> Result<(ClientOpts<HttpConnectionOpts>, C, S), StackKmsBuilderError> {
        let mut connection = self.connection;
        if connection.base_url().is_none() {
            if let Some(endpoint) = Self::base_url_from_env()? {
                connection = connection.with_base_url(endpoint);
            }
        }

        // `ClientOpts` rejects degenerate limits (0 keys-per-req would panic
        // `slice::chunks`; 0 concurrent-reqs would leave the request stream
        // pending forever) so they never reach `map_async_chunked`.
        let opts = ClientOpts::new(connection)
            .with_max_keys_per_req(self.max_keys_per_req)?
            .with_max_concurrent_reqs(self.max_concurrent_reqs)?;

        Ok((opts, self.credentials, self.client_key))
    }

    /// Resolve the ZeroKMS endpoint from the `CS_ZEROKMS_HOST` environment
    /// variable (or legacy `CS_VITUR_HOST`). The first variable that is set
    /// decides: an unusable value is an error, not a fall-through.
    fn base_url_from_env() -> Result<Option<ZeroKmsEndpoint>, StackKmsBuilderError> {
        use crate::vars::CS_ZEROKMS_HOST;

        for env_var in CS_ZEROKMS_HOST {
            if let Ok(value) = std::env::var(env_var) {
                return value
                    .parse()
                    .map(Some)
                    .map_err(|source| StackKmsBuilderError::InvalidEndpoint { env_var, source });
            }
        }

        Ok(None)
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

        fn from_env() -> Result<Option<ZeroKmsEndpoint>, StackKmsBuilderError> {
            StackKmsBuilder::<NeverStrategy>::base_url_from_env()
        }

        #[test]
        fn the_primary_variable_is_listed_first() {
            assert_eq!(crate::vars::CS_ZEROKMS_HOST, &[PRIMARY, LEGACY]);
        }

        #[test]
        fn returns_none_when_neither_variable_is_set() {
            let _env = ScopedEnv::new(&[(PRIMARY, None), (LEGACY, None)]);
            assert!(from_env().unwrap().is_none());
        }

        #[test]
        fn parses_the_primary_variable() {
            let _env = ScopedEnv::new(&[
                (PRIMARY, Some("https://primary.example")),
                (LEGACY, Some("https://legacy.example")),
            ]);
            let url = from_env().unwrap().unwrap();
            assert_eq!(url.as_str(), "https://primary.example/");
        }

        #[test]
        fn falls_back_to_the_legacy_variable() {
            let _env = ScopedEnv::new(&[(PRIMARY, None), (LEGACY, Some("https://legacy.example"))]);
            let url = from_env().unwrap().unwrap();
            assert_eq!(url.as_str(), "https://legacy.example/");
        }

        #[test]
        fn an_invalid_primary_is_an_error_even_when_the_legacy_variable_is_valid() {
            let _env = ScopedEnv::new(&[
                (PRIMARY, Some("not a url")),
                (LEGACY, Some("https://legacy.example")),
            ]);
            let err = from_env().unwrap_err();
            assert!(
                matches!(
                    &err,
                    StackKmsBuilderError::InvalidEndpoint { env_var, source: InvalidEndpoint::Parse(_) }
                        if *env_var == PRIMARY
                ),
                "got: {err:?}"
            );
            assert!(err.to_string().contains(PRIMARY), "{err}");
        }

        #[test]
        fn a_scheme_less_host_and_port_is_rejected_naming_the_variable() {
            // `Url::parse` accepts `localhost:3002` (scheme `localhost`), so
            // without endpoint validation this would build and then fail every
            // request with an opaque "Failed to construct request URL".
            let _env = ScopedEnv::new(&[(PRIMARY, Some("localhost:3002")), (LEGACY, None)]);
            let err = from_env().unwrap_err();
            assert!(
                matches!(
                    &err,
                    StackKmsBuilderError::InvalidEndpoint { env_var, source: InvalidEndpoint::NoHost(_) }
                        if *env_var == PRIMARY
                ),
                "got: {err:?}"
            );
        }

        #[test]
        fn an_invalid_endpoint_fails_build() {
            let _env = ScopedEnv::new(&[(PRIMARY, Some("localhost:3002")), (LEGACY, None)]);
            let err = builder()
                .with_client_key(random_client_key())
                .build()
                .err()
                .expect("an invalid env endpoint must fail build");
            assert!(
                matches!(err, StackKmsBuilderError::InvalidEndpoint { .. }),
                "got: {err:?}"
            );
        }

        #[test]
        fn an_explicit_endpoint_takes_precedence_and_the_env_is_not_consulted() {
            let _env = ScopedEnv::new(&[(PRIMARY, Some("not a url")), (LEGACY, None)]);
            builder()
                .with_base_url("https://explicit.example".parse().unwrap())
                .with_client_key(random_client_key())
                .build()
                .expect("an explicit endpoint must not be overridden by a bad env value");
        }
    }
}
