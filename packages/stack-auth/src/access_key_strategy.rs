use cts_common::{CtsServiceDiscovery, Region, ServiceDiscovery};

use crate::access_key::AccessKey;
use crate::access_key_refresher::AccessKeyRefresher;
use crate::auto_refresh::AutoRefresh;
use crate::token_store::{NoStore, TokenStore};
use crate::{ensure_trailing_slash, AuthError, AuthStrategy, SecretToken, ServiceToken};

/// An [`AuthStrategy`] that uses a static access key to authenticate.
///
/// The first call to [`get_token`](AuthStrategy::get_token) authenticates with
/// the server. Subsequent calls return the cached token until it expires, at
/// which point re-authentication happens automatically.
///
/// When constructed via [`AccessKeyStrategyBuilder::with_token_store`], the
/// strategy also persists tokens through an external [`TokenStore`] so that
/// short-lived strategy instances (e.g. one per Edge Function request) can
/// share a cache and avoid re-authenticating every cold start.
///
/// # Example
///
/// ```no_run
/// use stack_auth::{AccessKey, AccessKeyStrategy};
/// use cts_common::Region;
///
/// let region = Region::aws("ap-southeast-2").unwrap();
/// let key: AccessKey = "CSAKmyKeyId.myKeySecret".parse().unwrap();
/// let strategy = AccessKeyStrategy::new(region, key).unwrap();
/// ```
pub struct AccessKeyStrategy<S = NoStore> {
    inner: AutoRefresh<AccessKeyRefresher, S>,
}

impl AccessKeyStrategy {
    /// Create a new `AccessKeyStrategy` for the given region and access key.
    ///
    /// The auth endpoint is resolved automatically via service discovery.
    pub fn new(region: Region, access_key: AccessKey) -> Result<Self, AuthError> {
        Self::builder(region, access_key).build()
    }

    /// Return a builder for configuring an `AccessKeyStrategy` before construction.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use stack_auth::{AccessKey, AccessKeyStrategy};
    /// use cts_common::Region;
    ///
    /// let region = Region::aws("ap-southeast-2").unwrap();
    /// let key: AccessKey = "CSAKmyKeyId.myKeySecret".parse().unwrap();
    /// let strategy = AccessKeyStrategy::builder(region, key)
    ///     .audience("my-audience")
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder(region: Region, access_key: AccessKey) -> AccessKeyStrategyBuilder {
        AccessKeyStrategyBuilder {
            region,
            access_key: access_key.into_secret_token(),
            audience: None,
            base_url_override: None,
            token_store: NoStore,
        }
    }
}

impl<S: TokenStore> AuthStrategy for &AccessKeyStrategy<S> {
    async fn get_token(self) -> Result<ServiceToken, AuthError> {
        Ok(self.inner.get_token().await?)
    }
}

/// Builder for [`AccessKeyStrategy`].
///
/// Created via [`AccessKeyStrategy::builder`].
pub struct AccessKeyStrategyBuilder<S = NoStore> {
    region: Region,
    access_key: SecretToken,
    audience: Option<String>,
    base_url_override: Option<url::Url>,
    token_store: S,
}

impl<S> AccessKeyStrategyBuilder<S> {
    /// Set the audience for token requests.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Override the base URL resolved by service discovery.
    ///
    /// Useful for pointing at a local or mock auth server during testing.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn base_url(mut self, url: url::Url) -> Self {
        self.base_url_override = Some(url);
        self
    }

    /// Wire an external [`TokenStore`] into the strategy.
    ///
    /// On every call to [`get_token`](AuthStrategy::get_token), if no token is
    /// cached in memory, the store is consulted before falling back to
    /// re-authenticating with the access key. After every successful refresh
    /// or initial auth, the new token is written back to the store. Use this
    /// from short-lived strategy instances (Edge Functions, Workers, proxy
    /// worker pools) to share a service-token cache across processes.
    ///
    /// Returns a new builder with the store type erased into the chain — see
    /// [`InMemoryTokenStore`](crate::InMemoryTokenStore) and
    /// [`CallbackTokenStore`](crate::CallbackTokenStore) for ready-made
    /// implementations.
    pub fn with_token_store<T: TokenStore>(self, store: T) -> AccessKeyStrategyBuilder<T> {
        AccessKeyStrategyBuilder {
            region: self.region,
            access_key: self.access_key,
            audience: self.audience,
            base_url_override: self.base_url_override,
            token_store: store,
        }
    }
}

impl<S: TokenStore> AccessKeyStrategyBuilder<S> {
    /// Build the [`AccessKeyStrategy`].
    ///
    /// Resolves the base URL via service discovery unless overridden with
    /// `base_url` (available when the `test-utils` feature is enabled).
    pub fn build(self) -> Result<AccessKeyStrategy<S>, AuthError> {
        let base_url = match self.base_url_override {
            Some(url) => url,
            None => crate::cts_base_url_from_env()?
                .unwrap_or(CtsServiceDiscovery::endpoint(self.region)?),
        };
        let refresher = AccessKeyRefresher::new(
            self.access_key,
            ensure_trailing_slash(base_url),
            self.audience,
        );
        Ok(AccessKeyStrategy {
            inner: AutoRefresh::with_store(refresher, self.token_store),
        })
    }
}
