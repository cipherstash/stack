use cts_common::{Crn, CtsServiceDiscovery, Region, ServiceDiscovery};

use crate::access_key_refresher::AccessKeyRefresher;
use crate::auto_refresh::AutoRefresh;
use crate::{ensure_trailing_slash, AuthError, AuthStrategy, SecretToken};

/// An [`AuthStrategy`] that uses a static access key to authenticate.
///
/// The first call to [`get_token`](AuthStrategy::get_token) authenticates with
/// the server. Subsequent calls return the cached token until it expires, at
/// which point re-authentication happens automatically.
///
/// # Example
///
/// ```no_run
/// use stack_auth::{AccessKeyStrategy, SecretToken};
/// use cts_common::Region;
///
/// let region = Region::aws("ap-southeast-2").unwrap();
/// let strategy = AccessKeyStrategy::new(region, SecretToken::new("my-key")).unwrap();
/// ```
pub struct AccessKeyStrategy {
    crn: Option<Crn>,
    inner: AutoRefresh<AccessKeyRefresher>,
}

impl AccessKeyStrategy {
    /// Create a new `AccessKeyStrategy` for the given region and access key.
    ///
    /// The auth endpoint is resolved automatically via service discovery.
    pub fn new(region: Region, access_key: SecretToken) -> Result<Self, AuthError> {
        Self::builder(region, access_key).build()
    }

    /// Create a new `AccessKeyStrategy` for the given CRN and access key.
    ///
    /// The region is extracted from the CRN for service discovery.
    /// The full CRN is stored and available via [`workspace_crn`](Self::workspace_crn).
    pub fn new_with_crn(crn: Crn, access_key: SecretToken) -> Result<Self, AuthError> {
        Self::builder(crn.region, access_key).crn(crn).build()
    }

    /// Return a builder for configuring an `AccessKeyStrategy` before construction.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use stack_auth::{AccessKeyStrategy, SecretToken};
    /// use cts_common::Region;
    ///
    /// let region = Region::aws("ap-southeast-2").unwrap();
    /// let strategy = AccessKeyStrategy::builder(region, SecretToken::new("my-key"))
    ///     .audience("my-audience")
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder(region: Region, access_key: SecretToken) -> AccessKeyStrategyBuilder {
        AccessKeyStrategyBuilder {
            region,
            access_key,
            audience: None,
            base_url_override: None,
            crn: None,
        }
    }

    /// Return the workspace CRN, if one was provided at construction time.
    pub fn workspace_crn(&self) -> Option<&Crn> {
        self.crn.as_ref()
    }
}

impl AuthStrategy for &AccessKeyStrategy {
    async fn get_token(self) -> Result<SecretToken, AuthError> {
        Ok(self.inner.get_token().await?)
    }
}

/// Builder for [`AccessKeyStrategy`].
///
/// Created via [`AccessKeyStrategy::builder`].
pub struct AccessKeyStrategyBuilder {
    region: Region,
    access_key: SecretToken,
    audience: Option<String>,
    base_url_override: Option<url::Url>,
    crn: Option<Crn>,
}

impl AccessKeyStrategyBuilder {
    /// Set the audience for token requests.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Associate a workspace CRN with this strategy.
    pub fn crn(mut self, crn: Crn) -> Self {
        self.crn = Some(crn);
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

    /// Build the [`AccessKeyStrategy`].
    ///
    /// Resolves the base URL via service discovery unless overridden with
    /// `base_url` (available when the `test-utils` feature is enabled).
    pub fn build(self) -> Result<AccessKeyStrategy, AuthError> {
        let base_url = match self.base_url_override {
            Some(url) => url,
            None => CtsServiceDiscovery::endpoint(self.region)?,
        };
        let refresher = AccessKeyRefresher::new(
            self.access_key,
            ensure_trailing_slash(base_url),
            self.audience,
        );
        Ok(AccessKeyStrategy {
            crn: self.crn,
            inner: AutoRefresh::new(refresher),
        })
    }
}
