use cts_common::{CtsServiceDiscovery, Region, ServiceDiscovery, WorkspaceId};

use crate::auto_refresh::AutoRefresh;
use crate::oidc_refresher::{OidcProvider, OidcRefresher};
use crate::token_store::{NoStore, TokenStore};
use crate::{ensure_trailing_slash, AuthError, AuthStrategy, ServiceToken};

/// An [`AuthStrategy`] that federates a third-party OIDC JWT (Clerk, Supabase,
/// Auth0, …) into a CipherStash CTS service token via `POST /api/authorise`.
///
/// Each call to [`get_token`](AuthStrategy::get_token) returns a cached CTS
/// token until it expires. Because `/api/authorise` issues no CTS refresh
/// token, renewal means *re-federating*: the strategy calls the
/// [`OidcProvider`] again for a current third-party JWT and exchanges it for a
/// fresh CTS token. Supply an `OidcProvider` that returns the live provider
/// token each time (e.g. wrapping `clerk.session.getToken()`).
///
/// When constructed via [`OidcFederationStrategyBuilder::with_token_store`], the strategy
/// also persists tokens through an external [`TokenStore`] so short-lived
/// instances (e.g. one per Edge Function request) can share a cache and skip
/// re-federating on every cold start.
///
/// # Example
///
/// ```no_run
/// use stack_auth::{AuthError, OidcProviderFn, OidcFederationStrategy, SecretToken};
/// use cts_common::{Region, WorkspaceId};
///
/// let region = Region::aws("ap-southeast-2").unwrap();
/// let workspace_id: WorkspaceId = "ZVATKW3VHMFG27DY".parse().unwrap();
/// let provider = OidcProviderFn::new(|| async {
///     // Real consumers call into a provider SDK / FFI to fetch a live JWT.
///     Ok::<_, AuthError>(SecretToken::new("header.payload.signature".to_string()))
/// });
/// let strategy = OidcFederationStrategy::new(region, workspace_id, provider).unwrap();
/// ```
pub struct OidcFederationStrategy<P, S = NoStore> {
    inner: AutoRefresh<OidcRefresher<P>, S>,
}

impl<P: OidcProvider> OidcFederationStrategy<P> {
    /// Create a new `OidcFederationStrategy` for the given region, workspace, and
    /// OIDC provider.
    ///
    /// The auth endpoint is resolved automatically via service discovery.
    pub fn new(
        region: Region,
        workspace_id: WorkspaceId,
        oidc_provider: P,
    ) -> Result<Self, AuthError> {
        Self::builder(region, workspace_id, oidc_provider).build()
    }

    /// Return a builder for configuring an `OidcFederationStrategy` before construction.
    pub fn builder(
        region: Region,
        workspace_id: WorkspaceId,
        oidc_provider: P,
    ) -> OidcFederationStrategyBuilder<P> {
        OidcFederationStrategyBuilder {
            region,
            workspace_id,
            oidc_provider,
            audience: None,
            base_url_override: None,
            token_store: NoStore,
        }
    }
}

impl<P: OidcProvider, S: TokenStore> AuthStrategy for &OidcFederationStrategy<P, S> {
    async fn get_token(self) -> Result<ServiceToken, AuthError> {
        Ok(self.inner.get_token().await?)
    }
}

/// Builder for [`OidcFederationStrategy`].
///
/// Created via [`OidcFederationStrategy::builder`].
pub struct OidcFederationStrategyBuilder<P, S = NoStore> {
    region: Region,
    workspace_id: WorkspaceId,
    oidc_provider: P,
    audience: Option<String>,
    base_url_override: Option<url::Url>,
    token_store: S,
}

impl<P, S> OidcFederationStrategyBuilder<P, S> {
    /// Set the audience for token requests.
    ///
    /// Defaults to the workspace host FQDN server-side when unset.
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
    /// re-federating. After every successful federation the new token is
    /// written back to the store. Use this from short-lived strategy instances
    /// (Edge Functions, Workers) to share a service-token cache across
    /// processes — e.g. an HTTP-only cookie.
    ///
    /// Returns a new builder with the store type erased into the chain — see
    /// [`InMemoryTokenStore`](crate::InMemoryTokenStore) and
    /// [`TokenStoreFn`](crate::TokenStoreFn) for ready-made implementations.
    pub fn with_token_store<T: TokenStore>(self, store: T) -> OidcFederationStrategyBuilder<P, T> {
        OidcFederationStrategyBuilder {
            region: self.region,
            workspace_id: self.workspace_id,
            oidc_provider: self.oidc_provider,
            audience: self.audience,
            base_url_override: self.base_url_override,
            token_store: store,
        }
    }
}

impl<P: OidcProvider, S: TokenStore> OidcFederationStrategyBuilder<P, S> {
    /// Build the [`OidcFederationStrategy`].
    ///
    /// Resolves the base URL via service discovery unless overridden with
    /// `base_url` (available when the `test-utils` feature is enabled).
    pub fn build(self) -> Result<OidcFederationStrategy<P, S>, AuthError> {
        let base_url = match self.base_url_override {
            Some(url) => url,
            None => crate::cts_base_url_from_env()?
                .unwrap_or(CtsServiceDiscovery::endpoint(self.region)?),
        };
        let refresher = OidcRefresher::new(
            self.oidc_provider,
            self.workspace_id,
            ensure_trailing_slash(base_url),
            self.audience,
        );
        Ok(OidcFederationStrategy {
            inner: AutoRefresh::with_store(refresher, self.token_store),
        })
    }
}
