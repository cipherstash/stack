use cts_common::{CtsServiceDiscovery, Region, ServiceDiscovery};

use crate::auto_refresh::AutoRefresh;
use crate::oauth_refresher::OAuthRefresher;
use crate::token_store::TokenStore;
use crate::{ensure_trailing_slash, AuthError, AuthStrategy, SecretToken, Token};

/// An [`AuthStrategy`] that uses OAuth refresh tokens to maintain a valid access token.
///
/// # Construction
///
/// Use [`OAuthStrategy::new`] with a token obtained from a device code flow
/// (or any other OAuth flow) for in-memory caching only. Use
/// [`OAuthStrategy::using_store`] to load a token from disk and persist
/// refreshed tokens back to the store.
///
/// # Example
///
/// ```no_run
/// use stack_auth::{OAuthStrategy, Token};
/// use cts_common::Region;
///
/// # fn run(token: Token) -> Result<(), Box<dyn std::error::Error>> {
/// let region = Region::aws("ap-southeast-2")?;
/// let strategy = OAuthStrategy::new(region, "my-client-id", token)?;
/// # Ok(())
/// # }
/// ```
pub struct OAuthStrategy {
    inner: AutoRefresh<OAuthRefresher>,
}

impl OAuthStrategy {
    /// Create a new `OAuthStrategy` with the given token (in-memory only).
    ///
    /// The token's `region` and `client_id` fields are set before caching.
    /// No token store is used — tokens are not persisted to disk.
    pub fn new(
        region: Region,
        client_id: impl Into<String>,
        token: Token,
    ) -> Result<Self, AuthError> {
        Self::builder(region, client_id, token).build()
    }

    /// Return a builder for configuring an `OAuthStrategy` from a token.
    pub fn builder(
        region: Region,
        client_id: impl Into<String>,
        token: Token,
    ) -> OAuthStrategyBuilder {
        OAuthStrategyBuilder {
            source: OAuthTokenSource::Token {
                region,
                client_id: client_id.into(),
                token,
            },
            base_url_override: None,
        }
    }

    /// Create an `OAuthStrategy` by loading a token from the given store.
    ///
    /// The token must have `region` and `client_id` set (as saved by
    /// [`DeviceCodeStrategy`](crate::DeviceCodeStrategy) or a prior
    /// `OAuthStrategy`). The store is used for persisting refreshed tokens.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::NotAuthenticated`] if the token file is missing,
    /// or if the stored token is missing `region` or `client_id`.
    pub fn using_store(store: TokenStore) -> Result<Self, AuthError> {
        Self::from_store(store).build()
    }

    /// Return a builder for configuring an `OAuthStrategy` from a token store.
    ///
    /// The token is loaded from the store immediately. The builder allows
    /// further configuration (e.g. overriding the base URL) before building.
    pub fn from_store(store: TokenStore) -> OAuthStrategyBuilder {
        OAuthStrategyBuilder {
            source: OAuthTokenSource::Store(store),
            base_url_override: None,
        }
    }
}

impl AuthStrategy for &OAuthStrategy {
    async fn get_token(self) -> Result<SecretToken, AuthError> {
        Ok(self.inner.get_token().await?)
    }
}

/// Where the initial OAuth token comes from.
enum OAuthTokenSource {
    /// A token provided directly (in-memory only, no store).
    Token {
        region: Region,
        client_id: String,
        token: Token,
    },
    /// A token loaded from a persistent store.
    Store(TokenStore),
}

/// Builder for [`OAuthStrategy`].
///
/// Created via [`OAuthStrategy::builder`] or [`OAuthStrategy::from_store`].
pub struct OAuthStrategyBuilder {
    source: OAuthTokenSource,
    base_url_override: Option<url::Url>,
}

impl OAuthStrategyBuilder {
    /// Override the base URL resolved by service discovery.
    ///
    /// Useful for pointing at a local or mock auth server during testing.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn base_url(mut self, url: url::Url) -> Self {
        self.base_url_override = Some(url);
        self
    }

    /// Build the [`OAuthStrategy`].
    ///
    /// Resolves the base URL via service discovery unless overridden with
    /// `base_url` (available when the `test-utils` feature is enabled).
    pub fn build(self) -> Result<OAuthStrategy, AuthError> {
        match self.source {
            OAuthTokenSource::Token {
                region,
                client_id,
                mut token,
            } => {
                let base_url = match self.base_url_override {
                    Some(url) => url,
                    None => CtsServiceDiscovery::endpoint(region)?,
                };
                let region_id = region.identifier();
                token.set_region(&region_id);
                token.set_client_id(&client_id);
                let refresher = OAuthRefresher::new(
                    None,
                    ensure_trailing_slash(base_url),
                    &client_id,
                    &region_id,
                );
                Ok(OAuthStrategy {
                    inner: AutoRefresh::with_token(refresher, token),
                })
            }
            OAuthTokenSource::Store(store) => {
                let token = store.load()?;

                let region_str = token
                    .region()
                    .ok_or(AuthError::NotAuthenticated)?
                    .to_string();
                let client_id = token
                    .client_id()
                    .ok_or(AuthError::NotAuthenticated)?
                    .to_string();

                let base_url = match self.base_url_override {
                    Some(url) => url,
                    None => token.issuer()?,
                };

                let refresher = OAuthRefresher::new(
                    Some(store),
                    ensure_trailing_slash(base_url),
                    &client_id,
                    &region_str,
                );
                Ok(OAuthStrategy {
                    inner: AutoRefresh::with_token(refresher, token),
                })
            }
        }
    }
}
