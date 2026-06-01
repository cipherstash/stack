use cts_common::{Crn, CtsServiceDiscovery, Region, ServiceDiscovery};
use tracing::warn;

#[cfg(not(target_arch = "wasm32"))]
use stack_profile::ProfileStore;

use crate::auto_refresh::AutoRefresh;
use crate::device_session_refresher::DeviceSessionRefresher;
use crate::{ensure_trailing_slash, AuthError, AuthStrategy, ServiceToken, Token};

/// An [`AuthStrategy`] that renews a CTS session minted by an interactive
/// OAuth login (the device-code flow), using its OAuth refresh token.
///
/// This *renews* an existing CTS session — it cannot federate a raw
/// third-party JWT. For that, see [`OidcFederationStrategy`](crate::OidcFederationStrategy).
///
/// # Construction
///
/// Use [`DeviceSessionStrategy::with_token`] with a token obtained from a device code flow
/// (or any other OAuth flow) for in-memory caching only. Use
/// [`DeviceSessionStrategy::with_profile`] to load a token from disk and persist
/// refreshed tokens back to the store.
///
/// # Example
///
/// ```no_run
/// use stack_auth::{DeviceSessionStrategy, Token};
/// use cts_common::Region;
///
/// # fn run(token: Token) -> Result<(), Box<dyn std::error::Error>> {
/// let region = Region::aws("ap-southeast-2")?;
/// let strategy = DeviceSessionStrategy::with_token(region, "my-client-id", token).build()?;
/// # Ok(())
/// # }
/// ```
pub struct DeviceSessionStrategy {
    crn: Option<Crn>,
    inner: AutoRefresh<DeviceSessionRefresher>,
}

impl DeviceSessionStrategy {
    /// Return a builder for configuring a `DeviceSessionStrategy` from a token.
    ///
    /// The token's `region` and `client_id` fields are set before caching.
    /// No token store is used — tokens are not persisted to disk.
    pub fn with_token(
        region: Region,
        client_id: impl Into<String>,
        token: Token,
    ) -> DeviceSessionStrategyBuilder {
        DeviceSessionStrategyBuilder {
            source: OAuthTokenSource::Token {
                region,
                client_id: client_id.into(),
                token,
            },
            base_url_override: None,
        }
    }

    /// Return a builder for configuring a `DeviceSessionStrategy` from a profile store.
    ///
    /// The token is loaded from the store when [`DeviceSessionStrategyBuilder::build`] is called.
    /// The builder allows further configuration (e.g. overriding the base URL) before building.
    ///
    /// The token must have `region` and `client_id` set (as saved by
    /// [`DeviceCodeStrategy`](crate::DeviceCodeStrategy) or a prior
    /// `DeviceSessionStrategy`). The store is used for persisting refreshed tokens.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_profile(store: ProfileStore) -> DeviceSessionStrategyBuilder {
        DeviceSessionStrategyBuilder {
            source: OAuthTokenSource::Store(store),
            base_url_override: None,
        }
    }

    /// Return the workspace CRN, if one was extracted from the token at build time.
    pub fn workspace_crn(&self) -> Option<&Crn> {
        self.crn.as_ref()
    }
}

impl AuthStrategy for &DeviceSessionStrategy {
    async fn get_token(self) -> Result<ServiceToken, AuthError> {
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
    #[cfg(not(target_arch = "wasm32"))]
    Store(ProfileStore),
}

/// Builder for [`DeviceSessionStrategy`].
///
/// Created via [`DeviceSessionStrategy::with_token`] or [`DeviceSessionStrategy::with_profile`].
pub struct DeviceSessionStrategyBuilder {
    source: OAuthTokenSource,
    base_url_override: Option<url::Url>,
}

impl DeviceSessionStrategyBuilder {
    /// Override the base URL resolved by service discovery.
    ///
    /// Useful for pointing at a local or mock auth server during testing.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn base_url(mut self, url: url::Url) -> Self {
        self.base_url_override = Some(url);
        self
    }

    /// Build the [`DeviceSessionStrategy`].
    ///
    /// Resolves the base URL via service discovery unless overridden with
    /// `base_url` (available when the `test-utils` feature is enabled).
    pub fn build(self) -> Result<DeviceSessionStrategy, AuthError> {
        match self.source {
            OAuthTokenSource::Token {
                region,
                client_id,
                mut token,
            } => {
                let base_url = match self.base_url_override {
                    Some(url) => url,
                    None => crate::cts_base_url_from_env()?
                        .unwrap_or(CtsServiceDiscovery::endpoint(region)?),
                };
                // Derive CRN from the explicit region parameter and the token's
                // workspace claim. We can't use token.workspace_crn() here
                // because set_region() hasn't been called on the token yet.
                let crn = token
                    .workspace_id()
                    .map(|ws| Crn::new(region, ws))
                    .map_err(|e| {
                        warn!("Could not extract workspace CRN from token: {e}");
                        e
                    })
                    .ok();
                let region_id = region.identifier();
                let device_instance_id = token.device_instance_id().map(String::from);
                token.set_region(&region_id);
                token.set_client_id(&client_id);
                let refresher = DeviceSessionRefresher::new(
                    None,
                    ensure_trailing_slash(base_url),
                    &client_id,
                    &region_id,
                    device_instance_id,
                );
                Ok(DeviceSessionStrategy {
                    crn,
                    inner: AutoRefresh::with_token(refresher, token),
                })
            }
            #[cfg(not(target_arch = "wasm32"))]
            OAuthTokenSource::Store(store) => {
                let ws_store = store.current_workspace_store()?;
                let token: Token = ws_store.load_profile()?;

                let region_str = token
                    .region()
                    .ok_or(AuthError::NotAuthenticated)?
                    .to_string();
                let client_id = token
                    .client_id()
                    .ok_or(AuthError::NotAuthenticated)?
                    .to_string();
                let crn = token
                    .workspace_crn()
                    .map_err(|e| {
                        warn!("Could not extract workspace CRN from token: {e}");
                        e
                    })
                    .ok();
                let device_instance_id = token.device_instance_id().map(String::from);

                let base_url = match self.base_url_override {
                    Some(url) => url,
                    None => crate::cts_base_url_from_env()?.unwrap_or(token.issuer()?),
                };

                let refresher = DeviceSessionRefresher::new(
                    Some(ws_store),
                    ensure_trailing_slash(base_url),
                    &client_id,
                    &region_str,
                    device_instance_id,
                );
                Ok(DeviceSessionStrategy {
                    crn,
                    inner: AutoRefresh::with_token(refresher, token),
                })
            }
        }
    }
}
