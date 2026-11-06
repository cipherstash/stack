use cts_common::{Crn, CtsServiceDiscovery, Region, ServiceDiscovery, WorkspaceId};
use tracing::warn;

use stack_profile::ProfileStore;

use crate::auto_refresh::AutoRefresh;
use crate::device_session_refresher::DeviceSessionRefresher;
use crate::transport::{self, SharedTransport};
use crate::{ensure_trailing_slash, AuthError, AuthStrategy, HttpTransport, ServiceToken, Token};

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
    /// When set, every token is checked against this workspace.
    expected_workspace: Option<WorkspaceId>,
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
            transport: None,
            expected_workspace: None,
        }
    }

    /// Return a builder for configuring a `DeviceSessionStrategy` from a profile store.
    ///
    /// The token is loaded from the store when [`DeviceSessionStrategyBuilder::build`] is called.
    /// The builder allows further configuration (e.g. overriding the base URL) before building.
    ///
    /// The token must have `region` and `client_id` set (as saved by
    /// `DeviceCodeStrategy` (native, with the `http` feature) or a prior
    /// `DeviceSessionStrategy`). The store is used for persisting refreshed tokens.
    pub fn with_profile(store: ProfileStore) -> DeviceSessionStrategyBuilder {
        DeviceSessionStrategyBuilder {
            source: OAuthTokenSource::Store(store),
            base_url_override: None,
            transport: None,
            expected_workspace: None,
        }
    }

    /// Build from a workspace-scoped profile store. WASI hosts use this
    /// after taking the sibling auth.json lock; the store is read when
    /// `build` runs, so a sibling process's completed rotation is observed.
    /// On wasm32 the host must hold that lock through `get_token`, including
    /// the save, because WASI preview 1 has no file locking.
    pub fn with_workspace_store(store: ProfileStore) -> DeviceSessionStrategyBuilder {
        DeviceSessionStrategyBuilder {
            source: OAuthTokenSource::WorkspaceStore(store),
            base_url_override: None,
            transport: None,
            expected_workspace: None,
        }
    }

    /// Return the workspace CRN, if one was extracted from the token at build time.
    pub fn workspace_crn(&self) -> Option<&Crn> {
        self.crn.as_ref()
    }
}

impl AuthStrategy for &DeviceSessionStrategy {
    async fn get_token(self) -> Result<ServiceToken, AuthError> {
        let token = self.inner.get_token().await?;
        match self.expected_workspace {
            Some(expected) => token.verify_workspace(expected),
            None => Ok(token),
        }
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
    Store(ProfileStore),
    WorkspaceStore(ProfileStore),
}

/// Builder for [`DeviceSessionStrategy`].
///
/// Created via [`DeviceSessionStrategy::with_token`] or [`DeviceSessionStrategy::with_profile`].
pub struct DeviceSessionStrategyBuilder {
    source: OAuthTokenSource,
    base_url_override: Option<url::Url>,
    transport: Option<SharedTransport>,
    expected_workspace: Option<WorkspaceId>,
}

impl DeviceSessionStrategyBuilder {
    /// Pin the strategy to the workspace named by `crn`.
    ///
    /// For a strategy built from a profile store, the token is loaded from
    /// that workspace's directory rather than from the store's *current*
    /// workspace, so a CLI user who has switched workspaces does not change
    /// which one this process uses. Every token returned by `get_token` is
    /// also checked against the workspace, failing with
    /// [`AuthError::WorkspaceMismatch`] if it belongs to another one — as
    /// [`AccessKeyStrategy`](crate::AccessKeyStrategy) does.
    pub fn workspace_crn(mut self, crn: &Crn) -> Self {
        self.expected_workspace = Some(crn.workspace_id);
        self
    }

    /// Send this strategy's requests through `transport` instead of the
    /// bundled `reqwest` client.
    ///
    /// Without the `http` feature there is no bundled client, so this is
    /// required; with it, this is how a host with its own HTTP stack (or a
    /// test with a stub) takes over the wire without changing anything else
    /// about the strategy.
    pub fn transport(mut self, transport: impl HttpTransport) -> Self {
        self.transport = Some(transport::share(transport));
        self
    }

    /// [`transport`](Self::transport), for a caller that may or may not
    /// have one — the auto strategy hands its own through. Native-only,
    /// because on wasm32 the auto strategy has no profile to detect from.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn maybe_transport(mut self, transport: Option<SharedTransport>) -> Self {
        self.transport = transport;
        self
    }
    /// Override the CTS base URL resolved for this strategy.
    ///
    /// Takes precedence over both the `CS_CTS_HOST` environment variable and
    /// the token issuer / region-derived service discovery. Use it to point a
    /// single strategy instance at a specific CTS host — e.g. a self-hosted
    /// CTS, or a local mock auth server in development — without relying on the
    /// process-wide `CS_CTS_HOST`, which would redirect every other CTS client
    /// sharing the process.
    pub fn base_url(mut self, url: url::Url) -> Self {
        self.base_url_override = Some(url);
        self
    }

    /// Build the [`DeviceSessionStrategy`].
    ///
    /// Resolves the base URL in priority order: an explicit [`base_url`]
    /// override, then the `CS_CTS_HOST` environment variable, then the token
    /// issuer.
    ///
    /// [`base_url`]: Self::base_url
    pub fn build(self) -> Result<DeviceSessionStrategy, AuthError> {
        let Self {
            source,
            base_url_override,
            transport,
            expected_workspace,
        } = self;
        let transport = transport::resolve(transport)?;
        match source {
            OAuthTokenSource::Token {
                region,
                client_id,
                token,
            } => Self::build_from_token(region, client_id, token, base_url_override, transport),
            OAuthTokenSource::Store(store) => {
                let ws_store = match expected_workspace {
                    Some(ws) => store.workspace_store(ws.as_str())?,
                    None => store.current_workspace_store()?,
                };
                Self::build_from_workspace_store(ws_store, base_url_override, transport)
            }
            OAuthTokenSource::WorkspaceStore(store) => {
                Self::build_from_workspace_store(store, base_url_override, transport)
            }
        }
        .map(|mut strategy| {
            strategy.expected_workspace = expected_workspace;
            strategy
        })
    }

    /// Build from a token supplied directly (in-memory only, no store).
    fn build_from_token(
        region: Region,
        client_id: String,
        mut token: Token,
        base_url_override: Option<url::Url>,
        transport: SharedTransport,
    ) -> Result<DeviceSessionStrategy, AuthError> {
        let base_url = match base_url_override {
            Some(url) => url,
            None => {
                crate::cts_base_url_from_env()?.unwrap_or(CtsServiceDiscovery::endpoint(region)?)
            }
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
            transport,
        );
        Ok(DeviceSessionStrategy {
            crn,
            expected_workspace: None,
            inner: AutoRefresh::with_token(refresher, token),
        })
    }

    /// Build from a token persisted in a [`ProfileStore`].
    fn build_from_workspace_store(
        ws_store: ProfileStore,
        base_url_override: Option<url::Url>,
        transport: SharedTransport,
    ) -> Result<DeviceSessionStrategy, AuthError> {
        let token: Token = ws_store.load_profile()?;

        let region_str = token
            .region()
            .ok_or(AuthError::NotAuthenticated(crate::error::NotAuthenticated))?
            .to_string();
        let client_id = token
            .client_id()
            .ok_or(AuthError::NotAuthenticated(crate::error::NotAuthenticated))?
            .to_string();
        let crn = token
            .workspace_crn()
            .map_err(|e| {
                warn!("Could not extract workspace CRN from token: {e}");
                e
            })
            .ok();
        let device_instance_id = token.device_instance_id().map(String::from);

        let base_url = match base_url_override {
            Some(url) => url,
            None => crate::cts_base_url_from_env()?.unwrap_or(token.issuer()?),
        };

        let refresher = DeviceSessionRefresher::new(
            Some(ws_store),
            ensure_trailing_slash(base_url),
            &client_id,
            &region_str,
            device_instance_id,
            transport,
        );
        Ok(DeviceSessionStrategy {
            crn,
            expected_workspace: None,
            inner: AutoRefresh::with_token(refresher, token),
        })
    }
}

// Every test here builds a strategy with no transport of its own, which
// needs the bundled one.
#[cfg(test)]
#[cfg(feature = "http")]
mod tests {
    use super::*;
    use crate::test_support::{claims_with_workspace, jwt_token, raw_token};

    fn base_url() -> url::Url {
        "https://cts.example.com".parse().expect("valid url")
    }

    #[test]
    fn build_from_token_derives_crn_from_the_jwt_workspace_claim() {
        let region = Region::aws("ap-southeast-2").expect("valid region");
        let token = jwt_token(claims_with_workspace("7366ITCXSAPCH5TN"));

        let strategy = DeviceSessionStrategy::with_token(region, "my-client", token)
            .base_url(base_url())
            .build()
            .expect("build should succeed for a valid token");

        let crn = strategy
            .workspace_crn()
            .expect("CRN should be derived from the workspace claim")
            .to_string();
        assert!(crn.starts_with("crn:"), "unexpected CRN: {crn}");
        assert!(
            crn.contains("7366ITCXSAPCH5TN"),
            "CRN should carry the token's workspace, got: {crn}"
        );
    }

    #[test]
    fn build_from_token_succeeds_without_a_crn_when_the_workspace_claim_is_absent() {
        let region = Region::aws("ap-southeast-2").expect("valid region");
        // A non-JWT access token: the workspace claim can't be decoded, so CRN
        // derivation is skipped (it is best-effort) but the build still succeeds.
        let token = raw_token("not-a-jwt");

        let strategy = DeviceSessionStrategy::with_token(region, "my-client", token)
            .base_url(base_url())
            .build()
            .expect("build should succeed even when the CRN can't be derived");

        assert!(
            strategy.workspace_crn().is_none(),
            "CRN should be None when the token has no decodable workspace claim"
        );
    }

    #[tokio::test]
    async fn get_token_rejects_a_token_from_another_workspace() {
        let region = Region::aws("ap-southeast-2").expect("valid region");
        let token = jwt_token(claims_with_workspace("7366ITCXSAPCH5TN"));
        let other: Crn = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"
            .parse()
            .expect("valid crn");

        let strategy = DeviceSessionStrategy::with_token(region, "my-client", token)
            .base_url(base_url())
            .workspace_crn(&other)
            .build()
            .expect("build should succeed");

        let err = (&strategy)
            .get_token()
            .await
            .expect_err("a token for another workspace must be rejected");
        assert!(
            matches!(err, AuthError::WorkspaceMismatch(_)),
            "expected WorkspaceMismatch, got {err:?}"
        );
    }

    #[tokio::test]
    async fn get_token_accepts_a_token_from_the_pinned_workspace() {
        let region = Region::aws("ap-southeast-2").expect("valid region");
        let token = jwt_token(claims_with_workspace("7366ITCXSAPCH5TN"));
        let same: Crn = "crn:ap-southeast-2.aws:7366ITCXSAPCH5TN"
            .parse()
            .expect("valid crn");

        let strategy = DeviceSessionStrategy::with_token(region, "my-client", token)
            .base_url(base_url())
            .workspace_crn(&same)
            .build()
            .expect("build should succeed");

        (&strategy)
            .get_token()
            .await
            .expect("matching workspace should pass");
    }
}
