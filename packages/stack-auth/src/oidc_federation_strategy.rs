use cts_common::{Crn, CtsServiceDiscovery, ServiceDiscovery, WorkspaceId};

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
/// The strategy is bound to a workspace CRN at construction. The region is
/// derived from the CRN — there is no separate `region` argument — so a
/// caller can't accidentally point the strategy at one region while the
/// CRN says another, matching
/// [`AccessKeyStrategy`](crate::AccessKeyStrategy).
///
/// Every returned token is checked against the CRN's workspace — the
/// same post-auth verification `AccessKeyStrategy` performs — so a token CTS
/// minted for a different workspace (or one loaded from a poisoned shared
/// cache) is never handed back. Verification can fail in two ways:
///
/// - [`AuthError::WorkspaceMismatch`] — the JWT decoded cleanly but its
///   `workspace` claim doesn't match the CRN's workspace ID.
/// - [`AuthError::InvalidToken`] — the JWT is malformed or missing the
///   `workspace` claim entirely, so verification can't run.
///
/// When constructed via [`OidcFederationStrategyBuilder::with_token_store`], the strategy
/// also persists tokens through an external [`TokenStore`] so short-lived
/// instances (e.g. one per Edge Function request) can share a cache and skip
/// re-federating on every cold start. The workspace check runs on cached and
/// store-loaded tokens too, not just freshly federated ones.
///
/// # Example
///
/// ```no_run
/// use stack_auth::{AuthError, OidcProviderFn, OidcFederationStrategy, SecretToken};
/// use cts_common::Crn;
///
/// let crn: Crn = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY".parse().unwrap();
/// let provider = OidcProviderFn::new(|| async {
///     // Real consumers call into a provider SDK / FFI to fetch a live JWT.
///     Ok::<_, AuthError>(SecretToken::new("header.payload.signature".to_string()))
/// });
/// let strategy = OidcFederationStrategy::new(crn, provider).unwrap();
/// ```
pub struct OidcFederationStrategy<P, S = NoStore> {
    inner: AutoRefresh<OidcRefresher<P>, S>,
    expected_workspace: WorkspaceId,
}

impl<P: OidcProvider> OidcFederationStrategy<P> {
    /// Create a new `OidcFederationStrategy` for the given workspace CRN and
    /// OIDC provider.
    ///
    /// The auth endpoint is resolved automatically via service discovery
    /// using the region encoded in the CRN; the workspace ID is used to
    /// verify every federated token belongs to the right workspace.
    ///
    /// A CRN with a `service_name` component (e.g.
    /// `crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY:zerokms`) is accepted; the
    /// `service_name` is ignored. Only the region and workspace ID are
    /// load-bearing for this strategy.
    pub fn new(workspace_crn: Crn, oidc_provider: P) -> Result<Self, AuthError> {
        Self::builder(workspace_crn, oidc_provider).build()
    }

    /// Return a builder for configuring an `OidcFederationStrategy` before construction.
    pub fn builder(workspace_crn: Crn, oidc_provider: P) -> OidcFederationStrategyBuilder<P> {
        OidcFederationStrategyBuilder {
            workspace_crn,
            oidc_provider,
            base_url_override: None,
            token_store: NoStore,
        }
    }
}

impl<P: OidcProvider, S: TokenStore> AuthStrategy for &OidcFederationStrategy<P, S> {
    async fn get_token(self) -> Result<ServiceToken, AuthError> {
        self.inner
            .get_token()
            .await?
            .verify_workspace(self.expected_workspace)
    }
}

/// Builder for [`OidcFederationStrategy`].
///
/// Created via [`OidcFederationStrategy::builder`].
pub struct OidcFederationStrategyBuilder<P, S = NoStore> {
    workspace_crn: Crn,
    oidc_provider: P,
    base_url_override: Option<url::Url>,
    token_store: S,
}

impl<P, S> OidcFederationStrategyBuilder<P, S> {
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
            workspace_crn: self.workspace_crn,
            oidc_provider: self.oidc_provider,
            base_url_override: self.base_url_override,
            token_store: store,
        }
    }
}

impl<P: OidcProvider, S: TokenStore> OidcFederationStrategyBuilder<P, S> {
    /// Build the [`OidcFederationStrategy`].
    ///
    /// Resolves the base URL via service discovery using the CRN's region,
    /// unless overridden with `base_url` (available when the `test-utils`
    /// feature is enabled).
    pub fn build(self) -> Result<OidcFederationStrategy<P, S>, AuthError> {
        let expected_workspace = self.workspace_crn.workspace_id;
        let region = self.workspace_crn.region;
        let base_url = match self.base_url_override {
            Some(url) => url,
            None => {
                crate::cts_base_url_from_env()?.unwrap_or(CtsServiceDiscovery::endpoint(region)?)
            }
        };
        let refresher = OidcRefresher::new(
            self.oidc_provider,
            expected_workspace,
            ensure_trailing_slash(base_url),
        );
        Ok(OidcFederationStrategy {
            inner: AutoRefresh::with_store(refresher, self.token_store),
            expected_workspace,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use mocktail::prelude::*;

    use super::*;
    use crate::oidc_refresher::OidcProviderFn;
    use crate::test_support::{crn_with_workspace, jwt_with_workspace};
    use crate::{InMemoryTokenStore, SecretToken, Token, TokenStore};

    /// A mock CTS that federates any OIDC token into a CTS token carrying the
    /// given `workspace` claim.
    async fn start_mock_server_returning_jwt(workspace: &str) -> MockServer {
        let mut mocks = MockSet::new();
        let jwt = jwt_with_workspace(workspace);
        mocks.mock(move |when, then| {
            when.post().path("/api/authorise");
            then.json(serde_json::json!({ "accessToken": jwt, "expiry": 3600 }));
        });
        let server =
            MockServer::new_http("oidc-federation-strategy-workspace-test").with_mocks(mocks);
        server.start().await.expect("mock server start");
        server
    }

    fn provider() -> OidcProviderFn<impl Fn() -> std::future::Ready<Result<SecretToken, AuthError>>>
    {
        OidcProviderFn::new(|| {
            std::future::ready(Ok(SecretToken::new("header.payload.signature".to_string())))
        })
    }

    /// Happy path — the federated token's `workspace` claim matches the
    /// configured workspace: `get_token()` returns the token cleanly.
    #[tokio::test]
    async fn returns_token_when_workspace_matches() {
        const WS: &str = "ZVATKW3VHMFG27DY";
        let server = start_mock_server_returning_jwt(WS).await;

        let strategy = OidcFederationStrategy::builder(crn_with_workspace(WS), provider())
            .base_url(server.url(""))
            .build()
            .expect("builder");

        let token = (&strategy).get_token().await.expect("get_token");
        assert_eq!(
            token.workspace_id().expect("workspace_id").as_str(),
            WS,
            "happy-path token should carry the expected workspace",
        );
    }

    /// A CRN carrying a `service_name` component is accepted; the
    /// `service_name` is ignored, exactly as for
    /// [`AccessKeyStrategy`](crate::AccessKeyStrategy). Pinned as a test —
    /// matching `access_key_strategy::accepts_crn_with_service_name` — so a
    /// future contributor doesn't tighten the constructor into rejecting these
    /// CRNs without realising the docstring already promises acceptance.
    #[tokio::test]
    async fn accepts_crn_with_service_name() {
        const WS: &str = "ZVATKW3VHMFG27DY";
        let server = start_mock_server_returning_jwt(WS).await;
        let crn: Crn = format!("crn:ap-southeast-2.aws:{WS}:zerokms")
            .parse()
            .expect("CRN with service_name parses");

        let strategy = OidcFederationStrategy::builder(crn, provider())
            .base_url(server.url(""))
            .build()
            .expect("CRN with service_name should construct a strategy");

        let token = (&strategy).get_token().await.expect("get_token");
        assert_eq!(
            token.workspace_id().expect("workspace_id").as_str(),
            WS,
            "service_name is ignored — verification still uses the workspace ID",
        );
    }

    /// Mismatch — CTS federates the OIDC token into a CTS token for a
    /// *different* workspace than the strategy was configured for. This is the
    /// security-critical case: the OIDC provider could be authenticated for a
    /// workspace the caller didn't intend. `get_token()` must return
    /// `WorkspaceMismatch`, not the token.
    #[tokio::test]
    async fn errors_when_token_workspace_differs() {
        const TOKEN_WS: &str = "AAAAAAAAAAAAAAAA";
        const EXPECTED_WS: &str = "ZVATKW3VHMFG27DY";
        let server = start_mock_server_returning_jwt(TOKEN_WS).await;

        let strategy = OidcFederationStrategy::builder(crn_with_workspace(EXPECTED_WS), provider())
            .base_url(server.url(""))
            .build()
            .expect("builder");

        let err = (&strategy)
            .get_token()
            .await
            .expect_err("expected mismatch");
        match err {
            AuthError::WorkspaceMismatch {
                expected_workspace,
                token_workspace,
            } => {
                assert_eq!(expected_workspace.as_str(), EXPECTED_WS);
                assert_eq!(token_workspace.as_str(), TOKEN_WS);
            }
            other => panic!("expected WorkspaceMismatch, got {other:?}"),
        }
    }

    /// A malformed CTS token (not a JWT) can't be decoded, so verification
    /// can't run — `get_token()` surfaces `InvalidToken` rather than handing
    /// back an unverifiable token.
    #[tokio::test]
    async fn errors_with_invalid_token_when_jwt_malformed() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(serde_json::json!({ "accessToken": "not-a-jwt", "expiry": 3600 }));
        });
        let server =
            MockServer::new_http("oidc-federation-strategy-malformed-test").with_mocks(mocks);
        server.start().await.expect("mock server start");

        let strategy =
            OidcFederationStrategy::builder(crn_with_workspace("ZVATKW3VHMFG27DY"), provider())
                .base_url(server.url(""))
                .build()
                .expect("builder");

        let err = (&strategy)
            .get_token()
            .await
            .expect_err("expected invalid-token error");
        assert!(
            matches!(err, AuthError::InvalidToken(_)),
            "expected InvalidToken, got {err:?}",
        );
    }

    /// A pre-populated [`TokenStore`] returning a token for a *different*
    /// workspace must still be rejected by the strategy wrapper — the same
    /// poisoned-shared-cache interaction `AccessKeyStrategy` guards against.
    /// A 500-returning mock fails the test loudly if the strategy ever
    /// re-federates instead of trusting (and rejecting) the stored token.
    #[tokio::test]
    async fn rejects_stored_token_for_different_workspace() {
        const TOKEN_WS: &str = "AAAAAAAAAAAAAAAA";
        const EXPECTED_WS: &str = "ZVATKW3VHMFG27DY";

        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.internal_server_error()
                .json(serde_json::json!({"error": "store must satisfy the request"}));
        });
        let server =
            MockServer::new_http("oidc-federation-strategy-store-mismatch-test").with_mocks(mocks);
        server.start().await.expect("mock server start");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_secs();
        let stored = Token {
            access_token: SecretToken::new(jwt_with_workspace(TOKEN_WS)),
            token_type: "Bearer".to_string(),
            expires_at: now + 3600,
            refresh_token: None,
            region: None,
            client_id: None,
            device_instance_id: None,
        };
        let store = Arc::new(InMemoryTokenStore::new());
        store.save(&stored).await;

        let strategy = OidcFederationStrategy::builder(crn_with_workspace(EXPECTED_WS), provider())
            .base_url(server.url(""))
            .with_token_store(Arc::clone(&store))
            .build()
            .expect("builder");

        let err = (&strategy)
            .get_token()
            .await
            .expect_err("expected mismatch from stored token");
        assert!(
            matches!(err, AuthError::WorkspaceMismatch { .. }),
            "expected WorkspaceMismatch, got {err:?}",
        );
    }

    /// Regression guard — the workspace check runs on *every* `get_token()`
    /// call, not only the one that triggers initial federation. A future
    /// optimisation that cached the "verified" verdict would let a mismatched
    /// token slide through on the second call.
    #[tokio::test]
    async fn errors_on_each_subsequent_get_token_call() {
        const TOKEN_WS: &str = "AAAAAAAAAAAAAAAA";
        const EXPECTED_WS: &str = "ZVATKW3VHMFG27DY";
        let server = start_mock_server_returning_jwt(TOKEN_WS).await;

        let strategy = OidcFederationStrategy::builder(crn_with_workspace(EXPECTED_WS), provider())
            .base_url(server.url(""))
            .build()
            .expect("builder");

        for call in 1..=2 {
            let err = match (&strategy).get_token().await {
                Ok(_) => panic!("call {call}: expected Err, got Ok"),
                Err(e) => e,
            };
            assert!(
                matches!(err, AuthError::WorkspaceMismatch { .. }),
                "call {call}: expected WorkspaceMismatch, got {err:?}",
            );
        }
    }
}
