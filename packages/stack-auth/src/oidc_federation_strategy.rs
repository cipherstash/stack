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
    /// Takes precedence over both the `CS_CTS_HOST` environment variable and
    /// region-derived service discovery. Use this to point a single strategy
    /// instance at a specific CTS host — e.g. a self-hosted CTS, or a local
    /// mock auth server in development — without relying on the process-wide
    /// `CS_CTS_HOST`, which would also redirect any other CTS client (e.g. the
    /// `protect-ffi` encryption client) sharing the same process.
    pub fn base_url(mut self, url: url::Url) -> Self {
        self.base_url_override = Some(url);
        self
    }

    /// Apply an optional base-URL override supplied as a raw string.
    ///
    /// The string-typed convenience the language bindings (napi, wasm) call,
    /// so the "empty means absent, otherwise parse-or-reject" semantics live in
    /// one place rather than being re-derived per binding. An absent or empty
    /// string is a no-op — base-URL resolution falls back to `CS_CTS_HOST` /
    /// region service discovery (see [`build`](Self::build)); a non-empty but
    /// malformed string is rejected as [`AuthError::InvalidUrl`]. For an
    /// already-parsed URL, use [`base_url`](Self::base_url).
    pub fn maybe_base_url(self, base_url: Option<String>) -> Result<Self, AuthError> {
        match base_url {
            Some(s) if !s.is_empty() => Ok(self.base_url(s.parse::<url::Url>()?)),
            _ => Ok(self),
        }
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
    /// Resolves the base URL in priority order: an explicit [`base_url`]
    /// override, then the `CS_CTS_HOST` environment variable, then service
    /// discovery using the CRN's region.
    ///
    /// [`base_url`]: Self::base_url
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

    const WS: &str = "ZVATKW3VHMFG27DY";

    /// `maybe_base_url` is the string-typed override seam the language bindings
    /// rely on; pin its empty/absent/valid/malformed semantics here so the napi
    /// and wasm crates don't each re-test (and risk re-deriving) them.
    mod maybe_base_url {
        use super::*;

        #[test]
        fn absent_is_a_noop() {
            let b = OidcFederationStrategy::builder(crn_with_workspace(WS), provider())
                .maybe_base_url(None)
                .unwrap();
            assert!(b.base_url_override.is_none());
        }

        #[test]
        fn empty_string_is_a_noop() {
            let b = OidcFederationStrategy::builder(crn_with_workspace(WS), provider())
                .maybe_base_url(Some(String::new()))
                .unwrap();
            assert!(b.base_url_override.is_none());
        }

        #[test]
        fn valid_url_sets_the_override() {
            let b = OidcFederationStrategy::builder(crn_with_workspace(WS), provider())
                .maybe_base_url(Some("https://cts.example.com".to_string()))
                .unwrap();
            assert_eq!(
                b.base_url_override.as_ref().map(url::Url::as_str),
                Some("https://cts.example.com/")
            );
        }

        #[test]
        fn malformed_url_is_invalid_url() {
            // The builder isn't `Debug`, so match on the result rather than
            // `unwrap_err()` (which would require `T: Debug`).
            match OidcFederationStrategy::builder(crn_with_workspace(WS), provider())
                .maybe_base_url(Some("not a url".to_string()))
            {
                Err(AuthError::InvalidUrl(_)) => {}
                Ok(_) => panic!("expected Err(InvalidUrl), got Ok"),
                Err(other) => panic!("expected InvalidUrl, got: {other:?}"),
            }
        }
    }

    /// Precedence: an explicit `base_url` override (the one `maybe_base_url`
    /// sets) wins over the `CS_CTS_HOST` environment variable. `build()`
    /// resolves the host in priority order override → `CS_CTS_HOST` →
    /// discovery, so with `CS_CTS_HOST` pointed at a dead address the strategy
    /// must still federate against the override's mock — proving the env var
    /// was not consulted.
    ///
    /// `CS_CTS_HOST` is read inside `build()` (not `get_token`), so the env
    /// override is scoped to just that synchronous call via `temp_env`; the
    /// async federation runs with the environment already restored. No other
    /// test in this crate reads `CS_CTS_HOST` (every strategy test pins
    /// `base_url`), so this can't perturb a concurrent test.
    #[tokio::test]
    async fn base_url_override_takes_precedence_over_cs_cts_host() {
        const WS: &str = "ZVATKW3VHMFG27DY";
        let server = start_mock_server_returning_jwt(WS).await;

        // A routable-but-dead host: if `CS_CTS_HOST` were consulted, federation
        // would target this and fail rather than hitting the mock.
        let strategy = temp_env::with_var("CS_CTS_HOST", Some("http://127.0.0.1:1/"), || {
            OidcFederationStrategy::builder(crn_with_workspace(WS), provider())
                .maybe_base_url(Some(server.url("").to_string()))
                .expect("override URL parses")
                .build()
                .expect("builder")
        });

        let token = (&strategy)
            .get_token()
            .await
            .expect("override must win: federation should hit the mock, not CS_CTS_HOST");
        assert_eq!(
            token.workspace_id().expect("workspace_id").as_str(),
            WS,
            "token should come from the override's mock server",
        );
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
