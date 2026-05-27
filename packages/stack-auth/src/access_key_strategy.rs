use cts_common::{Crn, CtsServiceDiscovery, ServiceDiscovery, WorkspaceId};

use crate::access_key::AccessKey;
use crate::access_key_refresher::AccessKeyRefresher;
use crate::auto_refresh::AutoRefresh;
use crate::token_store::{NoStore, TokenStore};
use crate::{
    ensure_trailing_slash, AuthError, AuthStrategy, SecretToken, ServiceToken,
};

/// An [`AuthStrategy`] that uses a static access key to authenticate against
/// a specific workspace.
///
/// The strategy is bound to a workspace CRN at construction. The region is
/// derived from the CRN — there is no separate `region` argument — so a
/// caller can't accidentally point the strategy at one region while the
/// CRN says another.
///
/// The first call to [`get_token`](AuthStrategy::get_token) authenticates
/// with the server. Subsequent calls return the cached token until it
/// expires, at which point re-authentication happens automatically. Every
/// returned token is checked: if the JWT's `workspace` claim does not match
/// the CRN's workspace ID, [`AuthError::WorkspaceMismatch`] is returned
/// rather than silently letting the caller operate on a different workspace
/// than they specified.
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
/// use cts_common::Crn;
///
/// let crn: Crn = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY".parse().unwrap();
/// let key: AccessKey = "CSAKmyKeyId.myKeySecret".parse().unwrap();
/// let strategy = AccessKeyStrategy::new(crn, key).unwrap();
/// ```
pub struct AccessKeyStrategy<S = NoStore> {
    inner: AutoRefresh<AccessKeyRefresher, S>,
    expected_workspace: WorkspaceId,
}

impl AccessKeyStrategy {
    /// Create a new `AccessKeyStrategy` for the given workspace CRN and
    /// access key. The auth endpoint is resolved automatically via service
    /// discovery using the region encoded in the CRN.
    pub fn new(workspace_crn: Crn, access_key: AccessKey) -> Result<Self, AuthError> {
        Self::builder(workspace_crn, access_key).build()
    }

    /// Return a builder for configuring an `AccessKeyStrategy` before construction.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use stack_auth::{AccessKey, AccessKeyStrategy};
    /// use cts_common::Crn;
    ///
    /// let crn: Crn = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY".parse().unwrap();
    /// let key: AccessKey = "CSAKmyKeyId.myKeySecret".parse().unwrap();
    /// let strategy = AccessKeyStrategy::builder(crn, key)
    ///     .audience("my-audience")
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder(workspace_crn: Crn, access_key: AccessKey) -> AccessKeyStrategyBuilder {
        AccessKeyStrategyBuilder {
            workspace_crn,
            access_key: access_key.into_secret_token(),
            audience: None,
            base_url_override: None,
            token_store: NoStore,
        }
    }
}

impl<S: TokenStore> AuthStrategy for &AccessKeyStrategy<S> {
    async fn get_token(self) -> Result<ServiceToken, AuthError> {
        let token: ServiceToken = self.inner.get_token().await?;
        let token_workspace = token.workspace_id()?;
        if token_workspace != &self.expected_workspace {
            return Err(AuthError::WorkspaceMismatch {
                expected_workspace: self.expected_workspace.clone(),
                token_workspace: token_workspace.clone(),
            });
        }
        Ok(token)
    }
}

/// Builder for [`AccessKeyStrategy`].
///
/// Created via [`AccessKeyStrategy::builder`].
pub struct AccessKeyStrategyBuilder<S = NoStore> {
    workspace_crn: Crn,
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
    /// [`TokenStoreFn`](crate::TokenStoreFn) for ready-made
    /// implementations.
    pub fn with_token_store<T: TokenStore>(self, store: T) -> AccessKeyStrategyBuilder<T> {
        AccessKeyStrategyBuilder {
            workspace_crn: self.workspace_crn,
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
    /// Resolves the base URL via service discovery using the CRN's region,
    /// unless overridden with `base_url` (available when the `test-utils`
    /// feature is enabled).
    pub fn build(self) -> Result<AccessKeyStrategy<S>, AuthError> {
        let expected_workspace = self.workspace_crn.workspace_id.clone();
        let region = self.workspace_crn.region.clone();
        let base_url = match self.base_url_override {
            Some(url) => url,
            None => crate::cts_base_url_from_env()?
                .unwrap_or(CtsServiceDiscovery::endpoint(region)?),
        };
        let refresher = AccessKeyRefresher::new(
            self.access_key,
            ensure_trailing_slash(base_url),
            self.audience,
        );
        Ok(AccessKeyStrategy {
            inner: AutoRefresh::with_store(refresher, self.token_store),
            expected_workspace,
        })
    }
}

#[cfg(test)]
mod workspace_verification_tests {
    use super::*;
    use mocktail::prelude::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Build a JWT carrying the given `workspace` claim. Mirrors the
    /// helper in `node/src/mock_auth_server.rs`.
    fn jwt_with_workspace(workspace: &str) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        #[allow(clippy::expect_used)]
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_secs();
        let claims = serde_json::json!({
            "iss": "https://cts.example.com/",
            "sub": "CS|test-access-key",
            "aud": "test-audience",
            "iat": now,
            "exp": now + 3600,
            "workspace": workspace,
            "scope": "",
        });
        #[allow(clippy::expect_used)]
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("JWT encode")
    }

    async fn start_mock_server_returning_jwt(workspace: &str) -> MockServer {
        let mut mocks = MockSet::new();
        let jwt = jwt_with_workspace(workspace);
        mocks.mock(move |when, then| {
            when.post().path("/api/authorise");
            then.json(serde_json::json!({
                "accessToken": jwt,
                "expiry": 3600,
            }));
        });
        let server = MockServer::new_http("access-key-strategy-workspace-test")
            .with_mocks(mocks);
        #[allow(clippy::expect_used)]
        server.start().await.expect("mock server start");
        server
    }

    fn crn_with_workspace(workspace: &str) -> Crn {
        let s = format!("crn:ap-southeast-2.aws:{workspace}");
        s.parse().expect("test CRN parses")
    }

    fn test_access_key() -> AccessKey {
        "CSAKtestKeyId.testKeySecret"
            .parse()
            .expect("test access key parses")
    }

    /// Happy path — JWT workspace matches the CRN: `get_token()` returns
    /// the token cleanly.
    #[tokio::test]
    async fn returns_token_when_workspace_matches() {
        const WS: &str = "ZVATKW3VHMFG27DY";
        let server = start_mock_server_returning_jwt(WS).await;
        let crn = crn_with_workspace(WS);

        let strategy = AccessKeyStrategy::builder(crn, test_access_key())
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

    /// Mismatch — JWT workspace differs from the CRN's: `get_token()`
    /// returns `AuthError::WorkspaceMismatch` rather than the token.
    #[tokio::test]
    async fn errors_when_token_workspace_differs_from_crn() {
        const TOKEN_WS: &str = "AAAAAAAAAAAAAAAA";
        const CRN_WS: &str = "ZVATKW3VHMFG27DY";
        let server = start_mock_server_returning_jwt(TOKEN_WS).await;
        let crn = crn_with_workspace(CRN_WS);

        let strategy = AccessKeyStrategy::builder(crn, test_access_key())
            .base_url(server.url(""))
            .build()
            .expect("builder");

        let err = (&strategy).get_token().await.expect_err("expected mismatch");
        match err {
            AuthError::WorkspaceMismatch {
                expected_workspace,
                token_workspace,
            } => {
                assert_eq!(expected_workspace.as_str(), CRN_WS);
                assert_eq!(token_workspace.as_str(), TOKEN_WS);
            }
            other => panic!("expected WorkspaceMismatch, got {other:?}"),
        }
        assert_eq!(
            AuthError::WorkspaceMismatch {
                expected_workspace: CRN_WS.parse().unwrap(),
                token_workspace: TOKEN_WS.parse().unwrap(),
            }
            .error_code(),
            "WORKSPACE_MISMATCH",
        );
    }
}
