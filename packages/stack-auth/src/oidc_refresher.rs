use std::future::Future;
use std::sync::Arc;

use cts_common::WorkspaceId;
use url::Url;
use web_time::{SystemTime, UNIX_EPOCH};

use crate::authorize_dto::AuthoriseResponse;
use crate::refresher::Refresher;
use crate::{http_client, AuthError, SecretToken, Token};

/// Asynchronously supplies the *current* third-party OIDC JWT to federate.
///
/// [`OidcFederationStrategy`](crate::OidcFederationStrategy) re-invokes this on every refresh:
/// `/api/authorise` issues no CTS refresh token, so renewing an expired CTS
/// token means re-federating with a fresh provider JWT. Implementations
/// typically wrap a provider SDK call (`clerk.session.getToken()`,
/// `supabase.auth.getSession()`), an FFI callback, or a test double.
///
/// On native targets the trait carries `Send + Sync` bounds so the provider
/// can be driven from `tokio::spawn` background work. On wasm32 the bounds
/// are dropped — reqwest's fetch-backed futures are not `Send` and edge
/// runtimes are single-threaded anyway.
#[cfg(not(target_arch = "wasm32"))]
pub trait OidcProvider: Send + Sync {
    /// Fetch the current third-party OIDC JWT to federate.
    fn fetch(&self) -> impl Future<Output = Result<SecretToken, AuthError>> + Send;
}

/// Wasm32 variant of [`OidcProvider`] — drops the `Send + Sync` bounds.
#[cfg(target_arch = "wasm32")]
pub trait OidcProvider {
    /// Fetch the current third-party OIDC JWT to federate.
    fn fetch(&self) -> impl Future<Output = Result<SecretToken, AuthError>>;
}

/// [`OidcProvider`] backed by a user-supplied async closure.
///
/// The closure fires on every federation — initial auth and every
/// re-federation after expiry — so it should return the *current* JWT each
/// time (e.g. by calling into a provider SDK that refreshes short-lived
/// tokens itself), not a value captured once.
///
/// # Example
///
/// ```no_run
/// use stack_auth::{AuthError, OidcProviderFn, SecretToken};
///
/// let provider = OidcProviderFn::new(|| async {
///     // Real consumers call into a provider SDK / FFI / IPC.
///     Ok::<_, AuthError>(SecretToken::new("header.payload.signature".to_string()))
/// });
/// ```
pub struct OidcProviderFn<F> {
    fetch: F,
}

impl<F> OidcProviderFn<F> {
    /// Build an `OidcProviderFn` from an async closure returning the current JWT.
    pub fn new(fetch: F) -> Self {
        Self { fetch }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<F, Fut> OidcProvider for OidcProviderFn<F>
where
    F: Fn() -> Fut + Send + Sync,
    Fut: Future<Output = Result<SecretToken, AuthError>> + Send,
{
    fn fetch(&self) -> impl Future<Output = Result<SecretToken, AuthError>> + Send {
        (self.fetch)()
    }
}

#[cfg(target_arch = "wasm32")]
impl<F, Fut> OidcProvider for OidcProviderFn<F>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<SecretToken, AuthError>>,
{
    fn fetch(&self) -> impl Future<Output = Result<SecretToken, AuthError>> {
        (self.fetch)()
    }
}

/// A [`Refresher`] that federates a third-party OIDC JWT into a CTS service
/// token via `POST /api/authorise`.
///
/// Federation is stateless: the credential is always available (the
/// [`OidcProvider`] is re-callable), so `try_credential` returns `Some(())` and
/// `restore` is a no-op — exactly like
/// [`AccessKeyRefresher`](crate::access_key_refresher). `/api/authorise`
/// issues no CTS refresh token, so `AutoRefresh` renews an expired token by
/// calling `refresh` again, which re-invokes the `OidcProvider` for a current
/// JWT.
pub(crate) struct OidcRefresher<P> {
    oidc_provider: P,
    workspace_id: WorkspaceId,
    base_url: Url,
    audience: Option<String>,
    http_client: Arc<reqwest::Client>,
}

impl<P> OidcRefresher<P> {
    pub(crate) fn new(
        oidc_provider: P,
        workspace_id: WorkspaceId,
        base_url: Url,
        audience: Option<String>,
    ) -> Self {
        Self {
            oidc_provider,
            workspace_id,
            base_url,
            audience,
            http_client: Arc::new(http_client()),
        }
    }
}

impl<P: OidcProvider> Refresher for OidcRefresher<P> {
    type Credential = ();

    fn save(&self, _token: &Token) {
        // Federated tokens are ephemeral — no per-refresher persistence.
    }

    fn try_credential(&self, _token: Option<&mut Token>) -> Option<Self::Credential> {
        // The OIDC provider is always re-callable, so federation can always be
        // attempted — including on cold start (initial auth).
        Some(())
    }

    fn restore(&self, _token: &mut Token, _credential: Self::Credential) {
        // Nothing to restore — the OIDC provider is re-callable.
    }

    async fn refresh(&self, _credential: &Self::Credential) -> Result<Token, AuthError> {
        let oidc_token = self.oidc_provider.fetch().await?;

        let url = self.base_url.join("api/authorise")?;
        tracing::debug!(url = %url, "federating OIDC token");

        let resp = self
            .http_client
            .post(url)
            .json(&OidcAuthoriseRequest {
                oidc_token: oidc_token.as_str(),
                workspace_id: self.workspace_id.as_str(),
                audience: self.audience.as_deref(),
            })
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::debug!(%status, %body, "OIDC federation failed");
            return Err(AuthError::Server(format!("{status}: {body}")));
        }

        let auth_resp: AuthoriseResponse = resp.json().await?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Token {
            access_token: auth_resp.access_token,
            token_type: "Bearer".to_string(),
            expires_at: now + auth_resp.expiry,
            refresh_token: None,
            region: None,
            client_id: None,
            device_instance_id: None,
        })
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct OidcAuthoriseRequest<'a> {
    oidc_token: &'a str,
    workspace_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<&'a str>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use mocktail::prelude::*;

    use super::*;
    use crate::auto_refresh::{AutoRefresh, AutoRefreshError};
    use crate::TokenStore;

    const WORKSPACE_ID: &str = "ZVATKW3VHMFG27DY";

    fn workspace_id() -> WorkspaceId {
        WORKSPACE_ID.parse().unwrap()
    }

    fn auth_response_json(access: &str, expiry: u64) -> serde_json::Value {
        serde_json::json!({ "accessToken": access, "expiry": expiry })
    }

    async fn start_server(mocks: MockSet) -> MockServer {
        let server = MockServer::new_http("oidc-refresher-test").with_mocks(mocks);
        server.start().await.unwrap();
        server
    }

    /// A [`OidcProvider`] test double that counts invocations and returns a
    /// distinct JWT each call (`jwt-0`, `jwt-1`, …).
    fn counting_provider() -> (Arc<AtomicUsize>, impl OidcProvider) {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);
        let provider = OidcProviderFn::new(move || {
            let calls = Arc::clone(&calls_clone);
            async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                Ok(SecretToken::new(format!("jwt-{n}")))
            }
        });
        (calls, provider)
    }

    fn make_strategy<P: OidcProvider>(
        server: &MockServer,
        provider: P,
    ) -> AutoRefresh<OidcRefresher<P>> {
        let refresher = OidcRefresher::new(provider, workspace_id(), server.url(""), None);
        AutoRefresh::with_store(refresher, crate::NoStore)
    }

    fn make_token(access: &str, expires_in_secs: u64) -> Token {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Token {
            access_token: SecretToken::new(access),
            token_type: "Bearer".to_string(),
            expires_at: now + expires_in_secs,
            refresh_token: None,
            region: None,
            client_id: None,
            device_instance_id: None,
        }
    }

    #[tokio::test]
    async fn test_initial_federation() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("cts-token", 3600));
        });
        let server = start_server(mocks).await;
        let (calls, provider) = counting_provider();
        let strategy = make_strategy(&server, provider);

        let token = strategy.get_token().await.unwrap();

        assert_eq!(token.as_str(), "cts-token");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "initial federation should invoke the OIDC provider once"
        );
    }

    #[test]
    fn test_request_serialization_omits_audience_when_unset() {
        let body = serde_json::to_value(OidcAuthoriseRequest {
            oidc_token: "the-jwt",
            workspace_id: WORKSPACE_ID,
            audience: None,
        })
        .unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "oidcToken": "the-jwt", "workspaceId": WORKSPACE_ID }),
            "audience must be omitted from the request body when not set"
        );
    }

    #[test]
    fn test_request_serialization_includes_audience_when_set() {
        let body = serde_json::to_value(OidcAuthoriseRequest {
            oidc_token: "the-jwt",
            workspace_id: WORKSPACE_ID,
            audience: Some("my-audience"),
        })
        .unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "oidcToken": "the-jwt",
                "workspaceId": WORKSPACE_ID,
                "audience": "my-audience",
            }),
        );
    }

    #[tokio::test]
    async fn test_audience_set_still_federates() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("cts-token", 3600));
        });
        let server = start_server(mocks).await;
        let (_calls, provider) = counting_provider();
        let refresher = OidcRefresher::new(
            provider,
            workspace_id(),
            server.url(""),
            Some("my-audience".to_string()),
        );
        let strategy = AutoRefresh::with_store(refresher, crate::NoStore);

        let token = strategy.get_token().await.unwrap();
        assert_eq!(token.as_str(), "cts-token");
    }

    #[tokio::test]
    async fn test_caches_token_after_initial_federation() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("cts-token", 3600));
        });
        let server = start_server(mocks).await;
        let (calls, provider) = counting_provider();
        let strategy = make_strategy(&server, provider);

        assert_eq!(strategy.get_token().await.unwrap().as_str(), "cts-token");

        // Replace the mock so a second federation call would fail loudly.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/api/authorise");
            then.internal_server_error()
                .json(serde_json::json!({"error": "should not be called"}));
        });

        assert_eq!(strategy.get_token().await.unwrap().as_str(), "cts-token");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "cached token should be returned without re-federating"
        );
    }

    #[tokio::test]
    async fn test_re_federates_on_expiry() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("re-federated-token", 3600));
        });
        let server = start_server(mocks).await;

        let (calls, provider) = counting_provider();
        // Pre-seed the store with an already-expired token.
        let store = Arc::new(crate::InMemoryTokenStore::new());
        store.save(&make_token("stale-cts-token", 0)).await;

        let refresher = OidcRefresher::new(provider, workspace_id(), server.url(""), None);
        let strategy = AutoRefresh::with_store(refresher, Arc::clone(&store));

        let token = strategy.get_token().await.unwrap();
        assert_eq!(
            token.as_str(),
            "re-federated-token",
            "expired cached token should trigger re-federation"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "re-federation should invoke the OIDC provider for a current JWT"
        );
    }

    #[tokio::test]
    async fn test_oidc_provider_failure_propagates() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("unreachable", 3600));
        });
        let server = start_server(mocks).await;

        let provider = OidcProviderFn::new(|| async {
            Err::<SecretToken, _>(AuthError::Server("provider exploded".to_string()))
        });
        let strategy = make_strategy(&server, provider);

        let err = strategy.get_token().await.unwrap_err();
        assert!(
            matches!(err, AutoRefreshError::Auth(AuthError::Server(_))),
            "OIDC provider failure should surface as an auth error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_server_rejection_propagates() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.internal_server_error()
                .json(serde_json::json!({"error": "workspace mismatch"}));
        });
        let server = start_server(mocks).await;
        let (_calls, provider) = counting_provider();
        let strategy = make_strategy(&server, provider);

        let err = strategy.get_token().await.unwrap_err();
        assert!(
            matches!(err, AutoRefreshError::Auth(AuthError::Server(_))),
            "a 500 from /api/authorise should surface as a server error, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_loads_token_from_store_on_cold_start_no_http() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.internal_server_error()
                .json(serde_json::json!({"error": "should not be called"}));
        });
        let server = start_server(mocks).await;

        let store = Arc::new(crate::InMemoryTokenStore::new());
        store.save(&make_token("from-store", 3600)).await;

        let (calls, provider) = counting_provider();
        let refresher = OidcRefresher::new(provider, workspace_id(), server.url(""), None);
        let strategy = AutoRefresh::with_store(refresher, Arc::clone(&store));

        let token = strategy.get_token().await.unwrap();
        assert_eq!(token.as_str(), "from-store");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a fresh cached token should be used without invoking the OIDC provider"
        );
    }

    #[tokio::test]
    async fn test_persists_token_to_store_after_federation() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("freshly-federated", 3600));
        });
        let server = start_server(mocks).await;

        let store = Arc::new(crate::InMemoryTokenStore::new());
        let (_calls, provider) = counting_provider();
        let refresher = OidcRefresher::new(provider, workspace_id(), server.url(""), None);
        let strategy = AutoRefresh::with_store(refresher, Arc::clone(&store));

        let token = strategy.get_token().await.unwrap();
        assert_eq!(token.as_str(), "freshly-federated");

        let saved = store
            .load()
            .await
            .expect("store should hold a token after federation");
        assert_eq!(saved.access_token().as_str(), "freshly-federated");
    }
}
