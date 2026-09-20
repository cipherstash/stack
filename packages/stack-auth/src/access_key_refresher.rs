use url::Url;

use crate::authorize_dto::AuthoriseResponse;
use crate::refresher::Refresher;
use crate::transport::{self, SharedTransport};
use crate::{AuthError, SecretToken, Token};

/// A [`Refresher`] that uses a static access key to authenticate.
///
/// Unlike OAuth, the access key never changes — `try_credential` always returns
/// `Some(())` and `restore` is a no-op. This means `AutoRefresh` can perform
/// initial authentication on the first `get_token()` call (cold start).
pub(crate) struct AccessKeyRefresher {
    access_key: SecretToken,
    base_url: Url,
    audience: Option<String>,
    transport: SharedTransport,
}

impl AccessKeyRefresher {
    pub(crate) fn new(
        access_key: SecretToken,
        base_url: Url,
        audience: Option<String>,
        transport: SharedTransport,
    ) -> Self {
        Self {
            access_key,
            base_url,
            audience,
            transport,
        }
    }
}

impl Refresher for AccessKeyRefresher {
    type Credential = ();

    fn save(&self, _token: &Token) {
        // Access key tokens are ephemeral — no persistence needed.
    }

    fn try_credential(&self, _token: Option<&mut Token>) -> Option<Self::Credential> {
        Some(())
    }

    fn restore(&self, _token: &mut Token, _credential: Self::Credential) {
        // Nothing to restore — the access key is always available.
    }

    async fn refresh(&self, _credential: &Self::Credential) -> Result<Token, AuthError> {
        let url = self.base_url.join("api/authorise")?;

        tracing::debug!(url = %url, "authenticating with access key");

        let resp = transport::post_json(
            &self.transport,
            url,
            &AuthoriseRequest {
                access_key: self.access_key.as_str(),
                audience: self.audience.as_deref(),
            },
        )
        .await?;

        if !resp.is_success() {
            let status = resp.status();
            let body = resp.text();
            tracing::debug!(%status, %body, "access key auth failed");
            if let Some(err) = crate::error::classify_issuance_failure(status, &body) {
                return Err(err);
            }
            return Err(AuthError::Server(crate::error::ServerError(format!(
                "{status}: {body}"
            ))));
        }

        let auth_resp: AuthoriseResponse = resp.json()?;

        // The response → Token mapping (including the absolute-epoch `expiry`
        // handling that CIP-3233 fixed) lives on `From<AuthoriseResponse>`.
        Ok(auth_resp.into())
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthoriseRequest<'a> {
    access_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<&'a str>,
}

#[cfg(test)]
#[cfg(feature = "http")]
mod tests {
    use super::*;
    use crate::auto_refresh::{AutoRefresh, AutoRefreshError};
    use crate::transport::default_transport;
    use crate::TokenStore;
    use mocktail::prelude::*;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Build a mock `/api/authorise` response. CTS returns `expiry` as an
    /// ABSOLUTE Unix epoch (the JWT `exp` claim), so model that faithfully: the
    /// token is valid for `expires_in_secs` from now.
    fn auth_response_json(access: &str, expires_in_secs: u64) -> serde_json::Value {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        serde_json::json!({
            "accessToken": access,
            "expiry": now + expires_in_secs
        })
    }

    async fn start_server(mocks: MockSet) -> MockServer {
        let server = MockServer::new_http("access-key-refresher-test").with_mocks(mocks);
        server.start().await.unwrap();
        server
    }

    fn make_access_key_strategy(server: &MockServer) -> AutoRefresh<AccessKeyRefresher> {
        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            server.url(""),
            Some("test-audience".to_string()),
            default_transport(),
        );
        AutoRefresh::with_store(refresher, crate::NoStore)
    }

    /// Build a `Token` whose `expires_at` is `expires_in_secs` from now —
    /// pass `0` for "already expired", `3600` for "fresh, well outside the
    /// 90s expiry-leeway window".
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

    fn make_expired_token(access: &str) -> Token {
        make_token(access, 0)
    }

    fn make_fresh_token(access: &str) -> Token {
        make_token(access, 3600)
    }

    // ---- Regression: CTS `expiry` is an absolute epoch (CIP-3233) ----

    /// CTS `/api/authorise` returns `expiry` as an ABSOLUTE Unix epoch (the JWT
    /// `exp` claim), not a relative duration. The refresher must use it as-is.
    ///
    /// Pre-fix (`expires_at = now + expiry`), this token's `expires_at` lands
    /// ~decades in the future, so `is_expired()` is never true — the token never
    /// refreshes and silently dies at its real ~15-minute `exp`. The assertion
    /// below fails under the pre-fix arithmetic (`expires_in()` ≈ 1.7e9) and
    /// passes with the fix (`expires_in()` ≈ 900).
    #[tokio::test]
    async fn access_key_expiry_is_absolute_epoch_not_relative() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let absolute_expiry = now + 900; // a 15-minute token, as an absolute epoch

        let mut mocks = MockSet::new();
        mocks.mock(move |when, then| {
            when.post().path("/api/authorise");
            then.json(serde_json::json!({
                "accessToken": "tok",
                "expiry": absolute_expiry
            }));
        });
        let server = start_server(mocks).await;

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("CSAKid.secret"),
            server.url(""),
            None,
            default_transport(),
        );
        let token = refresher.refresh(&()).await.unwrap();

        assert!(
            token.expires_in() <= 1000,
            "expires_in should be ~900s (absolute `expiry` used as-is); got {} \
             — pre-fix `now + expiry` yields ~1.7e9",
            token.expires_in()
        );
        assert!(
            !token.is_expired(),
            "a fresh 15-minute token must not be reported as already expired"
        );
    }

    // ---- Initial auth tests ----

    #[tokio::test]
    async fn test_initial_auth_no_cached_token() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("new-token", 3600));
        });
        let server = start_server(mocks).await;
        let strategy = make_access_key_strategy(&server);

        let token = strategy.get_token().await.unwrap();

        assert_eq!(token.as_str(), "new-token");
    }

    /// A usage denial must not arrive as `SERVER_ERROR`. Clients treat that as
    /// transient and retry — but no amount of retrying clears a usage limit, so
    /// they would spin until the plan changes.
    #[tokio::test]
    async fn usage_limit_402_is_typed_not_server_error() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.status(reqwest::StatusCode::PAYMENT_REQUIRED).json(serde_json::json!({
                "error": "usage_limit_exceeded",
                "error_description": "Workspace has exceeded its usage limit and cannot issue an access token",
            }));
        });
        let server = start_server(mocks).await;
        let strategy = make_access_key_strategy(&server);

        let err = strategy
            .get_token()
            .await
            .expect_err("402 must fail the token request");

        let auth_err = match err {
            AutoRefreshError::Auth(e) => e,
            other => panic!("expected an auth error, got {other:?}"),
        };
        assert_eq!(auth_err.error_code(), "USAGE_LIMIT_EXCEEDED");
        assert!(
            auth_err.to_string().contains("exceeded its usage limit"),
            "server's description should survive verbatim, got {auth_err}",
        );
    }

    /// Only 402 means "usage limit". Other failures must keep their existing
    /// classification, or this becomes a catch-all that hides real errors.
    #[tokio::test]
    async fn non_402_failures_are_unchanged() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.internal_server_error()
                .json(serde_json::json!({"error": "boom"}));
        });
        let server = start_server(mocks).await;
        let strategy = make_access_key_strategy(&server);

        let err = strategy.get_token().await.expect_err("500 must fail");

        let auth_err = match err {
            AutoRefreshError::Auth(e) => e,
            other => panic!("expected an auth error, got {other:?}"),
        };
        assert_eq!(auth_err.error_code(), "SERVER_ERROR");
    }

    #[tokio::test]
    async fn test_caches_token_after_initial_auth() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("new-token", 3600));
        });
        let server = start_server(mocks).await;
        let strategy = make_access_key_strategy(&server);

        let token1 = strategy.get_token().await.unwrap();
        assert_eq!(token1.as_str(), "new-token");

        // Replace mock — second call should use cached token.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/api/authorise");
            then.internal_server_error()
                .json(serde_json::json!({"error": "should not be called"}));
        });

        let token2 = strategy.get_token().await.unwrap();
        assert_eq!(token2.as_str(), "new-token");
    }

    // ---- TokenStore integration tests ----

    #[tokio::test]
    async fn test_loads_token_from_store_on_cold_start_no_http() {
        // Mock returns 500 so we know the test fails loudly if the strategy
        // ever calls authorise — but we expect it not to, since the store
        // already holds a fresh token.
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.internal_server_error()
                .json(serde_json::json!({"error": "should not be called"}));
        });
        let server = start_server(mocks).await;

        let store = Arc::new(crate::InMemoryTokenStore::new());
        store.save(&make_fresh_token("from-store")).await;

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            server.url(""),
            None,
            default_transport(),
        );
        let strategy = AutoRefresh::with_store(refresher, Arc::clone(&store));

        let token = strategy.get_token().await.unwrap();
        assert_eq!(
            token.as_str(),
            "from-store",
            "cold-start should return the token loaded from the store, not call HTTP"
        );
    }

    #[tokio::test]
    async fn test_persists_token_to_store_after_initial_auth() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("freshly-minted", 3600));
        });
        let server = start_server(mocks).await;

        let store = Arc::new(crate::InMemoryTokenStore::new());
        assert!(
            store.load().await.is_none(),
            "store should be empty before initial auth"
        );

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            server.url(""),
            None,
            default_transport(),
        );
        let strategy = AutoRefresh::with_store(refresher, Arc::clone(&store));

        let token = strategy.get_token().await.unwrap();
        assert_eq!(
            token.as_str(),
            "freshly-minted",
            "initial auth should return the newly issued token"
        );

        // After initial auth, the store should hold the new token.
        let saved = store
            .load()
            .await
            .expect("store should hold a token after initial auth");
        assert_eq!(
            saved.access_token().as_str(),
            "freshly-minted",
            "store should hold the same token initial auth returned"
        );
    }

    #[tokio::test]
    async fn test_two_strategies_sharing_store_skip_http_on_second_cold_start() {
        // Allow exactly one /api/authorise call; the second strategy must hit
        // the store, not the server.
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("shared-cache-token", 3600));
        });
        let server = start_server(mocks).await;
        let store = Arc::new(crate::InMemoryTokenStore::new());

        // First strategy — does the HTTP exchange and writes to the store.
        let refresher_a = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            server.url(""),
            None,
            default_transport(),
        );
        let strategy_a = AutoRefresh::with_store(refresher_a, Arc::clone(&store));
        let token_a = strategy_a.get_token().await.unwrap();
        assert_eq!(
            token_a.as_str(),
            "shared-cache-token",
            "first strategy should mint a fresh token via HTTP"
        );

        // Replace the mock so any second call fails the test loudly.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/api/authorise");
            then.internal_server_error()
                .json(serde_json::json!({"error": "second strategy must hit store"}));
        });

        // Second strategy — fresh instance, same store. Should load from store.
        let refresher_b = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            server.url(""),
            None,
            default_transport(),
        );
        let strategy_b = AutoRefresh::with_store(refresher_b, Arc::clone(&store));
        let token_b = strategy_b.get_token().await.unwrap();
        assert_eq!(
            token_b.as_str(),
            "shared-cache-token",
            "second strategy should return the same token via the shared store, not the failing mock"
        );
    }

    #[tokio::test]
    async fn test_refreshes_when_store_has_expired_token() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("refreshed-after-store-miss", 3600));
        });
        let server = start_server(mocks).await;

        let store = Arc::new(crate::InMemoryTokenStore::new());
        store.save(&make_expired_token("stale-from-store")).await;

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            server.url(""),
            None,
            default_transport(),
        );
        let strategy = AutoRefresh::with_store(refresher, Arc::clone(&store));

        let token = strategy.get_token().await.unwrap();
        assert_eq!(
            token.as_str(),
            "refreshed-after-store-miss",
            "expired store entry should trigger refresh, not be returned as-is"
        );

        // Store should now hold the refreshed token, not the stale one.
        let saved = store
            .load()
            .await
            .expect("store should still hold a token after refresh");
        assert_eq!(
            saved.access_token().as_str(),
            "refreshed-after-store-miss",
            "store should be overwritten with the refreshed token"
        );
    }

    // ---- Refresh on expiry tests ----

    #[tokio::test]
    async fn test_re_authenticates_on_expiry() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("refreshed-token", 3600));
        });
        let server = start_server(mocks).await;

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            server.url(""),
            None,
            default_transport(),
        );
        let strategy = AutoRefresh::with_token(refresher, make_expired_token("old-token"));

        let token = strategy.get_token().await.unwrap();

        assert_eq!(token.as_str(), "refreshed-token");
    }

    // ---- Error handling tests ----

    #[tokio::test]
    async fn test_initial_auth_failure() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.unauthorized()
                .json(serde_json::json!({"error": "invalid key"}));
        });
        let server = start_server(mocks).await;
        let strategy = make_access_key_strategy(&server);

        let err = strategy.get_token().await.unwrap_err();

        assert!(matches!(err, AutoRefreshError::Auth(_)));
    }

    #[tokio::test]
    async fn refresh_failure_propagates_the_refusal_not_expired() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.unauthorized()
                .json(serde_json::json!({"error": "invalid key"}));
        });
        let server = start_server(mocks).await;

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            server.url(""),
            None,
            default_transport(),
        );
        let strategy = AutoRefresh::with_token(refresher, make_expired_token("old-token"));

        let err = strategy.get_token().await.unwrap_err();

        assert!(
            matches!(err, AutoRefreshError::Auth(_)),
            "the caller must see why the refresh was refused; flattening to \
             Expired tells them to do the one thing that cannot help — {err:?}",
        );
    }

    #[tokio::test]
    async fn usage_limit_on_refresh_reaches_the_caller() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.status(reqwest::StatusCode::PAYMENT_REQUIRED)
                .json(serde_json::json!({
                    "error": "access_denied",
                    "cs_code": "USAGE_LIMIT_EXCEEDED",
                    "error_description": "Workspace has exceeded its usage limit",
                }));
        });
        let server = start_server(mocks).await;

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            server.url(""),
            None,
            default_transport(),
        );
        let strategy = AutoRefresh::with_token(refresher, make_expired_token("old-token"));

        let AutoRefreshError::Auth(err) = strategy.get_token().await.unwrap_err() else {
            panic!("expected a typed auth error");
        };

        assert_eq!(err.error_code(), crate::error::codes::USAGE_LIMIT_EXCEEDED);
    }

    /// Counts requests to `/api/authorise` and replies with a fixed status and
    /// body, so a test can assert how many times the client actually went to
    /// the network rather than only what it returned.
    async fn start_counting_server(
        status: axum::http::StatusCode,
        body: serde_json::Value,
    ) -> (Url, Arc<AtomicUsize>) {
        type CountingState = (Arc<AtomicUsize>, axum::http::StatusCode, serde_json::Value);

        async fn handler(
            axum::extract::State((calls, status, body)): axum::extract::State<CountingState>,
        ) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
            calls.fetch_add(1, Ordering::SeqCst);
            (status, axum::Json(body))
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let app = axum::Router::new()
            .route("/api/authorise", axum::routing::post(handler))
            .with_state((calls.clone(), status, body));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (Url::parse(&format!("http://{addr}")).unwrap(), calls)
    }

    /// A usage limit will not clear by asking again. Without a negative cache
    /// an over-limit client re-POSTs `/api/authorise` on every `get_token` —
    /// at its own request rate, against a decision already made.
    #[tokio::test]
    async fn a_settled_refusal_is_not_re_issued_on_every_call() {
        let (url, calls) = start_counting_server(
            axum::http::StatusCode::PAYMENT_REQUIRED,
            serde_json::json!({
                "error": "access_denied",
                "cs_code": "USAGE_LIMIT_EXCEEDED",
                "error_description": "Workspace has exceeded its usage limit",
            }),
        )
        .await;

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            url,
            None,
            default_transport(),
        );
        let strategy = AutoRefresh::with_token(refresher, make_expired_token("old-token"));

        for call in 1..=5 {
            let AutoRefreshError::Auth(err) = strategy.get_token().await.unwrap_err() else {
                panic!("call {call}: expected a typed auth error");
            };
            assert_eq!(
                err.error_code(),
                crate::error::codes::USAGE_LIMIT_EXCEEDED,
                "call {call}: the cached refusal must be replayed verbatim",
            );
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "five get_token calls against a settled refusal must produce one \
             HTTP request, not five",
        );
    }

    /// Serves a usage limit until `upgraded` is set, then a valid token —
    /// modelling a customer upgrading their plan while a strategy is live.
    async fn start_upgradable_server() -> (Url, Arc<AtomicUsize>, Arc<AtomicBool>) {
        type UpgradableState = (Arc<AtomicUsize>, Arc<AtomicBool>);

        async fn handler(
            axum::extract::State((calls, upgraded)): axum::extract::State<UpgradableState>,
        ) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
            calls.fetch_add(1, Ordering::SeqCst);
            if upgraded.load(Ordering::SeqCst) {
                (
                    axum::http::StatusCode::OK,
                    axum::Json(auth_response_json("upgraded-token", 3600)),
                )
            } else {
                (
                    axum::http::StatusCode::PAYMENT_REQUIRED,
                    axum::Json(serde_json::json!({
                        "error": "access_denied",
                        "cs_code": "USAGE_LIMIT_EXCEEDED",
                        "error_description": "Workspace has exceeded its usage limit",
                    })),
                )
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let upgraded = Arc::new(AtomicBool::new(false));
        let app = axum::Router::new()
            .route("/api/authorise", axum::routing::post(handler))
            .with_state((calls.clone(), upgraded.clone()));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (
            Url::parse(&format!("http://{addr}")).unwrap(),
            calls,
            upgraded,
        )
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// A token whose expiry is an absolute instant, for tests driving a frozen
    /// [`TestClock`](crate::clock::TestClock).
    ///
    /// `make_expired_token` reads the wall clock itself, so pairing it with a
    /// clock frozen at a separately-read `now` is a race: if the two reads
    /// straddle a second boundary the token is a second short of expired, no
    /// refresh is attempted, and the test fails only on an unlucky run. Derive
    /// both from one instant instead.
    fn make_token_expiring_at(access: &str, expires_at: u64) -> Token {
        Token {
            access_token: SecretToken::new(access),
            token_type: "Bearer".to_string(),
            expires_at,
            refresh_token: None,
            region: None,
            client_id: None,
            device_instance_id: None,
        }
    }

    /// A cached refusal must not be permanent. Suppressing the retry storm is
    /// the point; suppressing it forever means a customer who upgrades their
    /// plan stays locked out until the process restarts.
    #[tokio::test]
    async fn a_settled_refusal_is_retried_once_it_expires() {
        let (url, calls, _upgraded) = start_upgradable_server().await;
        let start = now_secs();
        let clock = crate::clock::TestClock::new(start);

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            url,
            None,
            default_transport(),
        );
        let strategy = AutoRefresh::with_token_and_clock(
            refresher,
            make_token_expiring_at("old-token", start - 3600),
            clock.shared(),
        );

        strategy.get_token().await.unwrap_err();
        strategy.get_token().await.unwrap_err();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "within the window the cached refusal is replayed",
        );

        clock.advance(super::super::auto_refresh::DENIAL_TTL_SECS + 1);
        strategy.get_token().await.unwrap_err();

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "once the refusal expires the server must be asked again",
        );
    }

    /// The reason the expiry matters: the upgrade has to become visible.
    #[tokio::test]
    async fn an_upgraded_plan_is_observed_once_the_refusal_expires() {
        let (url, _calls, upgraded) = start_upgradable_server().await;
        let start = now_secs();
        let clock = crate::clock::TestClock::new(start);

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            url,
            None,
            default_transport(),
        );
        let strategy = AutoRefresh::with_token_and_clock(
            refresher,
            make_token_expiring_at("old-token", start - 3600),
            clock.shared(),
        );

        strategy.get_token().await.unwrap_err();

        // Customer upgrades their plan.
        upgraded.store(true, Ordering::SeqCst);

        strategy
            .get_token()
            .await
            .expect_err("still inside the refusal window");

        clock.advance(super::super::auto_refresh::DENIAL_TTL_SECS + 1);

        let token = strategy
            .get_token()
            .await
            .expect("an upgraded plan must eventually be observed");
        assert_eq!(token.as_str(), "upgraded-token");
    }

    /// A successful refresh clears the refusal outright, so the *next* call
    /// after recovery does not wait out a stale window.
    #[tokio::test]
    async fn a_success_clears_the_refusal_immediately() {
        let (url, calls, upgraded) = start_upgradable_server().await;
        let start = now_secs();
        let clock = crate::clock::TestClock::new(start);

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            url,
            None,
            default_transport(),
        );
        let strategy = AutoRefresh::with_token_and_clock(
            refresher,
            make_token_expiring_at("old-token", start - 3600),
            clock.shared(),
        );

        strategy.get_token().await.unwrap_err();
        upgraded.store(true, Ordering::SeqCst);
        clock.advance(super::super::auto_refresh::DENIAL_TTL_SECS + 1);
        strategy.get_token().await.unwrap();

        let before = calls.load(Ordering::SeqCst);
        strategy
            .get_token()
            .await
            .expect("cached token is still valid");

        assert_eq!(
            calls.load(Ordering::SeqCst),
            before,
            "a valid cached token needs no further round-trip",
        );
    }

    /// A wall clock can move backwards — NTP step, VM snapshot restore, a
    /// manual change. `now - recorded_at` would then underflow, and with a
    /// wrapping subtraction the refusal would look freshly recorded for
    /// billions of seconds. Erring towards asking again costs one request.
    #[tokio::test]
    async fn a_backwards_clock_does_not_pin_the_refusal() {
        let (url, calls, upgraded) = start_upgradable_server().await;
        let start = now_secs();
        let clock = crate::clock::TestClock::new(start);

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            url,
            None,
            default_transport(),
        );
        // Expired well before `start`, so it is still expired after the rewind
        // — otherwise the token-expiry check short-circuits and the refusal is
        // never consulted, and the test would prove nothing.
        let strategy = AutoRefresh::with_token_and_clock(
            refresher,
            make_token_expiring_at("old-token", start - 86_400),
            clock.shared(),
        );

        strategy.get_token().await.unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        upgraded.store(true, Ordering::SeqCst);
        clock.set(start - 3600);

        strategy
            .get_token()
            .await
            .expect("a clock that jumped backwards must not pin the refusal");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// The mirror of the above: a server fault may clear, so it must *not*
    /// stick. Treating a transient failure as permanent locks a client out of
    /// a service that has since recovered — the worse of the two mistakes.
    #[tokio::test]
    async fn a_server_fault_is_retried_on_the_next_call() {
        let (url, calls) = start_counting_server(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({}),
        )
        .await;

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            url,
            None,
            default_transport(),
        );
        let strategy = AutoRefresh::with_token(refresher, make_expired_token("old-token"));

        for _ in 0..3 {
            strategy.get_token().await.unwrap_err();
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "a server fault must be retried; only settled refusals stick",
        );
    }

    // ---- Cascade prevention tests ----

    #[tokio::test]
    async fn test_concurrent_initial_auth_only_one_http_call() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("new-token", 3600));
        });
        let server = start_server(mocks).await;
        let strategy = Arc::new(make_access_key_strategy(&server));

        let s1 = Arc::clone(&strategy);
        let handle_a = tokio::spawn(async move { s1.get_token().await.unwrap() });

        let s2 = Arc::clone(&strategy);
        let handle_b = tokio::spawn(async move { s2.get_token().await.unwrap() });

        let (result_a, result_b) = tokio::join!(handle_a, handle_b);
        let token_a = result_a.unwrap();
        let token_b = result_b.unwrap();

        assert_eq!(token_a.as_str(), "new-token");
        assert_eq!(token_b.as_str(), "new-token");
    }

    #[tokio::test]
    async fn test_concurrent_access_expired_token() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("refreshed-token", 3600));
        });
        let server = start_server(mocks).await;

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            server.url(""),
            None,
            default_transport(),
        );
        let strategy = Arc::new(AutoRefresh::with_token(
            refresher,
            make_expired_token("old-token"),
        ));

        let s1 = Arc::clone(&strategy);
        let handle_a = tokio::spawn(async move { s1.get_token().await.unwrap() });

        let s2 = Arc::clone(&strategy);
        let handle_b = tokio::spawn(async move { s2.get_token().await.unwrap() });

        let (result_a, result_b) = tokio::join!(handle_a, handle_b);
        let token_a = result_a.unwrap();
        let token_b = result_b.unwrap();

        assert_eq!(token_a.as_str(), "refreshed-token");
        assert_eq!(token_b.as_str(), "refreshed-token");
    }

    // ---- Concurrent access: expiring but usable ----

    #[tokio::test]
    async fn test_concurrent_access_expiring_but_usable() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("refreshed-token", 3600));
        });
        let server = start_server(mocks).await;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiring_token = Token {
            access_token: SecretToken::new("still-usable"),
            token_type: "Bearer".to_string(),
            expires_at: now + 30, // is_expired() = true (within 90s), is_usable() = true
            refresh_token: None,
            region: None,
            client_id: None,
            device_instance_id: None,
        };

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            server.url(""),
            None,
            default_transport(),
        );
        let strategy = Arc::new(AutoRefresh::with_token(refresher, expiring_token));

        let s1 = Arc::clone(&strategy);
        let handle_a = tokio::spawn(async move { s1.get_token().await.unwrap() });

        let s2 = Arc::clone(&strategy);
        let handle_b = tokio::spawn(async move { s2.get_token().await.unwrap() });

        let (result_a, result_b) = tokio::join!(handle_a, handle_b);
        let token_a = result_a.unwrap();
        let token_b = result_b.unwrap();

        // Both should succeed with either old or refreshed token.
        assert!(
            token_a.as_str() == "still-usable" || token_a.as_str() == "refreshed-token",
            "unexpected token_a: {}",
            token_a.as_str()
        );
        assert!(
            token_b.as_str() == "still-usable" || token_b.as_str() == "refreshed-token",
            "unexpected token_b: {}",
            token_b.as_str()
        );
    }

    // ---- Stress tests ----

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    #[derive(Clone)]
    struct CountingState {
        total: Arc<AtomicUsize>,
        current: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    impl CountingState {
        fn new() -> Self {
            Self {
                total: Arc::new(AtomicUsize::new(0)),
                current: Arc::new(AtomicUsize::new(0)),
                peak: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn enter(&self) {
            self.total.fetch_add(1, Ordering::SeqCst);
            let prev = self.current.fetch_add(1, Ordering::SeqCst);
            self.peak.fetch_max(prev + 1, Ordering::SeqCst);
        }

        fn exit(&self) {
            self.current.fetch_sub(1, Ordering::SeqCst);
        }

        fn peak(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }

        fn total(&self) -> usize {
            self.total.load(Ordering::SeqCst)
        }
    }

    #[derive(Clone)]
    struct DelayedAuthState {
        counting: CountingState,
        delay: Duration,
    }

    async fn delayed_auth_handler(
        axum::extract::State(state): axum::extract::State<DelayedAuthState>,
    ) -> axum::Json<serde_json::Value> {
        state.counting.enter();
        tokio::time::sleep(state.delay).await;
        state.counting.exit();
        // CTS returns `expiry` as an absolute epoch (JWT `exp`); model a token
        // valid for 1 hour from now.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        axum::Json(serde_json::json!({
            "accessToken": "refreshed-token",
            "expiry": now + 3600
        }))
    }

    async fn start_axum_server(state: DelayedAuthState) -> (Url, CountingState) {
        let counting = state.counting.clone();
        let app = axum::Router::new()
            .route("/api/authorise", axum::routing::post(delayed_auth_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base_url = Url::parse(&format!("http://{addr}")).unwrap();
        (base_url, counting)
    }

    const CONCURRENCY: usize = 50;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_stress_initial_auth() {
        let state = DelayedAuthState {
            counting: CountingState::new(),
            delay: Duration::from_millis(200),
        };
        let (base_url, stats) = start_axum_server(state).await;

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            base_url,
            None,
            default_transport(),
        );
        let strategy = Arc::new(AutoRefresh::with_store(refresher, crate::NoStore));

        let start = Instant::now();
        let mut handles = Vec::with_capacity(CONCURRENCY);
        for _ in 0..CONCURRENCY {
            let s = Arc::clone(&strategy);
            handles.push(tokio::spawn(async move { s.get_token().await.unwrap() }));
        }

        let results: Vec<_> = {
            let mut results = Vec::with_capacity(handles.len());
            for handle in handles {
                results.push(handle.await.unwrap());
            }
            results
        };
        let elapsed = start.elapsed();

        for token in &results {
            assert_eq!(token.as_str(), "refreshed-token");
        }

        assert!(
            elapsed < Duration::from_millis(600),
            "expected < 600ms, got {:?}",
            elapsed
        );
        assert_eq!(stats.total(), 1, "only one auth request should be made");
        assert_eq!(stats.peak(), 1, "peak concurrency to auth endpoint");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_stress_cached_token() {
        let state = DelayedAuthState {
            counting: CountingState::new(),
            delay: Duration::from_millis(500),
        };
        let (base_url, stats) = start_axum_server(state).await;

        // Pre-authenticate.
        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            base_url,
            None,
            default_transport(),
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = Token {
            access_token: SecretToken::new("cached-token"),
            token_type: "Bearer".to_string(),
            expires_at: now + 3600,
            refresh_token: None,
            region: None,
            client_id: None,
            device_instance_id: None,
        };
        let strategy = Arc::new(AutoRefresh::with_token(refresher, token));

        let start = Instant::now();
        let mut handles = Vec::with_capacity(CONCURRENCY);
        for _ in 0..CONCURRENCY {
            let s = Arc::clone(&strategy);
            handles.push(tokio::spawn(async move { s.get_token().await.unwrap() }));
        }

        let results: Vec<_> = {
            let mut results = Vec::with_capacity(handles.len());
            for handle in handles {
                results.push(handle.await.unwrap());
            }
            results
        };
        let elapsed = start.elapsed();

        for token in &results {
            assert_eq!(token.as_str(), "cached-token");
        }

        assert!(
            elapsed < Duration::from_millis(200),
            "expected < 200ms for cached tokens, got {:?}",
            elapsed
        );
        assert_eq!(stats.total(), 0, "no auth requests should be made");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_stress_expiring_but_usable_non_blocking() {
        let state = DelayedAuthState {
            counting: CountingState::new(),
            delay: Duration::from_millis(500),
        };
        let (base_url, stats) = start_axum_server(state).await;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiring_token = Token {
            access_token: SecretToken::new("still-usable"),
            token_type: "Bearer".to_string(),
            expires_at: now + 30,
            refresh_token: None,
            region: None,
            client_id: None,
            device_instance_id: None,
        };
        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            base_url,
            None,
            default_transport(),
        );
        let strategy = Arc::new(AutoRefresh::with_token(refresher, expiring_token));

        let start = Instant::now();
        let mut handles = Vec::with_capacity(CONCURRENCY);
        for _ in 0..CONCURRENCY {
            let s = Arc::clone(&strategy);
            handles.push(tokio::spawn(async move {
                let call_start = Instant::now();
                let token = s.get_token().await.unwrap();
                (token, call_start.elapsed())
            }));
        }

        let results: Vec<_> = {
            let mut results = Vec::with_capacity(handles.len());
            for handle in handles {
                results.push(handle.await.unwrap());
            }
            results
        };
        let _elapsed = start.elapsed();

        for (token, _) in &results {
            assert!(
                token.as_str() == "still-usable" || token.as_str() == "refreshed-token",
                "unexpected token: {}",
                token.as_str()
            );
        }

        // At least N-1 callers should be fast (non-blocking).
        let fast_callers = results
            .iter()
            .filter(|(_, dur)| *dur < Duration::from_millis(100))
            .count();
        assert!(
            fast_callers >= CONCURRENCY - 1,
            "expected at least {} fast callers, got {}",
            CONCURRENCY - 1,
            fast_callers,
        );

        assert_eq!(stats.peak(), 1, "peak concurrency to auth endpoint");
        assert_eq!(stats.total(), 1, "total auth requests");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_stress_expired_token_blocks() {
        let refresh_delay = Duration::from_millis(200);
        let state = DelayedAuthState {
            counting: CountingState::new(),
            delay: refresh_delay,
        };
        let (base_url, stats) = start_axum_server(state).await;

        let refresher = AccessKeyRefresher::new(
            SecretToken::new("test-access-key"),
            base_url,
            None,
            default_transport(),
        );
        let strategy = Arc::new(AutoRefresh::with_token(
            refresher,
            make_expired_token("old-token"),
        ));

        let start = Instant::now();
        let mut handles = Vec::with_capacity(CONCURRENCY);
        for _ in 0..CONCURRENCY {
            let s = Arc::clone(&strategy);
            handles.push(tokio::spawn(async move { s.get_token().await.unwrap() }));
        }

        let results: Vec<_> = {
            let mut results = Vec::with_capacity(handles.len());
            for handle in handles {
                results.push(handle.await.unwrap());
            }
            results
        };
        let elapsed = start.elapsed();

        for token in &results {
            assert_eq!(token.as_str(), "refreshed-token");
        }

        assert!(
            elapsed < refresh_delay + Duration::from_millis(200),
            "expected < {:?}, got {:?}",
            refresh_delay + Duration::from_millis(200),
            elapsed
        );

        assert_eq!(stats.peak(), 1, "peak concurrency to auth endpoint");
        assert_eq!(stats.total(), 1, "total auth requests");
    }
}
