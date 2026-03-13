use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use url::Url;

use crate::refresher::Refresher;
use crate::{http_client, AuthError, SecretToken, Token};

/// A [`Refresher`] that uses a static access key to authenticate.
///
/// Unlike OAuth, the access key never changes — `try_credential` always returns
/// `Some(())` and `restore` is a no-op. This means `AutoRefresh` can perform
/// initial authentication on the first `get_token()` call (cold start).
pub(crate) struct AccessKeyRefresher {
    access_key: SecretToken,
    base_url: Url,
    audience: Option<String>,
    http_client: Arc<reqwest::Client>,
}

impl AccessKeyRefresher {
    pub(crate) fn new(access_key: SecretToken, base_url: Url, audience: Option<String>) -> Self {
        Self {
            access_key,
            base_url,
            audience,
            http_client: Arc::new(http_client()),
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

        let resp = self
            .http_client
            .post(url)
            .json(&AuthoriseRequest {
                access_key: self.access_key.as_str(),
                audience: self.audience.as_deref(),
            })
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::debug!(%status, %body, "access key auth failed");
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
struct AuthoriseRequest<'a> {
    access_key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<&'a str>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthoriseResponse {
    access_token: SecretToken,
    expiry: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto_refresh::{AutoRefresh, AutoRefreshError};
    use mocktail::prelude::*;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn auth_response_json(access: &str, expiry: u64) -> serde_json::Value {
        serde_json::json!({
            "accessToken": access,
            "expiry": expiry
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
        );
        AutoRefresh::new(refresher)
    }

    fn make_expired_token(access: &str) -> Token {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Token {
            access_token: SecretToken::new(access),
            token_type: "Bearer".to_string(),
            expires_at: now, // already expired
            refresh_token: None,
            region: None,
            client_id: None,
            device_instance_id: None,
        }
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

    // ---- Refresh on expiry tests ----

    #[tokio::test]
    async fn test_re_authenticates_on_expiry() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.json(auth_response_json("refreshed-token", 3600));
        });
        let server = start_server(mocks).await;

        let refresher =
            AccessKeyRefresher::new(SecretToken::new("test-access-key"), server.url(""), None);
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
    async fn test_refresh_failure_returns_expired() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.unauthorized()
                .json(serde_json::json!({"error": "invalid key"}));
        });
        let server = start_server(mocks).await;

        let refresher =
            AccessKeyRefresher::new(SecretToken::new("test-access-key"), server.url(""), None);
        let strategy = AutoRefresh::with_token(refresher, make_expired_token("old-token"));

        let err = strategy.get_token().await.unwrap_err();

        assert!(matches!(err, AutoRefreshError::Expired));
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

        let refresher =
            AccessKeyRefresher::new(SecretToken::new("test-access-key"), server.url(""), None);
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

        let refresher =
            AccessKeyRefresher::new(SecretToken::new("test-access-key"), server.url(""), None);
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

    use std::sync::atomic::{AtomicUsize, Ordering};
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
        axum::Json(serde_json::json!({
            "accessToken": "refreshed-token",
            "expiry": 3600
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

        let refresher =
            AccessKeyRefresher::new(SecretToken::new("test-access-key"), base_url, None);
        let strategy = Arc::new(AutoRefresh::new(refresher));

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
        let refresher =
            AccessKeyRefresher::new(SecretToken::new("test-access-key"), base_url, None);
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
        let refresher =
            AccessKeyRefresher::new(SecretToken::new("test-access-key"), base_url, None);
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

        let refresher =
            AccessKeyRefresher::new(SecretToken::new("test-access-key"), base_url, None);
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
