use tokio::sync::Mutex;

use crate::refresher::Refresher;
use crate::{SecretToken, Token};

/// Internal errors from [`AutoRefresh::get_token`].
///
/// Strategy wrappers convert these into [`AuthError`](crate::AuthError) for the
/// public API.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AutoRefreshError {
    /// No token is cached and the strategy cannot self-authenticate.
    #[error("No token found")]
    NotFound,
    /// The token has expired and refresh failed or is unavailable.
    #[error("Token has expired")]
    Expired,
    /// The refresh/auth HTTP call failed.
    #[error("Auth error: {0}")]
    Auth(#[from] crate::AuthError),
}

impl From<AutoRefreshError> for crate::AuthError {
    fn from(err: AutoRefreshError) -> Self {
        match err {
            AutoRefreshError::NotFound => crate::AuthError::NotAuthenticated,
            AutoRefreshError::Expired => crate::AuthError::TokenExpired,
            AutoRefreshError::Auth(e) => e,
        }
    }
}

/// Caches a token in memory and uses a [`Refresher`] to re-authenticate
/// or refresh before expiry.
///
/// # Concurrency model
///
/// Internal state is protected by a [`tokio::sync::Mutex`]. The key design
/// decision is *when* the lock is held during a refresh, which depends on
/// whether the current token is still usable as a bearer credential:
///
/// - [`Token::is_expired()`] — returns `true` when the token is within **90
///   seconds** of its `expires_at` timestamp. This triggers a preemptive
///   refresh attempt.
/// - [`Token::is_usable()`] — returns `true` when the token has **not yet
///   reached** its `expires_at` timestamp. A token can be "expired" (in the
///   leeway sense) but still "usable" (the server will still accept it).
///
/// This distinction enables two concurrent refresh strategies:
///
/// 1. **Expiring but still usable** — The refreshing caller drops the lock
///    before making the HTTP request. Concurrent callers acquire the lock and
///    receive the current (still-valid) token immediately.
/// 2. **Fully expired** — The refreshing caller holds the lock through the
///    HTTP request. Concurrent callers block on `lock().await` until the
///    refresh completes, then see the new token.
///
/// Cascade prevention: the `refresh_in_progress` flag prevents multiple
/// callers from initiating concurrent refreshes.
///
/// # Flow diagram
///
/// ```mermaid
/// flowchart TD
///     Start["get_token()"] --> Lock["Acquire lock"]
///     Lock --> Cached{Token cached?}
///     Cached -- No --> TryCred0["try_credential(None)"]
///     TryCred0 -- None --> ErrNotFound["Return NotFound"]
///     TryCred0 -- "Some(cred)" --> InitAuth["refresh(cred)
///     (lock HELD)"]
///     InitAuth -- OK --> SaveInit["save + cache token"]
///     SaveInit --> ReturnNew["Return Ok(new token)"]
///     InitAuth -- Err --> ErrAuth["Return Auth(err)"]
///     Cached -- Yes --> CheckRefresh{is_expired?}
///
///     CheckRefresh -- "No (fresh)" --> CloneFresh["Clone access token,
///     release lock"]
///     CloneFresh --> ReturnOk["Return Ok(token)"]
///
///     CheckRefresh -- "Yes (needs refresh)" --> InProgress{refresh_in_progress?}
///     InProgress -- Yes --> Usable0{is_usable?}
///     Usable0 -- Yes --> CloneUsable0["Clone access token"]
///     CloneUsable0 --> ReturnOk
///     Usable0 -- No --> ErrExpired["Return Expired"]
///
///     InProgress -- No --> TryCred{try_credential}
///     TryCred -- None --> Usable1{is_usable?}
///     Usable1 -- Yes --> CloneUsable1["Clone access token"]
///     CloneUsable1 --> ReturnOk
///     Usable1 -- No --> ErrExpired
///
///     TryCred -- "Some(cred)" --> SetFlag["refresh_in_progress = true"]
///     SetFlag --> Usable2{is_usable?}
///
///     Usable2 -- "Yes (expiring but usable)" --> DropLock["Clone access token,
///     release lock"]
///     DropLock --> HTTP1["refresh(cred)
///     (lock NOT held)"]
///     HTTP1 -- OK --> Relock1["Re-acquire lock,
///     save + cache, clear flag"]
///     HTTP1 -- Err --> Restore1["Restore credential,
///     clear flag"]
///     Relock1 --> ReturnOld["Return Ok(old token)"]
///     Restore1 --> ReturnOld
///
///     Usable2 -- "No (fully expired)" --> HTTP2["refresh(cred)
///     (lock HELD)"]
///     HTTP2 -- OK --> StoreNew["save + cache,
///     clear flag, release lock"]
///     StoreNew --> ReturnNew2["Return Ok(new token)"]
///     HTTP2 -- Err --> Restore2["Restore credential,
///     clear flag"]
///     Restore2 --> ErrExpired
/// ```
#[cfg_attr(doc, aquamarine::aquamarine)]
pub(crate) struct AutoRefresh<R> {
    refresher: R,
    state: Mutex<State>,
}

struct State {
    token: Option<Token>,
    refresh_in_progress: bool,
}

impl<R> AutoRefresh<R> {
    /// Create a new `AutoRefresh` with no initial token.
    ///
    /// The first call to `get_token` will attempt initial authentication via
    /// `try_credential(None)` → `refresh()`. Use this for refreshers that can
    /// self-authenticate (e.g. access keys).
    pub(crate) fn new(refresher: R) -> Self {
        Self {
            refresher,
            state: Mutex::new(State {
                token: None,
                refresh_in_progress: false,
            }),
        }
    }

    /// Create a new `AutoRefresh` with a pre-loaded token.
    ///
    /// Use this for refreshers that cannot self-authenticate (e.g. OAuth,
    /// which needs a refresh token from a prior device code flow).
    pub(crate) fn with_token(refresher: R, token: Token) -> Self {
        Self {
            refresher,
            state: Mutex::new(State {
                token: Some(token),
                refresh_in_progress: false,
            }),
        }
    }
}

impl<R: Refresher> AutoRefresh<R> {
    /// Retrieve a valid access token, refreshing or re-authenticating as needed.
    pub(crate) async fn get_token(&self) -> Result<SecretToken, AutoRefreshError> {
        let mut state = self.state.lock().await;

        // No cached token — attempt initial auth.
        if state.token.is_none() {
            let Some(credential) = self.refresher.try_credential(None) else {
                return Err(AutoRefreshError::NotFound);
            };
            state.refresh_in_progress = true;
            match self.refresher.refresh(&credential).await {
                Ok(new_token) => {
                    self.refresher.save(&new_token);
                    let access_token = new_token.access_token().clone();
                    state.token = Some(new_token);
                    state.refresh_in_progress = false;
                    return Ok(access_token);
                }
                Err(err) => {
                    state.refresh_in_progress = false;
                    return Err(AutoRefreshError::Auth(err));
                }
            }
        }

        let needs_refresh = state.token.as_ref().is_some_and(|t| t.is_expired());
        if !needs_refresh {
            // Token is fresh — clone and return.
            let token = state.token.as_ref().ok_or(AutoRefreshError::NotFound)?;
            return Ok(token.access_token().clone());
        }

        // Check cascade prevention flag.
        if state.refresh_in_progress {
            let token = state.token.as_ref().ok_or(AutoRefreshError::NotFound)?;
            if token.is_usable() {
                return Ok(token.access_token().clone());
            }
            // NOTE: If a refresh was started while the token was still usable
            // (lock released) but the token has since crossed its real expiry,
            // we return Expired rather than waiting for the in-flight refresh.
            // This is a deliberate trade-off: adding a Notify/condvar to wait
            // for the in-flight refresh would increase complexity, and the
            // window is narrow (token must expire during the HTTP call). The
            // 90s leeway on is_expired() makes this unlikely. Callers can
            // retry and will get the new token once the refresh completes.
            return Err(AutoRefreshError::Expired);
        }

        // Token needs refresh. Try to get a credential.
        let credential = self.refresher.try_credential(state.token.as_mut());

        let Some(credential) = credential else {
            // No credential available (e.g. OAuth with no refresh token).
            let token = state.token.as_ref().ok_or(AutoRefreshError::NotFound)?;
            if token.is_usable() {
                return Ok(token.access_token().clone());
            }
            return Err(AutoRefreshError::Expired);
        };

        state.refresh_in_progress = true;

        // Check if the current token is still usable.
        let is_usable = state.token.as_ref().is_some_and(|t| t.is_usable());

        if is_usable {
            // Token is expiring but still usable. Clone the current access
            // token, drop the lock, and refresh in the background of this call.
            let current_access_token = state
                .token
                .as_ref()
                .ok_or(AutoRefreshError::NotFound)?
                .access_token()
                .clone();
            drop(state);

            match self.refresher.refresh(&credential).await {
                Ok(new_token) => {
                    self.refresher.save(&new_token);
                    let mut state = self.state.lock().await;
                    state.token = Some(new_token);
                    state.refresh_in_progress = false;
                }
                Err(err) => {
                    tracing::warn!(%err, "token refresh failed (token still usable)");
                    let mut state = self.state.lock().await;
                    if let Some(token) = state.token.as_mut() {
                        self.refresher.restore(token, credential);
                    }
                    state.refresh_in_progress = false;
                }
            }

            Ok(current_access_token)
        } else {
            // Token is fully expired. Refresh while holding the lock.
            match self.refresher.refresh(&credential).await {
                Ok(new_token) => {
                    self.refresher.save(&new_token);
                    let access_token = new_token.access_token().clone();
                    state.token = Some(new_token);
                    state.refresh_in_progress = false;
                    Ok(access_token)
                }
                Err(err) => {
                    tracing::warn!(%err, "token refresh failed");
                    if let Some(token) = state.token.as_mut() {
                        self.refresher.restore(token, credential);
                    }
                    state.refresh_in_progress = false;
                    Err(AutoRefreshError::Expired)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth_refresher::OAuthRefresher;
    use crate::TokenStore;
    use mocktail::prelude::*;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_token(access: &str, expires_in: u64, refresh: bool) -> Token {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Token {
            access_token: SecretToken::new(access),
            token_type: "Bearer".to_string(),
            expires_at: now + expires_in,
            refresh_token: if refresh {
                Some(SecretToken::new("test-refresh-token"))
            } else {
                None
            },
            region: None,
            client_id: None,
            device_instance_id: None,
        }
    }

    fn refresh_response_json(access: &str) -> serde_json::Value {
        serde_json::json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new-refresh-token"
        })
    }

    fn error_json(error: &str) -> serde_json::Value {
        serde_json::json!({
            "error": error,
            "error_description": format!("{error} occurred")
        })
    }

    async fn start_server(mocks: MockSet) -> MockServer {
        let server = MockServer::new_http("auto-refresh-test").with_mocks(mocks);
        server.start().await.unwrap();
        server
    }

    fn auto_refresh_with_token(
        dir: &tempfile::TempDir,
        server: &MockServer,
        token: Token,
    ) -> AutoRefresh<OAuthRefresher> {
        let store = TokenStore::new(dir.path());
        store.save("auth.json", &token).unwrap();
        let refresher = OAuthRefresher::new(
            Some(store),
            server.url(""),
            "cli",
            "ap-southeast-2.aws",
            None,
        );
        AutoRefresh::with_token(refresher, token)
    }

    // ---- Basic loading tests ----

    #[tokio::test]
    async fn test_returns_cached_token() {
        let dir = tempfile::tempdir().unwrap();
        let server = start_server(MockSet::new()).await;
        let strategy =
            auto_refresh_with_token(&dir, &server, make_token("my-access-token", 3600, false));

        let token = strategy.get_token().await.unwrap();

        assert_eq!(token.as_str(), "my-access-token");
    }

    #[tokio::test]
    async fn test_returns_not_found_when_no_token_and_oauth() {
        let server = start_server(MockSet::new()).await;
        let store = TokenStore::new("/tmp/nonexistent");
        let refresher = OAuthRefresher::new(
            Some(store),
            server.url(""),
            "cli",
            "ap-southeast-2.aws",
            None,
        );
        let strategy = AutoRefresh::new(refresher);

        let err = strategy.get_token().await.unwrap_err();

        assert!(matches!(err, AutoRefreshError::NotFound));
    }

    #[tokio::test]
    async fn test_caches_token_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        let server = start_server(MockSet::new()).await;
        let strategy =
            auto_refresh_with_token(&dir, &server, make_token("my-access-token", 3600, false));

        let token1 = strategy.get_token().await.unwrap();
        assert_eq!(token1.as_str(), "my-access-token");

        // Delete the file — second call should still return the cached token.
        std::fs::remove_file(dir.path().join("auth.json")).unwrap();

        let token2 = strategy.get_token().await.unwrap();
        assert_eq!(token2.as_str(), "my-access-token");
    }

    // ---- Expiry tests ----

    #[tokio::test]
    async fn test_expired_token_without_refresh_token_returns_expired() {
        let dir = tempfile::tempdir().unwrap();
        let server = start_server(MockSet::new()).await;
        let strategy = auto_refresh_with_token(&dir, &server, make_token("old-token", 0, false));

        let err = strategy.get_token().await.unwrap_err();

        assert!(matches!(err, AutoRefreshError::Expired));
    }

    // ---- Refresh tests ----

    #[tokio::test]
    async fn test_refreshes_expiring_token() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-token"));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

        let token = strategy.get_token().await.unwrap();

        assert_eq!(token.as_str(), "refreshed-token");
    }

    #[tokio::test]
    async fn test_refresh_persists_new_token_to_disk() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-token"));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

        let _ = strategy.get_token().await.unwrap();

        // Verify the refreshed token was saved to disk.
        let store = TokenStore::new(dir.path());
        let on_disk: Token = store.load("auth.json").unwrap();
        assert_eq!(on_disk.access_token().as_str(), "refreshed-token");
    }

    #[tokio::test]
    async fn test_refresh_failure_returns_expired_when_token_is_expired() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.bad_request().json(error_json("invalid_grant"));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

        let err = strategy.get_token().await.unwrap_err();

        assert!(matches!(err, AutoRefreshError::Expired));
    }

    #[tokio::test]
    async fn test_does_not_refresh_fresh_token() {
        // Mock that would fail if hit — proves no refresh request is made.
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.internal_server_error()
                .json(error_json("should_not_be_called"));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy =
            auto_refresh_with_token(&dir, &server, make_token("fresh-token", 3600, true));

        let token = strategy.get_token().await.unwrap();

        assert_eq!(token.as_str(), "fresh-token");
    }

    // ---- Cascade prevention tests ----

    #[tokio::test]
    async fn test_refresh_token_is_taken_preventing_second_refresh() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-token"));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

        // First call refreshes successfully.
        let token = strategy.get_token().await.unwrap();
        assert_eq!(token.as_str(), "refreshed-token");

        // Replace the mock with one that errors.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/oauth/token");
            then.bad_request().json(error_json("should_not_be_called"));
        });

        // Second call should return the refreshed token without hitting
        // the server again (the new token has a fresh expiry).
        let token = strategy.get_token().await.unwrap();
        assert_eq!(token.as_str(), "refreshed-token");
    }

    #[tokio::test]
    async fn test_failed_refresh_restores_refresh_token_for_retry() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.bad_request().json(error_json("invalid_grant"));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

        // First call: refresh fails, returns Expired.
        let err = strategy.get_token().await.unwrap_err();
        assert!(matches!(err, AutoRefreshError::Expired));

        // Verify the refresh token was restored so a retry is possible.
        let state = strategy.state.lock().await;
        assert!(state.token.is_some());
        assert!(state.token.as_ref().unwrap().refresh_token().is_some());
        drop(state);

        // Replace mock with a success response.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-token"));
        });

        // Second call: refresh token is available → retry succeeds.
        let token = strategy.get_token().await.unwrap();
        assert_eq!(token.as_str(), "refreshed-token");
    }

    #[tokio::test]
    async fn test_access_token_remains_after_refresh_token_is_taken() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.bad_request().json(error_json("server_error"));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();
        // Token expires in 30s (within the 90s leeway so is_expired() = true),
        // but the access token is still technically usable.
        let strategy = auto_refresh_with_token(&dir, &server, make_token("still-usable", 30, true));

        // The refresh fails, but the access token should still be returned
        // because it's still usable (30s remaining > 0).
        let token = strategy.get_token().await.unwrap();
        assert_eq!(token.as_str(), "still-usable");

        // Verify the access token and refresh token are still present.
        let state = strategy.state.lock().await;
        assert!(state.token.is_some());
        assert_eq!(
            state.token.as_ref().unwrap().access_token().as_str(),
            "still-usable"
        );
        assert!(
            state.token.as_ref().unwrap().refresh_token().is_some(),
            "refresh token should be restored after failed refresh"
        );
    }

    #[tokio::test]
    async fn test_failed_refresh_of_usable_token_can_be_retried() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.bad_request().json(error_json("server_error"));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();
        // Token expires in 30s — is_expired() = true, is_usable() = true.
        let strategy = auto_refresh_with_token(&dir, &server, make_token("still-usable", 30, true));

        // First call: refresh fails, but the still-usable token is returned.
        let token = strategy.get_token().await.unwrap();
        assert_eq!(token.as_str(), "still-usable");

        // Replace mock with a success response.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-token"));
        });

        // Second call: refresh token was restored, so the retry succeeds.
        let token = strategy.get_token().await.unwrap();
        assert!(
            token.as_str() == "still-usable" || token.as_str() == "refreshed-token",
            "expected old or refreshed token, got: {}",
            token.as_str()
        );

        // Verify the cache now holds the refreshed token.
        let state = strategy.state.lock().await;
        assert_eq!(
            state.token.as_ref().unwrap().access_token().as_str(),
            "refreshed-token"
        );
    }

    #[tokio::test]
    async fn test_multiple_sequential_calls_only_refresh_once() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-once"));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

        // First call triggers refresh.
        let token = strategy.get_token().await.unwrap();
        assert_eq!(token.as_str(), "refreshed-once");

        // Swap mock to track if another refresh is attempted.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-twice"));
        });

        // Calls 2-5: the refreshed token is fresh, so no further refresh.
        for _ in 0..4 {
            let token = strategy.get_token().await.unwrap();
            assert_eq!(
                token.as_str(),
                "refreshed-once",
                "should return cached refreshed token, not trigger another refresh"
            );
        }
    }

    // ---- Concurrent access tests ----

    #[tokio::test]
    async fn test_concurrent_access_with_expiring_but_usable_token() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-token"));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = Arc::new(auto_refresh_with_token(
            &dir,
            &server,
            make_token("still-usable", 30, true),
        ));

        let s1 = Arc::clone(&strategy);
        let handle_a = tokio::spawn(async move { s1.get_token().await.unwrap() });

        let s2 = Arc::clone(&strategy);
        let handle_b = tokio::spawn(async move { s2.get_token().await.unwrap() });

        let (result_a, result_b) = tokio::join!(handle_a, handle_b);
        let token_a = result_a.unwrap();
        let token_b = result_b.unwrap();

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

    #[tokio::test]
    async fn test_concurrent_access_with_fully_expired_token() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-token"));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = Arc::new(auto_refresh_with_token(
            &dir,
            &server,
            make_token("expired-token", 0, true),
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
}

#[cfg(test)]
mod stress_tests {
    use super::*;
    use crate::oauth_refresher::OAuthRefresher;
    use crate::TokenStore;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    /// Tracks in-flight and peak concurrency for test assertions.
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
    struct DelayedRefreshState {
        counting: CountingState,
        delay: Duration,
    }

    async fn delayed_refresh_handler(
        axum::extract::State(state): axum::extract::State<DelayedRefreshState>,
    ) -> axum::Json<serde_json::Value> {
        state.counting.enter();
        tokio::time::sleep(state.delay).await;
        state.counting.exit();
        axum::Json(serde_json::json!({
            "access_token": "refreshed-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new-refresh-token"
        }))
    }

    async fn delayed_error_handler(
        axum::extract::State(state): axum::extract::State<DelayedRefreshState>,
    ) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
        state.counting.enter();
        tokio::time::sleep(state.delay).await;
        state.counting.exit();
        (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "invalid_grant occurred"
            })),
        )
    }

    async fn start_axum_server<H, T>(
        handler: H,
        state: DelayedRefreshState,
    ) -> (url::Url, CountingState)
    where
        H: axum::handler::Handler<T, DelayedRefreshState> + Clone + Send + 'static,
        T: 'static,
    {
        let counting = state.counting.clone();
        let app = axum::Router::new()
            .route("/oauth/token", axum::routing::post(handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base_url = url::Url::parse(&format!("http://{addr}")).unwrap();
        (base_url, counting)
    }

    fn make_token(access: &str, expires_in: u64, refresh: bool) -> Token {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Token {
            access_token: SecretToken::new(access),
            token_type: "Bearer".to_string(),
            expires_at: now + expires_in,
            refresh_token: if refresh {
                Some(SecretToken::new("test-refresh-token"))
            } else {
                None
            },
            region: None,
            client_id: None,
            device_instance_id: None,
        }
    }

    fn auto_refresh_with_token(
        dir: &tempfile::TempDir,
        base_url: &url::Url,
        token: Token,
    ) -> AutoRefresh<OAuthRefresher> {
        let store = TokenStore::new(dir.path());
        store.save("auth.json", &token).unwrap();
        let refresher = OAuthRefresher::new(
            Some(store),
            base_url.clone(),
            "cli",
            "ap-southeast-2.aws",
            None,
        );
        AutoRefresh::with_token(refresher, token)
    }

    const CONCURRENCY: usize = 50;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_fresh_token_no_contention() {
        let counting = CountingState::new();
        let state = DelayedRefreshState {
            counting: counting.clone(),
            delay: Duration::from_millis(500),
        };
        let (base_url, stats) = start_axum_server(delayed_refresh_handler, state).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = Arc::new(auto_refresh_with_token(
            &dir,
            &base_url,
            make_token("fresh-token", 3600, true),
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
            assert_eq!(token.as_str(), "fresh-token");
        }

        assert!(
            elapsed < Duration::from_millis(200),
            "expected < 200ms for fresh tokens, got {:?}",
            elapsed
        );
        assert_eq!(stats.total(), 0, "no refresh requests should be made");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_expiring_token_non_blocking_reads() {
        let counting = CountingState::new();
        let state = DelayedRefreshState {
            counting: counting.clone(),
            delay: Duration::from_millis(500),
        };
        let (base_url, stats) = start_axum_server(delayed_refresh_handler, state).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = Arc::new(auto_refresh_with_token(
            &dir,
            &base_url,
            make_token("still-usable", 30, true),
        ));

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
        let elapsed = start.elapsed();

        for (token, _) in &results {
            assert!(
                token.as_str() == "still-usable" || token.as_str() == "refreshed-token",
                "unexpected token: {}",
                token.as_str()
            );
        }

        let fast_callers = results
            .iter()
            .filter(|(_, dur)| *dur < Duration::from_millis(100))
            .count();
        assert!(
            fast_callers >= CONCURRENCY - 1,
            "expected at least {} fast callers, got {} (total elapsed: {:?})",
            CONCURRENCY - 1,
            fast_callers,
            elapsed
        );

        assert_eq!(stats.peak(), 1, "peak concurrency to refresh endpoint");
        assert_eq!(stats.total(), 1, "total refresh requests");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_expired_token_blocks_until_refresh() {
        let refresh_delay = Duration::from_millis(200);
        let counting = CountingState::new();
        let state = DelayedRefreshState {
            counting: counting.clone(),
            delay: refresh_delay,
        };
        let (base_url, stats) = start_axum_server(delayed_refresh_handler, state).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = Arc::new(auto_refresh_with_token(
            &dir,
            &base_url,
            make_token("expired-token", 0, true),
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
            "expected < {:?} for blocked callers, got {:?}",
            refresh_delay + Duration::from_millis(200),
            elapsed
        );

        assert_eq!(stats.peak(), 1, "peak concurrency to refresh endpoint");
        assert_eq!(stats.total(), 1, "total refresh requests");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_expired_token_refresh_failure_recovers() {
        let counting = CountingState::new();
        let state = DelayedRefreshState {
            counting: counting.clone(),
            delay: Duration::from_millis(10),
        };
        let (base_url, stats) = start_axum_server(delayed_error_handler, state).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = Arc::new(auto_refresh_with_token(
            &dir,
            &base_url,
            make_token("expired-token", 0, true),
        ));

        let mut handles = Vec::with_capacity(CONCURRENCY);
        for _ in 0..CONCURRENCY {
            let s = Arc::clone(&strategy);
            handles.push(tokio::spawn(async move { s.get_token().await }));
        }

        let results: Vec<_> = {
            let mut results = Vec::with_capacity(handles.len());
            for handle in handles {
                results.push(handle.await.unwrap());
            }
            results
        };

        for result in &results {
            assert!(result.is_err(), "expected Expired error, got Ok");
            assert!(matches!(
                result.as_ref().unwrap_err(),
                AutoRefreshError::Expired
            ));
        }

        let state = strategy.state.lock().await;
        assert!(
            state.token.as_ref().unwrap().refresh_token().is_some(),
            "refresh token should be restored after failed refresh"
        );
        drop(state);

        assert_eq!(stats.peak(), 1, "peak concurrency to refresh endpoint");
        assert!(
            stats.total() >= 1,
            "at least one refresh attempt should be made"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_refresh_failure_then_retry() {
        // Phase 1: Server returns errors.
        let counting1 = CountingState::new();
        let state1 = DelayedRefreshState {
            counting: counting1.clone(),
            delay: Duration::from_millis(50),
        };
        let (base_url, _) = start_axum_server(delayed_error_handler, state1).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = Arc::new(auto_refresh_with_token(
            &dir,
            &base_url,
            make_token("expired-token", 0, true),
        ));

        let mut handles = Vec::with_capacity(CONCURRENCY);
        for _ in 0..CONCURRENCY {
            let s = Arc::clone(&strategy);
            handles.push(tokio::spawn(async move { s.get_token().await }));
        }

        let results: Vec<_> = {
            let mut results = Vec::with_capacity(handles.len());
            for handle in handles {
                results.push(handle.await.unwrap());
            }
            results
        };

        for result in &results {
            assert!(
                result.is_err(),
                "first wave: expected Expired, got Ok({})",
                result.as_ref().unwrap().as_str()
            );
        }

        // Phase 2: New server that returns success.
        let counting2 = CountingState::new();
        let state2 = DelayedRefreshState {
            counting: counting2.clone(),
            delay: Duration::from_millis(50),
        };
        let (base_url2, stats2) = start_axum_server(delayed_refresh_handler, state2).await;

        let strategy2 = Arc::new(auto_refresh_with_token(
            &dir,
            &base_url2,
            make_token("expired-token", 0, true),
        ));

        let mut handles = Vec::with_capacity(CONCURRENCY);
        for _ in 0..CONCURRENCY {
            let s = Arc::clone(&strategy2);
            handles.push(tokio::spawn(async move { s.get_token().await.unwrap() }));
        }

        let results: Vec<_> = {
            let mut results = Vec::with_capacity(handles.len());
            for handle in handles {
                results.push(handle.await.unwrap());
            }
            results
        };

        for token in &results {
            assert_eq!(token.as_str(), "refreshed-token");
        }

        assert_eq!(stats2.total(), 1, "only one retry refresh should be made");
    }
}
