use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{Mutex, MutexGuard, Notify};

use crate::refresher::Refresher;
use crate::token_store::{NoStore, TokenStore};
use crate::{ServiceToken, Token};

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
/// or refresh before expiry, optionally backed by an external [`TokenStore`]
/// for persistence across short-lived strategy instances.
///
/// See the [crate-level documentation](crate#token-refresh) for a full
/// description of the concurrency model and flow diagram.
pub(crate) struct AutoRefresh<R, S = NoStore> {
    refresher: R,
    state: Mutex<State>,
    store: S,
    /// Set to `true` while a refresh HTTP call is in-flight.
    ///
    /// Stored as an [`AtomicBool`] rather than inside [`State`] so that
    /// [`CancelGuard`] can reset it on future cancellation without acquiring
    /// the mutex.
    refresh_in_progress: AtomicBool,
    refresh_notify: Notify,
}

struct State {
    token: Option<Token>,
}

/// Ensures [`AutoRefresh::refresh_in_progress`] is cleared and waiters are
/// notified if the refresh future is cancelled (dropped) before completing.
///
/// On the normal path (success or handled error), the guard is defused before
/// drop so that the regular cleanup code runs instead.
struct CancelGuard<'a> {
    in_progress: &'a AtomicBool,
    notify: &'a Notify,
    defused: bool,
}

impl Drop for CancelGuard<'_> {
    fn drop(&mut self) {
        if !self.defused {
            self.in_progress.store(false, Ordering::Release);
            self.notify.notify_waiters();
        }
    }
}

impl CancelGuard<'_> {
    fn defuse(&mut self) {
        self.defused = true;
    }
}

impl State {
    fn service_token(&self) -> Result<ServiceToken, AutoRefreshError> {
        let token = self.token.as_ref().ok_or(AutoRefreshError::NotFound)?;
        Ok(ServiceToken::new(token.access_token().clone()))
    }

    fn require_usable_token(&self) -> Result<ServiceToken, AutoRefreshError> {
        let token = self.token.as_ref().ok_or(AutoRefreshError::NotFound)?;
        if token.is_usable() {
            Ok(ServiceToken::new(token.access_token().clone()))
        } else {
            Err(AutoRefreshError::Expired)
        }
    }
}

impl<R> AutoRefresh<R, NoStore> {
    /// Create a new `AutoRefresh` with a pre-loaded token and no external store.
    ///
    /// Use this for refreshers that cannot self-authenticate (e.g. OAuth,
    /// which needs a refresh token from a prior device code flow).
    pub(crate) fn with_token(refresher: R, token: Token) -> Self {
        Self {
            refresher,
            state: Mutex::new(State { token: Some(token) }),
            store: NoStore,
            refresh_in_progress: AtomicBool::new(false),
            refresh_notify: Notify::new(),
        }
    }
}

impl<R, S: TokenStore> AutoRefresh<R, S> {
    /// Create a new `AutoRefresh` backed by `store` and no in-memory token.
    ///
    /// On the first `get_token` call the store is consulted before falling
    /// through to initial authentication via `try_credential(None)`; every
    /// successful refresh writes the new token back via `store.save()`. Pass
    /// [`NoStore`] for the no-external-cache case — it's the default and
    /// elides to a zero-cost no-op.
    pub(crate) fn with_store(refresher: R, store: S) -> Self {
        Self {
            refresher,
            state: Mutex::new(State { token: None }),
            store,
            refresh_in_progress: AtomicBool::new(false),
            refresh_notify: Notify::new(),
        }
    }
}

impl<R: Refresher, S: TokenStore> AutoRefresh<R, S> {
    /// Retrieve a valid access token, refreshing or re-authenticating as needed.
    pub(crate) async fn get_token(&self) -> Result<ServiceToken, AutoRefreshError> {
        let mut state = self.state.lock().await;

        if state.token.is_none() {
            // Drop the lock for the store read so a slow user-supplied backend
            // (cookie, KV, Redis) doesn't serialise concurrent `get_token`
            // callers. Re-acquire and double-check `state.token.is_none()` in
            // case another caller populated it while we awaited.
            drop(state);
            let loaded = self.store.load().await;
            state = self.state.lock().await;
            if state.token.is_none() {
                if let Some(t) = loaded {
                    state.token = Some(t);
                }
            }
        }

        if state.token.is_none() {
            return self.initial_auth(&mut state).await;
        }

        if !state.token.as_ref().is_some_and(|t| t.is_expired()) {
            return state.service_token();
        }

        if self.refresh_in_progress.load(Ordering::Acquire) {
            return self.wait_for_in_flight_refresh(state).await;
        }

        let Some(credential) = self.refresher.try_credential(state.token.as_mut()) else {
            return state.require_usable_token();
        };

        self.refresh_in_progress.store(true, Ordering::Release);

        if state.token.as_ref().is_some_and(|t| t.is_usable()) {
            self.refresh_non_blocking(state, credential).await
        } else {
            self.refresh_blocking(&mut state, credential).await
        }
    }

    /// No cached token — authenticate via `try_credential(None)`.
    ///
    /// The lock is held throughout to prevent concurrent initial-auth attempts.
    async fn initial_auth(&self, state: &mut State) -> Result<ServiceToken, AutoRefreshError> {
        let Some(credential) = self.refresher.try_credential(None) else {
            return Err(AutoRefreshError::NotFound);
        };
        self.refresh_in_progress.store(true, Ordering::Release);
        let mut guard = CancelGuard {
            in_progress: &self.refresh_in_progress,
            notify: &self.refresh_notify,
            defused: false,
        };
        match self.refresher.refresh(&credential).await {
            Ok(new_token) => {
                guard.defuse();
                self.refresher.save(&new_token);
                self.store.save(&new_token).await;
                let service_token = ServiceToken::new(new_token.access_token().clone());
                state.token = Some(new_token);
                self.refresh_in_progress.store(false, Ordering::Release);
                Ok(service_token)
            }
            Err(err) => {
                guard.defuse();
                self.refresh_in_progress.store(false, Ordering::Release);
                Err(AutoRefreshError::Auth(err))
            }
        }
    }

    /// Another caller is already refreshing — return the current token if still
    /// usable, otherwise wait for the in-flight refresh to complete via `Notify`.
    ///
    /// Takes `MutexGuard` by value because the lock is dropped before awaiting
    /// the notification.
    async fn wait_for_in_flight_refresh(
        &self,
        state: MutexGuard<'_, State>,
    ) -> Result<ServiceToken, AutoRefreshError> {
        if let Ok(token) = state.service_token() {
            if state.token.as_ref().is_some_and(|t| t.is_usable()) {
                return Ok(token);
            }
        }
        // Token crossed real expiry during in-flight refresh. Wait for the
        // refresh to complete rather than returning Expired.
        let notified = self.refresh_notify.notified();
        drop(state);
        notified.await;
        // Re-check after wake — refresh may have failed.
        let state = self.state.lock().await;
        state.require_usable_token()
    }

    /// Token is expiring but still usable — drop the lock, refresh in the
    /// background of this call, and return the old (still-valid) token.
    ///
    /// Takes `MutexGuard` by value because the lock is dropped before the HTTP
    /// request. Notifies waiters after the refresh completes (success or error).
    ///
    /// A [`CancelGuard`] ensures that if this future is cancelled during the
    /// HTTP request, `refresh_in_progress` is cleared, the credential is
    /// restored (best-effort via `try_lock`), and waiters are notified.
    async fn refresh_non_blocking(
        &self,
        state: MutexGuard<'_, State>,
        credential: R::Credential,
    ) -> Result<ServiceToken, AutoRefreshError> {
        let current_service_token = state.service_token()?;
        drop(state);

        let mut guard = CancelGuard {
            in_progress: &self.refresh_in_progress,
            notify: &self.refresh_notify,
            defused: false,
        };

        match self.refresher.refresh(&credential).await {
            Ok(new_token) => {
                guard.defuse();
                self.refresher.save(&new_token);
                self.store.save(&new_token).await;
                let mut state = self.state.lock().await;
                state.token = Some(new_token);
                self.refresh_in_progress.store(false, Ordering::Release);
            }
            Err(err) => {
                guard.defuse();
                tracing::warn!(%err, "token refresh failed (token still usable)");
                let mut state = self.state.lock().await;
                if let Some(token) = state.token.as_mut() {
                    self.refresher.restore(token, credential);
                }
                self.refresh_in_progress.store(false, Ordering::Release);
            }
        }

        self.refresh_notify.notify_waiters();
        Ok(current_service_token)
    }

    /// Token is fully expired — refresh while holding the lock so concurrent
    /// callers block on `lock().await` until the new token is available.
    ///
    /// A [`CancelGuard`] ensures that if this future is cancelled during the
    /// HTTP request, `refresh_in_progress` is cleared and waiters are notified
    /// so they don't hang indefinitely. (The credential is lost on cancel —
    /// see [`CancelGuard`] docs — but subsequent callers will get `Expired`
    /// rather than blocking forever.)
    async fn refresh_blocking(
        &self,
        state: &mut State,
        credential: R::Credential,
    ) -> Result<ServiceToken, AutoRefreshError> {
        let mut guard = CancelGuard {
            in_progress: &self.refresh_in_progress,
            notify: &self.refresh_notify,
            defused: false,
        };
        match self.refresher.refresh(&credential).await {
            Ok(new_token) => {
                guard.defuse();
                self.refresher.save(&new_token);
                self.store.save(&new_token).await;
                let service_token = ServiceToken::new(new_token.access_token().clone());
                state.token = Some(new_token);
                self.refresh_in_progress.store(false, Ordering::Release);
                Ok(service_token)
            }
            Err(err) => {
                guard.defuse();
                tracing::warn!(%err, "token refresh failed");
                if let Some(token) = state.token.as_mut() {
                    self.refresher.restore(token, credential);
                }
                self.refresh_in_progress.store(false, Ordering::Release);
                Err(AutoRefreshError::Expired)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::oauth_refresher::OAuthRefresher;
    use crate::SecretToken;
    use mocktail::prelude::*;
    use stack_profile::ProfileStore;
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
        let store = ProfileStore::new(dir.path());
        store.init_workspace("ZVATKW3VHMFG27DY").unwrap();
        let ws_store = store.current_workspace_store().unwrap();
        ws_store.save_profile(&token).unwrap();
        let refresher = OAuthRefresher::new(
            Some(ws_store),
            server.url(""),
            "cli",
            "ap-southeast-2.aws",
            None,
        );
        AutoRefresh::with_token(refresher, token)
    }

    mod given_no_cached_token {
        use super::*;

        #[tokio::test]
        async fn returns_not_found_for_oauth() {
            let server = start_server(MockSet::new()).await;
            let store = ProfileStore::new("/tmp/nonexistent");
            let refresher = OAuthRefresher::new(
                Some(store),
                server.url(""),
                "cli",
                "ap-southeast-2.aws",
                None,
            );
            let strategy = AutoRefresh::with_store(refresher, NoStore);

            let err = strategy.get_token().await.unwrap_err();

            assert!(
                matches!(err, AutoRefreshError::NotFound),
                "expected NotFound, got: {err:?}"
            );
        }
    }

    mod given_fresh_token {
        use super::*;

        #[tokio::test]
        async fn returns_cached_token() {
            let dir = tempfile::tempdir().unwrap();
            let server = start_server(MockSet::new()).await;
            let strategy =
                auto_refresh_with_token(&dir, &server, make_token("my-access-token", 3600, false));

            let token = strategy.get_token().await.unwrap();

            assert_eq!(
                token.as_str(),
                "my-access-token",
                "should return the cached access token"
            );
        }

        #[tokio::test]
        async fn caches_across_calls() {
            let dir = tempfile::tempdir().unwrap();
            let server = start_server(MockSet::new()).await;
            let strategy =
                auto_refresh_with_token(&dir, &server, make_token("my-access-token", 3600, false));

            let token1 = strategy.get_token().await.unwrap();
            assert_eq!(
                token1.as_str(),
                "my-access-token",
                "first call should return the cached token"
            );

            // Delete the file — second call should still return the cached token.
            std::fs::remove_file(
                dir.path()
                    .join("workspaces")
                    .join("ZVATKW3VHMFG27DY")
                    .join("auth.json"),
            )
            .unwrap();

            let token2 = strategy.get_token().await.unwrap();
            assert_eq!(
                token2.as_str(),
                "my-access-token",
                "second call should return the cached token even after file deletion"
            );
        }

        #[tokio::test]
        async fn does_not_trigger_refresh() {
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

            assert_eq!(
                token.as_str(),
                "fresh-token",
                "should return fresh token without triggering refresh"
            );
        }
    }

    mod given_fully_expired_token {
        use super::*;

        mod without_refresh_token {
            use super::*;

            #[tokio::test]
            async fn returns_expired() {
                let dir = tempfile::tempdir().unwrap();
                let server = start_server(MockSet::new()).await;
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("old-token", 0, false));

                let err = strategy.get_token().await.unwrap_err();

                assert!(
                    matches!(err, AutoRefreshError::Expired),
                    "expected Expired, got: {err:?}"
                );
            }
        }

        mod with_refresh_token {
            use super::*;

            #[tokio::test]
            async fn refreshes_and_returns_new_token() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.json(refresh_response_json("refreshed-token"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

                let token = strategy.get_token().await.unwrap();

                assert_eq!(
                    token.as_str(),
                    "refreshed-token",
                    "should return the refreshed token"
                );
            }

            #[tokio::test]
            async fn persists_refreshed_token_to_disk() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.json(refresh_response_json("refreshed-token"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

                let _ = strategy.get_token().await.unwrap();

                // Verify the refreshed token was saved to the workspace directory.
                let store = ProfileStore::new(dir.path());
                let ws_store = store.current_workspace_store().unwrap();
                let on_disk: Token = ws_store.load_profile().unwrap();
                assert_eq!(
                    on_disk.access_token().as_str(),
                    "refreshed-token",
                    "refreshed token should be persisted to disk"
                );
            }

            #[tokio::test]
            async fn returns_expired_on_refresh_failure() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.bad_request().json(error_json("invalid_grant"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

                let err = strategy.get_token().await.unwrap_err();

                assert!(
                    matches!(err, AutoRefreshError::Expired),
                    "expected Expired after failed refresh, got: {err:?}"
                );
            }

            #[tokio::test]
            async fn restores_refresh_token_after_failure() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.bad_request().json(error_json("invalid_grant"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

                // First call: refresh fails, returns Expired.
                let err = strategy.get_token().await.unwrap_err();
                assert!(
                    matches!(err, AutoRefreshError::Expired),
                    "expected Expired on first attempt, got: {err:?}"
                );

                // Verify the refresh token was restored so a retry is possible.
                let state = strategy.state.lock().await;
                assert!(
                    state.token.is_some(),
                    "token should still be cached after failed refresh"
                );
                assert!(
                    state.token.as_ref().unwrap().refresh_token().is_some(),
                    "refresh token should be restored for retry"
                );
                drop(state);

                // Replace mock with a success response.
                server.mocks().clear();
                server.mocks().mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.json(refresh_response_json("refreshed-token"));
                });

                // Second call: refresh token is available → retry succeeds.
                let token = strategy.get_token().await.unwrap();
                assert_eq!(
                    token.as_str(),
                    "refreshed-token",
                    "retry should succeed with restored refresh token"
                );
            }

            #[tokio::test]
            async fn sequential_calls_only_refresh_once() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.json(refresh_response_json("refreshed-once"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

                // First call triggers refresh.
                let token = strategy.get_token().await.unwrap();
                assert_eq!(
                    token.as_str(),
                    "refreshed-once",
                    "first call should trigger refresh"
                );

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

            #[tokio::test]
            async fn prevents_second_refresh_after_success() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.json(refresh_response_json("refreshed-token"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

                // First call refreshes successfully.
                let token = strategy.get_token().await.unwrap();
                assert_eq!(
                    token.as_str(),
                    "refreshed-token",
                    "first call should refresh the token"
                );

                // Replace the mock with one that errors.
                server.mocks().clear();
                server.mocks().mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.bad_request().json(error_json("should_not_be_called"));
                });

                // Second call should return the refreshed token without hitting
                // the server again (the new token has a fresh expiry).
                let token = strategy.get_token().await.unwrap();
                assert_eq!(
                    token.as_str(),
                    "refreshed-token",
                    "second call should return cached refreshed token"
                );
            }
        }
    }

    mod given_expiring_but_usable_token {
        use super::*;

        mod when_refresh_fails {
            use super::*;

            #[tokio::test]
            async fn returns_current_token() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.bad_request().json(error_json("server_error"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                // Token expires in 30s (within the 90s leeway so is_expired() = true),
                // but the access token is still technically usable.
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("still-usable", 30, true));

                // The refresh fails, but the access token should still be returned
                // because it's still usable (30s remaining > 0).
                let token = strategy.get_token().await.unwrap();
                assert_eq!(
                    token.as_str(),
                    "still-usable",
                    "should return still-usable token despite failed refresh"
                );

                // Verify the access token and refresh token are still present.
                let state = strategy.state.lock().await;
                assert!(state.token.is_some(), "token should still be cached");
                assert_eq!(
                    state.token.as_ref().unwrap().access_token().as_str(),
                    "still-usable",
                    "access token should be unchanged after failed refresh"
                );
                assert!(
                    state.token.as_ref().unwrap().refresh_token().is_some(),
                    "refresh token should be restored after failed refresh"
                );
            }

            #[tokio::test]
            async fn restores_refresh_token_for_retry() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.bad_request().json(error_json("server_error"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                // Token expires in 30s — is_expired() = true, is_usable() = true.
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("still-usable", 30, true));

                // First call: refresh fails, but the still-usable token is returned.
                let token = strategy.get_token().await.unwrap();
                assert_eq!(
                    token.as_str(),
                    "still-usable",
                    "first call should return still-usable token"
                );

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
                    "refreshed-token",
                    "cache should hold the refreshed token after retry"
                );
            }
        }
    }

    mod given_concurrent_callers {
        use super::*;

        #[tokio::test]
        async fn returns_usable_token_while_refreshing() {
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
        async fn blocks_until_refresh_completes() {
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

            assert_eq!(
                token_a.as_str(),
                "refreshed-token",
                "caller a should receive refreshed token"
            );
            assert_eq!(
                token_b.as_str(),
                "refreshed-token",
                "caller b should receive refreshed token"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod stress_tests {
    use super::*;
    use crate::oauth_refresher::OAuthRefresher;
    use crate::SecretToken;
    use stack_profile::ProfileStore;
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
        let store = ProfileStore::new(dir.path());
        store.init_workspace("ZVATKW3VHMFG27DY").unwrap();
        let ws_store = store.current_workspace_store().unwrap();
        ws_store.save_profile(&token).unwrap();
        let refresher = OAuthRefresher::new(
            Some(ws_store),
            base_url.clone(),
            "cli",
            "ap-southeast-2.aws",
            None,
        );
        AutoRefresh::with_token(refresher, token)
    }

    const CONCURRENCY: usize = 50;

    mod given_fresh_token {
        use super::*;

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn all_callers_return_immediately() {
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
                assert_eq!(
                    token.as_str(),
                    "fresh-token",
                    "all callers should receive the fresh token"
                );
            }

            assert!(
                elapsed < Duration::from_millis(200),
                "expected < 200ms for fresh tokens, got {:?}",
                elapsed
            );
            assert_eq!(stats.total(), 0, "no refresh requests should be made");
        }
    }

    mod given_expiring_but_usable_token {
        use super::*;

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn non_blocking_reads_during_refresh() {
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

        /// Reproduces the race condition where a token crosses real expiry during
        /// an in-flight non-blocking refresh. Before the fix, late-arriving callers
        /// would see `refresh_in_progress = true` + `!is_usable()` and return
        /// `Err(Expired)` instead of waiting for the refresh to complete.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn waiters_receive_token_when_expiry_crosses() {
            // Token with 1s until real expiry (minimum granularity since
            // expires_at is in seconds). is_expired() = true (within 90s leeway),
            // is_usable() = true (1s remaining). Refresh takes 1.5s so the token
            // crosses real expiry mid-refresh.
            let refresh_delay = Duration::from_millis(1500);
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
                make_token("expiring-soon", 1, true),
            ));

            // First caller triggers the non-blocking refresh and gets the old token.
            let first = strategy.get_token().await.unwrap();
            assert_eq!(
                first.as_str(),
                "expiring-soon",
                "first caller should receive the expiring token"
            );

            // Wait for the token to cross real expiry (but refresh is still in-flight).
            tokio::time::sleep(Duration::from_millis(1100)).await;

            // Launch 50 concurrent callers. Without the fix, these would all get
            // Err(Expired) because refresh_in_progress = true and !is_usable().
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

            // All callers must succeed — none should get Expired.
            for (i, result) in results.iter().enumerate() {
                assert!(
                    result.is_ok(),
                    "caller {i} got Err({:?}), expected Ok",
                    result.as_ref().unwrap_err()
                );
                assert_eq!(
                    result.as_ref().unwrap().as_str(),
                    "refreshed-token",
                    "caller {i} should receive the refreshed token"
                );
            }

            assert_eq!(stats.total(), 1, "only one refresh request should be made");
        }
    }

    mod given_fully_expired_token {
        use super::*;

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn all_callers_block_until_refresh() {
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
                assert_eq!(
                    token.as_str(),
                    "refreshed-token",
                    "all callers should receive refreshed token"
                );
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
        async fn all_callers_receive_expired_on_failure() {
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
                let err = result.as_ref().unwrap_err();
                assert!(
                    matches!(err, AutoRefreshError::Expired),
                    "expected Expired, got: {err:?}"
                );
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
        async fn retry_succeeds_after_failure() {
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
                assert_eq!(
                    token.as_str(),
                    "refreshed-token",
                    "retry callers should receive refreshed token"
                );
            }

            assert_eq!(stats2.total(), 1, "only one retry refresh should be made");
        }
    }

    mod given_cancelled_refresh {
        use super::*;

        /// If a blocking refresh (fully expired token) is cancelled mid-flight,
        /// the `CancelGuard` must reset `refresh_in_progress` and notify waiters
        /// so the next caller doesn't hang in `wait_for_in_flight_refresh`.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn blocked_callers_recover_after_cancellation() {
            let counting = CountingState::new();
            let state = DelayedRefreshState {
                counting: counting.clone(),
                delay: Duration::from_secs(10), // Very slow — will be cancelled
            };
            let (base_url, _) = start_axum_server(delayed_refresh_handler, state).await;
            let dir = tempfile::tempdir().unwrap();
            let strategy = Arc::new(auto_refresh_with_token(
                &dir,
                &base_url,
                make_token("expired-token", 0, true),
            ));

            // Spawn get_token and let the blocking refresh start.
            let s = Arc::clone(&strategy);
            let handle = tokio::spawn(async move { s.get_token().await });
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Cancel the refresh mid-flight.
            handle.abort();
            let _ = handle.await;

            // The next caller must not hang. The credential is lost (refresh
            // token was taken before the HTTP call), so the result is Expired,
            // but the important thing is that it completes promptly.
            let s = Arc::clone(&strategy);
            let result = tokio::time::timeout(Duration::from_secs(2), s.get_token()).await;

            assert!(
                result.is_ok(),
                "get_token() should not hang after cancelled blocking refresh"
            );
        }

        /// If a non-blocking refresh (expiring-but-usable token) is cancelled
        /// mid-flight, the `CancelGuard` must reset `refresh_in_progress` and
        /// notify waiters so they don't hang once the token crosses real expiry.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn non_blocking_callers_recover_after_cancellation() {
            let counting = CountingState::new();
            let state = DelayedRefreshState {
                counting: counting.clone(),
                delay: Duration::from_secs(10), // Very slow — will be cancelled
            };
            let (base_url, _) = start_axum_server(delayed_refresh_handler, state).await;
            let dir = tempfile::tempdir().unwrap();
            // Token expires in 30s — is_expired() = true, is_usable() = true.
            let strategy = Arc::new(auto_refresh_with_token(
                &dir,
                &base_url,
                make_token("still-usable", 30, true),
            ));

            // Spawn get_token — triggers non-blocking refresh, drops lock, then
            // blocks on the slow HTTP call.
            let s = Arc::clone(&strategy);
            let handle = tokio::spawn(async move { s.get_token().await });
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Cancel the refresh mid-flight.
            handle.abort();
            let _ = handle.await;

            // The next caller must not hang. The token is still usable so it
            // should be returned even though the refresh was cancelled.
            let s = Arc::clone(&strategy);
            let result = tokio::time::timeout(Duration::from_secs(2), s.get_token()).await;

            assert!(
                result.is_ok(),
                "get_token() should not hang after cancelled non-blocking refresh"
            );
            let result = result.unwrap();
            assert!(
                result.is_ok(),
                "expected Ok with still-usable token, got: {:?}",
                result.unwrap_err()
            );
        }
    }
}
