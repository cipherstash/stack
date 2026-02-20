use std::borrow::Cow;

use tokio::sync::Mutex;
use url::Url;

use crate::token_store::{TokenStore, TokenStoreError};
use crate::{AuthStrategy, SecretToken, Token};

/// An [`AuthStrategy`] that loads a token from a [`TokenStore`], caches it in
/// memory, and preemptively refreshes it before it expires.
///
/// The token is loaded from disk on the first call to [`get_token`](AuthStrategy::get_token)
/// and cached for subsequent calls. When the token is within 60 seconds of
/// expiry and a refresh token is available, the strategy automatically refreshes
/// it and persists the new token to disk.
///
/// # Concurrency model
///
/// Internal state is protected by a [`tokio::sync::Mutex`]. The key design
/// decision is *when* the lock is held during a refresh, which depends on
/// whether the current token is still usable as a bearer credential:
///
/// - [`Token::is_expired()`] — returns `true` when the token is within **60
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
/// Cascade prevention: the first caller to detect an expiring token *takes*
/// the refresh token out of the cached [`Token`] (leaving `None`). Subsequent
/// callers see no refresh token and skip the refresh, returning the current
/// token if usable or [`TokenStoreError::Expired`] if not.
///
/// # Flow diagram
///
/// The following diagram shows the decision tree inside
/// [`get_token()`](AuthStrategy::get_token):
///
/// ```mermaid
/// flowchart TD
///     Start["get_token()"] --> Lock["Acquire lock"]
///     Lock --> Cached{Token cached?}
///     Cached -- No --> Load["Load from disk"]
///     Load -- Not found --> ErrNotFound["Return NotFound"]
///     Load -- OK --> CheckRefresh
///     Cached -- Yes --> CheckRefresh{is_expired?}
///
///     CheckRefresh -- "No (fresh)" --> CloneFresh["Clone access token,
///     release lock"]
///     CloneFresh --> ReturnOk["Return Ok(token)"]
///
///     CheckRefresh -- "Yes (needs refresh)" --> TakeRT{take_refresh_token}
///
///     TakeRT -- "None (already taken)" --> Usable1{is_usable?}
///     Usable1 -- Yes --> CloneUsable1["Clone access token,
///     release lock"]
///     CloneUsable1 --> ReturnOk
///     Usable1 -- No --> ErrExpired["Return Expired"]
///
///     TakeRT -- "Some(refresh_token)" --> Usable2{is_usable?}
///
///     Usable2 -- "Yes (expiring but usable)" --> DropLock["Clone access token,
///     release lock"]
///     DropLock --> HTTP1["HTTP refresh
///     (lock NOT held)"]
///     HTTP1 -- OK --> Relock1["Re-acquire lock,
///     store new token"]
///     HTTP1 -- Err --> Restore1["Restore refresh token,
///     log warning"]
///     Relock1 --> ReturnOld["Return Ok(old token)"]
///     Restore1 --> ReturnOld
///
///     Usable2 -- "No (fully expired)" --> HTTP2["HTTP refresh
///     (lock HELD)"]
///     HTTP2 -- OK --> StoreNew["Store new token,
///     release lock"]
///     StoreNew --> ReturnNew["Return Ok(new token)"]
///     HTTP2 -- Err --> Restore2["Restore refresh token"]
///     Restore2 --> ErrExpired
/// ```
#[cfg_attr(doc, aquamarine::aquamarine)]
pub struct TokenStoreStrategy {
    store: TokenStore,
    base_url: Url,
    client_id: String,
    state: Mutex<State>,
}

struct State {
    token: Option<Token>,
}

impl TokenStoreStrategy {
    /// Create a new `TokenStoreStrategy`.
    ///
    /// The `base_url` and `client_id` are used when refreshing an expired token
    /// via the `/oauth/token` endpoint.
    pub fn new(store: TokenStore, base_url: Url, client_id: impl Into<String>) -> Self {
        Self {
            store,
            base_url,
            client_id: client_id.into(),
            state: Mutex::new(State { token: None }),
        }
    }
}

impl<'a> AuthStrategy<'a> for &'a TokenStoreStrategy {
    type Error = TokenStoreError;

    async fn get_token(self) -> Result<Cow<'a, SecretToken>, Self::Error> {
        let mut state = self.state.lock().await;

        // Load from disk if not yet cached.
        if state.token.is_none() {
            let token = self.store.load()?.ok_or(TokenStoreError::NotFound)?;
            state.token = Some(token);
        }

        let needs_refresh = state.token.as_ref().is_some_and(|t| t.is_expired());
        if !needs_refresh {
            // Token is fresh — clone and return.
            let token = state.token.as_ref().ok_or(TokenStoreError::NotFound)?;
            return Ok(Cow::Owned(token.access_token().clone()));
        }

        // Token needs refresh. Take the refresh token to prevent cascades.
        let refresh_token = state.token.as_mut().and_then(|t| t.take_refresh_token());

        let Some(refresh_token) = refresh_token else {
            // No refresh token available. If the token is still usable (not
            // actually expired, just within the 60s leeway), return it.
            // Otherwise another caller is already refreshing (they took the
            // refresh token) — if the token is usable, return it; if not,
            // it's truly expired.
            let token = state.token.as_ref().ok_or(TokenStoreError::NotFound)?;
            if token.is_usable() {
                return Ok(Cow::Owned(token.access_token().clone()));
            }
            return Err(TokenStoreError::Expired);
        };

        // We have a refresh token. Check if the current token is still usable.
        let is_usable = state.token.as_ref().is_some_and(|t| t.is_usable());

        if is_usable {
            // Token is expiring but still usable. Clone the current access
            // token, drop the lock, and refresh in the background of this call.
            // Other callers can acquire the lock and get the still-valid token.
            let current_access_token = state
                .token
                .as_ref()
                .ok_or(TokenStoreError::NotFound)?
                .access_token()
                .clone();
            drop(state);

            match Token::exchange_refresh_token(&refresh_token, &self.base_url, &self.client_id)
                .await
            {
                Ok(new_token) => {
                    match self.store.save(&new_token) {
                        Ok(()) => tracing::debug!("refreshed token saved to disk"),
                        Err(err) => {
                            tracing::warn!(%err, "failed to save refreshed token to disk")
                        }
                    }
                    self.state.lock().await.token = Some(new_token);
                }
                Err(err) => {
                    tracing::warn!(%err, "token refresh failed (token still usable)");
                    // Restore the refresh token so the next call can retry.
                    if let Some(token) = self.state.lock().await.token.as_mut() {
                        token.refresh_token = Some(refresh_token);
                    }
                }
            }

            Ok(Cow::Owned(current_access_token))
        } else {
            // Token is fully expired. Refresh while holding the lock so other
            // callers block until the new token is available.
            match Token::exchange_refresh_token(&refresh_token, &self.base_url, &self.client_id)
                .await
            {
                Ok(new_token) => {
                    match self.store.save(&new_token) {
                        Ok(()) => tracing::debug!("refreshed token saved to disk"),
                        Err(err) => {
                            tracing::warn!(%err, "failed to save refreshed token to disk")
                        }
                    }
                    let access_token = new_token.access_token().clone();
                    state.token = Some(new_token);
                    Ok(Cow::Owned(access_token))
                }
                Err(err) => {
                    tracing::warn!(%err, "token refresh failed");
                    // Restore the refresh token so the next call can retry.
                    if let Some(token) = state.token.as_mut() {
                        token.refresh_token = Some(refresh_token);
                    }
                    Err(TokenStoreError::Expired)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let server = MockServer::new_http("token-store-strategy-test").with_mocks(mocks);
        server.start().await.unwrap();
        server
    }

    fn strategy_with_token(
        dir: &tempfile::TempDir,
        server: &MockServer,
        token: Token,
    ) -> TokenStoreStrategy {
        let store = TokenStore::new(dir.path().join("auth.json"));
        store.save(&token).unwrap();
        TokenStoreStrategy::new(store, server.url(""), "cli")
    }

    // ---- Basic loading tests ----

    #[tokio::test]
    async fn test_loads_token_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let server = start_server(MockSet::new()).await;
        let strategy =
            strategy_with_token(&dir, &server, make_token("my-access-token", 3600, false));

        let token = (&strategy).get_token().await.unwrap();

        assert_eq!(token.as_str(), "my-access-token");
    }

    #[tokio::test]
    async fn test_returns_not_found_when_no_token_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let server = start_server(MockSet::new()).await;
        let store = TokenStore::new(dir.path().join("auth.json"));
        let strategy = TokenStoreStrategy::new(store, server.url(""), "cli");

        let err = (&strategy).get_token().await.unwrap_err();

        assert!(matches!(err, TokenStoreError::NotFound));
    }

    #[tokio::test]
    async fn test_caches_token_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        let server = start_server(MockSet::new()).await;
        let strategy =
            strategy_with_token(&dir, &server, make_token("my-access-token", 3600, false));

        let token1 = (&strategy).get_token().await.unwrap();
        assert_eq!(token1.as_str(), "my-access-token");

        // Delete the file — second call should still return the cached token.
        std::fs::remove_file(dir.path().join("auth.json")).unwrap();

        let token2 = (&strategy).get_token().await.unwrap();
        assert_eq!(token2.as_str(), "my-access-token");
    }

    // ---- Expiry tests ----

    #[tokio::test]
    async fn test_expired_token_without_refresh_token_returns_expired() {
        let dir = tempfile::tempdir().unwrap();
        let server = start_server(MockSet::new()).await;
        let strategy = strategy_with_token(&dir, &server, make_token("old-token", 0, false));

        let err = (&strategy).get_token().await.unwrap_err();

        assert!(matches!(err, TokenStoreError::Expired));
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
        let strategy = strategy_with_token(&dir, &server, make_token("old-token", 0, true));

        let token = (&strategy).get_token().await.unwrap();

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
        let strategy = strategy_with_token(&dir, &server, make_token("old-token", 0, true));

        let _ = (&strategy).get_token().await.unwrap();

        // Verify the refreshed token was saved to disk.
        let store = TokenStore::new(dir.path().join("auth.json"));
        let on_disk = store.load().unwrap().unwrap();
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
        let strategy = strategy_with_token(&dir, &server, make_token("old-token", 0, true));

        let err = (&strategy).get_token().await.unwrap_err();

        assert!(matches!(err, TokenStoreError::Expired));
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
        let strategy = strategy_with_token(&dir, &server, make_token("fresh-token", 3600, true));

        let token = (&strategy).get_token().await.unwrap();

        assert_eq!(token.as_str(), "fresh-token");
    }

    // ---- Cascade prevention tests ----

    #[tokio::test]
    async fn test_refresh_token_is_taken_preventing_second_refresh() {
        // Set up a server that returns a new token on the first refresh but
        // would fail on any subsequent refresh attempt.
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-token"));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = strategy_with_token(&dir, &server, make_token("old-token", 0, true));

        // First call refreshes successfully.
        let token = (&strategy).get_token().await.unwrap();
        assert_eq!(token.as_str(), "refreshed-token");

        // Replace the mock with one that errors — any refresh attempt would fail.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/oauth/token");
            then.bad_request().json(error_json("should_not_be_called"));
        });

        // Second call should return the refreshed token without hitting
        // the server again (the new token has a fresh expiry).
        let token = (&strategy).get_token().await.unwrap();
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
        let strategy = strategy_with_token(&dir, &server, make_token("old-token", 0, true));

        // First call: refresh fails, returns Expired.
        let err = (&strategy).get_token().await.unwrap_err();
        assert!(matches!(err, TokenStoreError::Expired));

        // Verify the refresh token was restored so a retry is possible.
        let state = strategy.state.lock().await;
        assert!(state.token.is_some());
        assert!(state.token.as_ref().unwrap().refresh_token().is_some());
        drop(state);

        // Replace mock with a success response — the retry should use it.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-token"));
        });

        // Second call: refresh token is available → retry succeeds.
        let token = (&strategy).get_token().await.unwrap();
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
        // Token expires in 30s (within the 60s leeway so is_expired() = true),
        // but the access token is still technically usable.
        let strategy = strategy_with_token(&dir, &server, make_token("still-usable", 30, true));

        // The refresh fails, but the access token should still be returned
        // because it's still usable (30s remaining > 0).
        let token = (&strategy).get_token().await.unwrap();
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
        let strategy = strategy_with_token(&dir, &server, make_token("still-usable", 30, true));

        // First call: refresh fails, but the still-usable token is returned.
        let token = (&strategy).get_token().await.unwrap();
        assert_eq!(token.as_str(), "still-usable");

        // Replace mock with a success response — the retry should use it.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-token"));
        });

        // Second call: refresh token was restored, so the retry succeeds.
        // The caller still gets the old token (it's returned before the
        // refresh completes), but the cache is updated.
        let token = (&strategy).get_token().await.unwrap();
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
        let strategy = strategy_with_token(&dir, &server, make_token("old-token", 0, true));

        // First call triggers refresh.
        let token = (&strategy).get_token().await.unwrap();
        assert_eq!(token.as_str(), "refreshed-once");

        // Swap mock to track if another refresh is attempted.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-twice"));
        });

        // Calls 2-5: the refreshed token is fresh, so no further refresh.
        for _ in 0..4 {
            let token = (&strategy).get_token().await.unwrap();
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
        // Token expires in 30s — is_expired() = true (within 60s leeway),
        // but is_usable() = true (not actually expired).
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-token"));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = Arc::new(strategy_with_token(
            &dir,
            &server,
            make_token("still-usable", 30, true),
        ));

        // Spawn two concurrent callers.
        let s1 = Arc::clone(&strategy);
        let handle_a = tokio::spawn(async move {
            let token = s1.as_ref().get_token().await.unwrap();
            token.into_owned()
        });

        let s2 = Arc::clone(&strategy);
        let handle_b = tokio::spawn(async move {
            let token = s2.as_ref().get_token().await.unwrap();
            token.into_owned()
        });

        let (result_a, result_b) = tokio::join!(handle_a, handle_b);
        let token_a = result_a.unwrap();
        let token_b = result_b.unwrap();

        // Both should succeed. One gets the old token (still usable), the
        // other may get either old or refreshed depending on timing.
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
        // Token is fully expired (expires_at in the past) with a refresh token.
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-token"));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();
        let strategy = Arc::new(strategy_with_token(
            &dir,
            &server,
            make_token("expired-token", 0, true),
        ));

        // Spawn two concurrent callers.
        let s1 = Arc::clone(&strategy);
        let handle_a = tokio::spawn(async move {
            let token = s1.as_ref().get_token().await.unwrap();
            token.into_owned()
        });

        let s2 = Arc::clone(&strategy);
        let handle_b = tokio::spawn(async move {
            let token = s2.as_ref().get_token().await.unwrap();
            token.into_owned()
        });

        let (result_a, result_b) = tokio::join!(handle_a, handle_b);
        let token_a = result_a.unwrap();
        let token_b = result_b.unwrap();

        // Both should get the refreshed token (one blocks until the other
        // finishes refreshing).
        assert_eq!(token_a.as_str(), "refreshed-token");
        assert_eq!(token_b.as_str(), "refreshed-token");
    }
}
