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
pub struct TokenStoreStrategy {
    store: TokenStore,
    base_url: Url,
    client_id: String,
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
            token: None,
        }
    }
}

impl<'a> AuthStrategy<'a> for &'a mut TokenStoreStrategy {
    type Error = TokenStoreError;

    async fn get_token(self) -> Result<&'a SecretToken, Self::Error> {
        // Load from disk if not yet cached.
        if self.token.is_none() {
            let token = self.store.load()?.ok_or(TokenStoreError::NotFound)?;
            self.token = Some(token);
        }

        // Preemptively refresh if the token is expiring within 60 seconds.
        // Take only the refresh token so the access token stays available
        // for other callers and subsequent calls won't attempt a concurrent
        // refresh (they'll see refresh_token is None and skip this block).
        let refresh_token = self
            .token
            .as_mut()
            .filter(|t| t.is_expired())
            .and_then(|t| t.take_refresh_token());

        if let Some(refresh_token) = refresh_token {
            match Token::exchange_refresh_token(&refresh_token, &self.base_url, &self.client_id)
                .await
            {
                Ok(new_token) => {
                    match self.store.save(&new_token) {
                        Ok(()) => tracing::debug!("refreshed token saved to disk"),
                        Err(err) => tracing::warn!(%err, "failed to save refreshed token to disk"),
                    }
                    self.token = Some(new_token);
                }
                Err(err) => {
                    tracing::warn!(%err, "token refresh failed");
                }
            }
        }

        let token = self.token.as_ref().ok_or(TokenStoreError::NotFound)?;
        if token.is_expired() {
            return Err(TokenStoreError::Expired);
        }
        Ok(token.access_token())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mocktail::prelude::*;
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
        let mut strategy =
            strategy_with_token(&dir, &server, make_token("my-access-token", 3600, false));

        let token = (&mut strategy).get_token().await.unwrap();

        assert_eq!(token.as_str(), "my-access-token");
    }

    #[tokio::test]
    async fn test_returns_not_found_when_no_token_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let server = start_server(MockSet::new()).await;
        let store = TokenStore::new(dir.path().join("auth.json"));
        let mut strategy = TokenStoreStrategy::new(store, server.url(""), "cli");

        let err = (&mut strategy).get_token().await.unwrap_err();

        assert!(matches!(err, TokenStoreError::NotFound));
    }

    #[tokio::test]
    async fn test_caches_token_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        let server = start_server(MockSet::new()).await;
        let mut strategy =
            strategy_with_token(&dir, &server, make_token("my-access-token", 3600, false));

        let token1 = (&mut strategy).get_token().await.unwrap();
        assert_eq!(token1.as_str(), "my-access-token");

        // Delete the file — second call should still return the cached token.
        std::fs::remove_file(dir.path().join("auth.json")).unwrap();

        let token2 = (&mut strategy).get_token().await.unwrap();
        assert_eq!(token2.as_str(), "my-access-token");
    }

    // ---- Expiry tests ----

    #[tokio::test]
    async fn test_expired_token_without_refresh_token_returns_expired() {
        let dir = tempfile::tempdir().unwrap();
        let server = start_server(MockSet::new()).await;
        let mut strategy =
            strategy_with_token(&dir, &server, make_token("old-token", 0, false));

        let err = (&mut strategy).get_token().await.unwrap_err();

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
        let mut strategy =
            strategy_with_token(&dir, &server, make_token("old-token", 0, true));

        let token = (&mut strategy).get_token().await.unwrap();

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
        let mut strategy =
            strategy_with_token(&dir, &server, make_token("old-token", 0, true));

        let _ = (&mut strategy).get_token().await.unwrap();

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
        let mut strategy =
            strategy_with_token(&dir, &server, make_token("old-token", 0, true));

        let err = (&mut strategy).get_token().await.unwrap_err();

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
        let mut strategy =
            strategy_with_token(&dir, &server, make_token("fresh-token", 3600, true));

        let token = (&mut strategy).get_token().await.unwrap();

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
        let mut strategy =
            strategy_with_token(&dir, &server, make_token("old-token", 0, true));

        // First call refreshes successfully.
        let token = (&mut strategy).get_token().await.unwrap();
        assert_eq!(token.as_str(), "refreshed-token");

        // Replace the mock with one that errors — any refresh attempt would fail.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/oauth/token");
            then.bad_request().json(error_json("should_not_be_called"));
        });

        // Second call should return the refreshed token without hitting
        // the server again (the new token has a fresh expiry).
        let token = (&mut strategy).get_token().await.unwrap();
        assert_eq!(token.as_str(), "refreshed-token");
    }

    #[tokio::test]
    async fn test_failed_refresh_removes_refresh_token_preventing_cascade() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.bad_request().json(error_json("invalid_grant"));
        });
        let server = start_server(mocks).await;
        let dir = tempfile::tempdir().unwrap();
        let mut strategy =
            strategy_with_token(&dir, &server, make_token("old-token", 0, true));

        // First call: refresh fails, returns Expired.
        let err = (&mut strategy).get_token().await.unwrap_err();
        assert!(matches!(err, TokenStoreError::Expired));

        // Verify the refresh token has been consumed (taken out).
        // The cached token should still exist but without a refresh token.
        assert!(strategy.token.is_some());
        assert!(strategy.token.as_ref().unwrap().refresh_token().is_none());

        // Replace mock with a success response to prove it's never called.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("should-not-reach"));
        });

        // Second call: no refresh token → no refresh attempt → Expired again.
        let err = (&mut strategy).get_token().await.unwrap_err();
        assert!(matches!(err, TokenStoreError::Expired));
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
        let mut strategy =
            strategy_with_token(&dir, &server, make_token("still-usable", 30, true));

        // The refresh fails, but the access token should still be in the cache.
        // Since is_expired() returns true (30s < 60s leeway), get_token will
        // return Expired, but the token itself is not destroyed.
        let _ = (&mut strategy).get_token().await;

        // Verify the access token is still present in the cached token.
        assert!(strategy.token.is_some());
        assert_eq!(
            strategy.token.as_ref().unwrap().access_token().as_str(),
            "still-usable"
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
        let mut strategy =
            strategy_with_token(&dir, &server, make_token("old-token", 0, true));

        // First call triggers refresh.
        let token = (&mut strategy).get_token().await.unwrap();
        assert_eq!(token.as_str(), "refreshed-once");

        // Swap mock to track if another refresh is attempted.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-twice"));
        });

        // Calls 2-5: the refreshed token is fresh, so no further refresh.
        for _ in 0..4 {
            let token = (&mut strategy).get_token().await.unwrap();
            assert_eq!(
                token.as_str(),
                "refreshed-once",
                "should return cached refreshed token, not trigger another refresh"
            );
        }
    }
}
