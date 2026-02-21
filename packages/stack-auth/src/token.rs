use std::time::{SystemTime, UNIX_EPOCH};

use url::Url;

use crate::{http_client, AuthError, SecretToken};

/// How many seconds before expiry [`Token::is_expired`] returns `true`.
///
/// This leeway triggers preemptive refresh well before the token becomes
/// unusable, giving the HTTP refresh call time to complete while concurrent
/// callers can still use the current token.
const EXPIRY_LEEWAY_SECS: u64 = 90;

/// An access token returned by a successful authentication flow.
///
/// The token contains a [`SecretToken`] (the bearer credential), a token type
/// (typically `"Bearer"`), and an absolute expiry timestamp.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Token {
    pub(crate) access_token: SecretToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) refresh_token: Option<SecretToken>,
    pub(crate) token_type: String,
    pub(crate) expires_at: u64,
}

impl Token {
    /// Returns a reference to the access token credential.
    ///
    /// The returned [`SecretToken`] is opaque — its [`Debug`] output is masked.
    /// Pass it to API clients that need the raw bearer token.
    pub fn access_token(&self) -> &SecretToken {
        &self.access_token
    }

    /// The token type (e.g. `"Bearer"`).
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// The absolute epoch timestamp when the token expires.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// How many seconds until the token expires (computed from the current time).
    pub fn expires_in(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.expires_at.saturating_sub(now)
    }

    /// Returns `true` if the token has expired (with 90 seconds of leeway).
    ///
    /// The 90-second leeway triggers preemptive refresh well before the token
    /// becomes unusable, giving the HTTP refresh call plenty of time to complete
    /// while the current token is still valid for concurrent callers.
    ///
    /// For checking whether the token is still usable as a bearer credential,
    /// use [`is_usable`](Self::is_usable) instead.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now + EXPIRY_LEEWAY_SECS >= self.expires_at
    }

    /// Returns `true` if the token is still usable (before the actual expiry timestamp).
    ///
    /// Unlike [`is_expired`](Self::is_expired) which includes 90s leeway for preemptive
    /// refresh, this only returns `false` when the token has genuinely expired.
    pub fn is_usable(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now < self.expires_at
    }

    /// Returns a reference to the refresh token, if one was provided.
    pub fn refresh_token(&self) -> Option<&SecretToken> {
        self.refresh_token.as_ref()
    }

    /// Takes the refresh token out, leaving `None` in its place.
    pub fn take_refresh_token(&mut self) -> Option<SecretToken> {
        self.refresh_token.take()
    }

    /// Exchange a refresh token for a new [`Token`] via the `/oauth/token`
    /// endpoint.
    ///
    /// This is a static constructor — it takes a bare [`SecretToken`] (the
    /// refresh token) rather than operating on an existing `Token`. This
    /// allows callers to manage the refresh token lifecycle independently
    /// (e.g. taking it out of a cached token for cascade prevention and
    /// restoring it on failure).
    ///
    /// # Errors
    ///
    /// - [`AuthError::InvalidGrant`] — the refresh token was revoked or expired.
    /// - [`AuthError::InvalidClient`] — the client ID is not recognized.
    /// - [`AuthError::Request`] — a network error occurred.
    pub async fn refresh(
        refresh_token: &SecretToken,
        base_url: &Url,
        client_id: &str,
    ) -> Result<Token, AuthError> {
        let token_url = base_url.join("oauth/token")?;

        tracing::debug!(url = %token_url, "refreshing token");

        let resp = http_client()
            .post(token_url)
            .form(&RefreshRequest {
                grant_type: "refresh_token",
                client_id,
                refresh_token: refresh_token.as_str(),
            })
            .send()
            .await?;

        if !resp.status().is_success() {
            let err: RefreshErrorResponse = resp.json().await?;
            tracing::debug!(error = %err.error, "token refresh failed");
            return Err(match err.error.as_str() {
                "invalid_grant" => AuthError::InvalidGrant,
                "invalid_client" => AuthError::InvalidClient,
                "access_denied" => AuthError::AccessDenied,
                _ => AuthError::Server(err.error_description),
            });
        }

        let token_resp: RefreshResponse = resp.json().await?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Token {
            access_token: token_resp.access_token,
            token_type: token_resp.token_type,
            expires_at: now + token_resp.expires_in,
            refresh_token: token_resp.refresh_token,
        })
    }
}

#[derive(serde::Serialize)]
struct RefreshRequest<'a> {
    grant_type: &'a str,
    client_id: &'a str,
    refresh_token: &'a str,
}

#[derive(serde::Deserialize)]
struct RefreshResponse {
    access_token: SecretToken,
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<SecretToken>,
}

#[derive(serde::Deserialize)]
struct RefreshErrorResponse {
    error: String,
    #[serde(default)]
    error_description: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthError;
    use mocktail::prelude::*;

    fn make_token(expires_in: u64, refresh: bool) -> Token {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Token {
            access_token: SecretToken::new("test-access-token"),
            token_type: "Bearer".to_string(),
            expires_at: now + expires_in,
            refresh_token: if refresh {
                Some(SecretToken::new("test-refresh-token"))
            } else {
                None
            },
        }
    }

    fn refresh_response_json() -> serde_json::Value {
        serde_json::json!({
            "access_token": "new-access-token",
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
        let server = MockServer::new_http("token-refresh-test").with_mocks(mocks);
        server.start().await.unwrap();
        server
    }

    #[test]
    fn test_secret_token_debug_does_not_leak() {
        let token = SecretToken("super_secret_value".to_string());
        let debug = format!("{:?}", token);
        assert!(
            !debug.contains("super_secret_value"),
            "SecretToken Debug should not contain the secret, got: {debug}"
        );
    }

    // ---- refresh() tests ----

    #[tokio::test]
    async fn test_refresh_success() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json());
        });
        let server = start_server(mocks).await;
        let base_url = server.url("");

        let refresh_token = SecretToken::new("test-refresh-token");
        let refreshed = Token::refresh(&refresh_token, &base_url, "cli")
            .await
            .unwrap();

        assert_eq!(refreshed.access_token().as_str(), "new-access-token");
        assert_eq!(refreshed.token_type(), "Bearer");
        assert_eq!(
            refreshed.refresh_token().unwrap().as_str(),
            "new-refresh-token"
        );
        assert!(!refreshed.is_expired());
        assert!((3598..=3600).contains(&refreshed.expires_in()));
    }

    #[tokio::test]
    async fn test_refresh_invalid_grant() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.bad_request().json(error_json("invalid_grant"));
        });
        let server = start_server(mocks).await;
        let base_url = server.url("");

        let refresh_token = SecretToken::new("test-refresh-token");
        let err = Token::refresh(&refresh_token, &base_url, "cli")
            .await
            .unwrap_err();

        assert!(matches!(err, AuthError::InvalidGrant));
    }

    #[tokio::test]
    async fn test_refresh_invalid_client() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.bad_request().json(error_json("invalid_client"));
        });
        let server = start_server(mocks).await;
        let base_url = server.url("");

        let refresh_token = SecretToken::new("test-refresh-token");
        let err = Token::refresh(&refresh_token, &base_url, "cli")
            .await
            .unwrap_err();

        assert!(matches!(err, AuthError::InvalidClient));
    }

    #[tokio::test]
    async fn test_refresh_access_denied() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.bad_request().json(error_json("access_denied"));
        });
        let server = start_server(mocks).await;
        let base_url = server.url("");

        let refresh_token = SecretToken::new("test-refresh-token");
        let err = Token::refresh(&refresh_token, &base_url, "cli")
            .await
            .unwrap_err();

        assert!(matches!(err, AuthError::AccessDenied));
    }

    #[tokio::test]
    async fn test_refresh_unknown_error() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.bad_request().json(error_json("something_unexpected"));
        });
        let server = start_server(mocks).await;
        let base_url = server.url("");

        let refresh_token = SecretToken::new("test-refresh-token");
        let err = Token::refresh(&refresh_token, &base_url, "cli")
            .await
            .unwrap_err();

        assert!(matches!(&err, AuthError::Server(desc) if desc == "something_unexpected occurred"));
    }

    #[tokio::test]
    async fn test_refresh_response_without_new_refresh_token() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(serde_json::json!({
                "access_token": "new-access-token",
                "token_type": "Bearer",
                "expires_in": 3600
            }));
        });
        let server = start_server(mocks).await;
        let base_url = server.url("");

        let refresh_token = SecretToken::new("test-refresh-token");
        let refreshed = Token::refresh(&refresh_token, &base_url, "cli")
            .await
            .unwrap();

        assert_eq!(refreshed.access_token().as_str(), "new-access-token");
        assert!(refreshed.refresh_token().is_none());
    }

    #[tokio::test]
    async fn test_refresh_debug_does_not_leak_tokens() {
        let token = make_token(3600, true);
        let debug = format!("{:?}", token);
        assert!(
            !debug.contains("test-access-token"),
            "Debug output should not contain access token, got: {debug}"
        );
        assert!(
            !debug.contains("test-refresh-token"),
            "Debug output should not contain refresh token, got: {debug}"
        );
    }
}
