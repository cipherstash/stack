use std::time::{SystemTime, UNIX_EPOCH};

use url::Url;

use crate::{AuthError, SecretToken};

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

    /// Returns `true` if the token has expired (with 60 seconds of leeway).
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now + 60 >= self.expires_at
    }

    /// Returns a reference to the refresh token, if one was provided.
    pub fn refresh_token(&self) -> Option<&SecretToken> {
        self.refresh_token.as_ref()
    }

    /// Refresh this token using the `/oauth/token` endpoint.
    ///
    /// Consumes `self` and returns a new [`Token`] with a fresh access token.
    /// The `base_url` should be the CTS auth server base URL (e.g. from service
    /// discovery) and `client_id` the OAuth client identifier.
    ///
    /// # Errors
    ///
    /// - [`AuthError::NoRefreshToken`] — this token has no refresh token.
    /// - [`AuthError::InvalidGrant`] — the refresh token was revoked or expired.
    /// - [`AuthError::InvalidClient`] — the client ID is not recognized.
    /// - [`AuthError::Request`] — a network error occurred.
    pub async fn refresh(self, base_url: &Url, client_id: &str) -> Result<Token, AuthError> {
        let refresh_token = self.refresh_token.ok_or(AuthError::NoRefreshToken)?;

        let token_url = base_url.join("oauth/token")?;

        tracing::debug!(url = %token_url, "refreshing token");

        let resp = reqwest::Client::new()
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

    #[test]
    fn test_secret_token_debug_does_not_leak() {
        let token = SecretToken("super_secret_value".to_string());
        let debug = format!("{:?}", token);
        assert!(
            !debug.contains("super_secret_value"),
            "SecretToken Debug should not contain the secret, got: {debug}"
        );
    }
}
