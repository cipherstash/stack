use cts_common::{CtsServiceDiscovery, Region, ServiceDiscovery};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{AuthError, SecretToken, Token};

/// Drives the RFC 8628 device authorization flow against CTS-hosted endpoints.
pub struct DeviceCodeStrategy {
    base_url: Url,
    client_id: String,
}

/// The result of initiating a device code flow.
///
/// Contains the user-facing codes and URIs needed to complete authorization,
/// and provides [`poll_for_token`](PendingDeviceCode::poll_for_token) to
/// exchange the device code for an access token once the user has authorized.
#[derive(Debug)]
pub struct PendingDeviceCode {
    token_url: Url,
    client_id: String,
    device_code: SecretToken,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: u64,
}

impl PendingDeviceCode {
    /// The short code the user must enter to authorize this device.
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    /// The base verification URI (without the user code embedded).
    pub fn verification_uri(&self) -> &str {
        &self.verification_uri
    }

    /// The full verification URI with the user code pre-filled.
    pub fn verification_uri_complete(&self) -> &str {
        &self.verification_uri_complete
    }

    /// How many seconds the device code remains valid.
    pub fn expires_in(&self) -> u64 {
        self.expires_in
    }

    /// Open the verification URI in the user's default browser.
    ///
    /// Returns `true` if the browser was opened successfully.
    pub fn open_in_browser(&self) -> bool {
        open::that(&self.verification_uri_complete).is_ok()
    }

    /// Poll the token endpoint until the user authorizes (or the code expires).
    pub async fn poll_for_token(self) -> Result<Token, AuthError> {
        let client = reqwest::Client::new();
        let mut interval = tokio::time::Duration::from_secs(5);
        let deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_secs(self.expires_in);

        tracing::debug!(
            url = %self.token_url,
            expires_in = self.expires_in,
            "polling for token"
        );

        loop {
            tokio::time::sleep(interval).await;

            if tokio::time::Instant::now() >= deadline {
                tracing::debug!("device code expired while polling");
                return Err(AuthError::ExpiredToken);
            }

            let resp = client
                .post(self.token_url.clone())
                .form(&TokenRequest {
                    client_id: &self.client_id,
                    device_code: &self.device_code.0,
                    grant_type: "urn:ietf:params:oauth:grant-type:device_code",
                })
                .send()
                .await?;

            if resp.status().is_success() {
                tracing::debug!("token received");
                let token_resp: TokenResponse = resp.json().await?;
                return Ok(Token {
                    access_token: token_resp.access_token,
                    token_type: token_resp.token_type,
                    expires_in: token_resp.expires_in,
                });
            }

            let err: ErrorResponse = resp.json().await?;
            match err.error.as_str() {
                "authorization_pending" => {
                    tracing::debug!("authorization pending, retrying");
                    continue;
                }
                "slow_down" => {
                    interval += tokio::time::Duration::from_secs(5);
                    tracing::debug!(interval_secs = interval.as_secs(), "slowing down");
                    continue;
                }
                "expired_token" => return Err(AuthError::ExpiredToken),
                "access_denied" => return Err(AuthError::AccessDenied),
                "invalid_grant" => return Err(AuthError::InvalidGrant),
                "invalid_client" => return Err(AuthError::InvalidClient),
                _ => return Err(AuthError::Server(err.error_description)),
            }
        }
    }
}

/// Ensure a URL has a trailing slash so that `Url::join` with relative paths
/// appends to the path rather than replacing the last segment.
fn ensure_trailing_slash(mut url: Url) -> Url {
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    url
}

impl DeviceCodeStrategy {
    pub fn new(region: Region, client_id: impl Into<String>) -> Result<Self, AuthError> {
        let base_url = CtsServiceDiscovery::endpoint(region)?;
        Ok(Self {
            base_url: ensure_trailing_slash(base_url),
            client_id: client_id.into(),
        })
    }

    /// Override the base URL resolved by service discovery.
    ///
    /// Useful for pointing at a local or mock CTS instance during testing.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn with_base_url<U>(mut self, base_url: U) -> Result<Self, AuthError>
    where
        U: TryInto<Url>,
        U::Error: Into<AuthError>,
    {
        self.base_url = ensure_trailing_slash(base_url.try_into().map_err(Into::into)?);
        Ok(self)
    }

    /// Initiate the device code flow.
    ///
    /// Posts to the device code endpoint and returns a [`PendingDeviceCode`]
    /// containing the user code and verification URIs. The caller can then
    /// display these to the user and call
    /// [`poll_for_token`](PendingDeviceCode::poll_for_token) to complete the
    /// flow.
    pub async fn begin(&self) -> Result<PendingDeviceCode, AuthError> {
        let client = reqwest::Client::new();

        let code_url = self.base_url.join("oauth/device/code")?;

        tracing::debug!(url = %code_url, client_id = %self.client_id, "requesting device code");

        let code_resp = client
            .post(code_url)
            .form(&DeviceCodeRequest {
                client_id: &self.client_id,
            })
            .send()
            .await?;

        if !code_resp.status().is_success() {
            let err: ErrorResponse = code_resp.json().await?;
            tracing::debug!(error = %err.error, "device code request failed");
            return Err(match err.error.as_str() {
                "invalid_client" => AuthError::InvalidClient,
                _ => AuthError::Server(err.error_description),
            });
        }

        let code: DeviceCodeResponse = code_resp.json().await?;

        let token_url = self.base_url.join("oauth/device/token")?;

        tracing::debug!(
            user_code = %code.user_code,
            expires_in = code.expires_in,
            "device code received"
        );

        Ok(PendingDeviceCode {
            token_url,
            client_id: self.client_id.clone(),
            device_code: code.device_code,
            user_code: code.user_code,
            verification_uri: code.verification_uri,
            verification_uri_complete: code.verification_uri_complete,
            expires_in: code.expires_in,
        })
    }
}

#[derive(Deserialize)]
struct DeviceCodeResponse {
    device_code: SecretToken,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: SecretToken,
    token_type: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
    #[serde(default)]
    error_description: String,
}

#[derive(Serialize)]
struct DeviceCodeRequest<'a> {
    client_id: &'a str,
}

#[derive(Serialize)]
struct TokenRequest<'a> {
    client_id: &'a str,
    device_code: &'a str,
    grant_type: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cts_common::Region;
    use mocktail::prelude::*;

    fn device_code_json() -> serde_json::Value {
        serde_json::json!({
            "device_code": "test_device_code",
            "user_code": "ABCD-EFGH",
            "verification_uri": "http://example.com/activate",
            "verification_uri_complete": "http://example.com/activate?user_code=ABCD-EFGH",
            "expires_in": 900
        })
    }

    fn token_json() -> serde_json::Value {
        serde_json::json!({
            "access_token": "test_access_token_value",
            "token_type": "Bearer",
            "expires_in": 3600
        })
    }

    fn error_json(error: &str) -> serde_json::Value {
        serde_json::json!({
            "error": error,
            "error_description": format!("{error} occurred")
        })
    }

    fn mock_code_endpoint(mocks: &mut MockSet) {
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/code");
            then.json(device_code_json());
        });
    }

    async fn start_server(mocks: MockSet) -> MockServer {
        let server = MockServer::new_http("stack-auth-test").with_mocks(mocks);
        server.start().await.unwrap();
        server
    }

    fn strategy_for(server: &MockServer) -> DeviceCodeStrategy {
        DeviceCodeStrategy::new(Region::aws("ap-southeast-2").unwrap(), "cli")
            .unwrap()
            .with_base_url(server.url(""))
            .unwrap()
    }

    // ---- begin() tests ----

    #[tokio::test]
    async fn test_begin_returns_pending_device_code() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        let server = start_server(mocks).await;

        let pending = strategy_for(&server).begin().await.unwrap();

        assert_eq!(pending.user_code(), "ABCD-EFGH");
        assert_eq!(pending.verification_uri(), "http://example.com/activate");
        assert_eq!(
            pending.verification_uri_complete(),
            "http://example.com/activate?user_code=ABCD-EFGH"
        );
        assert_eq!(pending.expires_in(), 900);
    }

    #[tokio::test]
    async fn test_begin_invalid_client() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/code");
            then.bad_request().json(error_json("invalid_client"));
        });
        let server = start_server(mocks).await;

        let err = strategy_for(&server).begin().await.unwrap_err();

        assert!(matches!(err, AuthError::InvalidClient));
    }

    #[tokio::test]
    async fn test_begin_server_error() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/code");
            then.bad_request().json(error_json("server_error"));
        });
        let server = start_server(mocks).await;

        let err = strategy_for(&server).begin().await.unwrap_err();

        assert!(matches!(&err, AuthError::Server(desc) if desc == "server_error occurred"));
    }

    // ---- poll_for_token() tests ----

    /// Helper: calls begin() against a server that already has the code mock,
    /// then returns the PendingDeviceCode ready for polling.
    async fn begin_pending(server: &MockServer) -> PendingDeviceCode {
        strategy_for(server).begin().await.unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn test_poll_for_token_success() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.json(token_json());
        });
        let server = start_server(mocks).await;

        let token = begin_pending(&server).await.poll_for_token().await.unwrap();

        assert_eq!(token.access_token().0, "test_access_token_value");
        assert_eq!(token.token_type(), "Bearer");
        assert_eq!(token.expires_in(), 3600);
    }

    #[tokio::test(start_paused = true)]
    async fn test_poll_for_token_access_denied() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.bad_request().json(error_json("access_denied"));
        });
        let server = start_server(mocks).await;

        let err = begin_pending(&server)
            .await
            .poll_for_token()
            .await
            .unwrap_err();

        assert!(matches!(err, AuthError::AccessDenied));
    }

    #[tokio::test(start_paused = true)]
    async fn test_poll_for_token_expired_token() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.bad_request().json(error_json("expired_token"));
        });
        let server = start_server(mocks).await;

        let err = begin_pending(&server)
            .await
            .poll_for_token()
            .await
            .unwrap_err();

        assert!(matches!(err, AuthError::ExpiredToken));
    }

    #[tokio::test(start_paused = true)]
    async fn test_poll_for_token_invalid_grant() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.bad_request().json(error_json("invalid_grant"));
        });
        let server = start_server(mocks).await;

        let err = begin_pending(&server)
            .await
            .poll_for_token()
            .await
            .unwrap_err();

        assert!(matches!(err, AuthError::InvalidGrant));
    }

    #[tokio::test(start_paused = true)]
    async fn test_poll_for_token_invalid_client() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.bad_request().json(error_json("invalid_client"));
        });
        let server = start_server(mocks).await;

        let err = begin_pending(&server)
            .await
            .poll_for_token()
            .await
            .unwrap_err();

        assert!(matches!(err, AuthError::InvalidClient));
    }

    #[tokio::test(start_paused = true)]
    async fn test_poll_for_token_unknown_error() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.bad_request().json(error_json("something_unexpected"));
        });
        let server = start_server(mocks).await;

        let err = begin_pending(&server)
            .await
            .poll_for_token()
            .await
            .unwrap_err();

        assert!(matches!(&err, AuthError::Server(desc) if desc == "something_unexpected occurred"));
    }

    #[tokio::test(start_paused = true)]
    async fn test_poll_for_token_authorization_pending_then_success() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.bad_request().json(error_json("authorization_pending"));
        });
        let server = start_server(mocks).await;
        let pending = begin_pending(&server).await;

        // Use tokio::join! so the swap future can borrow server.mocks() directly
        // (the shared RwLock) rather than cloning the MockSet.
        // First poll at T=5s returns "authorization_pending".
        // At T=6s the mock is swapped. Second poll at T=10s returns success.
        let (result, _) = tokio::join!(pending.poll_for_token(), async {
            tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;
            server.mocks().clear();
            server.mocks().mock(|when, then| {
                when.post().path("/oauth/device/token");
                then.json(token_json());
            });
        });

        let token = result.unwrap();
        assert_eq!(token.access_token().0, "test_access_token_value");
    }

    #[tokio::test(start_paused = true)]
    async fn test_poll_for_token_slow_down_then_success() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.bad_request().json(error_json("slow_down"));
        });
        let server = start_server(mocks).await;
        let pending = begin_pending(&server).await;

        // First poll returns "slow_down", interval increases to 10s.
        // Swap the mock to return success before the second poll.
        let (result, _) = tokio::join!(pending.poll_for_token(), async {
            tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;
            server.mocks().clear();
            server.mocks().mock(|when, then| {
                when.post().path("/oauth/device/token");
                then.json(token_json());
            });
        });

        let token = result.unwrap();
        assert_eq!(token.access_token().0, "test_access_token_value");
    }

    /// Proves that `slow_down` increases the poll interval: with a short
    /// `expires_in`, the increased interval pushes the next poll past the
    /// deadline, causing an `ExpiredToken` error.
    #[tokio::test(start_paused = true)]
    async fn test_poll_for_token_slow_down_increases_interval() {
        let mut mocks = MockSet::new();
        // expires_in = 12: without slow_down, second poll at T=10 is within
        // the deadline. With slow_down, interval becomes 10s, so second poll
        // at T=15 exceeds the 12s deadline.
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/code");
            then.json(serde_json::json!({
                "device_code": "test_device_code",
                "user_code": "ABCD-EFGH",
                "verification_uri": "http://example.com/activate",
                "verification_uri_complete": "http://example.com/activate?user_code=ABCD-EFGH",
                "expires_in": 12
            }));
        });
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.bad_request().json(error_json("slow_down"));
        });
        let server = start_server(mocks).await;
        let pending = begin_pending(&server).await;

        let err = pending.poll_for_token().await.unwrap_err();

        assert!(matches!(err, AuthError::ExpiredToken));
    }

    // ---- ensure_trailing_slash / URL join tests ----

    #[test]
    fn test_ensure_trailing_slash_adds_slash() {
        let url = Url::parse("http://localhost:3001").unwrap();
        let result = ensure_trailing_slash(url);
        assert_eq!(result.as_str(), "http://localhost:3001/");
    }

    #[test]
    fn test_ensure_trailing_slash_preserves_existing() {
        let url = Url::parse("http://localhost:3001/").unwrap();
        let result = ensure_trailing_slash(url);
        assert_eq!(result.as_str(), "http://localhost:3001/");
    }

    #[test]
    fn test_ensure_trailing_slash_with_path() {
        let url = Url::parse("http://localhost:3001/api/v1").unwrap();
        let result = ensure_trailing_slash(url);
        assert_eq!(result.as_str(), "http://localhost:3001/api/v1/");
    }

    #[test]
    fn test_relative_join_preserves_base_path() {
        let base = ensure_trailing_slash(Url::parse("http://localhost:3001/api/v1").unwrap());
        let joined = base.join("oauth/device/code").unwrap();
        assert_eq!(
            joined.as_str(),
            "http://localhost:3001/api/v1/oauth/device/code"
        );
    }

    #[test]
    fn test_relative_join_on_root_url() {
        let base = ensure_trailing_slash(Url::parse("http://localhost:3001").unwrap());
        let joined = base.join("oauth/device/code").unwrap();
        assert_eq!(joined.as_str(), "http://localhost:3001/oauth/device/code");
    }

    #[tokio::test]
    async fn test_pending_device_code_debug_does_not_leak() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        let server = start_server(mocks).await;

        let pending = begin_pending(&server).await;
        let debug = format!("{:?}", pending);

        assert!(
            !debug.contains("test_device_code"),
            "PendingDeviceCode Debug should not contain the device code, got: {debug}"
        );
    }
}
