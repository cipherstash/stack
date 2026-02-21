use std::sync::Mutex;

use stack_auth::{AuthError, DeviceCodeStrategy, PendingDeviceCode};
use cts_common::Region;
use napi::bindgen_prelude::*;
use napi_derive::napi;

#[cfg(feature = "test-utils")]
mod mock_auth_server;

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

fn error_code(err: &AuthError) -> &'static str {
    match err {
        AuthError::Request(_) => "REQUEST_ERROR",
        AuthError::AccessDenied => "ACCESS_DENIED",
        AuthError::ExpiredToken => "EXPIRED_TOKEN",
        AuthError::InvalidGrant => "INVALID_GRANT",
        AuthError::InvalidClient => "INVALID_CLIENT",
        AuthError::InvalidUrl(_) => "INVALID_URL",
        AuthError::Region(_) => "INVALID_REGION",
        AuthError::Server(_) => "SERVER_ERROR",
        AuthError::Store(_) => "STORE_ERROR",
        _ => "UNKNOWN_ERROR",
    }
}

fn to_napi_error(err: AuthError) -> napi::Error {
    let code = error_code(&err);
    napi::Error::new(Status::GenericFailure, format!("{code}: {err}"))
}

// ---------------------------------------------------------------------------
// TokenResult — plain data object
// ---------------------------------------------------------------------------

/// Metadata returned after a successful device code authentication.
///
/// The actual token is never exposed to JavaScript — it is saved directly
/// to `~/.cipherstash/auth.json` by the Rust layer.
#[derive(Debug)]
#[napi(object)]
pub struct AuthResult {
    /// Absolute epoch timestamp (seconds) when the token expires.
    pub expires_at: f64,
    /// Number of seconds before the token expires (computed at time of return).
    pub expires_in: f64,
}

// ---------------------------------------------------------------------------
// DeviceCodeResult — class with methods
// ---------------------------------------------------------------------------

#[derive(Debug)]
#[napi]
pub struct DeviceCodeResult {
    /// The short code the user must enter to authorize this device.
    user_code: String,
    /// The base verification URI (without the user code embedded).
    verification_uri: String,
    /// The full verification URI with the user code pre-filled.
    verification_uri_complete: String,
    /// How many seconds the device code remains valid.
    expires_in: f64,
    /// The pending device code handle (consumed by `pollForToken`).
    pending: Mutex<Option<PendingDeviceCode>>,
}

#[napi]
impl DeviceCodeResult {
    #[napi(getter)]
    pub fn user_code(&self) -> String {
        self.user_code.clone()
    }

    #[napi(getter)]
    pub fn verification_uri(&self) -> String {
        self.verification_uri.clone()
    }

    #[napi(getter, js_name = "verificationUriComplete")]
    pub fn verification_uri_complete(&self) -> String {
        self.verification_uri_complete.clone()
    }

    #[napi(getter)]
    pub fn expires_in(&self) -> f64 {
        self.expires_in
    }

    /// Poll the auth server until the user completes authorization.
    ///
    /// **Consumes** the internal handle — it cannot be reused after this call.
    /// If you need to open the browser, call `openInBrowser` *before*
    /// `pollForToken`.
    #[napi]
    pub async fn poll_for_token(&self) -> Result<AuthResult> {
        let pending = self
            .pending
            .lock()
            .map_err(|_| napi::Error::new(Status::GenericFailure, "Lock poisoned"))?
            .take()
            .ok_or_else(|| {
                napi::Error::new(
                    Status::GenericFailure,
                    "Device code handle has already been consumed",
                )
            })?;

        let token = pending.poll_for_token().await.map_err(to_napi_error)?;

        Ok(AuthResult {
            expires_at: token.expires_at() as f64,
            expires_in: token.expires_in() as f64,
        })
    }

    /// Open the verification URI in the user's default browser.
    ///
    /// Does **not** consume the handle — you can still call `pollForToken`
    /// afterwards.
    #[napi]
    pub fn open_in_browser(&self) -> Result<bool> {
        let guard = self
            .pending
            .lock()
            .map_err(|_| napi::Error::new(Status::GenericFailure, "Lock poisoned"))?;

        match guard.as_ref() {
            Some(pending) => Ok(pending.open_in_browser()),
            None => Err(napi::Error::new(
                Status::GenericFailure,
                "Device code handle has already been consumed",
            )),
        }
    }
}

impl DeviceCodeResult {
    fn from_pending(pending: PendingDeviceCode) -> Self {
        Self {
            user_code: pending.user_code().to_string(),
            verification_uri: pending.verification_uri().to_string(),
            verification_uri_complete: pending.verification_uri_complete().to_string(),
            expires_in: pending.expires_in() as f64,
            pending: Mutex::new(Some(pending)),
        }
    }
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/// Begin the OAuth 2.0 Device Authorization flow.
#[napi]
pub async fn begin_device_code_flow(
    region: String,
    client_id: String,
) -> Result<DeviceCodeResult> {
    let region = Region::new(&region).map_err(|e| to_napi_error(AuthError::from(e)))?;
    let strategy = DeviceCodeStrategy::new(region, client_id).map_err(to_napi_error)?;
    let pending = strategy.begin().await.map_err(to_napi_error)?;
    Ok(DeviceCodeResult::from_pending(pending))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use cts_common::Region;
    use mocktail::prelude::*;

    // --- Mock response builders (mirrors stack-auth/src/device_code.rs) ---

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
        let server = MockServer::new_http("stack-auth-node-test").with_mocks(mocks);
        server.start().await.unwrap();
        server
    }

    /// Create a `DeviceCodeResult` by running the real `DeviceCodeStrategy`
    /// against a mock server, then wrapping the `PendingDeviceCode`.
    async fn begin_result(server: &MockServer) -> DeviceCodeResult {
        let strategy =
            DeviceCodeStrategy::builder(Region::aws("ap-southeast-2").unwrap(), "test-client")
                .base_url(server.url(""))
                .build()
                .unwrap();
        let pending = strategy.begin().await.unwrap();
        DeviceCodeResult::from_pending(pending)
    }

    // ---- Error mapping (no mock server needed) ----

    #[test]
    fn test_error_code_mapping() {
        assert_eq!(error_code(&AuthError::AccessDenied), "ACCESS_DENIED");
        assert_eq!(error_code(&AuthError::ExpiredToken), "EXPIRED_TOKEN");
        assert_eq!(error_code(&AuthError::InvalidGrant), "INVALID_GRANT");
        assert_eq!(error_code(&AuthError::InvalidClient), "INVALID_CLIENT");
        assert_eq!(
            error_code(&AuthError::InvalidUrl(
                "http://[".parse::<url::Url>().unwrap_err()
            )),
            "INVALID_URL"
        );
        assert_eq!(
            error_code(&AuthError::Region(Region::new("invalid").unwrap_err())),
            "INVALID_REGION"
        );
        assert_eq!(
            error_code(&AuthError::Server("test".to_string())),
            "SERVER_ERROR"
        );
    }

    #[test]
    fn test_napi_error_format() {
        let err = to_napi_error(AuthError::AccessDenied);
        assert!(
            err.reason.starts_with("ACCESS_DENIED: "),
            "expected 'ACCESS_DENIED: ...' but got: {}",
            err.reason
        );

        let err = to_napi_error(AuthError::Server("something broke".to_string()));
        assert!(
            err.reason.starts_with("SERVER_ERROR: "),
            "expected 'SERVER_ERROR: ...' but got: {}",
            err.reason
        );
    }

    // ---- Getters (mock server needed to create a real PendingDeviceCode) ----

    #[tokio::test]
    async fn test_getters() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        let server = start_server(mocks).await;

        let result = begin_result(&server).await;

        assert_eq!(result.user_code(), "ABCD-EFGH");
        assert_eq!(result.verification_uri(), "http://example.com/activate");
        assert_eq!(
            result.verification_uri_complete(),
            "http://example.com/activate?user_code=ABCD-EFGH"
        );
        assert_eq!(result.expires_in(), 900.0);
    }

    // ---- Full flow with mock server ----
    //
    // `start_paused = true` creates a tokio runtime where the internal clock
    // is paused. Timer operations like `tokio::time::sleep` advance the clock
    // instantly instead of waiting in real-time. This matters because
    // `poll_for_token` sleeps 5 seconds between each poll — without paused
    // time these tests would take 5+ real seconds each. I/O (HTTP requests
    // to the mock server) still works normally.

    #[tokio::test(start_paused = true)]
    async fn test_poll_for_token_success() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.json(token_json());
        });
        let server = start_server(mocks).await;

        let result = begin_result(&server).await;
        let token = result.poll_for_token().await.unwrap();

        assert!(token.expires_in >= 3598.0 && token.expires_in <= 3600.0);
        assert!(token.expires_at > 0.0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_poll_for_token_error_propagation() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.bad_request().json(error_json("access_denied"));
        });
        let server = start_server(mocks).await;

        let result = begin_result(&server).await;
        let err = result.poll_for_token().await.unwrap_err();

        assert!(
            err.reason.contains("ACCESS_DENIED: "),
            "expected ACCESS_DENIED error, got: {}",
            err.reason
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_poll_for_token_expired() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.bad_request().json(error_json("expired_token"));
        });
        let server = start_server(mocks).await;

        let result = begin_result(&server).await;
        let err = result.poll_for_token().await.unwrap_err();

        assert!(
            err.reason.contains("EXPIRED_TOKEN: "),
            "expected EXPIRED_TOKEN error, got: {}",
            err.reason
        );
    }

    // ---- Consumed handle semantics ----

    #[tokio::test(start_paused = true)]
    async fn test_poll_for_token_already_consumed() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.json(token_json());
        });
        let server = start_server(mocks).await;

        let result = begin_result(&server).await;
        // First call succeeds — consumes the handle
        result.poll_for_token().await.unwrap();
        // Second call should fail — handle already consumed
        let err = result.poll_for_token().await.unwrap_err();

        assert!(
            err.reason.contains("already been consumed"),
            "expected 'already been consumed' error, got: {}",
            err.reason
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_open_in_browser_after_consumed() {
        let mut mocks = MockSet::new();
        mock_code_endpoint(&mut mocks);
        mocks.mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.json(token_json());
        });
        let server = start_server(mocks).await;

        let result = begin_result(&server).await;
        // Consume the handle
        result.poll_for_token().await.unwrap();
        // open_in_browser should fail — handle consumed
        let err = result.open_in_browser().unwrap_err();

        assert!(
            err.reason.contains("already been consumed"),
            "expected 'already been consumed' error, got: {}",
            err.reason
        );
    }

    // ---- Top-level function error handling ----

    #[tokio::test]
    async fn test_begin_invalid_region() {
        let err = begin_device_code_flow("not-a-region".to_string(), "test-client".to_string())
            .await
            .unwrap_err();

        assert!(
            err.reason.contains("INVALID_REGION: "),
            "expected INVALID_REGION error, got: {}",
            err.reason
        );
    }
}

/// Variant of `beginDeviceCodeFlow` that targets a custom auth server URL.
///
/// Intended for **testing only** — requires the crate to be built with the
/// `test-utils` Cargo feature.
#[cfg(feature = "test-utils")]
#[napi]
pub async fn begin_device_code_flow_with_base_url(
    region: String,
    client_id: String,
    base_url: String,
) -> Result<DeviceCodeResult> {
    let region = Region::new(&region).map_err(|e| to_napi_error(AuthError::from(e)))?;
    let parsed_url: url::Url = base_url
        .parse()
        .map_err(|e: url::ParseError| to_napi_error(AuthError::from(e)))?;
    let strategy = DeviceCodeStrategy::builder(region, client_id)
        .base_url(parsed_url)
        .build()
        .map_err(to_napi_error)?;
    let pending = strategy.begin().await.map_err(to_napi_error)?;
    Ok(DeviceCodeResult::from_pending(pending))
}
