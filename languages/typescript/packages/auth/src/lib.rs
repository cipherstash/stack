use std::collections::HashMap;
use std::sync::Mutex;

use cts_common::Region;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use stack_auth::{
    AuthError, AuthStrategy, DeviceClientError, DeviceCodeStrategy, PendingDeviceCode, ServiceToken,
};
use vitaminc_protected::OpaqueDebug;

#[cfg(feature = "test-utils")]
mod mock_auth_server;

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

fn error_code(err: &AuthError) -> &'static str {
    match err {
        AuthError::Request(_) => "REQUEST_ERROR",
        AuthError::AccessDenied => "ACCESS_DENIED",
        AuthError::TokenExpired => "EXPIRED_TOKEN",
        AuthError::InvalidGrant => "INVALID_GRANT",
        AuthError::InvalidClient => "INVALID_CLIENT",
        AuthError::InvalidUrl(_) => "INVALID_URL",
        AuthError::Region(_) => "INVALID_REGION",
        AuthError::InvalidToken(_) => "INVALID_TOKEN",
        AuthError::Server(_) => "SERVER_ERROR",
        AuthError::Store(_) => "STORE_ERROR",
        AuthError::NotAuthenticated => "NOT_AUTHENTICATED",
        AuthError::MissingWorkspaceCrn => "MISSING_WORKSPACE_CRN",
        AuthError::InvalidAccessKey(_) => "INVALID_ACCESS_KEY",
        AuthError::InvalidCrn(_) => "INVALID_CRN",
        _ => "UNKNOWN_ERROR",
    }
}

fn to_napi_error(err: AuthError) -> napi::Error {
    let code = error_code(&err);
    napi::Error::new(Status::GenericFailure, format!("{code}: {err}"))
}

// ---------------------------------------------------------------------------
// TokenResult — returned by strategy.getToken()
// ---------------------------------------------------------------------------

/// The result of a successful `getToken()` call.
///
/// Contains the bearer credential and decoded JWT claims for service discovery.
#[derive(OpaqueDebug)]
#[napi(object)]
pub struct TokenResult {
    /// The bearer token string (used as `Authorization: Bearer <token>`).
    pub token: String,
    /// The subject claim from the JWT (e.g. `"CS|auth0|user123"` or `"CS|CSAKkeyId"`).
    pub subject: String,
    /// The workspace identifier from the JWT.
    pub workspace_id: String,
    /// The issuer URL from the JWT `iss` claim (i.e. the CTS host).
    pub issuer: String,
    /// Service endpoint URLs from the JWT `services` claim (e.g. `{ zerokms: "https://..." }`).
    pub services: HashMap<String, String>,
}

fn token_result_from(token: ServiceToken) -> Result<TokenResult> {
    let subject = token.subject().map_err(to_napi_error)?.to_string();
    let workspace_id = token.workspace_id().map_err(to_napi_error)?.to_string();
    let issuer = token.issuer().map_err(to_napi_error)?.to_string();
    let services = token
        .services()
        .map_err(to_napi_error)?
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_string()))
        .collect();

    Ok(TokenResult {
        token: token.as_str().to_string(),
        subject,
        workspace_id,
        issuer,
        services,
    })
}

// ---------------------------------------------------------------------------
// AutoStrategy — auto-detect credentials
// ---------------------------------------------------------------------------

/// Options for `AutoStrategy.detect()`.
#[derive(Debug)]
#[napi(object)]
pub struct AutoStrategyOptions {
    /// An explicit access key (takes precedence over `CS_CLIENT_ACCESS_KEY` env var).
    pub access_key: Option<String>,
    /// An explicit workspace CRN (takes precedence over `CS_WORKSPACE_CRN` env var).
    pub workspace_crn: Option<String>,
}

/// An auth strategy that auto-detects credentials from environment variables
/// and the local profile store.
///
/// Detection order:
/// 1. `CS_CLIENT_ACCESS_KEY` env var (or explicit `accessKey` option) → access key auth
/// 2. `~/.cipherstash/auth.json` → OAuth token auth
/// 3. Error: not authenticated
#[napi]
pub struct AutoStrategy {
    inner: stack_auth::AutoStrategy,
}

#[napi]
impl AutoStrategy {
    /// Detect available credentials and return an `AutoStrategy`.
    ///
    /// Pass options to provide explicit values that take precedence over
    /// environment variables.
    #[napi(factory)]
    pub fn detect(options: Option<AutoStrategyOptions>) -> Result<Self> {
        let mut builder = stack_auth::AutoStrategy::builder();

        if let Some(opts) = options {
            if let Some(key) = opts.access_key {
                builder = builder.with_access_key(key);
            }
            if let Some(crn_str) = opts.workspace_crn {
                let crn = crn_str
                    .parse()
                    .map_err(|e| to_napi_error(AuthError::InvalidCrn(e)))?;
                builder = builder.with_workspace_crn(crn);
            }
        }

        let inner = builder.detect().map_err(to_napi_error)?;
        Ok(Self { inner })
    }

    /// Retrieve a valid access token, refreshing or re-authenticating as needed.
    #[napi]
    pub async fn get_token(&self) -> Result<TokenResult> {
        let token = (&self.inner).get_token().await.map_err(to_napi_error)?;
        token_result_from(token)
    }
}

// ---------------------------------------------------------------------------
// AccessKeyStrategy — static access key auth
// ---------------------------------------------------------------------------

/// An auth strategy that uses a static access key for service-to-service
/// or CI/CD authentication.
#[napi]
pub struct AccessKeyStrategy {
    inner: stack_auth::AccessKeyStrategy,
}

#[napi]
impl AccessKeyStrategy {
    /// Create a new `AccessKeyStrategy` for the given region and access key.
    #[napi(factory)]
    pub fn create(region: String, access_key: String) -> Result<Self> {
        let region = Region::new(&region).map_err(|e| to_napi_error(AuthError::from(e)))?;
        let key: stack_auth::AccessKey = access_key
            .parse()
            .map_err(|e| to_napi_error(AuthError::from(e)))?;
        let inner = stack_auth::AccessKeyStrategy::new(region, key).map_err(to_napi_error)?;
        Ok(Self { inner })
    }

    /// Retrieve a valid access token, refreshing or re-authenticating as needed.
    #[napi]
    pub async fn get_token(&self) -> Result<TokenResult> {
        let token = (&self.inner).get_token().await.map_err(to_napi_error)?;
        token_result_from(token)
    }
}

// ---------------------------------------------------------------------------
// OAuthStrategy — OAuth with profile store
// ---------------------------------------------------------------------------

/// An auth strategy that uses OAuth refresh tokens persisted to disk
/// (`~/.cipherstash/auth.json`).
#[napi]
pub struct OAuthStrategy {
    inner: stack_auth::OAuthStrategy,
}

#[napi]
impl OAuthStrategy {
    /// Load credentials from the default profile store and create an `OAuthStrategy`.
    #[napi(factory)]
    pub fn from_profile() -> Result<Self> {
        let store = stack_profile::ProfileStore::resolve(None)
            .map_err(|e| to_napi_error(AuthError::from(e)))?;
        let inner = stack_auth::OAuthStrategy::with_profile(store)
            .build()
            .map_err(to_napi_error)?;
        Ok(Self { inner })
    }

    /// Retrieve a valid access token, refreshing as needed.
    #[napi]
    pub async fn get_token(&self) -> Result<TokenResult> {
        let token = (&self.inner).get_token().await.map_err(to_napi_error)?;
        token_result_from(token)
    }
}

// ---------------------------------------------------------------------------
// AuthResult — plain data object (device code flow)
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

fn device_client_error_code(err: &DeviceClientError) -> &'static str {
    match err {
        DeviceClientError::Profile(_) => "STORE_ERROR",
        DeviceClientError::Auth(auth_err) => error_code(auth_err),
        DeviceClientError::Request(_) => "REQUEST_ERROR",
        DeviceClientError::Server { .. } => "SERVER_ERROR",
        DeviceClientError::InvalidUrl(_) => "INVALID_URL",
    }
}

fn device_client_to_napi_error(err: DeviceClientError) -> napi::Error {
    let code = device_client_error_code(&err);
    napi::Error::new(Status::GenericFailure, format!("{code}: {err}"))
}

/// Provision a device client in ZeroKMS after login.
///
/// Loads the auth token and device identity from `~/.cipherstash/`,
/// creates a client on the workspace's default keyset, and persists the
/// resulting secret key to `~/.cipherstash/secretkey.json`.
///
/// This is a no-op if the secret key already exists or the server returns
/// 409 (conflict).
#[napi]
pub async fn bind_client_device() -> Result<()> {
    let store = stack_profile::ProfileStore::resolve(None)
        .map_err(|e| device_client_to_napi_error(DeviceClientError::from(e)))?;
    stack_auth::bind_client_device(&store)
        .await
        .map_err(device_client_to_napi_error)
}

/// Begin the OAuth 2.0 Device Authorization flow.
#[napi]
pub async fn begin_device_code_flow(region: String, client_id: String) -> Result<DeviceCodeResult> {
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
    use tempfile::TempDir;

    // --- Shared helpers ---

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
    async fn begin_result(server: &MockServer, dir: &TempDir) -> DeviceCodeResult {
        let strategy =
            DeviceCodeStrategy::builder(Region::aws("ap-southeast-2").unwrap(), "test-client")
                .base_url(server.url(""))
                .profile_dir(dir.path())
                .build()
                .unwrap();
        let pending = strategy.begin().await.unwrap();
        DeviceCodeResult::from_pending(pending)
    }

    fn make_service_token(iss: &str, zerokms_url: &str) -> ServiceToken {
        use jsonwebtoken::{encode, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = serde_json::json!({
            "iss": iss,
            "sub": "CS|test-user",
            "aud": "test-aud",
            "iat": now,
            "exp": now + 3600,
            "workspace": "ZVATKW3VHMFG27DY",
            "scope": "",
            "services": { "zerokms": zerokms_url },
        });

        let jwt = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap();

        ServiceToken::new(stack_auth::SecretToken::new(jwt))
    }

    /// Extract the error from a `Result<T, napi::Error>` without requiring
    /// `T: Debug` (NAPI wrapper structs don't implement it).
    fn expect_err<T>(result: Result<T>) -> napi::Error {
        match result {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    mod assertions {
        /// Assert that a NAPI error's reason contains the expected error code prefix.
        pub(super) fn has_error_code(err: &napi::Error, expected_code: &str) {
            assert!(
                err.reason.contains(&format!("{expected_code}: ")),
                "expected '{expected_code}: ...' but got: {}",
                err.reason
            );
        }
    }

    // --- Error mapping ---

    mod error_mapping {
        use super::*;

        #[test]
        fn maps_all_auth_error_variants() {
            assert_eq!(
                error_code(&AuthError::AccessDenied),
                "ACCESS_DENIED",
                "AccessDenied should map to ACCESS_DENIED"
            );
            assert_eq!(
                error_code(&AuthError::TokenExpired),
                "EXPIRED_TOKEN",
                "TokenExpired should map to EXPIRED_TOKEN"
            );
            assert_eq!(
                error_code(&AuthError::InvalidGrant),
                "INVALID_GRANT",
                "InvalidGrant should map to INVALID_GRANT"
            );
            assert_eq!(
                error_code(&AuthError::InvalidClient),
                "INVALID_CLIENT",
                "InvalidClient should map to INVALID_CLIENT"
            );
            assert_eq!(
                error_code(&AuthError::InvalidUrl(
                    "http://[".parse::<url::Url>().unwrap_err()
                )),
                "INVALID_URL",
                "InvalidUrl should map to INVALID_URL"
            );
            assert_eq!(
                error_code(&AuthError::Region(Region::new("invalid").unwrap_err())),
                "INVALID_REGION",
                "Region should map to INVALID_REGION"
            );
            assert_eq!(
                error_code(&AuthError::Server("test".to_string())),
                "SERVER_ERROR",
                "Server should map to SERVER_ERROR"
            );
            assert_eq!(
                error_code(&AuthError::NotAuthenticated),
                "NOT_AUTHENTICATED",
                "NotAuthenticated should map to NOT_AUTHENTICATED"
            );
            assert_eq!(
                error_code(&AuthError::MissingWorkspaceCrn),
                "MISSING_WORKSPACE_CRN",
                "MissingWorkspaceCrn should map to MISSING_WORKSPACE_CRN"
            );
            assert_eq!(
                error_code(&AuthError::InvalidAccessKey(
                    "bad-key".parse::<stack_auth::AccessKey>().unwrap_err()
                )),
                "INVALID_ACCESS_KEY",
                "InvalidAccessKey should map to INVALID_ACCESS_KEY"
            );
            assert_eq!(
                error_code(&AuthError::InvalidCrn(
                    "not-a-crn".parse::<cts_common::Crn>().unwrap_err()
                )),
                "INVALID_CRN",
                "InvalidCrn should map to INVALID_CRN"
            );
        }

        #[test]
        fn formats_as_code_colon_message() {
            let err = to_napi_error(AuthError::AccessDenied);
            assertions::has_error_code(&err, "ACCESS_DENIED");

            let err = to_napi_error(AuthError::Server("something broke".to_string()));
            assertions::has_error_code(&err, "SERVER_ERROR");
        }
    }

    // --- Device code result ---
    //
    // `start_paused = true` creates a tokio runtime where the internal clock
    // is paused. Timer operations like `tokio::time::sleep` advance the clock
    // instantly instead of waiting in real-time. This matters because
    // `poll_for_token` sleeps 5 seconds between each poll — without paused
    // time these tests would take 5+ real seconds each. I/O (HTTP requests
    // to the mock server) still works normally.

    mod device_code_result {
        use super::*;

        mod given_pending_device_code {
            use super::*;

            #[tokio::test]
            async fn exposes_getters() {
                let dir = TempDir::new().unwrap();
                let mut mocks = MockSet::new();
                mock_code_endpoint(&mut mocks);
                let server = start_server(mocks).await;

                let result = begin_result(&server, &dir).await;

                assert_eq!(
                    result.user_code(),
                    "ABCD-EFGH",
                    "user_code should match device code response"
                );
                assert_eq!(
                    result.verification_uri(),
                    "http://example.com/activate",
                    "verification_uri should match device code response"
                );
                assert_eq!(
                    result.verification_uri_complete(),
                    "http://example.com/activate?user_code=ABCD-EFGH",
                    "verification_uri_complete should include user code"
                );
                assert_eq!(
                    result.expires_in(),
                    900.0,
                    "expires_in should match device code response"
                );
            }

            mod given_successful_token_exchange {
                use super::*;

                #[tokio::test(start_paused = true)]
                async fn returns_expiry_metadata() {
                    let dir = TempDir::new().unwrap();
                    let mut mocks = MockSet::new();
                    mock_code_endpoint(&mut mocks);
                    mocks.mock(|when, then| {
                        when.post().path("/oauth/device/token");
                        then.json(token_json());
                    });
                    let server = start_server(mocks).await;

                    let result = begin_result(&server, &dir).await;
                    let token = result.poll_for_token().await.unwrap();

                    assert!(
                        token.expires_in >= 3598.0 && token.expires_in <= 3600.0,
                        "expires_in should be ~3600, got: {}",
                        token.expires_in
                    );
                    assert!(
                        token.expires_at > 0.0,
                        "expires_at should be a positive epoch timestamp"
                    );
                }
            }

            mod given_access_denied {
                use super::*;

                #[tokio::test(start_paused = true)]
                async fn returns_access_denied_error() {
                    let dir = TempDir::new().unwrap();
                    let mut mocks = MockSet::new();
                    mock_code_endpoint(&mut mocks);
                    mocks.mock(|when, then| {
                        when.post().path("/oauth/device/token");
                        then.bad_request().json(error_json("access_denied"));
                    });
                    let server = start_server(mocks).await;

                    let result = begin_result(&server, &dir).await;
                    let err = result.poll_for_token().await.unwrap_err();

                    assertions::has_error_code(&err, "ACCESS_DENIED");
                }
            }

            mod given_expired_token {
                use super::*;

                #[tokio::test(start_paused = true)]
                async fn returns_expired_token_error() {
                    let dir = TempDir::new().unwrap();
                    let mut mocks = MockSet::new();
                    mock_code_endpoint(&mut mocks);
                    mocks.mock(|when, then| {
                        when.post().path("/oauth/device/token");
                        then.bad_request().json(error_json("expired_token"));
                    });
                    let server = start_server(mocks).await;

                    let result = begin_result(&server, &dir).await;
                    let err = result.poll_for_token().await.unwrap_err();

                    assertions::has_error_code(&err, "EXPIRED_TOKEN");
                }
            }

            mod given_consumed_handle {
                use super::*;

                async fn consumed_result(server: &MockServer, dir: &TempDir) -> DeviceCodeResult {
                    let result = begin_result(server, dir).await;
                    result.poll_for_token().await.unwrap();
                    result
                }

                #[tokio::test(start_paused = true)]
                async fn poll_for_token_returns_consumed_error() {
                    let dir = TempDir::new().unwrap();
                    let mut mocks = MockSet::new();
                    mock_code_endpoint(&mut mocks);
                    mocks.mock(|when, then| {
                        when.post().path("/oauth/device/token");
                        then.json(token_json());
                    });
                    let server = start_server(mocks).await;

                    let result = consumed_result(&server, &dir).await;
                    let err = result.poll_for_token().await.unwrap_err();

                    assert!(
                        err.reason.contains("already been consumed"),
                        "second poll_for_token call should fail with consumed error, got: {}",
                        err.reason
                    );
                }

                #[tokio::test(start_paused = true)]
                async fn open_in_browser_returns_consumed_error() {
                    let dir = TempDir::new().unwrap();
                    let mut mocks = MockSet::new();
                    mock_code_endpoint(&mut mocks);
                    mocks.mock(|when, then| {
                        when.post().path("/oauth/device/token");
                        then.json(token_json());
                    });
                    let server = start_server(mocks).await;

                    let result = consumed_result(&server, &dir).await;
                    let err = result.open_in_browser().unwrap_err();

                    assert!(
                        err.reason.contains("already been consumed"),
                        "open_in_browser after consume should fail, got: {}",
                        err.reason
                    );
                }
            }
        }

        mod given_invalid_region {
            use super::*;

            #[tokio::test]
            async fn returns_invalid_region_error() {
                let err =
                    begin_device_code_flow("not-a-region".to_string(), "test-client".to_string())
                        .await
                        .unwrap_err();

                assertions::has_error_code(&err, "INVALID_REGION");
            }
        }
    }

    // --- token_result_from ---

    mod token_result {
        use super::*;

        mod given_valid_jwt {
            use super::*;

            #[test]
            fn includes_bearer_token_and_claims() {
                let service_token =
                    make_service_token("https://cts.example.com/", "https://zerokms.example.com/");
                let result = token_result_from(service_token).unwrap();

                assert!(!result.token.is_empty(), "token string should not be empty");
                assert_eq!(
                    result.subject, "CS|test-user",
                    "subject should match JWT sub claim"
                );
                assert_eq!(
                    result.workspace_id, "ZVATKW3VHMFG27DY",
                    "workspace_id should match JWT workspace claim"
                );
                assert_eq!(
                    result.issuer, "https://cts.example.com/",
                    "issuer should match JWT iss claim"
                );
                assert_eq!(
                    result.services.get("zerokms").map(String::as_str),
                    Some("https://zerokms.example.com/"),
                    "services should include zerokms endpoint"
                );
            }
        }

        mod given_non_jwt {
            use super::*;

            #[test]
            fn returns_invalid_token_error() {
                let token = ServiceToken::new(stack_auth::SecretToken::new("not-a-jwt"));
                let err = token_result_from(token).unwrap_err();

                assertions::has_error_code(&err, "INVALID_TOKEN");
            }
        }
    }

    // --- Strategy factories ---

    mod auto_strategy_detect {
        use super::*;

        mod given_access_key_without_crn {
            use super::*;

            #[test]
            fn returns_missing_workspace_crn_error() {
                let saved_key = std::env::var("CS_CLIENT_ACCESS_KEY").ok();
                let saved_crn = std::env::var("CS_WORKSPACE_CRN").ok();
                std::env::remove_var("CS_CLIENT_ACCESS_KEY");
                std::env::remove_var("CS_WORKSPACE_CRN");

                let err = expect_err(AutoStrategy::detect(Some(AutoStrategyOptions {
                    access_key: Some("CSAKtestKeyId.testKeySecret".to_string()),
                    workspace_crn: None,
                })));

                if let Some(val) = saved_key {
                    std::env::set_var("CS_CLIENT_ACCESS_KEY", val);
                }
                if let Some(val) = saved_crn {
                    std::env::set_var("CS_WORKSPACE_CRN", val);
                }

                assertions::has_error_code(&err, "MISSING_WORKSPACE_CRN");
            }
        }

        mod given_invalid_crn {
            use super::*;

            #[test]
            fn returns_invalid_crn_error() {
                let err = expect_err(AutoStrategy::detect(Some(AutoStrategyOptions {
                    access_key: Some("CSAKtestKeyId.testKeySecret".to_string()),
                    workspace_crn: Some("not-a-crn".to_string()),
                })));

                assertions::has_error_code(&err, "INVALID_CRN");
            }
        }
    }

    mod access_key_strategy_create {
        use super::*;

        mod given_invalid_region {
            use super::*;

            #[test]
            fn returns_invalid_region_error() {
                let err = expect_err(AccessKeyStrategy::create(
                    "not-a-region".to_string(),
                    "CSAKid.secret".to_string(),
                ));

                assertions::has_error_code(&err, "INVALID_REGION");
            }
        }

        mod given_invalid_key {
            use super::*;

            #[test]
            fn returns_invalid_access_key_error() {
                let err = expect_err(AccessKeyStrategy::create(
                    "ap-southeast-2.aws".to_string(),
                    "not-a-valid-key".to_string(),
                ));

                assertions::has_error_code(&err, "INVALID_ACCESS_KEY");
            }
        }
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

/// Variant of `provisionDeviceClient` that uses a custom profile directory.
///
/// Intended for **testing only** — requires the crate to be built with the
/// `test-utils` Cargo feature.
#[cfg(feature = "test-utils")]
#[napi]
pub async fn bind_client_device_with_profile_dir(profile_dir: String) -> Result<()> {
    let store = stack_profile::ProfileStore::new(&profile_dir);
    stack_auth::bind_client_device(&store)
        .await
        .map_err(device_client_to_napi_error)
}

/// Save a test auth token to the given profile directory with the ZeroKMS
/// service URL set to `zerokms_base_url`.
///
/// Intended for **testing only** — requires the crate to be built with the
/// `test-utils` Cargo feature.
#[cfg(feature = "test-utils")]
#[napi]
pub fn save_test_token(profile_dir: String, zerokms_base_url: String) -> Result<()> {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| napi::Error::new(Status::GenericFailure, format!("{e}")))?
        .as_secs();

    let claims = serde_json::json!({
        "iss": "https://cts.example.com/",
        "sub": "CS|test-user",
        "aud": "legacy-aud-value",
        "iat": now,
        "exp": now + 3600,
        "workspace": "ZVATKW3VHMFG27DY",
        "scope": "",
        "services": {
            "zerokms": zerokms_base_url,
        },
    });

    let jwt = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(b"test-secret"),
    )
    .map_err(|e| napi::Error::new(Status::GenericFailure, format!("{e}")))?;

    let token_json = serde_json::json!({
        "access_token": jwt,
        "token_type": "Bearer",
        "expires_at": now + 3600,
    });

    let store = stack_profile::ProfileStore::new(&profile_dir);
    store
        .save_with_mode("auth.json", &token_json, 0o600)
        .map_err(|e| napi::Error::new(Status::GenericFailure, format!("{e}")))?;

    Ok(())
}
