use mocktail::prelude::*;
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Build a valid JWT access token containing a workspace claim.
///
/// Used by mock endpoints that need to return a token that can be decoded
/// by `Token::workspace_id()`.
fn test_jwt() -> String {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[allow(clippy::expect_used)]
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs();

    let claims = serde_json::json!({
        "iss": "https://cts.example.com/",
        "sub": "CS|test-user",
        "aud": "test-audience",
        "iat": now,
        "exp": now + 3600,
        "workspace": "ZVATKW3VHMFG27DY",
        "scope": "",
    });

    #[allow(clippy::expect_used)]
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(b"test-secret"),
    )
    .expect("JWT encode")
}

#[napi]
pub struct MockAuthServer {
    server: MockServer,
}

#[napi]
impl MockAuthServer {
    /// Start a mock auth server on a random port.
    #[napi(factory)]
    pub async fn start() -> Result<Self> {
        let server = MockServer::new_http("stack-auth-node-vitest");
        server
            .start()
            .await
            .map_err(|e| napi::Error::new(Status::GenericFailure, format!("{e}")))?;
        Ok(Self { server })
    }

    /// The base URL of the running mock server (e.g. `http://127.0.0.1:12345`).
    #[napi(getter)]
    pub fn base_url(&self) -> String {
        self.server.url("").to_string()
    }

    /// Register a mock for `POST /oauth/device/code` that returns a standard
    /// device-code JSON response.
    #[napi]
    pub fn mock_device_code_endpoint(&self) {
        self.server.mocks().mock(|when, then| {
            when.post().path("/oauth/device/code");
            then.json(serde_json::json!({
                "device_code": "test_device_code",
                "user_code": "ABCD-EFGH",
                "verification_uri": "http://example.com/activate",
                "verification_uri_complete": "http://example.com/activate?user_code=ABCD-EFGH",
                "expires_in": 900
            }));
        });
    }

    /// Register a mock for `POST /oauth/device/token` that returns a standard
    /// token JSON response.
    #[napi]
    pub fn mock_token_endpoint(&self) {
        let jwt = test_jwt();
        self.server.mocks().mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.json(serde_json::json!({
                "access_token": jwt,
                "token_type": "Bearer",
                "expires_in": 3600
            }));
        });
    }

    /// Register a mock for `POST /oauth/device/token` that returns a 400 error
    /// with the given OAuth error code and optional description.
    #[napi]
    pub fn mock_token_endpoint_error(&self, code: String, description: Option<String>) {
        let desc = description.unwrap_or_else(|| format!("{code} occurred"));
        self.server.mocks().mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.bad_request().json(serde_json::json!({
                "error": code,
                "error_description": desc,
            }));
        });
    }

    /// Register a mock for `POST /api/authorise` that returns a successful
    /// federation response (`{ accessToken, expiry }`), as CTS would for an
    /// `OidcFederationStrategy` JWT exchange.
    ///
    /// `expiry` (seconds until the CTS token expires) defaults to 3600. Pass a
    /// small value to exercise re-federation on expiry.
    #[napi]
    pub fn mock_authorize_endpoint(&self, expiry: Option<u32>) {
        let jwt = test_jwt();
        let expiry = expiry.unwrap_or(3600);
        self.server.mocks().mock(move |when, then| {
            when.post().path("/api/authorise");
            then.json(serde_json::json!({
                "accessToken": jwt,
                "expiry": expiry,
            }));
        });
    }

    /// Register a mock for `POST /api/authorise` that returns a 500 error.
    #[napi]
    pub fn mock_authorize_endpoint_error(&self) {
        self.server.mocks().mock(|when, then| {
            when.post().path("/api/authorise");
            then.internal_server_error()
                .json(serde_json::json!({"error": "federation failed"}));
        });
    }

    /// Register a mock for `POST /create-client` that returns a successful
    /// create-client JSON response (as ZeroKMS would).
    #[napi]
    pub fn mock_create_client_endpoint(&self) {
        self.server.mocks().mock(|when, then| {
            when.post().path("/create-client");
            then.json(serde_json::json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "dataset_id": "00000000-0000-0000-0000-000000000099",
                "name": "test-device",
                "description": "test-device",
                "client_key": "dGVzdC1rZXktbWF0ZXJpYWw="
            }));
        });
    }

    /// Register a mock for `POST /create-client` that returns a 409 conflict.
    #[napi]
    pub fn mock_create_client_conflict(&self) {
        self.server.mocks().mock(|when, then| {
            when.post().path("/create-client");
            then.status(reqwest::StatusCode::CONFLICT)
                .json(serde_json::json!({"error": "conflict"}));
        });
    }

    /// Remove all registered mocks.
    #[napi]
    pub fn clear_mocks(&self) {
        self.server.mocks().clear();
    }
}
