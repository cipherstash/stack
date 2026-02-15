use mocktail::prelude::*;
use napi::bindgen_prelude::*;
use napi_derive::napi;

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
        self.server.mocks().mock(|when, then| {
            when.post().path("/oauth/device/token");
            then.json(serde_json::json!({
                "access_token": "test_access_token_value",
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

    /// Remove all registered mocks.
    #[napi]
    pub fn clear_mocks(&self) {
        self.server.mocks().clear();
    }
}
