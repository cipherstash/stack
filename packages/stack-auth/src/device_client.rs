//! Post-login device client provisioning.
//!
//! After a device-code login, the caller must create a client in ZeroKMS and
//! persist the resulting secret key to disk. This module provides the
//! orchestration logic so that any consumer (not just the CLI) can perform
//! this step.

use stack_profile::{DeviceIdentity, ProfileStore};
use uuid::Uuid;
use zerokms_protocol::{CreateClientRequest, CreateClientResponse, ViturKeyMaterial, ViturRequest};

use crate::{ensure_trailing_slash, http_client, ServiceToken, Token};

fn user_agent() -> String {
    format!(
        "stack-auth/{} ({} {})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    )
}

// ---------------------------------------------------------------------------
// Secret key file (output)
// ---------------------------------------------------------------------------

const SECRET_KEY_FILENAME: &str = "secretkey.json";
const SECRET_KEY_MODE: u32 = 0o600;

/// The on-disk shape of `secretkey.json`.
///
/// Must stay in sync with `cipherstash_client::zerokms::SecretKey` which
/// deserializes this file. If that type moves to a shared crate, replace
/// this with a re-export.
#[derive(serde::Serialize)]
struct SecretKeyFile {
    client_id: Uuid,
    client_key: ViturKeyMaterial,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during device client provisioning.
#[derive(Debug, thiserror::Error)]
pub enum DeviceClientError {
    /// The profile store could not load or create required data.
    #[error("Profile error: {0}")]
    Profile(#[from] stack_profile::ProfileError),

    /// Authentication token could not be loaded or decoded.
    #[error("Auth error: {0}")]
    Auth(#[from] crate::AuthError),

    /// The HTTP request to ZeroKMS failed.
    #[error("ZeroKMS request failed: {0}")]
    Request(#[from] reqwest::Error),

    /// ZeroKMS returned a non-success, non-conflict status.
    #[error("ZeroKMS returned {status}: {body}")]
    Server { status: u16, body: String },

    /// Failed to construct the ZeroKMS endpoint URL.
    #[error("Invalid ZeroKMS URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Provision a device client after login.
///
/// Loads the auth token and device identity from disk, creates a client in
/// ZeroKMS (on the workspace's default keyset), and persists the resulting
/// secret key to the profile store.
///
/// If the secret key already exists on disk, or the server returns 409
/// (conflict), this is a no-op.
pub async fn bind_client_device(store: &ProfileStore) -> Result<(), DeviceClientError> {
    let ws_store = store.current_workspace_store()?;

    if ws_store.exists(SECRET_KEY_FILENAME) {
        tracing::debug!("secret key already exists, skipping provisioning");
        return Ok(());
    }

    let token: Token = ws_store.load_profile()?;
    let service_token = ServiceToken::new(token.access_token().clone());
    let zerokms_url = ensure_trailing_slash(service_token.zerokms_url()?);

    // DeviceIdentity is NOT workspace-scoped, so this reads from the root.
    let identity = DeviceIdentity::load_or_create(store)?;

    let request = CreateClientRequest {
        keyset_id: None,
        name: (&identity.device_name).into(),
        description: (&identity.device_name).into(),
    };

    let url = zerokms_url.join(CreateClientRequest::ENDPOINT)?;

    let response = http_client()
        .post(url)
        .header(reqwest::header::USER_AGENT, user_agent())
        .bearer_auth(service_token.as_str())
        .json(&request)
        .send()
        .await?;

    let status = response.status();

    if status == reqwest::StatusCode::CONFLICT {
        // Another client was already provisioned server-side.
        tracing::debug!("device client already exists, skipping");
        return Ok(());
    }

    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(DeviceClientError::Server {
            status: status.as_u16(),
            body,
        });
    }

    let created: CreateClientResponse = response.json().await?;

    let secret_key = SecretKeyFile {
        client_id: created.id,
        client_key: created.client_key,
    };

    ws_store.save_with_mode(SECRET_KEY_FILENAME, &secret_key, SECRET_KEY_MODE)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretToken;
    use mocktail::prelude::*;
    use tempfile::TempDir;

    fn make_test_jwt(zerokms_url: impl std::fmt::Display) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};

        let zerokms_url = zerokms_url.to_string();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
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
                "zerokms": zerokms_url,
            },
        });

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap()
    }

    const TEST_WORKSPACE_ID: &str = "ZVATKW3VHMFG27DY";

    fn save_test_token(store: &ProfileStore, access_token: &str) {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let token = Token {
            access_token: SecretToken::new(access_token),
            refresh_token: None,
            token_type: "Bearer".into(),
            expires_at: now + 3600,
            region: None,
            client_id: None,
            device_instance_id: None,
        };
        store.init_workspace(TEST_WORKSPACE_ID).unwrap();
        let ws_store = store.current_workspace_store().unwrap();
        ws_store.save_profile(&token).unwrap();
    }

    fn client_response_json() -> serde_json::Value {
        serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "dataset_id": "00000000-0000-0000-0000-000000000099",
            "name": "test-device",
            "description": "test-device",
            "client_key": "dGVzdC1rZXktbWF0ZXJpYWw="
        })
    }

    async fn start_server(mocks: MockSet) -> MockServer {
        let server = MockServer::new_http("device-client-test").with_mocks(mocks);
        server.start().await.unwrap();
        server
    }

    #[tokio::test]
    async fn provisions_and_saves_secret_key() {
        let dir = TempDir::new().unwrap();
        let store = ProfileStore::new(dir.path());

        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/create-client");
            then.json(client_response_json());
        });
        let server = start_server(mocks).await;

        let jwt = make_test_jwt(server.url("/"));
        save_test_token(&store, &jwt);

        bind_client_device(&store).await.unwrap();

        let ws_store = store.workspace_store(TEST_WORKSPACE_ID).unwrap();
        let saved: serde_json::Value = ws_store.load(SECRET_KEY_FILENAME).unwrap();
        assert_eq!(saved["client_id"], "00000000-0000-0000-0000-000000000001");
        assert_eq!(saved["client_key"], "dGVzdC1rZXktbWF0ZXJpYWw=");
    }

    #[tokio::test]
    async fn skips_when_secret_key_exists() {
        let dir = TempDir::new().unwrap();
        let store = ProfileStore::new(dir.path());
        store.init_workspace(TEST_WORKSPACE_ID).unwrap();

        // Pre-populate secretkey.json in the workspace directory
        let ws_store = store.workspace_store(TEST_WORKSPACE_ID).unwrap();
        ws_store
            .save_with_mode(
                SECRET_KEY_FILENAME,
                &serde_json::json!({"client_id": "old", "client_key": "old"}),
                SECRET_KEY_MODE,
            )
            .unwrap();

        // No mock server needed — the HTTP call should never happen.
        bind_client_device(&store).await.unwrap();

        let saved: serde_json::Value = ws_store.load(SECRET_KEY_FILENAME).unwrap();
        assert_eq!(
            saved["client_id"], "old",
            "should not overwrite existing key"
        );
    }

    #[tokio::test]
    async fn no_op_on_conflict() {
        let dir = TempDir::new().unwrap();
        let store = ProfileStore::new(dir.path());

        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/create-client");
            then.status(reqwest::StatusCode::CONFLICT)
                .json(serde_json::json!({"error": "conflict"}));
        });
        let server = start_server(mocks).await;

        let jwt = make_test_jwt(server.url("/"));
        save_test_token(&store, &jwt);

        bind_client_device(&store).await.unwrap();

        let ws_store = store.workspace_store(TEST_WORKSPACE_ID).unwrap();
        assert!(
            !ws_store.exists(SECRET_KEY_FILENAME),
            "should not write secret key on conflict"
        );
    }

    #[tokio::test]
    async fn returns_error_on_server_failure() {
        let dir = TempDir::new().unwrap();
        let store = ProfileStore::new(dir.path());

        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/create-client");
            then.status(reqwest::StatusCode::INTERNAL_SERVER_ERROR)
                .json(serde_json::json!({"error": "internal error"}));
        });
        let server = start_server(mocks).await;

        let jwt = make_test_jwt(server.url("/"));
        save_test_token(&store, &jwt);

        let err = bind_client_device(&store).await.unwrap_err();
        assert!(
            matches!(err, DeviceClientError::Server { status: 500, .. }),
            "expected Server error, got: {err:?}"
        );
    }
}
