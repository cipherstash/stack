use super::*;
use cts_common::Region;
use mocktail::prelude::*;
use tempfile::TempDir;

fn device_code_json() -> serde_json::Value {
    serde_json::json!({
        "device_code": "test_device_code",
        "user_code": "ABCD-EFGH",
        "verification_uri": "http://example.com/activate",
        "verification_uri_complete": "http://example.com/activate?user_code=ABCD-EFGH",
        "expires_in": 900
    })
}

/// Build a valid JWT access token containing a workspace claim.
fn test_access_token() -> String {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
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

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(b"test-secret"),
    )
    .unwrap()
}

fn token_json() -> serde_json::Value {
    serde_json::json!({
        "access_token": test_access_token(),
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

fn strategy_for(server: &MockServer, dir: &TempDir) -> DeviceCodeStrategy {
    DeviceCodeStrategy::builder(Region::aws("ap-southeast-2").unwrap(), "cli")
        .base_url(server.url(""))
        .profile_dir(dir.path())
        .build()
        .unwrap()
}

// ---- begin() tests ----

#[tokio::test]
async fn test_begin_returns_pending_device_code() {
    let dir = TempDir::new().unwrap();
    let mut mocks = MockSet::new();
    mock_code_endpoint(&mut mocks);
    let server = start_server(mocks).await;

    let pending = strategy_for(&server, &dir).begin().await.unwrap();

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
    let dir = TempDir::new().unwrap();
    let mut mocks = MockSet::new();
    mocks.mock(|when, then| {
        when.post().path("/oauth/device/code");
        then.bad_request().json(error_json("invalid_client"));
    });
    let server = start_server(mocks).await;

    let err = strategy_for(&server, &dir).begin().await.unwrap_err();

    assert!(matches!(err, AuthError::InvalidClient));
}

#[tokio::test]
async fn test_begin_server_error() {
    let dir = TempDir::new().unwrap();
    let mut mocks = MockSet::new();
    mocks.mock(|when, then| {
        when.post().path("/oauth/device/code");
        then.bad_request().json(error_json("server_error"));
    });
    let server = start_server(mocks).await;

    let err = strategy_for(&server, &dir).begin().await.unwrap_err();

    assert!(matches!(&err, AuthError::Server(desc) if desc == "server_error occurred"));
}

// ---- poll_for_token() tests ----

/// Helper: calls begin() against a server that already has the code mock,
/// then returns the PendingDeviceCode ready for polling.
async fn begin_pending(server: &MockServer, dir: &TempDir) -> PendingDeviceCode {
    strategy_for(server, dir).begin().await.unwrap()
}

#[tokio::test(start_paused = true)]
async fn test_poll_for_token_success() {
    let dir = TempDir::new().unwrap();
    let mut mocks = MockSet::new();
    mock_code_endpoint(&mut mocks);
    mocks.mock(|when, then| {
        when.post().path("/oauth/device/token");
        then.json(token_json());
    });
    let server = start_server(mocks).await;

    let token = begin_pending(&server, &dir)
        .await
        .poll_for_token()
        .await
        .unwrap();

    assert_eq!(token.token_type(), "Bearer");
    assert!(!token.is_expired());
    assert!((3598..=3600).contains(&token.expires_in()));
    assert_eq!(
        token.workspace_id().unwrap().as_str(),
        "ZVATKW3VHMFG27DY",
        "workspace ID should be extracted from the JWT"
    );

    // Verify the token was persisted to the workspace directory
    let store = ProfileStore::new(dir.path());
    assert_eq!(
        store.current_workspace().unwrap(),
        "ZVATKW3VHMFG27DY",
        "current workspace should be set after poll_for_token"
    );
}

#[tokio::test(start_paused = true)]
async fn test_poll_for_token_access_denied() {
    let dir = TempDir::new().unwrap();
    let mut mocks = MockSet::new();
    mock_code_endpoint(&mut mocks);
    mocks.mock(|when, then| {
        when.post().path("/oauth/device/token");
        then.bad_request().json(error_json("access_denied"));
    });
    let server = start_server(mocks).await;

    let err = begin_pending(&server, &dir)
        .await
        .poll_for_token()
        .await
        .unwrap_err();

    assert!(matches!(err, AuthError::AccessDenied));
}

#[tokio::test(start_paused = true)]
async fn test_poll_for_token_expired_token() {
    let dir = TempDir::new().unwrap();
    let mut mocks = MockSet::new();
    mock_code_endpoint(&mut mocks);
    mocks.mock(|when, then| {
        when.post().path("/oauth/device/token");
        then.bad_request().json(error_json("expired_token"));
    });
    let server = start_server(mocks).await;

    let err = begin_pending(&server, &dir)
        .await
        .poll_for_token()
        .await
        .unwrap_err();

    assert!(matches!(err, AuthError::TokenExpired));
}

#[tokio::test(start_paused = true)]
async fn test_poll_for_token_invalid_grant() {
    let dir = TempDir::new().unwrap();
    let mut mocks = MockSet::new();
    mock_code_endpoint(&mut mocks);
    mocks.mock(|when, then| {
        when.post().path("/oauth/device/token");
        then.bad_request().json(error_json("invalid_grant"));
    });
    let server = start_server(mocks).await;

    let err = begin_pending(&server, &dir)
        .await
        .poll_for_token()
        .await
        .unwrap_err();

    assert!(matches!(err, AuthError::InvalidGrant));
}

#[tokio::test(start_paused = true)]
async fn test_poll_for_token_invalid_client() {
    let dir = TempDir::new().unwrap();
    let mut mocks = MockSet::new();
    mock_code_endpoint(&mut mocks);
    mocks.mock(|when, then| {
        when.post().path("/oauth/device/token");
        then.bad_request().json(error_json("invalid_client"));
    });
    let server = start_server(mocks).await;

    let err = begin_pending(&server, &dir)
        .await
        .poll_for_token()
        .await
        .unwrap_err();

    assert!(matches!(err, AuthError::InvalidClient));
}

#[tokio::test(start_paused = true)]
async fn test_poll_for_token_unknown_error() {
    let dir = TempDir::new().unwrap();
    let mut mocks = MockSet::new();
    mock_code_endpoint(&mut mocks);
    mocks.mock(|when, then| {
        when.post().path("/oauth/device/token");
        then.bad_request().json(error_json("something_unexpected"));
    });
    let server = start_server(mocks).await;

    let err = begin_pending(&server, &dir)
        .await
        .poll_for_token()
        .await
        .unwrap_err();

    assert!(matches!(&err, AuthError::Server(desc) if desc == "something_unexpected occurred"));
}

#[tokio::test(start_paused = true)]
async fn test_poll_for_token_authorization_pending_then_success() {
    let dir = TempDir::new().unwrap();
    let mut mocks = MockSet::new();
    mock_code_endpoint(&mut mocks);
    mocks.mock(|when, then| {
        when.post().path("/oauth/device/token");
        then.bad_request().json(error_json("authorization_pending"));
    });
    let server = start_server(mocks).await;
    let pending = begin_pending(&server, &dir).await;

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
    assert_eq!(token.token_type(), "Bearer");
    assert!(
        token.workspace_id().is_ok(),
        "token should contain a valid workspace claim"
    );
}

#[tokio::test(start_paused = true)]
async fn test_poll_for_token_slow_down_then_success() {
    let dir = TempDir::new().unwrap();
    let mut mocks = MockSet::new();
    mock_code_endpoint(&mut mocks);
    mocks.mock(|when, then| {
        when.post().path("/oauth/device/token");
        then.bad_request().json(error_json("slow_down"));
    });
    let server = start_server(mocks).await;
    let pending = begin_pending(&server, &dir).await;

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
    assert_eq!(token.token_type(), "Bearer");
    assert!(
        token.workspace_id().is_ok(),
        "token should contain a valid workspace claim"
    );
}

/// Proves that `slow_down` increases the poll interval: with a short
/// `expires_in`, the increased interval pushes the next poll past the
/// deadline, causing a `TokenExpired` error.
#[tokio::test(start_paused = true)]
async fn test_poll_for_token_slow_down_increases_interval() {
    let dir = TempDir::new().unwrap();
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
    let pending = begin_pending(&server, &dir).await;

    let err = pending.poll_for_token().await.unwrap_err();

    assert!(matches!(err, AuthError::TokenExpired));
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
    let dir = TempDir::new().unwrap();
    let mut mocks = MockSet::new();
    mock_code_endpoint(&mut mocks);
    let server = start_server(mocks).await;

    let pending = begin_pending(&server, &dir).await;
    let debug = format!("{:?}", pending);

    assert!(
        !debug.contains("test_device_code"),
        "PendingDeviceCode Debug should not contain the device code, got: {debug}"
    );
}
