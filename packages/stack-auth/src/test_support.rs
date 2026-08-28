//! Shared, crate-internal test helpers for minting [`Token`]s.
//!
//! Several test modules need a token carrying specific JWT claims, or a token
//! with an arbitrary raw access-token string. Keeping one definition here avoids
//! the fixture drift that comes from copy-pasting the `Token { .. }` literal and
//! the unsigned-JWT mint into every test module.

#[cfg(feature = "http")]
use cts_common::Crn;

use crate::{SecretToken, Token};

/// A [`Token`] with the given raw access-token string and a far-future expiry,
/// so it reads as valid. The access token need not be a JWT — pass any string to
/// exercise the not-a-JWT paths.
pub(crate) fn raw_token(access_token: &str) -> Token {
    Token {
        access_token: SecretToken::new(access_token),
        token_type: "Bearer".to_string(),
        expires_at: u64::MAX,
        refresh_token: Some(SecretToken::new("refresh-token")),
        region: None,
        client_id: None,
        device_instance_id: None,
    }
}

/// A [`Token`] whose access token is a real (unsigned) JWT carrying `claims`.
pub(crate) fn jwt_token(claims: serde_json::Value) -> Token {
    use jsonwebtoken::{encode, EncodingKey, Header};
    let jwt = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(b"test-secret"),
    )
    .expect("encode JWT");
    raw_token(&jwt)
}

/// Standard CTS JWT claims for `workspace`, with the other required claims
/// (`iss`/`sub`/`aud`/`iat`/`exp`/`org_id`/`scope`) filled in with valid placeholders.
///
/// NOTE: `exp` is a fixed *past* epoch, so the token reads as expired — use
/// [`jwt_with_workspace`] instead when a currently-valid token is needed.
pub(crate) fn claims_with_workspace(workspace: &str) -> serde_json::Value {
    serde_json::json!({
        "workspace": workspace,
        "iss": "https://cts.example.com",
        "sub": "user-123",
        "aud": "https://cts.example.com",
        "iat": 1_700_000_000u64,
        "exp": 1_700_003_600u64,
        "org_id": "org_test_default",
        "scope": "dataset:create",
    })
}

/// A workspace [`Crn`] in the standard test region (`ap-southeast-2.aws`)
/// carrying the given `workspace` ID.
///
/// Only the http-gated CRN-bound strategies have tests that need one.
#[cfg(feature = "http")]
pub(crate) fn crn_with_workspace(workspace: &str) -> Crn {
    format!("crn:ap-southeast-2.aws:{workspace}")
        .parse()
        .expect("test CRN parses")
}

/// A real (unsigned) JWT *string* carrying the given `workspace` claim and a
/// currently-valid (`now + 1h`) expiry — for exercising the post-auth
/// workspace verification that CRN-bound strategies run. Unlike
/// [`claims_with_workspace`], whose `exp` is a fixed past epoch, the token this
/// mints reads as valid.
#[cfg(feature = "http")]
pub(crate) fn jwt_with_workspace(workspace: &str) -> String {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let claims = serde_json::json!({
        "iss": "https://cts.example.com/",
        "sub": "CS|test-principal",
        "aud": "test-audience",
        "iat": now,
        "exp": now + 3600,
        "workspace": workspace,
        "org_id": "org_test_default",
        "scope": "",
    });
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(b"test-secret"),
    )
    .expect("JWT encode")
}
