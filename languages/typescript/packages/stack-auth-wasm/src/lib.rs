//! WebAssembly bindings for `stack-auth`.
//!
//! Mirrors the wasm-compatible subset of the `stack-auth-node` napi crate.
//! Targets Supabase Edge Functions (Deno) and bundler consumers via
//! `wasm-pack build --target deno` / `--target bundler`.
//!
//! Excluded vs the napi crate (these can't work on wasm32):
//!
//! - `bindClientDevice` / `beginDeviceCodeFlow` — filesystem identity and browser launch
//! - `OAuthStrategy.fromProfile` — filesystem-backed profile store
//! - `AutoStrategy` profile-store fallback — `detect()` on wasm only resolves via env vars

use std::collections::HashMap;

use cts_common::Region;
use serde::{Deserialize, Serialize};
use stack_auth::{AuthError, AuthStrategy, ServiceToken, Token};
use wasm_bindgen::prelude::*;

/// Install the `console_error_panic_hook` exactly once. Called from the
/// public constructors so any panic in the upstream auth stack lands as a
/// readable `console.error` instead of an opaque `RuntimeError: unreachable`.
fn install_panic_hook() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(console_error_panic_hook::set_once);
}

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
        AuthError::NotAuthenticated => "NOT_AUTHENTICATED",
        AuthError::MissingWorkspaceCrn => "MISSING_WORKSPACE_CRN",
        AuthError::InvalidAccessKey(_) => "INVALID_ACCESS_KEY",
        AuthError::InvalidCrn(_) => "INVALID_CRN",
        _ => "UNKNOWN_ERROR",
    }
}

/// Build a JS `Error` enriched with a `.code` property — matches the
/// `AuthError` shape exposed by `stack-auth-node`. `.message` is the plain
/// error text; the machine-readable identifier lives on `.code`.
fn to_js_error(err: AuthError) -> JsValue {
    let code = error_code(&err);
    let js_err = js_sys::Error::new(&err.to_string());
    let _ = js_sys::Reflect::set(
        &js_err,
        &JsValue::from_str("code"),
        &JsValue::from_str(code),
    );
    js_err.into()
}

/// Build a JS `TypeError` enriched with a `.code` property. Used when the
/// caller passes structurally invalid input to a binding (vs. an auth-layer
/// failure, which uses [`to_js_error`]).
fn to_js_type_error(message: &str, code: &str) -> JsValue {
    let js_err = js_sys::TypeError::new(message);
    let _ = js_sys::Reflect::set(
        &js_err,
        &JsValue::from_str("code"),
        &JsValue::from_str(code),
    );
    js_err.into()
}

// ---------------------------------------------------------------------------
// TokenResult — returned by strategy.getToken()
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct TokenResultPayload {
    token: String,
    subject: String,
    #[serde(rename = "workspaceId")]
    workspace_id: String,
    issuer: String,
    services: HashMap<String, String>,
}

fn token_result_from(token: ServiceToken) -> Result<JsValue, JsValue> {
    let subject = token.subject().map_err(to_js_error)?.to_string();
    let workspace_id = token.workspace_id().map_err(to_js_error)?.to_string();
    let issuer = token.issuer().map_err(to_js_error)?.to_string();
    let services = token
        .services()
        .map_err(to_js_error)?
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_string()))
        .collect();

    let payload = TokenResultPayload {
        token: token.as_str().to_string(),
        subject,
        workspace_id,
        issuer,
        services,
    };
    serde_wasm_bindgen::to_value(&payload).map_err(JsValue::from)
}

// ---------------------------------------------------------------------------
// AutoStrategyOptions — plain JS object deserialized from JsValue
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AutoStrategyOptions {
    #[serde(default)]
    access_key: Option<String>,
    #[serde(default)]
    workspace_crn: Option<String>,
}

// ---------------------------------------------------------------------------
// TokenInput — camelCase JS shape, bridged to `stack_auth::Token`
// ---------------------------------------------------------------------------
//
// `stack_auth::Token` has `pub(crate)` fields, so we can't construct one
// directly. Instead we deserialize a `TokenInput` (camelCase, idiomatic for
// JS callers) and JSON-round-trip it into the snake_case shape `Token`
// expects.

#[derive(Deserialize)]
struct TokenInput {
    #[serde(rename = "accessToken", alias = "access_token")]
    access_token: String,
    #[serde(rename = "refreshToken", alias = "refresh_token", default)]
    refresh_token: Option<String>,
    #[serde(rename = "tokenType", alias = "token_type")]
    token_type: String,
    #[serde(rename = "expiresAt", alias = "expires_at")]
    expires_at: u64,
    #[serde(default)]
    region: Option<String>,
    #[serde(rename = "clientId", alias = "client_id", default)]
    client_id: Option<String>,
    #[serde(rename = "deviceInstanceId", alias = "device_instance_id", default)]
    device_instance_id: Option<String>,
}

fn parse_token_input(value: JsValue) -> Result<Token, AuthError> {
    let input: TokenInput = serde_wasm_bindgen::from_value(value)
        .map_err(|e| AuthError::InvalidToken(e.to_string()))?;
    // Build the snake_case JSON shape that `Token`'s Deserialize expects.
    // We can't construct `Token` directly because its fields are `pub(crate)`.
    let mut snake = serde_json::Map::new();
    snake.insert(
        "access_token".into(),
        serde_json::Value::String(input.access_token),
    );
    snake.insert(
        "token_type".into(),
        serde_json::Value::String(input.token_type),
    );
    snake.insert(
        "expires_at".into(),
        serde_json::Value::Number(input.expires_at.into()),
    );
    if let Some(v) = input.refresh_token {
        snake.insert("refresh_token".into(), serde_json::Value::String(v));
    }
    if let Some(v) = input.region {
        snake.insert("region".into(), serde_json::Value::String(v));
    }
    if let Some(v) = input.client_id {
        snake.insert("client_id".into(), serde_json::Value::String(v));
    }
    if let Some(v) = input.device_instance_id {
        snake.insert("device_instance_id".into(), serde_json::Value::String(v));
    }
    serde_json::from_value(serde_json::Value::Object(snake))
        .map_err(|e| AuthError::InvalidToken(e.to_string()))
}

// ---------------------------------------------------------------------------
// AccessKeyStrategy
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub struct AccessKeyStrategy {
    inner: stack_auth::AccessKeyStrategy,
}

#[wasm_bindgen]
impl AccessKeyStrategy {
    /// Create a new `AccessKeyStrategy` for the given region and access key.
    pub fn create(region: String, access_key: String) -> Result<AccessKeyStrategy, JsValue> {
        install_panic_hook();
        let region = Region::new(&region).map_err(|e| to_js_error(AuthError::from(e)))?;
        let key: stack_auth::AccessKey = access_key
            .parse()
            .map_err(|e| to_js_error(AuthError::from(e)))?;
        let inner = stack_auth::AccessKeyStrategy::new(region, key).map_err(to_js_error)?;
        Ok(AccessKeyStrategy { inner })
    }

    /// Retrieve a valid access token, refreshing or re-authenticating as needed.
    #[wasm_bindgen(js_name = getToken)]
    pub async fn get_token(&self) -> Result<JsValue, JsValue> {
        let token = (&self.inner).get_token().await.map_err(to_js_error)?;
        token_result_from(token)
    }
}

// ---------------------------------------------------------------------------
// OAuthStrategy
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub struct OAuthStrategy {
    inner: stack_auth::OAuthStrategy,
}

#[wasm_bindgen]
impl OAuthStrategy {
    /// Build an `OAuthStrategy` from a caller-supplied token. The token is
    /// held in memory only — there is no persistence on wasm.
    ///
    /// `token` must be a JS object shaped like:
    /// `{ accessToken: string, refreshToken?: string, tokenType: string,
    ///    expiresAt: number, region?: string, clientId?: string,
    ///    deviceInstanceId?: string }`.
    ///
    /// The Rust `Token` struct uses `snake_case` field names internally, so
    /// the deserialisation goes through a small shim that accepts either casing
    /// for forward compatibility.
    #[wasm_bindgen(js_name = withToken)]
    pub fn with_token(
        region: String,
        client_id: String,
        token: JsValue,
    ) -> Result<OAuthStrategy, JsValue> {
        install_panic_hook();
        let region = Region::new(&region).map_err(|e| to_js_error(AuthError::from(e)))?;
        let token = parse_token_input(token).map_err(to_js_error)?;
        let inner = stack_auth::OAuthStrategy::with_token(region, client_id, token)
            .build()
            .map_err(to_js_error)?;
        Ok(OAuthStrategy { inner })
    }

    /// Retrieve a valid access token, refreshing as needed via the embedded
    /// refresh token.
    #[wasm_bindgen(js_name = getToken)]
    pub async fn get_token(&self) -> Result<JsValue, JsValue> {
        let token = (&self.inner).get_token().await.map_err(to_js_error)?;
        token_result_from(token)
    }
}

// ---------------------------------------------------------------------------
// AutoStrategy
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub struct AutoStrategy {
    inner: stack_auth::AutoStrategy,
}

#[wasm_bindgen]
impl AutoStrategy {
    /// Detect available credentials and return an `AutoStrategy`.
    ///
    /// On wasm32 there is no profile store fallback — `detect()` resolves
    /// only via the `CS_CLIENT_ACCESS_KEY` / `CS_WORKSPACE_CRN` env vars or
    /// the explicit values passed in `options`.
    pub fn detect(options: Option<JsValue>) -> Result<AutoStrategy, JsValue> {
        install_panic_hook();
        let mut builder = stack_auth::AutoStrategy::builder();

        if let Some(options) = options.filter(|v| !v.is_null() && !v.is_undefined()) {
            let opts: AutoStrategyOptions =
                serde_wasm_bindgen::from_value(options).map_err(|e| {
                    to_js_type_error(&format!("invalid options: {e}"), "INVALID_ARGUMENT")
                })?;
            if let Some(key) = opts.access_key {
                builder = builder.with_access_key(key);
            }
            if let Some(crn_str) = opts.workspace_crn {
                let crn = crn_str
                    .parse()
                    .map_err(|e| to_js_error(AuthError::InvalidCrn(e)))?;
                builder = builder.with_workspace_crn(crn);
            }
        }

        let inner = builder.detect().map_err(to_js_error)?;
        Ok(AutoStrategy { inner })
    }

    /// Retrieve a valid access token, refreshing or re-authenticating as needed.
    #[wasm_bindgen(js_name = getToken)]
    pub async fn get_token(&self) -> Result<JsValue, JsValue> {
        let token = (&self.inner).get_token().await.map_err(to_js_error)?;
        token_result_from(token)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Tests are gated on `target_arch = "wasm32"` and driven by
// `wasm-bindgen-test`. Native `cargo test` doesn't exercise this crate
// (the bindings only make sense in a wasm runtime). The CI invocation is
// `wasm-pack test --node packages/stack-auth/wasm`.

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use base64::Engine;
    use stack_auth::SecretToken;
    use wasm_bindgen_test::wasm_bindgen_test;

    // -------- JWT fixture --------

    /// Build an unsigned JWT-shaped token: `<header>.<payload>.<sig>`.
    /// Signature segment is a dummy `"sig"` literal — `decode_jwt_payload_wasm`
    /// in stack-auth only reads the payload segment and ignores the signature.
    fn make_jwt(claims: serde_json::Value) -> String {
        let header = serde_json::json!({"alg": "HS256", "typ": "JWT"});
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        format!("{header_b64}.{payload_b64}.sig")
    }

    fn make_service_token(iss: &str, zerokms_url: &str) -> ServiceToken {
        let claims = serde_json::json!({
            "iss": iss,
            "sub": "CS|test-user",
            "aud": "test-aud",
            "iat": 1_700_000_000u64,
            "exp": 4_000_000_000u64,
            "workspace": "ZVATKW3VHMFG27DY",
            "scope": "",
            "services": { "zerokms": zerokms_url },
        });
        ServiceToken::new(SecretToken::new(make_jwt(claims)))
    }

    /// Extract `.code` from a JsValue Error.
    fn error_code_of(err: &JsValue) -> String {
        js_sys::Reflect::get(err, &JsValue::from_str("code"))
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default()
    }

    /// Unwrap the `Err` variant without requiring `Debug` on the `Ok` type.
    /// The bindings structs deliberately don't derive `Debug` (matches the
    /// node crate's posture — wrappers shouldn't leak internal state via Debug).
    fn expect_js_err<T>(result: Result<T, JsValue>) -> JsValue {
        match result {
            Ok(_) => panic!("expected Err, got Ok"),
            Err(e) => e,
        }
    }

    // -------- error_code mapping --------

    #[wasm_bindgen_test]
    fn maps_known_auth_error_variants() {
        assert_eq!(error_code(&AuthError::AccessDenied), "ACCESS_DENIED");
        assert_eq!(error_code(&AuthError::TokenExpired), "EXPIRED_TOKEN");
        assert_eq!(error_code(&AuthError::InvalidGrant), "INVALID_GRANT");
        assert_eq!(error_code(&AuthError::InvalidClient), "INVALID_CLIENT");
        assert_eq!(
            error_code(&AuthError::NotAuthenticated),
            "NOT_AUTHENTICATED"
        );
        assert_eq!(
            error_code(&AuthError::MissingWorkspaceCrn),
            "MISSING_WORKSPACE_CRN"
        );
        assert_eq!(error_code(&AuthError::Server("x".into())), "SERVER_ERROR");
        assert_eq!(
            error_code(&AuthError::InvalidToken("malformed".into())),
            "INVALID_TOKEN"
        );
    }

    #[wasm_bindgen_test]
    fn to_js_error_attaches_code_property() {
        let err = to_js_error(AuthError::AccessDenied);
        assert_eq!(error_code_of(&err), "ACCESS_DENIED");
        let err = to_js_error(AuthError::Server("boom".into()));
        assert_eq!(error_code_of(&err), "SERVER_ERROR");
    }

    // -------- TokenResult --------

    #[wasm_bindgen_test]
    fn token_result_from_extracts_jwt_claims() {
        let token = make_service_token("https://cts.example.com/", "https://zerokms.example.com/");
        let value = token_result_from(token).expect("conversion should succeed");

        let subject =
            js_sys::Reflect::get(&value, &JsValue::from_str("subject")).expect("has subject");
        assert_eq!(subject.as_string().as_deref(), Some("CS|test-user"));

        let workspace = js_sys::Reflect::get(&value, &JsValue::from_str("workspaceId"))
            .expect("has workspaceId");
        assert_eq!(workspace.as_string().as_deref(), Some("ZVATKW3VHMFG27DY"));

        let issuer =
            js_sys::Reflect::get(&value, &JsValue::from_str("issuer")).expect("has issuer");
        assert_eq!(
            issuer.as_string().as_deref(),
            Some("https://cts.example.com/")
        );
    }

    #[wasm_bindgen_test]
    fn token_result_from_rejects_non_jwt() {
        let token = ServiceToken::new(SecretToken::new("not-a-jwt"));
        let err = token_result_from(token).expect_err("non-JWT should fail");
        assert_eq!(error_code_of(&err), "INVALID_TOKEN");
    }

    // -------- AccessKeyStrategy::create --------

    #[wasm_bindgen_test]
    fn access_key_strategy_rejects_invalid_region() {
        let err = expect_js_err(AccessKeyStrategy::create(
            "not-a-region".to_string(),
            "CSAKtestKeyId.testKeySecret".to_string(),
        ));
        assert_eq!(error_code_of(&err), "INVALID_REGION");
    }

    #[wasm_bindgen_test]
    fn access_key_strategy_rejects_invalid_key() {
        let err = expect_js_err(AccessKeyStrategy::create(
            "ap-southeast-2.aws".to_string(),
            "not-a-valid-key".to_string(),
        ));
        assert_eq!(error_code_of(&err), "INVALID_ACCESS_KEY");
    }

    #[wasm_bindgen_test]
    fn access_key_strategy_accepts_valid_inputs() {
        let result = AccessKeyStrategy::create(
            "ap-southeast-2.aws".to_string(),
            "CSAKtestKeyId.testKeySecret".to_string(),
        );
        // Parsing + base-URL resolution succeed without hitting the network.
        // The returned strategy is unused — we're just exercising the constructor.
        assert!(result.is_ok());
    }

    // -------- OAuthStrategy::withToken --------

    /// Build a JS-side Token-shaped object that mirrors what a Deno caller
    /// would pass in. We construct it via `JSON.parse` so we get a real JS
    /// plain object (vs. `serde_wasm_bindgen::to_value`, which produces a
    /// JS `Map` for `serde_json::Value::Object` and won't deserialize back
    /// into a struct).
    fn make_token_jsvalue() -> JsValue {
        let jwt = make_jwt(serde_json::json!({
            "iss": "https://cts.example.com",
            "sub": "user-123",
            "aud": "test-aud",
            "iat": 1_700_000_000u64,
            "exp": 4_000_000_000u64,
            "workspace": "ZVATKW3VHMFG27DY",
            "scope": "",
        }));
        let json = serde_json::json!({
            "accessToken": jwt,
            "tokenType": "Bearer",
            "expiresAt": 4_000_000_000u64,
            "refreshToken": "refresh-secret",
        });
        js_sys::JSON::parse(&json.to_string()).unwrap()
    }

    #[wasm_bindgen_test]
    fn oauth_strategy_with_token_constructs() {
        let token = make_token_jsvalue();
        let result =
            OAuthStrategy::with_token("ap-southeast-2.aws".to_string(), "cli".to_string(), token);
        if let Err(e) = &result {
            let msg = js_sys::Reflect::get(e, &JsValue::from_str("message"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_else(|| "<no message>".into());
            panic!("expected Ok, got Err: {msg}");
        }
    }

    #[wasm_bindgen_test]
    fn oauth_strategy_with_token_rejects_invalid_region() {
        let token = make_token_jsvalue();
        let err = expect_js_err(OAuthStrategy::with_token(
            "not-a-region".to_string(),
            "cli".to_string(),
            token,
        ));
        assert_eq!(error_code_of(&err), "INVALID_REGION");
    }

    #[wasm_bindgen_test]
    fn oauth_strategy_with_token_rejects_malformed_token() {
        let bogus = js_sys::JSON::parse(r#"{"not":"a token"}"#).unwrap();
        let err = expect_js_err(OAuthStrategy::with_token(
            "ap-southeast-2.aws".to_string(),
            "cli".to_string(),
            bogus,
        ));
        assert_eq!(error_code_of(&err), "INVALID_TOKEN");
    }
}
