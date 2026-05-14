//! WebAssembly bindings for `stack-auth`.
//!
//! Mirrors the wasm-compatible subset of the `stack-auth-node` napi crate,
//! scoped to `AccessKeyStrategy` (M2M auth). OAuth- and profile-based
//! strategies are deliberately out of scope for the initial wasm surface —
//! they need design work around federation and token pinning that hasn't
//! happened yet.
//!
//! Targets Supabase Edge Functions and bundler consumers via
//! `wasm-pack build --target bundler` / `--target deno`.

use std::collections::BTreeMap;

use cts_common::Region;
use serde::Serialize;
use stack_auth::{AuthError, AuthStrategy, ServiceToken};
use wasm_bindgen::prelude::*;

/// Route Rust panics to `console.error` with a readable message + stack.
/// Without this, panics surface as opaque `RuntimeError: unreachable` from
/// wasm bytecode offsets.
#[wasm_bindgen(start)]
fn module_init() {
    console_error_panic_hook::set_once();
}

/// Attach a machine-readable `.code` to a JS error object.
fn attach_code(js_err: impl Into<JsValue>, code: &str) -> JsValue {
    let v: JsValue = js_err.into();
    let _ = js_sys::Reflect::set(&v, &JsValue::from_str("code"), &JsValue::from_str(code));
    v
}

fn to_js_error(err: AuthError) -> JsValue {
    attach_code(js_sys::Error::new(&err.to_string()), err.error_code())
}

#[derive(Serialize)]
struct TokenResultPayload {
    token: String,
    subject: String,
    #[serde(rename = "workspaceId")]
    workspace_id: String,
    issuer: String,
    services: BTreeMap<String, String>,
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

#[wasm_bindgen]
pub struct AccessKeyStrategy {
    inner: stack_auth::AccessKeyStrategy,
}

#[wasm_bindgen]
impl AccessKeyStrategy {
    /// Create a new `AccessKeyStrategy` for the given region and access key.
    pub fn create(region: String, access_key: String) -> Result<AccessKeyStrategy, JsValue> {
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
        let token = self.inner.get_token().await.map_err(to_js_error)?;
        token_result_from(token)
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use base64::Engine;
    use stack_auth::SecretToken;
    use wasm_bindgen_test::wasm_bindgen_test;

    /// Build an unsigned JWT-shaped token: `<header>.<payload>.<sig>`.
    /// Signature segment is a dummy `"sig"` literal — the JWT-claim decoder
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

    fn error_code_of(err: &JsValue) -> String {
        js_sys::Reflect::get(err, &JsValue::from_str("code"))
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default()
    }

    /// The bindings structs deliberately don't derive `Debug` (wrappers
    /// shouldn't leak internal state via Debug — matches the node crate's
    /// posture), so `expect_err` / `unwrap_err` aren't available.
    fn expect_js_err<T>(result: Result<T, JsValue>) -> JsValue {
        match result {
            Ok(_) => panic!("expected Err, got Ok"),
            Err(e) => e,
        }
    }

    #[wasm_bindgen_test]
    fn to_js_error_attaches_code_property() {
        let err = to_js_error(AuthError::AccessDenied);
        assert_eq!(error_code_of(&err), "ACCESS_DENIED");
        let err = to_js_error(AuthError::Server("boom".into()));
        assert_eq!(error_code_of(&err), "SERVER_ERROR");
    }

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
        assert!(result.is_ok());
    }
}
