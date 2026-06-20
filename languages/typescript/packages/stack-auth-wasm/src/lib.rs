//! WebAssembly bindings for `stack-auth`.
//!
//! Mirrors the wasm-compatible subset of the `stack-auth-node` napi crate:
//! `AccessKeyStrategy` (M2M auth) and `OidcFederationStrategy` (federating a third-party
//! OIDC JWT into a CTS service token via `/api/authorise`). The interactive
//! device-code flow and profile-store loading remain out of scope — they need
//! Node-only APIs (filesystem device identity, browser launching) that can't
//! be ported to wasm32.
//!
//! Targets Supabase Edge Functions and bundler consumers via
//! `wasm-pack build --target bundler` / `--target deno`.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use stack_auth::{AuthError, AuthStrategy, ServiceToken};
#[cfg(target_arch = "wasm32")]
use stack_auth::{OidcProvider, SecretToken, Token, TokenStore};
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use zeroize::Zeroizing;

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
    // Bearer credential. Kept as `String` rather than `stack_auth::SecretToken`
    // because the protections `SecretToken` provides (`ZeroizeOnDrop`,
    // `OpaqueDebug`) don't survive `serde_wasm_bindgen` — once the value
    // crosses the FFI boundary it lives in JS-managed memory with no zeroize
    // equivalent. Wasm-side memory hygiene is tracked separately as the
    // "never-expose-JWT" follow-up.
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
    // `json_compatible` serializes maps as plain objects rather than JS `Map`s,
    // so consumers can `JSON.stringify` the result and read fields with normal
    // object syntax — matches the `Record<string, string>` shape advertised in
    // `wasm-types.d.ts`.
    payload
        .serialize(&Serializer::json_compatible())
        .map_err(JsValue::from)
}

/// `TokenStore` adapter over a pair of JS callbacks.
///
/// `load` is called with no arguments and is expected to return
/// `Promise<string | null | undefined>` — the previously-stored JSON
/// or a nullish value if nothing is cached. `save` is called with the
/// JSON string and is expected to return `Promise<void>`.
///
/// Cfg-gated to `wasm32` because `js_sys::Function` is not `Send` and the
/// parent `stack_auth::TokenStore` trait drops the `Send + Sync` bound on
/// wasm32 to accommodate exactly this case.
#[cfg(target_arch = "wasm32")]
struct JsTokenStore {
    load: js_sys::Function,
    save: js_sys::Function,
}

#[cfg(target_arch = "wasm32")]
impl TokenStore for JsTokenStore {
    async fn load(&self) -> Option<Token> {
        let promise = match self.load.call0(&JsValue::NULL) {
            Ok(p) => p,
            Err(err) => {
                warn_callback("loadToken", "synchronous throw", &err);
                return None;
            }
        };
        match JsFuture::from(js_sys::Promise::from(promise)).await {
            Ok(result) => {
                // Zero the JSON heap buffer on drop — it carries the bearer
                // token in cleartext between the JS boundary and serde.
                let json = Zeroizing::new(result.as_string()?);
                serde_json::from_str(&json).ok()
            }
            Err(err) => {
                warn_callback("loadToken", "promise rejection", &err);
                None
            }
        }
    }

    async fn save(&self, token: &Token) {
        let Ok(json) = serde_json::to_string(token).map(Zeroizing::new) else {
            return;
        };
        let promise = match self.save.call1(&JsValue::NULL, &JsValue::from_str(&json)) {
            Ok(p) => p,
            Err(err) => {
                warn_callback("saveToken", "synchronous throw", &err);
                return;
            }
        };
        if let Err(err) = JsFuture::from(js_sys::Promise::from(promise)).await {
            warn_callback("saveToken", "promise rejection", &err);
        }
    }
}

/// Surface JS callback failures so consumers can see them — without this,
/// rejections in user-supplied `loadToken` / `saveToken` were invisible and
/// led to silent cache misses (e.g. when `setCookie` rejected a value
/// containing chars outside RFC 6265's allowed range). See CIP-3114.
#[cfg(target_arch = "wasm32")]
fn warn_callback(name: &str, kind: &str, err: &JsValue) {
    let msg = format!("stack-auth: {name} {kind}");
    web_sys::console::warn_2(&JsValue::from_str(&msg), err);
}

/// Best-effort human-readable detail for a JS error value, for embedding in an
/// [`AuthError`] message. Prefers a thrown string, then an `Error.message`
/// property, falling back to the `Debug` representation.
#[cfg(target_arch = "wasm32")]
fn js_error_detail(err: &JsValue) -> String {
    err.as_string()
        .or_else(|| {
            js_sys::Reflect::get(err, &JsValue::from_str("message"))
                .ok()
                .and_then(|m| m.as_string())
        })
        .unwrap_or_else(|| format!("{err:?}"))
}

/// `OidcProvider` adapter over a JS callback.
///
/// `getJwt` is called with no arguments and is expected to return
/// `Promise<string>` — the current third-party OIDC JWT to federate. Unlike
/// [`JsTokenStore`], a failure here is fatal: federation can't proceed without
/// a JWT, so it surfaces as an [`AuthError`] rather than a silent cache miss.
/// The failure is still logged via [`warn_callback`] so the JS-side cause is
/// visible.
#[cfg(target_arch = "wasm32")]
struct JsOidcProvider {
    get_jwt: js_sys::Function,
}

#[cfg(target_arch = "wasm32")]
impl OidcProvider for JsOidcProvider {
    async fn fetch(&self) -> Result<SecretToken, AuthError> {
        let promise = self.get_jwt.call0(&JsValue::NULL).map_err(|err| {
            warn_callback("getJwt", "synchronous throw", &err);
            AuthError::Server(format!("getJwt callback threw: {}", js_error_detail(&err)))
        })?;
        let result = JsFuture::from(js_sys::Promise::from(promise))
            .await
            .map_err(|err| {
                warn_callback("getJwt", "promise rejection", &err);
                AuthError::Server(format!(
                    "getJwt callback rejected: {}",
                    js_error_detail(&err)
                ))
            })?;
        // `SecretToken` owns the JWT string and zeroes its heap buffer on drop
        // (it's `ZeroizeOnDrop`) — it carries the bearer credential between the
        // JS boundary and the federation HTTP request.
        let jwt = result.as_string().ok_or_else(|| {
            AuthError::Server("getJwt callback did not return a string".to_string())
        })?;
        Ok(SecretToken::new(jwt))
    }
}

/// Parse a workspace CRN string, mapping a parse failure to the `INVALID_CRN`
/// error code. Shared by every factory that takes a workspace CRN
/// (`AccessKeyStrategy`, `OidcFederationStrategy`).
fn parse_workspace_crn(workspace_crn: &str) -> Result<cts_common::Crn, JsValue> {
    workspace_crn
        .parse()
        .map_err(|e| to_js_error(AuthError::InvalidCrn(e)))
}

/// Parse an optional `baseUrl` override into a [`url::Url`]. An absent or empty
/// string yields `None` (fall back to region service discovery); an invalid URL
/// maps to the `INVALID_URL` error code.
#[cfg(target_arch = "wasm32")]
fn parse_base_url(base_url: Option<String>) -> Result<Option<url::Url>, JsValue> {
    match base_url {
        Some(s) if !s.is_empty() => Ok(Some(
            s.parse::<url::Url>().map_err(|e| to_js_error(AuthError::from(e)))?,
        )),
        _ => Ok(None),
    }
}

enum AccessKeyStrategyInner {
    NoStore(stack_auth::AccessKeyStrategy),
    #[cfg(target_arch = "wasm32")]
    WithStore(stack_auth::AccessKeyStrategy<JsTokenStore>),
}

impl AccessKeyStrategyInner {
    async fn get_token(&self) -> Result<ServiceToken, AuthError> {
        match self {
            Self::NoStore(s) => s.get_token().await,
            #[cfg(target_arch = "wasm32")]
            Self::WithStore(s) => s.get_token().await,
        }
    }
}

#[wasm_bindgen]
pub struct AccessKeyStrategy {
    inner: AccessKeyStrategyInner,
}

#[wasm_bindgen]
impl AccessKeyStrategy {
    /// Create a new `AccessKeyStrategy` for the given workspace CRN and
    /// access key. Region is derived from the CRN — there's no separate
    /// region argument — so the strategy can't be configured for one
    /// workspace's region while the CRN says another.
    ///
    /// Every issued token's workspace claim is verified against the CRN;
    /// a mismatch fails the call with a `WORKSPACE_MISMATCH` error.
    pub fn create(workspace_crn: String, access_key: String) -> Result<AccessKeyStrategy, JsValue> {
        let crn = parse_workspace_crn(&workspace_crn)?;
        let key: stack_auth::AccessKey = access_key
            .parse()
            .map_err(|e| to_js_error(AuthError::from(e)))?;
        let inner = stack_auth::AccessKeyStrategy::new(crn, key).map_err(to_js_error)?;
        Ok(AccessKeyStrategy {
            inner: AccessKeyStrategyInner::NoStore(inner),
        })
    }

    /// Create an `AccessKeyStrategy` backed by external token-store callbacks.
    ///
    /// `loadToken` is called on cold start before any HTTP request fires; it
    /// must return the previously-saved JSON string (or null/undefined for
    /// "cache miss") wrapped in a Promise. `saveToken` receives the JSON
    /// string after every successful refresh and must persist it; its return
    /// Promise resolves to undefined.
    ///
    /// Use this to back the strategy with HTTP-only cookies (Supabase Edge),
    /// KV stores (Cloudflare Workers), or any other request-scoped cache.
    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = createWithStore)]
    pub fn create_with_store(
        workspace_crn: String,
        access_key: String,
        load_token: js_sys::Function,
        save_token: js_sys::Function,
    ) -> Result<AccessKeyStrategy, JsValue> {
        let crn = parse_workspace_crn(&workspace_crn)?;
        let key: stack_auth::AccessKey = access_key
            .parse()
            .map_err(|e| to_js_error(AuthError::from(e)))?;
        let store = JsTokenStore {
            load: load_token,
            save: save_token,
        };
        let inner = stack_auth::AccessKeyStrategy::builder(crn, key)
            .with_token_store(store)
            .build()
            .map_err(to_js_error)?;
        Ok(AccessKeyStrategy {
            inner: AccessKeyStrategyInner::WithStore(inner),
        })
    }

    /// Retrieve a valid access token, refreshing or re-authenticating as needed.
    #[wasm_bindgen(js_name = getToken)]
    pub async fn get_token(&self) -> Result<JsValue, JsValue> {
        let token = self.inner.get_token().await.map_err(to_js_error)?;
        token_result_from(token)
    }
}

/// Cfg-gated to wasm32: `OidcFederationStrategy` is generic over the JWT provider, and
/// the only provider the bindings offer (`JsOidcProvider`) wraps a
/// `js_sys::Function`, which exists only on wasm32. The native build of this
/// crate (used for `cargo clippy` / host `cargo test`) therefore has no
/// `OidcFederationStrategy` — there is nothing native-testable about a JS-callback type.
#[cfg(target_arch = "wasm32")]
enum OidcFederationStrategyInner {
    NoStore(stack_auth::OidcFederationStrategy<JsOidcProvider>),
    WithStore(stack_auth::OidcFederationStrategy<JsOidcProvider, JsTokenStore>),
}

#[cfg(target_arch = "wasm32")]
impl OidcFederationStrategyInner {
    async fn get_token(&self) -> Result<ServiceToken, AuthError> {
        match self {
            Self::NoStore(s) => s.get_token().await,
            Self::WithStore(s) => s.get_token().await,
        }
    }
}

/// Federates a third-party OIDC JWT (Clerk, Supabase, …) into a CTS service
/// token. See the crate-level docs and `stack_auth::OidcFederationStrategy`.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct OidcFederationStrategy {
    inner: OidcFederationStrategyInner,
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl OidcFederationStrategy {
    /// Create an `OidcFederationStrategy` for the given workspace CRN.
    ///
    /// The CRN format is `crn:<region>:<workspace-id>` (e.g.
    /// `"crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"`). Region is parsed from
    /// the CRN and used for service discovery; the workspace ID is used to
    /// verify every federated token belongs to the right workspace.
    ///
    /// `getJwt` is called on every federation — initial auth and every
    /// re-federation after expiry — and must return `Promise<string>`
    /// resolving to the *current* third-party OIDC JWT (e.g. by calling
    /// `clerk.session.getToken()`).
    ///
    /// `baseUrl`, when supplied, pins this strategy to a specific CTS host —
    /// e.g. a self-hosted CTS or a local mock auth server. It overrides region
    /// service discovery and is scoped to this strategy alone. In wasm there is
    /// no `CS_CTS_HOST` env fallback (the sandbox can't read env), so `baseUrl`
    /// is the only way to target a host other than the region-discovered one.
    pub fn create(
        workspace_crn: String,
        get_jwt: js_sys::Function,
        base_url: Option<String>,
    ) -> Result<OidcFederationStrategy, JsValue> {
        let crn = parse_workspace_crn(&workspace_crn)?;
        let mut builder =
            stack_auth::OidcFederationStrategy::builder(crn, JsOidcProvider { get_jwt });
        if let Some(url) = parse_base_url(base_url)? {
            builder = builder.base_url(url);
        }
        let inner = builder.build().map_err(to_js_error)?;
        Ok(OidcFederationStrategy {
            inner: OidcFederationStrategyInner::NoStore(inner),
        })
    }

    /// Create an `OidcFederationStrategy` backed by external token-store callbacks.
    ///
    /// Behaves like [`create`](Self::create) but persists the federated CTS
    /// token through `loadToken` / `saveToken` — see
    /// [`AccessKeyStrategy::create_with_store`] for the callback contract. Use
    /// this to back the strategy with an HTTP-only cookie so a federated token
    /// survives across Edge Function invocations without re-federating.
    ///
    /// `baseUrl` behaves as in [`create`](Self::create) — an explicit,
    /// strategy-scoped CTS host that overrides region service discovery.
    #[wasm_bindgen(js_name = createWithStore)]
    pub fn create_with_store(
        workspace_crn: String,
        get_jwt: js_sys::Function,
        load_token: js_sys::Function,
        save_token: js_sys::Function,
        base_url: Option<String>,
    ) -> Result<OidcFederationStrategy, JsValue> {
        let crn = parse_workspace_crn(&workspace_crn)?;
        let store = JsTokenStore {
            load: load_token,
            save: save_token,
        };
        let mut builder =
            stack_auth::OidcFederationStrategy::builder(crn, JsOidcProvider { get_jwt });
        if let Some(url) = parse_base_url(base_url)? {
            builder = builder.base_url(url);
        }
        let inner = builder
            .with_token_store(store)
            .build()
            .map_err(to_js_error)?;
        Ok(OidcFederationStrategy {
            inner: OidcFederationStrategyInner::WithStore(inner),
        })
    }

    /// Retrieve a valid CTS service token, federating or re-federating as needed.
    #[wasm_bindgen(js_name = getToken)]
    pub async fn get_token(&self) -> Result<JsValue, JsValue> {
        self.inner
            .get_token()
            .await
            .map_err(to_js_error)
            .and_then(token_result_from)
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use base64::Engine;
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

    /// Regression for the FFI mapping of the workspace-verification error.
    /// A full HTTP-roundtrip test isn't viable on wasm32 (no mocktail-style
    /// fetch interception in the wasm-bindgen test runner), so we exercise
    /// just the boundary: any `WorkspaceMismatch` reaching `to_js_error`
    /// must surface as `WORKSPACE_MISMATCH`. The underlying check is
    /// covered by `stack_auth::access_key_strategy` tests on the native
    /// target.
    #[wasm_bindgen_test]
    fn workspace_mismatch_maps_to_workspace_mismatch_code() {
        let err = to_js_error(AuthError::WorkspaceMismatch {
            expected_workspace: "ZVATKW3VHMFG27DY".parse().unwrap(),
            token_workspace: "AAAAAAAAAAAAAAAA".parse().unwrap(),
        });
        assert_eq!(error_code_of(&err), "WORKSPACE_MISMATCH");
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

        // `services` must serialise as a plain object so `JSON.stringify`
        // returns the entries — not as a JS `Map`, which stringifies to `{}`.
        let services =
            js_sys::Reflect::get(&value, &JsValue::from_str("services")).expect("has services");
        assert!(
            !services.is_instance_of::<js_sys::Map>(),
            "services must not be a JS Map (JSON.stringify would drop entries)",
        );
        let zerokms_url = js_sys::Reflect::get(&services, &JsValue::from_str("zerokms"))
            .expect("services has zerokms entry");
        assert_eq!(
            zerokms_url.as_string().as_deref(),
            Some("https://zerokms.example.com/")
        );
    }

    #[wasm_bindgen_test]
    fn token_result_from_rejects_non_jwt() {
        let token = ServiceToken::new(SecretToken::new("not-a-jwt"));
        let err = token_result_from(token).expect_err("non-JWT should fail");
        assert_eq!(error_code_of(&err), "INVALID_TOKEN");
    }

    const VALID_CRN: &str = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY";
    const VALID_KEY: &str = "CSAKtestKeyId.testKeySecret";

    #[wasm_bindgen_test]
    fn access_key_strategy_rejects_invalid_crn() {
        let err = expect_js_err(AccessKeyStrategy::create(
            "not-a-crn".to_string(),
            VALID_KEY.to_string(),
        ));
        assert_eq!(error_code_of(&err), "INVALID_CRN");
    }

    #[wasm_bindgen_test]
    fn access_key_strategy_rejects_invalid_key() {
        let err = expect_js_err(AccessKeyStrategy::create(
            VALID_CRN.to_string(),
            "not-a-valid-key".to_string(),
        ));
        assert_eq!(error_code_of(&err), "INVALID_ACCESS_KEY");
    }

    #[wasm_bindgen_test]
    fn access_key_strategy_accepts_valid_inputs() {
        let result = AccessKeyStrategy::create(VALID_CRN.to_string(), VALID_KEY.to_string());
        assert!(result.is_ok());
    }

    fn empty_load_fn() -> js_sys::Function {
        // `async () => null`
        js_sys::Function::new_no_args("return Promise.resolve(null);")
    }

    fn noop_save_fn() -> js_sys::Function {
        // `async (_) => undefined`
        js_sys::Function::new_with_args("_json", "return Promise.resolve();")
    }

    #[wasm_bindgen_test]
    fn create_with_store_rejects_invalid_crn() {
        let err = expect_js_err(AccessKeyStrategy::create_with_store(
            "not-a-crn".to_string(),
            VALID_KEY.to_string(),
            empty_load_fn(),
            noop_save_fn(),
        ));
        assert_eq!(
            error_code_of(&err),
            "INVALID_CRN",
            "invalid CRN should surface INVALID_CRN even on the store variant"
        );
    }

    #[wasm_bindgen_test]
    fn create_with_store_rejects_invalid_access_key() {
        let err = expect_js_err(AccessKeyStrategy::create_with_store(
            VALID_CRN.to_string(),
            "not-a-valid-key".to_string(),
            empty_load_fn(),
            noop_save_fn(),
        ));
        assert_eq!(
            error_code_of(&err),
            "INVALID_ACCESS_KEY",
            "invalid access key should surface INVALID_ACCESS_KEY"
        );
    }

    #[wasm_bindgen_test]
    fn create_with_store_accepts_valid_inputs() {
        let result = AccessKeyStrategy::create_with_store(
            VALID_CRN.to_string(),
            VALID_KEY.to_string(),
            empty_load_fn(),
            noop_save_fn(),
        );
        assert!(
            result.is_ok(),
            "valid CRN + key + callbacks should construct successfully"
        );
    }

    #[wasm_bindgen_test]
    async fn js_token_store_load_returns_none_on_callback_throw() {
        use stack_auth::TokenStore as _;
        // A throwing `loadToken` mustn't crash — it should be treated as a
        // cache miss so the strategy falls through to initial auth.
        // CIP-3114: prior to the fix this still returned None (via `.ok()?`)
        // but without surfacing the throw. With the fix, the throw is logged
        // via `web_sys::console::warn_2`; behaviour-wise we just confirm
        // the call returns None rather than panicking.
        let store = JsTokenStore {
            load: js_sys::Function::new_no_args("throw new Error('boom');"),
            save: noop_save_fn(),
        };
        assert!(
            store.load().await.is_none(),
            "throwing loadToken should produce a cache miss, not a crash"
        );
    }

    #[wasm_bindgen_test]
    async fn js_token_store_save_swallows_callback_throw() {
        use stack_auth::TokenStore as _;
        // A throwing `saveToken` mustn't crash the surrounding refresh path.
        // Trait contract is "best-effort" — save returns `()` regardless.
        let store = JsTokenStore {
            load: empty_load_fn(),
            save: js_sys::Function::new_with_args("_json", "throw new Error('boom');"),
        };
        // `Token`'s fields are `pub(crate)`; round-trip through serde to build
        // one from this crate without touching the field privacy.
        let token: Token = serde_json::from_str(
            r#"{"access_token":"dummy","token_type":"Bearer","expires_at":4000000000}"#,
        )
        .unwrap();
        // No assertion needed beyond "this doesn't panic".
        store.save(&token).await;
    }

    fn jwt_fn(jwt: &str) -> js_sys::Function {
        // `async () => "<jwt>"`
        js_sys::Function::new_no_args(&format!("return Promise.resolve('{jwt}');"))
    }

    #[wasm_bindgen_test]
    fn oidc_federation_strategy_rejects_invalid_crn() {
        let err = expect_js_err(OidcFederationStrategy::create(
            "not-a-crn".to_string(),
            jwt_fn("h.p.s"),
        ));
        assert_eq!(error_code_of(&err), "INVALID_CRN");
    }

    /// A structurally well-formed CRN whose workspace segment fails
    /// `WorkspaceId` validation is rejected with `INVALID_CRN` — the path the
    /// old `INVALID_WORKSPACE_ID` test covered before the factory took a CRN.
    /// "not-a-crn" above fails at the `crn:` prefix; this exercises the
    /// workspace sub-parser instead.
    #[wasm_bindgen_test]
    fn oidc_federation_strategy_rejects_crn_with_malformed_workspace() {
        let err = expect_js_err(OidcFederationStrategy::create(
            "crn:ap-southeast-2.aws:not-a-valid-workspace".to_string(),
            jwt_fn("h.p.s"),
        ));
        assert_eq!(error_code_of(&err), "INVALID_CRN");
    }

    #[wasm_bindgen_test]
    fn oidc_federation_strategy_accepts_valid_inputs() {
        let result = OidcFederationStrategy::create(VALID_CRN.to_string(), jwt_fn("h.p.s"));
        assert!(result.is_ok());
    }

    #[wasm_bindgen_test]
    fn oidc_create_with_store_rejects_invalid_crn() {
        let err = expect_js_err(OidcFederationStrategy::create_with_store(
            "not-a-crn".to_string(),
            jwt_fn("h.p.s"),
            empty_load_fn(),
            noop_save_fn(),
        ));
        assert_eq!(error_code_of(&err), "INVALID_CRN");
    }

    #[wasm_bindgen_test]
    fn oidc_create_with_store_accepts_valid_inputs() {
        let result = OidcFederationStrategy::create_with_store(
            VALID_CRN.to_string(),
            jwt_fn("h.p.s"),
            empty_load_fn(),
            noop_save_fn(),
        );
        assert!(result.is_ok());
    }

    #[wasm_bindgen_test]
    async fn js_oidc_provider_returns_jwt() {
        let provider = JsOidcProvider {
            get_jwt: jwt_fn("header.payload.signature"),
        };
        let jwt = provider.fetch().await.expect("getJwt should succeed");
        assert_eq!(jwt.as_str(), "header.payload.signature");
    }

    #[wasm_bindgen_test]
    async fn js_oidc_provider_errors_on_callback_throw() {
        let provider = JsOidcProvider {
            get_jwt: js_sys::Function::new_no_args("throw new Error('boom');"),
        };
        let err = match provider.fetch().await {
            Ok(_) => panic!("expected getJwt throw to surface as an error"),
            Err(e) => e,
        };
        assert!(matches!(err, AuthError::Server(_)), "got: {err:?}");
    }

    #[wasm_bindgen_test]
    async fn js_oidc_provider_errors_on_non_string_result() {
        let provider = JsOidcProvider {
            get_jwt: js_sys::Function::new_no_args("return Promise.resolve(42);"),
        };
        let err = match provider.fetch().await {
            Ok(_) => panic!("expected non-string getJwt result to surface as an error"),
            Err(e) => e,
        };
        assert!(matches!(err, AuthError::Server(_)), "got: {err:?}");
    }
}
