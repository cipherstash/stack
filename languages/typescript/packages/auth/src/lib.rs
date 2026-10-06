use std::collections::HashMap;
use std::sync::Mutex;

use cts_common::Region;
use napi::bindgen_prelude::*;
use napi::threadsafe_function::{ErrorStrategy, ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::tokio::sync::oneshot;
use napi_derive::napi;
use stack_auth::{
    AlreadyConsumed, AuthError, AuthStrategy, DeviceClientError, DeviceCodeStrategy, InternalError,
    OidcProvider, PendingDeviceCode, SecretToken, ServerError, ServiceToken, Token, TokenStore,
};
use vitaminc_protected::OpaqueDebug;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

/// Sentinel prefix that marks a `napi::Error` whose `reason` carries a
/// serialized [`AuthError`] (a domain failure) rather than an arbitrary throw.
/// `index.js` keys on this to convert the rejection into a `Result` `failure`
/// envelope; anything without it is re-thrown as a genuine error/panic.
const FAILURE_SENTINEL: &str = "__CS_FAIL__";

fn to_napi_error(err: AuthError) -> napi::Error {
    // `napi::Error` only carries a string `reason`, so the structured failure
    // (`{ type, message, help?, url?, ...payload }`) travels as a JSON blob
    // behind the sentinel. `index.js` parses it back into the `Result` failure.
    let json = serde_json::to_string(&err).unwrap_or_else(|_| {
        serde_json::json!({ "type": err.error_code(), "message": err.to_string() }).to_string()
    });
    napi::Error::new(Status::GenericFailure, format!("{FAILURE_SENTINEL}{json}"))
}

/// Surface a JS callback failure on stderr so it isn't silently swallowed —
/// the node counterpart to the wasm binding's `warn_callback` (`console.warn`).
fn warn_callback(name: &str, detail: &str) {
    eprintln!("stack-auth: {name} {detail}");
}

/// Parse a workspace CRN string, mapping a parse failure to the `INVALID_CRN`
/// error code. Shared by every factory that takes a workspace CRN
/// (`AccessKeyStrategy`, `AutoStrategy`, `OidcFederationStrategy`).
fn parse_workspace_crn(workspace_crn: &str) -> Result<cts_common::Crn> {
    workspace_crn
        .parse()
        .map_err(|e| to_napi_error(AuthError::from(e)))
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
#[derive(OpaqueDebug)]
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
                builder = builder.with_workspace_crn(parse_workspace_crn(&crn_str)?);
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
    /// Create a new `AccessKeyStrategy` for the given workspace CRN and
    /// access key.
    ///
    /// The CRN format is `crn:<region>:<workspace-id>` (e.g.
    /// `"crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"`). Region is parsed
    /// from the CRN and used for service discovery; the workspace ID is
    /// used to verify every issued token belongs to the right workspace.
    /// A mismatch fails `getToken()` with `code === "WORKSPACE_MISMATCH"`.
    #[napi(factory)]
    pub fn create(workspace_crn: String, access_key: String) -> Result<Self> {
        let crn = parse_workspace_crn(&workspace_crn)?;
        let key: stack_auth::AccessKey = access_key
            .parse()
            .map_err(|e| to_napi_error(AuthError::from(e)))?;
        let inner = stack_auth::AccessKeyStrategy::new(crn, key).map_err(to_napi_error)?;
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
// DeviceSessionStrategy — OAuth with profile store
// ---------------------------------------------------------------------------

/// An auth strategy that uses OAuth refresh tokens persisted to disk
/// (`~/.cipherstash/auth.json`).
#[napi]
pub struct DeviceSessionStrategy {
    inner: stack_auth::DeviceSessionStrategy,
}

#[napi]
impl DeviceSessionStrategy {
    /// Load credentials from the default profile store and create a `DeviceSessionStrategy`.
    #[napi(factory)]
    pub fn from_profile() -> Result<Self> {
        let store = stack_profile::ProfileStore::resolve(None)
            .map_err(|e| to_napi_error(AuthError::from(e)))?;
        let inner = stack_auth::DeviceSessionStrategy::with_profile(store)
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
// OidcFederationStrategy — federate a third-party OIDC JWT into a CTS service token
// ---------------------------------------------------------------------------

/// Bridges a JS `getJwt` callback into a Rust [`OidcProvider`].
///
/// `getJwt` is a JS function returning `Promise<string>` — the current
/// third-party OIDC JWT. The threadsafe function lets the Rust refresh engine
/// (running on napi's tokio pool) schedule the call onto the Node event-loop
/// thread; the JS-returned `Promise` is ferried back and awaited here.
struct NapiOidcProvider {
    get_jwt: ThreadsafeFunction<(), ErrorStrategy::Fatal>,
}

impl OidcProvider for NapiOidcProvider {
    async fn fetch(&self) -> std::result::Result<SecretToken, AuthError> {
        let (tx, rx) = oneshot::channel::<Promise<String>>();
        let status = self.get_jwt.call_with_return_value(
            (),
            ThreadsafeFunctionCallMode::NonBlocking,
            move |promise: Promise<String>| {
                let _ = tx.send(promise);
                Ok(())
            },
        );
        // A `getJwt` failure is fatal — federation can't proceed without a JWT —
        // so each arm logs the JS-side cause before surfacing the `AuthError`,
        // mirroring the wasm binding's `warn_callback`. Without this the error
        // reaches the caller with no breadcrumb of *why* the callback failed.
        if status != Status::Ok {
            let detail = format!("callback dispatch failed: {status:?}");
            warn_callback("getJwt", &detail);
            return Err(AuthError::Server(ServerError(format!("getJwt {detail}"))));
        }
        let promise = rx.await.map_err(|_| {
            warn_callback("getJwt", "callback did not run");
            AuthError::Server(ServerError("getJwt callback did not run".to_string()))
        })?;
        // `SecretToken` owns the JWT and zeroes it on drop (it's `ZeroizeOnDrop`),
        // so the awaited `String` moves straight in — no intermediate `Zeroizing`.
        let jwt = promise.await.map_err(|e| {
            warn_callback("getJwt", &format!("promise rejected: {e}"));
            AuthError::Server(ServerError(format!("getJwt rejected: {e}")))
        })?;
        Ok(SecretToken::new(jwt))
    }
}

/// Bridges JS `loadToken` / `saveToken` callbacks into a Rust [`TokenStore`].
///
/// Both are best-effort, mirroring [`stack_auth::TokenStoreFn`] semantics: a
/// `load` failure becomes a cache miss, a `save` failure is swallowed.
struct NapiTokenStore {
    load: ThreadsafeFunction<(), ErrorStrategy::Fatal>,
    save: ThreadsafeFunction<String, ErrorStrategy::Fatal>,
}

impl TokenStore for NapiTokenStore {
    async fn load(&self) -> Option<Token> {
        let (tx, rx) = oneshot::channel::<Promise<Option<String>>>();
        let status = self.load.call_with_return_value(
            (),
            ThreadsafeFunctionCallMode::NonBlocking,
            move |promise: Promise<Option<String>>| {
                let _ = tx.send(promise);
                Ok(())
            },
        );
        if status != Status::Ok {
            return None;
        }
        let json = Zeroizing::new(rx.await.ok()?.await.ok()??);
        serde_json::from_str(&json).ok()
    }

    async fn save(&self, token: &Token) {
        let Ok(json) = serde_json::to_string(token).map(Zeroizing::new) else {
            return;
        };
        let (tx, rx) = oneshot::channel::<Promise<()>>();
        let status = self.save.call_with_return_value(
            json.to_string(),
            ThreadsafeFunctionCallMode::NonBlocking,
            move |promise: Promise<()>| {
                let _ = tx.send(promise);
                Ok(())
            },
        );
        if status != Status::Ok {
            return;
        }
        if let Ok(promise) = rx.await {
            let _ = promise.await;
        }
    }
}

enum OidcFederationStrategyInner {
    NoStore(stack_auth::OidcFederationStrategy<NapiOidcProvider>),
    WithStore(stack_auth::OidcFederationStrategy<NapiOidcProvider, NapiTokenStore>),
}

/// An auth strategy that federates a third-party OIDC JWT (Clerk, Supabase, …)
/// into a CipherStash CTS service token via `/api/authorise`.
#[napi]
pub struct OidcFederationStrategy {
    inner: OidcFederationStrategyInner,
}

#[napi]
impl OidcFederationStrategy {
    /// Create an `OidcFederationStrategy` for the given workspace CRN.
    ///
    /// The CRN format is `crn:<region>:<workspace-id>` (e.g.
    /// `"crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"`). Region is parsed from
    /// the CRN and used for service discovery; the workspace ID is used to
    /// verify every federated token belongs to the right workspace.
    ///
    /// `getJwt` is called on every `getToken()` and must return
    /// `Promise<string>` resolving to the third-party OIDC JWT of the user the
    /// current request is for. The strategy keeps one CTS token per distinct
    /// JWT (a bounded, least-recently-used cache) and exchanges a JWT only
    /// while it has no unexpired token, so one long-lived strategy serves many
    /// users and no caller is ever handed another user's token. The `index.js`
    /// wrapper's `getToken()` calls `getJwt` in the caller's own async
    /// context (so it may read the request from `AsyncLocalStorage`, as
    /// Clerk's `auth()` and Next.js `headers()` do) and then calls
    /// `getTokenForJwt`; the threadsafe function here serves only the raw
    /// `getToken()`. Keep the callback cheap: identity-provider SDKs cache
    /// their session, so calling them per operation is fine. Return the same
    /// JWT for a user until the
    /// identity provider rotates it: the cache is keyed on the whole JWT, so
    /// a callback that mints a new JWT on every call makes the strategy
    /// exchange on every call, and each new JWT takes a cache slot from
    /// another user.
    ///
    /// `baseUrl`, when supplied, pins this strategy to a specific CTS host —
    /// e.g. a self-hosted CTS or a local mock auth server. It takes precedence
    /// over the `CS_CTS_HOST` environment variable and region service
    /// discovery, and is scoped to this strategy alone (unlike `CS_CTS_HOST`,
    /// which redirects every CTS client in the process).
    ///
    /// `cacheCapacity` is how many distinct JWTs the strategy keeps a CTS
    /// token for (1024 unless set); when full, the least recently used JWT's
    /// token is dropped and that user is exchanged again on their next call.
    /// Size it to the users a long-lived strategy serves within a CTS token's
    /// lifetime (about 15 minutes). `0` caches nothing. Each eviction is
    /// logged at `debug`.
    #[napi(factory)]
    pub fn create(
        workspace_crn: String,
        get_jwt: ThreadsafeFunction<(), ErrorStrategy::Fatal>,
        base_url: Option<String>,
        cache_capacity: Option<u32>,
    ) -> Result<Self> {
        let crn = parse_workspace_crn(&workspace_crn)?;
        let mut builder =
            stack_auth::OidcFederationStrategy::builder(crn, NapiOidcProvider { get_jwt })
                .maybe_base_url(base_url)
                .map_err(to_napi_error)?;
        if let Some(capacity) = cache_capacity {
            builder = builder.cache_capacity(capacity as usize);
        }
        let inner = builder.build().map_err(to_napi_error)?;
        Ok(Self {
            inner: OidcFederationStrategyInner::NoStore(inner),
        })
    }

    /// Create an `OidcFederationStrategy` backed by external token-store callbacks.
    ///
    /// Behaves like `create` but persists the federated CTS
    /// token through `loadToken` (`() => Promise<string | null | undefined>`)
    /// and `saveToken` (`(json: string) => Promise<void>`) — e.g. an HTTP-only
    /// cookie — so a federated token survives across requests without
    /// re-federating. A stored token is served only to the JWT it was
    /// federated from: a cookie left over from another user's sign-in is a
    /// cache miss, not that user's token.
    ///
    /// `baseUrl` and `cacheCapacity` behave as in `create` — an explicit,
    /// strategy-scoped CTS host that overrides `CS_CTS_HOST` and service
    /// discovery, and the number of JWTs whose token is kept in memory.
    #[napi(factory)]
    pub fn create_with_store(
        workspace_crn: String,
        get_jwt: ThreadsafeFunction<(), ErrorStrategy::Fatal>,
        load_token: ThreadsafeFunction<(), ErrorStrategy::Fatal>,
        save_token: ThreadsafeFunction<String, ErrorStrategy::Fatal>,
        base_url: Option<String>,
        cache_capacity: Option<u32>,
    ) -> Result<Self> {
        let crn = parse_workspace_crn(&workspace_crn)?;
        let store = NapiTokenStore {
            load: load_token,
            save: save_token,
        };
        let mut builder =
            stack_auth::OidcFederationStrategy::builder(crn, NapiOidcProvider { get_jwt })
                .maybe_base_url(base_url)
                .map_err(to_napi_error)?;
        if let Some(capacity) = cache_capacity {
            builder = builder.cache_capacity(capacity as usize);
        }
        let inner = builder
            .with_token_store(store)
            .build()
            .map_err(to_napi_error)?;
        Ok(Self {
            inner: OidcFederationStrategyInner::WithStore(inner),
        })
    }

    /// Retrieve a valid CTS service token, federating or re-federating as needed.
    ///
    /// Asks `getJwt` through the threadsafe function, which runs it in the
    /// async context of the `create()` call rather than of this caller, so a
    /// callback that reads the request from `AsyncLocalStorage` cannot see it
    /// here. The `index.js` wrapper therefore calls `getJwt` itself and uses
    /// `getTokenForJwt`; this entry stays for callers of the raw binding whose
    /// `getJwt` needs no request context.
    #[napi]
    pub async fn get_token(&self) -> Result<TokenResult> {
        let token = match &self.inner {
            OidcFederationStrategyInner::NoStore(s) => s.get_token().await,
            OidcFederationStrategyInner::WithStore(s) => s.get_token().await,
        }
        .map_err(to_napi_error)?;
        token_result_from(token)
    }

    /// Retrieve a valid CTS service token for `jwt`, the caller's own provider
    /// JWT, federating it if no unexpired token is cached for it.
    ///
    /// `getToken()` minus the `getJwt` call: the wrapper fetches the JWT on the
    /// JavaScript side, in the caller's async context, and hands it in here.
    /// Both entries share the strategy's cache.
    #[napi]
    pub async fn get_token_for_jwt(&self, jwt: String) -> Result<TokenResult> {
        let jwt = SecretToken::new(jwt);
        let token = match &self.inner {
            OidcFederationStrategyInner::NoStore(s) => s.get_token_for_jwt(jwt).await,
            OidcFederationStrategyInner::WithStore(s) => s.get_token_for_jwt(jwt).await,
        }
        .map_err(to_napi_error)?;
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
            .map_err(|_| to_napi_error(AuthError::Internal(InternalError("lock poisoned".into()))))?
            .take()
            .ok_or_else(|| to_napi_error(AuthError::AlreadyConsumed(AlreadyConsumed)))?;

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
        let guard = self.pending.lock().map_err(|_| {
            to_napi_error(AuthError::Internal(InternalError("lock poisoned".into())))
        })?;

        match guard.as_ref() {
            Some(pending) => Ok(pending.open_in_browser()),
            None => Err(to_napi_error(AuthError::AlreadyConsumed(AlreadyConsumed))),
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

fn device_client_to_napi_error(err: DeviceClientError) -> napi::Error {
    // Route through the canonical `AuthError` mapping (`From<DeviceClientError>`
    // in stack-auth) so the code/help/payload envelope comes from the one
    // `to_napi_error` path rather than a parallel code table and hand-built blob.
    to_napi_error(err.into())
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

    /// The hand-written `AuthFailure` discriminated unions in `index.d.ts` and
    /// `wasm-inline.d.ts` must list exactly the codes the Rust `AuthError` can
    /// emit. The expected set is the exported [`AuthError::ERROR_CODES`]
    /// constant — a real symbol the compiler resolves, not a scrape of the core
    /// crate's source text. A core-crate test pins that constant against the
    /// per-error `AuthErrorKind::error_code` impls, so adding an `AuthError`
    /// variant forces a new code there, which this test then requires the TS
    /// unions to include; forget to update them and this fails.
    #[test]
    fn ts_auth_failure_union_matches_error_codes() {
        use std::collections::BTreeSet;

        // The codes the Rust `AuthError` can emit — the canonical set exported
        // by stack-auth, not a scrape of `error.rs`.
        let expected: BTreeSet<&str> = AuthError::ERROR_CODES.iter().copied().collect();

        // Each TS union member is `... { type: "CODE" ... }`; pull every literal.
        let codes_in = |dts: &str| -> BTreeSet<String> {
            dts.match_indices("type: \"")
                .map(|(i, _)| {
                    let after = &dts[i + "type: \"".len()..];
                    let close = after
                        .find('"')
                        .expect("TS union type missing closing quote");
                    after[..close].to_string()
                })
                .collect()
        };

        for (name, dts) in [
            ("index.d.ts", include_str!("../index.d.ts")),
            ("wasm-inline.d.ts", include_str!("../wasm-inline.d.ts")),
        ] {
            let union = codes_in(dts);
            let expected: BTreeSet<String> = expected.iter().map(|s| s.to_string()).collect();
            assert_eq!(
                union, expected,
                "AuthFailure union in {name} drifted from AuthError::ERROR_CODES",
            );

            // The tag scrape above only checks `type` literals. `WORKSPACE_MISMATCH`
            // is the one variant carrying a structured payload (`WorkspaceMismatch::payload`
            // in error.rs emits `expected`/`actual`), so pin those field names in the
            // union too — a serde key rename or a dropped `.d.ts` field would otherwise
            // leave the declared shape silently lying. A JS runtime test
            // (`oidc-federation-strategy.test.ts`) drives it end-to-end through the
            // `...payload` spread.
            assert!(
                dts.contains("type: \"WORKSPACE_MISMATCH\"; expected: string; actual: string"),
                "{name}: WORKSPACE_MISMATCH union member must declare `expected: string; actual: string`",
            );
        }
    }

    /// `wasm-types.d.ts` declares the same taxonomy in a different shape — a
    /// bare `| 'CODE'` union rather than `FailureBase & { type: "CODE" }` — so
    /// the scrape above cannot see it. It went unchecked long enough to grow a
    /// phantom `UNKNOWN_ERROR` and lose three real codes.
    ///
    /// The wasm build has no `Store` variant (see the `cfg` on `AuthError`),
    /// so its union is `ERROR_CODES` minus `STORE_ERROR`.
    #[test]
    fn wasm_types_union_matches_error_codes() {
        use std::collections::BTreeSet;

        let dts = include_str!("../wasm-types.d.ts");

        let union: BTreeSet<&str> = dts
            .match_indices("| '")
            .map(|(i, _)| {
                let after = &dts[i + "| '".len()..];
                let close = after
                    .find('\'')
                    .expect("TS union member missing close quote");
                &after[..close]
            })
            .collect();

        let expected: BTreeSet<&str> = AuthError::ERROR_CODES
            .iter()
            .copied()
            .filter(|code| *code != "STORE_ERROR")
            .collect();

        assert_eq!(
            union, expected,
            "AuthErrorCode union in wasm-types.d.ts drifted from AuthError::ERROR_CODES",
        );
    }

    #[test]
    fn index_dts_retains_hand_written_reexports() {
        // The union test above only guards the `AuthFailure` codes. The other
        // hand-written pieces of `index.d.ts` are equally load-bearing but
        // NAPI-RS cannot emit them — they describe the `Result` contract, not the
        // raw throwing bindings — so a regen or careless edit that drops any of
        // them compiles green: the node tests import these as `import type`
        // (erased at runtime) and vitest never runs `tsc`. Pin them by string
        // presence so a deletion fails here.
        let dts = include_str!("../index.d.ts");
        for needle in [
            // The native type re-use that ties this file to `native.d.ts`.
            "from \"./native\"",
            // The discriminated failure union returned in the `Result` arm.
            "export type AuthFailure =",
            // The deprecated runtime alias `index.js` still exports.
            "export declare const OAuthStrategy",
        ] {
            assert!(
                dts.contains(needle),
                "index.d.ts lost hand-written {needle:?}",
            );
        }
    }

    /// The `__CS_FAIL__` sentinel is declared in both Rust (`FAILURE_SENTINEL`)
    /// and JS (`index.js`), and every napi domain error depends on the two
    /// agreeing: `toFailure` only recognizes a failure whose message starts with
    /// it, re-throwing anything else as a panic. If the two drift, every failure
    /// silently becomes a thrown error and no other test catches it. Pin that
    /// `index.js` declares exactly the Rust value.
    #[test]
    fn failure_sentinel_matches_index_js() {
        let js = include_str!("../index.js");
        let expected = format!("const FAILURE_SENTINEL = \"{FAILURE_SENTINEL}\";");
        assert!(
            js.contains(&expected),
            "index.js must declare `{expected}` — the __CS_FAIL__ sentinel drifted from src/lib.rs",
        );
    }

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

    fn test_access_token_jwt() -> String {
        jwt_with_workspace("ZVATKW3VHMFG27DY")
    }

    /// Build a JWT carrying the given `workspace` claim. Used by the
    /// workspace-verification regression tests to mint tokens whose
    /// workspace claim is deliberately mismatched against the CRN passed
    /// to the strategy.
    fn jwt_with_workspace(workspace: &str) -> String {
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
            "workspace": workspace,
            "org_id": "org_test_default",
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
            "access_token": test_access_token_jwt(),
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
            "org_id": "org_test_default",
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
        /// Parse the `__CS_FAIL__`-sentineled JSON failure envelope that a
        /// `napi::Error` now carries (see `to_napi_error`).
        pub(super) fn failure_json(err: &napi::Error) -> serde_json::Value {
            let reason = err
                .reason
                .strip_prefix(crate::FAILURE_SENTINEL)
                .unwrap_or_else(|| panic!("error reason missing failure sentinel: {}", err.reason));
            serde_json::from_str(reason)
                .unwrap_or_else(|e| panic!("failure JSON did not parse ({e}): {reason}"))
        }

        /// Assert the failure envelope's `type` matches the expected code.
        pub(super) fn has_error_code(err: &napi::Error, expected_code: &str) {
            let json = failure_json(err);
            assert_eq!(
                json.get("type").and_then(|v| v.as_str()),
                Some(expected_code),
                "expected type {expected_code:?} but got envelope: {json}"
            );
        }
    }

    // --- Error mapping ---

    mod error_mapping {
        use super::*;

        // `to_napi_error` is the napi FFI seam: it serializes an `AuthError`
        // into the `__CS_FAIL__`-sentineled JSON envelope (`{ type, message,
        // help?, ...payload }`) that index.js turns into a `Result` failure.
        // The canonical `error_code` mapping is exhaustively pinned in the core
        // `stack-auth` crate; here we guard the FFI envelope shape itself.
        #[test]
        fn serializes_failure_envelope() {
            let err = to_napi_error(AuthError::AccessDenied(stack_auth::AccessDenied));
            assertions::has_error_code(&err, "ACCESS_DENIED");

            let err = to_napi_error(AuthError::Server(ServerError(
                "something broke".to_string(),
            )));
            let json = assertions::failure_json(&err);
            assert_eq!(json["type"], "SERVER_ERROR");
            assert_eq!(json["message"], "Server error: something broke");
        }

        // A variant carrying structured payload + diagnostic help surfaces both
        // in the envelope, so a JS consumer can narrow on them.
        #[test]
        fn envelope_includes_payload_and_help() {
            let ws = |s: &str| s.parse::<cts_common::WorkspaceId>().unwrap();
            let err = to_napi_error(AuthError::WorkspaceMismatch(
                stack_auth::WorkspaceMismatch {
                    expected_workspace: ws("ZVATKW3VHMFG27DY"),
                    token_workspace: ws("AAAAAAAAAAAAAAAA"),
                },
            ));
            let json = assertions::failure_json(&err);
            assert_eq!(json["type"], "WORKSPACE_MISMATCH");
            assert_eq!(json["expected"], "ZVATKW3VHMFG27DY");
            assert_eq!(json["actual"], "AAAAAAAAAAAAAAAA");
            assert!(
                json["help"].as_str().is_some(),
                "expected help in envelope, got: {json}"
            );
        }

        // `device_client_to_napi_error` routes every `DeviceClientError` through
        // its canonical `AuthError` mapping. A help-carrying error (here an
        // `Auth`-wrapped `WorkspaceMismatch`) must keep its help + structured
        // payload; a help-less one (`Profile` -> `Store`) yields just
        // type + message. A regression that dropped the canonical routing would
        // lose the help/payload here.
        #[test]
        fn device_client_auth_arm_preserves_full_envelope() {
            let ws = |s: &str| s.parse::<cts_common::WorkspaceId>().unwrap();
            let err = device_client_to_napi_error(DeviceClientError::Auth(
                AuthError::WorkspaceMismatch(stack_auth::WorkspaceMismatch {
                    expected_workspace: ws("ZVATKW3VHMFG27DY"),
                    token_workspace: ws("AAAAAAAAAAAAAAAA"),
                }),
            ));
            let json = assertions::failure_json(&err);
            assert_eq!(json["type"], "WORKSPACE_MISMATCH");
            assert_eq!(json["expected"], "ZVATKW3VHMFG27DY");
            assert_eq!(json["actual"], "AAAAAAAAAAAAAAAA");
            assert!(
                json["help"].as_str().is_some(),
                "Auth arm must carry help through the canonical envelope, got: {json}"
            );

            // Non-Auth variant routes through `From<DeviceClientError>` to the
            // canonical `Store` error: same `STORE_ERROR` code, and no help
            // (StoreError carries none).
            let err = device_client_to_napi_error(DeviceClientError::Profile(
                stack_profile::ProfileError::HomeDirNotFound,
            ));
            let json = assertions::failure_json(&err);
            assert_eq!(json["type"], "STORE_ERROR");
            assert!(json["message"].as_str().is_some());
            assert!(json.get("help").is_none());
        }
    }

    // The `baseUrl` override parsing (empty/absent/valid/malformed semantics)
    // lives on `OidcFederationStrategyBuilder::maybe_base_url` in the core
    // `stack-auth` crate and is unit-tested there. The factory callbacks are
    // `ThreadsafeFunction`s, so these factories can't be driven from a Rust
    // unit test — but they *are* exercised end-to-end through the napi seam by
    // the vitest suite (`__tests__/oidc-federation-strategy.test.ts`), which
    // covers the `baseUrl` override winning over `CS_CTS_HOST`, the
    // `INVALID_URL` rejection through the factory, and empty-as-absent.

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

            mod given_invalid_grant {
                use super::*;

                #[tokio::test(start_paused = true)]
                async fn returns_invalid_grant_error() {
                    let dir = TempDir::new().unwrap();
                    let mut mocks = MockSet::new();
                    mock_code_endpoint(&mut mocks);
                    mocks.mock(|when, then| {
                        when.post().path("/oauth/device/token");
                        then.bad_request().json(error_json("invalid_grant"));
                    });
                    let server = start_server(mocks).await;

                    let result = begin_result(&server, &dir).await;
                    let err = result.poll_for_token().await.unwrap_err();

                    assertions::has_error_code(&err, "INVALID_GRANT");
                }
            }

            mod given_invalid_client {
                use super::*;

                #[tokio::test(start_paused = true)]
                async fn returns_invalid_client_error() {
                    let dir = TempDir::new().unwrap();
                    let mut mocks = MockSet::new();
                    mock_code_endpoint(&mut mocks);
                    mocks.mock(|when, then| {
                        when.post().path("/oauth/device/token");
                        then.bad_request().json(error_json("invalid_client"));
                    });
                    let server = start_server(mocks).await;

                    let result = begin_result(&server, &dir).await;
                    let err = result.poll_for_token().await.unwrap_err();

                    assertions::has_error_code(&err, "INVALID_CLIENT");
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

                    assertions::has_error_code(&err, "ALREADY_CONSUMED");
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

                    assertions::has_error_code(&err, "ALREADY_CONSUMED");
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

        /// Happy path: explicit access key + explicit valid CRN constructs
        /// an `AutoStrategy` (specifically the `AccessKey` variant). The
        /// existing tests only cover the error paths, so a regression in
        /// the napi → `AutoStrategy::builder` plumbing (e.g. dropping the
        /// CRN before `detect()`) would slide through.
        mod given_valid_access_key_and_crn {
            use super::*;

            #[test]
            fn constructs_strategy_successfully() {
                let result = AutoStrategy::detect(Some(AutoStrategyOptions {
                    access_key: Some("CSAKtestKeyId.testKeySecret".to_string()),
                    workspace_crn: Some("crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY".to_string()),
                }));

                assert!(
                    result.is_ok(),
                    "valid access key + CRN should construct an AutoStrategy",
                );
            }
        }
    }

    mod access_key_strategy_create {
        use super::*;

        // A syntactically valid CRN to use when the test wants to exercise a
        // *later* failure path (e.g. invalid access key). Workspace ID is
        // arbitrary — these tests never reach the workspace-verification step.
        const VALID_CRN: &str = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY";

        mod given_invalid_crn {
            use super::*;

            #[test]
            fn returns_invalid_crn_error() {
                let err = expect_err(AccessKeyStrategy::create(
                    "not-a-crn".to_string(),
                    "CSAKid.secret".to_string(),
                ));

                assertions::has_error_code(&err, "INVALID_CRN");
            }
        }

        mod given_invalid_key {
            use super::*;

            #[test]
            fn returns_invalid_access_key_error() {
                let err = expect_err(AccessKeyStrategy::create(
                    VALID_CRN.to_string(),
                    "not-a-valid-key".to_string(),
                ));

                assertions::has_error_code(&err, "INVALID_ACCESS_KEY");
            }
        }

        /// Happy path: valid CRN + valid access key constructs a strategy.
        /// The wasm bindings have an equivalent test
        /// (`access_key_strategy_accepts_valid_inputs`); the napi seam
        /// needs the same guard so a future regression in
        /// `AccessKeyStrategy::create` (e.g. always returning an error) is
        /// caught.
        mod given_valid_inputs {
            use super::*;

            #[test]
            fn constructs_strategy_successfully() {
                let result = AccessKeyStrategy::create(
                    VALID_CRN.to_string(),
                    "CSAKtestKeyId.testKeySecret".to_string(),
                );

                assert!(
                    result.is_ok(),
                    "valid CRN + access key should construct an AccessKeyStrategy",
                );
            }
        }

        /// End-to-end coverage that the `WorkspaceMismatch` error variant
        /// surfaces through the napi boundary as `WORKSPACE_MISMATCH` —
        /// the underlying Rust check is covered in
        /// `stack_auth::access_key_strategy`, but the FFI mapping has its
        /// own regression risk (the `error_code` match in this crate).
        mod given_token_workspace_mismatch {
            use super::*;

            // Drives the wrapper's inner field directly because the public
            // `AccessKeyStrategy::create` factory doesn't expose a base-URL
            // override. The base-URL override lives behind the `test-utils`
            // feature on `stack-auth` and isn't part of the napi surface.
            fn build_strategy_against(
                server: &MockServer,
                crn_workspace: &str,
            ) -> AccessKeyStrategy {
                let crn: cts_common::Crn = format!("crn:ap-southeast-2.aws:{crn_workspace}")
                    .parse()
                    .unwrap();
                let key: stack_auth::AccessKey = "CSAKtestKeyId.testKeySecret".parse().unwrap();
                let inner = stack_auth::AccessKeyStrategy::builder(crn, key)
                    .base_url(server.url(""))
                    .build()
                    .unwrap();
                AccessKeyStrategy { inner }
            }

            #[tokio::test]
            async fn get_token_returns_workspace_mismatch_error() {
                const TOKEN_WS: &str = "AAAAAAAAAAAAAAAA";
                const CRN_WS: &str = "ZVATKW3VHMFG27DY";

                let jwt = jwt_with_workspace(TOKEN_WS);
                let mut mocks = MockSet::new();
                mocks.mock(move |when, then| {
                    when.post().path("/api/authorise");
                    then.json(serde_json::json!({
                        "accessToken": jwt,
                        "expiry": 3600,
                    }));
                });
                let server = start_server(mocks).await;

                let strategy = build_strategy_against(&server, CRN_WS);
                let err = strategy.get_token().await.unwrap_err();

                assertions::has_error_code(&err, "WORKSPACE_MISMATCH");
            }
        }
    }
}
