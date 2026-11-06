//! Microsoft Entra ID (Azure AD) access tokens for Key Vault and Managed
//! HSM, and the credentials that get them.
//!
//! [`TokenProvider`] is the seam: the client asks it for an [`AccessToken`]
//! for a scope (`https://vault.azure.net/.default` or
//! `https://managedhsm.azure.net/.default`) before each request. This crate
//! provides:
//!
//! * [`AccessToken`] itself: a static token, for example from
//!   `az account get-access-token --resource https://vault.azure.net`.
//!   Everywhere. It is used for every scope until Azure refuses it.
//! * [`ClientSecretLogin`]: a service principal's client secret, exchanged
//!   at the Entra ID token endpoint (OAuth 2.0 client credentials).
//!   Everywhere.
//! * [`WorkloadIdentityLogin`]: a federated token from a file (AKS
//!   workload identity, `AZURE_FEDERATED_TOKEN_FILE`), exchanged as a
//!   client assertion. **Native only.**
//! * [`ManagedIdentityLogin`]: the managed identity of an Azure VM, VM scale
//!   set, AKS node or container instance (IMDS), or of an App Service or
//!   Functions app (`IDENTITY_ENDPOINT`). **Native only.**
//! * [`CachedToken`]: keeps the token of each scope and gets a new one
//!   before it expires.
//! * [`DefaultCredentials`] (native): picks one from the environment.
//!
//! In the WASI guest the host supplies the token (ADR-0011): the guest
//! implements [`TokenProvider`] over a host import.
//!
//! **Not supported:** client certificate credentials
//! (`AZURE_CLIENT_CERTIFICATE_PATH`). They sign a JWT with the service
//! principal's RSA key, and the only pure-Rust RSA crate has an open timing
//! advisory (RUSTSEC-2023-0071). Use a client secret, workload identity or a
//! managed identity. Also not supported: Azure CLI credentials, Azure Arc
//! and Service Fabric managed identity.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::{Mutex as SyncMutex, PoisonError};
use std::time::Duration;

use futures::lock::Mutex;
use serde::Deserialize;
use stack_kms::{BackendErrorKind, MaybeSend};
use stack_kms_vendor::{classify_status, VendorResponse};
use web_time::SystemTime;
use zeroize::Zeroizing;

use crate::config::EnvLookup;
use crate::time::{system_clock, unix_seconds, Clock};

mod client_secret;
#[cfg(not(target_arch = "wasm32"))]
mod managed_identity;
#[cfg(not(target_arch = "wasm32"))]
mod workload_identity;

pub use client_secret::{
    is_tenant_id, ClientSecretLogin, DEFAULT_AUTHORITY_HOST, JWT_BEARER_ASSERTION_TYPE,
};
#[cfg(not(target_arch = "wasm32"))]
pub use managed_identity::{
    ManagedIdentityLogin, APP_SERVICE_API_VERSION, IMDS_API_VERSION, IMDS_TOKEN_URL,
};
#[cfg(not(target_arch = "wasm32"))]
pub use workload_identity::WorkloadIdentityLogin;

/// The environment variable of a static access token. Azure has no
/// standard name for one; this one is ours.
pub const ACCESS_TOKEN_VARIABLE: &str = "AZURE_KEY_VAULT_ACCESS_TOKEN";

/// An Entra ID access token, and how long it lasts from when it was
/// issued.
///
/// The token is wiped on drop and never printed.
#[derive(Clone)]
pub struct AccessToken {
    token: Zeroizing<String>,
    expires_in: Option<Duration>,
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessToken")
            .field("token", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl AccessToken {
    /// A token with no known expiry: it is used until Azure refuses it.
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: Zeroizing::new(token.into()),
            expires_in: None,
        }
    }

    /// The same token, which expires `expires_in` from now.
    pub fn with_expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = Some(expires_in);
        self
    }

    /// The token from [`ACCESS_TOKEN_VARIABLE`], or `None` when it is not
    /// set.
    pub fn from_env_lookup(env: &EnvLookup) -> Option<Self> {
        env(ACCESS_TOKEN_VARIABLE).map(Self::new)
    }

    /// The token.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// How long the token lasts from when it was issued. `None` for a token
    /// with no known expiry.
    pub fn expires_in(&self) -> Option<Duration> {
        self.expires_in
    }
}

/// A token could not be got.
#[derive(Debug, thiserror::Error)]
#[error("Azure credentials: {message}")]
pub struct AuthError {
    kind: BackendErrorKind,
    message: String,
}

impl AuthError {
    /// A failure of `kind`, described by `message`. Never put a secret in
    /// the message.
    pub fn new(kind: BackendErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// No credentials are configured, or they were refused.
    pub fn access_denied(message: impl Into<String>) -> Self {
        Self::new(BackendErrorKind::AccessDenied, message)
    }

    /// The token endpoint or the managed identity endpoint did not answer.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(BackendErrorKind::Unavailable, message)
    }

    /// The failure kind the client reports.
    pub fn kind(&self) -> BackendErrorKind {
        self.kind
    }
}

/// Where a client gets its access tokens. The client asks before each
/// request, so a provider that logs in should cache ([`CachedToken`]).
///
/// The returned future is bounded by [`MaybeSend`]: `Send` on native
/// targets, unbounded on wasm32.
pub trait TokenProvider: Send + Sync {
    /// A token for `scope` (`https://vault.azure.net/.default`). A managed
    /// identity asks for the resource, the scope without `/.default`.
    fn token(
        &self,
        scope: &str,
    ) -> impl Future<Output = Result<AccessToken, AuthError>> + MaybeSend;

    /// Azure refused a token (HTTP 401). A caching provider drops its
    /// tokens, so that the next request gets a new one. The default does
    /// nothing.
    fn invalidate(&self) {}
}

impl TokenProvider for AccessToken {
    fn token(
        &self,
        _scope: &str,
    ) -> impl Future<Output = Result<AccessToken, AuthError>> + MaybeSend {
        std::future::ready(Ok(self.clone()))
    }
}

/// The resource of a scope: the scope without `/.default`.
pub fn resource_of(scope: &str) -> &str {
    scope.strip_suffix("/.default").unwrap_or(scope)
}

/// An integer of a JSON response that may be a number or a string (IMDS and
/// App Service send strings).
fn read_u64(value: Option<&serde_json::Value>) -> Option<u64> {
    match value? {
        serde_json::Value::String(text) => text.trim().parse().ok(),
        serde_json::Value::Number(number) => number.as_u64(),
        _ => None,
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    expires_in: Option<serde_json::Value>,
    expires_on: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct TokenErrorBody {
    error: Option<serde_json::Value>,
    error_description: Option<String>,
}

/// The access token of a token endpoint or managed identity response, read
/// at `now`. `source` names it in errors.
///
/// The life is `expires_in` (seconds, a number or a string), else
/// `expires_on` (Unix seconds) less `now`.
pub(crate) fn read_token_response(
    source: &str,
    response: &VendorResponse,
    now: SystemTime,
) -> Result<AccessToken, AuthError> {
    if let Some(kind) = classify_status(response.status) {
        // A refused grant is HTTP 400 or 401 (`invalid_client`); IMDS
        // answers 400 or 404 for an identity it does not have. None of these
        // is a missing key or a damaged ciphertext. IMDS answers 410 while
        // it updates, which a later try fixes.
        let kind = match (response.status, kind) {
            (410, _) => BackendErrorKind::Unavailable,
            (_, BackendErrorKind::InvalidCiphertext | BackendErrorKind::NotFound) => {
                BackendErrorKind::AccessDenied
            }
            (_, kind) => kind,
        };
        let detail = serde_json::from_slice::<TokenErrorBody>(&response.body)
            .ok()
            .map(|body| {
                let error = match body.error {
                    Some(serde_json::Value::String(text)) => text,
                    Some(serde_json::Value::Object(object)) => object
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or_default()
                        .to_owned(),
                    _ => String::new(),
                };
                match body.error_description {
                    Some(description) => format!("{error}: {description}"),
                    None => error,
                }
            })
            .unwrap_or_default();
        return Err(AuthError::new(
            kind,
            format!("{source} failed with HTTP {}: {detail}", response.status),
        ));
    }
    let parsed: TokenResponse = serde_json::from_slice(&response.body).map_err(|_| {
        AuthError::unavailable(format!("{source} returned a response that is not JSON"))
    })?;
    let token = AccessToken {
        token: Zeroizing::new(
            parsed
                .access_token
                .filter(|token| !token.is_empty())
                .ok_or_else(|| {
                    AuthError::unavailable(format!("{source} returned no access token"))
                })?,
        ),
        expires_in: None,
    };
    let life = match read_u64(parsed.expires_in.as_ref()) {
        Some(seconds) => Some(seconds),
        None => {
            read_u64(parsed.expires_on.as_ref()).map(|end| end.saturating_sub(unix_seconds(now)))
        }
    };
    Ok(match life {
        None | Some(0) => token,
        Some(seconds) => token.with_expires_in(Duration::from_secs(seconds)),
    })
}

/// The default time before a token expires at which [`CachedToken`] gets a
/// new one. For a short-lived token the window is a third of its life.
pub const DEFAULT_REFRESH_BEFORE_EXPIRY: Duration = Duration::from_secs(5 * 60);

/// A token in the cache, and when to get the next one.
struct Cached {
    token: AccessToken,
    /// When to get a new token. `None`: never.
    refresh_at: Option<SystemTime>,
    /// When the token expires. `None`: never.
    expires_at: Option<SystemTime>,
}

/// Keeps the token `inner` returns for each scope, and gets a new one when
/// it is near its expiry: [`DEFAULT_REFRESH_BEFORE_EXPIRY`] before, or a
/// third of its life before when it lives less than three times that.
///
/// One fetch runs at a time: callers that arrive during a fetch wait for it.
/// If a fetch fails while the cached token has not expired, the cached
/// token is still returned. A token with no expiry is kept until Azure
/// refuses it ([`TokenProvider::invalidate`], which drops every scope's).
pub struct CachedToken<P> {
    inner: P,
    cached: SyncMutex<HashMap<String, Cached>>,
    fetch: Mutex<()>,
    refresh_before: Duration,
    clock: Clock,
}

impl<P: fmt::Debug> fmt::Debug for CachedToken<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedToken")
            .field("inner", &self.inner)
            .field("refresh_before", &self.refresh_before)
            .finish_non_exhaustive()
    }
}

impl<P: TokenProvider> CachedToken<P> {
    /// Cache the tokens of `inner`.
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            cached: SyncMutex::new(HashMap::new()),
            fetch: Mutex::new(()),
            refresh_before: DEFAULT_REFRESH_BEFORE_EXPIRY,
            clock: system_clock(),
        }
    }

    /// Get a new token at most `refresh_before` before the token expires.
    pub fn with_refresh_before(mut self, refresh_before: Duration) -> Self {
        self.refresh_before = refresh_before;
        self
    }

    /// Read the time from `clock`.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// The provider whose tokens are cached.
    pub fn inner(&self) -> &P {
        &self.inner
    }

    /// The cached token of `scope`, if it does not need a refresh yet.
    fn fresh(&self, scope: &str, now: SystemTime) -> Option<AccessToken> {
        let cached = self.cached.lock().unwrap_or_else(PoisonError::into_inner);
        cached
            .get(scope)
            .filter(|cached| cached.refresh_at.is_none_or(|at| now < at))
            .map(|cached| cached.token.clone())
    }
}

impl<P: TokenProvider> TokenProvider for CachedToken<P> {
    async fn token(&self, scope: &str) -> Result<AccessToken, AuthError> {
        if let Some(token) = self.fresh(scope, (self.clock)()) {
            return Ok(token);
        }
        let _fetch = self.fetch.lock().await;
        // Another caller may have got a token while this one waited.
        let now = (self.clock)();
        if let Some(token) = self.fresh(scope, now) {
            return Ok(token);
        }
        match self.inner.token(scope).await {
            Ok(token) => {
                let (refresh_at, expires_at) = match token.expires_in {
                    Some(life) => {
                        let window = self.refresh_before.min(life / 3);
                        (now.checked_add(life - window), now.checked_add(life))
                    }
                    None => (None, None),
                };
                let _ = self
                    .cached
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(
                        scope.to_owned(),
                        Cached {
                            token: token.clone(),
                            refresh_at,
                            expires_at,
                        },
                    );
                Ok(token)
            }
            Err(error) => {
                let cached = self.cached.lock().unwrap_or_else(PoisonError::into_inner);
                match cached.get(scope) {
                    Some(cached) if cached.expires_at.is_some_and(|end| now < end) => {
                        Ok(cached.token.clone())
                    }
                    _ => Err(error),
                }
            }
        }
    }

    fn invalidate(&self) {
        self.cached
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.inner.invalidate();
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod default {
    use stack_kms_vendor::VendorTransport;

    use super::*;
    use crate::config::process_env;

    /// The credentials [`DefaultCredentials::from_env`] picks.
    #[derive(Debug)]
    pub enum DefaultCredentials<T> {
        /// [`ACCESS_TOKEN_VARIABLE`].
        Token(AccessToken),
        /// `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`.
        ClientSecret(CachedToken<ClientSecretLogin<T>>),
        /// `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and
        /// `AZURE_FEDERATED_TOKEN_FILE`.
        WorkloadIdentity(CachedToken<WorkloadIdentityLogin<T>>),
        /// A managed identity: App Service (`IDENTITY_ENDPOINT`) or IMDS.
        ManagedIdentity(CachedToken<ManagedIdentityLogin<T>>),
    }

    impl<T: VendorTransport + Send + Sync> DefaultCredentials<T> {
        /// Pick credentials from the environment, in this order (the order
        /// of the Azure SDKs' `DefaultAzureCredential`, less the ones this
        /// crate does not support):
        ///
        /// 1. [`ACCESS_TOKEN_VARIABLE`]: a static access token.
        /// 2. `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`:
        ///    a client secret. `AZURE_CLIENT_CERTIFICATE_PATH` with no
        ///    secret is refused (not supported).
        /// 3. `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and
        ///    `AZURE_FEDERATED_TOKEN_FILE`: workload identity.
        /// 4. Otherwise a managed identity: App Service when
        ///    `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` are set, else IMDS.
        ///    `AZURE_CLIENT_ID`, if set, names a user-assigned identity.
        ///
        /// `AZURE_AUTHORITY_HOST` changes the Entra ID host (for a national
        /// cloud). The logins send through `transport` and are cached.
        pub fn from_env(transport: T) -> Result<Self, AuthError> {
            Self::from_env_lookup(transport, &process_env())
        }

        /// As [`from_env`](Self::from_env), reading the variables with `env`.
        pub fn from_env_lookup(transport: T, env: &EnvLookup) -> Result<Self, AuthError> {
            if let Some(token) = AccessToken::from_env_lookup(env) {
                return Ok(Self::Token(token));
            }
            let tenant = env("AZURE_TENANT_ID");
            let client = env("AZURE_CLIENT_ID");
            if let (Some(tenant), Some(client)) = (&tenant, &client) {
                if let Some(secret) = env("AZURE_CLIENT_SECRET") {
                    let login = ClientSecretLogin::new(tenant, client, secret, transport)?;
                    let login = match env("AZURE_AUTHORITY_HOST") {
                        Some(host) => login.with_authority_host(host)?,
                        None => login,
                    };
                    return Ok(Self::ClientSecret(CachedToken::new(login)));
                }
                if env("AZURE_CLIENT_CERTIFICATE_PATH").is_some() {
                    return Err(AuthError::access_denied(
                        "client certificate credentials (AZURE_CLIENT_CERTIFICATE_PATH) are \
                         not supported; use a client secret, workload identity or a managed \
                         identity",
                    ));
                }
                if let Some(file) = env("AZURE_FEDERATED_TOKEN_FILE") {
                    let login = WorkloadIdentityLogin::new(tenant, client, file, transport)?;
                    let login = match env("AZURE_AUTHORITY_HOST") {
                        Some(host) => login.with_authority_host(host)?,
                        None => login,
                    };
                    return Ok(Self::WorkloadIdentity(CachedToken::new(login)));
                }
            }
            Ok(Self::ManagedIdentity(CachedToken::new(
                ManagedIdentityLogin::from_env_lookup(transport, env)?,
            )))
        }
    }

    impl<T: VendorTransport + Send + Sync> TokenProvider for DefaultCredentials<T> {
        async fn token(&self, scope: &str) -> Result<AccessToken, AuthError> {
            match self {
                Self::Token(token) => Ok(token.clone()),
                Self::ClientSecret(login) => login.token(scope).await,
                Self::WorkloadIdentity(login) => login.token(scope).await,
                Self::ManagedIdentity(login) => login.token(scope).await,
            }
        }

        fn invalidate(&self) {
            match self {
                Self::Token(_) => {}
                Self::ClientSecret(login) => login.invalidate(),
                Self::WorkloadIdentity(login) => login.invalidate(),
                Self::ManagedIdentity(login) => login.invalidate(),
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use default::DefaultCredentials;

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;

    use web_time::UNIX_EPOCH;

    use super::*;

    #[test]
    fn debug_hides_the_token() {
        let text = format!("{:?}", AccessToken::new("the-access-token"));
        assert!(!text.contains("the-access-token"));
    }

    #[test]
    fn the_resource_is_the_scope_without_default() {
        assert_eq!(
            resource_of("https://vault.azure.net/.default"),
            "https://vault.azure.net"
        );
        assert_eq!(resource_of("https://x"), "https://x");
    }

    struct Counting {
        calls: AtomicUsize,
        fail: AtomicBool,
        life: Option<Duration>,
    }

    impl TokenProvider for Counting {
        async fn token(&self, scope: &str) -> Result<AccessToken, AuthError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(AuthError::unavailable("down"));
            }
            let token = AccessToken::new(format!("{scope}-{call}"));
            Ok(match self.life {
                Some(life) => token.with_expires_in(life),
                None => token,
            })
        }
    }

    fn cached(life: Option<Duration>) -> (CachedToken<Counting>, Arc<AtomicU64>) {
        let now = Arc::new(AtomicU64::new(1_000_000));
        let clock_now = Arc::clone(&now);
        let clock: Clock =
            Arc::new(move || UNIX_EPOCH + Duration::from_secs(clock_now.load(Ordering::SeqCst)));
        let provider = Counting {
            calls: AtomicUsize::new(0),
            fail: false.into(),
            life,
        };
        (CachedToken::new(provider).with_clock(clock), now)
    }

    async fn token_of(cache: &CachedToken<Counting>, scope: &str) -> String {
        cache.token(scope).await.unwrap().token().to_owned()
    }

    #[tokio::test]
    async fn a_token_is_got_again_before_it_expires() {
        let (cache, now) = cached(Some(Duration::from_secs(3600)));
        assert_eq!(token_of(&cache, "v").await, "v-0");
        now.fetch_add(3600 - 301, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-0");
        now.fetch_add(1, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-1");
        assert_eq!(cache.inner().calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn each_scope_has_its_own_token() {
        let (cache, _) = cached(Some(Duration::from_secs(3600)));
        assert_eq!(token_of(&cache, "vault").await, "vault-0");
        assert_eq!(token_of(&cache, "hsm").await, "hsm-1");
        assert_eq!(token_of(&cache, "vault").await, "vault-0");
        assert_eq!(token_of(&cache, "hsm").await, "hsm-1");
        cache.invalidate();
        assert_eq!(token_of(&cache, "hsm").await, "hsm-2");
        assert_eq!(token_of(&cache, "vault").await, "vault-3");
    }

    #[tokio::test]
    async fn a_short_life_refreshes_a_third_before_its_end() {
        let (cache, now) = cached(Some(Duration::from_secs(60)));
        assert_eq!(token_of(&cache, "v").await, "v-0");
        now.fetch_add(39, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-0");
        now.fetch_add(1, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-1");
    }

    #[tokio::test]
    async fn a_token_with_no_expiry_is_kept_until_invalidated() {
        let (cache, now) = cached(None);
        assert_eq!(token_of(&cache, "v").await, "v-0");
        now.fetch_add(10 * 365 * 86_400, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-0");
        cache.invalidate();
        assert_eq!(token_of(&cache, "v").await, "v-1");
    }

    #[tokio::test]
    async fn a_failed_fetch_keeps_a_token_that_has_not_expired() {
        let (cache, now) = cached(Some(Duration::from_secs(3600)));
        assert_eq!(token_of(&cache, "v").await, "v-0");
        cache.inner().fail.store(true, Ordering::SeqCst);
        now.fetch_add(3500, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-0");
        now.fetch_add(100, Ordering::SeqCst);
        let error = cache.token("v").await.unwrap_err();
        assert_eq!(error.kind(), BackendErrorKind::Unavailable);
        // Another scope has nothing cached to fall back on.
        let error = cache.token("w").await.unwrap_err();
        assert_eq!(error.kind(), BackendErrorKind::Unavailable);
    }

    #[tokio::test]
    async fn the_refresh_window_is_configurable() {
        let (cache, now) = cached(Some(Duration::from_secs(3600)));
        let cache = cache.with_refresh_before(Duration::ZERO);
        assert_eq!(token_of(&cache, "v").await, "v-0");
        now.fetch_add(3599, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-0");
        now.fetch_add(1, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-1");
    }

    #[test]
    fn token_responses_are_read_and_failures_classified() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        for (body, life) in [
            (
                &br#"{"token_type":"Bearer","expires_in":3599,"access_token":"t"}"#[..],
                Some(3599),
            ),
            (br#"{"access_token":"t","expires_in":"86399"}"#, Some(86399)),
            (
                br#"{"access_token":"t","expires_on":"1003600"}"#,
                Some(3600),
            ),
            (br#"{"access_token":"t","expires_on":1000060}"#, Some(60)),
            (br#"{"access_token":"t","expires_on":"999999"}"#, None),
            (br#"{"access_token":"t"}"#, None),
        ] {
            let token =
                read_token_response("x", &VendorResponse::new(200, body.to_vec()), now).unwrap();
            assert_eq!(token.token(), "t");
            assert_eq!(token.expires_in(), life.map(Duration::from_secs));
        }
        for (status, body, kind) in [
            (
                400,
                &br#"{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}"#[..],
                BackendErrorKind::AccessDenied,
            ),
            (401, b"{}", BackendErrorKind::AccessDenied),
            (404, b"not found", BackendErrorKind::AccessDenied),
            (410, b"", BackendErrorKind::Unavailable),
            (429, b"", BackendErrorKind::Throttled),
            (503, b"", BackendErrorKind::Unavailable),
            (200, b"not json", BackendErrorKind::Unavailable),
            (
                200,
                br#"{"access_token":""}"#,
                BackendErrorKind::Unavailable,
            ),
        ] {
            let error =
                read_token_response("x", &VendorResponse::new(status, body.to_vec()), now)
                    .unwrap_err();
            assert_eq!(error.kind(), kind, "{status}");
        }
        let error = read_token_response(
            "the token endpoint",
            &VendorResponse::new(
                401,
                br#"{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}"#
                    .to_vec(),
            ),
            now,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Azure credentials: the token endpoint failed with HTTP 401: \
             invalid_client: AADSTS7000215: Invalid client secret provided."
        );
    }
}
