//! OAuth 2.0 access tokens for Cloud KMS, and the credentials that get them.
//!
//! [`TokenProvider`] is the seam: the client asks it for an [`AccessToken`]
//! before each request. This crate provides:
//!
//! * [`AccessToken`] itself: a static token, for example from
//!   `gcloud auth print-access-token`. Everywhere. It is used until Google
//!   refuses it.
//! * [`ServiceAccountLogin`]: a service account key (the JSON file Google
//!   issues, [`ServiceAccountKey`]) signs a JWT with RS256 and exchanges it
//!   at the token endpoint (RFC 7523). Everywhere: the key can come from
//!   bytes.
//! * [`MetadataServerLogin`]: the token of the attached service account,
//!   from the metadata server of Compute Engine, GKE, Cloud Run and Cloud
//!   Functions. **Native only.**
//! * [`CachedToken`]: keeps the token a login returns and gets a new one
//!   before it expires.
//! * [`DefaultCredentials`] (native): picks one from the environment.
//!
//! In the WASI guest the host supplies the token (ADR-0011): the guest
//! implements [`TokenProvider`] over a host import.
//!
//! **Not supported:** the `authorized_user` file that
//! `gcloud auth application-default login` writes, `external_account`
//! (workload identity federation) files, and service account
//! impersonation. Use a service account key, the metadata server, or a
//! static token.

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
use crate::time::{system_clock, Clock};

#[cfg(not(target_arch = "wasm32"))]
mod metadata;
mod service_account;

#[cfg(not(target_arch = "wasm32"))]
pub use metadata::{MetadataServerLogin, DEFAULT_METADATA_HOST, METADATA_TOKEN_PATH};
pub use service_account::{
    ServiceAccountKey, ServiceAccountLogin, ASSERTION_LIFETIME, CLOUD_KMS_SCOPE, DEFAULT_TOKEN_URI,
    JWT_BEARER_GRANT_TYPE,
};

/// An OAuth 2.0 access token, and how long it lasts from when it was
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
    /// A token with no known expiry: it is used until Google refuses it.
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

    /// The token from `GOOGLE_OAUTH_ACCESS_TOKEN`, or `None` when it is not
    /// set.
    pub fn from_env_lookup(env: &EnvLookup) -> Option<Self> {
        env("GOOGLE_OAUTH_ACCESS_TOKEN").map(Self::new)
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
#[error("Google credentials: {message}")]
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

    /// The token endpoint or the metadata server did not answer.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(BackendErrorKind::Unavailable, message)
    }

    /// The failure kind the client reports.
    pub fn kind(&self) -> BackendErrorKind {
        self.kind
    }
}

/// Where a client gets its access token. The client asks before each
/// request, so a provider that logs in should cache ([`CachedToken`]).
///
/// The returned future is bounded by [`MaybeSend`]: `Send` on native
/// targets, unbounded on wasm32.
pub trait TokenProvider: Send + Sync {
    /// The current token.
    fn token(&self) -> impl Future<Output = Result<AccessToken, AuthError>> + MaybeSend;

    /// Google refused the current token (HTTP 401). A caching provider
    /// drops it, so that the next request gets a new one. The default does
    /// nothing.
    fn invalidate(&self) {}
}

impl TokenProvider for AccessToken {
    fn token(&self) -> impl Future<Output = Result<AccessToken, AuthError>> + MaybeSend {
        std::future::ready(Ok(self.clone()))
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    #[serde(default)]
    expires_in: u64,
}

#[derive(Deserialize)]
struct TokenErrorBody {
    error: Option<serde_json::Value>,
    error_description: Option<String>,
}

/// The access token of a token endpoint or metadata server response.
/// `source` names it in errors.
pub(crate) fn read_token_response(
    source: &str,
    response: &VendorResponse,
) -> Result<AccessToken, AuthError> {
    if let Some(kind) = classify_status(response.status) {
        // A refused grant is HTTP 400 (`invalid_grant`); a metadata server
        // with no service account answers 404. Neither is a missing key or
        // a damaged ciphertext.
        let kind = match kind {
            BackendErrorKind::InvalidCiphertext | BackendErrorKind::NotFound => {
                BackendErrorKind::AccessDenied
            }
            kind => kind,
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
    let token = Zeroizing::new(
        parsed
            .access_token
            .filter(|token| !token.is_empty())
            .ok_or_else(|| AuthError::unavailable(format!("{source} returned no access token")))?,
    );
    let token = AccessToken {
        token,
        expires_in: None,
    };
    Ok(match parsed.expires_in {
        0 => token,
        seconds => token.with_expires_in(Duration::from_secs(seconds)),
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

/// Keeps the token `inner` returns, and gets a new one when it is near its
/// expiry: [`DEFAULT_REFRESH_BEFORE_EXPIRY`] before, or a third of its life
/// before when it lives less than three times that.
///
/// One fetch runs at a time: callers that arrive during a fetch wait for it
/// and share its result. If a fetch fails while the cached token has not
/// expired, the cached token is still returned. A token with no expiry is
/// kept until Google refuses it ([`TokenProvider::invalidate`]).
pub struct CachedToken<P> {
    inner: P,
    cached: SyncMutex<Option<Cached>>,
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
    /// Cache the token of `inner`.
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            cached: SyncMutex::new(None),
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

    /// The provider whose token is cached.
    pub fn inner(&self) -> &P {
        &self.inner
    }

    /// The cached token, if it does not need a refresh yet.
    fn fresh(&self, now: SystemTime) -> Option<AccessToken> {
        let cached = self.cached.lock().unwrap_or_else(PoisonError::into_inner);
        cached
            .as_ref()
            .filter(|cached| cached.refresh_at.is_none_or(|at| now < at))
            .map(|cached| cached.token.clone())
    }
}

impl<P: TokenProvider> TokenProvider for CachedToken<P> {
    async fn token(&self) -> Result<AccessToken, AuthError> {
        if let Some(token) = self.fresh((self.clock)()) {
            return Ok(token);
        }
        let _fetch = self.fetch.lock().await;
        // Another caller may have got a token while this one waited.
        let now = (self.clock)();
        if let Some(token) = self.fresh(now) {
            return Ok(token);
        }
        match self.inner.token().await {
            Ok(token) => {
                let (refresh_at, expires_at) = match token.expires_in {
                    Some(life) => {
                        let window = self.refresh_before.min(life / 3);
                        (now.checked_add(life - window), now.checked_add(life))
                    }
                    None => (None, None),
                };
                *self.cached.lock().unwrap_or_else(PoisonError::into_inner) = Some(Cached {
                    token: token.clone(),
                    refresh_at,
                    expires_at,
                });
                Ok(token)
            }
            Err(error) => {
                let cached = self.cached.lock().unwrap_or_else(PoisonError::into_inner);
                match cached.as_ref() {
                    Some(cached) if cached.expires_at.is_some_and(|end| now < end) => {
                        Ok(cached.token.clone())
                    }
                    _ => Err(error),
                }
            }
        }
    }

    fn invalidate(&self) {
        *self.cached.lock().unwrap_or_else(PoisonError::into_inner) = None;
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
        /// `GOOGLE_OAUTH_ACCESS_TOKEN`.
        Token(AccessToken),
        /// The service account key file at `GOOGLE_APPLICATION_CREDENTIALS`.
        ServiceAccount(Box<CachedToken<ServiceAccountLogin<T>>>),
        /// The metadata server.
        MetadataServer(CachedToken<MetadataServerLogin<T>>),
    }

    impl<T: VendorTransport + Send + Sync> DefaultCredentials<T> {
        /// Pick credentials from the environment, in this order:
        ///
        /// 1. `GOOGLE_OAUTH_ACCESS_TOKEN`: a static access token.
        /// 2. `GOOGLE_APPLICATION_CREDENTIALS`: the path of a service
        ///    account key file. A file of another type (an
        ///    `authorized_user` or `external_account` file) is refused.
        /// 3. Otherwise the metadata server, at `GCE_METADATA_HOST` if set.
        ///
        /// The logins send through `transport` and are cached.
        pub fn from_env(transport: T) -> Result<Self, AuthError> {
            Self::from_env_lookup(transport, &process_env())
        }

        /// As [`from_env`](Self::from_env), reading the variables with `env`.
        pub fn from_env_lookup(transport: T, env: &EnvLookup) -> Result<Self, AuthError> {
            if let Some(token) = AccessToken::from_env_lookup(env) {
                return Ok(Self::Token(token));
            }
            if let Some(path) = env("GOOGLE_APPLICATION_CREDENTIALS") {
                let key = ServiceAccountKey::from_file(path)?;
                return Ok(Self::ServiceAccount(Box::new(CachedToken::new(
                    ServiceAccountLogin::new(key, transport),
                ))));
            }
            Ok(Self::MetadataServer(CachedToken::new(
                MetadataServerLogin::from_env_lookup(transport, env)?,
            )))
        }
    }

    impl<T: VendorTransport + Send + Sync> TokenProvider for DefaultCredentials<T> {
        async fn token(&self) -> Result<AccessToken, AuthError> {
            match self {
                Self::Token(token) => Ok(token.clone()),
                Self::ServiceAccount(login) => login.token().await,
                Self::MetadataServer(login) => login.token().await,
            }
        }

        fn invalidate(&self) {
            match self {
                Self::Token(_) => {}
                Self::ServiceAccount(login) => login.invalidate(),
                Self::MetadataServer(login) => login.invalidate(),
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

    struct Counting {
        calls: AtomicUsize,
        fail: AtomicBool,
        life: Option<Duration>,
    }

    impl TokenProvider for Counting {
        async fn token(&self) -> Result<AccessToken, AuthError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(AuthError::unavailable("down"));
            }
            let token = AccessToken::new(format!("token-{call}"));
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

    async fn token_of(cache: &CachedToken<Counting>) -> String {
        cache.token().await.unwrap().token().to_owned()
    }

    #[tokio::test]
    async fn a_token_is_got_again_before_it_expires() {
        let (cache, now) = cached(Some(Duration::from_secs(3600)));
        assert_eq!(token_of(&cache).await, "token-0");
        now.fetch_add(3600 - 301, Ordering::SeqCst);
        assert_eq!(token_of(&cache).await, "token-0");
        now.fetch_add(1, Ordering::SeqCst);
        assert_eq!(token_of(&cache).await, "token-1");
        assert_eq!(cache.inner().calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_short_life_refreshes_a_third_before_its_end() {
        let (cache, now) = cached(Some(Duration::from_secs(60)));
        assert_eq!(token_of(&cache).await, "token-0");
        now.fetch_add(39, Ordering::SeqCst);
        assert_eq!(token_of(&cache).await, "token-0");
        now.fetch_add(1, Ordering::SeqCst);
        assert_eq!(token_of(&cache).await, "token-1");
    }

    #[tokio::test]
    async fn a_token_with_no_expiry_is_kept_until_invalidated() {
        let (cache, now) = cached(None);
        assert_eq!(token_of(&cache).await, "token-0");
        now.fetch_add(10 * 365 * 86_400, Ordering::SeqCst);
        assert_eq!(token_of(&cache).await, "token-0");
        cache.invalidate();
        assert_eq!(token_of(&cache).await, "token-1");
    }

    #[tokio::test]
    async fn a_failed_fetch_keeps_a_token_that_has_not_expired() {
        let (cache, now) = cached(Some(Duration::from_secs(3600)));
        assert_eq!(token_of(&cache).await, "token-0");
        cache.inner().fail.store(true, Ordering::SeqCst);
        now.fetch_add(3500, Ordering::SeqCst);
        assert_eq!(token_of(&cache).await, "token-0");
        now.fetch_add(100, Ordering::SeqCst);
        let error = cache.token().await.unwrap_err();
        assert_eq!(error.kind(), BackendErrorKind::Unavailable);
    }

    #[tokio::test]
    async fn the_refresh_window_is_configurable() {
        let (cache, now) = cached(Some(Duration::from_secs(3600)));
        let cache = cache.with_refresh_before(Duration::ZERO);
        assert_eq!(token_of(&cache).await, "token-0");
        now.fetch_add(3599, Ordering::SeqCst);
        assert_eq!(token_of(&cache).await, "token-0");
        now.fetch_add(1, Ordering::SeqCst);
        assert_eq!(token_of(&cache).await, "token-1");
    }

    #[test]
    fn token_responses_are_read_and_failures_classified() {
        let ok = VendorResponse::new(
            200,
            br#"{"access_token":"t","expires_in":3599,"token_type":"Bearer"}"#.to_vec(),
        );
        let token = read_token_response("x", &ok).unwrap();
        assert_eq!(token.token(), "t");
        assert_eq!(token.expires_in(), Some(Duration::from_secs(3599)));
        for (status, body, kind) in [
            (
                400,
                &br#"{"error":"invalid_grant","error_description":"Invalid JWT Signature."}"#[..],
                BackendErrorKind::AccessDenied,
            ),
            (401, b"{}", BackendErrorKind::AccessDenied),
            (404, b"not found", BackendErrorKind::AccessDenied),
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
                read_token_response("x", &VendorResponse::new(status, body.to_vec())).unwrap_err();
            assert_eq!(error.kind(), kind, "{status}");
        }
        let error = read_token_response(
            "the token endpoint",
            &VendorResponse::new(
                400,
                br#"{"error":"invalid_grant","error_description":"Invalid JWT Signature."}"#
                    .to_vec(),
            ),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Google credentials: the token endpoint failed with HTTP 400: \
             invalid_grant: Invalid JWT Signature."
        );
    }
}
