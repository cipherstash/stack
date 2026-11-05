//! AWS credentials and where they come from.
//!
//! [`CredentialsProvider`] is the seam: the client asks it for
//! [`Credentials`] before it signs each request. This crate provides:
//!
//! * [`Credentials`] itself: static credentials, from explicit values or
//!   from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and
//!   `AWS_SESSION_TOKEN` ([`Credentials::from_env`]). Everywhere.
//! * [`CachedCredentials`]: keeps the credentials another provider returns
//!   and fetches new ones before they expire. Everywhere.
//! * Workload identity, **native only**: [`WebIdentityCredentials`] (IRSA
//!   on EKS: STS `AssumeRoleWithWebIdentity`), [`EcsCredentials`] (the ECS
//!   and EKS Pod Identity container endpoint) and [`ImdsCredentials`] (the
//!   EC2 instance metadata service, IMDSv2). [`DefaultCredentials`] picks
//!   one from the environment, as the AWS SDKs do.
//!
//! In the WASI guest the host supplies the credentials (ADR-0011): the
//! guest implements [`CredentialsProvider`] over a host import.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use futures::lock::Mutex;
use stack_kms::{BackendErrorKind, MaybeSend};
use web_time::SystemTime;
use zeroize::Zeroizing;

use crate::time::{system_clock, Clock};

#[cfg(not(target_arch = "wasm32"))]
mod chain;
#[cfg(not(target_arch = "wasm32"))]
mod ecs;
#[cfg(not(target_arch = "wasm32"))]
mod imds;
#[cfg(not(target_arch = "wasm32"))]
mod response;
#[cfg(not(target_arch = "wasm32"))]
mod web_identity;

#[cfg(not(target_arch = "wasm32"))]
pub use chain::{DefaultCredentials, DefaultCredentialsSource};
#[cfg(not(target_arch = "wasm32"))]
pub use ecs::EcsCredentials;
#[cfg(not(target_arch = "wasm32"))]
pub use imds::{ImdsCredentials, DEFAULT_IMDS_ENDPOINT};
#[cfg(not(target_arch = "wasm32"))]
pub use web_identity::WebIdentityCredentials;

/// How an environment variable is read: the process environment unless a
/// test gives another.
pub type EnvLookup = std::sync::Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The process environment. An empty variable counts as unset.
pub fn process_env() -> EnvLookup {
    std::sync::Arc::new(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
}

/// AWS credentials: an access key id, a secret access key and, for
/// temporary credentials, a session token and an expiry time.
///
/// The secret and the session token are wiped on drop and never printed.
#[derive(Clone)]
pub struct Credentials {
    access_key_id: String,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
    expires_at: Option<SystemTime>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Credentials {
    /// Credentials from explicit values. They do not expire.
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<String>,
    ) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: Zeroizing::new(secret_access_key.into()),
            session_token: session_token.map(Zeroizing::new),
            expires_at: None,
        }
    }

    /// The same credentials, expiring at `expires_at`.
    pub fn with_expiry(mut self, expires_at: SystemTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Credentials from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and
    /// (optional) `AWS_SESSION_TOKEN`. `None` unless both of the first two
    /// are set.
    pub fn from_env() -> Option<Self> {
        Self::from_env_lookup(&process_env())
    }

    /// As [`from_env`](Self::from_env), reading the variables with `env`.
    pub fn from_env_lookup(env: &EnvLookup) -> Option<Self> {
        let access_key_id = env("AWS_ACCESS_KEY_ID")?;
        let secret = Zeroizing::new(env("AWS_SECRET_ACCESS_KEY")?);
        Some(Self {
            access_key_id,
            secret_access_key: secret,
            session_token: env("AWS_SESSION_TOKEN").map(Zeroizing::new),
            expires_at: None,
        })
    }

    /// The access key id.
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    /// The secret access key.
    pub fn secret_access_key(&self) -> &str {
        &self.secret_access_key
    }

    /// The session token, for temporary credentials.
    pub fn session_token(&self) -> Option<&str> {
        self.session_token.as_ref().map(|token| token.as_str())
    }

    /// When the credentials expire. `None` for credentials that do not.
    pub fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }
}

/// The credentials could not be got.
#[derive(Debug, thiserror::Error)]
#[error("AWS credentials: {message}")]
pub struct CredentialsError {
    kind: BackendErrorKind,
    message: String,
}

impl CredentialsError {
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

    /// The credentials source did not answer.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(BackendErrorKind::Unavailable, message)
    }

    /// The failure kind the client reports.
    pub fn kind(&self) -> BackendErrorKind {
        self.kind
    }
}

/// Where a client gets its credentials. The client asks before it signs
/// each request, so a provider that fetches should cache
/// ([`CachedCredentials`]).
///
/// The returned future is bounded by [`MaybeSend`]: `Send` on native
/// targets, unbounded on wasm32.
pub trait CredentialsProvider: Send + Sync {
    /// The current credentials.
    fn credentials(
        &self,
    ) -> impl Future<Output = Result<Credentials, CredentialsError>> + MaybeSend;
}

impl CredentialsProvider for Credentials {
    fn credentials(
        &self,
    ) -> impl Future<Output = Result<Credentials, CredentialsError>> + MaybeSend {
        std::future::ready(Ok(self.clone()))
    }
}

/// The default time before expiry at which [`CachedCredentials`] fetches
/// new credentials.
pub const DEFAULT_REFRESH_BEFORE_EXPIRY: Duration = Duration::from_secs(5 * 60);

/// Keeps the credentials `inner` returns, and fetches new ones when they
/// are within the refresh window of their expiry
/// ([`DEFAULT_REFRESH_BEFORE_EXPIRY`]).
///
/// One fetch runs at a time: callers that arrive during a fetch wait for
/// it and share its result. If a fetch fails while the cached credentials
/// have not yet expired, they are still returned. Credentials with no
/// expiry are kept for good.
pub struct CachedCredentials<P> {
    inner: P,
    cached: Mutex<Option<Credentials>>,
    refresh_before: Duration,
    clock: Clock,
}

impl<P: fmt::Debug> fmt::Debug for CachedCredentials<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedCredentials")
            .field("inner", &self.inner)
            .field("refresh_before", &self.refresh_before)
            .finish_non_exhaustive()
    }
}

impl<P: CredentialsProvider> CachedCredentials<P> {
    /// Cache the credentials of `inner`.
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            cached: Mutex::new(None),
            refresh_before: DEFAULT_REFRESH_BEFORE_EXPIRY,
            clock: system_clock(),
        }
    }

    /// Fetch new credentials `refresh_before` before expiry.
    pub fn with_refresh_before(mut self, refresh_before: Duration) -> Self {
        self.refresh_before = refresh_before;
        self
    }

    /// Read the time from `clock`.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// The provider whose credentials are cached.
    pub fn inner(&self) -> &P {
        &self.inner
    }
}

impl<P: CredentialsProvider> CredentialsProvider for CachedCredentials<P> {
    async fn credentials(&self) -> Result<Credentials, CredentialsError> {
        let mut cached = self.cached.lock().await;
        let now = (self.clock)();
        if let Some(credentials) = cached.as_ref() {
            let fresh = credentials
                .expires_at
                .is_none_or(|expiry| now + self.refresh_before < expiry);
            if fresh {
                return Ok(credentials.clone());
            }
        }
        match self.inner.credentials().await {
            Ok(credentials) => {
                *cached = Some(credentials.clone());
                Ok(credentials)
            }
            Err(error) => match cached.as_ref() {
                Some(credentials) if credentials.expires_at.is_some_and(|e| now < e) => {
                    Ok(credentials.clone())
                }
                _ => Err(error),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;

    use web_time::UNIX_EPOCH;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> EnvLookup {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Arc::new(move |name| map.get(name).cloned())
    }

    #[test]
    fn static_credentials_come_from_the_environment() {
        assert!(Credentials::from_env_lookup(&env(&[])).is_none());
        assert!(Credentials::from_env_lookup(&env(&[("AWS_ACCESS_KEY_ID", "AKID")])).is_none());
        let credentials = Credentials::from_env_lookup(&env(&[
            ("AWS_ACCESS_KEY_ID", "AKID"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
        ]))
        .unwrap();
        assert_eq!(credentials.access_key_id(), "AKID");
        assert_eq!(credentials.secret_access_key(), "secret");
        assert_eq!(credentials.session_token(), None);
        assert_eq!(credentials.expires_at(), None);
        let credentials = Credentials::from_env_lookup(&env(&[
            ("AWS_ACCESS_KEY_ID", "AKID"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("AWS_SESSION_TOKEN", "token"),
        ]))
        .unwrap();
        assert_eq!(credentials.session_token(), Some("token"));
    }

    #[test]
    fn debug_hides_the_secret_and_the_token() {
        let text = format!(
            "{:?}",
            Credentials::new("AKID", "the-secret", Some("the-token".into()))
        );
        assert!(text.contains("AKID"));
        assert!(!text.contains("the-secret"));
        assert!(!text.contains("the-token"));
    }

    /// A provider that hands out credentials expiring `lifetime` after the
    /// test clock, or fails when told to.
    struct Counting {
        calls: AtomicUsize,
        fail: std::sync::atomic::AtomicBool,
        now: Arc<AtomicU64>,
        lifetime: Option<Duration>,
    }

    impl CredentialsProvider for Counting {
        async fn credentials(&self) -> Result<Credentials, CredentialsError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(CredentialsError::unavailable("down"));
            }
            let credentials = Credentials::new(format!("AKID{call}"), "secret", None);
            Ok(match self.lifetime {
                Some(lifetime) => credentials.with_expiry(
                    UNIX_EPOCH + Duration::from_secs(self.now.load(Ordering::SeqCst)) + lifetime,
                ),
                None => credentials,
            })
        }
    }

    fn cached(lifetime: Option<Duration>) -> (CachedCredentials<Counting>, Arc<AtomicU64>) {
        let now = Arc::new(AtomicU64::new(1_000_000));
        let clock_now = Arc::clone(&now);
        let provider = Counting {
            calls: AtomicUsize::new(0),
            fail: false.into(),
            now: Arc::clone(&now),
            lifetime,
        };
        let clock: Clock =
            Arc::new(move || UNIX_EPOCH + Duration::from_secs(clock_now.load(Ordering::SeqCst)));
        (CachedCredentials::new(provider).with_clock(clock), now)
    }

    #[tokio::test]
    async fn credentials_are_fetched_again_before_they_expire() {
        let (cache, now) = cached(Some(Duration::from_secs(3600)));
        assert_eq!(cache.credentials().await.unwrap().access_key_id(), "AKID0");
        now.fetch_add(3600 - 301, Ordering::SeqCst);
        assert_eq!(cache.credentials().await.unwrap().access_key_id(), "AKID0");
        now.fetch_add(1, Ordering::SeqCst);
        assert_eq!(cache.credentials().await.unwrap().access_key_id(), "AKID1");
        assert_eq!(cache.inner().calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn credentials_without_expiry_are_kept() {
        let (cache, now) = cached(None);
        cache.credentials().await.unwrap();
        now.fetch_add(10 * 365 * 86_400, Ordering::SeqCst);
        assert_eq!(cache.credentials().await.unwrap().access_key_id(), "AKID0");
        assert_eq!(cache.inner().calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_unexpired_credentials_only() {
        let (cache, now) = cached(Some(Duration::from_secs(3600)));
        cache.credentials().await.unwrap();
        cache.inner().fail.store(true, Ordering::SeqCst);
        now.fetch_add(3500, Ordering::SeqCst);
        assert_eq!(cache.credentials().await.unwrap().access_key_id(), "AKID0");
        now.fetch_add(100, Ordering::SeqCst);
        let error = cache.credentials().await.unwrap_err();
        assert_eq!(error.kind(), BackendErrorKind::Unavailable);
    }

    #[tokio::test]
    async fn the_refresh_window_is_configurable() {
        let (cache, now) = cached(Some(Duration::from_secs(3600)));
        let cache = cache.with_refresh_before(Duration::ZERO);
        cache.credentials().await.unwrap();
        now.fetch_add(3599, Ordering::SeqCst);
        assert_eq!(cache.credentials().await.unwrap().access_key_id(), "AKID0");
        now.fetch_add(1, Ordering::SeqCst);
        assert_eq!(cache.credentials().await.unwrap().access_key_id(), "AKID1");
    }
}
