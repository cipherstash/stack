//! What the vendor crates share about credentials: the access token, the
//! credential error, and the cache that keeps a credential until it is
//! near its expiry.
//!
//! Each vendor crate declares one marker type that implements
//! [`CredentialKind`]. The marker names the credential the crate caches,
//! what the cache is keyed by (a scope, or nothing) and the text that
//! starts each [`CredentialError`]. The crate then implements
//! [`FetchCredential`] on the marker for each of its providers, and its own
//! provider trait for [`CachedToken<P, Marker>`](CachedToken). The crate
//! names these with type aliases, for example
//! `type CachedToken<P> = stack_kms_vendor::CachedToken<P, GoogleCredentials>`.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::{Mutex as SyncMutex, PoisonError};
use std::time::Duration;

use futures::lock::Mutex;
use stack_kms::{BackendErrorKind, MaybeSend};
use web_time::SystemTime;
use zeroize::Zeroizing;

/// The time source of a credential cache: `SystemTime::now` unless a test
/// sets another.
pub type Clock = std::sync::Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// The system clock.
pub fn system_clock() -> Clock {
    std::sync::Arc::new(SystemTime::now)
}

/// When a credential stops working.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    /// No known expiry: the credential is used until the vendor refuses it.
    Never,
    /// It lasts this long from when it was got (an OAuth `expires_in`, a
    /// Vault lease).
    After(Duration),
    /// It stops working at this time (AWS temporary credentials).
    At(SystemTime),
}

/// A credential that [`CachedToken`] can keep.
pub trait Expiring: Clone + Send + Sync + 'static {
    /// When the credential stops working.
    fn expiry(&self) -> Expiry;
}

/// An OAuth 2.0 bearer token, and how long it lasts from when it was
/// issued. Google Cloud and Azure use it.
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
    /// A token with no known expiry: it is used until the vendor refuses
    /// it.
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

impl Expiring for AccessToken {
    fn expiry(&self) -> Expiry {
        self.expires_in.map_or(Expiry::Never, Expiry::After)
    }
}

/// The credential of a vendor crate, as its cache and its errors see it.
/// A vendor crate implements this on one marker type (an empty enum).
pub trait CredentialKind: Sized + 'static {
    /// The text that starts each [`CredentialError`] of this kind, for
    /// example `"Google credentials"`.
    const LABEL: &'static str;

    /// What the cache keeps one credential for: `()` for one credential, a
    /// scope for one credential per scope.
    type Key: Eq + Hash + Clone + Send + Sync + 'static;

    /// The credential.
    type Credential: Expiring;
}

/// A credential could not be got.
///
/// `K` names the vendor: the message starts with [`CredentialKind::LABEL`].
/// Each vendor crate names this type with an alias (`AuthError`,
/// `CredentialsError`).
pub struct CredentialError<K> {
    kind: BackendErrorKind,
    message: String,
    vendor: PhantomData<fn() -> K>,
}

impl<K: CredentialKind> CredentialError<K> {
    /// A failure of `kind`, described by `message`. Never put a secret in
    /// the message.
    pub fn new(kind: BackendErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            vendor: PhantomData,
        }
    }

    /// No credentials are configured, or they were refused.
    pub fn access_denied(message: impl Into<String>) -> Self {
        Self::new(BackendErrorKind::AccessDenied, message)
    }

    /// The credential source did not answer.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(BackendErrorKind::Unavailable, message)
    }

    /// The failure kind the client reports.
    pub fn kind(&self) -> BackendErrorKind {
        self.kind
    }
}

impl<K: CredentialKind> fmt::Debug for CredentialError<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialError")
            .field("vendor", &K::LABEL)
            .field("kind", &self.kind)
            .field("message", &self.message)
            .finish()
    }
}

impl<K: CredentialKind> fmt::Display for CredentialError<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", K::LABEL, self.message)
    }
}

impl<K: CredentialKind> std::error::Error for CredentialError<K> {}

/// How [`CachedToken`] gets a credential of kind `Self` from a provider
/// `P`. A vendor crate implements this on its marker type, for every type
/// that implements its own provider trait.
pub trait FetchCredential<P>: CredentialKind {
    /// Get a new credential for `key` from `provider`.
    ///
    /// The returned future is bounded by [`MaybeSend`]: `Send` on native
    /// targets, unbounded on wasm32.
    fn fetch<'a>(
        provider: &'a P,
        key: &'a Self::Key,
    ) -> impl Future<Output = Result<Self::Credential, CredentialError<Self>>> + MaybeSend + 'a;

    /// The vendor refused a credential of `provider`. The default does
    /// nothing.
    fn invalidate(provider: &P) {
        let _ = provider;
    }
}

/// The default time before a credential expires at which [`CachedToken`]
/// gets a new one. For a short-lived credential the window is a third of
/// its life.
pub const DEFAULT_REFRESH_BEFORE_EXPIRY: Duration = Duration::from_secs(5 * 60);

/// A credential in the cache, and when to get the next one.
struct Cached<C> {
    credential: C,
    /// When to get a new credential. `None`: never.
    refresh_at: Option<SystemTime>,
    /// When the credential expires. `None`: never.
    expires_at: Option<SystemTime>,
}

/// Keeps the credential `inner` returns for each key, and gets a new one
/// when it is near its expiry: [`DEFAULT_REFRESH_BEFORE_EXPIRY`] before, or
/// a third of its life before when it lives less than three times that.
///
/// One fetch runs at a time: callers that arrive during a fetch wait for it
/// and share its result. If a fetch fails while the cached credential has
/// not expired, the cached credential is still returned. A credential with
/// no expiry ([`Expiry::Never`]) is kept until
/// [`invalidate`](Self::invalidate).
///
/// `K` is the vendor crate's marker type ([`CredentialKind`]).
pub struct CachedToken<P, K: CredentialKind> {
    inner: P,
    cached: SyncMutex<HashMap<K::Key, Cached<K::Credential>>>,
    fetch: Mutex<()>,
    refresh_before: Duration,
    clock: Clock,
}

impl<P: fmt::Debug, K: CredentialKind> fmt::Debug for CachedToken<P, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedToken")
            .field("inner", &self.inner)
            .field("refresh_before", &self.refresh_before)
            .finish_non_exhaustive()
    }
}

impl<P, K: CredentialKind> CachedToken<P, K> {
    /// Cache the credentials of `inner`.
    pub fn new(inner: P) -> Self {
        Self {
            inner,
            cached: SyncMutex::new(HashMap::new()),
            fetch: Mutex::new(()),
            refresh_before: DEFAULT_REFRESH_BEFORE_EXPIRY,
            clock: system_clock(),
        }
    }

    /// Get a new credential at most `refresh_before` before the credential
    /// expires.
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

    /// The cached credential of `key`, if it does not need a refresh yet.
    fn fresh<Q>(&self, key: &Q, now: SystemTime) -> Option<K::Credential>
    where
        K::Key: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let cached = self.cached.lock().unwrap_or_else(PoisonError::into_inner);
        cached
            .get(key)
            .filter(|cached| cached.refresh_at.is_none_or(|at| now < at))
            .map(|cached| cached.credential.clone())
    }

    /// When to refresh a credential got at `now`, and when it expires.
    fn schedule(
        &self,
        expiry: Expiry,
        now: SystemTime,
    ) -> (Option<SystemTime>, Option<SystemTime>) {
        let expires_at = match expiry {
            Expiry::Never => return (None, None),
            Expiry::After(life) => now.checked_add(life),
            Expiry::At(at) => Some(at),
        };
        let Some(expires_at) = expires_at else {
            // Past the end of time: as good as no expiry.
            return (None, None);
        };
        let life = expires_at.duration_since(now).unwrap_or(Duration::ZERO);
        let window = self.refresh_before.min(life / 3);
        (expires_at.checked_sub(window), Some(expires_at))
    }
}

impl<P, K: FetchCredential<P>> CachedToken<P, K> {
    /// The credential of `key`: the cached one, or a new one from the
    /// provider when the cached one is near its expiry.
    pub async fn get<Q>(&self, key: &Q) -> Result<K::Credential, CredentialError<K>>
    where
        K::Key: Borrow<Q>,
        Q: Hash + Eq + ToOwned<Owned = K::Key> + ?Sized,
    {
        if let Some(credential) = self.fresh(key, (self.clock)()) {
            return Ok(credential);
        }
        let _fetch = self.fetch.lock().await;
        // Another caller may have got a credential while this one waited.
        let now = (self.clock)();
        if let Some(credential) = self.fresh(key, now) {
            return Ok(credential);
        }
        let key = key.to_owned();
        match K::fetch(&self.inner, &key).await {
            Ok(credential) => {
                let (refresh_at, expires_at) = self.schedule(credential.expiry(), now);
                let _ = self
                    .cached
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(
                        key,
                        Cached {
                            credential: credential.clone(),
                            refresh_at,
                            expires_at,
                        },
                    );
                Ok(credential)
            }
            Err(error) => {
                let cached = self.cached.lock().unwrap_or_else(PoisonError::into_inner);
                match cached.get::<K::Key>(&key) {
                    Some(cached) if cached.expires_at.is_some_and(|end| now < end) => {
                        Ok(cached.credential.clone())
                    }
                    _ => Err(error),
                }
            }
        }
    }

    /// The vendor refused a credential: drop every cached credential, so
    /// that the next [`get`](Self::get) fetches a new one, and tell the
    /// provider ([`FetchCredential::invalidate`]).
    pub fn invalidate(&self) {
        self.cached
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        K::invalidate(&self.inner);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;

    use web_time::UNIX_EPOCH;

    use super::*;

    /// The test vendor: one token per key (a `String`).
    enum Test {}

    impl CredentialKind for Test {
        const LABEL: &'static str = "Test credentials";
        type Key = String;
        type Credential = AccessToken;
    }

    /// The expiry the provider gives its tokens.
    #[derive(Clone, Copy)]
    enum Life {
        Never,
        After(u64),
        /// Expires at this many seconds after the test clock's start.
        At(u64),
    }

    struct Counting {
        calls: AtomicUsize,
        invalidations: AtomicUsize,
        fail: AtomicBool,
        life: Life,
        /// Held by a test to keep a fetch waiting.
        gate: Mutex<()>,
    }

    /// A token whose `expiry` is not the one `AccessToken` reports, to
    /// test [`Expiry::At`].
    #[derive(Clone)]
    struct Timed(AccessToken, Expiry);

    impl Expiring for Timed {
        fn expiry(&self) -> Expiry {
            self.1
        }
    }

    enum TimedTest {}

    impl CredentialKind for TimedTest {
        const LABEL: &'static str = "Timed credentials";
        type Key = ();
        type Credential = Timed;
    }

    const START: u64 = 1_000_000;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    impl Counting {
        async fn next(&self, key: &str) -> Result<(AccessToken, Expiry), String> {
            let _gate = self.gate.lock().await;
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err("down".to_owned());
            }
            let token = AccessToken::new(format!("{key}-{call}"));
            Ok(match self.life {
                Life::Never => (token, Expiry::Never),
                Life::After(seconds) => {
                    let token = token.with_expires_in(Duration::from_secs(seconds));
                    let expiry = token.expiry();
                    (token, expiry)
                }
                Life::At(seconds) => (token, Expiry::At(at(START + seconds))),
            })
        }
    }

    impl FetchCredential<Counting> for Test {
        async fn fetch(
            provider: &Counting,
            key: &String,
        ) -> Result<AccessToken, CredentialError<Self>> {
            provider
                .next(key)
                .await
                .map(|(token, _)| token)
                .map_err(CredentialError::unavailable)
        }

        fn invalidate(provider: &Counting) {
            provider.invalidations.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl FetchCredential<Counting> for TimedTest {
        async fn fetch(provider: &Counting, _key: &()) -> Result<Timed, CredentialError<Self>> {
            provider
                .next("t")
                .await
                .map(|(token, expiry)| Timed(token, expiry))
                .map_err(CredentialError::unavailable)
        }
    }

    fn provider(life: Life) -> Counting {
        Counting {
            calls: AtomicUsize::new(0),
            invalidations: AtomicUsize::new(0),
            fail: false.into(),
            life,
            gate: Mutex::new(()),
        }
    }

    fn clock() -> (Clock, Arc<AtomicU64>) {
        let now = Arc::new(AtomicU64::new(START));
        let clock_now = Arc::clone(&now);
        let clock: Clock = Arc::new(move || at(clock_now.load(Ordering::SeqCst)));
        (clock, now)
    }

    fn cached(life: Life) -> (CachedToken<Counting, Test>, Arc<AtomicU64>) {
        let (clock, now) = clock();
        (CachedToken::new(provider(life)).with_clock(clock), now)
    }

    async fn token_of(cache: &CachedToken<Counting, Test>, key: &str) -> String {
        cache.get(key).await.unwrap().token().to_owned()
    }

    #[tokio::test]
    async fn a_credential_is_got_again_before_it_expires() {
        let (cache, now) = cached(Life::After(3600));
        assert_eq!(token_of(&cache, "v").await, "v-0");
        now.fetch_add(3600 - 301, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-0");
        now.fetch_add(1, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-1");
        assert_eq!(cache.inner().calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_short_life_refreshes_a_third_before_its_end() {
        let (cache, now) = cached(Life::After(60));
        assert_eq!(token_of(&cache, "v").await, "v-0");
        now.fetch_add(39, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-0");
        now.fetch_add(1, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-1");
    }

    #[tokio::test]
    async fn a_credential_with_no_expiry_is_kept_until_invalidated() {
        let (cache, now) = cached(Life::Never);
        assert_eq!(token_of(&cache, "v").await, "v-0");
        now.fetch_add(10 * 365 * 86_400, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-0");
        assert_eq!(cache.inner().invalidations.load(Ordering::SeqCst), 0);
        cache.invalidate();
        assert_eq!(cache.inner().invalidations.load(Ordering::SeqCst), 1);
        assert_eq!(token_of(&cache, "v").await, "v-1");
    }

    #[tokio::test]
    async fn a_failed_fetch_keeps_a_credential_that_has_not_expired() {
        let (cache, now) = cached(Life::After(3600));
        assert_eq!(token_of(&cache, "v").await, "v-0");
        cache.inner().fail.store(true, Ordering::SeqCst);
        now.fetch_add(3500, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-0");
        // At the expiry the credential is not returned.
        now.fetch_add(100, Ordering::SeqCst);
        let error = cache.get("v").await.unwrap_err();
        assert_eq!(error.kind(), BackendErrorKind::Unavailable);
        // Another key has nothing cached to fall back on.
        let error = cache.get("w").await.unwrap_err();
        assert_eq!(error.kind(), BackendErrorKind::Unavailable);
    }

    #[tokio::test]
    async fn a_failed_fetch_returns_a_credential_until_its_last_second() {
        let (cache, now) = cached(Life::After(3600));
        assert_eq!(token_of(&cache, "v").await, "v-0");
        cache.inner().fail.store(true, Ordering::SeqCst);
        now.fetch_add(3599, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-0");
    }

    #[tokio::test]
    async fn a_failed_fetch_with_no_expiry_is_an_error() {
        let (cache, _) = cached(Life::Never);
        cache.inner().fail.store(true, Ordering::SeqCst);
        assert!(cache.get("v").await.is_err());
    }

    #[tokio::test]
    async fn the_refresh_window_is_configurable() {
        let (cache, now) = cached(Life::After(3600));
        let cache = cache.with_refresh_before(Duration::ZERO);
        assert_eq!(token_of(&cache, "v").await, "v-0");
        now.fetch_add(3599, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-0");
        now.fetch_add(1, Ordering::SeqCst);
        assert_eq!(token_of(&cache, "v").await, "v-1");
    }

    #[tokio::test]
    async fn each_key_has_its_own_credential() {
        let (cache, _) = cached(Life::After(3600));
        assert_eq!(token_of(&cache, "vault").await, "vault-0");
        assert_eq!(token_of(&cache, "hsm").await, "hsm-1");
        assert_eq!(token_of(&cache, "vault").await, "vault-0");
        assert_eq!(token_of(&cache, "hsm").await, "hsm-1");
        cache.invalidate();
        assert_eq!(token_of(&cache, "hsm").await, "hsm-2");
        assert_eq!(token_of(&cache, "vault").await, "vault-3");
    }

    #[tokio::test]
    async fn callers_during_a_fetch_share_its_result() {
        let (cache, _) = cached(Life::After(3600));
        let gate = cache.inner().gate.lock().await;
        let open = async {
            // Let both callers start before the fetch can end.
            tokio::task::yield_now().await;
            drop(gate);
        };
        let (first, second, ()) = futures::join!(cache.get("v"), cache.get("v"), open);
        assert_eq!(first.unwrap().token(), "v-0");
        assert_eq!(second.unwrap().token(), "v-0");
        assert_eq!(cache.inner().calls.load(Ordering::SeqCst), 1);
    }

    fn timed(life: Life) -> (CachedToken<Counting, TimedTest>, Arc<AtomicU64>) {
        let (clock, now) = clock();
        (CachedToken::new(provider(life)).with_clock(clock), now)
    }

    async fn timed_token(cache: &CachedToken<Counting, TimedTest>) -> String {
        cache.get(&()).await.unwrap().0.token().to_owned()
    }

    #[tokio::test]
    async fn a_credential_with_an_expiry_time_is_refreshed_before_it() {
        let (cache, now) = timed(Life::At(3600));
        assert_eq!(timed_token(&cache).await, "t-0");
        now.fetch_add(3600 - 301, Ordering::SeqCst);
        assert_eq!(timed_token(&cache).await, "t-0");
        now.fetch_add(1, Ordering::SeqCst);
        assert_eq!(timed_token(&cache).await, "t-1");
    }

    #[tokio::test]
    async fn an_expiry_time_measures_the_life_from_the_fetch() {
        // Got at START, expires at START + 60: refreshed 20 seconds early.
        let (cache, now) = timed(Life::At(60));
        assert_eq!(timed_token(&cache).await, "t-0");
        now.fetch_add(39, Ordering::SeqCst);
        assert_eq!(timed_token(&cache).await, "t-0");
        now.fetch_add(1, Ordering::SeqCst);
        assert_eq!(timed_token(&cache).await, "t-1");
    }

    #[tokio::test]
    async fn a_credential_that_has_already_expired_is_not_kept() {
        let (cache, now) = timed(Life::At(0));
        now.fetch_add(10, Ordering::SeqCst);
        assert_eq!(timed_token(&cache).await, "t-0");
        assert_eq!(timed_token(&cache).await, "t-1");
        cache.inner().fail.store(true, Ordering::SeqCst);
        assert!(cache.get(&()).await.is_err());
    }

    #[test]
    fn an_access_token_reports_its_expiry() {
        assert_eq!(AccessToken::new("t").expiry(), Expiry::Never);
        let token = AccessToken::new("t").with_expires_in(Duration::from_secs(9));
        assert_eq!(token.token(), "t");
        assert_eq!(token.expires_in(), Some(Duration::from_secs(9)));
        assert_eq!(token.expiry(), Expiry::After(Duration::from_secs(9)));
    }

    #[tokio::test]
    async fn debug_hides_the_secret() {
        let text = format!("{:?}", AccessToken::new("the-access-token"));
        assert!(text.contains("AccessToken"));
        assert!(!text.contains("the-access-token"));
        let (cache, _) = cached(Life::Never);
        let _ = cache.get("v").await.unwrap();
        let text = format!("{cache:?}");
        assert!(text.contains("CachedToken"));
        assert!(!text.contains("v-0"));
    }

    impl fmt::Debug for Counting {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Counting")
        }
    }

    #[test]
    fn an_error_names_its_vendor_and_kind() {
        let error = CredentialError::<Test>::access_denied("no key");
        assert_eq!(error.kind(), BackendErrorKind::AccessDenied);
        assert_eq!(error.to_string(), "Test credentials: no key");
        assert!(format!("{error:?}").contains("Test credentials"));
        let error = CredentialError::<Test>::unavailable("down");
        assert_eq!(error.kind(), BackendErrorKind::Unavailable);
        let error = CredentialError::<Test>::new(BackendErrorKind::Throttled, "slow");
        assert_eq!(error.kind(), BackendErrorKind::Throttled);
        assert_eq!(error.to_string(), "Test credentials: slow");
    }
}
