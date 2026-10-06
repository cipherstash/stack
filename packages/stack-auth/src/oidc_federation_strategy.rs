use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use cts_common::{Crn, CtsServiceDiscovery, ServiceDiscovery, WorkspaceId};

use crate::auto_refresh::AutoRefresh;
use crate::oidc_refresher::{JwtDigest, JwtRefresher, OidcFederation, OidcProvider};
use crate::token_store::{NoStore, TokenStore};
use crate::transport::{self, SharedTransport};
use crate::HttpTransport;
use crate::{ensure_trailing_slash, AuthError, AuthStrategy, SecretToken, ServiceToken, Token};

/// How many distinct provider JWTs a strategy keeps a CTS token for unless
/// [`OidcFederationStrategyBuilder::cache_capacity`] says otherwise.
pub(crate) const DEFAULT_CACHE_CAPACITY: usize = 1024;

/// An [`AuthStrategy`] that federates a third-party OIDC JWT (Clerk, Supabase,
/// Auth0, …) into a CipherStash CTS service token via `POST /api/authorise`.
///
/// # One token per user
///
/// Every call to [`get_token`](AuthStrategy::get_token) asks the
/// [`OidcProvider`] for the JWT of the caller the request is for, and returns
/// the CTS token cached **for that JWT**, exchanging it only when that JWT has
/// no cached, unexpired CTS token yet. A server that serves many users through
/// one long-lived client therefore gets each user their own token, provided
/// its provider returns the JWT of the user behind the current request. That
/// is what makes the strategy safe to share across requests: a value this
/// strategy helps encrypt under a lock context is bound to the identity in
/// *that caller's* JWT, not to whichever user federated first.
///
/// The cache is keyed on the whole JWT, never on claims read from it (the
/// client cannot verify a JWT, so a forged one naming another user's `sub`
/// must not reach that user's token), and holds at most
/// [`cache_capacity`](OidcFederationStrategyBuilder::cache_capacity) JWTs
/// (1024 by default), dropping the least recently used. Because
/// `/api/authorise` issues no CTS refresh token, renewing an expired CTS token
/// means federating the same JWT again; once the identity provider rotates a
/// user's JWT, the next request lands on a new cache entry and is exchanged
/// once more. The provider callback runs on every call, so it should be
/// cheap — provider SDKs cache their session locally and are fine to call per
/// request.
///
/// # Workspace binding
///
/// The strategy is bound to a workspace CRN at construction. The region is
/// derived from the CRN — there is no separate `region` argument — so a
/// caller can't accidentally point the strategy at one region while the
/// CRN says another, matching
/// [`AccessKeyStrategy`](crate::AccessKeyStrategy).
///
/// Every returned token is checked against the CRN's workspace — the
/// same post-auth verification `AccessKeyStrategy` performs — so a token CTS
/// minted for a different workspace (or one loaded from a poisoned shared
/// cache) is never handed back. Verification can fail in two ways:
///
/// - [`AuthError::WorkspaceMismatch`] — the JWT decoded cleanly but its
///   `workspace` claim doesn't match the CRN's workspace ID.
/// - [`AuthError::InvalidToken`] — the JWT is malformed or missing the
///   `workspace` claim entirely, so verification can't run.
///
/// # Persisting tokens
///
/// When constructed via [`OidcFederationStrategyBuilder::with_token_store`],
/// the strategy also persists tokens through an external [`TokenStore`] so
/// short-lived instances (e.g. one per Edge Function request) can share a
/// cache and skip re-federating on every cold start. A stored token is served
/// only to the JWT it was federated from (it carries that JWT's digest, see
/// [`Token::federated_from`]), so a store shared across users, or a cookie
/// that outlives a sign-out, never hands one user another's token: a
/// mismatch is a cache miss and a fresh exchange. The workspace check runs on
/// cached and store-loaded tokens too, not just freshly federated ones.
///
/// # Example
///
/// ```no_run
/// use stack_auth::{AuthError, OidcProviderFn, OidcFederationStrategy, SecretToken};
/// use cts_common::Crn;
///
/// let crn: Crn = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY".parse().unwrap();
/// let provider = OidcProviderFn::new(|| async {
///     // Real consumers return the JWT of the user behind the *current*
///     // request, from a provider SDK, a request context, or an FFI callback.
///     Ok::<_, AuthError>(SecretToken::new("header.payload.signature".to_string()))
/// });
/// let strategy = OidcFederationStrategy::new(crn, provider).unwrap();
/// ```
pub struct OidcFederationStrategy<P, S = NoStore> {
    provider: P,
    federation: Arc<OidcFederation>,
    store: Arc<S>,
    expected_workspace: WorkspaceId,
    cache: Mutex<Cache<Engine<S>>>,
}

/// The refresh engine for one provider JWT.
type Engine<S> = Arc<AutoRefresh<JwtRefresher, BoundStore<S>>>;

/// The per-JWT engines, bounded, least recently used out first.
///
/// Generic over the engine handle `T` (an [`Engine`] in the strategy) so the
/// policy can be tested without building one.
struct Cache<T> {
    capacity: usize,
    /// A logical clock, bumped on every lookup: the entry with the smallest
    /// stamp is the least recently used one.
    tick: u64,
    engines: HashMap<JwtDigest, Cached<T>>,
}

struct Cached<T> {
    engine: T,
    last_used: u64,
}

impl<T: Clone> Cache<T> {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            tick: 0,
            engines: HashMap::new(),
        }
    }

    /// The engine for `digest`, built with `build` if there is none yet.
    ///
    /// A new engine is retained only while there is room: at capacity, the
    /// least recently used entry makes way for it, and with a capacity of
    /// zero nothing is retained at all.
    fn engine_for(&mut self, digest: JwtDigest, build: impl FnOnce() -> T) -> T {
        self.tick += 1;
        if let Some(cached) = self.engines.get_mut(&digest) {
            cached.last_used = self.tick;
            return cached.engine.clone();
        }
        let engine = build();
        if self.capacity == 0 {
            return engine;
        }
        if self.engines.len() >= self.capacity {
            let victim = self
                .engines
                .iter()
                .min_by_key(|(_, cached)| cached.last_used)
                .map(|(digest, _)| *digest);
            if let Some(victim) = victim {
                let _ = self.engines.remove(&victim);
            }
        }
        let _ = self.engines.insert(
            digest,
            Cached {
                engine: engine.clone(),
                last_used: self.tick,
            },
        );
        engine
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    fn digest(jwt: &str) -> JwtDigest {
        JwtDigest::of(&SecretToken::new(jwt))
    }

    /// A cache over a unit handle: `()` is `Clone`, so the policy runs with
    /// no engine behind it.
    fn cache(capacity: usize) -> Cache<()> {
        Cache::new(capacity)
    }

    fn last_used(cache: &Cache<()>, jwt: &str) -> Option<u64> {
        cache.engines.get(&digest(jwt)).map(|c| c.last_used)
    }

    /// The clock advances by one per lookup, hit or miss, and a hit restamps
    /// its entry; that is what makes "least recently used" mean used, not
    /// inserted.
    #[test]
    fn every_lookup_advances_the_clock_and_a_hit_restamps_the_entry() {
        let mut cache = cache(8);
        let built = std::cell::Cell::new(0);
        let build = || built.set(built.get() + 1);

        cache.engine_for(digest("a"), build);
        cache.engine_for(digest("b"), build);
        assert_eq!(
            (last_used(&cache, "a"), last_used(&cache, "b")),
            (Some(1), Some(2))
        );

        cache.engine_for(digest("a"), build);
        assert_eq!(cache.tick, 3);
        assert_eq!(last_used(&cache, "a"), Some(3), "a hit restamps");
        assert_eq!(
            last_used(&cache, "b"),
            Some(2),
            "an untouched entry keeps its stamp"
        );
        assert_eq!(built.get(), 2, "a hit does not build");
    }

    /// At capacity the entry with the smallest stamp goes: with room for two,
    /// touching A before C arrives keeps A and evicts B.
    #[test]
    fn at_capacity_the_least_recently_used_entry_is_evicted() {
        let mut cache = cache(2);
        for jwt in ["a", "b", "a", "c"] {
            cache.engine_for(digest(jwt), || ());
        }
        assert_eq!(cache.engines.len(), 2);
        assert_eq!(last_used(&cache, "a"), Some(3));
        assert_eq!(
            last_used(&cache, "b"),
            None,
            "b was the least recently used"
        );
        assert_eq!(last_used(&cache, "c"), Some(4));
    }

    /// Capacity zero retains nothing and builds on every lookup.
    #[test]
    fn a_zero_capacity_cache_retains_nothing() {
        let mut cache = cache(0);
        let built = std::cell::Cell::new(0);
        for _ in 0..3 {
            cache.engine_for(digest("a"), || built.set(built.get() + 1));
        }
        assert_eq!(built.get(), 3);
        assert!(cache.engines.is_empty());
    }
}

/// A [`TokenStore`] view that serves a stored token only to the JWT it was
/// federated from.
///
/// The user's store is a single slot. Without this, an engine for user B
/// would load user A's token from it on cold start — the same bug the
/// per-JWT cache fixes, in its persisted form (a shared store, or a cookie
/// that outlives a sign-out). The engine for JWT `j` sees the store's token
/// only if it carries `j`'s digest; anything else, including a token stored
/// before tokens were stamped, is a miss, and the fresh exchange overwrites
/// it.
struct BoundStore<S> {
    inner: Arc<S>,
    /// The hex digest the token must carry, see [`Token::federated_from`].
    federated_from: String,
}

impl<S: TokenStore> TokenStore for BoundStore<S> {
    async fn load(&self) -> Option<Token> {
        let token = self.inner.load().await?;
        if token.federated_from() == Some(self.federated_from.as_str()) {
            Some(token)
        } else {
            tracing::debug!("stored token was federated from another JWT; ignoring it");
            None
        }
    }

    async fn save(&self, token: &Token) {
        self.inner.save(token).await
    }
}

impl<P: OidcProvider> OidcFederationStrategy<P> {
    /// Create a new `OidcFederationStrategy` for the given workspace CRN and
    /// OIDC provider.
    ///
    /// The auth endpoint is resolved automatically via service discovery
    /// using the region encoded in the CRN; the workspace ID is used to
    /// verify every federated token belongs to the right workspace.
    ///
    /// A CRN with a `service_name` component (e.g.
    /// `crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY:zerokms`) is accepted; the
    /// `service_name` is ignored. Only the region and workspace ID are
    /// load-bearing for this strategy.
    pub fn new(workspace_crn: Crn, oidc_provider: P) -> Result<Self, AuthError> {
        Self::builder(workspace_crn, oidc_provider).build()
    }

    /// Return a builder for configuring an `OidcFederationStrategy` before construction.
    pub fn builder(workspace_crn: Crn, oidc_provider: P) -> OidcFederationStrategyBuilder<P> {
        OidcFederationStrategyBuilder {
            workspace_crn,
            oidc_provider,
            base_url_override: None,
            token_store: NoStore,
            transport: None,
            cache_capacity: DEFAULT_CACHE_CAPACITY,
        }
    }
}

impl<P, S: TokenStore> OidcFederationStrategy<P, S> {
    /// The refresh engine for `jwt`: the cached one, or a new one over this
    /// strategy's federation endpoint and store, bound to `jwt`.
    fn engine_for(&self, digest: JwtDigest, jwt: SecretToken) -> Engine<S> {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        cache.engine_for(digest, || {
            Arc::new(AutoRefresh::with_store(
                JwtRefresher::new(jwt, digest, Arc::clone(&self.federation)),
                BoundStore {
                    inner: Arc::clone(&self.store),
                    federated_from: digest.to_hex(),
                },
            ))
        })
    }

    /// How many distinct JWTs currently have a cached engine.
    #[cfg(all(test, feature = "http"))]
    fn cached_jwts(&self) -> usize {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .engines
            .len()
    }
}

impl<P: OidcProvider, S: TokenStore> AuthStrategy for &OidcFederationStrategy<P, S> {
    async fn get_token(self) -> Result<ServiceToken, AuthError> {
        // Ask who this call is for before anything else: the JWT is the key
        // to the right cached token, and only its owner may receive it.
        let jwt = self.provider.fetch().await?;
        let digest = JwtDigest::of(&jwt);
        let engine = self.engine_for(digest, jwt);
        engine
            .get_token()
            .await?
            .verify_workspace(self.expected_workspace)
    }
}

/// Builder for [`OidcFederationStrategy`].
///
/// Created via [`OidcFederationStrategy::builder`].
pub struct OidcFederationStrategyBuilder<P, S = NoStore> {
    workspace_crn: Crn,
    oidc_provider: P,
    base_url_override: Option<url::Url>,
    token_store: S,
    transport: Option<SharedTransport>,
    cache_capacity: usize,
}

impl<P, S> OidcFederationStrategyBuilder<P, S> {
    /// Send this strategy's requests through `transport` instead of the
    /// bundled `reqwest` client.
    ///
    /// Without the `http` feature there is no bundled client, so this is
    /// required; with it, this is how a host with its own HTTP stack (or a
    /// test with a stub) takes over the wire without changing anything else
    /// about the strategy.
    pub fn transport(mut self, transport: impl HttpTransport) -> Self {
        self.transport = Some(transport::share(transport));
        self
    }
    /// Override the base URL resolved by service discovery.
    ///
    /// Takes precedence over both the `CS_CTS_HOST` environment variable and
    /// region-derived service discovery. Use this to point a single strategy
    /// instance at a specific CTS host — e.g. a self-hosted CTS, or a local
    /// mock auth server in development — without relying on the process-wide
    /// `CS_CTS_HOST`, which would also redirect any other CTS client (e.g. the
    /// `protect-ffi` encryption client) sharing the same process.
    pub fn base_url(mut self, url: url::Url) -> Self {
        self.base_url_override = Some(url);
        self
    }

    /// Apply an optional base-URL override supplied as a raw string.
    ///
    /// The string-typed convenience the language bindings (napi, wasm) call,
    /// so the "empty means absent, otherwise parse-or-reject" semantics live in
    /// one place rather than being re-derived per binding. An absent or empty
    /// string is a no-op — base-URL resolution falls back to `CS_CTS_HOST` /
    /// region service discovery (see [`build`](Self::build)); a non-empty but
    /// malformed string is rejected as [`AuthError::InvalidUrl`]. For an
    /// already-parsed URL, use [`base_url`](Self::base_url).
    pub fn maybe_base_url(self, base_url: Option<String>) -> Result<Self, AuthError> {
        match base_url {
            Some(s) if !s.is_empty() => Ok(self.base_url(s.parse::<url::Url>()?)),
            _ => Ok(self),
        }
    }

    /// How many distinct provider JWTs the strategy keeps a CTS token for
    /// (1024 unless set). When full, the least recently used JWT's token is
    /// dropped and that user is re-federated on their next call. Zero caches
    /// nothing: every call exchanges its JWT.
    ///
    /// Size it to the number of users a client serves concurrently within a
    /// CTS token's lifetime (about 15 minutes); each entry holds that user's
    /// JWT and CTS token.
    pub fn cache_capacity(mut self, capacity: usize) -> Self {
        self.cache_capacity = capacity;
        self
    }

    /// Wire an external [`TokenStore`] into the strategy.
    ///
    /// When a caller's JWT has no token cached in memory, the store is
    /// consulted before falling back to re-federating, and after every
    /// successful federation the new token is written back to the store. Use
    /// this from short-lived strategy instances (Edge Functions, Workers) to
    /// share a service-token cache across processes — e.g. an HTTP-only
    /// cookie.
    ///
    /// The store holds one token, and the strategy serves it only to the JWT
    /// it was federated from (see [`Token::federated_from`]): a store shared
    /// by several users is safe but caches only the last of them, and a
    /// cookie left over from a previous sign-in on the same browser is a cache
    /// miss, not that user's token.
    ///
    /// Returns a new builder with the store type erased into the chain — see
    /// [`InMemoryTokenStore`](crate::InMemoryTokenStore) and
    /// [`TokenStoreFn`](crate::TokenStoreFn) for ready-made implementations.
    pub fn with_token_store<T: TokenStore>(self, store: T) -> OidcFederationStrategyBuilder<P, T> {
        OidcFederationStrategyBuilder {
            workspace_crn: self.workspace_crn,
            oidc_provider: self.oidc_provider,
            base_url_override: self.base_url_override,
            token_store: store,
            transport: self.transport,
            cache_capacity: self.cache_capacity,
        }
    }
}

impl<P: OidcProvider, S: TokenStore> OidcFederationStrategyBuilder<P, S> {
    /// Build the [`OidcFederationStrategy`].
    ///
    /// Resolves the base URL in priority order: an explicit [`base_url`]
    /// override, then the `CS_CTS_HOST` environment variable, then service
    /// discovery using the CRN's region.
    ///
    /// [`base_url`]: Self::base_url
    pub fn build(self) -> Result<OidcFederationStrategy<P, S>, AuthError> {
        let expected_workspace = self.workspace_crn.workspace_id;
        let region = self.workspace_crn.region;
        let base_url = match self.base_url_override {
            Some(url) => url,
            None => {
                crate::cts_base_url_from_env()?.unwrap_or(CtsServiceDiscovery::endpoint(region)?)
            }
        };
        let federation = OidcFederation::new(
            expected_workspace,
            ensure_trailing_slash(base_url),
            transport::resolve(self.transport)?,
        );
        Ok(OidcFederationStrategy {
            provider: self.oidc_provider,
            federation: Arc::new(federation),
            store: Arc::new(self.token_store),
            expected_workspace,
            cache: Mutex::new(Cache::new(self.cache_capacity)),
        })
    }
}

#[cfg(test)]
#[cfg(feature = "http")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use mocktail::prelude::*;

    use super::*;
    use crate::oidc_refresher::OidcProviderFn;
    use crate::test_support::{crn_with_workspace, jwt_for_principal, jwt_with_workspace};
    use crate::{InMemoryTokenStore, SecretToken, Token, TokenStore};

    const WS: &str = "ZVATKW3VHMFG27DY";

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_secs()
    }

    /// A mock CTS that federates any OIDC token into a CTS token carrying the
    /// given `workspace` claim.
    async fn start_mock_server_returning_jwt(workspace: &str) -> MockServer {
        let mut mocks = MockSet::new();
        let jwt = jwt_with_workspace(workspace);
        let expiry = now() + 3600;
        mocks.mock(move |when, then| {
            when.post().path("/api/authorise");
            then.json(serde_json::json!({ "accessToken": jwt, "expiry": expiry }));
        });
        let server =
            MockServer::new_http("oidc-federation-strategy-workspace-test").with_mocks(mocks);
        server.start().await.expect("mock server start");
        server
    }

    /// An empty mock CTS; register exchanges on it with [`accept_exchange`].
    async fn start_mock_server() -> MockServer {
        let server = MockServer::new_http("oidc-federation-strategy-per-user-test");
        server.start().await.expect("mock server start");
        server
    }

    /// Accept the exchange of exactly `jwt`, answering with a CTS token for
    /// `principal` in [`WS`], valid for an hour.
    fn accept_exchange(server: &MockServer, jwt: &str, principal: &str) {
        let body = serde_json::json!({ "oidcToken": jwt, "workspaceId": WS });
        let cts = jwt_for_principal(WS, principal);
        let expiry = now() + 3600;
        server.mocks().mock(move |when, then| {
            when.post().path("/api/authorise").json(body);
            then.json(serde_json::json!({ "accessToken": cts, "expiry": expiry }));
        });
    }

    /// Refuse every exchange from now on, so a call that succeeds proves it
    /// was served from the cache and a call that fails proves it tried to
    /// exchange.
    fn refuse_exchanges(server: &MockServer) {
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/api/authorise");
            then.internal_server_error()
                .json(serde_json::json!({"error": "no exchange expected"}));
        });
    }

    fn provider() -> OidcProviderFn<impl Fn() -> std::future::Ready<Result<SecretToken, AuthError>>>
    {
        OidcProviderFn::new(|| {
            std::future::ready(Ok(SecretToken::new("header.payload.signature".to_string())))
        })
    }

    /// A provider standing in for "the user behind the current request": it
    /// returns whatever JWT `current` holds and counts how often it is asked.
    fn switchable_provider() -> (Arc<Mutex<String>>, Arc<AtomicUsize>, impl OidcProvider) {
        let current = Arc::new(Mutex::new(String::from("jwt-a")));
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = {
            let current = Arc::clone(&current);
            let calls = Arc::clone(&calls);
            OidcProviderFn::new(move || {
                let _ = calls.fetch_add(1, Ordering::SeqCst);
                let jwt = current
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                std::future::ready(Ok(SecretToken::new(jwt)))
            })
        };
        (current, calls, provider)
    }

    fn act_as(current: &Mutex<String>, jwt: &str) {
        *current.lock().unwrap_or_else(PoisonError::into_inner) = jwt.to_string();
    }

    fn strategy_on<P: OidcProvider>(
        server: &MockServer,
        provider: P,
    ) -> OidcFederationStrategyBuilder<P> {
        OidcFederationStrategy::builder(crn_with_workspace(WS), provider).base_url(server.url(""))
    }

    /// A stored CTS token for [`WS`], as a strategy would have persisted it
    /// after federating `jwt` — or unstamped, as a store written before tokens
    /// were stamped holds it.
    fn stored_token(federated_from: Option<&str>) -> Token {
        Token {
            access_token: SecretToken::new(jwt_for_principal(WS, "CS|stored")),
            token_type: "Bearer".to_string(),
            expires_at: now() + 3600,
            refresh_token: None,
            region: None,
            client_id: None,
            device_instance_id: None,
            federated_from: federated_from
                .map(|jwt| JwtDigest::of(&SecretToken::new(jwt)).to_hex()),
        }
    }

    fn subject(token: &ServiceToken) -> String {
        token
            .subject()
            .expect("CTS token has a subject")
            .to_string()
    }

    /// `maybe_base_url` is the string-typed override seam the language bindings
    /// rely on; pin its empty/absent/valid/malformed semantics here so the napi
    /// and wasm crates don't each re-test (and risk re-deriving) them.
    mod maybe_base_url {
        use super::*;

        #[test]
        fn absent_is_a_noop() {
            let b = OidcFederationStrategy::builder(crn_with_workspace(WS), provider())
                .maybe_base_url(None)
                .unwrap();
            assert!(b.base_url_override.is_none());
        }

        #[test]
        fn empty_string_is_a_noop() {
            let b = OidcFederationStrategy::builder(crn_with_workspace(WS), provider())
                .maybe_base_url(Some(String::new()))
                .unwrap();
            assert!(b.base_url_override.is_none());
        }

        #[test]
        fn valid_url_sets_the_override() {
            let b = OidcFederationStrategy::builder(crn_with_workspace(WS), provider())
                .maybe_base_url(Some("https://cts.example.com".to_string()))
                .unwrap();
            assert_eq!(
                b.base_url_override.as_ref().map(url::Url::as_str),
                Some("https://cts.example.com/")
            );
        }

        #[test]
        fn malformed_url_is_invalid_url() {
            // The builder isn't `Debug`, so match on the result rather than
            // `unwrap_err()` (which would require `T: Debug`).
            match OidcFederationStrategy::builder(crn_with_workspace(WS), provider())
                .maybe_base_url(Some("not a url".to_string()))
            {
                Err(AuthError::InvalidUrl(_)) => {}
                Ok(_) => panic!("expected Err(InvalidUrl), got Ok"),
                Err(other) => panic!("expected InvalidUrl, got: {other:?}"),
            }
        }
    }

    /// The number the docs quote. A builder that changes the default must
    /// change the docs on `cache_capacity` and the type too.
    #[test]
    fn the_default_cache_capacity_is_the_documented_one() {
        assert_eq!(DEFAULT_CACHE_CAPACITY, 1024);
        let b = OidcFederationStrategy::builder(crn_with_workspace(WS), provider());
        assert_eq!(b.cache_capacity, DEFAULT_CACHE_CAPACITY);
        assert_eq!(
            b.cache_capacity(7)
                .with_token_store(crate::NoStore)
                .cache_capacity,
            7,
            "the capacity survives the store type change"
        );
    }

    /// Precedence: an explicit `base_url` override (the one `maybe_base_url`
    /// sets) wins over the `CS_CTS_HOST` environment variable. `build()`
    /// resolves the host in priority order override → `CS_CTS_HOST` →
    /// discovery, so with `CS_CTS_HOST` pointed at a dead address the strategy
    /// must still federate against the override's mock — proving the env var
    /// was not consulted.
    ///
    /// `CS_CTS_HOST` is read inside `build()` (not `get_token`), so the env
    /// override is scoped to just that synchronous call via `temp_env`; the
    /// async federation runs with the environment already restored. No other
    /// test in this crate reads `CS_CTS_HOST` (every strategy test pins
    /// `base_url`), so this can't perturb a concurrent test.
    #[tokio::test]
    async fn base_url_override_takes_precedence_over_cs_cts_host() {
        let server = start_mock_server_returning_jwt(WS).await;

        // A routable-but-dead host: if `CS_CTS_HOST` were consulted, federation
        // would target this and fail rather than hitting the mock.
        let strategy = temp_env::with_var("CS_CTS_HOST", Some("http://127.0.0.1:1/"), || {
            OidcFederationStrategy::builder(crn_with_workspace(WS), provider())
                .maybe_base_url(Some(server.url("").to_string()))
                .expect("override URL parses")
                .build()
                .expect("builder")
        });

        let token = (&strategy)
            .get_token()
            .await
            .expect("override must win: federation should hit the mock, not CS_CTS_HOST");
        assert_eq!(
            token.workspace_id().expect("workspace_id").as_str(),
            WS,
            "token should come from the override's mock server",
        );
    }

    /// Happy path — the federated token's `workspace` claim matches the
    /// configured workspace: `get_token()` returns the token cleanly.
    #[tokio::test]
    async fn returns_token_when_workspace_matches() {
        let server = start_mock_server_returning_jwt(WS).await;

        let strategy = strategy_on(&server, provider()).build().expect("builder");

        let token = (&strategy).get_token().await.expect("get_token");
        assert_eq!(
            token.workspace_id().expect("workspace_id").as_str(),
            WS,
            "happy-path token should carry the expected workspace",
        );
    }

    /// A CRN carrying a `service_name` component is accepted; the
    /// `service_name` is ignored, exactly as for
    /// [`AccessKeyStrategy`](crate::AccessKeyStrategy). Pinned as a test —
    /// matching `access_key_strategy::accepts_crn_with_service_name` — so a
    /// future contributor doesn't tighten the constructor into rejecting these
    /// CRNs without realising the docstring already promises acceptance.
    #[tokio::test]
    async fn accepts_crn_with_service_name() {
        let server = start_mock_server_returning_jwt(WS).await;
        let crn: Crn = format!("crn:ap-southeast-2.aws:{WS}:zerokms")
            .parse()
            .expect("CRN with service_name parses");

        let strategy = OidcFederationStrategy::builder(crn, provider())
            .base_url(server.url(""))
            .build()
            .expect("CRN with service_name should construct a strategy");

        let token = (&strategy).get_token().await.expect("get_token");
        assert_eq!(
            token.workspace_id().expect("workspace_id").as_str(),
            WS,
            "service_name is ignored — verification still uses the workspace ID",
        );
    }

    /// Mismatch — CTS federates the OIDC token into a CTS token for a
    /// *different* workspace than the strategy was configured for. This is the
    /// security-critical case: the OIDC provider could be authenticated for a
    /// workspace the caller didn't intend. `get_token()` must return
    /// `WorkspaceMismatch`, not the token.
    #[tokio::test]
    async fn errors_when_token_workspace_differs() {
        const TOKEN_WS: &str = "AAAAAAAAAAAAAAAA";
        let server = start_mock_server_returning_jwt(TOKEN_WS).await;

        let strategy = strategy_on(&server, provider()).build().expect("builder");

        let err = (&strategy)
            .get_token()
            .await
            .expect_err("expected mismatch");
        match err {
            AuthError::WorkspaceMismatch(crate::error::WorkspaceMismatch {
                expected_workspace,
                token_workspace,
            }) => {
                assert_eq!(expected_workspace.as_str(), WS);
                assert_eq!(token_workspace.as_str(), TOKEN_WS);
            }
            other => panic!("expected WorkspaceMismatch, got {other:?}"),
        }
    }

    /// A malformed CTS token (not a JWT) can't be decoded, so verification
    /// can't run — `get_token()` surfaces `InvalidToken` rather than handing
    /// back an unverifiable token.
    #[tokio::test]
    async fn errors_with_invalid_token_when_jwt_malformed() {
        let server = start_mock_server().await;
        let expiry = now() + 3600;
        server.mocks().mock(move |when, then| {
            when.post().path("/api/authorise");
            then.json(serde_json::json!({ "accessToken": "not-a-jwt", "expiry": expiry }));
        });

        let strategy = strategy_on(&server, provider()).build().expect("builder");

        let err = (&strategy)
            .get_token()
            .await
            .expect_err("expected invalid-token error");
        assert!(
            matches!(err, AuthError::InvalidToken(_)),
            "expected InvalidToken, got {err:?}",
        );
    }

    /// Regression guard — the workspace check runs on *every* `get_token()`
    /// call, not only the one that triggers initial federation. A future
    /// optimisation that cached the "verified" verdict would let a mismatched
    /// token slide through on the second call.
    #[tokio::test]
    async fn errors_on_each_subsequent_get_token_call() {
        const TOKEN_WS: &str = "AAAAAAAAAAAAAAAA";
        let server = start_mock_server_returning_jwt(TOKEN_WS).await;

        let strategy = strategy_on(&server, provider()).build().expect("builder");

        for call in 1..=2 {
            let err = match (&strategy).get_token().await {
                Ok(_) => panic!("call {call}: expected Err, got Ok"),
                Err(e) => e,
            };
            assert!(
                matches!(err, AuthError::WorkspaceMismatch { .. }),
                "call {call}: expected WorkspaceMismatch, got {err:?}",
            );
        }
    }

    // ---- One token per user (CIP-4301 / #1045) ----

    /// The bug, as a test. User A federates. Every exchange is then refused,
    /// so the only token the strategy *could* hand out is A's. User B's call
    /// must fail — it must try to exchange B's JWT — rather than succeed with
    /// A's token, which is what one cached token per strategy did.
    #[tokio::test]
    async fn a_second_user_is_never_served_the_first_users_token() {
        let server = start_mock_server().await;
        accept_exchange(&server, "jwt-a", "CS|a");
        let (current, _, provider) = switchable_provider();
        let strategy = strategy_on(&server, provider).build().expect("builder");

        act_as(&current, "jwt-a");
        let a = (&strategy).get_token().await.expect("A federates");
        assert_eq!(subject(&a), "CS|a");

        refuse_exchanges(&server);
        act_as(&current, "jwt-b");
        let err = (&strategy)
            .get_token()
            .await
            .expect_err("B must be exchanged, not served A's token");
        assert!(
            matches!(err, AuthError::Server(_)),
            "B's call should have reached the (refusing) exchange, got {err:?}"
        );
    }

    /// Two users through one strategy, interleaved: each receives the token
    /// federated from their own JWT, the provider is asked on every call, and
    /// once both have a token neither is exchanged again.
    #[tokio::test]
    async fn each_jwt_gets_its_own_token_and_the_provider_is_asked_every_time() {
        let server = start_mock_server().await;
        accept_exchange(&server, "jwt-a", "CS|a");
        accept_exchange(&server, "jwt-b", "CS|b");
        let (current, calls, provider) = switchable_provider();
        let strategy = strategy_on(&server, provider).build().expect("builder");

        act_as(&current, "jwt-a");
        assert_eq!(subject(&(&strategy).get_token().await.expect("A")), "CS|a");
        act_as(&current, "jwt-b");
        assert_eq!(subject(&(&strategy).get_token().await.expect("B")), "CS|b");
        act_as(&current, "jwt-a");
        assert_eq!(
            subject(&(&strategy).get_token().await.expect("A again")),
            "CS|a"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "the provider is asked on every call"
        );
        assert_eq!(strategy.cached_jwts(), 2);

        // Both are cached now: nothing below may exchange.
        refuse_exchanges(&server);
        act_as(&current, "jwt-b");
        assert_eq!(
            subject(&(&strategy).get_token().await.expect("B cached")),
            "CS|b"
        );
        act_as(&current, "jwt-a");
        assert_eq!(
            subject(&(&strategy).get_token().await.expect("A cached")),
            "CS|a"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }

    /// A provider that cannot say who the caller is fails the call before any
    /// exchange is attempted: its own error comes back, not the exchange's.
    #[tokio::test]
    async fn a_provider_failure_is_returned_before_any_exchange() {
        let server = start_mock_server().await;
        refuse_exchanges(&server);
        let provider = OidcProviderFn::new(|| async {
            Err::<SecretToken, _>(AuthError::Custom(crate::error::CustomError(
                "no session".to_string(),
            )))
        });
        let strategy = strategy_on(&server, provider).build().expect("builder");

        let err = (&strategy).get_token().await.expect_err("provider failed");
        assert!(
            matches!(err, AuthError::Custom(ref e) if e.to_string().contains("no session")),
            "expected the provider's own error, got {err:?}"
        );
    }

    /// The cache is bounded, and the JWT that goes is the least recently
    /// *used* one, not the oldest: with room for two, touching A before C
    /// arrives keeps A and evicts B.
    #[tokio::test]
    async fn the_cache_evicts_the_least_recently_used_jwt() {
        let server = start_mock_server().await;
        accept_exchange(&server, "jwt-a", "CS|a");
        accept_exchange(&server, "jwt-b", "CS|b");
        accept_exchange(&server, "jwt-c", "CS|c");
        let (current, _, provider) = switchable_provider();
        let strategy = strategy_on(&server, provider)
            .cache_capacity(2)
            .build()
            .expect("builder");

        for jwt in ["jwt-a", "jwt-b", "jwt-a", "jwt-c"] {
            act_as(&current, jwt);
            let _ = (&strategy).get_token().await.expect(jwt);
        }
        assert_eq!(strategy.cached_jwts(), 2, "never more than the capacity");

        refuse_exchanges(&server);
        act_as(&current, "jwt-a");
        assert_eq!(
            subject(&(&strategy).get_token().await.expect("A kept")),
            "CS|a"
        );
        act_as(&current, "jwt-c");
        assert_eq!(
            subject(&(&strategy).get_token().await.expect("C kept")),
            "CS|c"
        );
        act_as(&current, "jwt-b");
        let err = (&strategy)
            .get_token()
            .await
            .expect_err("B was evicted and must be exchanged again");
        assert!(matches!(err, AuthError::Server(_)), "{err:?}");
        assert_eq!(
            strategy.cached_jwts(),
            2,
            "the failed exchange's engine took B's place"
        );
    }

    /// Capacity zero retains nothing: the same JWT is exchanged on every
    /// call.
    #[tokio::test]
    async fn a_zero_capacity_cache_exchanges_on_every_call() {
        let server = start_mock_server().await;
        accept_exchange(&server, "jwt-a", "CS|a");
        let (_, _, provider) = switchable_provider();
        let strategy = strategy_on(&server, provider)
            .cache_capacity(0)
            .build()
            .expect("builder");

        assert_eq!(subject(&(&strategy).get_token().await.expect("A")), "CS|a");
        assert_eq!(strategy.cached_jwts(), 0);

        refuse_exchanges(&server);
        let err = (&strategy)
            .get_token()
            .await
            .expect_err("nothing is cached, so this must exchange");
        assert!(matches!(err, AuthError::Server(_)), "{err:?}");
    }

    // ---- The store is bound to the JWT ----

    /// A federated token is persisted stamped with its JWT's digest — the
    /// mark a later cold start needs to know whose token it is.
    #[tokio::test]
    async fn a_federated_token_is_stored_stamped_with_its_jwt_digest() {
        let server = start_mock_server().await;
        accept_exchange(&server, "header.payload.signature", "CS|a");
        let store = Arc::new(InMemoryTokenStore::new());
        let strategy = strategy_on(&server, provider())
            .with_token_store(Arc::clone(&store))
            .build()
            .expect("builder");

        let _ = (&strategy).get_token().await.expect("federates");

        let saved = store.load().await.expect("store holds the token");
        assert_eq!(
            subject(&ServiceToken::new(saved.access_token().clone())),
            "CS|a"
        );
        // `printf '%s' header.payload.signature | shasum -a 256`
        assert_eq!(
            saved.federated_from(),
            Some("256d04db4e5e4ac308751ed0885b722b758630567c53a7125ed9fbd068e5c3f6")
        );
    }

    /// A stored token is served to the JWT it was federated from, without an
    /// exchange — the cold-start cache the store exists for.
    #[tokio::test]
    async fn a_stored_token_is_served_to_the_jwt_it_was_federated_from() {
        let server = start_mock_server().await;
        refuse_exchanges(&server);
        let store = Arc::new(InMemoryTokenStore::new());
        store.save(&stored_token(Some("jwt-a"))).await;
        let (current, calls, provider) = switchable_provider();
        let strategy = strategy_on(&server, provider)
            .with_token_store(Arc::clone(&store))
            .build()
            .expect("builder");

        act_as(&current, "jwt-a");
        let token = (&strategy)
            .get_token()
            .await
            .expect("served from the store without an exchange");
        assert_eq!(subject(&token), "CS|stored");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the provider is still asked who is calling"
        );
    }

    /// The persisted form of the bug: a store (a shared Redis slot, a cookie
    /// left over from a previous sign-in on this browser) holding a token
    /// federated from *another* JWT. The caller must be exchanged, never
    /// handed that token.
    #[tokio::test]
    async fn a_stored_token_from_another_jwt_is_a_cache_miss() {
        let server = start_mock_server().await;
        accept_exchange(&server, "jwt-b", "CS|b");
        let store = Arc::new(InMemoryTokenStore::new());
        store.save(&stored_token(Some("jwt-a"))).await;
        let (current, _, provider) = switchable_provider();
        let strategy = strategy_on(&server, provider)
            .with_token_store(Arc::clone(&store))
            .build()
            .expect("builder");

        act_as(&current, "jwt-b");
        let token = (&strategy).get_token().await.expect("B exchanges");
        assert_eq!(subject(&token), "CS|b", "B's own token, not the stored one");

        // ... and B's token has replaced A's in the single-slot store.
        let saved = store.load().await.expect("store holds a token");
        assert_eq!(
            saved.federated_from(),
            Some(JwtDigest::of(&SecretToken::new("jwt-b")).to_hex().as_str())
        );
    }

    /// A token stored before tokens were stamped carries no digest, so nothing
    /// says whose it is: it is a miss, and the fresh token overwrites it.
    #[tokio::test]
    async fn an_unstamped_stored_token_is_a_cache_miss() {
        let server = start_mock_server().await;
        accept_exchange(&server, "jwt-a", "CS|a");
        let store = Arc::new(InMemoryTokenStore::new());
        store.save(&stored_token(None)).await;
        let (current, _, provider) = switchable_provider();
        let strategy = strategy_on(&server, provider)
            .with_token_store(Arc::clone(&store))
            .build()
            .expect("builder");

        act_as(&current, "jwt-a");
        let token = (&strategy).get_token().await.expect("A exchanges");
        assert_eq!(subject(&token), "CS|a");
        assert!(store
            .load()
            .await
            .expect("stored")
            .federated_from()
            .is_some());
    }

    /// An expired stored token for this JWT triggers a fresh exchange of the
    /// same JWT, as it would in memory.
    #[tokio::test]
    async fn an_expired_stored_token_is_re_federated() {
        let server = start_mock_server().await;
        accept_exchange(&server, "jwt-a", "CS|fresh");
        let store = Arc::new(InMemoryTokenStore::new());
        let mut stale = stored_token(Some("jwt-a"));
        stale.expires_at = 0;
        store.save(&stale).await;
        let (current, _, provider) = switchable_provider();
        let strategy = strategy_on(&server, provider)
            .with_token_store(Arc::clone(&store))
            .build()
            .expect("builder");

        act_as(&current, "jwt-a");
        let token = (&strategy).get_token().await.expect("re-federates");
        assert_eq!(subject(&token), "CS|fresh");
    }

    /// A pre-populated [`TokenStore`] returning a token for a *different*
    /// workspace must still be rejected by the strategy wrapper — the same
    /// poisoned-shared-cache interaction `AccessKeyStrategy` guards against.
    /// The stored token is stamped as this caller's, so it is served; a
    /// 500-returning mock fails the test loudly if the strategy ever
    /// re-federates instead of trusting (and rejecting) the stored token.
    #[tokio::test]
    async fn rejects_stored_token_for_different_workspace() {
        const TOKEN_WS: &str = "AAAAAAAAAAAAAAAA";
        let server = start_mock_server().await;
        refuse_exchanges(&server);

        let mut stored = stored_token(Some("header.payload.signature"));
        stored.access_token = SecretToken::new(jwt_with_workspace(TOKEN_WS));
        let store = Arc::new(InMemoryTokenStore::new());
        store.save(&stored).await;

        let strategy = strategy_on(&server, provider())
            .with_token_store(Arc::clone(&store))
            .build()
            .expect("builder");

        let err = (&strategy)
            .get_token()
            .await
            .expect_err("expected mismatch from stored token");
        assert!(
            matches!(err, AuthError::WorkspaceMismatch { .. }),
            "expected WorkspaceMismatch, got {err:?}",
        );
    }
}
