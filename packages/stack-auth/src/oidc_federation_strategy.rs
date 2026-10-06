mod cache;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use cts_common::{Crn, CtsServiceDiscovery, ServiceDiscovery, WorkspaceId};

use crate::auto_refresh::{AutoRefresh, StickyDenial};
use crate::clock::{system_clock, SharedClock};
use crate::oidc_refresher::{JwtDigest, JwtRefresher, OidcFederation, OidcProvider};
use crate::token_store::{NoStore, TokenStore};
use crate::transport::{self, SharedTransport};
use crate::HttpTransport;
use crate::{ensure_trailing_slash, AuthError, AuthStrategy, SecretToken, ServiceToken, Token};
use cache::JwtCache;

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
/// Whether the provider *can* name the caller is the host's affair, and it
/// decides whether one strategy may be shared. In Rust the provider reads the
/// caller from whatever carries it (a task-local, a request extension), and
/// the Go binding passes the provider the `ctx` of the `Token` call, so one
/// strategy serves every user there. The Node binding cannot: it runs
/// `getJwt` through a napi `ThreadsafeFunction`, outside the async context
/// (`AsyncLocalStorage`) of the `getToken()` caller, so a callback that reads
/// the request from there finds no request, or the one the strategy was
/// created in, and every caller is exchanged as that user. Node builds one
/// strategy per request or per user and captures the request in the closure;
/// the per-JWT cache is defence in depth there, not a licence to share.
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
    engines: Mutex<Engines<S>>,
    /// The last account-level refusal (a usage limit, an unprovisioned org),
    /// remembered for the strategy as a whole.
    ///
    /// Each engine remembers refusals for its own JWT, but an engine whose
    /// first exchange is refused is not kept (see
    /// [`forget_failed`](Self::forget_failed)), and a refusal of the
    /// *account* is the same answer for every JWT. Without this, a client
    /// over its usage limit would re-ask CTS once per request per user, the
    /// storm the engine's own denial exists to stop.
    denial: Mutex<Option<StickyDenial>>,
    clock: SharedClock,
}

/// The refresh engine for one provider JWT: the same [`AutoRefresh`] every
/// strategy uses, over a refresher that federates that one JWT and a store
/// view bound to it.
type RefreshEngine<S> = Arc<AutoRefresh<JwtRefresher, BoundStore<S>>>;

/// The strategy's engines, in two tiers.
///
/// An engine earns its place in the bounded cache by holding a token. Until
/// its first exchange has succeeded it waits in `pending`, where concurrent
/// callers for the same JWT still find it (and so share one exchange), but
/// where it cannot evict a user who holds a token. A caller presenting JWTs
/// CTS refuses therefore churns nothing: each refused engine leaves
/// `pending` with its failure, and `pending` itself is bounded by the number
/// of calls in flight — a call that is cancelled mid-exchange takes its
/// entry with it (see [`InFlight`]).
struct Engines<S> {
    cache: JwtCache<RefreshEngine<S>>,
    pending: HashMap<JwtDigest, RefreshEngine<S>>,
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
    /// The digest a stored token must carry, see [`Token::federated_from`].
    digest: JwtDigest,
}

impl<S: TokenStore> TokenStore for BoundStore<S> {
    async fn load(&self) -> Option<Token> {
        let token = self.inner.load().await?;
        if token
            .federated_from()
            .is_some_and(|hex| self.digest.matches_hex(hex))
        {
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
            clock: system_clock(),
        }
    }
}

impl<P, S: TokenStore> OidcFederationStrategy<P, S> {
    /// The refresh engine for `jwt`: the cached one, or a new one over this
    /// strategy's federation endpoint and store, bound to `jwt`.
    ///
    /// A new engine is created only if no account-level refusal is fresh:
    /// that refusal is the answer every JWT would get, so it is returned
    /// without an exchange. A cached engine is handed back regardless — it may
    /// hold a token that is still usable, which a settled refusal does not
    /// invalidate (the same rule [`AutoRefresh`] applies to its own).
    fn engine_for(&self, jwt: SecretToken) -> Result<RefreshEngine<S>, AuthError> {
        let digest = JwtDigest::of(&jwt);
        let mut engines = self.engines.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(engine) = engines.cache.get(digest) {
            return Ok(engine);
        }
        if let Some(engine) = engines.pending.get(&digest) {
            return Ok(Arc::clone(engine));
        }
        // A new engine is about to make its first exchange: a refusal of the
        // account answers it without one.
        if let Some(err) = self.fresh_denial() {
            return Err(err);
        }
        let engine = Arc::new(AutoRefresh::with_store(
            JwtRefresher::new(jwt, Arc::clone(&self.federation)),
            BoundStore {
                inner: Arc::clone(&self.store),
                digest,
            },
        ));
        let _ = engines.pending.insert(digest, Arc::clone(&engine));
        Ok(engine)
    }

    /// Record how `engine`'s `get_token` went.
    ///
    /// Success puts the engine in the cache: it holds a token and may take a
    /// slot. (Whether or not it was still pending — a sibling call for the
    /// same JWT may have been cancelled and taken the pending entry with it.)
    /// Failure drops it from wherever it is — a pending engine never earned
    /// a slot, and a cached one whose renewal left it with no usable token
    /// has nothing left to hold one with — unless the entry has since been
    /// replaced. A refusal of the account rather than the credential is also
    /// remembered for every JWT.
    fn settle(&self, engine: &RefreshEngine<S>, outcome: Result<(), &AuthError>) {
        let digest = engine.refresher().digest();
        let mut engines = self.engines.lock().unwrap_or_else(PoisonError::into_inner);
        if engines
            .pending
            .get(&digest)
            .is_some_and(|pending| Arc::ptr_eq(pending, engine))
        {
            let _ = engines.pending.remove(&digest);
        }
        match outcome {
            Ok(()) => engines.cache.insert(digest, Arc::clone(engine)),
            Err(err) => {
                engines
                    .cache
                    .remove_if(digest, |cached| Arc::ptr_eq(cached, engine));
                if err.is_account_refusal() {
                    let now = self.clock.now_unix_secs();
                    *self.denial.lock().unwrap_or_else(PoisonError::into_inner) =
                        Some(StickyDenial::new(err, now));
                }
            }
        }
    }

    /// The remembered account-level refusal, if it is still within its
    /// window; a stale one is discarded so the next exchange asks CTS again.
    fn fresh_denial(&self) -> Option<AuthError> {
        let now = self.clock.now_unix_secs();
        let mut denial = self.denial.lock().unwrap_or_else(PoisonError::into_inner);
        match &*denial {
            Some(recorded) if !recorded.is_stale(now) => Some(recorded.to_error()),
            Some(_) => {
                *denial = None;
                None
            }
            None => None,
        }
    }

    /// How many distinct JWTs currently hold a token in the cache.
    #[cfg(all(test, feature = "http"))]
    fn cached_jwts(&self) -> usize {
        self.engines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .cache
            .len()
    }

    /// How many engines are waiting on their first exchange.
    #[cfg(all(test, feature = "http"))]
    fn pending_jwts(&self) -> usize {
        self.engines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pending
            .len()
    }
}

/// One call's claim on an engine, from [`engine_for`](OidcFederationStrategy::engine_for)
/// until it is [settled](Self::settle).
///
/// A `get_token` future can be dropped mid-exchange — a request timeout, a
/// `select!`, a client that went away — and then nothing after the `.await`
/// runs. Without this guard the engine would stay in `pending` for ever,
/// holding the caller's JWT, and a rotated JWT is never presented again to
/// promote or replace it. Dropping an unsettled guard removes the pending
/// entry if it is still this engine.
struct InFlight<'a, P, S: TokenStore> {
    strategy: &'a OidcFederationStrategy<P, S>,
    engine: RefreshEngine<S>,
    settled: bool,
}

impl<P, S: TokenStore> InFlight<'_, P, S> {
    fn settle(mut self, outcome: Result<(), &AuthError>) {
        self.settled = true;
        self.strategy.settle(&self.engine, outcome);
    }
}

impl<P, S: TokenStore> Drop for InFlight<'_, P, S> {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let digest = self.engine.refresher().digest();
        let mut engines = self
            .strategy
            .engines
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if engines
            .pending
            .get(&digest)
            .is_some_and(|pending| Arc::ptr_eq(pending, &self.engine))
        {
            let _ = engines.pending.remove(&digest);
        }
    }
}

impl<P: OidcProvider, S: TokenStore> AuthStrategy for &OidcFederationStrategy<P, S> {
    async fn get_token(self) -> Result<ServiceToken, AuthError> {
        // Ask who this call is for before anything else: the JWT is the key
        // to the right cached token, and only its owner may receive it.
        let jwt = self.provider.fetch().await?;
        let engine = self.engine_for(jwt)?;
        let in_flight = InFlight {
            strategy: self,
            engine: Arc::clone(&engine),
            settled: false,
        };
        let token = match engine.get_token().await {
            Ok(token) => {
                in_flight.settle(Ok(()));
                token
            }
            Err(err) => {
                let err = AuthError::from(err);
                in_flight.settle(Err(&err));
                return Err(err);
            }
        };
        token.verify_workspace(self.expected_workspace)
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
    clock: SharedClock,
}

impl<P, S> OidcFederationStrategyBuilder<P, S> {
    /// Read "now" from `clock` instead of the wall clock, so a test can age
    /// the remembered account refusal deterministically.
    #[cfg(all(test, feature = "http"))]
    fn clock(mut self, clock: SharedClock) -> Self {
        self.clock = clock;
        self
    }

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
    /// nothing: every call exchanges its JWT. A JWT whose exchange CTS refuses
    /// takes no slot.
    ///
    /// Size it to the number of users a client serves concurrently within a
    /// CTS token's lifetime (about 15 minutes); each entry holds that user's
    /// JWT and CTS token. The language bindings build with the default.
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
            clock: self.clock,
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
            engines: Mutex::new(Engines {
                cache: JwtCache::new(self.cache_capacity),
                pending: HashMap::new(),
            }),
            denial: Mutex::new(None),
            clock: self.clock,
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

    /// The cache is keyed on the JWT's bytes, not its claims: a JWT that
    /// copies a cached user's header and payload under another signature is
    /// exchanged (and refused here), never served that user's token. The
    /// client cannot verify a signature, so a cache keyed on `iss`/`sub`
    /// would hand this forgery the victim's CTS token without CTS ever
    /// seeing it.
    #[tokio::test]
    async fn a_jwt_with_the_same_claims_but_other_bytes_is_not_served_the_cached_token() {
        let server = start_mock_server().await;
        let victim = jwt_for_principal(WS, "user-1");
        let (signed, signature) = victim.rsplit_once('.').expect("a JWT");
        let forged = format!("{signed}.{}", signature.chars().rev().collect::<String>());
        assert_ne!(forged, victim, "the forgery differs in its signature");
        assert_eq!(
            forged.rsplit_once('.').map(|(claims, _)| claims),
            Some(signed),
            "and only there"
        );
        accept_exchange(&server, &victim, "CS|victim");
        let (current, _, provider) = switchable_provider();
        let strategy = strategy_on(&server, provider).build().expect("builder");

        act_as(&current, &victim);
        assert_eq!(
            subject(&(&strategy).get_token().await.expect("the victim federates")),
            "CS|victim"
        );

        refuse_exchanges(&server);
        act_as(&current, &forged);
        let err = (&strategy)
            .get_token()
            .await
            .expect_err("the forgery must be exchanged, never served the victim's token");
        assert!(
            matches!(err, AuthError::Server(_)),
            "the forgery's call should have reached the (refusing) exchange, got {err:?}"
        );
        assert_eq!(
            strategy.cached_jwts(),
            1,
            "the refused forgery took no slot"
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
            "a refused exchange takes no slot: A and C are still cached"
        );
        assert_eq!(strategy.pending_jwts(), 0, "B's engine was dropped");
        act_as(&current, "jwt-a");
        assert_eq!(
            subject(&(&strategy).get_token().await.expect("A still cached")),
            "CS|a"
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

    // ---- Exchanges counted exactly, over a stub transport ----

    /// A transport that answers `/api/authorise` itself: a CTS token naming
    /// the JWT it was exchanged from, or a canned refusal, and counts the
    /// exchanges it saw. Exact counts are what the mock server above cannot
    /// give.
    #[derive(Clone)]
    struct CountingCts(Arc<CountingCtsInner>);

    struct CountingCtsInner {
        exchanges: AtomicUsize,
        /// Refusals to hand out, in order, before answering normally.
        refusals: Mutex<Vec<(u16, &'static str)>>,
        /// When set, every exchange waits for a permit before answering, so a
        /// test can look at the strategy while an exchange is in flight.
        gate: Option<Arc<tokio::sync::Semaphore>>,
        /// How many of the next successful answers carry a token that has
        /// already expired, so the engine that receives one must renew on
        /// its next call.
        expired_answers: AtomicUsize,
    }

    impl CountingCts {
        fn new() -> Self {
            Self(Arc::new(CountingCtsInner {
                exchanges: AtomicUsize::new(0),
                refusals: Mutex::new(Vec::new()),
                gate: None,
                expired_answers: AtomicUsize::new(0),
            }))
        }

        /// A CTS whose exchanges block until the returned semaphore grants
        /// them a permit.
        fn gated() -> (Self, Arc<tokio::sync::Semaphore>) {
            let gate = Arc::new(tokio::sync::Semaphore::new(0));
            let cts = Self(Arc::new(CountingCtsInner {
                exchanges: AtomicUsize::new(0),
                refusals: Mutex::new(Vec::new()),
                gate: Some(Arc::clone(&gate)),
                expired_answers: AtomicUsize::new(0),
            }));
            (cts, gate)
        }

        fn exchanges(&self) -> usize {
            self.0.exchanges.load(Ordering::SeqCst)
        }

        /// The next exchange is refused with `status` and `body`.
        fn refuse_next(&self, status: u16, body: &'static str) {
            self.0
                .refusals
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((status, body));
        }

        /// The next successful answer carries a token that has already
        /// expired: `AutoRefresh` installs and returns it all the same, so
        /// the engine is cached holding a token it must renew next time.
        fn expire_next_answer(&self) {
            let _ = self.0.expired_answers.fetch_add(1, Ordering::SeqCst);
        }
    }

    const USAGE_LIMIT_BODY: &str = r#"{"error":"access_denied","cs_code":"USAGE_LIMIT_EXCEEDED","error_description":"Workspace has exceeded its usage limit"}"#;

    impl HttpTransport for CountingCts {
        async fn send(
            &self,
            request: crate::HttpRequest,
        ) -> Result<crate::HttpResponse, crate::RequestError> {
            let _ = self.0.exchanges.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = &self.0.gate {
                gate.acquire().await.expect("gate is never closed").forget();
            }
            let refusal = {
                let mut refusals = self
                    .0
                    .refusals
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if refusals.is_empty() {
                    None
                } else {
                    Some(refusals.remove(0))
                }
            };
            if let Some((status, body)) = refusal {
                return Ok(crate::HttpResponse::new(status, Vec::new(), body.into()));
            }
            let body: serde_json::Value =
                serde_json::from_slice(request.body()).expect("exchange body is JSON");
            let jwt = body["oidcToken"]
                .as_str()
                .expect("exchange carries the JWT");
            let cts = jwt_for_principal(WS, &format!("CS|{jwt}"));
            let expired = self
                .0
                .expired_answers
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
            let expiry = if expired { now() - 1 } else { now() + 3600 };
            let answer = serde_json::json!({ "accessToken": cts, "expiry": expiry });
            Ok(crate::HttpResponse::new(
                200,
                Vec::new(),
                serde_json::to_vec(&answer).expect("JSON"),
            ))
        }
    }

    fn strategy_over<P: OidcProvider>(
        cts: &CountingCts,
        provider: P,
    ) -> OidcFederationStrategyBuilder<P> {
        OidcFederationStrategy::builder(crn_with_workspace(WS), provider)
            .transport(cts.clone())
            .base_url("https://cts.example.com/".parse().expect("url"))
    }

    /// Two callers arriving together for one JWT share one exchange: the
    /// engine is in the cache before either federates, so the second waits
    /// on the first rather than asking CTS again.
    #[tokio::test]
    async fn concurrent_first_calls_for_one_jwt_share_one_exchange() {
        let cts = CountingCts::new();
        let strategy = strategy_over(&cts, provider()).build().expect("builder");

        let (first, second) = tokio::join!((&strategy).get_token(), (&strategy).get_token());
        assert_eq!(
            subject(&first.expect("first")),
            "CS|header.payload.signature"
        );
        assert_eq!(
            subject(&second.expect("second")),
            "CS|header.payload.signature"
        );
        assert_eq!(cts.exchanges(), 1, "one exchange for both callers");
        assert_eq!(strategy.cached_jwts(), 1);
        assert_eq!(strategy.pending_jwts(), 0, "promoted into the cache");
    }

    /// A refused exchange leaves nothing in the cache: a caller presenting
    /// JWTs CTS rejects cannot evict users who hold tokens, and the same JWT
    /// is simply exchanged again on its next call.
    #[tokio::test]
    async fn a_refused_exchange_takes_no_slot_and_is_retried() {
        let cts = CountingCts::new();
        cts.refuse_next(500, r#"{"error":"boom"}"#);
        let strategy = strategy_over(&cts, provider()).build().expect("builder");

        let err = (&strategy).get_token().await.expect_err("refused");
        assert!(matches!(err, AuthError::Server(_)), "{err:?}");
        assert_eq!(strategy.cached_jwts(), 0, "a refused JWT holds no slot");
        assert_eq!(strategy.pending_jwts(), 0, "and does not linger as pending");

        let token = (&strategy).get_token().await.expect("retried");
        assert_eq!(subject(&token), "CS|header.payload.signature");
        assert_eq!(cts.exchanges(), 2);
        assert_eq!(strategy.cached_jwts(), 1);
    }

    /// A refusal of the *account* (a usage limit) is remembered for every
    /// JWT: the next user's call within the window gets the same answer
    /// without a second exchange, even though no engine was kept.
    #[tokio::test]
    async fn an_account_refusal_is_remembered_across_jwts_without_an_engine() {
        let cts = CountingCts::new();
        cts.refuse_next(402, USAGE_LIMIT_BODY);
        let (current, _, provider) = switchable_provider();
        let strategy = strategy_over(&cts, provider).build().expect("builder");

        act_as(&current, "jwt-a");
        let err = (&strategy).get_token().await.expect_err("over the limit");
        assert!(matches!(err, AuthError::UsageLimitExceeded(_)), "{err:?}");
        assert_eq!(strategy.cached_jwts(), 0);

        act_as(&current, "jwt-b");
        let err = (&strategy)
            .get_token()
            .await
            .expect_err("the refusal is the account's, so B gets it too");
        assert!(matches!(err, AuthError::UsageLimitExceeded(_)), "{err:?}");
        assert_eq!(cts.exchanges(), 1, "B did not re-ask CTS");
    }

    /// A remembered account refusal does not take a token away from a user
    /// who already holds one: a settled refusal suppresses exchanges, it does
    /// not invalidate a credential that still works.
    #[tokio::test]
    async fn a_remembered_refusal_does_not_block_a_cached_user() {
        let cts = CountingCts::new();
        let (current, _, provider) = switchable_provider();
        let strategy = strategy_over(&cts, provider).build().expect("builder");

        act_as(&current, "jwt-a");
        assert_eq!(
            subject(&(&strategy).get_token().await.expect("A")),
            "CS|jwt-a"
        );

        cts.refuse_next(402, USAGE_LIMIT_BODY);
        act_as(&current, "jwt-b");
        let _ = (&strategy).get_token().await.expect_err("B is refused");

        act_as(&current, "jwt-a");
        assert_eq!(
            subject(&(&strategy).get_token().await.expect("A still served")),
            "CS|jwt-a"
        );
        assert_eq!(cts.exchanges(), 2, "A's call was served from the cache");
    }

    /// While its first exchange is in flight an engine is pending, not
    /// cached: a second caller for the same JWT finds it there and waits,
    /// and only the answer promotes it into the cache.
    #[tokio::test]
    async fn an_engine_is_pending_until_its_first_exchange_answers() {
        let (cts, gate) = CountingCts::gated();
        let strategy = Arc::new(strategy_over(&cts, provider()).build().expect("builder"));

        let in_flight = {
            let strategy = Arc::clone(&strategy);
            tokio::spawn(async move { (&*strategy).get_token().await })
        };
        for _ in 0..1000 {
            if strategy.pending_jwts() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(strategy.pending_jwts(), 1, "the engine is waiting on CTS");
        assert_eq!(strategy.cached_jwts(), 0, "and holds no slot yet");

        // A second caller for the same JWT joins the pending engine rather
        // than starting another exchange.
        let joined = {
            let strategy = Arc::clone(&strategy);
            tokio::spawn(async move { (&*strategy).get_token().await })
        };
        tokio::task::yield_now().await;
        assert_eq!(strategy.pending_jwts(), 1);
        assert_eq!(cts.exchanges(), 1, "the second caller did not exchange");

        gate.add_permits(1);
        let first = in_flight.await.expect("task").expect("first caller");
        let second = joined.await.expect("task").expect("second caller");
        assert_eq!(subject(&first), "CS|header.payload.signature");
        assert_eq!(subject(&second), "CS|header.payload.signature");
        assert_eq!(strategy.pending_jwts(), 0, "promoted");
        assert_eq!(strategy.cached_jwts(), 1);
        assert_eq!(cts.exchanges(), 1);
    }

    tokio::task_local! {
        /// The JWT of "the user behind the current request", carried by the
        /// task so two concurrent callers can present different JWTs to one
        /// provider — what `switchable_provider`'s single shared slot cannot.
        static CALLER: String;
    }

    /// Two users whose first exchanges are in flight together each wait on
    /// their own pending engine and receive their own token. The pending
    /// tier is keyed on the JWT like the cache: a lookup that ignored the
    /// digest would have B join A's exchange and receive A's token — the
    /// #1045 bug during the first exchange, which the sequential multi-user
    /// tests cannot see because `pending` is empty when each of their calls
    /// starts.
    #[tokio::test]
    async fn concurrent_first_calls_for_two_jwts_do_not_share_an_engine() {
        let (cts, gate) = CountingCts::gated();
        let provider = OidcProviderFn::new(|| {
            std::future::ready(Ok::<_, AuthError>(SecretToken::new(
                CALLER.with(|jwt| jwt.clone()),
            )))
        });
        let strategy = Arc::new(strategy_over(&cts, provider).build().expect("builder"));
        let spawn_as = |jwt: &str| {
            let strategy = Arc::clone(&strategy);
            let call = async move { (&*strategy).get_token().await };
            tokio::spawn(CALLER.scope(jwt.to_string(), call))
        };

        let a = spawn_as("jwt-a");
        let b = spawn_as("jwt-b");
        for _ in 0..1000 {
            if strategy.pending_jwts() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(strategy.pending_jwts(), 2, "one pending engine per JWT");
        assert_eq!(cts.exchanges(), 2, "both exchanges are in flight");
        assert_eq!(strategy.cached_jwts(), 0);

        gate.add_permits(2);
        let a = a.await.expect("task").expect("A");
        let b = b.await.expect("task").expect("B");
        assert_eq!(subject(&a), "CS|jwt-a");
        assert_eq!(
            subject(&b),
            "CS|jwt-b",
            "B waited on its own engine, not on A's"
        );
        assert_eq!(cts.exchanges(), 2);
        assert_eq!(strategy.cached_jwts(), 2, "both promoted");
        assert_eq!(strategy.pending_jwts(), 0);
    }

    /// A call dropped mid-exchange (a timeout, a `select!`, a client that
    /// went away) takes its pending entry with it, so cancelled first calls
    /// cannot accumulate JWTs in `pending`; the next call for that JWT
    /// starts afresh.
    #[tokio::test]
    async fn a_cancelled_first_call_leaves_nothing_pending() {
        let (cts, gate) = CountingCts::gated();
        let strategy = Arc::new(strategy_over(&cts, provider()).build().expect("builder"));

        let in_flight = {
            let strategy = Arc::clone(&strategy);
            tokio::spawn(async move { (&*strategy).get_token().await })
        };
        for _ in 0..1000 {
            if strategy.pending_jwts() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(strategy.pending_jwts(), 1);

        in_flight.abort();
        assert!(in_flight.await.expect_err("aborted").is_cancelled());
        assert_eq!(
            strategy.pending_jwts(),
            0,
            "the cancelled call took its entry with it"
        );
        assert_eq!(strategy.cached_jwts(), 0);

        // The abandoned exchange's permit is still owed; the fresh call takes it.
        gate.add_permits(1);
        let token = (&*strategy)
            .get_token()
            .await
            .expect("a fresh call succeeds");
        assert_eq!(subject(&token), "CS|header.payload.signature");
        assert_eq!(
            cts.exchanges(),
            2,
            "the cancelled exchange counted once, the fresh one once"
        );
        assert_eq!(strategy.cached_jwts(), 1);
    }

    /// A sibling that was still waiting on an engine whose pending entry a
    /// cancelled call removed still gets its token cached: success promotes
    /// regardless of who removed the entry.
    #[tokio::test]
    async fn a_survivor_of_a_cancelled_sibling_still_caches_its_token() {
        let (cts, gate) = CountingCts::gated();
        let strategy = Arc::new(strategy_over(&cts, provider()).build().expect("builder"));

        let spawn = || {
            let strategy = Arc::clone(&strategy);
            tokio::spawn(async move { (&*strategy).get_token().await })
        };
        let first = spawn();
        for _ in 0..1000 {
            if strategy.pending_jwts() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        let second = spawn();
        tokio::task::yield_now().await;

        first.abort();
        let _ = first.await;
        assert_eq!(
            strategy.pending_jwts(),
            0,
            "the cancelled call removed the entry"
        );

        gate.add_permits(1);
        let token = second.await.expect("task").expect("the survivor completes");
        assert_eq!(subject(&token), "CS|header.payload.signature");
        assert_eq!(
            strategy.cached_jwts(),
            1,
            "its token is cached all the same"
        );
        // The abandoned exchange died with the cancelled call; the survivor,
        // next in line on the engine, made its own and took the permit.
        assert_eq!(cts.exchanges(), 2);
    }

    /// The remembered account refusal is forgotten after its window, so the
    /// next first call asks CTS again: the customer may have upgraded.
    #[tokio::test]
    async fn a_remembered_refusal_expires_after_its_window() {
        let cts = CountingCts::new();
        cts.refuse_next(402, USAGE_LIMIT_BODY);
        let clock = crate::clock::TestClock::new(1_700_000_000);
        let (current, _, provider) = switchable_provider();
        let strategy = strategy_over(&cts, provider)
            .clock(Arc::new(clock.clone()))
            .build()
            .expect("builder");

        act_as(&current, "jwt-a");
        let _ = (&strategy).get_token().await.expect_err("over the limit");
        act_as(&current, "jwt-b");
        let _ = (&strategy)
            .get_token()
            .await
            .expect_err("still remembered within the window");
        assert_eq!(cts.exchanges(), 1);

        clock.advance(crate::auto_refresh::DENIAL_TTL_SECS);
        let token = (&strategy)
            .get_token()
            .await
            .expect("the window has passed, so CTS is asked again and answers");
        assert_eq!(subject(&token), "CS|jwt-b");
        assert_eq!(cts.exchanges(), 2);
    }

    /// A credential refusal (a 500 here) is not an account refusal: the next
    /// JWT is exchanged normally.
    #[tokio::test]
    async fn a_credential_refusal_is_not_remembered_for_other_jwts() {
        let cts = CountingCts::new();
        cts.refuse_next(500, r#"{"error":"boom"}"#);
        let (current, _, provider) = switchable_provider();
        let strategy = strategy_over(&cts, provider).build().expect("builder");

        act_as(&current, "jwt-a");
        let _ = (&strategy).get_token().await.expect_err("A refused");
        act_as(&current, "jwt-b");
        assert_eq!(
            subject(&(&strategy).get_token().await.expect("B")),
            "CS|jwt-b"
        );
        assert_eq!(cts.exchanges(), 2);
    }

    /// A cached engine whose renewal is refused holds no usable token, so it
    /// gives up its slot; the next call for that JWT starts a new engine.
    /// Every other failure in this module comes from a pending engine, whose
    /// first exchange has not answered, so this is the one path on which
    /// `settle` has a cache entry to remove.
    #[tokio::test]
    async fn a_cached_engine_whose_renewal_is_refused_leaves_the_cache() {
        let cts = CountingCts::new();
        cts.expire_next_answer();
        let strategy = strategy_over(&cts, provider()).build().expect("builder");

        let token = (&strategy)
            .get_token()
            .await
            .expect("the first exchange answers, expired or not");
        assert_eq!(subject(&token), "CS|header.payload.signature");
        assert_eq!(
            strategy.cached_jwts(),
            1,
            "an engine holding a token is cached"
        );

        cts.refuse_next(500, r#"{"error":"boom"}"#);
        let err = (&strategy)
            .get_token()
            .await
            .expect_err("renewal is refused");
        assert!(matches!(err, AuthError::Server(_)), "{err:?}");
        assert_eq!(
            cts.exchanges(),
            2,
            "the expired token was renewed, not served"
        );
        assert_eq!(
            strategy.cached_jwts(),
            0,
            "an engine left with no usable token gives up its slot"
        );
        assert_eq!(strategy.pending_jwts(), 0);

        let token = (&strategy)
            .get_token()
            .await
            .expect("the next call for that JWT starts a new engine");
        assert_eq!(subject(&token), "CS|header.payload.signature");
        assert_eq!(cts.exchanges(), 3);
        assert_eq!(strategy.cached_jwts(), 1);
    }

    /// A renewal refused for the *account* is remembered for every JWT, as a
    /// refused first exchange is: the next user's call within the window gets
    /// the same answer without asking CTS.
    #[tokio::test]
    async fn an_account_refusal_on_renewal_is_remembered_for_other_jwts() {
        let cts = CountingCts::new();
        cts.expire_next_answer();
        let (current, _, provider) = switchable_provider();
        let strategy = strategy_over(&cts, provider).build().expect("builder");

        act_as(&current, "jwt-a");
        let _ = (&strategy).get_token().await.expect("A's first exchange");
        cts.refuse_next(402, USAGE_LIMIT_BODY);
        let err = (&strategy)
            .get_token()
            .await
            .expect_err("A's renewal is refused for the account");
        assert!(matches!(err, AuthError::UsageLimitExceeded(_)), "{err:?}");
        assert_eq!(strategy.cached_jwts(), 0, "A's engine gave up its slot");

        act_as(&current, "jwt-b");
        let err = (&strategy)
            .get_token()
            .await
            .expect_err("the refusal is the account's, so B gets it too");
        assert!(matches!(err, AuthError::UsageLimitExceeded(_)), "{err:?}");
        assert_eq!(cts.exchanges(), 2, "B did not re-ask CTS");
    }
}
