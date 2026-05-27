//! Pluggable persistence for service tokens.
//!
//! [`AutoRefresh`](crate::auto_refresh::AutoRefresh) consults a [`TokenStore`]
//! on cold start (no in-memory token) and writes back after every successful
//! refresh or initial auth. This lets strategies share a service-token cache
//! across short-lived processes — HTTP-only cookies in Edge Functions, KV
//! stores in Cloudflare Workers, Redis in multi-instance Node services, or a
//! shared cache across the CipherStash Proxy's worker pool.
//!
//! Wire a store onto a strategy via the builder:
//!
//! ```no_run
//! use std::sync::Arc;
//! use stack_auth::{AccessKey, AccessKeyStrategy, InMemoryTokenStore};
//! use cts_common::Crn;
//!
//! let crn: Crn = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY".parse().unwrap();
//! let key: AccessKey = "CSAKmyKeyId.myKeySecret".parse().unwrap();
//! let store = Arc::new(InMemoryTokenStore::new());
//! let strategy = AccessKeyStrategy::builder(crn, key)
//!     .with_token_store(store)
//!     .build()
//!     .unwrap();
//! ```
//!
//! For cookie-style storage where the load/save logic lives in the calling
//! request handler, use [`TokenStoreFn::new`] with two async closures
//! that deal in JSON strings:
//!
//! ```no_run
//! use std::sync::Arc;
//! use stack_auth::TokenStoreFn;
//!
//! let store = Arc::new(TokenStoreFn::new(
//!     || async { /* read cookie */ None::<String> },
//!     |_json: String| async move { /* write Set-Cookie header */ },
//! ));
//! ```
//!
//! See also: [`AuthStrategyFn`](crate::AuthStrategyFn) — the closure-shaped
//! impl of the *acquisition* layer ([`AuthStrategy`](crate::AuthStrategy)).
//! `TokenStoreFn` plugs into an existing strategy as a persistence backend;
//! `AuthStrategyFn` replaces the whole acquisition pipeline (used by FFI
//! consumers like `protect-ffi` that source tokens from JS).

use std::future::Future;
use std::sync::Arc;

use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::Token;

/// Pluggable persistent cache for service tokens.
///
/// Implementations are consulted by `AutoRefresh` whenever it has no
/// in-memory token (cold start), and written to after every successful
/// refresh or initial authentication. Implementations should treat both
/// methods as best-effort — `load` returns [`None`] for "no token, or load
/// failed", `save` is fire-and-forget. The `AutoRefresh` state machine
/// always validates freshness via [`Token::is_usable`] / [`Token::is_expired`]
/// before returning a loaded token, so implementations don't need to.
///
/// On native targets the trait carries `Send + Sync` bounds so the store can
/// be shared across `tokio::spawn` background work. On wasm32 the bounds are
/// dropped — edge runtimes are single-threaded.
#[cfg(not(target_arch = "wasm32"))]
pub trait TokenStore: Send + Sync {
    /// Load the most recently saved token, or `None` if none has been stored
    /// (or the load failed). Errors are swallowed — the calling state machine
    /// falls back to fresh authentication when this returns `None`.
    fn load(&self) -> impl Future<Output = Option<Token>> + Send;

    /// Persist a token after a successful refresh or initial authentication.
    /// Best-effort — implementations should log on failure rather than
    /// returning an error.
    fn save(&self, token: &Token) -> impl Future<Output = ()> + Send;
}

#[cfg(target_arch = "wasm32")]
pub trait TokenStore {
    fn load(&self) -> impl Future<Output = Option<Token>>;
    fn save(&self, token: &Token) -> impl Future<Output = ()>;
}

/// Forward [`TokenStore`] through `Arc` so one store can back many strategy
/// instances (Edge Function pool, CipherStash Proxy worker pool, etc).
#[cfg(not(target_arch = "wasm32"))]
impl<T: TokenStore + ?Sized> TokenStore for Arc<T> {
    fn load(&self) -> impl Future<Output = Option<Token>> + Send {
        (**self).load()
    }

    fn save(&self, token: &Token) -> impl Future<Output = ()> + Send {
        (**self).save(token)
    }
}

#[cfg(target_arch = "wasm32")]
impl<T: TokenStore + ?Sized> TokenStore for Arc<T> {
    fn load(&self) -> impl Future<Output = Option<Token>> {
        (**self).load()
    }

    fn save(&self, token: &Token) -> impl Future<Output = ()> {
        (**self).save(token)
    }
}

/// Zero-sized default for `AutoRefresh<R, S = NoStore>` — `load` returns
/// `None`, `save` is a no-op. Carries no per-instance cost.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoStore;

impl TokenStore for NoStore {
    async fn load(&self) -> Option<Token> {
        None
    }

    async fn save(&self, _token: &Token) {}
}

/// In-process token store. Useful for tests and as a shared cache across
/// multiple strategy instances in the same process (e.g. a worker pool).
///
/// Internally stores the JSON-serialised form of the token wrapped in
/// [`Zeroizing`] so the buffer is wiped on overwrite and on store drop. The
/// [`SecretToken`](crate::SecretToken) wrapped inside [`Token`] is
/// [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop), so we deliberately don't clone
/// the in-memory `Token` value — round-tripping through serde gives us a
/// fresh `SecretToken` on each `load` without violating that invariant.
pub struct InMemoryTokenStore {
    state: Mutex<Option<Zeroizing<String>>>,
}

impl InMemoryTokenStore {
    /// Create a new, empty in-memory token store.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(None),
        }
    }
}

impl Default for InMemoryTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStore for InMemoryTokenStore {
    async fn load(&self) -> Option<Token> {
        let guard = self.state.lock().await;
        let json = guard.as_ref()?;
        serde_json::from_str(json).ok()
    }

    async fn save(&self, token: &Token) {
        let Ok(json) = serde_json::to_string(token) else {
            tracing::warn!("InMemoryTokenStore: failed to serialise token");
            return;
        };
        let mut guard = self.state.lock().await;
        *guard = Some(Zeroizing::new(json));
    }
}

/// [`TokenStore`] backed by user-supplied `load` and `save` async closures.
///
/// This is the *persistence layer* primitive — it plugs into an existing
/// strategy (e.g. [`AccessKeyStrategy`](crate::AccessKeyStrategy)) so that
/// strategy can share its service-token cache across processes. For wiring
/// in a complete *acquisition pipeline* (e.g. a JS-defined strategy across
/// an FFI boundary), use [`AuthStrategyFn`](crate::AuthStrategyFn) instead.
///
/// Closures deal in JSON strings — the on-the-wire form of [`Token`] — not
/// the `Token` type itself. This keeps the caller's signatures free of
/// `stack-auth` internals and matches the natural shape of common storage
/// substrates: a cookie value, a KV blob, a Redis string.
///
/// The closure return types are generic so async blocks / `async ||`
/// closures / `async fn` adapters all compose without boxing.
///
/// **Secret-material handling.** The JSON string passed to the `save`
/// closure contains the bearer token verbatim (via
/// [`SecretToken`](crate::SecretToken)'s `#[serde(transparent)]` impl). Once
/// the value crosses into the user's closure, `stack-auth` has no control
/// over zeroize semantics — implementations should treat the input as
/// secret material and clear any local copies promptly. `load` wraps the
/// returned string in [`Zeroizing`] internally, so the buffer is wiped
/// after deserialisation. End-to-end protection at rest (e.g. encrypting
/// the value before it ever leaves the worker) is tracked as a future
/// `EncryptedTokenStore` decorator.
pub struct TokenStoreFn<L, S> {
    load: L,
    save: S,
}

impl<L, S> TokenStoreFn<L, S> {
    /// Build a token store from a `load` closure (returns the stored JSON, or
    /// `None` if nothing is cached) and a `save` closure (persists the JSON).
    ///
    /// See the module-level documentation for an example.
    pub fn new(load: L, save: S) -> Self {
        Self { load, save }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<L, LF, S, SF> TokenStore for TokenStoreFn<L, S>
where
    L: Fn() -> LF + Send + Sync,
    LF: Future<Output = Option<String>> + Send,
    S: Fn(String) -> SF + Send + Sync,
    SF: Future<Output = ()> + Send,
{
    async fn load(&self) -> Option<Token> {
        let json = Zeroizing::new((self.load)().await?);
        // Don't log the underlying serde_json error — its `Display` impl can
        // include byte positions of unexpected tokens, leaking partial token
        // content if the input was mid-parse when it failed.
        serde_json::from_str(&json).ok()
    }

    async fn save(&self, token: &Token) {
        let Ok(json) = serde_json::to_string(token) else {
            tracing::warn!("TokenStoreFn: failed to serialise token");
            return;
        };
        (self.save)(json).await;
    }
}

#[cfg(target_arch = "wasm32")]
impl<L, LF, S, SF> TokenStore for TokenStoreFn<L, S>
where
    L: Fn() -> LF,
    LF: Future<Output = Option<String>>,
    S: Fn(String) -> SF,
    SF: Future<Output = ()>,
{
    async fn load(&self) -> Option<Token> {
        let json = Zeroizing::new((self.load)().await?);
        // Don't log the underlying serde_json error — its `Display` impl can
        // include byte positions of unexpected tokens, leaking partial token
        // content if the input was mid-parse when it failed.
        serde_json::from_str(&json).ok()
    }

    async fn save(&self, token: &Token) {
        let Ok(json) = serde_json::to_string(token) else {
            tracing::warn!("TokenStoreFn: failed to serialise token");
            return;
        };
        (self.save)(json).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use crate::SecretToken;

    use super::*;

    fn dummy_token(expires_at: u64) -> Token {
        Token {
            access_token: SecretToken::new("dummy-access".to_string()),
            refresh_token: None,
            token_type: "Bearer".to_string(),
            expires_at,
            region: None,
            client_id: None,
            device_instance_id: None,
        }
    }

    #[tokio::test]
    async fn in_memory_load_returns_none_when_empty() {
        let store = InMemoryTokenStore::new();
        assert!(
            store.load().await.is_none(),
            "freshly constructed store should hold no token"
        );
    }

    #[tokio::test]
    async fn in_memory_round_trip_preserves_expires_at() {
        let store = InMemoryTokenStore::new();
        store.save(&dummy_token(4_000_000_000)).await;
        let loaded = store
            .load()
            .await
            .expect("load should return the saved token");
        assert_eq!(
            loaded.expires_at(),
            4_000_000_000,
            "round-trip should preserve expires_at"
        );
        assert_eq!(
            loaded.token_type(),
            "Bearer",
            "round-trip should preserve token_type"
        );
    }

    #[tokio::test]
    async fn in_memory_save_overwrites_previous() {
        let store = InMemoryTokenStore::new();
        store.save(&dummy_token(1_000_000_000)).await;
        store.save(&dummy_token(2_000_000_000)).await;
        let loaded = store.load().await.expect("store should hold a token");
        assert_eq!(
            loaded.expires_at(),
            2_000_000_000,
            "second save should replace the first"
        );
    }

    #[tokio::test]
    async fn callback_store_invokes_load_closure_each_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);
        let store = TokenStoreFn::new(
            move || {
                let calls = Arc::clone(&calls_clone);
                async move {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        None
                    } else {
                        Some(serde_json::to_string(&dummy_token(4_000_000_000)).unwrap())
                    }
                }
            },
            |_json: String| async move {},
        );

        assert!(
            store.load().await.is_none(),
            "first load returns None because the closure does"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "first call should have invoked the load closure exactly once"
        );

        let loaded = store
            .load()
            .await
            .expect("second load should yield a token");
        assert_eq!(
            loaded.expires_at(),
            4_000_000_000,
            "deserialised token should preserve the JSON payload's expires_at"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "second call should have invoked the load closure a second time"
        );
    }

    #[tokio::test]
    async fn callback_store_forwards_serialised_token_to_save_closure() {
        let captured = Arc::new(Mutex::new(None::<String>));
        let captured_clone = Arc::clone(&captured);
        let store = TokenStoreFn::new(
            || async { None },
            move |json: String| {
                let captured = Arc::clone(&captured_clone);
                async move {
                    *captured.lock().await = Some(json);
                }
            },
        );

        store.save(&dummy_token(4_000_000_000)).await;
        let json = captured
            .lock()
            .await
            .clone()
            .expect("save closure should have captured the JSON");
        assert!(
            json.contains("\"expires_at\":4000000000"),
            "captured JSON should encode expires_at; got: {json}"
        );
        assert!(
            json.contains("\"token_type\":\"Bearer\""),
            "captured JSON should encode token_type; got: {json}"
        );
    }

    #[tokio::test]
    async fn callback_store_ignores_invalid_json_on_load() {
        let store = TokenStoreFn::new(
            || async { Some("not valid json".to_string()) },
            |_json: String| async move {},
        );
        assert!(
            store.load().await.is_none(),
            "invalid JSON from the load closure should be treated as cache miss"
        );
    }
}
