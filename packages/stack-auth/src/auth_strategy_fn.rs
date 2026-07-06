//! [`AuthStrategy`] adapter built from an async closure.
//!
//! `AuthStrategyFn` is the closure-shaped impl of the *acquisition layer*
//! ([`AuthStrategy`]): the closure runs every time a token is requested and
//! returns a [`ServiceToken`]. Use this when the actual token acquisition
//! lives outside `stack-auth` — most commonly behind an FFI callback
//! (a JS `getToken()` reached via Neon, a foreign IPC channel, a hand-rolled
//! test double).
//!
//! Sibling primitive on the *persistence layer* is
//! [`TokenStoreFn`](crate::TokenStoreFn), which plugs into an existing
//! strategy to back its cache. `AuthStrategyFn` replaces the whole
//! acquisition pipeline; `TokenStoreFn` slots into one. See `auth-strategy-handover.md`
//! at the repo root for the wider design discussion.
//!
//! [`cipherstash-client`]: https://docs.rs/cipherstash-client/

use std::future::Future;

use crate::{AuthError, AuthStrategy, ServiceToken};

/// [`AuthStrategy`] backed by a user-supplied async closure that returns
/// a [`ServiceToken`].
///
/// # Example
///
/// ```no_run
/// use stack_auth::{AuthError, AuthStrategyFn, SecretToken, ServiceToken};
///
/// let strategy = AuthStrategyFn::new(|| async {
///     // Real consumers would call into FFI / IPC / a cached token store.
///     Ok::<_, AuthError>(ServiceToken::new(SecretToken::new("dummy.jwt.value".to_string())))
/// });
/// ```
///
/// # When to reach for this vs [`TokenStoreFn`](crate::TokenStoreFn)
///
/// - **`AuthStrategyFn`**: you control the *entire* token pipeline — fetch,
///   refresh, cache. `cipherstash-client` calls your closure and uses
///   whatever it returns, no further questions asked. Used by FFI bindings
///   that proxy to a JS-side strategy doing all the work upstream.
/// - **`TokenStoreFn`**: you want stack-auth's `AccessKeyStrategy` (or
///   another concrete strategy) to do the HTTP/refresh work, and you just
///   want to plug in custom persistence (a cookie, a KV blob, Redis).
pub struct AuthStrategyFn<F> {
    get_token: F,
}

impl<F> AuthStrategyFn<F> {
    /// Build an `AuthStrategyFn` from an async closure. The closure fires
    /// every time [`AuthStrategy::get_token`] is called on a reference to
    /// this strategy — typically once per `cipherstash-client` HTTP request,
    /// modulo any in-process caching the closure does internally.
    pub fn new(get_token: F) -> Self {
        Self { get_token }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<F, Fut> AuthStrategy for &AuthStrategyFn<F>
where
    F: Fn() -> Fut + Send + Sync,
    Fut: Future<Output = Result<ServiceToken, AuthError>> + Send,
{
    fn get_token(self) -> impl Future<Output = Result<ServiceToken, AuthError>> + Send {
        (self.get_token)()
    }
}

#[cfg(target_arch = "wasm32")]
impl<F, Fut> AuthStrategy for &AuthStrategyFn<F>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<ServiceToken, AuthError>>,
{
    fn get_token(self) -> impl Future<Output = Result<ServiceToken, AuthError>> {
        (self.get_token)()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use crate::SecretToken;

    use super::*;

    fn dummy_service_token(jwt: &str) -> ServiceToken {
        ServiceToken::new(SecretToken::new(jwt.to_string()))
    }

    #[tokio::test]
    async fn closure_runs_on_each_get_token_call() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);
        let strategy = AuthStrategyFn::new(move || {
            let calls = Arc::clone(&calls_clone);
            async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                Ok(dummy_service_token(&format!("jwt-{n}")))
            }
        });

        let first = (&strategy).get_token().await.unwrap();
        assert_eq!(
            first.as_str(),
            "jwt-0",
            "first call should yield the first token the closure produced"
        );

        let second = (&strategy).get_token().await.unwrap();
        assert_eq!(
            second.as_str(),
            "jwt-1",
            "second call should re-invoke the closure"
        );

        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "closure should have fired exactly twice"
        );
    }

    #[tokio::test]
    async fn closure_errors_propagate_unchanged() {
        let strategy = AuthStrategyFn::new(|| async {
            Err(AuthError::AccessDenied(crate::error::AccessDenied))
        });
        let err = (&strategy).get_token().await.unwrap_err();
        assert!(
            matches!(err, AuthError::AccessDenied(_)),
            "AccessDenied from the closure should surface verbatim, got: {err:?}"
        );
    }
}
