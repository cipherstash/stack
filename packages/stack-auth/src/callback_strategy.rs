//! [`AuthStrategy`] adapter built from an async closure.
//!
//! Mirrors [`CallbackTokenStore`](crate::CallbackTokenStore) but for the
//! single-method [`AuthStrategy`] trait. Lets foreign crates — most notably
//! `protect-ffi`, which hosts JS callbacks across a Neon boundary — present
//! a [`stack-auth`](crate)-shaped strategy to [`cipherstash-client`] without
//! depending on `stack-auth`'s concrete strategy types.
//!
//! See `auth-strategy-handover.md` at the repo root for the wider design
//! discussion this scaffolding supports.
//!
//! [`cipherstash-client`]: https://docs.rs/cipherstash-client/

use std::future::Future;

use crate::{AuthError, AuthStrategy, ServiceToken};

/// An [`AuthStrategy`] backed by a user-supplied async closure that returns
/// a [`ServiceToken`].
///
/// Use this when the actual token acquisition lives outside `stack-auth` —
/// behind an FFI callback, a custom IPC channel, a test fixture, etc. The
/// `cipherstash-client` integration test [in this crate's
/// `tests/`](https://github.com/cipherstash/cipherstash-suite/tree/main/packages/cipherstash-client/tests)
/// exercises this shape end-to-end against a mocktail server.
///
/// # Example
///
/// ```no_run
/// use stack_auth::{CallbackAuthStrategy, SecretToken, ServiceToken};
///
/// let strategy = CallbackAuthStrategy::new(|| async {
///     // Real consumers would call into FFI / IPC / a cached token store.
///     Ok(ServiceToken::new(SecretToken::new("dummy.jwt.value".to_string())))
/// });
/// ```
pub struct CallbackAuthStrategy<F> {
    get_token: F,
}

impl<F> CallbackAuthStrategy<F> {
    /// Build a `CallbackAuthStrategy` from an async closure. The closure
    /// fires every time [`AuthStrategy::get_token`] is called on a reference
    /// to this strategy — typically once per `cipherstash-client` HTTP
    /// request, modulo the in-process [`AutoRefresh`](crate::auto_refresh)
    /// cache layered on top by individual strategy implementations.
    pub fn new(get_token: F) -> Self {
        Self { get_token }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<F, Fut> AuthStrategy for &CallbackAuthStrategy<F>
where
    F: Fn() -> Fut + Send + Sync,
    Fut: Future<Output = Result<ServiceToken, AuthError>> + Send,
{
    fn get_token(self) -> impl Future<Output = Result<ServiceToken, AuthError>> + Send {
        (self.get_token)()
    }
}

#[cfg(target_arch = "wasm32")]
impl<F, Fut> AuthStrategy for &CallbackAuthStrategy<F>
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
        let strategy = CallbackAuthStrategy::new(move || {
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
        let strategy = CallbackAuthStrategy::new(|| async { Err(AuthError::AccessDenied) });
        let err = (&strategy).get_token().await.unwrap_err();
        assert!(
            matches!(err, AuthError::AccessDenied),
            "AccessDenied from the closure should surface verbatim, got: {err:?}"
        );
    }
}
