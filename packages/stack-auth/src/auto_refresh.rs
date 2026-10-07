use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{Mutex, MutexGuard, Notify};

use crate::clock::{system_clock, SharedClock};
use crate::refresher::Refresher;
use crate::token_store::{NoStore, TokenStore};
use crate::{ServiceToken, Token};

/// Internal errors from [`AutoRefresh::get_token`].
///
/// Strategy wrappers convert these into [`AuthError`](crate::AuthError) for the
/// public API.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AutoRefreshError {
    /// No token is cached and the strategy cannot self-authenticate.
    #[error("No token found")]
    NotFound,
    /// The token has expired and refresh failed or is unavailable.
    #[error("Token has expired")]
    Expired,
    /// The refresh/auth HTTP call failed.
    #[error("Auth error: {0}")]
    Auth(#[from] crate::AuthError),
}

impl From<AutoRefreshError> for crate::AuthError {
    fn from(err: AutoRefreshError) -> Self {
        match err {
            AutoRefreshError::NotFound => {
                crate::AuthError::NotAuthenticated(crate::error::NotAuthenticated)
            }
            AutoRefreshError::Expired => crate::AuthError::TokenExpired(crate::error::TokenExpired),
            AutoRefreshError::Auth(e) => e,
        }
    }
}

/// Caches a token in memory and uses a [`Refresher`] to re-authenticate
/// or refresh before expiry, optionally backed by an external [`TokenStore`]
/// for persistence across short-lived strategy instances.
///
/// See the [crate-level documentation](crate#token-refresh) for a full
/// description of the concurrency model and flow diagram.
pub(crate) struct AutoRefresh<R, S = NoStore> {
    refresher: R,
    state: Mutex<State>,
    store: S,
    /// Set to `true` while a refresh HTTP call is in-flight.
    ///
    /// Stored as an [`AtomicBool`] rather than inside [`State`] so that
    /// [`CancelGuard`] can reset it on future cancellation without acquiring
    /// the mutex.
    refresh_in_progress: AtomicBool,
    refresh_notify: Notify,
    /// Source of "now" for token-expiry checks. [`SystemClock`](crate::clock::SystemClock)
    /// in production; an injected clock in tests so expiry is deterministic.
    clock: SharedClock,
}

/// How long a cached refusal is replayed before the server is asked again.
///
/// The cache exists to stop an over-limit client re-issuing the same doomed
/// request at its own request rate. It must not outlive its usefulness: the
/// customer can upgrade their plan at any moment, and that is invisible to us
/// until we ask. Sixty seconds turns a per-request storm into one call a
/// minute while bounding how long an upgrade goes unnoticed.
pub(crate) const DENIAL_TTL_SECS: u64 = 60;

struct State {
    token: Option<Token>,
    /// The last refusal that will not resolve by retrying, if any.
    ///
    /// Without this, a client whose org is over its usage limit re-issues the
    /// same doomed request on every `get_token` call — at request rate, against
    /// a decision that has already been made. Expires after
    /// [`DENIAL_TTL_SECS`], and is cleared outright by any successful refresh.
    denial: Option<StickyDenial>,
    /// The error from the most recently completed refresh attempt, if it
    /// failed. Cleared on every successful refresh.
    ///
    /// Unlike `denial`, this is not TTL'd, is not restricted to account-level
    /// refusals, and is never consulted by `get_token`'s own retry path — it
    /// exists solely so a caller parked in
    /// [`wait_for_in_flight_refresh`](AutoRefresh::wait_for_in_flight_refresh)
    /// sees the *same* outcome as whoever actually performed the refresh it
    /// was waiting on, instead of a generic `Expired` that discards why the
    /// wait ended in failure.
    last_refresh_error: Option<(&'static str, String)>,
}

/// A non-retryable refusal, held in a form that can be handed to more than one
/// caller.
///
/// [`AuthError`](crate::AuthError) is not `Clone` — it wraps foreign error
/// types — so the denial is stored as the wire pair it round-trips through and
/// rebuilt per call. `USAGE_LIMIT_EXCEEDED` round-trips exactly, message
/// included; see [`AuthError::from_error_code`](crate::AuthError::from_error_code).
pub(crate) struct StickyDenial {
    code: &'static str,
    message: String,
    recorded_at: u64,
}

impl StickyDenial {
    pub(crate) fn new(err: &crate::AuthError, now: u64) -> Self {
        Self {
            code: err.error_code(),
            message: err.to_string(),
            recorded_at: now,
        }
    }

    /// Whether the refusal has outlived its window.
    ///
    /// A clock reading earlier than the moment of recording (NTP step, VM
    /// snapshot restore, manual change) counts as stale. The elapsed time is
    /// then unknowable, and the two ways of being wrong are not equal: asking
    /// again costs one request, while pinning the entry locks the caller out
    /// until the clock catches up — which for a large backwards step is
    /// indistinguishable from forever.
    pub(crate) fn is_stale(&self, now: u64) -> bool {
        now < self.recorded_at || now - self.recorded_at >= DENIAL_TTL_SECS
    }

    pub(crate) fn to_error(&self) -> crate::AuthError {
        crate::AuthError::from_error_code(self.code, &self.message, &serde_json::Map::new())
    }
}

/// Whether a failed [`Refresher::refresh`] spent its credential.
///
/// A store error means the upstream exchange succeeded and only persisting
/// the result failed (see [`Refresher::refresh`]). The credential has been
/// used, so restoring it would replay it on the next call; for a rotating
/// refresh token that replay trips the issuer's reuse detection and revokes
/// the whole chain.
fn credential_consumed(err: &crate::AuthError) -> bool {
    matches!(err, crate::AuthError::Store(_))
}

/// Ensures [`AutoRefresh::refresh_in_progress`] is cleared and waiters are
/// notified if the refresh future is cancelled (dropped) before completing.
///
/// On the normal path (success or handled error), the guard is defused before
/// drop so that the regular cleanup code runs instead.
///
/// Unlike the normal paths, `Drop` is synchronous and so notifies without
/// taking the state lock. A caller that has read `refresh_in_progress` as
/// `true` and is on its way into
/// [`wait_for_in_flight_refresh`](AutoRefresh::wait_for_in_flight_refresh)
/// holds that lock, which does not block this notification — so if the refresh
/// future is cancelled in that window, the wake still lands on an empty list
/// and that caller parks with nothing left to wake it. The `enable()` call in
/// `wait_for_in_flight_refresh` does not close this narrower variant; doing so
/// needs the notify moved under the state lock or a bounded wait, and is
/// tracked separately.
struct CancelGuard<'a> {
    in_progress: &'a AtomicBool,
    notify: &'a Notify,
    defused: bool,
}

impl Drop for CancelGuard<'_> {
    fn drop(&mut self) {
        if !self.defused {
            self.in_progress.store(false, Ordering::Release);
            self.notify.notify_waiters();
        }
    }
}

impl CancelGuard<'_> {
    fn defuse(&mut self) {
        self.defused = true;
    }
}

impl State {
    fn new(token: Option<Token>) -> Self {
        Self {
            token,
            denial: None,
            last_refresh_error: None,
        }
    }

    /// Record the outcome of a failed refresh attempt. Every failure path
    /// calls this exactly once, so the two things a failure needs to update
    /// can't drift apart by a call site remembering one and not the other:
    ///
    /// - if `err` refuses the *account* rather than the credential, it
    ///   becomes the sticky, TTL'd [`denial`](Self::fresh_denial) replayed to
    ///   this refresher's own future `get_token` calls. A usage limit is
    ///   different in kind from most non-retryable failures: the credential
    ///   was never the problem, so re-presenting it cannot change the answer.
    ///   See [`AuthError::is_account_refusal`] for why this is narrower than
    ///   [`is_retryable`](crate::AuthError::is_retryable).
    /// - `err` always becomes [`last_refresh_error`](Self::last_refresh_error),
    ///   regardless of its class, for any caller parked in
    ///   `wait_for_in_flight_refresh` to see the same answer this refresh
    ///   attempt actually got.
    fn record_refusal(&mut self, err: &crate::AuthError, now: u64) {
        if err.is_account_refusal() {
            self.denial = Some(StickyDenial::new(err, now));
        }
        self.last_refresh_error = Some((err.error_code(), err.to_string()));
    }

    /// The error from the most recently completed refresh attempt, if it
    /// failed and no success has happened since.
    fn last_refresh_error(&self) -> Option<crate::AuthError> {
        self.last_refresh_error.as_ref().map(|(code, message)| {
            crate::AuthError::from_error_code(code, message, &serde_json::Map::new())
        })
    }

    /// The recorded refusal if it is still within its window, discarding it if
    /// not so the next attempt goes back to the network.
    fn fresh_denial(&mut self, now: u64) -> Option<crate::AuthError> {
        match &self.denial {
            Some(denial) if !denial.is_stale(now) => Some(denial.to_error()),
            Some(_) => {
                self.denial = None;
                None
            }
            None => None,
        }
    }

    fn service_token(&self) -> Result<ServiceToken, AutoRefreshError> {
        let token = self.token.as_ref().ok_or(AutoRefreshError::NotFound)?;
        Ok(ServiceToken::new(token.access_token().clone()))
    }

    fn require_usable_token(&self, now: u64) -> Result<ServiceToken, AutoRefreshError> {
        let token = self.token.as_ref().ok_or(AutoRefreshError::NotFound)?;
        if token.is_usable_at(now) {
            Ok(ServiceToken::new(token.access_token().clone()))
        } else {
            Err(AutoRefreshError::Expired)
        }
    }
}

impl<R> AutoRefresh<R, NoStore> {
    /// Create a new `AutoRefresh` with a pre-loaded token and no external store.
    ///
    /// Use this for refreshers that cannot self-authenticate (e.g. OAuth,
    /// which needs a refresh token from a prior device code flow).
    pub(crate) fn with_token(refresher: R, token: Token) -> Self {
        Self {
            refresher,
            state: Mutex::new(State::new(Some(token))),
            store: NoStore,
            refresh_in_progress: AtomicBool::new(false),
            refresh_notify: Notify::new(),
            clock: system_clock(),
        }
    }

    /// Like [`with_token`](Self::with_token) but with an injected clock, so tests
    /// can drive token expiry deterministically.
    #[cfg(test)]
    #[cfg(feature = "http")]
    pub(crate) fn with_token_and_clock(refresher: R, token: Token, clock: SharedClock) -> Self {
        Self {
            refresher,
            state: Mutex::new(State::new(Some(token))),
            store: NoStore,
            refresh_in_progress: AtomicBool::new(false),
            refresh_notify: Notify::new(),
            clock,
        }
    }
}

impl<R, S: TokenStore> AutoRefresh<R, S> {
    /// Create a new `AutoRefresh` backed by `store` and no in-memory token.
    ///
    /// On the first `get_token` call the store is consulted before falling
    /// through to initial authentication via `try_credential(None)`; every
    /// successful refresh writes the new token back via `store.save()`. Pass
    /// [`NoStore`] for the no-external-cache case — it's the default and
    /// elides to a zero-cost no-op.
    pub(crate) fn with_store(refresher: R, store: S) -> Self {
        Self {
            refresher,
            state: Mutex::new(State::new(None)),
            store,
            refresh_in_progress: AtomicBool::new(false),
            refresh_notify: Notify::new(),
            clock: system_clock(),
        }
    }
}

impl<R, S> AutoRefresh<R, S> {
    /// The refresher this engine renews through.
    pub(crate) fn refresher(&self) -> &R {
        &self.refresher
    }
}

impl<R: Refresher, S: TokenStore> AutoRefresh<R, S> {
    /// Retrieve a valid access token, refreshing or re-authenticating as needed.
    pub(crate) async fn get_token(&self) -> Result<ServiceToken, AutoRefreshError> {
        let mut state = self.state.lock().await;

        if state.token.is_none() {
            // A settled account-level refusal is checked before the store
            // read: without this, every `get_token` call during the denial
            // window turns the suppressed HTTP storm against CTS into an
            // identical storm against the caller's own store backend instead.
            if let Some(err) = state.fresh_denial(self.clock.now_unix_secs()) {
                return Err(AutoRefreshError::Auth(err));
            }
            // Drop the lock for the store read so a slow user-supplied backend
            // (cookie, KV, Redis) doesn't serialise concurrent `get_token`
            // callers. Re-acquire and double-check `state.token.is_none()` in
            // case another caller populated it while we awaited.
            drop(state);
            let loaded = self.store.load().await;
            state = self.state.lock().await;
            if state.token.is_none() {
                state.token = loaded;
            }
        }

        // Read "now" once from the injected clock and use it for every expiry
        // decision in this call — token expiry and refusal expiry alike — so
        // the checks are mutually consistent and deterministic under test.
        let now = self.clock.now_unix_secs();

        if state.token.is_none() {
            if let Some(err) = state.fresh_denial(now) {
                return Err(AutoRefreshError::Auth(err));
            }
            return self.initial_auth(&mut state).await;
        }

        if !state.token.as_ref().is_some_and(|t| t.is_expired_at(now)) {
            return state.service_token();
        }

        if self.refresh_in_progress.load(Ordering::Acquire) {
            return self.wait_for_in_flight_refresh(state, now).await;
        }

        // A settled refusal stands until something outside this client changes.
        // Checked before `try_credential`, which moves the credential out of
        // the cached token and would need restoring on an early return.
        if let Some(err) = state.fresh_denial(now) {
            return if state.token.as_ref().is_some_and(|t| t.is_usable_at(now)) {
                state.service_token()
            } else {
                Err(AutoRefreshError::Auth(err))
            };
        }

        let Some(credential) = self.refresher.try_credential(state.token.as_mut()) else {
            return state.require_usable_token(now);
        };

        self.refresh_in_progress.store(true, Ordering::Release);

        if state.token.as_ref().is_some_and(|t| t.is_usable_at(now)) {
            self.refresh_non_blocking(state, credential).await
        } else {
            self.refresh_blocking(&mut state, credential).await
        }
    }

    /// No cached token — authenticate via `try_credential(None)`.
    ///
    /// The lock is held throughout to prevent concurrent initial-auth attempts.
    async fn initial_auth(&self, state: &mut State) -> Result<ServiceToken, AutoRefreshError> {
        let Some(credential) = self.refresher.try_credential(None) else {
            return Err(AutoRefreshError::NotFound);
        };
        self.refresh_in_progress.store(true, Ordering::Release);
        let mut guard = CancelGuard {
            in_progress: &self.refresh_in_progress,
            notify: &self.refresh_notify,
            defused: false,
        };
        match self.refresher.refresh(&credential).await {
            Ok(new_token) => {
                self.save_refreshed_token(&new_token).await;
                let token = self.install_refreshed_token(state, new_token);
                guard.defuse();
                Ok(token)
            }
            Err(err) => {
                guard.defuse();
                self.refresh_in_progress.store(false, Ordering::Release);
                state.record_refusal(&err, self.clock.now_unix_secs());
                Err(AutoRefreshError::Auth(err))
            }
        }
    }

    /// Persist a freshly refreshed token to the per-refresher sink and the
    /// user-supplied `TokenStore`. Awaits the store write, so callers should
    /// drop the state lock before invoking this where possible (the
    /// non-blocking refresh path does; the blocking/initial paths hold the
    /// state lock throughout by design).
    async fn save_refreshed_token(&self, new_token: &Token) {
        self.refresher.save(new_token);
        self.store.save(new_token).await;
    }

    /// Install a freshly refreshed token in `state`, clear the in-progress
    /// flag, and return the corresponding [`ServiceToken`]. Pure in-lock
    /// work; caller is responsible for having already persisted the token via
    /// [`save_refreshed_token`](Self::save_refreshed_token).
    fn install_refreshed_token(&self, state: &mut State, new_token: Token) -> ServiceToken {
        let service_token = ServiceToken::new(new_token.access_token().clone());
        state.token = Some(new_token);
        // A success proves whatever previously refused us has changed its mind.
        state.denial = None;
        state.last_refresh_error = None;
        self.refresh_in_progress.store(false, Ordering::Release);
        service_token
    }

    /// Another caller is already refreshing — return the current token if still
    /// usable, otherwise wait for the in-flight refresh to complete via `Notify`.
    ///
    /// Takes `MutexGuard` by value because the lock is dropped before awaiting
    /// the notification.
    async fn wait_for_in_flight_refresh(
        &self,
        state: MutexGuard<'_, State>,
        now: u64,
    ) -> Result<ServiceToken, AutoRefreshError> {
        if let Ok(token) = state.service_token() {
            if state.token.as_ref().is_some_and(|t| t.is_usable_at(now)) {
                return Ok(token);
            }
        }
        // Token crossed real expiry during in-flight refresh. Wait for the
        // refresh to complete rather than returning Expired.
        //
        // `Notified` does not join the notify list until it is first polled,
        // and `notify_waiters` stores no permit for futures that are not yet
        // on it. Registering only at `.await` would leave a window after the
        // lock drops in which the in-flight refresh can complete, notify an
        // empty list, and leave this caller parked until some later refresh
        // cycle notifies again — which for an idle client may be never.
        // `enable()` joins the list while the state lock is still held, and
        // `refresh_non_blocking` takes that same lock to record its outcome
        // before it notifies, so the notification cannot land before we are
        // listed. This does not cover `CancelGuard::drop`, which notifies
        // without the lock — see the note on that impl.
        let mut notified = std::pin::pin!(self.refresh_notify.notified());
        // The `bool` reports whether a stored permit was consumed, which only
        // `notify_one` produces; this `Notify` is only ever driven by
        // `notify_waiters`, so there is nothing to act on.
        let _ = notified.as_mut().enable();
        drop(state);
        notified.await;
        // Re-check after wake — refresh may have failed. Re-read the clock: an
        // arbitrary amount of time may have passed while awaiting the refresh.
        let now = self.clock.now_unix_secs();
        let mut state = self.state.lock().await;
        match state.require_usable_token(now) {
            Ok(token) => Ok(token),
            // The refresh we waited on may have failed with a refusal that no
            // retry clears. It is already recorded — `refresh_non_blocking`
            // records before `notify_waiters` wakes us — so reporting
            // `Expired` here would tell every caller *except* the one that
            // issued the request that their token lapsed. That is the same
            // misdiagnosis `refresh_blocking` stopped making, reached by a
            // different route: it sends the caller round the refresh loop
            // that just failed, for a condition only a plan upgrade or
            // support can clear.
            //
            // A still-usable token still wins, matching the pre-refresh path
            // in `get_token`: a settled refusal suppresses further requests,
            // it does not invalidate a credential that still works.
            Err(unusable) => match state.fresh_denial(now) {
                Some(err) => Err(AutoRefreshError::Auth(err)),
                // Not an account-level refusal (or none was recorded) — fall
                // back to whatever the refresh actually returned, so this
                // caller sees the same typed error the issuer would have
                // (e.g. `invalid_grant`, a rotated/revoked refresh token)
                // rather than a generic `Expired` that discards it. Skipped
                // when the recorded error already *is* `TokenExpired` — that
                // degrades to the same `AuthError` as `unusable` once
                // unwrapped, so there's nothing more specific to surface.
                None => match state.last_refresh_error() {
                    Some(err) if !matches!(err, crate::AuthError::TokenExpired(_)) => {
                        Err(AutoRefreshError::Auth(err))
                    }
                    _ => Err(unusable),
                },
            },
        }
    }

    /// Token is expiring but still usable — drop the lock, refresh in the
    /// background of this call, and return the old (still-valid) token.
    ///
    /// Takes `MutexGuard` by value because the lock is dropped before the HTTP
    /// request. Notifies waiters after the refresh completes (success or error).
    ///
    /// A [`CancelGuard`] ensures that if this future is cancelled at any point
    /// before the new token is installed — including the post-HTTP save +
    /// install window — `refresh_in_progress` is cleared and waiters are
    /// notified, so subsequent callers don't hang in
    /// [`wait_for_in_flight_refresh`](Self::wait_for_in_flight_refresh).
    /// The credential is not restored on cancellation (it's already gone from
    /// `state.token`), so the next caller will get whatever the cached token
    /// offers — usable, expired, or absent.
    async fn refresh_non_blocking(
        &self,
        state: MutexGuard<'_, State>,
        credential: R::Credential,
    ) -> Result<ServiceToken, AutoRefreshError> {
        let current_service_token = state.service_token()?;
        drop(state);

        let mut guard = CancelGuard {
            in_progress: &self.refresh_in_progress,
            notify: &self.refresh_notify,
            defused: false,
        };

        let result = match self.refresher.refresh(&credential).await {
            Ok(new_token) => {
                self.save_refreshed_token(&new_token).await;
                let mut state = self.state.lock().await;
                let _ = self.install_refreshed_token(&mut state, new_token);
                guard.defuse();
                Ok(current_service_token)
            }
            Err(err) => {
                let consumed = credential_consumed(&err);
                if consumed {
                    tracing::error!(%err, "refreshed token could not be persisted");
                } else {
                    tracing::warn!(%err, "token refresh failed (token still usable)");
                }
                // Defer `defuse()` until after the lock acquire so the
                // CancelGuard's Drop still fires if cancellation lands on
                // `state.lock().await`. Without this the in-progress flag
                // would stay set with no `notify_waiters`, wedging every
                // subsequent caller exactly like the Ok-path bug fixed
                // earlier in this file.
                let mut state = self.state.lock().await;
                if !consumed {
                    if let Some(token) = state.token.as_mut() {
                        self.refresher.restore(token, credential);
                    }
                }
                self.refresh_in_progress.store(false, Ordering::Release);
                // Record the refusal so the next call doesn't re-issue the
                // same request (if it's account-level), and so a caller parked
                // in `wait_for_in_flight_refresh` sees the same answer this
                // refresh actually got (regardless of its class).
                state.record_refusal(&err, self.clock.now_unix_secs());
                guard.defuse();
                // An ordinary failure leaves the cached token usable, so this
                // call still succeeds. A consumed credential does not: the
                // rotation happened upstream but was lost, and succeeding
                // would hide that until the cached token expires.
                if consumed {
                    Err(AutoRefreshError::Auth(err))
                } else {
                    Ok(current_service_token)
                }
            }
        };

        self.refresh_notify.notify_waiters();
        result
    }

    /// Token is fully expired — refresh while holding the lock so concurrent
    /// callers block on `lock().await` until the new token is available.
    ///
    /// A [`CancelGuard`] ensures that if this future is cancelled at any point
    /// before the new token is installed — including the post-HTTP save
    /// window — `refresh_in_progress` is cleared and waiters are notified so
    /// they don't hang indefinitely. (The credential is lost on cancel —
    /// see [`CancelGuard`] docs — but subsequent callers will get `Expired`
    /// rather than blocking forever.)
    async fn refresh_blocking(
        &self,
        state: &mut State,
        credential: R::Credential,
    ) -> Result<ServiceToken, AutoRefreshError> {
        let mut guard = CancelGuard {
            in_progress: &self.refresh_in_progress,
            notify: &self.refresh_notify,
            defused: false,
        };
        match self.refresher.refresh(&credential).await {
            Ok(new_token) => {
                self.save_refreshed_token(&new_token).await;
                let token = self.install_refreshed_token(state, new_token);
                guard.defuse();
                Ok(token)
            }
            Err(err) => {
                guard.defuse();
                tracing::warn!(%err, "token refresh failed");
                if !credential_consumed(&err) {
                    if let Some(token) = state.token.as_mut() {
                        self.refresher.restore(token, credential);
                    }
                }
                self.refresh_in_progress.store(false, Ordering::Release);
                state.record_refusal(&err, self.clock.now_unix_secs());
                // Propagate the refuser's own answer. Flattening to `Expired`
                // here would tell a caller who is over their usage limit that
                // their token expired, and send them round the same loop.
                Err(AutoRefreshError::Auth(err))
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "http")]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::device_session_refresher::DeviceSessionRefresher;
    use crate::SecretToken;
    use mocktail::prelude::*;
    use stack_profile::ProfileStore;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn auto_refresh_error_maps_to_public_auth_error() {
        use crate::AuthError;
        assert!(matches!(
            AuthError::from(AutoRefreshError::NotFound),
            AuthError::NotAuthenticated(_)
        ));
        assert!(matches!(
            AuthError::from(AutoRefreshError::Expired),
            AuthError::TokenExpired(_)
        ));
        // The `Auth` variant passes the inner error through unchanged.
        assert!(matches!(
            AuthError::from(AutoRefreshError::Auth(AuthError::AccessDenied(
                crate::error::AccessDenied
            ))),
            AuthError::AccessDenied(_)
        ));
    }

    /// The guard's contract, directly: armed, its drop clears the in-progress
    /// flag (the cancellation path); defused, its drop leaves the flag to
    /// the normal path that already owns it. A defused guard that still
    /// fired would clear the flag out from under a refresh another caller
    /// started after this one installed its token.
    #[test]
    fn a_defused_cancel_guard_leaves_the_flag_alone() {
        let in_progress = AtomicBool::new(true);
        let notify = Notify::new();

        let mut guard = CancelGuard {
            in_progress: &in_progress,
            notify: &notify,
            defused: false,
        };
        guard.defuse();
        drop(guard);
        assert!(
            in_progress.load(Ordering::Acquire),
            "a defused guard must not touch the flag"
        );

        drop(CancelGuard {
            in_progress: &in_progress,
            notify: &notify,
            defused: false,
        });
        assert!(
            !in_progress.load(Ordering::Acquire),
            "an armed guard clears the flag on drop"
        );
    }

    fn make_token(access: &str, expires_in: u64, refresh: bool) -> Token {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Token {
            access_token: SecretToken::new(access),
            token_type: "Bearer".to_string(),
            expires_at: now + expires_in,
            refresh_token: if refresh {
                Some(SecretToken::new("test-refresh-token"))
            } else {
                None
            },
            region: None,
            client_id: None,
            device_instance_id: None,
            federated_from: None,
        }
    }

    fn refresh_response_json(access: &str) -> serde_json::Value {
        serde_json::json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new-refresh-token"
        })
    }

    fn error_json(error: &str) -> serde_json::Value {
        serde_json::json!({
            "error": error,
            "error_description": format!("{error} occurred")
        })
    }

    async fn start_server(mocks: MockSet) -> MockServer {
        let server = MockServer::new_http("auto-refresh-test").with_mocks(mocks);
        server.start().await.unwrap();
        server
    }

    fn auto_refresh_with_token(
        dir: &tempfile::TempDir,
        server: &MockServer,
        token: Token,
    ) -> AutoRefresh<DeviceSessionRefresher> {
        let store = ProfileStore::new(dir.path());
        store.init_workspace("ZVATKW3VHMFG27DY").unwrap();
        let ws_store = store.current_workspace_store().unwrap();
        ws_store.save_profile(&token).unwrap();
        let refresher = DeviceSessionRefresher::new(
            Some(ws_store),
            server.url(""),
            "cli",
            "ap-southeast-2.aws",
            None,
            crate::transport::default_transport(),
        );
        AutoRefresh::with_token(refresher, token)
    }

    mod given_no_cached_token {
        use super::*;

        #[tokio::test]
        async fn returns_not_found_for_oauth() {
            let server = start_server(MockSet::new()).await;
            let store = ProfileStore::new("/tmp/nonexistent");
            let refresher = DeviceSessionRefresher::new(
                Some(store),
                server.url(""),
                "cli",
                "ap-southeast-2.aws",
                None,
                crate::transport::default_transport(),
            );
            let strategy = AutoRefresh::with_store(refresher, NoStore);

            let err = strategy.get_token().await.unwrap_err();

            assert!(
                matches!(err, AutoRefreshError::NotFound),
                "expected NotFound, got: {err:?}"
            );
        }
    }

    /// A settled account-level denial must short-circuit before the store is
    /// consulted, not just before the network call to CTS. Otherwise every
    /// `get_token` during the denial window turns the suppressed HTTP storm
    /// against CTS into an identical storm against the caller's own store
    /// backend (a cookie, a KV store, Redis) for the whole window instead.
    mod given_a_fresh_sticky_denial_and_no_cached_token {
        use super::*;
        use crate::token_store::TokenStore;
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// `TokenStore` that always misses, counting how many times `load` is
        /// called.
        struct CountingStore {
            load_calls: Arc<AtomicUsize>,
        }

        impl TokenStore for CountingStore {
            async fn load(&self) -> Option<Token> {
                self.load_calls.fetch_add(1, Ordering::SeqCst);
                None
            }

            async fn save(&self, _token: &Token) {}
        }

        /// `Refresher` that can authenticate from cold (no prior token) but
        /// always has its refresh refused as over the usage limit.
        struct AlwaysOverLimitRefresher;

        impl Refresher for AlwaysOverLimitRefresher {
            type Credential = ();

            fn save(&self, _token: &Token) {}

            fn try_credential(&self, _token: Option<&mut Token>) -> Option<Self::Credential> {
                Some(())
            }

            fn restore(&self, _token: &mut Token, _credential: Self::Credential) {}

            async fn refresh(
                &self,
                _credential: &Self::Credential,
            ) -> Result<Token, crate::AuthError> {
                Err(crate::AuthError::UsageLimitExceeded(
                    crate::error::UsageLimitExceeded("over limit".to_string()),
                ))
            }
        }

        #[tokio::test]
        async fn does_not_re_hit_the_store_while_the_denial_is_fresh() {
            let load_calls = Arc::new(AtomicUsize::new(0));
            let store = CountingStore {
                load_calls: Arc::clone(&load_calls),
            };
            let strategy = AutoRefresh::with_store(AlwaysOverLimitRefresher, store);

            let first = strategy.get_token().await;
            assert!(
                matches!(
                    first,
                    Err(AutoRefreshError::Auth(
                        crate::AuthError::UsageLimitExceeded(_)
                    ))
                ),
                "expected UsageLimitExceeded, got: {first:?}"
            );
            assert_eq!(
                load_calls.load(Ordering::SeqCst),
                1,
                "the first call has no denial recorded yet, so it must still consult the store"
            );

            let second = strategy.get_token().await;
            assert!(
                matches!(
                    second,
                    Err(AutoRefreshError::Auth(
                        crate::AuthError::UsageLimitExceeded(_)
                    ))
                ),
                "expected UsageLimitExceeded, got: {second:?}"
            );
            assert_eq!(
                load_calls.load(Ordering::SeqCst),
                1,
                "a fresh sticky denial must short-circuit before the store is consulted again"
            );
        }
    }

    mod given_fresh_token {
        use super::*;

        #[tokio::test]
        async fn returns_cached_token() {
            let dir = tempfile::tempdir().unwrap();
            let server = start_server(MockSet::new()).await;
            let strategy =
                auto_refresh_with_token(&dir, &server, make_token("my-access-token", 3600, false));

            let token = strategy.get_token().await.unwrap();

            assert_eq!(
                token.as_str(),
                "my-access-token",
                "should return the cached access token"
            );
        }

        #[tokio::test]
        async fn caches_across_calls() {
            let dir = tempfile::tempdir().unwrap();
            let server = start_server(MockSet::new()).await;
            let strategy =
                auto_refresh_with_token(&dir, &server, make_token("my-access-token", 3600, false));

            let token1 = strategy.get_token().await.unwrap();
            assert_eq!(
                token1.as_str(),
                "my-access-token",
                "first call should return the cached token"
            );

            // Delete the file — second call should still return the cached token.
            std::fs::remove_file(
                dir.path()
                    .join("workspaces")
                    .join("ZVATKW3VHMFG27DY")
                    .join("auth.json"),
            )
            .unwrap();

            let token2 = strategy.get_token().await.unwrap();
            assert_eq!(
                token2.as_str(),
                "my-access-token",
                "second call should return the cached token even after file deletion"
            );
        }

        #[tokio::test]
        async fn does_not_trigger_refresh() {
            // Mock that would fail if hit — proves no refresh request is made.
            let mut mocks = MockSet::new();
            mocks.mock(|when, then| {
                when.post().path("/oauth/token");
                then.internal_server_error()
                    .json(error_json("should_not_be_called"));
            });
            let server = start_server(mocks).await;
            let dir = tempfile::tempdir().unwrap();
            let strategy =
                auto_refresh_with_token(&dir, &server, make_token("fresh-token", 3600, true));

            let token = strategy.get_token().await.unwrap();

            assert_eq!(
                token.as_str(),
                "fresh-token",
                "should return fresh token without triggering refresh"
            );
        }
    }

    mod given_fully_expired_token {
        use super::*;

        mod without_refresh_token {
            use super::*;

            #[tokio::test]
            async fn returns_expired() {
                let dir = tempfile::tempdir().unwrap();
                let server = start_server(MockSet::new()).await;
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("old-token", 0, false));

                let err = strategy.get_token().await.unwrap_err();

                assert!(
                    matches!(err, AutoRefreshError::Expired),
                    "expected Expired, got: {err:?}"
                );
            }
        }

        mod with_refresh_token {
            use super::*;

            #[tokio::test]
            async fn refreshes_and_returns_new_token() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.json(refresh_response_json("refreshed-token"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

                let token = strategy.get_token().await.unwrap();

                assert_eq!(
                    token.as_str(),
                    "refreshed-token",
                    "should return the refreshed token"
                );
            }

            #[tokio::test]
            async fn persists_refreshed_token_to_disk() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.json(refresh_response_json("refreshed-token"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

                let _ = strategy.get_token().await.unwrap();

                // Verify the refreshed token was saved to the workspace directory.
                let store = ProfileStore::new(dir.path());
                let ws_store = store.current_workspace_store().unwrap();
                let on_disk: Token = ws_store.load_profile().unwrap();
                assert_eq!(
                    on_disk.access_token().as_str(),
                    "refreshed-token",
                    "refreshed token should be persisted to disk"
                );
            }

            #[tokio::test]
            async fn returns_the_servers_refusal_on_refresh_failure() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.bad_request().json(error_json("invalid_grant"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

                let err = strategy.get_token().await.unwrap_err();

                assert!(
                    matches!(
                        err,
                        AutoRefreshError::Auth(crate::AuthError::InvalidGrant(_))
                    ),
                    "the caller must see the grant was rejected, not a generic \
                     Expired that invites the same doomed retry: {err:?}"
                );
            }

            #[tokio::test]
            async fn restores_refresh_token_after_failure() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.bad_request().json(error_json("invalid_grant"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

                // First call: refresh fails and the rejection reaches the caller.
                let err = strategy.get_token().await.unwrap_err();
                assert!(
                    matches!(
                        err,
                        AutoRefreshError::Auth(crate::AuthError::InvalidGrant(_))
                    ),
                    "expected the grant rejection on first attempt, got: {err:?}"
                );

                // Verify the refresh token was restored so a retry is possible.
                let state = strategy.state.lock().await;
                assert!(
                    state.token.is_some(),
                    "token should still be cached after failed refresh"
                );
                assert!(
                    state.token.as_ref().unwrap().refresh_token().is_some(),
                    "refresh token should be restored for retry"
                );
                drop(state);

                // Replace mock with a success response.
                server.mocks().clear();
                server.mocks().mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.json(refresh_response_json("refreshed-token"));
                });

                // Second call: refresh token is available → retry succeeds.
                let token = strategy.get_token().await.unwrap();
                assert_eq!(
                    token.as_str(),
                    "refreshed-token",
                    "retry should succeed with restored refresh token"
                );
            }

            #[tokio::test]
            async fn sequential_calls_only_refresh_once() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.json(refresh_response_json("refreshed-once"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

                // First call triggers refresh.
                let token = strategy.get_token().await.unwrap();
                assert_eq!(
                    token.as_str(),
                    "refreshed-once",
                    "first call should trigger refresh"
                );

                // Swap mock to track if another refresh is attempted.
                server.mocks().clear();
                server.mocks().mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.json(refresh_response_json("refreshed-twice"));
                });

                // Calls 2-5: the refreshed token is fresh, so no further refresh.
                for _ in 0..4 {
                    let token = strategy.get_token().await.unwrap();
                    assert_eq!(
                        token.as_str(),
                        "refreshed-once",
                        "should return cached refreshed token, not trigger another refresh"
                    );
                }
            }

            #[tokio::test]
            async fn prevents_second_refresh_after_success() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.json(refresh_response_json("refreshed-token"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("old-token", 0, true));

                // First call refreshes successfully.
                let token = strategy.get_token().await.unwrap();
                assert_eq!(
                    token.as_str(),
                    "refreshed-token",
                    "first call should refresh the token"
                );

                // Replace the mock with one that errors.
                server.mocks().clear();
                server.mocks().mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.bad_request().json(error_json("should_not_be_called"));
                });

                // Second call should return the refreshed token without hitting
                // the server again (the new token has a fresh expiry).
                let token = strategy.get_token().await.unwrap();
                assert_eq!(
                    token.as_str(),
                    "refreshed-token",
                    "second call should return cached refreshed token"
                );
            }
        }
    }

    mod given_expiring_but_usable_token {
        use super::*;

        mod when_refresh_fails {
            use super::*;

            #[tokio::test]
            async fn returns_current_token() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.bad_request().json(error_json("server_error"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                // Token expires in 30s (within the 90s leeway so is_expired() = true),
                // but the access token is still technically usable.
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("still-usable", 30, true));

                // The refresh fails, but the access token should still be returned
                // because it's still usable (30s remaining > 0).
                let token = strategy.get_token().await.unwrap();
                assert_eq!(
                    token.as_str(),
                    "still-usable",
                    "should return still-usable token despite failed refresh"
                );

                // Verify the access token and refresh token are still present.
                let state = strategy.state.lock().await;
                assert!(state.token.is_some(), "token should still be cached");
                assert_eq!(
                    state.token.as_ref().unwrap().access_token().as_str(),
                    "still-usable",
                    "access token should be unchanged after failed refresh"
                );
                assert!(
                    state.token.as_ref().unwrap().refresh_token().is_some(),
                    "refresh token should be restored after failed refresh"
                );
            }

            #[tokio::test]
            async fn restores_refresh_token_for_retry() {
                let mut mocks = MockSet::new();
                mocks.mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.bad_request().json(error_json("server_error"));
                });
                let server = start_server(mocks).await;
                let dir = tempfile::tempdir().unwrap();
                // Token expires in 30s — is_expired() = true, is_usable() = true.
                let strategy =
                    auto_refresh_with_token(&dir, &server, make_token("still-usable", 30, true));

                // First call: refresh fails, but the still-usable token is returned.
                let token = strategy.get_token().await.unwrap();
                assert_eq!(
                    token.as_str(),
                    "still-usable",
                    "first call should return still-usable token"
                );

                // Replace mock with a success response.
                server.mocks().clear();
                server.mocks().mock(|when, then| {
                    when.post().path("/oauth/token");
                    then.json(refresh_response_json("refreshed-token"));
                });

                // Second call: refresh token was restored, so the retry succeeds.
                let token = strategy.get_token().await.unwrap();
                assert!(
                    token.as_str() == "still-usable" || token.as_str() == "refreshed-token",
                    "expected old or refreshed token, got: {}",
                    token.as_str()
                );

                // Verify the cache now holds the refreshed token.
                let state = strategy.state.lock().await;
                assert_eq!(
                    state.token.as_ref().unwrap().access_token().as_str(),
                    "refreshed-token",
                    "cache should hold the refreshed token after retry"
                );
            }
        }
    }

    /// Makes every later `auth.json` write fail: the atomic save renames a
    /// temp file over the target, which cannot replace a non-empty directory.
    fn break_token_persistence(dir: &tempfile::TempDir) {
        use stack_profile::ProfileData;
        let path = ProfileStore::new(dir.path())
            .workspace_store("ZVATKW3VHMFG27DY")
            .unwrap()
            .dir()
            .join(Token::FILENAME);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("occupied"), b"").unwrap();
    }

    fn refreshing_server() -> MockSet {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/oauth/token");
            then.json(refresh_response_json("refreshed-token"));
        });
        mocks
    }

    /// The upstream exchange succeeds, so the refresh token it sent is spent.
    /// Restoring it would replay it on the next call and revoke the chain.
    mod given_a_refreshed_token_cannot_be_saved {
        use super::*;
        use crate::AuthError;

        #[tokio::test]
        async fn an_expiring_token_fails_the_call_and_drops_the_spent_refresh_token() {
            let server = start_server(refreshing_server()).await;
            let dir = tempfile::tempdir().unwrap();
            // Inside the refresh leeway but still usable: the non-blocking path.
            let strategy =
                auto_refresh_with_token(&dir, &server, make_token("still-usable", 30, true));
            break_token_persistence(&dir);

            let result = strategy.get_token().await;
            assert!(
                matches!(result, Err(AutoRefreshError::Auth(AuthError::Store(_)))),
                "a lost rotation must fail the call, got: {result:?}"
            );

            let state = strategy.state.lock().await;
            assert!(
                state.token.as_ref().unwrap().refresh_token().is_none(),
                "the spent refresh token must not be restored for replay"
            );
        }

        #[tokio::test]
        async fn an_expired_token_fails_the_call_and_drops_the_spent_refresh_token() {
            let server = start_server(refreshing_server()).await;
            let dir = tempfile::tempdir().unwrap();
            let mut token = make_token("expired", 0, true);
            token.expires_at -= 10;
            let strategy = auto_refresh_with_token(&dir, &server, token);
            break_token_persistence(&dir);

            let result = strategy.get_token().await;
            assert!(
                matches!(result, Err(AutoRefreshError::Auth(AuthError::Store(_)))),
                "a lost rotation must fail the call, got: {result:?}"
            );

            let state = strategy.state.lock().await;
            assert!(
                state.token.as_ref().unwrap().refresh_token().is_none(),
                "the spent refresh token must not be restored for replay"
            );
        }
    }

    mod given_concurrent_callers {
        use super::*;

        #[tokio::test]
        async fn returns_usable_token_while_refreshing() {
            let mut mocks = MockSet::new();
            mocks.mock(|when, then| {
                when.post().path("/oauth/token");
                then.json(refresh_response_json("refreshed-token"));
            });
            let server = start_server(mocks).await;
            let dir = tempfile::tempdir().unwrap();
            let strategy = Arc::new(auto_refresh_with_token(
                &dir,
                &server,
                make_token("still-usable", 30, true),
            ));

            let s1 = Arc::clone(&strategy);
            let handle_a = tokio::spawn(async move { s1.get_token().await.unwrap() });

            let s2 = Arc::clone(&strategy);
            let handle_b = tokio::spawn(async move { s2.get_token().await.unwrap() });

            let (result_a, result_b) = tokio::join!(handle_a, handle_b);
            let token_a = result_a.unwrap();
            let token_b = result_b.unwrap();

            assert!(
                token_a.as_str() == "still-usable" || token_a.as_str() == "refreshed-token",
                "unexpected token_a: {}",
                token_a.as_str()
            );
            assert!(
                token_b.as_str() == "still-usable" || token_b.as_str() == "refreshed-token",
                "unexpected token_b: {}",
                token_b.as_str()
            );
        }

        #[tokio::test]
        async fn blocks_until_refresh_completes() {
            let mut mocks = MockSet::new();
            mocks.mock(|when, then| {
                when.post().path("/oauth/token");
                then.json(refresh_response_json("refreshed-token"));
            });
            let server = start_server(mocks).await;
            let dir = tempfile::tempdir().unwrap();
            let strategy = Arc::new(auto_refresh_with_token(
                &dir,
                &server,
                make_token("expired-token", 0, true),
            ));

            let s1 = Arc::clone(&strategy);
            let handle_a = tokio::spawn(async move { s1.get_token().await.unwrap() });

            let s2 = Arc::clone(&strategy);
            let handle_b = tokio::spawn(async move { s2.get_token().await.unwrap() });

            let (result_a, result_b) = tokio::join!(handle_a, handle_b);
            let token_a = result_a.unwrap();
            let token_b = result_b.unwrap();

            assert_eq!(
                token_a.as_str(),
                "refreshed-token",
                "caller a should receive refreshed token"
            );
            assert_eq!(
                token_b.as_str(),
                "refreshed-token",
                "caller b should receive refreshed token"
            );
        }
    }
}

#[cfg(test)]
#[cfg(feature = "http")]
#[allow(clippy::unwrap_used)]
mod stress_tests {
    use super::*;
    use crate::device_session_refresher::DeviceSessionRefresher;
    use crate::SecretToken;
    use stack_profile::ProfileStore;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    /// Tracks in-flight and peak concurrency for test assertions.
    #[derive(Clone)]
    struct CountingState {
        total: Arc<AtomicUsize>,
        current: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    impl CountingState {
        fn new() -> Self {
            Self {
                total: Arc::new(AtomicUsize::new(0)),
                current: Arc::new(AtomicUsize::new(0)),
                peak: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn enter(&self) {
            self.total.fetch_add(1, Ordering::SeqCst);
            let prev = self.current.fetch_add(1, Ordering::SeqCst);
            self.peak.fetch_max(prev + 1, Ordering::SeqCst);
        }

        fn exit(&self) {
            self.current.fetch_sub(1, Ordering::SeqCst);
        }

        fn peak(&self) -> usize {
            self.peak.load(Ordering::SeqCst)
        }

        fn total(&self) -> usize {
            self.total.load(Ordering::SeqCst)
        }
    }

    #[derive(Clone)]
    struct DelayedRefreshState {
        counting: CountingState,
        delay: Duration,
    }

    async fn delayed_refresh_handler(
        axum::extract::State(state): axum::extract::State<DelayedRefreshState>,
    ) -> axum::Json<serde_json::Value> {
        state.counting.enter();
        tokio::time::sleep(state.delay).await;
        state.counting.exit();
        axum::Json(serde_json::json!({
            "access_token": "refreshed-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new-refresh-token"
        }))
    }

    async fn delayed_error_handler(
        axum::extract::State(state): axum::extract::State<DelayedRefreshState>,
    ) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
        state.counting.enter();
        tokio::time::sleep(state.delay).await;
        state.counting.exit();
        (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "invalid_grant occurred"
            })),
        )
    }

    async fn start_axum_server<H, T>(
        handler: H,
        state: DelayedRefreshState,
    ) -> (url::Url, CountingState)
    where
        H: axum::handler::Handler<T, DelayedRefreshState> + Clone + Send + 'static,
        T: 'static,
    {
        let counting = state.counting.clone();
        let app = axum::Router::new()
            .route("/oauth/token", axum::routing::post(handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base_url = url::Url::parse(&format!("http://{addr}")).unwrap();
        (base_url, counting)
    }

    fn make_token(access: &str, expires_in: u64, refresh: bool) -> Token {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Token {
            access_token: SecretToken::new(access),
            token_type: "Bearer".to_string(),
            expires_at: now + expires_in,
            refresh_token: if refresh {
                Some(SecretToken::new("test-refresh-token"))
            } else {
                None
            },
            region: None,
            client_id: None,
            device_instance_id: None,
            federated_from: None,
        }
    }

    fn auto_refresh_with_token(
        dir: &tempfile::TempDir,
        base_url: &url::Url,
        token: Token,
    ) -> AutoRefresh<DeviceSessionRefresher> {
        let store = ProfileStore::new(dir.path());
        store.init_workspace("ZVATKW3VHMFG27DY").unwrap();
        let ws_store = store.current_workspace_store().unwrap();
        ws_store.save_profile(&token).unwrap();
        let refresher = DeviceSessionRefresher::new(
            Some(ws_store),
            base_url.clone(),
            "cli",
            "ap-southeast-2.aws",
            None,
            crate::transport::default_transport(),
        );
        AutoRefresh::with_token(refresher, token)
    }

    const CONCURRENCY: usize = 50;

    mod given_fresh_token {
        use super::*;

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn all_callers_return_immediately() {
            let counting = CountingState::new();
            let state = DelayedRefreshState {
                counting: counting.clone(),
                delay: Duration::from_millis(500),
            };
            let (base_url, stats) = start_axum_server(delayed_refresh_handler, state).await;
            let dir = tempfile::tempdir().unwrap();
            let strategy = Arc::new(auto_refresh_with_token(
                &dir,
                &base_url,
                make_token("fresh-token", 3600, true),
            ));

            let start = Instant::now();
            let mut handles = Vec::with_capacity(CONCURRENCY);
            for _ in 0..CONCURRENCY {
                let s = Arc::clone(&strategy);
                handles.push(tokio::spawn(async move { s.get_token().await.unwrap() }));
            }

            let results: Vec<_> = {
                let mut results = Vec::with_capacity(handles.len());
                for handle in handles {
                    results.push(handle.await.unwrap());
                }
                results
            };
            let elapsed = start.elapsed();

            for token in &results {
                assert_eq!(
                    token.as_str(),
                    "fresh-token",
                    "all callers should receive the fresh token"
                );
            }

            assert!(
                elapsed < Duration::from_millis(200),
                "expected < 200ms for fresh tokens, got {:?}",
                elapsed
            );
            assert_eq!(stats.total(), 0, "no refresh requests should be made");
        }
    }

    mod given_expiring_but_usable_token {
        use super::*;

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn non_blocking_reads_during_refresh() {
            let counting = CountingState::new();
            let state = DelayedRefreshState {
                counting: counting.clone(),
                delay: Duration::from_millis(500),
            };
            let (base_url, stats) = start_axum_server(delayed_refresh_handler, state).await;
            let dir = tempfile::tempdir().unwrap();
            let strategy = Arc::new(auto_refresh_with_token(
                &dir,
                &base_url,
                make_token("still-usable", 30, true),
            ));

            let start = Instant::now();
            let mut handles = Vec::with_capacity(CONCURRENCY);
            for _ in 0..CONCURRENCY {
                let s = Arc::clone(&strategy);
                handles.push(tokio::spawn(async move {
                    let call_start = Instant::now();
                    let token = s.get_token().await.unwrap();
                    (token, call_start.elapsed())
                }));
            }

            let results: Vec<_> = {
                let mut results = Vec::with_capacity(handles.len());
                for handle in handles {
                    results.push(handle.await.unwrap());
                }
                results
            };
            let elapsed = start.elapsed();

            for (token, _) in &results {
                assert!(
                    token.as_str() == "still-usable" || token.as_str() == "refreshed-token",
                    "unexpected token: {}",
                    token.as_str()
                );
            }

            let fast_callers = results
                .iter()
                .filter(|(_, dur)| *dur < Duration::from_millis(100))
                .count();
            assert!(
                fast_callers >= CONCURRENCY - 1,
                "expected at least {} fast callers, got {} (total elapsed: {:?})",
                CONCURRENCY - 1,
                fast_callers,
                elapsed
            );

            assert_eq!(stats.peak(), 1, "peak concurrency to refresh endpoint");
            assert_eq!(stats.total(), 1, "total refresh requests");
        }
    }

    mod given_fully_expired_token {
        use super::*;

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn all_callers_block_until_refresh() {
            let refresh_delay = Duration::from_millis(200);
            let counting = CountingState::new();
            let state = DelayedRefreshState {
                counting: counting.clone(),
                delay: refresh_delay,
            };
            let (base_url, stats) = start_axum_server(delayed_refresh_handler, state).await;
            let dir = tempfile::tempdir().unwrap();
            let strategy = Arc::new(auto_refresh_with_token(
                &dir,
                &base_url,
                make_token("expired-token", 0, true),
            ));

            let start = Instant::now();
            let mut handles = Vec::with_capacity(CONCURRENCY);
            for _ in 0..CONCURRENCY {
                let s = Arc::clone(&strategy);
                handles.push(tokio::spawn(async move { s.get_token().await.unwrap() }));
            }

            let results: Vec<_> = {
                let mut results = Vec::with_capacity(handles.len());
                for handle in handles {
                    results.push(handle.await.unwrap());
                }
                results
            };
            let elapsed = start.elapsed();

            for token in &results {
                assert_eq!(
                    token.as_str(),
                    "refreshed-token",
                    "all callers should receive refreshed token"
                );
            }

            assert!(
                elapsed < refresh_delay + Duration::from_millis(200),
                "expected < {:?} for blocked callers, got {:?}",
                refresh_delay + Duration::from_millis(200),
                elapsed
            );

            assert_eq!(stats.peak(), 1, "peak concurrency to refresh endpoint");
            assert_eq!(stats.total(), 1, "total refresh requests");
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn all_callers_receive_an_error_on_failure() {
            let counting = CountingState::new();
            let state = DelayedRefreshState {
                counting: counting.clone(),
                delay: Duration::from_millis(10),
            };
            let (base_url, stats) = start_axum_server(delayed_error_handler, state).await;
            let dir = tempfile::tempdir().unwrap();
            let strategy = Arc::new(auto_refresh_with_token(
                &dir,
                &base_url,
                make_token("expired-token", 0, true),
            ));

            let mut handles = Vec::with_capacity(CONCURRENCY);
            for _ in 0..CONCURRENCY {
                let s = Arc::clone(&strategy);
                handles.push(tokio::spawn(async move { s.get_token().await }));
            }

            let results: Vec<_> = {
                let mut results = Vec::with_capacity(handles.len());
                for handle in handles {
                    results.push(handle.await.unwrap());
                }
                results
            };

            // No caller may come away with a token. A fully-expired token
            // takes the *blocking* refresh path, which holds the state lock
            // across the whole HTTP call — so no other caller can ever be
            // concurrently parked in `wait_for_in_flight_refresh` while it
            // runs; every one of them queues on the lock itself and, on
            // acquiring it, performs (and fails) its own refresh in turn. So
            // every caller here sees the server's actual refusal directly,
            // not a generic `Expired` — this is asserted precisely, not just
            // "at least one caller does", so a change that lets some caller
            // fall through to `Expired` is caught.
            for result in &results {
                assert!(
                    matches!(
                        result,
                        Err(AutoRefreshError::Auth(crate::AuthError::InvalidGrant(_)))
                    ),
                    "every caller must receive the server's actual refusal, not a \
                     generic Expired: {result:?}"
                );
            }

            let state = strategy.state.lock().await;
            assert!(
                state.token.as_ref().unwrap().refresh_token().is_some(),
                "refresh token should be restored after failed refresh"
            );
            drop(state);

            assert_eq!(stats.peak(), 1, "peak concurrency to refresh endpoint");
            assert!(
                stats.total() >= 1,
                "at least one refresh attempt should be made"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn retry_succeeds_after_failure() {
            // Phase 1: Server returns errors.
            let counting1 = CountingState::new();
            let state1 = DelayedRefreshState {
                counting: counting1.clone(),
                delay: Duration::from_millis(50),
            };
            let (base_url, _) = start_axum_server(delayed_error_handler, state1).await;
            let dir = tempfile::tempdir().unwrap();
            let strategy = Arc::new(auto_refresh_with_token(
                &dir,
                &base_url,
                make_token("expired-token", 0, true),
            ));

            let mut handles = Vec::with_capacity(CONCURRENCY);
            for _ in 0..CONCURRENCY {
                let s = Arc::clone(&strategy);
                handles.push(tokio::spawn(async move { s.get_token().await }));
            }

            let results: Vec<_> = {
                let mut results = Vec::with_capacity(handles.len());
                for handle in handles {
                    results.push(handle.await.unwrap());
                }
                results
            };

            for result in &results {
                assert!(
                    result.is_err(),
                    "first wave: expected Expired, got Ok({})",
                    result.as_ref().unwrap().as_str()
                );
            }

            // Phase 2: New server that returns success.
            let counting2 = CountingState::new();
            let state2 = DelayedRefreshState {
                counting: counting2.clone(),
                delay: Duration::from_millis(50),
            };
            let (base_url2, stats2) = start_axum_server(delayed_refresh_handler, state2).await;

            let strategy2 = Arc::new(auto_refresh_with_token(
                &dir,
                &base_url2,
                make_token("expired-token", 0, true),
            ));

            let mut handles = Vec::with_capacity(CONCURRENCY);
            for _ in 0..CONCURRENCY {
                let s = Arc::clone(&strategy2);
                handles.push(tokio::spawn(async move { s.get_token().await.unwrap() }));
            }

            let results: Vec<_> = {
                let mut results = Vec::with_capacity(handles.len());
                for handle in handles {
                    results.push(handle.await.unwrap());
                }
                results
            };

            for token in &results {
                assert_eq!(
                    token.as_str(),
                    "refreshed-token",
                    "retry callers should receive refreshed token"
                );
            }

            assert_eq!(stats2.total(), 1, "only one retry refresh should be made");
        }
    }

    mod given_cancelled_refresh {
        use super::*;

        /// If a blocking refresh (fully expired token) is cancelled mid-flight,
        /// the `CancelGuard` must reset `refresh_in_progress` and notify waiters
        /// so the next caller doesn't hang in `wait_for_in_flight_refresh`.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn blocked_callers_recover_after_cancellation() {
            let counting = CountingState::new();
            let state = DelayedRefreshState {
                counting: counting.clone(),
                delay: Duration::from_secs(10), // Very slow — will be cancelled
            };
            let (base_url, _) = start_axum_server(delayed_refresh_handler, state).await;
            let dir = tempfile::tempdir().unwrap();
            let strategy = Arc::new(auto_refresh_with_token(
                &dir,
                &base_url,
                make_token("expired-token", 0, true),
            ));

            // Spawn get_token and let the blocking refresh start.
            let s = Arc::clone(&strategy);
            let handle = tokio::spawn(async move { s.get_token().await });
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Cancel the refresh mid-flight.
            handle.abort();
            let _ = handle.await;

            // The next caller must not hang. The credential is lost (refresh
            // token was taken before the HTTP call), so the result is Expired,
            // but the important thing is that it completes promptly.
            let s = Arc::clone(&strategy);
            let result = tokio::time::timeout(Duration::from_secs(2), s.get_token()).await;

            assert!(
                result.is_ok(),
                "get_token() should not hang after cancelled blocking refresh"
            );
        }

        /// Regression test: cancellation in the window *after* the upstream
        /// HTTP refresh succeeds but *before* the new token is installed must
        /// still clear `refresh_in_progress` and notify waiters. The previous
        /// implementation defused the [`CancelGuard`] before
        /// `save_refreshed_token`, so a drop during the (async) store-save or
        /// the subsequent state-lock acquire would strand the flag — wedging
        /// any caller that later hit `wait_for_in_flight_refresh`.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn save_phase_cancellation_does_not_strand_in_progress_flag() {
            use crate::token_store::TokenStore;

            /// Store that returns a single pre-loaded token from `load()` and
            /// delays inside `save()` long enough for a test to cancel.
            struct SlowSaveStore {
                initial: tokio::sync::Mutex<Option<Token>>,
                delay: Duration,
            }

            impl TokenStore for SlowSaveStore {
                async fn load(&self) -> Option<Token> {
                    self.initial.lock().await.take()
                }

                async fn save(&self, _token: &Token) {
                    tokio::time::sleep(self.delay).await;
                }
            }

            // Fast upstream HTTP — refresh succeeds in <50ms.
            let counting = CountingState::new();
            let state = DelayedRefreshState {
                counting: counting.clone(),
                delay: Duration::from_millis(10),
            };
            let (base_url, _) = start_axum_server(delayed_refresh_handler, state).await;
            let dir = tempfile::tempdir().unwrap();
            let store = ProfileStore::new(dir.path());
            store.init_workspace("ZVATKW3VHMFG27DY").unwrap();
            let ws_store = store.current_workspace_store().unwrap();
            let refresher = DeviceSessionRefresher::new(
                Some(ws_store),
                base_url,
                "cli",
                "ap-southeast-2.aws",
                None,
                crate::transport::default_transport(),
            );
            // Slow async save — cancellation reliably lands here, in the
            // post-HTTP / pre-install window.
            let slow_store = SlowSaveStore {
                initial: tokio::sync::Mutex::new(Some(make_token("expired-token", 0, true))),
                delay: Duration::from_secs(10),
            };
            let strategy = Arc::new(AutoRefresh::with_store(refresher, slow_store));

            // Trigger refresh; the task will complete the HTTP exchange and
            // then block inside store.save (the slow async path).
            let s = Arc::clone(&strategy);
            let handle = tokio::spawn(async move { s.get_token().await });
            // 200ms is comfortably past the 10ms HTTP delay but well inside
            // the 10s save delay — so abort() lands during save_refreshed_token.
            tokio::time::sleep(Duration::from_millis(200)).await;
            handle.abort();
            let _ = handle.await;

            // The CancelGuard must have cleared refresh_in_progress on drop.
            // If the old (pre-fix) code regresses, the flag stays true and a
            // subsequent caller wedges on wait_for_in_flight_refresh waiting
            // for a notify that will never come — the timeout below catches it.
            let s = Arc::clone(&strategy);
            let result = tokio::time::timeout(Duration::from_secs(2), s.get_token()).await;

            assert!(
                result.is_ok(),
                "get_token() should not hang after cancellation in the save/install window"
            );
        }

        /// If a non-blocking refresh (expiring-but-usable token) is cancelled
        /// mid-flight, the `CancelGuard` must reset `refresh_in_progress` and
        /// notify waiters so they don't hang once the token crosses real expiry.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn non_blocking_callers_recover_after_cancellation() {
            let counting = CountingState::new();
            let state = DelayedRefreshState {
                counting: counting.clone(),
                delay: Duration::from_secs(10), // Very slow — will be cancelled
            };
            let (base_url, _) = start_axum_server(delayed_refresh_handler, state).await;
            let dir = tempfile::tempdir().unwrap();
            // Token expires in 30s — is_expired() = true, is_usable() = true.
            let strategy = Arc::new(auto_refresh_with_token(
                &dir,
                &base_url,
                make_token("still-usable", 30, true),
            ));

            // Spawn get_token — triggers non-blocking refresh, drops lock, then
            // blocks on the slow HTTP call.
            let s = Arc::clone(&strategy);
            let handle = tokio::spawn(async move { s.get_token().await });
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Cancel the refresh mid-flight.
            handle.abort();
            let _ = handle.await;

            // The next caller must not hang. The token is still usable so it
            // should be returned even though the refresh was cancelled.
            let s = Arc::clone(&strategy);
            let result = tokio::time::timeout(Duration::from_secs(2), s.get_token()).await;

            assert!(
                result.is_ok(),
                "get_token() should not hang after cancelled non-blocking refresh"
            );
            let result = result.unwrap();
            assert!(
                result.is_ok(),
                "expected Ok with still-usable token, got: {:?}",
                result.unwrap_err()
            );
        }
    }
}

/// Deterministic regression test for the "token crosses real expiry while a
/// non-blocking refresh is in flight" race.
///
/// Before the fix, late-arriving callers saw `refresh_in_progress = true` +
/// `!is_usable()` and returned `Err(Expired)` instead of waiting for the
/// in-flight refresh. The original reproduction (a wall-clock stress test) hung
/// the outcome on a ~1-second window — token expiry has whole-second
/// granularity — which made it latently flaky and broke outright under coverage
/// instrumentation. This version drives expiry with a [`TestClock`] and gates
/// the refresh with a [`Notify`], so it is fully deterministic: no real sleeps,
/// no network.
#[cfg(test)]
#[cfg(feature = "http")]
#[allow(clippy::unwrap_used)]
mod expiry_crossing_regression {
    use super::*;
    use crate::clock::TestClock;
    use crate::{AuthError, SecretToken};
    use std::future::Future;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    /// Number of callers that arrive after the token crosses real expiry.
    const WAITERS: usize = 8;

    /// A [`Refresher`] whose `refresh` blocks on a test-controlled gate, so the
    /// test can hold a refresh "in flight" while it advances the clock and
    /// launches waiters — with no wall-clock timing involved.
    struct GatedRefresher {
        /// Notified once `refresh` is entered (the refresh is now in flight).
        started: Arc<Notify>,
        /// `refresh` awaits this; the test releases it to complete the refresh.
        gate: Arc<Notify>,
        /// Counts `refresh` invocations — asserts exactly one refresh happens.
        calls: Arc<AtomicUsize>,
        /// Absolute expiry stamped on the refreshed token.
        refreshed_expires_at: u64,
    }

    impl Refresher for GatedRefresher {
        type Credential = ();

        fn save(&self, _token: &Token) {}

        fn try_credential(&self, token: Option<&mut Token>) -> Option<Self::Credential> {
            // Refresh only when there's a token to refresh, matching the real
            // refreshers' "needs a prior token" contract.
            token.map(|_| ())
        }

        fn restore(&self, _token: &mut Token, _credential: Self::Credential) {}

        fn refresh(
            &self,
            _credential: &Self::Credential,
        ) -> impl Future<Output = Result<Token, AuthError>> + Send {
            let started = Arc::clone(&self.started);
            let gate = Arc::clone(&self.gate);
            let calls = Arc::clone(&self.calls);
            let refreshed_expires_at = self.refreshed_expires_at;
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                started.notify_one();
                gate.notified().await;
                Ok(make_token("refreshed-token", refreshed_expires_at))
            }
        }
    }

    fn make_token(access: &str, expires_at: u64) -> Token {
        Token {
            access_token: SecretToken::new(access),
            refresh_token: Some(SecretToken::new("refresh-token")),
            token_type: "Bearer".to_string(),
            expires_at,
            region: None,
            client_id: None,
            device_instance_id: None,
            federated_from: None,
        }
    }

    #[tokio::test]
    async fn waiters_wait_for_refresh_when_token_crosses_expiry() {
        let clock = TestClock::new(1_000_000);
        let started = Arc::new(Notify::new());
        let gate = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));

        let refresher = GatedRefresher {
            started: Arc::clone(&started),
            gate: Arc::clone(&gate),
            calls: Arc::clone(&calls),
            refreshed_expires_at: clock.now() + 3600,
        };

        // Within the 90s leeway (so a refresh is triggered) but still usable at
        // the current clock value (so the first caller takes the non-blocking
        // path and gets the old token).
        let token = make_token("expiring-soon", clock.now() + 10);
        let strategy = Arc::new(AutoRefresh::with_token_and_clock(
            refresher,
            token,
            clock.shared(),
        ));

        // 1. First caller starts the non-blocking refresh.
        let first = {
            let s = Arc::clone(&strategy);
            tokio::spawn(async move { s.get_token().await })
        };
        // Wait until the refresh is actually in flight (gated; won't complete yet).
        started.notified().await;

        // 2. Advance the clock past real expiry while the refresh is still gated.
        //    The token is now both expired and unusable.
        clock.advance(20);

        // 3. Launch waiters. They observe refresh_in_progress + !is_usable, so they
        //    must wait for the in-flight refresh rather than returning Expired.
        let waiters: Vec<_> = (0..WAITERS)
            .map(|_| {
                let s = Arc::clone(&strategy);
                tokio::spawn(async move { s.get_token().await })
            })
            .collect();

        // Let the waiters reach their wait point. This is cooperative scheduling
        // on the current-thread runtime (yielding lets the spawned waiters run
        // until they park on the refresh notification), not a wall-clock delay.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }

        // 4. Release the refresh. The first caller installs the new token and
        //    notifies the waiters, which then return the refreshed token.
        gate.notify_one();

        let first = first.await.unwrap().unwrap();
        assert_eq!(
            first.as_str(),
            "expiring-soon",
            "first caller receives the old token (still usable when it was called)"
        );

        for (i, waiter) in waiters.into_iter().enumerate() {
            let token = waiter.await.unwrap().unwrap_or_else(|e| {
                panic!("waiter {i} returned Err({e:?}), expected the refreshed token")
            });
            assert_eq!(
                token.as_str(),
                "refreshed-token",
                "waiter {i} should receive the refreshed token, not Expired"
            );
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "exactly one refresh should occur for all callers combined"
        );
    }

    /// A [`Refresher`] like [`GatedRefresher`], but whose gated `refresh`
    /// resolves to `Err` once released — so the test can exercise the *failure*
    /// axis of the in-flight-refresh race.
    struct FailingGatedRefresher {
        started: Arc<Notify>,
        gate: Arc<Notify>,
        calls: Arc<AtomicUsize>,
        /// Built per call rather than stored, because `AuthError` is not
        /// `Clone`. Lets one refresher drive both the generic-failure and the
        /// account-refusal axes, which take different paths out of the wait.
        error: fn() -> AuthError,
    }

    impl Refresher for FailingGatedRefresher {
        type Credential = ();

        fn save(&self, _token: &Token) {}

        fn try_credential(&self, token: Option<&mut Token>) -> Option<Self::Credential> {
            token.map(|_| ())
        }

        fn restore(&self, _token: &mut Token, _credential: Self::Credential) {}

        fn refresh(
            &self,
            _credential: &Self::Credential,
        ) -> impl Future<Output = Result<Token, AuthError>> + Send {
            let started = Arc::clone(&self.started);
            let gate = Arc::clone(&self.gate);
            let calls = Arc::clone(&self.calls);
            let error = self.error;
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                started.notify_one();
                gate.notified().await;
                Err(error())
            }
        }
    }

    /// The failure counterpart to
    /// [`waiters_wait_for_refresh_when_token_crosses_expiry`]: when the in-flight
    /// refresh *fails* and the clock has crossed real expiry, waiters waking in
    /// [`AutoRefresh::wait_for_in_flight_refresh`] must re-read the clock, find
    /// the cached token unusable via `require_usable_token(now)`, and return
    /// `Expired` — they must not hang, and must not hand back a stale token. This
    /// is exactly the branch the post-wake clock re-read (the `now` re-read after
    /// `notified().await`) exists to make correct.
    #[tokio::test]
    async fn waiters_get_expired_when_in_flight_refresh_fails() {
        let clock = TestClock::new(1_000_000);
        let started = Arc::new(Notify::new());
        let gate = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));

        let refresher = FailingGatedRefresher {
            started: Arc::clone(&started),
            gate: Arc::clone(&gate),
            calls: Arc::clone(&calls),
            error: || AuthError::TokenExpired(crate::error::TokenExpired),
        };

        // Within the 90s leeway (triggers a refresh) but still usable now, so the
        // first caller takes the non-blocking path and captures the old token.
        let token = make_token("expiring-soon", clock.now() + 10);
        let strategy = Arc::new(AutoRefresh::with_token_and_clock(
            refresher,
            token,
            clock.shared(),
        ));

        // 1. First caller starts the (gated) non-blocking refresh.
        let first = {
            let s = Arc::clone(&strategy);
            tokio::spawn(async move { s.get_token().await })
        };
        started.notified().await;

        // 2. Advance the clock past real expiry while the refresh is still gated.
        //    The cached token is now both expired and unusable.
        clock.advance(20);

        // 3. Launch waiters. They observe refresh_in_progress + !is_usable, so
        //    they park in wait_for_in_flight_refresh rather than returning early.
        let waiters: Vec<_> = (0..WAITERS)
            .map(|_| {
                let s = Arc::clone(&strategy);
                tokio::spawn(async move { s.get_token().await })
            })
            .collect();
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }

        // 4. Release the refresh → it returns Err. The first caller still returns
        //    the old token it captured while it was usable; the waiters re-read
        //    the now-advanced clock, find the token unusable, and get Expired.
        gate.notify_one();

        let first = first.await.unwrap();
        assert_eq!(
            first.unwrap().as_str(),
            "expiring-soon",
            "first caller keeps the old token it captured before the refresh failed"
        );

        for (i, waiter) in waiters.into_iter().enumerate() {
            let result = waiter.await.unwrap();
            assert!(
                matches!(result, Err(AutoRefreshError::Expired)),
                "waiter {i} should get Expired after the failed refresh, got: {result:?}"
            );
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "exactly one refresh attempt for all callers combined"
        );
    }

    /// The taxonomy counterpart to
    /// [`waiters_get_expired_when_in_flight_refresh_fails`]: when the in-flight
    /// refresh fails with a refusal no retry can clear, every waiter must
    /// receive *that* refusal rather than `Expired`.
    ///
    /// Only the caller that issued the request sees the server's answer
    /// directly; a waiter can learn it solely from the recorded denial, which
    /// `refresh_non_blocking` writes before `notify_waiters` wakes it. Without
    /// that consultation the waiters get `Expired`, which `cipherstash-cli`
    /// maps to `NoAuth` and turns into a login prompt — the one remedy
    /// guaranteed not to clear a usage limit.
    ///
    /// The window is narrow but not exotic: it needs only a proactive refresh
    /// that starts inside the expiry leeway and a token that crosses real
    /// expiry before the request comes back.
    #[tokio::test]
    async fn waiters_get_the_refusal_when_the_in_flight_refresh_is_denied() {
        let clock = TestClock::new(1_000_000);
        let started = Arc::new(Notify::new());
        let gate = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));

        let refresher = FailingGatedRefresher {
            started: Arc::clone(&started),
            gate: Arc::clone(&gate),
            calls: Arc::clone(&calls),
            error: || {
                AuthError::UsageLimitExceeded(crate::error::UsageLimitExceeded(
                    "Workspace has exceeded its usage limit".to_string(),
                ))
            },
        };

        // Inside the leeway (so a refresh starts) but still usable, so the
        // first caller takes the non-blocking path.
        let token = make_token("expiring-soon", clock.now() + 10);
        let strategy = Arc::new(AutoRefresh::with_token_and_clock(
            refresher,
            token,
            clock.shared(),
        ));

        let first = {
            let s = Arc::clone(&strategy);
            tokio::spawn(async move { s.get_token().await })
        };
        started.notified().await;

        // Cross real expiry while the refresh is gated, so the waiters park in
        // `wait_for_in_flight_refresh` instead of being served the cached token.
        clock.advance(20);

        let waiters: Vec<_> = (0..WAITERS)
            .map(|_| {
                let s = Arc::clone(&strategy);
                tokio::spawn(async move { s.get_token().await })
            })
            .collect();
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }

        gate.notify_one();

        let first = first.await.unwrap();
        assert_eq!(
            first.unwrap().as_str(),
            "expiring-soon",
            "first caller keeps the old token it captured before the refusal"
        );

        for (i, waiter) in waiters.into_iter().enumerate() {
            let result = waiter.await.unwrap();
            assert!(
                matches!(
                    result,
                    Err(AutoRefreshError::Auth(AuthError::UsageLimitExceeded(_)))
                ),
                "waiter {i} must receive the usage refusal, not a generic \
                 expiry, got: {result:?}"
            );
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the waiters must be served from the recorded denial, not by \
             re-issuing the request the refusal exists to suppress"
        );
    }

    /// A [`Refresher`] whose `refresh` panics if it is ever called, so a test can
    /// assert that no refresh is triggered.
    struct NeverRefresher;

    impl Refresher for NeverRefresher {
        type Credential = ();

        fn save(&self, _token: &Token) {}

        fn try_credential(&self, token: Option<&mut Token>) -> Option<Self::Credential> {
            token.map(|_| ())
        }

        fn restore(&self, _token: &mut Token, _credential: Self::Credential) {}

        // Keep the explicit `impl Future + Send` form to match the sibling test
        // refreshers; the trivial body would otherwise trip `manual_async_fn`.
        #[allow(clippy::manual_async_fn)]
        fn refresh(
            &self,
            _credential: &Self::Credential,
        ) -> impl Future<Output = Result<Token, AuthError>> + Send {
            async { panic!("refresh must not be called while the token reads as fresh") }
        }
    }

    /// The generalisation of `waiters_get_the_refusal_when_the_in_flight_refresh_is_denied`:
    /// waiters must see the issuer's actual refusal even when it is *not* one
    /// of the two account-level codes the sticky denial cache exists for.
    /// `invalid_grant` is a settled, non-retryable answer (the refresh token
    /// was rotated or revoked) — but because it isn't an account refusal,
    /// `record_refusal` never caches it as a sticky `denial`, so a waiter
    /// woken from `wait_for_in_flight_refresh` used to fall all the way
    /// through to a generic `Expired`, hiding *why* the refresh failed from
    /// every caller except the one that happened to perform it.
    #[tokio::test]
    async fn waiters_get_the_issuers_error_even_when_it_is_not_an_account_refusal() {
        let clock = TestClock::new(1_000_000);
        let started = Arc::new(Notify::new());
        let gate = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));

        let refresher = FailingGatedRefresher {
            started: Arc::clone(&started),
            gate: Arc::clone(&gate),
            calls: Arc::clone(&calls),
            error: || AuthError::InvalidGrant(crate::error::InvalidGrant),
        };

        // Inside the leeway (so a refresh starts) but still usable, so the
        // first caller takes the non-blocking path.
        let token = make_token("expiring-soon", clock.now() + 10);
        let strategy = Arc::new(AutoRefresh::with_token_and_clock(
            refresher,
            token,
            clock.shared(),
        ));

        let first = {
            let s = Arc::clone(&strategy);
            tokio::spawn(async move { s.get_token().await })
        };
        started.notified().await;

        // Cross real expiry while the refresh is gated, so the waiters park in
        // `wait_for_in_flight_refresh` instead of being served the cached token.
        clock.advance(20);

        let waiters: Vec<_> = (0..WAITERS)
            .map(|_| {
                let s = Arc::clone(&strategy);
                tokio::spawn(async move { s.get_token().await })
            })
            .collect();
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }

        gate.notify_one();

        let first = first.await.unwrap();
        assert_eq!(
            first.unwrap().as_str(),
            "expiring-soon",
            "first caller keeps the old token it captured before the refusal"
        );

        for (i, waiter) in waiters.into_iter().enumerate() {
            let result = waiter.await.unwrap();
            assert!(
                matches!(
                    result,
                    Err(AutoRefreshError::Auth(AuthError::InvalidGrant(_)))
                ),
                "waiter {i} must receive the invalid_grant refusal — a settled, \
                 non-retryable answer — not a generic Expired that hides why the \
                 refresh actually failed, got: {result:?}"
            );
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "exactly one refresh attempt for all callers combined"
        );
    }

    /// A wall clock running *backwards* (NTP step, VM snapshot restore) must not
    /// panic or spuriously force a refresh. Each `get_token` call samples `now`
    /// once and re-evaluates the pure `is_expired_at`/`is_usable_at` predicates,
    /// and the only time subtraction in the crate (`Token::expires_in`) saturates
    /// — so there is no cross-call delta to underflow. A rewind simply makes the
    /// token read as fresh again.
    #[tokio::test]
    async fn backwards_clock_does_not_panic_or_force_refresh() {
        let clock = TestClock::new(1_000_000);
        // Fresh token: expires well beyond the 90s leeway.
        let token = make_token("fresh", clock.now() + 3600);
        let strategy = AutoRefresh::with_token_and_clock(NeverRefresher, token, clock.shared());

        // Forward reading returns the cached token without refreshing.
        assert_eq!(strategy.get_token().await.unwrap().as_str(), "fresh");

        // The wall clock jumps 100_000s into the past.
        clock.set(900_000);

        // Still fresh, still no refresh (NeverRefresher would panic), no hang.
        assert_eq!(strategy.get_token().await.unwrap().as_str(), "fresh");
    }
}

#[cfg(test)]
#[cfg(feature = "http")]
#[allow(clippy::unwrap_used)]
mod regression_cip_3159 {
    use super::*;
    use crate::access_key_refresher::AccessKeyRefresher;
    use crate::SecretToken;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// `/api/authorise` handler that sleeps `delay` before returning a valid
    /// access-key token response (with an ABSOLUTE-epoch `expiry`, as CTS
    /// returns), giving the test a window to cancel in.
    async fn delayed_authorise_handler(
        axum::extract::State(delay): axum::extract::State<Duration>,
    ) -> axum::Json<serde_json::Value> {
        tokio::time::sleep(delay).await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        axum::Json(serde_json::json!({
            "accessToken": "refreshed-token",
            "expiry": now + 3600
        }))
    }

    async fn start_authorise_server(delay: Duration) -> url::Url {
        let app = axum::Router::new()
            .route(
                "/api/authorise",
                axum::routing::post(delayed_authorise_handler),
            )
            .with_state(delay);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        url::Url::parse(&format!("http://{addr}")).unwrap()
    }

    /// is_expired() == true (within the 90s leeway, so `get_token` refreshes),
    /// but is_usable() == true for `secs_until_expiry` (so it takes the
    /// non-blocking path).
    fn expiring_but_usable_token(access: &str, secs_until_expiry: u64) -> Token {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Token {
            access_token: SecretToken::new(access),
            token_type: "Bearer".to_string(),
            expires_at: now + secs_until_expiry,
            refresh_token: None,
            region: None,
            client_id: None,
            device_instance_id: None,
            federated_from: None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancellation_in_relock_window_does_not_strand_refresh() {
        let http_delay = Duration::from_millis(400);
        let base_url = start_authorise_server(http_delay).await;

        let strategy = Arc::new(AutoRefresh::with_token(
            AccessKeyRefresher::new(
                SecretToken::new("CSAKtestKeyId.testKeySecret"),
                base_url,
                None,
                crate::transport::default_transport(),
            ),
            expiring_but_usable_token("old-usable", 2),
        ));

        // Caller A drives the refresh: it locks state, sets the in-progress
        // flag, drops the lock, then awaits the (slow) HTTP authorise call.
        let a = Arc::clone(&strategy);
        let handle = tokio::spawn(async move { a.get_token().await });

        // Let A reach the HTTP await, then take the state lock so that when A's
        // request completes it parks on its post-HTTP `state.lock().await`
        // instead of installing the new token.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let held = strategy.state.lock().await;

        // A's HTTP completes (~400ms) and blocks on the lock we hold.
        tokio::time::sleep(http_delay + Duration::from_millis(200)).await;
        assert!(
            strategy.refresh_in_progress.load(Ordering::Acquire),
            "precondition: a refresh should be in flight while caller A is parked",
        );

        // Cancel A precisely in the post-HTTP, pre-install window.
        handle.abort();
        let _ = handle.await;
        drop(held);

        // The CancelGuard's Drop must have cleared the flag on cancellation.
        // Pre-fix, defuse() ran before the re-lock, so this stays `true`.
        assert!(
            !strategy.refresh_in_progress.load(Ordering::Acquire),
            "refresh_in_progress stranded `true` after cancellation in the re-lock window (CIP-3159)",
        );

        // End-to-end: once the cached token crosses real expiry, a stranded flag
        // would route the next caller into wait_for_in_flight_refresh and hang on
        // a notify that never comes. With the fix, the caller re-authenticates.
        tokio::time::sleep(Duration::from_millis(2100)).await;
        let b = Arc::clone(&strategy);
        let result =
            tokio::time::timeout(Duration::from_secs(3), async move { b.get_token().await }).await;
        assert!(
            matches!(result, Ok(Ok(_))),
            "get_token() hung or failed after cancellation — refresh wedged (CIP-3159): {result:?}",
        );
    }
}
