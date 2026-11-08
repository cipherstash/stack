//! Cancellation must leave the rotating session usable, including after the
//! issuer has spent the old credential. Gates pin each await without sleeps.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::clock::TestClock;
use crate::{AuthError, SecretToken};
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use tokio::sync::Semaphore;

fn token(generation: usize, expires_at: u64) -> Token {
    Token {
        access_token: SecretToken::new(format!("access-{generation}")),
        refresh_token: Some(SecretToken::new(generation.to_string())),
        token_type: "Bearer".into(),
        expires_at,
        region: None,
        client_id: None,
        device_instance_id: None,
        federated_from: None,
    }
}

struct Issuer {
    started: Notify,
    exchange: Semaphore,
    answered: Notify,
    persist: Semaphore,
    generation: AtomicUsize,
    saved: AtomicUsize,
    calls: AtomicUsize,
    fail_once: AtomicBool,
    initial_auth: bool,
}

impl Issuer {
    fn new(initial_auth: bool) -> Self {
        Self {
            started: Notify::new(),
            exchange: Semaphore::new(0),
            answered: Notify::new(),
            persist: Semaphore::new(0),
            generation: AtomicUsize::new(0),
            saved: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            fail_once: AtomicBool::new(false),
            initial_auth,
        }
    }
}

struct RotatingRefresher(Arc<Issuer>);

impl Refresher for RotatingRefresher {
    type Credential = SecretToken;

    fn save(&self, _: &Token) {}

    fn try_credential(&self, token: Option<&mut Token>) -> Option<SecretToken> {
        match token {
            Some(token) => token.take_refresh_token(),
            None if self.0.initial_auth => Some(SecretToken::new("0")),
            None => None,
        }
    }

    fn restore(&self, token: &mut Token, credential: SecretToken) {
        token.refresh_token = Some(credential);
    }

    async fn refresh(&self, credential: &SecretToken) -> Result<Token, AuthError> {
        let issuer = &self.0;
        issuer.calls.fetch_add(1, Ordering::SeqCst);
        issuer.started.notify_one();
        issuer.exchange.acquire().await.unwrap().forget();
        if issuer.fail_once.swap(false, Ordering::SeqCst) {
            return Err(crate::error::ServerError("injected transient failure".into()).into());
        }
        let previous = issuer.generation.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            credential.as_str(),
            previous.to_string(),
            "credential replay"
        );
        // The issuer has already rotated, but the response is not persisted.
        issuer.answered.notify_one();
        issuer.persist.acquire().await.unwrap().forget();
        issuer.saved.store(previous + 1, Ordering::SeqCst);
        Ok(token(previous + 1, (previous as u64 + 1) * 10_000))
    }
}

struct GatedStore {
    entered: Notify,
    save: Semaphore,
    saved: AtomicUsize,
}

impl TokenStore for GatedStore {
    async fn load(&self) -> Option<Token> {
        None
    }

    async fn save(&self, token: &Token) {
        self.entered.notify_one();
        self.save.acquire().await.unwrap().forget();
        self.saved.store(
            token.refresh_token().unwrap().as_str().parse().unwrap(),
            Ordering::SeqCst,
        );
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Exchange,
    PersistRotation,
    SaveStore,
    Install,
}

async fn cancelled_at(phase: Phase, usable: bool, initial: bool) {
    let clock = TestClock::new(1_000);
    let issuer = Arc::new(Issuer::new(initial));
    let store = Arc::new(GatedStore {
        entered: Notify::new(),
        save: Semaphore::new(0),
        saved: AtomicUsize::new(0),
    });
    let strategy = Arc::new(AutoRefresh::new(
        RotatingRefresher(issuer.clone()),
        store.clone(),
        (!initial).then(|| token(0, if usable { 1_030 } else { 999 })),
        clock.shared(),
    ));
    let caller = tokio::spawn({
        let strategy = strategy.clone();
        async move { strategy.get_token().await }
    });
    issuer.started.notified().await;
    if !matches!(phase, Phase::Exchange) {
        issuer.exchange.add_permits(1);
        issuer.answered.notified().await;
    }
    if matches!(phase, Phase::SaveStore | Phase::Install) {
        issuer.persist.add_permits(1);
        store.entered.notified().await;
    }
    // Only the non-blocking path releases the state lock during the exchange.
    let held = if matches!(phase, Phase::Install) {
        let held = strategy.shared.state.lock().await;
        store.save.add_permits(1);
        while store.saved.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        Some(held)
    } else {
        None
    };
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    // A later caller must wait for the rotated token, even on the formerly
    // non-blocking path. Cancelling that waiter must not affect other waiters.
    clock.advance(31);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), strategy.get_token())
            .await
            .is_err()
    );
    let mut waiters = Vec::new();
    for _ in 0..32 {
        let strategy = strategy.clone();
        waiters.push(tokio::spawn(async move { strategy.get_token().await }));
    }
    issuer.exchange.add_permits(1);
    issuer.persist.add_permits(1);
    store.save.add_permits(1);
    drop(held);
    for waiter in waiters {
        let result = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(result.as_str(), "access-1");
    }
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(issuer.saved.load(Ordering::SeqCst), 1);
    assert_eq!(store.saved.load(Ordering::SeqCst), 1);
    // A second rotation proves the new refresh credential was installed too.
    clock.set(10_001);
    issuer.exchange.add_permits(1);
    issuer.persist.add_permits(1);
    store.save.add_permits(1);
    let result = strategy.get_token().await.unwrap();
    assert_eq!(result.as_str(), "access-2");
    assert_eq!(issuer.saved.load(Ordering::SeqCst), 2);
    assert_eq!(store.saved.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn cancelled_blocking_refresh_finishes_every_phase() {
    for phase in [Phase::Exchange, Phase::PersistRotation, Phase::SaveStore] {
        cancelled_at(phase, false, false).await;
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_non_blocking_refresh_finishes_every_phase() {
    for phase in [
        Phase::Exchange,
        Phase::PersistRotation,
        Phase::SaveStore,
        Phase::Install,
    ] {
        cancelled_at(phase, true, false).await;
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_initial_auth_finishes_and_is_shared() {
    for phase in [Phase::Exchange, Phase::SaveStore] {
        cancelled_at(phase, false, true).await;
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_failed_refresh_restores_the_credential_for_retry() {
    for usable in [false, true] {
        let clock = TestClock::new(1_000);
        let issuer = Arc::new(Issuer::new(false));
        issuer.fail_once.store(true, Ordering::SeqCst);
        let strategy = Arc::new(AutoRefresh::with_token_and_clock(
            RotatingRefresher(issuer.clone()),
            token(0, if usable { 1_030 } else { 999 }),
            clock.shared(),
        ));
        let caller = tokio::spawn({
            let strategy = strategy.clone();
            async move { strategy.get_token().await }
        });
        issuer.started.notified().await;
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        issuer.exchange.add_permits(1);
        // Let the failing task settle before retrying, on either lock path.
        while strategy.shared.refresh_in_progress.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        clock.advance(31);
        issuer.exchange.add_permits(1);
        issuer.persist.add_permits(1);
        assert_eq!(strategy.get_token().await.unwrap().as_str(), "access-1");
        assert_eq!(issuer.calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test(start_paused = true)]
async fn rotation_is_saved_even_after_all_callers_drop_the_strategy() {
    let issuer = Arc::new(Issuer::new(false));
    let strategy = Arc::new(AutoRefresh::with_token_and_clock(
        RotatingRefresher(issuer.clone()),
        token(0, 999),
        TestClock::new(1_000).shared(),
    ));
    let caller = tokio::spawn(async move { strategy.get_token().await });
    issuer.started.notified().await;
    issuer.exchange.add_permits(1);
    issuer.answered.notified().await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    issuer.persist.add_permits(1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while issuer.saved.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn a_panicking_refresh_reports_an_error_and_releases_waiters() {
    let issuer = Arc::new(Issuer::new(false));
    let clock = TestClock::new(1_000);
    let strategy = Arc::new(AutoRefresh::with_token_and_clock(
        RotatingRefresher(issuer.clone()),
        token(0, 1_030),
        clock.shared(),
    ));
    let caller = tokio::spawn({
        let strategy = strategy.clone();
        async move { strategy.get_token().await }
    });
    issuer.started.notified().await;
    clock.advance(31);
    let waiter = tokio::spawn({
        let strategy = strategy.clone();
        async move { strategy.get_token().await }
    });
    tokio::task::yield_now().await;
    // Closing the gate makes the refresher panic at acquire().unwrap().
    issuer.exchange.close();
    assert!(matches!(
        caller.await.unwrap(),
        Err(AutoRefreshError::Auth(AuthError::Internal(_)))
    ));
    let result = tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(AutoRefreshError::Expired)));
}

#[tokio::test(start_paused = true)]
async fn guard_notification_before_waiter_registration_is_not_lost() {
    let strategy = AutoRefresh::with_token_and_clock(
        RotatingRefresher(Arc::new(Issuer::new(false))),
        token(0, 999),
        TestClock::new(1_000).shared(),
    );
    let shared = &strategy.shared;
    let state = shared.state.clone().lock_owned().await;
    shared.refresh_in_progress.store(true, Ordering::Release);
    // The waiter observed true while holding the lock, then the guard dropped
    // before the waiter could register its Notified future.
    drop(CancelGuard {
        in_progress: &shared.refresh_in_progress,
        notify: &shared.refresh_notify,
        defused: false,
    });
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        shared.wait_for_in_flight_refresh(state, 1_000),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(AutoRefreshError::Expired)));
}
