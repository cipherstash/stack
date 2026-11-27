//! Refresh ahead of expiry, off the caller's path, and backoff after a
//! failure. Time is Tokio's paused clock, so every wait is virtual.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::clock::Clock;
use crate::{AuthError, SecretToken};
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout, Instant};

/// "Now" from Tokio's clock, so a paused runtime moves the engine's time
/// with every virtual sleep.
struct TokioClock(Instant);

impl Clock for TokioClock {
    fn now_unix_secs(&self) -> u64 {
        1_000_000 + self.0.elapsed().as_secs()
    }
}

fn clock() -> SharedClock {
    Arc::new(TokioClock(Instant::now()))
}

fn token(access: &str, expires_at: u64) -> Token {
    Token {
        access_token: SecretToken::new(access),
        refresh_token: None,
        token_type: "Bearer".into(),
        expires_at,
        region: None,
        client_id: None,
        device_instance_id: None,
        federated_from: None,
    }
}

/// An issuer that answers with a new token valid for `lifetime` seconds,
/// fails the first `failures` exchanges, and holds each exchange until the
/// test opens `gate` (when `gated`).
struct Issuer {
    calls: AtomicUsize,
    failures: AtomicUsize,
    gated: bool,
    gate: Semaphore,
    lifetime: u64,
    attempts: StdMutex<Vec<u64>>,
}

impl Issuer {
    fn new(failures: usize, gated: bool) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            failures: AtomicUsize::new(failures),
            gated,
            gate: Semaphore::new(0),
            lifetime: 900,
            attempts: StdMutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

struct IssuerRefresher {
    issuer: Arc<Issuer>,
    clock: SharedClock,
}

impl Refresher for IssuerRefresher {
    type Credential = ();

    fn save(&self, _: &Token) {}

    fn try_credential(&self, _: Option<&mut Token>) -> Option<()> {
        Some(())
    }

    fn restore(&self, _: &mut Token, _: ()) {}

    async fn refresh(&self, _: &()) -> Result<Token, AuthError> {
        let issuer = &self.issuer;
        let call = issuer.calls.fetch_add(1, Ordering::SeqCst) + 1;
        issuer
            .attempts
            .lock()
            .unwrap()
            .push(self.clock.now_unix_secs());
        if issuer.gated {
            issuer.gate.acquire().await.unwrap().forget();
        }
        if issuer
            .failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(crate::error::ServerError("injected failure".into()).into());
        }
        Ok(token(
            &format!("issued-{call}"),
            self.clock.now_unix_secs() + issuer.lifetime,
        ))
    }
}

fn strategy(
    issuer: &Arc<Issuer>,
    clock: &SharedClock,
    current: Option<Token>,
) -> AutoRefresh<IssuerRefresher> {
    AutoRefresh::new(
        IssuerRefresher {
            issuer: Arc::clone(issuer),
            clock: Arc::clone(clock),
        },
        NoStore,
        current,
        Arc::clone(clock),
    )
}

/// A token 60 seconds from expiry is inside the refresh window and still
/// works. The caller gets it at once: it neither starts nor waits for the
/// refresh, which runs in the background.
#[tokio::test(start_paused = true)]
async fn a_caller_with_a_valid_token_does_not_wait_for_its_refresh() {
    let clock = clock();
    let issuer = Issuer::new(0, true);
    let now = clock.now_unix_secs();
    let strategy = strategy(&issuer, &clock, Some(token("current", now + 60)));

    let got = timeout(Duration::from_secs(5), strategy.get_token())
        .await
        .expect("the caller waited for a refresh its valid token did not need")
        .unwrap();
    assert_eq!(got.as_str(), "current");

    // The refresh runs without any caller waiting on it, half way through
    // the token's remaining life.
    issuer.gate.add_permits(1);
    timeout(Duration::from_secs(35), async {
        while strategy
            .shared
            .state
            .lock()
            .await
            .token
            .as_ref()
            .unwrap()
            .access_token()
            .as_str()
            == "current"
        {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the background refresh did not install a new token");
    assert_eq!(issuer.calls(), 1, "one refresh, not one per caller");
}

/// After a refresh fails and the token has expired, a caller fails at once
/// with that refresh's error. It does not start an exchange of its own
/// while the refresh backs off.
#[tokio::test(start_paused = true)]
async fn an_expired_token_fails_fast_while_refreshes_back_off() {
    let clock = clock();
    let issuer = Issuer::new(usize::MAX, false);
    let now = clock.now_unix_secs();
    let strategy = strategy(&issuer, &clock, Some(token("expired", now - 1)));

    let first = strategy.get_token().await.unwrap_err();
    assert!(
        matches!(first, AutoRefreshError::Auth(AuthError::Server(_))),
        "{first:?}"
    );
    assert_eq!(issuer.calls(), 1);

    for _ in 0..10 {
        let again = strategy.get_token().await.unwrap_err();
        assert!(
            matches!(again, AutoRefreshError::Auth(AuthError::Server(_))),
            "a caller during the backoff gets the last refresh error, not {again:?}"
        );
    }
    assert_eq!(
        issuer.calls(),
        1,
        "callers during the backoff started exchanges of their own"
    );
}

/// A token in use is refreshed before it expires, with no caller asking.
#[tokio::test(start_paused = true)]
async fn a_token_in_use_is_refreshed_before_it_expires() {
    let clock = clock();
    let issuer = Issuer::new(0, false);
    let now = clock.now_unix_secs();
    let strategy = strategy(&issuer, &clock, Some(token("current", now + 900)));

    assert_eq!(strategy.get_token().await.unwrap().as_str(), "current");
    sleep(Duration::from_secs(899)).await;

    assert_eq!(
        issuer.calls(),
        1,
        "nothing refreshed the token before it expired"
    );
    let refreshed_at = issuer.attempts.lock().unwrap()[0];
    // 90 s is the expiry leeway: a call inside it would refresh anyway.
    assert!(
        refreshed_at < now + 900 - 90,
        "the refresh ran at {} s, inside the 90 s leeway",
        refreshed_at - now
    );
    assert_eq!(strategy.get_token().await.unwrap().as_str(), "issued-1");
}

/// A token nobody has asked for since its last refresh is not refreshed
/// again, so an idle process does not call the issuer forever.
#[tokio::test(start_paused = true)]
async fn an_idle_strategy_stops_refreshing() {
    let clock = clock();
    let issuer = Issuer::new(0, false);
    let now = clock.now_unix_secs();
    let strategy = strategy(&issuer, &clock, Some(token("current", now + 900)));

    strategy.get_token().await.unwrap();
    sleep(Duration::from_secs(900)).await;
    assert_eq!(
        issuer.calls(),
        1,
        "the token in use was not refreshed ahead"
    );
    sleep(Duration::from_secs(10 * 900)).await;
    assert_eq!(issuer.calls(), 1, "an idle strategy kept refreshing");

    // A caller wakes it again, and its token is refreshed ahead once more.
    strategy.get_token().await.unwrap();
    sleep(Duration::from_secs(900)).await;
    assert_eq!(issuer.calls(), 2);
}

/// A failed refresh is retried with growing gaps while the token is in use,
/// and a success before expiry leaves callers none the wiser.
#[tokio::test(start_paused = true)]
async fn a_failed_refresh_is_retried_with_backoff() {
    let clock = clock();
    let issuer = Issuer::new(3, false);
    let now = clock.now_unix_secs();
    let strategy = strategy(&issuer, &clock, Some(token("current", now + 900)));

    // A call every second keeps the token in use, so only the backoff
    // spaces the retries.
    for _ in 0..900 {
        assert!(strategy.get_token().await.is_ok());
        sleep(Duration::from_secs(1)).await;
    }

    let attempts = issuer.attempts.lock().unwrap().clone();
    assert_eq!(attempts.len(), 4, "attempts at {attempts:?}");
    let gaps: Vec<u64> = attempts.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(gaps.iter().all(|&gap| gap >= 1), "no backoff: {gaps:?}");
    assert!(gaps[2] > gaps[0], "the backoff did not grow: {gaps:?}");
    assert_eq!(strategy.get_token().await.unwrap().as_str(), "issued-4");
}

/// Dropping the strategy stops its background refresh: nothing outlives it.
#[tokio::test(start_paused = true)]
async fn dropping_the_strategy_stops_its_background_refresh() {
    let clock = clock();
    let issuer = Issuer::new(0, false);
    let now = clock.now_unix_secs();
    let strategy = strategy(&issuer, &clock, Some(token("current", now + 900)));
    strategy.get_token().await.unwrap();

    drop(strategy);
    sleep(Duration::from_secs(1)).await;
    assert_eq!(
        Arc::strong_count(&issuer),
        1,
        "something still holds the dropped strategy's refresher"
    );
    sleep(Duration::from_secs(10 * 900)).await;
    assert_eq!(issuer.calls(), 0);
}
