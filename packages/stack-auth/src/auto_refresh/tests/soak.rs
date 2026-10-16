//! Seeded, virtual-time cancellation soak. No credentials or network needed.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::clock::Clock;
use crate::{AuthError, SecretToken};
use std::collections::HashSet;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, Instant};

// One deterministic stream per caller and one for the issuer. There is no
// dependency on thread scheduling or the process-global RNG.
struct Random(u64);

impl Random {
    fn below(&mut self, limit: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % limit
    }
}

struct PausedClock(Instant);

impl Clock for PausedClock {
    fn now_unix_secs(&self) -> u64 {
        1_000_000 + self.0.elapsed().as_secs()
    }
}

struct IdentityProvider {
    random: Random,
    generation: u64,
    used: HashSet<u64>,
    revoked: bool,
    saved: u64,
    errors: u64,
}

struct RotatingRefresher {
    idp: Arc<StdMutex<IdentityProvider>>,
    clock: SharedClock,
}

fn token(generation: u64, expires_at: u64) -> Token {
    Token {
        access_token: SecretToken::new(format!("{generation}:{expires_at}")),
        refresh_token: Some(SecretToken::new(generation.to_string())),
        token_type: "Bearer".into(),
        expires_at,
        region: None,
        client_id: None,
        device_instance_id: None,
        federated_from: None,
    }
}

impl Refresher for RotatingRefresher {
    type Credential = SecretToken;

    fn save(&self, _: &Token) {}

    fn try_credential(&self, token: Option<&mut Token>) -> Option<SecretToken> {
        token.and_then(Token::take_refresh_token)
    }

    fn restore(&self, token: &mut Token, credential: SecretToken) {
        token.refresh_token = Some(credential);
    }

    async fn refresh(&self, credential: &SecretToken) -> Result<Token, AuthError> {
        let (delay, fail, lifetime) = {
            let mut idp = self.idp.lock().unwrap();
            (
                idp.random.below(3_000),
                idp.random.below(8) == 0,
                95 + idp.random.below(30),
            )
        };
        sleep(Duration::from_millis(delay)).await;
        let generation = {
            let mut idp = self.idp.lock().unwrap();
            if fail {
                // A definite rejection before spending the credential. An
                // ambiguous network failure after rotation needs IdP support
                // (idempotency/grace), and is not caused by caller cancellation.
                idp.errors += 1;
                return Err(crate::error::ServerError("injected transient failure".into()).into());
            }
            let presented: u64 = credential.as_str().parse().unwrap();
            if presented != idp.generation || !idp.used.insert(presented) {
                idp.revoked = true;
            }
            if idp.revoked {
                return Err(crate::error::InvalidGrant.into());
            }
            idp.generation += 1;
            idp.generation
        };
        Ok(token(generation, self.clock.now_unix_secs() + lifetime))
    }
}

struct RotationStore(Arc<StdMutex<IdentityProvider>>);

impl TokenStore for RotationStore {
    async fn load(&self) -> Option<Token> {
        None
    }

    async fn save(&self, token: &Token) {
        let delay = self.0.lock().unwrap().random.below(2_000);
        // Callers also cancel after the IdP has rotated, during persistence.
        sleep(Duration::from_millis(delay)).await;
        let mut idp = self.0.lock().unwrap();
        let generation: u64 = token.refresh_token().unwrap().as_str().parse().unwrap();
        assert_eq!(generation, idp.generation, "saved a stale rotation");
        assert_eq!(generation, idp.saved + 1, "lost or reordered a rotation");
        idp.saved = generation;
    }
}

async fn soak(seed: u64, rounds: usize) {
    let clock: SharedClock = Arc::new(PausedClock(Instant::now()));
    let idp = Arc::new(StdMutex::new(IdentityProvider {
        random: Random(seed),
        generation: 0,
        used: HashSet::new(),
        revoked: false,
        saved: 0,
        errors: 0,
    }));
    let strategy = Arc::new(AutoRefresh::new(
        RotatingRefresher {
            idp: idp.clone(),
            clock: clock.clone(),
        },
        RotationStore(idp.clone()),
        Some(token(0, clock.now_unix_secs())),
        clock.clone(),
    ));
    let mut callers = JoinSet::new();
    for caller in 1..=256 {
        let strategy = strategy.clone();
        let clock = clock.clone();
        callers.spawn(async move {
            let mut random = Random(seed.wrapping_add(caller));
            let (mut completed, mut timed_out, mut selected_out) = (0, 0, 0);
            for _ in 0..rounds {
                sleep(Duration::from_millis(random.below(60_000))).await;
                let acquisition = async {
                    loop {
                        match strategy.get_token().await {
                            Ok(token) => {
                                let (_, expiry) = token.as_str().split_once(':').unwrap();
                                assert!(
                                    clock.now_unix_secs() < expiry.parse::<u64>().unwrap(),
                                    "returned an expired token (seed {seed})"
                                );
                                break;
                            }
                            // Injected transient errors may reach a caller
                            // with no usable token. Retry within the bound.
                            Err(AutoRefreshError::Auth(AuthError::Server(_))) => {
                                sleep(Duration::from_millis(10)).await;
                            }
                            Err(err) => panic!("session lost (seed {seed}): {err:?}"),
                        }
                    }
                };
                let cancel_after = Duration::from_millis(random.below(4_000));
                // One third never cancel: a fixed outer bound proves they
                // cannot get stranded behind a missed notification.
                let kind = random.below(3);
                timeout(Duration::from_secs(30), async {
                    match kind {
                        0 => {
                            acquisition.await;
                            completed += 1;
                        }
                        1 => {
                            if timeout(cancel_after, acquisition).await.is_ok() {
                                completed += 1;
                            } else {
                                timed_out += 1;
                            }
                        }
                        _ => tokio::select! {
                            biased;
                            () = acquisition => completed += 1,
                            () = sleep(cancel_after) => selected_out += 1,
                        },
                    }
                })
                .await
                .expect("caller exceeded 30s virtual-time bound");
            }
            (completed, timed_out, selected_out)
        });
    }
    let (mut completed, mut timed_out, mut selected_out) = (0, 0, 0);
    while let Some(result) = callers.join_next().await {
        let counts = result.unwrap();
        completed += counts.0;
        timed_out += counts.1;
        selected_out += counts.2;
    }
    // Drain a refresh whose last waiter cancelled, then compare all three
    // views of the rotating credential: issuer, durable store and engine.
    timeout(Duration::from_secs(30), async {
        while strategy.shared.refresh_in_progress.load(Ordering::Acquire) {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    let state = strategy.shared.state.lock().await;
    let installed: u64 = state
        .token
        .as_ref()
        .unwrap()
        .refresh_token()
        .unwrap()
        .as_str()
        .parse()
        .unwrap();
    let idp = idp.lock().unwrap();
    assert!(!idp.revoked, "refresh-token reuse revoked the session");
    assert_eq!(idp.saved, idp.generation, "newest rotation was not saved");
    assert_eq!(
        installed, idp.generation,
        "newest rotation was not installed"
    );
    assert!(
        idp.generation > 25 && idp.errors > 0,
        "insufficient refresh/error coverage"
    );
    assert!(
        completed > 0 && timed_out > 0 && selected_out > 0,
        "insufficient cancellation coverage"
    );
    // Test-only progress counters make the long CI run's coverage reviewable.
    #[allow(clippy::print_stderr)]
    {
        eprintln!("seed={seed}, rotations={}, injected_errors={}, completed={completed}, timeouts={timed_out}, select_cancels={selected_out}", idp.generation, idp.errors);
    }
}

#[tokio::test(start_paused = true)]
async fn cancellation_soak_short() {
    soak(0x1170, 128).await;
}

#[tokio::test(start_paused = true)]
#[ignore = "long release soak; run with test:soak:stack-auth"]
async fn cancellation_soak_long() {
    for seed in [0x1170, 0xdead_beef, 0xcafe_f00d, 0x1234_5678] {
        soak(seed, 4_096).await;
    }
}
