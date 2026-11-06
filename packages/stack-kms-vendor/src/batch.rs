//! N vendor calls at once, with a limit, backoff and fail-whole-batch.

use std::future::Future;
use std::num::NonZeroUsize;
use std::time::Duration;

use futures::{StreamExt, TryStreamExt};
use stack_kms::{BackendErrorKind, Error};

/// How [`run_batch`] sends a batch of vendor calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchOptions {
    /// The most calls in flight at once. Default 16.
    pub concurrency: NonZeroUsize,
    /// The most attempts for one call, the first one included. A call is
    /// tried again only after a `Throttled` failure. Default 5.
    pub max_attempts: u32,
    /// The wait before the second attempt. Each later wait is double the
    /// one before it, up to `max_delay`. Default 50 ms.
    pub base_delay: Duration,
    /// The longest wait between two attempts. Default 2 s.
    pub max_delay: Duration,
}

impl Default for BatchOptions {
    fn default() -> Self {
        Self {
            concurrency: NonZeroUsize::new(16).unwrap_or(NonZeroUsize::MIN),
            max_attempts: 5,
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(2),
        }
    }
}

impl BatchOptions {
    /// The wait after the failed attempt number `attempt` (1-based).
    fn delay_after(&self, attempt: u32) -> Duration {
        let factor = 1u32
            .checked_shl(attempt.saturating_sub(1))
            .unwrap_or(u32::MAX);
        self.base_delay
            .checked_mul(factor)
            .map_or(self.max_delay, |delay| delay.min(self.max_delay))
    }
}

fn is_throttled(error: &Error) -> bool {
    matches!(
        error,
        Error::Backend {
            kind: BackendErrorKind::Throttled,
            ..
        }
    )
}

/// Run `call(0)` to `call(count - 1)`, at most
/// [`concurrency`](BatchOptions::concurrency) at once, and return the
/// results in index order.
///
/// A call that fails with
/// [`Throttled`](stack_kms::BackendErrorKind::Throttled) is tried again
/// after `sleep(delay)`, with an exponential delay, up to
/// [`max_attempts`](BatchOptions::max_attempts) in all. Any other failure,
/// or a call that is still throttled after the last attempt, fails the
/// whole batch: the calls still in flight are dropped and no partial result
/// is returned.
///
/// Runtime-agnostic: it uses no timer and no executor of its own. `sleep`
/// is the caller's timer ([`KeyVendorBackend::sleep`](crate::KeyVendorBackend::sleep)).
pub async fn run_batch<T, F, Fut, S, SFut>(
    options: &BatchOptions,
    count: usize,
    call: F,
    sleep: S,
) -> Result<Vec<T>, Error>
where
    F: Fn(usize) -> Fut,
    Fut: Future<Output = Result<T, Error>>,
    S: Fn(Duration) -> SFut,
    SFut: Future<Output = ()>,
{
    let attempt = |index: usize| {
        let call = &call;
        let sleep = &sleep;
        async move {
            let mut attempt = 1;
            loop {
                match call(index).await {
                    Err(error) if is_throttled(&error) && attempt < options.max_attempts => {
                        sleep(options.delay_after(attempt)).await;
                        attempt += 1;
                    }
                    result => return result,
                }
            }
        }
    };
    futures::stream::iter(0..count)
        .map(attempt)
        .buffered(options.concurrency.get())
        .try_collect()
        .await
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::*;

    fn throttled() -> Error {
        Error::Backend {
            backend: stack_kms::KeyVendor::Static.into(),
            kind: BackendErrorKind::Throttled,
            source: "slow down".into(),
        }
    }

    fn options() -> BatchOptions {
        BatchOptions {
            concurrency: NonZeroUsize::new(3).unwrap(),
            ..BatchOptions::default()
        }
    }

    #[tokio::test]
    async fn results_keep_index_order() {
        let results = run_batch(
            &options(),
            10,
            |index| async move {
                tokio::time::sleep(Duration::from_millis(10 - index as u64)).await;
                Ok(index)
            },
            |_| async {},
        )
        .await
        .unwrap();
        assert_eq!(results, (0..10).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn no_more_than_the_limit_runs_at_once() {
        let in_flight = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let _ = run_batch(
            &options(),
            12,
            |_| async {
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                let _ = peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
                let _ = in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            },
            |_| async {},
        )
        .await
        .unwrap();
        assert_eq!(peak.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_throttled_call_backs_off_and_is_tried_again() {
        let attempts = AtomicUsize::new(0);
        let waits = Mutex::new(Vec::new());
        let results = run_batch(
            &options(),
            1,
            |_| async {
                if attempts.fetch_add(1, Ordering::SeqCst) < 3 {
                    Err(throttled())
                } else {
                    Ok("done")
                }
            },
            |delay| {
                waits.lock().unwrap().push(delay);
                async {}
            },
        )
        .await
        .unwrap();
        assert_eq!(results, ["done"]);
        assert_eq!(
            *waits.lock().unwrap(),
            [
                Duration::from_millis(50),
                Duration::from_millis(100),
                Duration::from_millis(200)
            ]
        );
    }

    #[tokio::test]
    async fn still_throttled_after_the_last_attempt_fails_the_batch() {
        let attempts = AtomicUsize::new(0);
        let result = run_batch(
            &options(),
            1,
            |_| async {
                let _ = attempts.fetch_add(1, Ordering::SeqCst);
                Err::<(), _>(throttled())
            },
            |_| async {},
        )
        .await;
        assert!(matches!(
            result,
            Err(Error::Backend {
                kind: BackendErrorKind::Throttled,
                ..
            })
        ));
        assert_eq!(attempts.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn any_other_failure_fails_the_whole_batch_without_a_retry() {
        let attempts = AtomicUsize::new(0);
        let result = run_batch(
            &options(),
            6,
            |index| {
                let _ = attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    if index == 2 {
                        Err(Error::Backend {
                            backend: stack_kms::KeyVendor::Static.into(),
                            kind: BackendErrorKind::AccessDenied,
                            source: "no".into(),
                        })
                    } else {
                        Ok(index)
                    }
                }
            },
            |_| async {},
        )
        .await;
        assert!(matches!(
            result,
            Err(Error::Backend {
                kind: BackendErrorKind::AccessDenied,
                ..
            })
        ));
    }

    #[test]
    fn the_delay_doubles_up_to_the_cap() {
        let options = BatchOptions::default();
        assert_eq!(options.delay_after(1), Duration::from_millis(50));
        assert_eq!(options.delay_after(2), Duration::from_millis(100));
        assert_eq!(options.delay_after(6), Duration::from_millis(1600));
        assert_eq!(options.delay_after(7), Duration::from_secs(2));
        assert_eq!(options.delay_after(40), Duration::from_secs(2));
        assert_eq!(options.concurrency.get(), 16);
    }
}
