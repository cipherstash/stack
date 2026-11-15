//! One vendor call, with backoff on a throttle.

use std::future::Future;
use std::time::Duration;

use stack_kms::{BackendErrorKind, Error};

/// How [`retry`] tries a vendor call again after a throttle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryOptions {
    /// The most attempts for one call, the first one included. A call is
    /// tried again only after a `Throttled` failure. Default 5.
    pub max_attempts: u32,
    /// The wait before the second attempt. Each later wait is double the
    /// one before it, up to `max_delay`. Default 50 ms.
    pub base_delay: Duration,
    /// The longest wait between two attempts. Default 2 s.
    pub max_delay: Duration,
}

impl Default for RetryOptions {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(2),
        }
    }
}

impl RetryOptions {
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

/// Run `call`, and run it again after `sleep(delay)` each time it fails
/// with [`Throttled`](stack_kms::BackendErrorKind::Throttled), with an
/// exponential delay, up to [`max_attempts`](RetryOptions::max_attempts)
/// in all. Any other failure, or a call that is still throttled after the
/// last attempt, is returned as it is.
///
/// Runtime-agnostic: it uses no timer of its own. `sleep` is the caller's
/// timer ([`KeyVendorBackend::sleep`](crate::KeyVendorBackend::sleep)).
pub async fn retry<T, F, Fut, S, SFut>(
    options: &RetryOptions,
    call: F,
    sleep: S,
) -> Result<T, Error>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, Error>>,
    S: Fn(Duration) -> SFut,
    SFut: Future<Output = ()>,
{
    let mut attempt = 1;
    loop {
        match call().await {
            Err(error) if is_throttled(&error) && attempt < options.max_attempts => {
                sleep(options.delay_after(attempt)).await;
                attempt += 1;
            }
            result => return result,
        }
    }
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

    #[tokio::test]
    async fn a_throttled_call_backs_off_and_is_tried_again() {
        let attempts = AtomicUsize::new(0);
        let waits = Mutex::new(Vec::new());
        let result = retry(
            &RetryOptions::default(),
            || async {
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
        assert_eq!(result, "done");
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
    async fn still_throttled_after_the_last_attempt_fails() {
        let attempts = AtomicUsize::new(0);
        let result = retry(
            &RetryOptions::default(),
            || async {
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
    async fn any_other_failure_is_not_tried_again() {
        let attempts = AtomicUsize::new(0);
        let result = retry(
            &RetryOptions::default(),
            || async {
                let _ = attempts.fetch_add(1, Ordering::SeqCst);
                Err::<(), _>(Error::Backend {
                    backend: stack_kms::KeyVendor::Static.into(),
                    kind: BackendErrorKind::AccessDenied,
                    source: "no".into(),
                })
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
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_delay_doubles_up_to_the_cap() {
        let options = RetryOptions::default();
        assert_eq!(options.delay_after(1), Duration::from_millis(50));
        assert_eq!(options.delay_after(2), Duration::from_millis(100));
        assert_eq!(options.delay_after(6), Duration::from_millis(1600));
        assert_eq!(options.delay_after(7), Duration::from_secs(2));
        assert_eq!(options.delay_after(40), Duration::from_secs(2));
    }
}
