//! A small abstraction over "the current Unix time", in whole seconds.
//!
//! Token expiry ([`Token::is_expired`](crate::Token::is_expired),
//! [`Token::is_usable`](crate::Token::is_usable)) is time-dependent. In
//! production that time comes from the system wall clock, but a wall clock makes
//! the refresh concurrency tests inherently racy — the token's usable window is
//! measured in whole seconds, so test setup (or coverage instrumentation) can
//! cross an expiry boundary before the assertions run.
//!
//! [`Clock`] lets [`AutoRefresh`](crate::auto_refresh::AutoRefresh) read "now"
//! from an injected source: [`SystemClock`] in production, a controllable clock
//! in tests.

use std::sync::Arc;

use web_time::{SystemTime, UNIX_EPOCH};

/// Source of the current time as seconds since the Unix epoch.
pub(crate) trait Clock: Send + Sync {
    /// The current time, in whole seconds since the Unix epoch.
    fn now_unix_secs(&self) -> u64;
}

/// A shared, type-erased [`Clock`] handle.
///
/// Type-erased (rather than a generic parameter on `AutoRefresh`) so injecting a
/// clock doesn't ripple a third generic through every strategy wrapper.
pub(crate) type SharedClock = Arc<dyn Clock>;

/// The default [`Clock`]: the system wall clock.
///
/// Uses `web_time` rather than `std::time` so it behaves correctly on `wasm32`,
/// matching the rest of the crate's time handling.
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// The default shared clock (the system wall clock).
///
/// Returns clones of one process-wide handle: `SystemClock` is a stateless ZST,
/// so there's no reason to allocate a fresh `Arc` per `AutoRefresh`.
pub(crate) fn system_clock() -> SharedClock {
    static CLOCK: std::sync::LazyLock<SharedClock> =
        std::sync::LazyLock::new(|| Arc::new(SystemClock));
    CLOCK.clone()
}

/// A [`Clock`] whose value is set explicitly by the test, so token expiry can be
/// driven deterministically rather than racing the wall clock.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestClock(Arc<std::sync::atomic::AtomicU64>);

#[cfg(test)]
impl TestClock {
    /// Create a clock reading `now` seconds.
    pub(crate) fn new(now: u64) -> Self {
        Self(Arc::new(std::sync::atomic::AtomicU64::new(now)))
    }

    /// Move the clock forward by `secs` seconds.
    pub(crate) fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, std::sync::atomic::Ordering::SeqCst);
    }

    /// Set the clock to an arbitrary value, including one earlier than the
    /// current reading — used to simulate the wall clock jumping backwards
    /// (NTP step, VM snapshot restore, manual clock change).
    pub(crate) fn set(&self, now: u64) {
        self.0.store(now, std::sync::atomic::Ordering::SeqCst);
    }

    /// The current value of the clock.
    pub(crate) fn now(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// A [`SharedClock`] handle backed by this same underlying value, so the test
    /// and the `AutoRefresh` under test observe identical time.
    pub(crate) fn shared(&self) -> SharedClock {
        Arc::new(self.clone())
    }
}

#[cfg(test)]
impl Clock for TestClock {
    fn now_unix_secs(&self) -> u64 {
        self.now()
    }
}
