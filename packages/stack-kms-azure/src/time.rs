//! The time source of a client.

use web_time::{SystemTime, UNIX_EPOCH};

/// The time source of a token cache:
/// `SystemTime::now` unless a test sets another.
pub type Clock = std::sync::Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// The system clock.
pub fn system_clock() -> Clock {
    std::sync::Arc::new(SystemTime::now)
}

/// Seconds since the Unix epoch. A time before the epoch is 0.
pub(crate) fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
