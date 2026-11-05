//! The time source of a client.

use web_time::SystemTime;

/// The time source of a token cache: `SystemTime::now` unless a test sets
/// another.
pub type Clock = std::sync::Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// The system clock.
pub fn system_clock() -> Clock {
    std::sync::Arc::new(SystemTime::now)
}
