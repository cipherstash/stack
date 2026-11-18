//! The time source of a client.

#[cfg(feature = "service-account")]
use web_time::SystemTime;

/// The time source of a token cache and of the service account JWT:
/// `SystemTime::now` unless a test sets another.
pub use stack_kms_vendor::{system_clock, Clock};

/// Seconds since the Unix epoch. A time before the epoch is 0.
#[cfg(feature = "service-account")]
pub(crate) fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(web_time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
