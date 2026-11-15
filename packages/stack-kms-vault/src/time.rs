//! The time source of a client.

/// The time source of a token cache: `SystemTime::now` unless a test sets
/// another.
pub use stack_kms_vendor::{system_clock, Clock};
