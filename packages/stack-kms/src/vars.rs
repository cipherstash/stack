//! Environment variable names recognised by `stack-kms`.
//!
//! These mirror the names used by `cipherstash-client` so the two crates stay
//! interchangeable for credential discovery.

/// Endpoint override for the ZeroKMS service. The first present variable wins;
/// `CS_VITUR_HOST` is the legacy name kept for backwards compatibility.
pub static CS_ZEROKMS_HOST: &[&str] = &["CS_ZEROKMS_HOST", "CS_VITUR_HOST"];

/// The client (device) ID used to authenticate key operations.
pub static CS_CLIENT_ID: &str = "CS_CLIENT_ID";

/// The client key material (hex or base64 encoded) used to derive data keys.
pub static CS_CLIENT_KEY: &str = "CS_CLIENT_KEY";
