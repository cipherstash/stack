//! Exact SQL assets bundled with a published `eql-bindings` release.

/// Release metadata for the SQL bundle.
pub const RELEASE_MANIFEST_JSON: &str = include_str!("../sql/release-manifest.json");

/// Self-contained EQL v3 install SQL for this crate version.
pub const INSTALL_SQL: &str = include_str!("../sql/cipherstash-encrypt.sql");

/// Self-contained EQL v3 uninstall SQL for this crate version.
pub const UNINSTALL_SQL: &str = include_str!("../sql/cipherstash-encrypt-uninstall.sql");
