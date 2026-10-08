// Security lints
#![deny(unsafe_code)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::panic)]
// Prevent mem::forget from bypassing ZeroizeOnDrop
#![warn(clippy::mem_forget)]
// Prevent accidental data leaks via output
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]
#![warn(clippy::dbg_macro)]
// Code quality
#![warn(unreachable_pub)]
#![warn(unused_results)]
#![warn(clippy::todo)]
#![warn(clippy::unimplemented)]
// Relax in tests
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::panic))]
#![cfg_attr(test, allow(unused_results))]

//! Centralised `~/.cipherstash/` profile file management.
//!
//! The core type is [`ProfileStore`], a directory-scoped JSON file store that
//! handles reading, writing, and deleting profile data on disk.
//!
//! # Example
//!
//! ```no_run
//! use stack_profile::ProfileStore;
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct MyConfig {
//!     name: String,
//! }
//!
//! # fn main() -> Result<(), stack_profile::ProfileError> {
//! let store = ProfileStore::default();
//!
//! store.save("my-config.json", &MyConfig { name: "example".into() })?;
//! let config: MyConfig = store.load("my-config.json")?;
//! # Ok(())
//! # }
//! ```
//!
//! For sensitive files, use [`ProfileStore::save_with_mode`] to restrict permissions:
//!
//! ```no_run
//! # use stack_profile::ProfileStore;
//! # use serde::{Serialize, Deserialize};
//! # #[derive(Serialize, Deserialize)]
//! # struct Secret { key: String }
//! # fn main() -> Result<(), stack_profile::ProfileError> {
//! let store = ProfileStore::default();
//! store.save_with_mode("secret.json", &Secret { key: "shhh".into() }, 0o600)?;
//! # Ok(())
//! # }
//! ```

use serde::de::DeserializeOwned;
use serde::Serialize;

mod device_identity;
pub mod diagnostic;
mod error;
mod profile_store;

pub use device_identity::DeviceIdentity;
pub use diagnostic::ErrorPayload;
pub use error::ProfileError;
pub use profile_store::{FileLockGuard, ProfileStore};

/// A type that can be stored in a profile directory.
pub trait ProfileData: Serialize + DeserializeOwned {
    /// The filename used when saving/loading this type (e.g. `"secretkey.json"`).
    const FILENAME: &'static str;

    /// Unix file permissions for this file. `None` uses the default umask.
    /// Sensitive files should return `Some(0o600)`.
    const MODE: Option<u32> = None;
}
