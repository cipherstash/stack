//! The Node addon of `@cipherstash/recipher`.
//!
//! It defines the classes the package exports, [`Cipher`], [`Keyset`] and
//! [`Ciphertext`], and runs every operation through the Stack Encrypt engine.
//! napi-rs generates their TypeScript declarations (`native.d.ts`) from this
//! crate. It reads and builds JavaScript values only through vitaminc's
//! `vitaminc-aead-napi` (see [`js`]).
//!
//! # Outcomes
//!
//! A call that can fail returns an outcome object, `{ ok: true, value }` or
//! `{ ok: false, error }`, where `error` is a [`RecipherErrorFields`]; an
//! asynchronous call resolves to one and never rejects for a failure it can
//! report. Every argument is taken as an untyped JavaScript value and
//! checked here, so a value of the wrong type is an outcome too, never an
//! exception. The package's TypeScript turns an outcome into its `Result`.
//!
//! # The interface number
//!
//! [`binding_interface`] reports [`BINDING_INTERFACE`], the version of what
//! the TypeScript calls. It changes whenever a class, a method or an
//! outcome changes shape, and the TypeScript refuses a build that reports
//! another number.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::mem_forget)]
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]
#![warn(clippy::dbg_macro)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::panic))]

mod cipher;
mod ciphertext;
mod error;
pub mod js;
mod outcome;
mod value;

pub use cipher::{create_testing, Cipher, Keyset};
pub use ciphertext::Ciphertext;
pub use error::{ErrorKind, RecipherErrorFields};

use napi_derive::napi;

/// The version of the interface between the package's TypeScript and this
/// build.
pub const BINDING_INTERFACE: u32 = 1;

/// The version of the interface between the package's TypeScript and this
/// build. The TypeScript refuses a build that reports another.
#[napi]
pub fn binding_interface() -> u32 {
    BINDING_INTERFACE
}
