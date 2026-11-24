//! The Node addon of `@cipherstash/recipher`.
//!
//! The addon defines the classes the package exports: [`Cipher`],
//! [`Keyset`], [`Ciphertext`] and [`Json`]. Every operation runs through the
//! Stack Encrypt engine, the `stack-encrypt` crate. The engine encrypts and
//! decrypts values with keys from ZeroKMS, CipherStash's key service.
//!
//! napi-rs generates the classes' TypeScript declarations (`native.d.ts`)
//! from this crate. The crate reads and builds JavaScript values only
//! through the `recipher-value-napi` crate (see [`js`]).
//!
//! # Outcomes
//!
//! A call that can fail returns an outcome object instead of throwing. An
//! outcome object is `{ ok: true, value }` on success, or
//! `{ ok: false, error }` on failure. The `error` is a
//! [`RecipherErrorFields`]. An asynchronous call resolves to an outcome
//! object, and does not reject for a failure it can report.
//!
//! Every argument arrives as an untyped JavaScript value, and the addon
//! checks it. So a value of the wrong type gives a failed outcome object,
//! not an exception. The package's TypeScript turns each outcome object
//! into its `Result` type.
//!
//! # The interface number
//!
//! [`binding_interface`] returns [`BINDING_INTERFACE`]. That number is the
//! version of the interface that the package's TypeScript calls. The number
//! changes whenever a class, a method or an outcome object changes shape.
//! The TypeScript refuses an addon build that returns another number.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::mem_forget)]
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]
#![warn(clippy::dbg_macro)]
// A failure is built field for field as the object JavaScript receives.
// It is built only when a call fails, so boxing it would gain nothing.
#![allow(clippy::result_large_err)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::panic))]

mod cipher;
mod ciphertext;
mod error;
mod frames;
mod js;
mod json;
mod outcome;
mod record;
mod value;

#[cfg(all(test, feature = "testing"))]
mod engine_tests;
#[cfg(all(test, feature = "testing"))]
mod record_tests;

pub use cipher::{check_declarations, create_testing, Cipher, Keyset};
pub use ciphertext::Ciphertext;
pub use error::RecipherErrorFields;
pub use json::{json_document, Json};

use napi::bindgen_prelude::{JsObjectValue, Object, Unknown};
use napi::Env;
use napi_derive::napi;

/// The version of the interface between the package's TypeScript and this
/// addon build.
pub const BINDING_INTERFACE: u32 = 4;

/// Returns the version of the interface between the package's TypeScript
/// and this addon build. The TypeScript refuses a build that returns
/// another version.
#[napi]
pub fn binding_interface() -> u32 {
    BINDING_INTERFACE
}

/// Exports the wrapper classes of vitaminc, CipherStash's cryptography
/// library: `VcDate`, `VcTimestamp`, `VcDecimal` and `VcUuid`. Each class
/// stands for a type that JavaScript does not have. The addon exports them
/// so JavaScript can construct them, and so decrypted values are instances
/// of them.
// napi's module registration calls this function. `clippy --all-targets`
// also builds the crate as a test, where nothing calls it.
#[cfg_attr(test, allow(dead_code))]
#[napi(module_exports)]
fn wrappers(mut exports: Object<'_>, env: Env) -> napi::Result<()> {
    let classes = recipher_value_napi::Wrappers::exports(&env)?;
    for wrapper in recipher_value_napi::Wrapper::ALL {
        let name = wrapper.class_name();
        exports.set_named_property(name, classes.get_named_property::<Unknown<'_>>(name)?)?;
    }
    Ok(())
}
