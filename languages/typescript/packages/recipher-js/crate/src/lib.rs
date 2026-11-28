//! The Node addon of `@cipherstash/recipher`.
//!
//! The addon defines the classes the package exports: [`Cipher`],
//! [`Keyset`], [`Ciphertext`], and [`Json`]. Every operation runs through the
//! Stack Encrypt engine, the `stack-encrypt` crate. The engine encrypts and
//! decrypts values with keys from ZeroKMS, CipherStash's key service.
//!
//! napi-rs generates the classes' TypeScript declarations (`native.d.ts`)
//! from this crate. The crate reads and builds JavaScript values only
//! through the `recipher-value-napi` crate. The `js` module does that.
//!
//! # Results
//!
//! A call that can fail returns the package's `Result` instead of throwing:
//! an `Ok` of the value, or an `Err` of a `RecipherError`. An asynchronous
//! call resolves to a `Result`, and does not reject. The addon builds each
//! `Result` itself, from the classes the package's TypeScript installs when
//! it loads the addon ([`install_result`]).
//!
//! Every argument arrives as an untyped JavaScript value, and the addon
//! checks it. So a value of the wrong type gives an `Err`, not an
//! exception.
//!
//! One call of the addon's throws: a method called without its object, as
//! in `stored.map(cipher.decrypt)`. The JavaScript engine checks the object
//! and throws a `TypeError` before any of the addon's code runs.
//!
//! The wrapper classes are `RcDate`, `RcTimestamp`, `RcDecimal`, and
//! `RcUuid`. The value bridge defines them in JavaScript. A wrapper class's
//! constructor throws a `TypeError` for an argument that is not a string.
//!
//! The `ts_type`, `ts_args_type`, and `ts_return_type` attributes give each
//! method the signature that the package exports. The build writes the
//! signatures to `native.d.ts`, after the header in `native-header.d.ts`.
//! `native.d.ts` is the package's public type.
//!
//! # The interface number
//!
//! [`binding_interface`] returns [`BINDING_INTERFACE`]. That number is the
//! version of the interface that the package's TypeScript calls. The
//! TypeScript states the same number, as `BINDING_INTERFACE` in
//! `src/binding.ts`, and refuses an addon build that returns another one.
//! So an addon built from older or newer code fails when it loads, with the
//! code `recipher_js::binding_interface`. The build does not fail later, on
//! a call whose arguments or result changed shape.
//!
//! Add 1 to the number in both places whenever a class, a method, or a
//! returned value changes shape.
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
mod js;
mod json;
mod outcome;
mod value;

#[cfg(all(test, feature = "testing"))]
mod engine_tests;

pub use cipher::{create_testing, Cipher, Keyset};
pub use ciphertext::Ciphertext;
pub use error::RecipherErrorFields;
pub use json::{json_document, Json};
pub use outcome::install_result;

use napi::bindgen_prelude::{JsObjectValue, Object, Unknown};
use napi::Env;
use napi_derive::napi;

/// The version of the interface between the package's TypeScript and this
/// addon build.
pub const BINDING_INTERFACE: u32 = 2;

/// Returns the version of the interface between the package's TypeScript
/// and this addon build. The TypeScript refuses a build that returns
/// another version.
#[napi]
pub fn binding_interface() -> u32 {
    BINDING_INTERFACE
}

/// Exports the value bridge's wrapper classes: `RcDate`, `RcTimestamp`,
/// `RcDecimal`, and `RcUuid`. Each class represents a type that JavaScript
/// does not have. The addon exports the classes so that JavaScript can
/// construct them. A decrypted value is then an instance of the same
/// classes.
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
