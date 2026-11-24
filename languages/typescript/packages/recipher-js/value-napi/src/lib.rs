// These definitions precede the README so rustdoc links to the version being built.
// The README supplies published-API URLs for GitHub.
//! [`JsFault`]: crate::JsFault
//!
// Cross-crate links name the vitaminc version this crate is built with.
#![deny(missing_docs)]
#![doc = concat!(
    "\n[`Encrypt`]: https://docs.rs/vitaminc-aead/0.10.0/vitaminc_aead/trait.Encrypt.html\n",
    "\n[`Sink`]: https://docs.rs/vitaminc-aead/0.10.0/vitaminc_aead/trait.Sink.html\n",
)]
#![deny(clippy::unwrap_used, clippy::todo, unused_imports)]
// The only unsafe left is where napi-rs's conversion traits require it.
// Each block has to say why it is sound, and unsafe calls inside those trait
// methods still need their own block.
#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]
#![doc = include_str!("../README.md")]
mod ciphertext;
mod error;
mod js;
mod js_builder;
mod js_ref;
mod scalar;
mod wrappers;

pub use ciphertext::{JsCipherText, NapiPassthrough};
pub use error::JsFault;
pub use js::MAX_DEPTH;
pub use js_builder::JsBuilder;
pub use js_ref::JsRef;
pub use scalar::ConversionError;
pub use wrappers::{Wrapper, Wrappers};
