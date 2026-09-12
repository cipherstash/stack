//! Derive macros for the [`Encrypt`] and [`Decrypt`] traits of
//! [`vitaminc-aead`](https://docs.rs/vitaminc-aead).
//!
//! Both macros are re-exported from `vitaminc_aead`, so depend on that crate
//! rather than this one:
//!
//! ```ignore
//! use vitaminc_aead::{Decrypt, Encrypt};
//!
//! #[derive(Encrypt, Decrypt)]
//! struct User {
//!     name: String,
//!     age: u32,
//! }
//! ```
//!
//! # Wire shape
//!
//! A struct is encrypted as a **map**, keyed by field name. This is the
//! deliberate choice over a sequence: [`MapCipher`] binds each entry's key
//! into the AAD its value is sealed against (`Context::for_map_entry`), so a
//! stored ciphertext cannot have its fields renamed or swapped without
//! decryption failing. Sequence elements carry no such binding — their AAD
//! has no positional component — so two same-typed fields encoded as a
//! sequence would be freely interchangeable.
//!
//! The consequences of the map shape:
//!
//! - Field **names are part of the ciphertext contract**. Renaming a field is
//!   a wire-breaking change; use `#[aead(rename = "...")]` to keep an old name.
//! - A derived struct's ciphertext is interchangeable with the equivalent
//!   `HashMap<String, _>` ciphertext.
//! - Tuple structs of two or more fields use the decimal field index as the
//!   key (`"0"`, `"1"`, …), so they get the same per-field binding.
//! - A **newtype** struct (exactly one unnamed field) is *transparent*: it
//!   encrypts and decrypts exactly as its inner type, adding nothing to the
//!   ciphertext. This mirrors serde, and matches how `Protected<T>` and
//!   `Equatable<T>` behave.
//! - A unit struct — or a struct with no fields — encrypts to the
//!   authenticated empty-map marker.
//!
//! Field values are **not** authenticated in any particular order, so the
//! derived `Decrypt` reads keys first and matches them to fields. Decoding is
//! strict: an unknown key, a duplicate key, or a missing field is rejected.
//!
//! # Enums
//!
//! Enums are not supported. The ciphertext carries no authenticated variant
//! discriminator, so any encoding this macro could pick would either leak the
//! variant in the clear or leave it forgeable. Model the choice explicitly
//! (e.g. as a struct with `Option` fields) instead.
//!
//! [`Encrypt`]: https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Encrypt.html
//! [`Decrypt`]: https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Decrypt.html
//! [`MapCipher`]: https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.MapCipher.html
#![doc = include_str!("../docs/attributes.md")]
#![deny(unsafe_code)]

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod attrs;
mod decrypt;
mod encrypt;
mod shape;
#[cfg(test)]
mod test_support;

/// Derive [`Encrypt`](https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Encrypt.html)
/// for a struct. See the [crate documentation](crate) for the wire shape this
/// produces; the attributes it accepts are reproduced below.
#[doc = include_str!("../docs/attributes.md")]
#[proc_macro_derive(Encrypt, attributes(aead))]
pub fn derive_encrypt(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    encrypt::derive(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Derive [`Decrypt`](https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Decrypt.html)
/// for a struct. See the [crate documentation](crate) for the wire shape this
/// consumes; the attributes it accepts are reproduced below.
#[doc = include_str!("../docs/attributes.md")]
#[proc_macro_derive(Decrypt, attributes(aead))]
pub fn derive_decrypt(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    decrypt::derive(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
