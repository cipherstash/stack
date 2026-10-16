//! Derive macros for [`vitaminc-aead`](https://docs.rs/vitaminc-aead):
//! [`Plaintext`] and [`Decrypt`].
//!
//! Both are re-exported from `vitaminc_aead`, so depend on that crate
//! rather than this one:
//!
//! ```ignore
//! use vitaminc_aead::{Decrypt, Plaintext};
//!
//! #[derive(Plaintext, Decrypt)]
//! struct User {
//!     name: String,
//!     age: u32,
//! }
//! ```
//!
//! `#[derive(Plaintext)]` walks the struct into a sink as a map with one
//! entry per field. `#[derive(Decrypt)]` generates the map sink that builds
//! the struct back, routing each entry to the field's own sink.
//!
//! # Wire shape
//!
//! A struct is encrypted as a **map**, keyed by field name. This is the
//! deliberate choice over a sequence: the encrypting sink binds each entry's
//! key into the AAD its value is sealed against (`Context::for_map_entry`),
//! so a stored ciphertext cannot have its fields renamed or swapped without
//! decryption failing. Sequence elements carry no such binding — their AAD
//! has no positional component — so two same-typed fields encoded as a
//! sequence would be freely interchangeable.
//!
//! The consequences of the map shape:
//!
//! - Field **names are part of the ciphertext contract**. Renaming a field is
//!   a wire-breaking change; use `#[aead(rename = "...")]` to keep an old name.
//! - A derived struct's ciphertext is interchangeable with the equivalent
//!   `HashMap<String, _>` ciphertext, and with a map a host binding wrote.
//! - Tuple structs of two or more fields use the decimal field index as the
//!   key (`"0"`, `"1"`, …), so they get the same per-field binding.
//! - A **newtype** struct (exactly one unnamed field) is *transparent*: it
//!   encrypts and decrypts exactly as its inner type, adding nothing to the
//!   ciphertext. This mirrors serde, and matches how `Protected<T>` behaves.
//! - A unit struct — or a struct with no fields — encrypts to the
//!   authenticated empty-map marker.
//!
//! Field values are **not** authenticated in any particular order, so the
//! derived `Decrypt` reads keys first and matches them to fields. Decoding is
//! strict: an unknown key, a duplicate key, or a missing field is rejected.
//!
//! # Enums
//!
//! A **fieldless** enum is one `u32` leaf holding the variant's discriminant:
//! an explicit `= n`, or one more than the previous variant's, as Rust
//! assigns them. The leaf is sealed and authenticated like any other, and it
//! is fixed-width, so the ciphertext's length does not give the variant away
//! either. Decoding is strict: an int that is no variant's discriminant is
//! refused. Pin the discriminants with `= n` before storing anything, since
//! reordering variants otherwise changes them. Variants take no
//! `#[aead(...)]` attributes.
//!
//! Enums with fields are not supported. Their payload has no agreed layout
//! (internally or externally tagged, per-variant AAD), so model the choice
//! explicitly, as a struct with a fieldless discriminant and `Option`
//! fields.
//!
//! [`Plaintext`]: https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Plaintext.html
//! [`Decrypt`]: https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Decrypt.html
#![doc = include_str!("../docs/attributes.md")]
#![deny(unsafe_code)]

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod attrs;
mod plaintext;
mod shape;
#[cfg(test)]
mod test_support;
mod typed_decrypt;

/// Derive [`Plaintext`](https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Plaintext.html)
/// for a struct or a fieldless enum. See the [crate documentation](crate) for
/// the wire shape this produces; the attributes it accepts are reproduced
/// below.
#[doc = include_str!("../docs/attributes.md")]
#[proc_macro_derive(Plaintext, attributes(aead))]
pub fn derive_plaintext(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    plaintext::derive(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Derive [`Decrypt`](https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Decrypt.html)
/// for a struct or a fieldless enum: the sink that builds it. See the
/// [crate documentation](crate) for the wire shape this consumes; the
/// attributes it accepts are reproduced below.
#[doc = include_str!("../docs/attributes.md")]
#[proc_macro_derive(Decrypt, attributes(aead))]
pub fn derive_decrypt(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    typed_decrypt::derive(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
