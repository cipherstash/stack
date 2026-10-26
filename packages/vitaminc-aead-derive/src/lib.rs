//! Derive macros for [`vitaminc-aead`](https://docs.rs/vitaminc-aead):
//! [`Encrypt`] and [`Decrypt`].
//!
//! Both are re-exported from `vitaminc_aead`, so depend on that crate
//! rather than this one:
//!
//! ```rust
//! use vitaminc_aead::{Decrypt, Encrypt};
//!
//! #[derive(Encrypt, Decrypt)]
//! struct User {
//!     name: String,
//!     age: u32,
//! }
//! # let user = User { name: "Ada".into(), age: 37 };
//! # let plan = vitaminc_aead::plan::<_, std::convert::Infallible, _>(user, ()).unwrap();
//! # assert!(matches!(plan, vitaminc_aead::CipherText::Map(entries) if entries.len() == 2));
//! ```
//!
//! `#[derive(Encrypt)]` walks the struct into a sink as a map with one
//! entry per field. `#[derive(Decrypt)]` generates the map sink that builds
//! the struct back, routing each entry to the field's own sink.
//!
//! # Installation and compatibility
//!
//! Install the parent crate with `cargo add vitaminc-aead`. This macro crate
//! has no Cargo feature flags and requires Rust <!-- msrv:vitaminc-aead-derive -->**1.88.0**<!-- /msrv -->. The macros run on
//! the compiler host; the parent crate requires `std`.
//! MSRV increases require a minor release; patch releases retain the existing
//! floor. See the [workspace policy](https://github.com/cipherstash/vitaminc#compatibility).
//!
//! License: MIT.
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
// The derive and parent crates release together. Keep parent API links on the
// version being documented without adding a normal dependency cycle.
#![deny(missing_docs)]
#![doc = concat!(
    "\n[`Encrypt`]: https://docs.rs/vitaminc-aead/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_aead/trait.Encrypt.html\n",
    "[`Decrypt`]: https://docs.rs/vitaminc-aead/", env!("CARGO_PKG_VERSION"),
    "/vitaminc_aead/trait.Decrypt.html\n"
)]
#![doc = include_str!("../docs/attributes.md")]
#![deny(unsafe_code)]

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod attrs;
mod encrypt;
mod shape;
#[cfg(test)]
mod test_support;
mod typed_decrypt;

#[doc = concat!("Derive [`Encrypt`](https://docs.rs/vitaminc-aead/",
    env!("CARGO_PKG_VERSION"), "/vitaminc_aead/trait.Encrypt.html)")]
/// for a struct or a fieldless enum. See the [crate documentation](crate) for
/// the wire shape this produces; the attributes it accepts are reproduced
/// below.
#[doc = include_str!("../docs/attributes.md")]
#[proc_macro_derive(Encrypt, attributes(aead))]
pub fn derive_encrypt(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    encrypt::derive(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[doc = concat!("Derive [`Decrypt`](https://docs.rs/vitaminc-aead/",
    env!("CARGO_PKG_VERSION"), "/vitaminc_aead/trait.Decrypt.html)")]
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
