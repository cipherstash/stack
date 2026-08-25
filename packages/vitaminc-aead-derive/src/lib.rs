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
//! into the AAD its value is sealed against (`Aad::for_map_entry`), so a
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
//! # Attributes
//!
//! - `#[aead(crate = "path::to::vitaminc_aead")]` on the container — point the
//!   generated code at a re-export of `vitaminc_aead` (e.g. `::vitaminc::aead`).
//! - `#[aead(rename = "name")]` on a field — use `name` as the map key instead
//!   of the field's own name.
//! - `#[aead(passthrough)]` on a field — store the value **in the clear**
//!   instead of encrypting it. See the section below before reaching for it.
//!
//! # Passthrough fields
//!
//! `#[aead(passthrough)]` stores a field as a cleartext map entry, so it can be
//! an ordinary database column that other queries select, filter, and update
//! without holding the key:
//!
//! ```ignore
//! #[derive(Encrypt, Decrypt)]
//! struct Row {
//!     #[aead(passthrough)]
//!     tenant: String,   // a plain column
//!     ssn: String,      // encrypted
//! }
//! ```
//!
//! That independence is bought by giving up all protection on the field, and
//! the trade is total:
//!
//! - The value is **not encrypted** — anyone who can read the stored ciphertext
//!   can read it.
//! - The value is **not authenticated**. No tag covers it, and unlike an
//!   encrypted entry's key, nothing binds its key either. It can be edited,
//!   retargeted at another key, or removed, and the surrounding encrypted
//!   fields still decrypt. Treat what comes back as untrusted input — it is
//!   exactly as trustworthy as the column it was read from.
//! - Deleting the entry is caught only by the ordinary missing-field rule, and
//!   not distinguished from a value that was never written.
//!
//! So: non-sensitive, non-security-deciding data only. Never a field the
//! program later trusts to make an authorization choice. If a cleartext field
//! must be tamper-evident, it needs to be bound into the AAD rather than passed
//! through — and note that binding it couples the two, so any independent write
//! to that column breaks decryption of every encrypted field beside it.
//!
//! Two shapes are rejected at compile time: a struct whose fields are *all*
//! passthrough (nothing would be encrypted, so the ciphertext would carry no
//! tag at all — `MapCipher::end` refuses to seal one), and `passthrough` on a
//! newtype (transparent, so there is no map entry to hold it).
//!
//! A passthrough field's type must be `Any + Send + 'static`, since the value
//! travels through the cipher type-erased and is downcast on the way out. That
//! rules out borrowed types such as `&'a str`.
//!
//! [`Encrypt`]: https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Encrypt.html
//! [`Decrypt`]: https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Decrypt.html
//! [`MapCipher`]: https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.MapCipher.html
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
/// for a struct. See the [crate documentation](crate) for the wire shape and
/// supported attributes.
#[proc_macro_derive(Encrypt, attributes(aead))]
pub fn derive_encrypt(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    encrypt::derive(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Derive [`Decrypt`](https://docs.rs/vitaminc-aead/latest/vitaminc_aead/trait.Decrypt.html)
/// for a struct. See the [crate documentation](crate) for the wire shape and
/// supported attributes.
#[proc_macro_derive(Decrypt, attributes(aead))]
pub fn derive_decrypt(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    decrypt::derive(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
