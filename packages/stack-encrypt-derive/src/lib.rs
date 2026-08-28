//! Derive macros for [`stack-encrypt`](https://docs.rs/stack-encrypt)'s
//! target-directed encryption: `EncryptFrom` and `DecryptInto` for composite
//! records.
//!
//! Both macros are re-exported from `stack_encrypt`, so depend on that crate
//! rather than this one.
//!
//! # What a record is
//!
//! A stored encrypted value is rarely just a ciphertext — it is a *record*:
//! the ciphertext plus whatever index terms make the field queryable. Leaf
//! types (`StackCipherText`, the `sem` terms) implement `EncryptFrom` by
//! hand; a record is a struct of leaves, and this derive writes its impl:
//!
//! ```ignore
//! use stack_encrypt::sem::{EqualityTerm, OreTerm};
//! use stack_encrypt::{DecryptInto, EncryptFrom, StackCipherText};
//!
//! /// An encrypted integer, queryable by equality and range.
//! #[derive(EncryptFrom, DecryptInto)]
//! #[stack_encrypt(plaintext = u32)]
//! struct EncryptedAge {
//!     #[stack_encrypt(decrypt)]
//!     c: StackCipherText,
//!     hm: EqualityTerm,
//!     ob: OreTerm<u32>,
//! }
//!
//! let record: EncryptedAge = 42u32.encrypt_into(&cipher, "users/age").await?;
//! let age: u32 = record.decrypt_into(&cipher, "users/age").await?;
//! ```
//!
//! Every derived field is fed the **same source** under the **same
//! context**, exactly as the hand-written impl would: the ciphertext is
//! sealed with the context as its AAD, and every term is domain-separated by
//! it, so a term built at a query site under `"users/age"` matches the one
//! stored in the record. The field pendings are combined without being
//! awaited, so however many fields a record has, awaiting it is **one**
//! batched ZeroKMS call.
//!
//! # Rows
//!
//! One level up, the same derive: a struct whose fields are each derived from
//! a *field* of the plaintext, under a context of their own.
//!
//! ```ignore
//! struct User {
//!     age: u32,
//!     email: String,
//! }
//!
//! #[derive(EncryptFrom, DecryptInto)]
//! #[stack_encrypt(plaintext = User)]
//! struct EncryptedUser {
//!     #[stack_encrypt(from = age, context = "users/age", decrypt)]
//!     age: EncryptedAge,
//!     #[stack_encrypt(from = email, context = "users/email", decrypt)]
//!     email: StackCipherText,
//! }
//!
//! let row: EncryptedUser = user.encrypt_into(&cipher, ()).await?;   // one batch
//! let rows: Vec<EncryptedUser> = users.encrypt_into(&cipher, ()).await?; // still one
//! let user: User = row.decrypt_into(&cipher, ()).await?;
//! ```
//!
//! A `from` field's context is the *column's* identity, which is why it is a
//! literal on the field rather than something composed from the row's
//! context: the row's context is simply not used by fields that have their
//! own (pass `()`), and stays available for any field that has none.
//!
//! # What the derive commits to
//!
//! The impls are over `StackCipher<K>` for any `K`, returning its `Pending`.
//! That is the only cipher today, and the only one whose output can be
//! combined without awaiting; a derive generic over any `EncryptTarget` needs
//! combinators on that trait and can replace this one without changing the
//! attribute surface.
//!
//! Field-by-field decryption rebuilds the plaintext with a struct literal, so
//! every field of the plaintext must be recovered by some `decrypt` field, and
//! the plaintext must be a struct visible where the derive expands.
//!
//! # Enums
//!
//! Not supported: a record is a fixed set of fields derived from one source,
//! and a variant choice has no field to be derived into. Model the choice as
//! a struct of `Option` fields.
#![doc = include_str!("../docs/attributes.md")]
#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
#![deny(unsafe_code)]
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::mem_forget,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::dbg_macro,
    clippy::todo,
    clippy::unimplemented
)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::panic))]

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod attrs;
mod decrypt;
mod encrypt;
mod shape;
#[cfg(test)]
mod test_support;

/// Derive `EncryptFrom` for a record struct. See the [crate
/// documentation](crate) for what the derive emits; the attributes it accepts
/// are reproduced below.
#[doc = include_str!("../docs/attributes.md")]
#[proc_macro_derive(EncryptFrom, attributes(stack_encrypt))]
pub fn derive_encrypt_from(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    encrypt::derive(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Derive `DecryptInto<Plaintext, _>` for a record struct, one impl per
/// `plaintext` type. See the [crate documentation](crate); the attributes it
/// accepts are reproduced below.
#[doc = include_str!("../docs/attributes.md")]
#[proc_macro_derive(DecryptInto, attributes(stack_encrypt))]
pub fn derive_decrypt_into(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    decrypt::derive(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
