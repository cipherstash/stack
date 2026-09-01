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
//! ```
//! use stack_encrypt::sem::{EqualityTerm, OreTerm};
//! use stack_encrypt::target::EncryptInto;
//! use stack_encrypt::{DecryptInto, EncryptFrom, StackCipher, StackCipherText};
//! use stack_kms::FakeDataKeySource;
//!
//! /// An encrypted integer, queryable by equality and range.
//! #[derive(EncryptFrom, DecryptInto)]
//! #[stash(plaintext = u32)]
//! struct EncryptedAge {
//!     c: StackCipherText,
//!     hm: EqualityTerm,
//!     ob: OreTerm<u32>,
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let cipher = StackCipher::builder()
//!     .kms(FakeDataKeySource::new())
//!     .init()
//!     .await?;
//! let record: EncryptedAge = 42u32
//!     .encrypt_into_with_context(&cipher, "users/age")
//!     .await?;
//! let age: u32 = record.decrypt_into(&cipher, "users/age").await?;
//! assert_eq!(age, 42);
//! # Ok::<(), stack_encrypt::Error>(())
//! # }).unwrap();
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
//! The record takes the caller's context because its fields do: the derive
//! bounds the impl's context parameter by what each field accepts, so a
//! record of leaves — which accept only a `SuppliedContext` — is encrypted
//! with `encrypt_into_with_context`, and the context-free `encrypt_into`
//! does not compile against it. That is decided by the field types, not by
//! an attribute.
//!
//! Decryption opens the ciphertext field and passes over the terms, and no
//! attribute says which is which: each field type does, through
//! `Decryptable`, and the derive checks at compile time that exactly one
//! field is a ciphertext. `#[stash(decrypt)]` names the field only when the
//! types cannot — two ciphertexts, say.
//!
//! # Rows
//!
//! One level up, the same derive: a struct whose fields are each derived from
//! a *field* of the plaintext, under a context of their own. `row = User,
//! context = "users"` says so once, for every field: `age` is derived from
//! `user.age` under `"users/age"`, `email` from `user.email` under
//! `"users/email"` — the table you name and the field, nothing invented.
//! Attributes on the fields are for the exceptions: `from = ..` when the
//! names differ, `context = ".."` to pin a whole context by hand, `nested`
//! for a field whose type is itself a row carrying its own contexts.
//!
//! ```
//! # use stack_encrypt::sem::{EqualityTerm, OreTerm};
//! # use stack_encrypt::target::{DecryptFrom, EncryptInto};
//! # use stack_encrypt::{DecryptInto, EncryptFrom, StackCipher, StackCipherText};
//! # use stack_kms::FakeDataKeySource;
//! # #[derive(EncryptFrom, DecryptInto)]
//! # #[stash(plaintext = u32)]
//! # struct EncryptedAge {
//! #     c: StackCipherText,
//! #     hm: EqualityTerm,
//! #     ob: OreTerm<u32>,
//! # }
//! #[derive(Debug, PartialEq)]
//! struct User {
//!     age: u32,
//!     email: String,
//! }
//!
//! #[derive(EncryptFrom, DecryptInto)]
//! #[stash(row = User, context = "users")]
//! struct EncryptedUser {
//!     age: EncryptedAge,
//!     email: StackCipherText,
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! # let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! let user = User { age: 42, email: "alice@example.com".into() };
//! let row: EncryptedUser = user.encrypt_into(&cipher).await?; // one batch
//! let users = vec![User { age: 1, email: "a".into() }, User { age: 2, email: "b".into() }];
//! let rows: Vec<EncryptedUser> = users.encrypt_into(&cipher).await?; // still one
//! let user = User::decrypt_from(row, &cipher).await?;
//! assert_eq!(user, User { age: 42, email: "alice@example.com".into() });
//! assert_eq!(rows.len(), 2);
//! # Ok::<(), stack_encrypt::Error>(())
//! # }).unwrap();
//! ```
//!
//! A row field's context is the *column's* identity — `"users/age"` is what a
//! query site derives a probe under — which is why it is a literal per field
//! rather than something composed from a context the caller passes. A row
//! takes no context from the caller at all: its impls are for `()` exactly,
//! which is what makes the context-free `encrypt_into` / `decrypt_from` the
//! forms that compile against it. A `plaintext = ..` record's `from` field
//! with no `context` is handed `()` too, and its type decides whether that
//! will do: a nested row accepts it; a leaf refuses it, at the field, until
//! it is given a `context`. In a row, `#[stash(nested)]` is the same
//! hand-off: it marks the fields whose types carry their own contexts, so no
//! context is inferred for them.
//!
//! The prefix is given explicitly (`context = "users"`), never inferred from
//! the Rust type's name: it is part of the stored data's identity — the AAD
//! of every ciphertext in the row and the domain of every term — and a name
//! two types share, or a refactor changes, must not be able to move it
//! silently. The field half is still inferred from the plaintext field's
//! name, so renaming a plaintext field changes that column's context and
//! stored rows stop decrypting; pin the old value with `context = ".."` on
//! the field before such a rename. The [attributes](#rows) section says more.
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
//! every field of the plaintext must be recovered by exactly one ciphertext
//! field derived from it, and the plaintext must be a struct visible where
//! the derive expands.
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
#[proc_macro_derive(EncryptFrom, attributes(stash))]
pub fn derive_encrypt_from(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    encrypt::derive(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Derive `DecryptInto<Plaintext, _, _>` for a record struct, one impl per
/// `plaintext` type. See the [crate documentation](crate); the attributes it
/// accepts are reproduced below.
#[doc = include_str!("../docs/attributes.md")]
#[proc_macro_derive(DecryptInto, attributes(stash))]
pub fn derive_decrypt_into(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    decrypt::derive(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
