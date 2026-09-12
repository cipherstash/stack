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
//! use stack_encrypt::{nonempty, DecryptInto, EncryptFrom, StackCipher, StackCipherText};
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
//! let keyset = cipher.default_keyset();
//! let record: EncryptedAge = 42u32
//!     .encrypt_into_with_context(&keyset, nonempty!("users/age"))
//!     .await?;
//! let age: u32 = record.decrypt_into(&cipher, nonempty!("users/age")).await?;
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
//! batched ZeroKMS call. Encrypting binds to a keyset — the `KeysetCipher`
//! every data key is minted and every term derived under — while decrypting
//! takes the client-scoped `StackCipher` (a sealed leaf names its own keyset)
//! or the `KeysetCipher`, which then refuses leaves from any other keyset.
//!
//! The record takes the caller's context because its fields do: the derive
//! emits one impl for `()` and one for `NonEmpty<T>`, each bounded by what
//! the fields accept under it, so a record of leaves — which accept only a
//! `NonEmpty<T>` — is encrypted with `encrypt_into_with_context`, and the
//! context-free `encrypt_into` does not compile against it. That is decided
//! by the field types, not by an attribute.
//!
//! Decryption opens the ciphertext field and passes over the terms, and no
//! attribute says which is which: each field type does, through
//! `Decryptable`, and the derive checks at compile time that exactly one
//! field is a ciphertext. `#[stash(decrypt)]` names the field only when the
//! types cannot — two ciphertexts, say.
//!
//! # Structs, field by field
//!
//! One level up, the same derive: a struct whose fields are each derived from
//! a *field* of the plaintext, under a context of their own. `struct = User,
//! context = "users"` says so once, for every field: `age` is derived from
//! `user.age` under `"users/age"`, `email` from `user.email` under
//! `"users/email"` — the prefix you name and the field, nothing invented.
//! Attributes on the fields are for the exceptions: `from = ..` when the
//! names differ, `context = ".."` to pin a whole context by hand, `nested`
//! for a field whose type is itself such a struct, carrying its own contexts.
//!
//! ```
//! # use stack_encrypt::sem::{EqualityTerm, OreTerm};
//! # use stack_encrypt::target::{DecryptFrom, EncryptInto};
//! # use stack_encrypt::{nonempty, DecryptInto, EncryptFrom, StackCipher, StackCipherText};
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
//! #[stash(struct = User, context = "users")]
//! struct EncryptedUser {
//!     age: EncryptedAge,
//!     email: StackCipherText,
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! # let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! # let keyset = cipher.default_keyset();
//! let user = User { age: 42, email: "alice@example.com".into() };
//! let encrypted: EncryptedUser = user.encrypt_into(&keyset).await?; // one batch
//! let users = vec![User { age: 1, email: "a".into() }, User { age: 2, email: "b".into() }];
//! let column: Vec<EncryptedUser> = users.encrypt_into(&keyset).await?; // still one
//! let user = User::decrypt_from(encrypted, &cipher).await?;
//! assert_eq!(user, User { age: 42, email: "alice@example.com".into() });
//! assert_eq!(column.len(), 2);
//!
//! // A context passed by the caller *extends* every field's: `age` is now
//! // under `("users/age", 7u64)` — bound to its record as well as its name
//! // — and a probe for it is built under the same pair.
//! let user = User { age: 42, email: "alice@example.com".into() };
//! let encrypted: EncryptedUser = user.encrypt_into_with_context(&keyset, 7u64).await?;
//! let probe: EqualityTerm = 42u32
//!     .encrypt_into_with_context(&keyset, nonempty!("users/age").with(7u64))
//!     .await?;
//! assert_eq!(encrypted.age.hm, probe);
//! let user = User::decrypt_from_with_context(encrypted, &cipher, 7u64).await?;
//! assert_eq!(user.age, 42);
//! # Ok::<(), stack_encrypt::Error>(())
//! # }).unwrap();
//! ```
//!
//! A field's context is the stored field's identity — `"users/age"` is what
//! a query site derives a probe under — which is why it is inferred per
//! field rather than taken from the caller. What the caller passes is an
//! *extension*: the derive emits one impl for `()`, deriving each field
//! under its own context as it is, and one for `NonEmpty<T>`, deriving it
//! under `("users/age", context)` — a record id, typically, so a field opens
//! only in the record it was written to. That holds for a `plaintext`
//! record's `context = ".."` literals too: no record accepts a context and
//! then discards it. A field with no context of its own — a `plaintext`
//! record's field with no `context`, or a `#[stash(nested)]` field — is
//! handed the caller's as it is, and its type decides whether that will do:
//! a nested `struct` derive composes it with its own contexts; a leaf
//! accepts only a `NonEmpty<T>`, so the `()` impl fails to compile at the
//! field until it is given a `context`.
//!
//! The prefix is given explicitly (`context = "users"`), never inferred from
//! the Rust type's name: it is part of the stored data's identity — the AAD
//! of every ciphertext derived from the struct and the domain of every term
//! — and a name two types share, or a refactor changes, must not be able to
//! move it silently. The field half is still inferred from the plaintext
//! field's name, so renaming a plaintext field changes that field's context
//! and stored data stops decrypting; pin the old value with `context = ".."`
//! on the field before such a rename. The [attributes](#structs-field-by-field)
//! section says more.
//!
//! `plaintext = T` and `struct = T` are the two shapes a derive can take,
//! and the derive cannot tell them apart from `T` — a proc macro sees the
//! name, not the definition — so the attribute says which: `plaintext`
//! derives every field from the whole value, `struct` reaches into its
//! fields. `from` and `nested` exist only with `struct`.
//!
//! # What the derive commits to
//!
//! The `EncryptFrom` impls are over `KeysetCipher<'k, K>` and the
//! `DecryptInto` impls over `StackCipher<K>` (reaching a `KeysetCipher`
//! through stack-encrypt's blanket impls), for any `K`, each returning its
//! `Pending`. Those are the only ciphers today, and the only ones whose
//! output can be combined without awaiting; a derive generic over any
//! `EncryptTarget` needs combinators on that trait and can replace this one
//! without changing the attribute surface.
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
