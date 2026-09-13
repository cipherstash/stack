//! Derive operation declarations for encrypted records. `EncryptFrom<P>`
//! declares how to produce a target; `DecryptInto<P>` selects ciphertext for
//! recovery. Stack Encrypt owns execution through Vitamin C's plaintext traits.
//! Generated code receives context and encrypted outputs, never a cipher.
//!
//! ```
//! use stack_encrypt::{EncryptFrom, DecryptInto, StackCipher, StackCipherText, NonEmpty};
//! use stack_encrypt::sem::EqualityTerm;
//! use stack_encrypt::target::ExpectedContext;
//! use stack_kms::FakeDataKeySource;
//!
//! #[derive(EncryptFrom, DecryptInto)]
//! #[stash(plaintext = String)]
//! struct TextEq {
//!     #[stash(context_field)]
//!     identifier: String,
//!     c: StackCipherText,
//!     hm: EqualityTerm,
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! let keyset = cipher.default_keyset();
//! let value = "alice@example.com".to_owned();
//! // The output type selects ciphertext + equality; context is NonEmpty<String>.
//! let encrypted: TextEq = keyset.encrypt_as(&value, NonEmpty::new("users/email".to_owned())?).await?;
//! // Reads the identifier from the record, validates it, and opens through Vitamin C.
//! let opened: String = cipher.decrypt_as(encrypted, ExpectedContext::default()).await?;
//! assert_eq!(opened, value);
//! # Ok::<(), Box<dyn std::error::Error>> (())
//! # }).unwrap();
//! ```
//!
//! For a record without a context field, fields use the caller's context or a
//! declared literal. `struct = User, context = "users"` selects plaintext fields
//! and binds them under `"users/<field>"`. The storage envelope itself adds no
//! cryptographic map-entry context. Vitamin C still binds keys inside plaintext
//! maps and preserves authenticated absence and empty-container markers.
//!
//! Ciphertext and term operations compose before awaiting, preserving batched
//! key requests. Terms alone need only their respective PRF or ordering trait.
//! A custom storage field can declare a core operation followed by `.transcode()`;
//! its visitor receives native encrypted output, without an intermediate format.
//! Query-only targets derive `EncryptFrom` alone.
//!
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

/// Derive `DecryptInto<Plaintext>` for a record struct, one impl per
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
