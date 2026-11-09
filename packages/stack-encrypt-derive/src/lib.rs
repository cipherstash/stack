//! Derive the declarations of encrypted records.
//!
//! Derive `EncryptTarget<P>` and `DecryptSource<P>` on the struct that holds
//! the encrypted form of a plaintext `P`. Then:
//!
//! - `value.encrypt_into(&keyset)` takes the plaintext by value, encrypts
//!   it, and wipes it;
//! - `Protected::<P>::decrypt_from(record, &cipher)` decrypts the record into
//!   a `Protected`, which wipes the plaintext when it is dropped.
//!
//! `EncryptFrom<P>` and `DecryptInto<P>` are an older pair of derives over a
//! borrowed plaintext. They take the same attributes. Plans and the dynamic
//! engine still use them, and the API plan removes them once those have
//! moved to the new pair. See [Owned records](#owned-records).
//!
//! The generated code describes the encryption. Stack Encrypt runs it. The
//! generated code is never given a cipher.
//!
//! ```
//! use stack_encrypt::target::{DecryptSource, EncryptTarget};
//! use stack_encrypt::{nonempty, Controlled, DecryptFrom, EncryptInto, Protected, StackCipher, StackCipherText};
//! use stack_encrypt::sem::EqualityTerm;
//! use stack_encrypt::kms::FakeDataKeySource;
//!
//! #[derive(EncryptTarget, DecryptSource)]
//! #[stash(plaintext = String)]
//! struct TextEq {
//!     #[stash(context_field)]
//!     identifier: &'static str,
//!     c: StackCipherText,
//!     hm: EqualityTerm,
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! let keyset = cipher.default_keyset();
//! let value = "alice@example.com".to_owned();
//! // The output type selects a ciphertext and an equality term. The context
//! // is stored in `identifier`.
//! let encrypted: TextEq = value.clone().encrypt_into_with_context(&keyset, nonempty!("users/email")).await?;
//! // Passing the expected context refuses a value stored under any other
//! // context, before any key is requested.
//! let opened = Protected::<String>::decrypt_from_with_context(encrypted, &cipher, nonempty!("users/email")).await?;
//! assert_eq!(opened.risky_ref(), &value);
//! # Ok::<(), Box<dyn std::error::Error>> (())
//! # }).unwrap();
//! ```
//!
//! For a `plaintext` record without a context field, every field uses the
//! caller's context: a field takes no literal context of its own. A record
//! made only of ciphertexts can declare `context_type = AeadContext` and
//! accept a context type that implements `IntoAad` alone, as the ciphertext
//! leaf itself does.
//! `struct = User, scope = "users"` selects plaintext fields
//! and binds each under the pair `("users", "<field>")`, which renders
//! `users/<field>` as its ZeroKMS descriptor; `identity = ".."` on a field keys
//! it under `users/<identity>` instead. The storage envelope itself adds no
//! cryptographic map-entry context. Vitamin C still binds keys inside plaintext
//! maps and preserves authenticated absence and empty-container markers.
//!
//! Ciphertext and term operations compose before awaiting, preserving batched
//! key requests. Terms alone need only their respective PRF or ordering trait.
//! Query-only targets derive `EncryptFrom` alone.
//!
//! # The record's plan
//!
//! `#[derive(EncryptFrom)]` emits the record's plan, `Record::plan()`, and
//! its `EncryptFrom::encryption()` runs that plan and maps the outputs into
//! the struct. On the encrypt side the derive names plan verbs and nothing
//! beneath them, so a derived record and the same plan written by hand
//! cannot drift apart (see `stack_encrypt::plan`, "The derive emits a plan",
//! for a worked example):
//!
//! - a `struct = User, scope = "users"` record emits
//!   `Plan::context("users").fields()` with
//!   `.encrypt_into::<FieldType, _>(pick("field", |u: &User| &u.field))` per
//!   derived field, and `.identity("..")` where one is pinned;
//! - a `plaintext = T` record emits
//!   `Plan::value::<T>().encrypt_into::<(A, B, ..)>()` over the derived
//!   fields' types, with no context of its own (every output shares the
//!   caller's), plus `.context_field::<C>()` when a field stores the context.
//!   Its `EncryptFrom::indexes()` is the outputs' indexes, so a derived
//!   record used as a plan field answers the queries its terms support.
//!
//! A plan seals and opens each field, so every field type of a `struct`
//! record implements `DecryptField<F, CallerContext>` for the plaintext
//! field `F` it is derived from, even when the record derives `EncryptFrom`
//! alone: every target in `stack_encrypt` and every record deriving
//! `DecryptInto` does. That is refused at compile time, at the field: a
//! plaintext field that is borrowed (`&'static str`) cannot be opened into,
//! so derive from an owned field (`String`), or encrypt the borrowed value
//! through a `plaintext` record.
//!
//! Every other input whose plan would not build is refused at compile time
//! too, except one the derive cannot see: an index declared twice. The
//! derive sees field types by name, not the indexes they declare, so a
//! `plaintext` record with two outputs of one index (`EqualityTerm` twice)
//! and a `struct` record whose field type declares one index twice
//! (`Encrypted<(EqualityTerm, EqualityTerm)>`) compile, and `Record::plan()`
//! returns `Error::Plan(PlanError::DuplicateIndex { .. })`; encrypting
//! through the record fails with that error, before any key is requested.
//!
//! On the decrypt side, `DecryptInto` opens a `plaintext = T` record through
//! its one decryptable output (or the one `#[stash(decrypt)]` names) under
//! the record's context, and a `struct` record opens each field through its
//! own `DecryptField` under `<scope>/<identity>`, extended by the caller's
//! context. Neither goes through the plan: each is written out by the
//! derive, and the crate's tests open what one writes through the other.
//!
//! # A field in your own storage format
//!
//! A record's fields need not be the core types. A field type that stores
//! encrypted output in its own shape declares the core operation that produces
//! it and finishes the declaration with `.transcode()`: the cipher runs the
//! operation and then hands its native output, leaf by leaf, to a
//! `Visitor` (in `stack_encrypt::target::transcode`) the field type
//! names. The visitor implements only the shapes the field stores; the trait's
//! defaults refuse every other shape with `Error::UnsupportedShape`. Nothing
//! is serialised, re-encrypted, or gathered into an intermediate tree on the
//! way, so the bytes the visitor stores are the bytes the canonical path opens.
//!
//! ```
//! use stack_encrypt::sem::EqualityTerm;
//! use stack_encrypt::target::transcode::{Transcode, Visitor};
//! use stack_encrypt::target::{self, CallerContext, EncryptTarget, RequiredContext};
//! use stack_encrypt::{
//!     CipherText, Decryptable, EncryptInto, Encryption, Error, Encrypt, SealedValue,
//!     StackCipher, nonempty,
//! };
//! use zeroize::Zeroize;
//! use stack_encrypt::kms::FakeDataKeySource;
//!
//! /// A column that stores one sealed leaf as bytes.
//! struct LeafBytes(Vec<u8>);
//!
//! struct LeafBytesVisitor;
//! impl Visitor for LeafBytesVisitor {
//!     type Value = LeafBytes;
//!     // The one shape this column stores. A sequence or a map would reach a
//!     // default method and be refused, never flattened.
//!     fn sealed(self, leaf: SealedValue) -> Result<LeafBytes, Error> {
//!         Ok(LeafBytes(leaf.to_bytes()))
//!     }
//! }
//! impl Transcode for LeafBytes {
//!     type Visitor = LeafBytesVisitor;
//!     fn visitor() -> LeafBytesVisitor {
//!         LeafBytesVisitor
//!     }
//! }
//! // Whether the field holds recoverable ciphertext. The derive asks every
//! // field, so that a record can itself be a field of another record.
//! impl Decryptable for LeafBytes {
//!     const DECRYPTABLE: bool = true;
//! }
//! // The declaration: the canonical ciphertext operation, read into this type.
//! // It seals under the AEAD half of the context the record threads to it.
//! impl<S: Encrypt + Clone + Zeroize> EncryptTarget<S> for LeafBytes {
//!     type ContextInput = RequiredContext<CallerContext>;
//!     fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput>
//!     where
//!         S: 's,
//!     {
//!         target::ciphertext().accepting().transcode()
//!     }
//! }
//!
//! // The record uses it like any core field type.
//! #[derive(EncryptTarget)]
//! #[stash(plaintext = String)]
//! struct TextEq {
//!     #[stash(context_field)]
//!     identifier: &'static str,
//!     c: LeafBytes,
//!     hm: EqualityTerm,
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! let keyset = cipher.default_keyset();
//! let value = "alice@example.com".to_owned();
//! let context = nonempty!("users/email");
//! let encrypted: TextEq = value.clone().encrypt_into_with_context(&keyset, context.clone()).await?;
//!
//! // What the column holds is the leaf itself: the canonical path opens it.
//! let leaf = SealedValue::from_bytes(&encrypted.c.0)?;
//! let opened: String = cipher.decrypt(CipherText::Single(leaf), context).await?;
//! assert_eq!(opened, value);
//! # Ok::<(), Box<dyn std::error::Error>> (())
//! # }).unwrap();
//! ```
//!
//! To decrypt the plaintext through the record, the field type also
//! implements `DecryptSource` and `DecryptField`, and the record derives
//! `DecryptSource`. The crate's `transcode` integration test shows the full
//! set. A field of a `struct = ..` record needs `DecryptField` even
//! when the record derives `EncryptFrom` alone, because the record's plan
//! opens each field (see "The record's plan").
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
mod owned_decrypt;
mod owned_encrypt;
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

/// Derive the owned `EncryptTarget` declaration for a record struct. The
/// derive also implements the structural `EncryptFrom`, so the record works
/// where a structural record is expected.
///
/// The derive takes the same attributes as `EncryptFrom`. It also takes
/// `#[stash(passthrough)]` on a field of a `struct = ..` record. A
/// passthrough field is not encrypted and not authenticated. See
/// [Owned records](crate#owned-records).
#[doc = include_str!("../docs/attributes.md")]
#[proc_macro_derive(EncryptTarget, attributes(stash))]
pub fn derive_encrypt_target(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    owned_encrypt::derive(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Derive the owned `DecryptSource<Plaintext>` declaration for a record
/// struct, with one impl for each `plaintext` type. The derive also
/// implements the structural `DecryptInto` and `DecryptField`, so the record
/// works where a structural record is expected.
///
/// The derive also implements `DecryptSource<Protected<Plaintext>>` for each
/// listed plaintext, so `Protected::<User>::decrypt_from(record, &cipher)`
/// returns a value that is wiped when it is dropped. A bare `User` is not.
/// See [Owned records](crate#owned-records).
#[doc = include_str!("../docs/attributes.md")]
#[proc_macro_derive(DecryptSource, attributes(stash))]
pub fn derive_decrypt_source(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    owned_decrypt::derive(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
