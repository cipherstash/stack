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
//! The generated code describes the encryption. Stack Encrypt runs it. The
//! generated code is never given a cipher.
//!
//! ```
//! use stack_encrypt::target::{DecryptSource, EncryptTarget};
//! use stack_encrypt::{nonempty, Controlled, DecryptFrom, EncryptInto, Protected, StackCipher, StackCipherText};
//! use stack_encrypt::sem::EqualityTerm;
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
//! // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
//! // the environment, or from the profile that `npx stash auth login` writes.
//! let cipher = StackCipher::builder()
//! #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
//!     .init()
//!     .await?;
//! let keyset = cipher.default_keyset();
//! let value = "alice@example.com".to_owned();
//! // The output type selects a ciphertext and an equality term. The context
//! // is stored in `identifier`.
//! let encrypted: TextEq = value.clone().encrypt_into_with_context(&keyset, nonempty!("users/email")).await?;
//! // Passing the expected context refuses a value stored under any other
//! // context, before any key is requested.
//! let opened = Protected::<String>::decrypt_from_with_context(encrypted, &cipher, nonempty!("users/email")).await?;
//! # assert_eq!(opened.risky_ref(), &value);
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
//! it under `users/<identity>` instead.
//!
//! # Scopes and bindings
//!
//! A `struct` record lists the parts of its context that are not declared,
//! each a scope or a binding. A scope is a part a query supplies too, such
//! as a tenant. A binding ties a ciphertext to one row, such as a row ID. A
//! query does not know it, so a bound row is still found by a query under
//! the scopes.
//!
//! - `scope(tenant: u64)`: the caller passes the scope on every call, as
//!   `Scope::new(tenant)`.
//! - `bind(row: u128)`: the caller passes the binding on every call, as
//!   `Bind::new(row)`, or `Scope::new(tenant).bind(row)` with a scope.
//! - `scope(field = "tenant")` and `bind(field = "id")`: the part is stored
//!   in the row, in the `#[stash(passthrough)]` field derived from that
//!   plaintext field. Encrypt reads it from the plaintext. Decrypt reads it
//!   from the row, and checks it against a part the reader passes.
//!
//! A part the record does not list does not compile. The record's
//! `ContextInput` is `RequiredContext<Parts<..>>` when the caller supplies
//! a part, and the caller's value converts into it.
//!
//! A part stored in the row is a passthrough field, which is not
//! authenticated. It protects the row only when it is the identity the
//! database enforces, such as the primary key: a writer who copies the
//! row's `id` and ciphertext together gets a record that opens and reports
//! that `id`. A reader that has the row's identity passes it as well, as
//! `Scope::new(42u64).bind(9u128)` does below. A mismatch is refused before
//! any key is requested.
//!
//! ```
//! use stack_encrypt::sem::EqualityTerm;
//! use stack_encrypt::target::{Bind, DecryptSource, EncryptTarget, Scope};
//! use stack_encrypt::{DecryptFrom, EncryptInto, Encrypted, StackCipher};
//! use zeroize::Zeroize;
//!
//! #[derive(Zeroize)]
//! struct User { tenant: u64, email: String }
//!
//! #[derive(EncryptTarget, DecryptSource)]
//! #[stash(struct = User, scope = "users", scope(field = "tenant"), bind(row: u128))]
//! struct EncryptedUser {
//!     #[stash(passthrough)]
//!     tenant: u64,
//!     email: Encrypted<EqualityTerm>,
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
//! // the environment, or from the profile that `npx stash auth login` writes.
//! let cipher = StackCipher::builder()
//! #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
//!     .init()
//!     .await?;
//! let keyset = cipher.default_keyset();
//! let user = User { tenant: 42, email: "ada@example.com".into() };
//! // The tenant comes from the plaintext. The row ID comes from the caller.
//! let stored: EncryptedUser = user.encrypt_into_with_context(&keyset, Bind::new(9u128)).await?;
//! assert_eq!(stored.tenant, 42);
//! // The row ID must be passed. The tenant may be passed, to check it.
//! let back = User::decrypt_from_with_context(stored, &keyset, Scope::new(42u64).bind(9u128)).await?;
//! assert_eq!(back.email, "ada@example.com");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # }).unwrap();
//! ```
//!
//! The storage envelope itself adds no
//! cryptographic map-entry context. Vitamin C still binds keys inside plaintext
//! maps and preserves authenticated absence and empty-container markers.
//!
//! # Field references
//!
//! A `struct` record also emits one field reference per derived field, as an
//! associated constant named after the field in upper case:
//! `EncryptedUser::EMAIL` for a field `email` (`EncryptedDoc::TYPE` for
//! `r#type`). A field reference is the value a typed query of the field starts
//! from. It has one method per operator the field's indexes answer,
//! checked at compile time: one index (`Encrypted<EqualityTerm>`), several
//! (`Encrypted<(EqualityTerm, MatchTerms)>`, each operator answered by the
//! one index that answers it), or a nullable field of either
//! (`Option<Encrypted<EqualityTerm>>`).
//!
//! To query a field of a record that is itself a field, call `field` on
//! the outer field's reference:
//! `EncryptedAccount::ADDRESS.field(EncryptedAddress::STREET)`. A nullable
//! record field, `Option<EncryptedAddress>`, has the same method. If the
//! inner record lists a scope, the query needs each record's scope,
//! outermost first.
//!
//! `#[stash(query = String)]` on a field states the type its queries take,
//! so each of its field reference's methods takes that type alone. The derive checks
//! it against the plaintext struct's field, which is that type or an
//! `Option` of it. Without it, an equality field reference takes any type its index
//! accepts, since the derive does not see the plaintext struct's field
//! types otherwise. On a field whose field reference has no operator method, such
//! as a record field or a `StackCipherText`, it does nothing beyond that
//! check. A record that lists a caller scope
//! gives its field references that scope's type, and the query takes it with
//! `.scope(..)`, once; a record with none gives a query that is ready at
//! once. No binding can be given. The query ends with `.encrypt(&keyset)`
//! and derives under the context the derive sealed the field under, so it
//! is the stored term. See `stack_encrypt::FieldReference`. The constant's name is
//! the field's in upper case, so a record cannot define another constant
//! of that name; a tuple field has no name, so no field reference.
//!
//! Ciphertext and term operations compose before awaiting, preserving batched
//! key requests. Terms alone need only their respective PRF or ordering trait.
//! A record of terms alone, such as a query value, derives `EncryptTarget`
//! alone.
//!
//! # What the derives emit
//!
//! `#[derive(EncryptTarget)]` composes the declarations of the record's
//! fields, from the combinators in `stack_encrypt::target`:
//!
//! - A `struct = User, scope = "users"` record runs each field's own target
//!   over the plaintext field it is derived from, under the field's
//!   context: `("users", "<field>")`, or `("users", "<identity>")` where
//!   `identity = ".."` names another segment.
//! - A `plaintext = T` record runs every field's target over the whole
//!   value, under the one context the caller supplies. With a
//!   `#[stash(context_field)]`, the record stores that context. Its
//!   `EncryptTarget::indexes()` is the fields' indexes.
//!
//! `#[derive(DecryptSource)]` opens a `plaintext = T` record through its one
//! decryptable field, or the one `#[stash(decrypt)]` names, under the
//! record's context. It opens each field of a `struct` record through the
//! field type's `DecryptField`, under `<scope>/<identity>`, extended by the
//! record's scopes and bindings. So every field type of a `struct` record
//! that derives `DecryptSource` implements `DecryptField<F, CallerContext>`
//! for the plaintext field `F` it is derived from. Every target in
//! `stack_encrypt` does, and so does every record that derives
//! `DecryptSource`. A field whose type does not is refused at compile time,
//! at the field.
//!
//! The derive sees field types by name, not the indexes they declare. So
//! one mistake is refused when the record runs, before any key is
//! requested, and not at compile time: two indexes that answer one
//! operator. A `plaintext` record with two fields of one index
//! (`EqualityTerm` twice), and a field whose type declares one index twice
//! (`Encrypted<(EqualityTerm, EqualityTerm)>`), fail with
//! `Error::Plan(PlanError::DuplicateIndex { .. })`. An ORE term beside an
//! OPE term fails with `PlanError::IndexOverlap`.
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
//! // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
//! // the environment, or from the profile that `npx stash auth login` writes.
//! let cipher = StackCipher::builder()
//! #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
//!     .init()
//!     .await?;
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
//! set.
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
mod owned_decrypt;
mod owned_encrypt;
mod shape;

/// Derive the owned `EncryptTarget` declaration for a record struct. See
/// the [crate documentation](crate) for what the derive emits. The attributes
/// it accepts are reproduced below.
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
/// implements `DecryptField`, so the record can be a field of another
/// record.
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
