//! Targets declare operations; the cipher executes them through Vitamin C.
//!
//! The owned API uses [`EncryptTarget`] and [`DecryptSource`] declarations,
//! executed by [`EncryptInto`] and [`DecryptFrom`]. Their `ContextInput`
//! capabilities explicitly allow omission or supply; `Default` does not
//! determine either. [`scalar_ciphertext`] is the first owned operation.
//!
//! A `Vec<S>` of owned plaintexts encrypts into a `Vec<T>` of any owned
//! target, and decrypts back the same way. The collection uses the element
//! target's `ContextInput`. The collection makes one logical batch of key
//! requests. Each element is authenticated on its own.
//!
//! # The owned declarations
//!
//! | Trait | Implemented on | Methods | Plaintext |
//! |---|---|---|---|
//! | [`EncryptTarget<S>`] | An encrypted output or a term | `encryption` (over `&S`), `owned_encryption` (over `S` by value, which by default guards the value and wipes it), and `indexes` | `S: Zeroize` |
//! | [`DecryptSource<P>`] | An encrypted output that can be decrypted | `decryption(self, ContextInput)` | Decrypts to `P: Zeroize` |
//! | [`EncryptInto`] | Every `Zeroize` plaintext | `encrypt_into` and `encrypt_into_with_context` | Consumed and wiped |
//! | [`DecryptFrom`] | Every `Zeroize` plaintext | `decrypt_from` and `decrypt_from_with_context` | Returned to the caller, who must wipe it |
//!
//! The core leaves implement both owned traits, with these context inputs:
//!
//! - [`Ciphertext`](crate::Ciphertext) takes an [`OptionalContext`]. The
//!   empty context is a valid context.
//! - [`StackCipherText`](crate::StackCipherText) and [`Encrypted<Terms>`]
//!   require an [`AeadContext`] to decrypt.
//! - The terms require a [`CallerContext`] to derive. The terms are
//!   [`EqualityTerm`](crate::sem::EqualityTerm),
//!   [`MatchTerms`](crate::sem::MatchTerms), and the order terms.
//!
//! Each required context is a [`RequiredContext`]. A term implements
//! [`EncryptTarget`] alone, because a term cannot be decrypted.
//!
//! # Records
//!
//! `#[derive(EncryptTarget, DecryptSource)]` composes the declarations of
//! the fields.
//!
//! A `struct = User, scope = "users"` record gives each field its context,
//! `("users", "<field>")`, through [`Encryption::under`]. The record's name
//! is the first scope, and the field's name is the next. The record's input
//! is [`DeclaredScopes`]: the caller passes no context. When the record is
//! a field of another record, that field's context extends each of its own.
//! So the field target's `ContextInput` must implement `From<CallerContext>`:
//!
//! - These inputs implement it: [`OptionalContext`], a [`RequiredContext`]
//!   of a core context, and the [`DeclaredScopes`] of a nested record.
//! - These inputs do not: [`NoCallerContext`] and `RequiredContext<u64>`. A
//!   field whose target takes one of them is a compile error at that field.
//!
//! The borrowed `encryption` of a `struct` record takes each field out of a
//! borrow ([`Encryption::project`]), and clones each passthrough field. Its
//! `owned_encryption` divides the struct between the fields
//! ([`Encryption::split`]). So each `#[stash(passthrough)]` field is moved
//! into the record. Each sealed field is guarded by the owned form of its
//! own target.
//!
//! Decryption opens each field under the same context, and moves the
//! passthrough fields back. A passthrough field is not encrypted and not
//! authenticated.
//!
//! A `plaintext = T` record runs every field over the whole value, under
//! the one context the caller supplies. That context is a
//! [`RequiredContext<CallerContext>`], or a `RequiredContext<AeadContext>`
//! with `context_type = AeadContext`. A `#[stash(context_field)]` record
//! requires the `NonEmpty<T>` it stores. On decrypt the caller may pass that
//! `NonEmpty<T>` again, and the stored value must then equal it.
//!
//! Both derives also implement the structural traits ([`EncryptFrom`],
//! [`DecryptInto`] and [`DecryptField`]). So an owned record can be a field
//! of a structural record, or a typed field of a plan. A plan field uses
//! [`FieldsBuilder::encrypt_into`](crate::plan::FieldsBuilder::encrypt_into),
//! or [`target`](crate::plan::FieldsBuilder::target) for a target that is
//! only owned, such as a `Ciphertext`. A hand-written owned target that will
//! be a record field must implement [`Decryptable`] and [`DecryptField`], as
//! well as [`DecryptSource`]. A hand-written structural target does the
//! same.
//!
//! # Structural API during migration
//!
//! The structural derives, plans, and dynamic targets still use the
//! declarations below.
//!
//! [`EncryptFrom<S>`] describes ciphertext and/or term operations and has an
//! associated context type. It does not receive plaintext or a cipher. The
//! cipher's `encrypt_as` executes that description, returning the existing
//! batched [`Pending`]. [`DecryptInto<P>`] inspects stored output and describes
//! opening it through `P::Decrypt`.
//!
//! # Records and context
//!
//! The derives compose each semantic field's declaration. `#[stash(context_field)]`
//! on an identifier of type `T` makes the encryption context `NonEmpty<T>` and
//! stores its inner value. Opening takes the context the caller expects, or none: by default it checks only that the stored identifier is nonempty and opens under it as stored; a `NonEmpty<T>` also requires it to equal the destination the caller names, and a mismatch is refused before any key is retrieved.
//! Record envelope names do not add cryptographic map keys.
//!
//! Generic targets use [`CallerContext`] (ciphertext and terms) or [`AeadContext`]
//! (ciphertext only; a derived record made only of ciphertexts declares it with
//! `#[stash(context_type = AeadContext)]`). These own Vitamin C's context
//! encodings, preserving their structured descriptor identity. They are
//! constructed from a nonempty context, including a borrowed one — an
//! `AeadContext` from one with the AEAD encoding alone. Records that supply
//! their own field contexts use [`DeclaredContext`], whose default leaves those
//! contexts unchanged and whose nonempty form extends them. Custom targets may
//! instead declare `Context = ()`.
//!
//! Within one target, every operation runs under the one context the target is
//! handed: the context is a type parameter of [`Encryption`], zipped
//! subtrees must need the same one and receive the same value, and a ciphertext
//! beside a term takes the term's `CallerContext` — of which its own
//! `AeadContext` is the AEAD half — through [`Encryption::accepting`]. A record
//! gives a field a context of its own with [`Encryption::under`] or
//! [`Encryption::extend`], and the caller's context then extends it.
//! [`Encryption::contexts`] shows the result, before any key is requested.
//!
//! # Output adapters
//!
//! An adapter selects a core operation and converts only its completed output.
//! A [`transcode::Reader`] moves native ciphertext, terms, metadata, and sealed
//! structural markers into a target visitor. It creates no additional generic
//! tree or serialization buffer. The cipher's native tree, pending requests, and
//! the final target's own storage remain normal allocations.
//!
//! ```
//! use stack_encrypt::{EncryptFrom, Encryption};
//! use stack_encrypt::target::{self, CallerContext};
//! use stack_encrypt::sem::EqualityTerm;
//!
//! struct StoredEquality([u8; 32]);
//! impl<S> EncryptFrom<S> for StoredEquality
//! where EqualityTerm: EncryptFrom<S, Context = CallerContext> {
//!     type Context = CallerContext;
//!     fn encryption<'s,K:'static>()->Encryption<'s,S,Self,K,Self::Context>
//!     where S:'s {
//!         <EqualityTerm as EncryptFrom<S>>::encryption().map(|term| Self(term.into_bytes()))
//!     }
//! }
//! ```
//!
//! Ciphertext operations require Vitamin C's `Encrypt`/`Decrypt` on the plaintext;
//! there is no Serde fallback. Terms require only their PRF or ordering capability.
//! New cryptographic operations belong in core; output adapters cannot install an
//! execution callback. The separate cipher-directed API remains public.
//!
//! Those schemes consume the plaintext. A description is handed it by
//! reference by default, and an operation clones it before consuming it, so a
//! declaration's plaintext is `Clone`. A plaintext that must not be copied
//! runs in [`Owned`] mode through [`KeysetCipher::run`](crate::KeysetCipher::run):
//! a single operation takes the value with no copy, and only
//! [`Encryption::zip`] asks for `Clone`. See [`SourceMode`].
//!
//! # Collections and authentication
//!
//! `Vec<Target>` describes rows that are each encrypted on their own, under
//! the same context. That rule applies on the owned path, where a `Vec<S>` encrypts
//! into a `Vec` of [`EncryptTarget`]s, and on the structural path. Encrypting a plaintext `Vec<T>` into `StackCipherText` instead
//! follows Vitamin C's native sequence model, including its authenticated empty
//! marker. The same distinction applies to `Option<Target>` versus a native
//! encrypted option.
//! Readers preserve marker ciphertext and map keys; changing a key changes the
//! authenticated context when opening. Passthrough metadata and query terms are
//! not presented as AEAD-authenticated values.
//!
//! # Migration from the unpublished execution traits
//!
//! Implement `encryption`/`decryption`, returning core-owned descriptions, in place
//! of `encrypt_from`/`decrypt_into` methods that took a cipher. The derives do this
//! automatically. Call `keyset.encrypt_as(&value, context)` and
//! `cipher.decrypt_as(record, context)`. New scalar targets implement
//! [`EncryptTarget`] and [`DecryptSource`].
mod collections;
mod context;
mod conversion;
pub(crate) mod core;
pub(crate) mod index;
mod input;
mod operations;
mod pending;
mod request;
mod source;
pub mod transcode;
mod tuples;

pub(crate) use self::core::{bind_pending, seal_pending};
/// The check that a `#[stash(context_field)]` record runs on decrypt.
///
/// `ExpectedContext` is not part of the API. Only the derives and the EQL
/// types name it, and a caller passes a `NonEmpty<T>` or nothing. The type
/// is public only because the derives emit code in other crates that
/// names it. The definition is hidden too.
#[doc(hidden)]
pub use context::ExpectedContext;
pub use context::{
    AeadContext, Bind, BindPart, CallerContext, CheckedInput, DeclaredContext, Extends, NoBind,
    NoScope, Parts, Scope, ScopePart, Scopes, StoredParts,
};
pub use conversion::{DecryptFrom, DecryptSource, EncryptInto, EncryptTarget};
pub use index::{
    indexed, At, Encrypted, Equality, Index, IndexSpec, Indexes, Json, Match, Ope, Ore, OreBlock,
    Select, TermSet, Whole,
};
pub use input::{
    AcceptsContext, AllowsNoContext, ContextInput, DeclaredScopes, NoCallerContext,
    OptionalContext, RequiredContext, ScalarContext,
};
#[cfg(feature = "dynamic")]
pub(crate) use operations::chosen;
pub(crate) use operations::inspect;
pub use operations::{
    ciphertext, equality, json_document, json_terms, matching, ope, open, ore, ore_block,
    passthrough, scalar_ciphertext, DecryptField, DecryptInto, Decryptable, Decryption,
    EncryptFrom, Encryption, Layout,
};
pub use pending::{CipherRef, Pending, PendingFuture};
pub use request::{Request, Responses};
pub use source::{Borrowed, ConsumeSource, Owned, ShareSource, SourceMode};
pub use stack_encrypt_derive::{DecryptInto, EncryptFrom};
pub use stack_encrypt_derive::{DecryptSource, EncryptTarget};
pub use tuples::JoinContext;
/// The cleanup trait that every owned plaintext must implement. It is
/// re-exported here so that the derives can name it, even when the caller's
/// crate does not depend on `zeroize`.
pub use zeroize::Zeroize;
