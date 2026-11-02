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
//! | Trait | Implemented on | Methods | Source |
//! |---|---|---|---|
//! | [`EncryptTarget<S>`] | an encrypted output or term | `encryption` (borrowed `&S`), `owned_encryption` (`S` by value, defaulting to guard-and-wipe), `indexes` | `S: Zeroize` |
//! | [`DecryptSource<P>`] | a recoverable encrypted output | `decryption(self, ContextInput)` | opens to `P: Zeroize` |
//! | [`EncryptInto`] | every `Zeroize` plaintext | `encrypt_into`, `encrypt_into_with_context` | consumes and wipes |
//! | [`DecryptFrom`] | every `Zeroize` plaintext | `decrypt_from`, `decrypt_from_with_context` | returns the owned value |
//!
//! The core leaves implement both: [`Ciphertext`](crate::Ciphertext) takes
//! an [`OptionalContext`] (empty is a context); [`StackCipherText`](crate::StackCipherText)
//! and [`Encrypted<Terms>`] require an [`AeadContext`] to open and the
//! terms ([`EqualityTerm`](crate::sem::EqualityTerm), [`MatchTerms`](crate::sem::MatchTerms),
//! the order terms) require a [`CallerContext`] to derive, each as a
//! [`RequiredContext`]. A term implements [`EncryptTarget`] alone.
//!
//! # Records
//!
//! `#[derive(EncryptTarget, DecryptSource)]` composes the field declarations.
//! A `struct = User, context = "users"` record hands each field its pair
//! `("users", "<field>")`, extended by the caller's [`ContextExtension`] if
//! one is given, through [`Encryption::under`]: the field target's
//! `ContextInput` must therefore be `From<CallerContext>`, which an
//! [`OptionalContext`], a [`RequiredContext`] of a core context and a
//! nested record's [`ContextExtension`] are, and a [`NoCallerContext`] or a
//! `RequiredContext<u64>` is not — refused at that field. Its borrowed
//! `encryption` picks each field out of a borrow ([`Encryption::project`],
//! cloning a passthrough field); its `owned_encryption` divides the struct
//! between the fields ([`Encryption::split`]), so a `#[stash(passthrough)]`
//! field is moved into the record and each sealed field is guarded by its
//! own target's owned form. Decryption opens each field under the same pair
//! and moves the passthrough fields back.
//!
//! A `plaintext = T` record runs every field over the whole value under the
//! one [`RequiredContext<CallerContext>`] (or `RequiredContext<AeadContext>`
//! with `context_type = AeadContext`) the caller supplies; a
//! `#[stash(context_field)]` record requires the `NonEmpty<T>` it stores and
//! opens under an [`ExpectedContext`]. Both derives also emit the structural
//! declarations ([`EncryptFrom`], [`DecryptInto`], [`DecryptField`]) as a
//! bridge, so an owned record is a field of a structural record or a typed
//! plan field ([`FieldsBuilder::encrypt_into`](crate::plan::FieldsBuilder::encrypt_into),
//! or [`target`](crate::plan::FieldsBuilder::target) for an owned-only target
//! such as a `Ciphertext`). A hand-written owned target used as a record
//! field implements [`Decryptable`] and [`DecryptField`] beside
//! [`DecryptSource`], as a hand-written structural one does.
//!
//! # Structural API during migration
//!
//! Existing structural derives, plans and dynamic targets still use the declarations
//! below. Their borrowed convenience methods are isolated in [`legacy`].
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
//! stores its inner value. Opening takes an [`ExpectedContext`]: by default it checks only that the stored identifier is nonempty and opens under it as stored; a `NonEmpty<T>` also requires it to equal the destination the caller names, and a mismatch is refused before any key is retrieved.
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
//! handed (ADR-0004): the context is a type parameter of [`Encryption`], zipped
//! subtrees must need the same one and receive the same value, and a ciphertext
//! beside a term takes the term's `CallerContext` — of which its own
//! `AeadContext` is the AEAD half — through [`Encryption::accepting`]. A record
//! gives a field a context of its own with [`Encryption::under`] or
//! [`Encryption::extend`], and the caller's context then extends it.
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
//! `cipher.decrypt_as(record, context)`, or import [`legacy::EncryptInto`] and
//! [`legacy::DecryptFrom`] while migrating these declarations. New scalar
//! targets implement [`EncryptTarget`] and [`DecryptSource`].
mod collections;
mod context;
mod conversion;
pub(crate) mod core;
mod index;
mod input;
mod operations;
mod pending;
mod request;
mod source;
pub mod transcode;
mod tuples;

pub(crate) use self::core::{bind_pending, seal_pending};
pub use context::{AeadContext, CallerContext, DeclaredContext, ExpectedContext, Extends};
pub use index::{
    indexed, At, Encrypted, Equality, Index, IndexSpec, Indexes, Json, Match, Ope, Ore, OreBlock,
    Select, TermSet, Whole,
};
#[cfg(feature = "dynamic")]
pub(crate) use operations::chosen;
pub(crate) use operations::inspect;
pub use operations::{
    ciphertext, equality, json_document, json_terms, matching, ope, open, ore, ore_block,
    passthrough, scalar_ciphertext, DecryptField, DecryptInto, Decryptable, Decryption,
    EncryptFrom, Encryption, Layout,
};
pub use pending::{CipherScope, Pending, PendingFuture};
pub use request::{Request, Responses};
pub use source::{Borrowed, ConsumeSource, Owned, ShareSource, SourceMode};
pub use stack_encrypt_derive::{DecryptInto, EncryptFrom};
pub use tuples::JoinContext;

// The old borrowed declarations remain for plans, derives and the dynamic
// engine during the staged migration. New applications use the traits above.
/// Borrowed conversion helpers for declarations not yet migrated to the owned API.
/// Do not import these alongside the new conversion traits.
pub mod legacy {
    pub use super::operations::{
        LegacyDecryptFrom as DecryptFrom, LegacyEncryptInto as EncryptInto,
    };
}
pub use conversion::{DecryptFrom, DecryptSource, EncryptInto, EncryptTarget};
pub use input::{
    AcceptsContext, AllowsNoContext, ContextExtension, ContextInput, NoCallerContext,
    OptionalContext, RequiredContext, ScalarContext,
};
pub use stack_encrypt_derive::{DecryptSource, EncryptTarget};
/// The cleanup bound every owned plaintext carries, named here so the
/// derives can spell it without a `zeroize` dependency of the caller's.
pub use zeroize::Zeroize;
