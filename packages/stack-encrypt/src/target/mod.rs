//! Targets declare operations; the cipher executes them through Vitamin C.
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
//! `Vec<Target>` describes independently encrypted rows under the same context.
//! Encrypting a plaintext `Vec<T>` into `StackCipherText` instead follows Vitamin
//! C's native sequence model, including its authenticated empty marker. The same
//! distinction applies to `Option<Target>` versus a native encrypted option.
//! Readers preserve marker ciphertext and map keys; changing a key changes the
//! authenticated context when opening. Passthrough metadata and query terms are
//! not presented as AEAD-authenticated values.
//!
//! # Migration from the unpublished execution traits
//!
//! Implement `encryption`/`decryption`, returning core-owned descriptions, in place
//! of `encrypt_from`/`decrypt_into` methods that took a cipher. The derives do this
//! automatically. Call `keyset.encrypt_as(&value, context)` and
//! `cipher.decrypt_as(record, context)`, or import the blanket [`EncryptInto`] and
//! [`DecryptFrom`] convenience traits for the existing source-side call syntax.
//! `EncryptTarget` and `DecryptTarget` are no longer extension points.
mod context;
pub(crate) mod core;
mod index;
mod operations;
mod pending;
mod request;
mod source;
pub mod transcode;
mod tuples;

pub(crate) use self::core::{decipher_pending, seal_pending};
pub use context::{AeadContext, CallerContext, DeclaredContext, ExpectedContext, Extends};
pub use index::{
    indexed, At, Encrypted, Equality, Index, IndexSpec, Indexes, Match, Ope, Ore, Select, TermSet,
    Whole,
};
pub(crate) use operations::inspect;
pub use operations::{
    ciphertext, equality, matching, ope, open, ore, passthrough, DecryptField, DecryptFrom,
    DecryptInto, Decryptable, Decryption, EncryptFrom, EncryptInto, Encryption,
};
pub use pending::{CipherScope, Pending, PendingFuture};
pub use request::{Request, Responses};
pub use source::{Borrowed, ConsumeSource, Owned, ShareSource, SourceMode};
pub use stack_encrypt_derive::{DecryptInto, EncryptFrom};
pub use tuples::JoinContext;
