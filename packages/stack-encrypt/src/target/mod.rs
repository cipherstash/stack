//! Target-directed encryption: the *output* type decides what gets derived,
//! and the *cipher* decides the async shape.
//!
//! A stored encrypted value is rarely just a ciphertext — it is a record: the
//! AEAD ciphertext of the plaintext plus zero or more index terms derived from
//! the same plaintext by different primitives. [`EncryptFrom`] puts that
//! record shape in charge:
//!
//! ```text
//! let term: EqualityTerm = value.encrypt_into_with_context(&keyset, nonempty!("users/email")).await?;
//! let row: EncryptedUser = user.encrypt_into(&keyset).await?;
//! let row: EncryptedUser = user.encrypt_into_with_context(&keyset, user_id).await?;
//! ```
//!
//! compiles only when the output type declares itself an encrypted form of
//! the value's type, producible by that cipher (a [`KeysetCipher`]: every
//! data key is minted, and every term derived, under one keyset), under that
//! context — and a
//! context is something the output type may already have. A leaf has
//! nothing of its own to authenticate under and takes the caller's, proven
//! non-empty before it arrives ([`NonEmpty`]). A struct encrypted field by
//! field names each field's context itself and needs none, so the second
//! line is the whole call; the third *extends* every field's context with a
//! value only the caller knows — the record's id — so each field is bound
//! to its record as well as its name. See [Which form
//! compiles](self#which-form-compiles).
//!
//! # The pieces
//!
//! * [`EncryptFrom<S, C, Ctx>`] — implemented by an *output* type: "`Self` is
//!   an encrypted representation of `S`, producible by a cipher `C`, under a
//!   context `Ctx`". The context is a parameter of the *trait* so that an
//!   implementation can say which contexts it accepts: the leaves accept
//!   only a [`NonEmpty<T>`], and a derived record accepts `()` — its
//!   fields' own contexts — and any `NonEmpty<T>`, which extends them. Leaf
//!   implementations exist for [`StackCipherText`] (the AEAD ciphertext, via
//!   vitaminc's [`Encrypt`]) and for the SEM term types in [`sem`]
//!   ([`EqualityTerm`], [`MatchTerm`], [`OreTerm`], [`OpeTerm`]). Composite
//!   record types — a struct of leaves, or a struct of records — get theirs from
//!   [`#[derive(EncryptFrom)]`](macro@EncryptFrom), which combines the
//!   fields' pendings with [`Pending::zip`] / [`Pending::map`] exactly as a
//!   hand-written impl would.
//! * [`DecryptInto<P, C, Ctx>`] — the mirror, implemented by the *encrypted*
//!   type: "`Self` decrypts to the plaintext `P`". Only ciphertext fields
//!   participate — index terms are one-way by construction.
//!   [`#[derive(DecryptInto)]`](macro@DecryptInto) on the record emits it.
//!   `Self` is the record in both traits — the output of encryption, the
//!   input of decryption — because that is the type a downstream crate can
//!   implement on; the halves whose `Self` is the plaintext are blanket:
//! * [`EncryptInto`] / [`DecryptFrom`] — call-site sugar, the `Into` to
//!   `EncryptFrom` and the `From` to `DecryptInto`, each in two forms:
//!   [`encrypt_into(&cipher)`](EncryptInto::encrypt_into) passes `()`, for
//!   an output that needs nothing from the caller, and
//!   [`encrypt_into_with_context(&cipher, ctx)`](EncryptInto::encrypt_into_with_context)
//!   passes a `NonEmpty<T>` — the split of vitaminc's `encrypt` /
//!   `encrypt_with_aad`. Never implemented by hand.
//! * [`EncryptTarget`] / [`DecryptTarget`] — implemented by ciphers; their
//!   `Output` type decides what a call site gets back. A synchronous cipher
//!   returns `Result<T, E>` directly; [`KeysetCipher`] (the encrypt target)
//!   and [`StackCipher`] (the decrypt target — a sealed leaf names its own
//!   keyset, so opening is not keyset-scoped; a `KeysetCipher` decrypts too,
//!   refusing leaves from any other keyset) return a [`Pending`], which does
//!   its ZeroKMS I/O — **one batched call** — when awaited.
//!
//! # Contexts
//!
//! A context is one value that domain-separates every primitive a field can
//! use: it becomes the AEAD associated data of the ciphertext *and* the PRF
//! context of any index term, so the identifier that keeps `users/email`
//! terms apart from `users/name` terms also authenticates the ciphertext to
//! its column. The vocabulary is vitaminc's — [`IntoAad`],
//! [`IntoPrfContext`](crate::IntoPrfContext) and, for the proof that a value
//! carries caller bytes, [`NonEmpty<T>`] —
//! and this crate adds no trait of its own on top: anything vitaminc encodes
//! as a context is a context here. `&str`, `String`, byte strings, the
//! fixed-width integers, and `Option`s and pairs of those all qualify.
//!
//! The same context reaches ZeroKMS. Every data key a leaf asks for —
//! generated on encrypt, retrieved on decrypt — is requested under the
//! context rendered as the key's **descriptor** ([`Descriptor`]), which
//! ZeroKMS HMACs into the key tag and logs per retrieval. So `users/email`
//! is enforced twice: locally, where the ciphertext fails to open under
//! any other AAD, and at ZeroKMS, where the key fails to re-derive under
//! any other descriptor — and it is the name an audit trail shows. A
//! textual context is its own descriptor, and a composite renders its
//! parts in order: `nonempty!("users/email").with(7u64)` is the descriptor
//! `users/email|7u64`. See [`Descriptor::from_piece`] for the frozen rules,
//! and the [descriptor docs](crate::descriptor) for why a context must be
//! presented in the same shape on both sides.
//!
//! A leaf takes a `NonEmpty<T>` and nothing else. Under an empty context,
//! equal plaintexts in different fields derive identical index terms
//! (cross-field equality leakage), every field shares one ORE/OPE key
//! (values become mutually order-comparable), and ciphertexts transplant
//! between fields. `()` — what `encrypt_into` passes — is the canonical
//! empty context, and vitaminc implements the context traits for it, so a
//! leaf bound on those alone would let `value.encrypt_into(&cipher)` into a
//! term compile and quietly derive under nothing. Bound on `NonEmpty<T>`,
//! that call is a compile error, and `""`, `None`, `Some("")` never reach a
//! leaf either: [`NonEmpty::new`] refuses them once, where the value is
//! built, and [`nonempty!`](crate::nonempty) refuses an empty literal at compile time. An
//! integer is never empty and converts on its own (`42u64.into()`, or just
//! `42u64` to the sugar). A pair is empty only when both halves are, so a
//! proven head extends freely: `nonempty!("users/email").with(record_id)`.
//!
//! One collision to know about, inherited from vitaminc's integer encoding:
//! an integer's AAD is its untagged little-endian bytes, so `0u64`
//! authenticates the same eight zero bytes as `None::<u64>` (the PAE of an
//! empty list). Index terms do not collide — the PRF encoding is typed —
//! but a ciphertext sealed under `("users/age", 0u64)` opens under
//! `("users/age", None::<u64>)`. Do not mix an integer id and an optional
//! one under the same prefix; cipherstash/vitaminc#315 tracks typing the
//! AAD channel too.
//!
//! # Which form compiles
//!
//! Three record shapes, and the call forms each accepts. Which contexts a
//! type accepts is which [`EncryptFrom`] impls it has; the derive decides
//! what impls exist, and the compiler enforces it at every call site.
//!
//! A record whose field pins a literal context needs nothing from the
//! caller, and a context passed anyway *extends* the literal — it is never
//! silently dropped:
//!
//! ```
//! use stack_encrypt::target::EncryptInto;
//! use stack_encrypt::{DecryptInto, EncryptFrom, Error, NonEmpty, StackCipher, StackCipherText};
//! use stack_kms::FakeDataKeySource;
//!
//! #[derive(EncryptFrom, DecryptInto)]
//! #[stash(plaintext = u32)]
//! struct Pinned {
//!     #[stash(context = "legacy/age")]
//!     c: StackCipherText,
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! # let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! # let keyset = cipher.default_keyset();
//! // Sealed under "legacy/age".
//! let p: Pinned = 42u32.encrypt_into(&keyset).await?;
//! assert_eq!(p.decrypt_into(&cipher, ()).await?, 42);
//!
//! // Sealed under ("legacy/age", tenant): opens there, and nowhere else.
//! let tenant = 7u64;
//! let p: Pinned = 42u32.encrypt_into_with_context(&keyset, tenant).await?;
//! let p2: Pinned = 42u32.encrypt_into_with_context(&keyset, tenant).await?;
//! assert_eq!(p.decrypt_into(&cipher, NonEmpty::from(tenant)).await?, 42);
//! // The fake key source ignores descriptors, so the AEAD is what refuses
//! // here; ZeroKMS refuses the key retrieval itself first (`Error::Kms`).
//! assert!(matches!(p2.decrypt_into(&cipher, NonEmpty::from(8u64)).await, Err(Error::Aead)));
//! # Ok::<(), stack_encrypt::Error>(())
//! # }).unwrap();
//! ```
//!
//! A record whose fields have no context of their own has only the
//! caller's, so it must be given: the context-free form does not compile.
//!
//! ```
//! use stack_encrypt::sem::EqualityTerm;
//! use stack_encrypt::target::EncryptInto;
//! use stack_encrypt::{nonempty, DecryptInto, EncryptFrom, StackCipher, StackCipherText};
//! use stack_kms::FakeDataKeySource;
//!
//! #[derive(EncryptFrom, DecryptInto)]
//! #[stash(plaintext = u32)]
//! struct Foo {
//!     c: StackCipherText,
//!     hm: EqualityTerm,
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! # let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! # let keyset = cipher.default_keyset();
//! let f: Foo = 42u32.encrypt_into_with_context(&keyset, nonempty!("users/age")).await?;
//! assert_eq!(f.decrypt_into(&cipher, nonempty!("users/age")).await?, 42);
//! # Ok::<(), stack_encrypt::Error>(())
//! # }).unwrap();
//! ```
//!
//! ```compile_fail,E0277
//! # use stack_encrypt::sem::EqualityTerm;
//! # use stack_encrypt::target::EncryptInto;
//! # use stack_encrypt::{DecryptInto, EncryptFrom, KeysetCipher, StackCipherText};
//! # use stack_kms::FakeDataKeySource;
//! # #[derive(EncryptFrom, DecryptInto)]
//! # #[stash(plaintext = u32)]
//! # struct Foo { c: StackCipherText, hm: EqualityTerm }
//! async fn encrypt(keyset: &KeysetCipher<'_, FakeDataKeySource>) {
//!     // "`StackCipherText` is not an encrypted form of `u32` under a `()`
//!     // context": the leaf that needs a context is named.
//!     let _: Foo = 42u32.encrypt_into(keyset).await.unwrap();
//! }
//! ```
//!
//! A struct encrypted field by field infers a context for every field, so
//! it takes either form: `encrypt_into` seals each field under its own
//! context, `encrypt_into_with_context` under that context extended with
//! the caller's. See [the next section](self#records-and-structs-deriveencryptfrom)
//! for the worked example.
//! # Build synchronously, settle once
//!
//! `encrypt_from` does **no I/O**. It validates, derives every local term,
//! drives vitaminc's [`Encrypt`] to a pending ciphertext tree, and returns a
//! [`Pending`] carrying the ZeroKMS *requests* the value needs. Combining
//! pendings ([`Pending::zip`], [`Pending::all`]) merges their requests, so
//! however large the assembly — one field, one record, a whole column — the
//! `.await` at the end settles it with **one** ZeroKMS round-trip per request
//! kind:
//!
//! ```
//! use stack_encrypt::target::{DecryptInto, EncryptInto};
//! use stack_encrypt::{nonempty, StackCipher, StackCipherText};
//! use stack_kms::FakeDataKeySource;
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let cipher = StackCipher::builder()
//!     .kms(FakeDataKeySource::new())
//!     .init()
//!     .await
//!     .unwrap();
//! let keyset = cipher.default_keyset();
//!
//! let ages: Vec<u32> = vec![29, 34, 41];
//!
//! // A column of independently sealed ciphertexts: ONE generate_keys call.
//! let sealed: Vec<StackCipherText> = ages
//!     .encrypt_into_with_context(&keyset, nonempty!("users/age"))
//!     .await?;
//!
//! // And back: ONE retrieve_keys call for the whole column.
//! let roundtrip: Vec<u32> = sealed.decrypt_into(&cipher, nonempty!("users/age")).await?;
//! assert_eq!(roundtrip, ages);
//! # Ok::<(), stack_encrypt::Error>(())
//! # }).unwrap();
//! ```
//!
//! Batching therefore comes from the **source shape**, exactly as it does for
//! vitaminc's `Encrypt`: pass the collection, not the element. A caller who
//! awaits per element pays per element.
//!
//! Note the two distinct shapes: `Vec<u32> → StackCipherText` (via `Encrypt`)
//! is *one* record whose value is a list — one tree, elements sealed under
//! sequence-derived AAD. `Vec<u32> → Vec<StackCipherText>` (above) is a
//! *column* of independent records sharing one context. Both are one ZeroKMS
//! call; they differ in what the ciphertext *is*.
//!
//! # Extending with your own SEM type
//!
//! The set of term types is open. Any crate can define one: implement
//! [`EncryptFrom`] for it against [`KeysetCipher`], build the result with
//! [`Pending::ready`] (local derivation) or [`Pending::request`] (derivation
//! needing ZeroKMS responses). Every built-in term type is implemented with
//! **exactly** this recipe — they use no privileged access — so [`sem`]
//! doubles as worked examples.
//!
//! The one thing every searchable-encryption scheme needs is a keyed,
//! deterministic derivation — the keyset's PRF ([`KeysetCipher::prf`], keyed
//! by that keyset's index key). Under the local HMAC backend the PRF
//! completes synchronously (`into_result`), so the pending carries no
//! requests; a future 2-party ZeroKMS PRF backend moves the same visitor
//! behind a PRF request instead, joining the record's one batched call.
//!
//! ```
//! use stack_encrypt::target::{DecryptField, Decryptable, EncryptFrom, Pending};
//! use stack_encrypt::{Error, IntoPrfContext, KeysetCipher, NonEmpty, StackCipher};
//! use vitaminc_prf::{PrfContext, PrfValue, PrfVisitor, PrfVisitorError};
//!
//! /// A third-party term type: one PRF block under its own domain.
//! pub struct MyTerm([u8; 32]);
//!
//! struct MyVisitor;
//!
//! impl<P: Send + 'static> PrfVisitor<[u8; 32], P> for MyVisitor {
//!     type Value = MyTerm;
//!
//!     fn visit_block(self, block: [u8; 32]) -> Result<Self::Value, PrfVisitorError> {
//!         Ok(MyTerm(block))
//!     }
//! }
//!
//! // A leaf owns the context policy, and states it in the impl header: it
//! // exists only for a `NonEmpty<T>`, so `()` — and any unproven value — is
//! // a compile error (nothing above a leaf checks, since a column of rows
//! // has no context of its own). The lifetime is the context's own, as in
//! // the `IntoPrfContext<'c>` it implements; `'k` is the keyset handle's
//! // borrow of its `StackCipher`.
//! impl<'c, 'k, S, K, T> EncryptFrom<S, KeysetCipher<'k, K>, NonEmpty<T>> for MyTerm
//! where
//!     S: PrfValue + Clone,
//!     T: IntoPrfContext<'c>,
//! {
//!     fn encrypt_from<'a>(
//!         source: &'a S,
//!         cipher: &'a KeysetCipher<'k, K>,
//!         context: NonEmpty<T>,
//!     ) -> Pending<'a, Self, K>
//!     where
//!         Self: 'a,
//!     {
//!         // The type is the proof; there is nothing left to check. Encode,
//!         // then domain-separate under your own label so your terms can
//!         // never collide with another scheme's under the same context.
//!         let context = context.into_prf_context().into_owned();
//!         let context = PrfContext::pae(&[b"my-crate/my-term/v1".as_slice(), context.as_bytes()]);
//!         let term = source
//!             .clone()
//!             .prf_visit_with_context(cipher.prf(), context, MyVisitor)
//!             .into_result()
//!             .map_err(|e| Error::Other(Box::new(e)));
//!         Pending::ready(cipher, term)
//!     }
//! }
//!
//! // A term is one-way. Saying so is what lets `#[derive(DecryptInto)]`
//! // pass over a `MyTerm` field and open the ciphertext beside it. The
//! // decrypt side is over `StackCipher` — the `KeysetCipher` form is the
//! // blanket impl in `target`, as for every `DecryptInto` / `DecryptField`.
//! impl Decryptable for MyTerm {
//!     const DECRYPTABLE: bool = false;
//! }
//!
//! impl<P, K, Ctx> DecryptField<P, StackCipher<K>, Ctx> for MyTerm {
//!     fn decrypt_field<'a>(self, _: &'a StackCipher<K>, _: Ctx) -> Option<Pending<'a, P, K>>
//!     where
//!         Self: 'a,
//!         P: 'a,
//!     {
//!         None
//!     }
//! }
//! ```
//!
//! A third-party *ciphertext* type implements `DecryptInto` as well — over
//! `StackCipher<K>`, like `DecryptField` — sets `DECRYPTABLE` to `true`, and
//! has `decrypt_field` return `Some(self.decrypt_into(cipher, context))`.
//!
//! A scheme needing state the cipher does not carry defines its own
//! capability trait and implements it for [`KeysetCipher`] (a local trait on
//! a foreign type is orphan-rule-legal) using its public accessors
//! ([`keyset_id`](KeysetCipher::keyset_id), [`prf`](KeysetCipher::prf),
//! [`kms`](KeysetCipher::kms)).
//!
//! **Not yet here:** the `ore_rs` *block* ORE scheme (`OreBlock256`) that EQL
//! and `cipherstash-client` use. The ORE/OPE terms in [`sem`] are CLLW, a
//! different construction; the block scheme lands as a third-party term type
//! in `eql-bindings`, built with exactly the recipe above.
//!
//! # Records and structs: `#[derive(EncryptFrom)]`
//!
//! A struct of leaves derived from one value is a *record*; a struct whose
//! fields are each derived from one field of a plaintext struct, under a
//! context of its own, is that plaintext encrypted *field by field*. Both
//! are the same derive, and both settle as one batched call. The field-by-
//! field form names its prefix once and its fields' contexts follow —
//! `#[stash(struct = User, context = "users")]` derives `age` from
//! `user.age` under `"users/age"` — and are overridden per field where that
//! is not wanted. A context the caller passes *extends* those: under
//! `encrypt_into_with_context(&cipher, 42u64)` the same field is derived
//! under `("users/age", 42u64)`, binding it to its record as well as its
//! name. Which is what a query site derives its probe under, too:
//!
//! ```
//! use stack_encrypt::sem::{EqualityTerm, OreTerm};
//! use stack_encrypt::target::{DecryptFrom, EncryptInto};
//! use stack_encrypt::{nonempty, DecryptInto, EncryptFrom, StackCipher, StackCipherText};
//! use stack_kms::FakeDataKeySource;
//!
//! /// An encrypted `u32`, queryable by equality and range.
//! #[derive(EncryptFrom, DecryptInto)]
//! #[stash(plaintext = u32)]
//! struct EncryptedAge {
//!     c: StackCipherText,
//!     hm: EqualityTerm,
//!     ob: OreTerm<u32>,
//! }
//!
//! #[derive(Debug, PartialEq)]
//! struct User {
//!     age: u32,
//!     email: String,
//! }
//!
//! /// `User` field by field: each field from the plaintext field of its own
//! /// name, under the context `"users/<field>"` — no attribute on the fields.
//! #[derive(EncryptFrom, DecryptInto)]
//! #[stash(struct = User, context = "users")]
//! struct EncryptedUser {
//!     age: EncryptedAge,
//!     email: StackCipherText,
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let cipher = StackCipher::builder()
//!     .kms(FakeDataKeySource::new())
//!     .init()
//!     .await
//!     .unwrap();
//! let keyset = cipher.default_keyset();
//!
//! let user = User { age: 42, email: "alice@example.com".into() };
//! // Every field names its own context, so nothing is needed from the
//! // caller: the context-free forms are the whole call.
//! let row: EncryptedUser = user.encrypt_into(&keyset).await?;
//! // A query site derives the same term under the column's context.
//! let probe: EqualityTerm = 42u32
//!     .encrypt_into_with_context(&keyset, nonempty!("users/age"))
//!     .await?;
//! assert_eq!(row.age.hm, probe);
//! let recovered = User::decrypt_from(row, &cipher).await?;
//! assert_eq!(recovered, user);
//!
//! // Or the caller extends every field's context with the record's id: the
//! // same field is now under `("users/age", 7u64)`, and opens only there.
//! let row: EncryptedUser = user.encrypt_into_with_context(&keyset, 7u64).await?;
//! let probe: EqualityTerm = 42u32
//!     .encrypt_into_with_context(&keyset, nonempty!("users/age").with(7u64))
//!     .await?;
//! assert_eq!(row.age.hm, probe);
//! let recovered = User::decrypt_from_with_context(row, &cipher, 7u64).await?;
//! assert_eq!(recovered, user);
//! # Ok::<(), stack_encrypt::Error>(())
//! # }).unwrap();
//! ```
//!
//! The attributes, and what the derive commits to, are documented on
//! [`EncryptFrom`](macro@EncryptFrom).
//!
//! # Plaintext fan-out
//!
//! One source value reaches every field implementation, so encrypting a
//! record clones the plaintext once per derived field. Term clones are
//! consumed during the synchronous build; the ciphertext's copy lives inside
//! the pending (wrapped in `Protected`, wiped as it seals). This widens the
//! plaintext custody window by design; keep it in mind for high-sensitivity
//! values.
//!
//! [`sem`]: crate::sem
//! [`EqualityTerm`]: crate::sem::EqualityTerm
//! [`MatchTerm`]: crate::sem::MatchTerm
//! [`OreTerm`]: crate::sem::OreTerm
//! [`OpeTerm`]: crate::sem::OpeTerm

use stack_kms::MaybeSend;
use vitaminc_aead::{CipherText, Decrypt, Encrypt, IntoAad};
use vitaminc_protected::NonEmpty;

use crate::cipher::{bind_keys, PendingStackCipherText, StackDecipher};
use crate::{Descriptor, Error, KeysetCipher, StackCipher, StackCipherText};

mod pending;
mod request;

pub use pending::{CipherScope, Pending, PendingFuture};
pub use request::{Request, Responses};
pub use stack_encrypt_derive::{DecryptInto, EncryptFrom};

// =============================================================================
// Cipher-owned output types
// =============================================================================

/// Implemented by ciphers: decides what an [`EncryptFrom`] implementation
/// hands back. A cipher that does no I/O sets
/// `Output<'a, T> = Result<T, Self::Error>` — no future, no `.await`.
/// [`KeysetCipher`] sets `Output<'a, T> = Pending<'a, T, K>`, a request
/// carrier that talks to ZeroKMS when awaited.
///
/// This mirrors `Cipher::Ok` and `Prf::Ok<T>`: the async shape belongs to the
/// implementation, never to the trait.
pub trait EncryptTarget {
    /// The error the cipher's outputs resolve to.
    type Error;
    /// What `encrypt_from` returns: the finished value, or a deferred handle
    /// to it.
    type Output<'a, T>
    where
        Self: 'a,
        T: 'a;
}

/// The decrypt-side mirror of [`EncryptTarget`].
pub trait DecryptTarget {
    /// The error the cipher's outputs resolve to.
    type Error;
    /// What `decrypt_from` returns: the recovered value, or a deferred handle
    /// to it.
    type Output<'a, T>
    where
        Self: 'a,
        T: 'a;
}

/// Encrypting binds to a keyset: data keys are minted under one, and index
/// terms are derived under one's index key. So the encrypt target is the
/// [`KeysetCipher`], not the client-scoped [`StackCipher`].
impl<K> EncryptTarget for KeysetCipher<'_, K> {
    type Error = Error;
    type Output<'a, T>
        = Pending<'a, T, K>
    where
        Self: 'a,
        T: 'a;
}

/// Decrypting is not keyset-scoped — a sealed leaf carries the id of the
/// keyset it was sealed under — so the client-scoped [`StackCipher`] is a
/// decrypt target, opening leaves from any keyset in one batch.
impl<K> DecryptTarget for StackCipher<K> {
    type Error = Error;
    type Output<'a, T>
        = Pending<'a, T, K>
    where
        Self: 'a,
        T: 'a;
}

/// A [`KeysetCipher`] decrypts too, constrained: every [`DecryptInto`] and
/// [`DecryptField`] implementation over [`StackCipher`] applies through it
/// (the blanket impls below), and a leaf from any other keyset is
/// [`Error::ForeignKeyset`] before any key is retrieved.
impl<K> DecryptTarget for KeysetCipher<'_, K> {
    type Error = Error;
    type Output<'a, T>
        = Pending<'a, T, K>
    where
        Self: 'a,
        T: 'a;
}

/// The constrained form of every decrypt: whatever opens through the
/// [`StackCipher`] opens through a [`KeysetCipher`] scoped to the leaves'
/// keyset, and refuses leaves from any other. Implement `DecryptInto` over
/// `StackCipher<K>`; this impl supplies the `KeysetCipher` form.
impl<'k, P, K, Ctx, X> DecryptInto<P, KeysetCipher<'k, K>, Ctx> for X
where
    X: DecryptInto<P, StackCipher<K>, Ctx>,
{
    fn decrypt_into<'a>(self, cipher: &'a KeysetCipher<'k, K>, context: Ctx) -> Pending<'a, P, K>
    where
        Self: 'a,
        P: 'a,
    {
        let inner: &'a StackCipher<K> = cipher.cipher();
        X::decrypt_into(self, inner, context).scoped_to(cipher.keyset_id())
    }
}

/// See the [`DecryptInto`] blanket above.
impl<'k, P, K, Ctx, X> DecryptField<P, KeysetCipher<'k, K>, Ctx> for X
where
    X: DecryptField<P, StackCipher<K>, Ctx>,
{
    fn decrypt_field<'a>(
        self,
        cipher: &'a KeysetCipher<'k, K>,
        context: Ctx,
    ) -> Option<Pending<'a, P, K>>
    where
        Self: 'a,
        P: 'a,
    {
        let inner: &'a StackCipher<K> = cipher.cipher();
        X::decrypt_field(self, inner, context).map(|pending| pending.scoped_to(cipher.keyset_id()))
    }
}

// =============================================================================
// The traits
// =============================================================================

/// `Self` is an encrypted representation of `S`, producible by a cipher `C`.
///
/// Implemented on the *output* type — a leaf primitive output
/// ([`StackCipherText`], a SEM term, ...) or a composite record of them. Open
/// for extension: see the
/// [module docs](self#extending-with-your-own-sem-type).
///
/// There is no associated error type: errors belong to the cipher
/// ([`EncryptTarget::Error`]), and implementations with failure modes of
/// their own use [`Error::Term`] or [`Error::Other`].
///
/// # The context parameter
///
/// `Ctx` is a parameter of the trait, not of the method, so that each
/// implementation can say which contexts it accepts. A leaf is implemented
/// for [`NonEmpty<T>`] alone — it has nothing else to authenticate under,
/// and `()` is the empty context it must never derive under (see the
/// [module docs](self#contexts)). A derived record is implemented twice:
/// for `()`, deriving each field under the context the field carries itself
/// (a `context = ".."` literal, or the one a `struct = ..` derive infers),
/// and for `NonEmpty<T>`, deriving each field under that context extended
/// with the caller's (`("users/age", id)`) — or, for a field with no
/// context of its own, under the caller's as it is. No record accepts a
/// context it then discards. The call site then
/// gets one of two answers from the compiler:
/// [`encrypt_into(&cipher)`](EncryptInto::encrypt_into) resolves against
/// `EncryptFrom<S, C, ()>`, so it compiles for exactly the outputs whose
/// every leaf has a context of its own; anything else takes
/// [`encrypt_into_with_context`](EncryptInto::encrypt_into_with_context).
///
/// The trait itself places no bound on `Ctx`; an implementation that uses the
/// context bounds it as `NonEmpty<T>` with `T: IntoAad<'c> + IntoPrfContext<'c>`
/// and the context's own lifetime as an impl parameter (see the
/// [module docs](self#extending-with-your-own-sem-type)).
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not an encrypted form of `{S}` under a `{Ctx}` context",
    label = "not `EncryptFrom<{S}, _, {Ctx}>`",
    note = "a leaf — a ciphertext or an index term — exists only under a `NonEmpty<_>` context: \
            `encrypt_into` passes `()`, so use `encrypt_into_with_context(&cipher, context)`, or \
            give the field a `context = \"..\"` of its own",
    note = "a context is anything vitaminc encodes (`&str`, `String`, bytes, integers, `Option`s \
            and pairs of those), proven non-empty: `nonempty!(\"users/email\")` for a literal, \
            `NonEmpty::new(value)?` for a runtime value, a bare integer for an id"
)]
pub trait EncryptFrom<S, C: EncryptTarget, Ctx>: Sized {
    /// Whether encrypting from `S` requests ZeroKMS data keys under the
    /// caller's context (or an extension of it), so that the context must
    /// render within [`Descriptor::MAX_LEN`]. A ciphertext leaf does; a
    /// term derives locally and never renders a descriptor, so it says
    /// `false` and a column of terms is not held to the limit. The default
    /// is the safe over-approximation: a type that does not say is treated
    /// as keyed, and a derived record is keyed if any field might be (the
    /// derive does not compute this per field, so a record of terms alone
    /// is checked like any other record).
    ///
    /// Read by the column implementations, which check the context once
    /// before walking their elements ([`ElementContext`]).
    const KEYED: bool = true;

    /// Encrypt `source` into `Self` under `context`, returning the cipher's
    /// [`Output`](EncryptTarget::Output). No I/O happens here; work needing
    /// ZeroKMS is carried as requests and settles when the output is awaited.
    ///
    /// Borrows the source because a composite record hands the same source to
    /// several field implementations; each takes what it needs (typically one
    /// clone).
    fn encrypt_from<'a>(source: &'a S, cipher: &'a C, context: Ctx) -> C::Output<'a, Self>
    where
        Self: 'a;
}

/// `Self` is an encrypted representation that decrypts to `P` by a cipher
/// `C` — the mirror of [`EncryptFrom`], implemented on the *encrypted* type.
///
/// Both traits put `Self` on the type that is local to the crate defining
/// the record: it is the *output* of encryption (`EncryptFrom`) and the
/// *input* of decryption (`DecryptInto`). One encrypted type may decrypt to
/// several plaintext types (`impl DecryptInto<u32, _>` and
/// `impl DecryptInto<u64, _>` coexist), and several encrypted types may
/// decrypt to the same plaintext — each owns its own opening.
///
/// Takes `self` by value: decryption consumes the ciphertext, and index
/// terms (which have no plaintext to recover) simply do not participate.
///
/// `Ctx` is a trait parameter for the reason it is on [`EncryptFrom`]: the
/// leaves accept only a [`NonEmpty<T>`], so an encrypted type that needs
/// no context from the caller is exactly one that implements
/// `DecryptInto<P, C, ()>` — what [`DecryptFrom::decrypt_from`] asks for —
/// and a derived record opened under `NonEmpty<T>` extends its fields'
/// contexts with it, exactly as it did when encrypting.
///
/// A record whose ciphertext field carries a `context = ".."` literal and
/// whose other fields are terms opens under `()` *and* under any
/// `NonEmpty<T>`, but not interchangeably. The terms open nothing, so a
/// context reaches them and is checked for nothing; the ciphertext
/// authenticates under its literal extended with the caller's context
/// exactly as it was sealed — `()` leaves the literal alone, a `NonEmpty<T>`
/// extends it. A record sealed with `encrypt_into` opens with
/// `decrypt_from` and one sealed under an extension opens only under the
/// same extension; a wrong caller context is the refusal it is against a
/// leaf: [`Error::Kms`], ZeroKMS declining the key retrieval under the
/// other descriptor before the AEAD runs, or [`Error::Aead`] from a key
/// source that ignores descriptors. What the caller's context cannot be is
/// something that is not a context at all:
///
/// ```compile_fail,E0277
/// use stack_encrypt::sem::EqualityTerm;
/// use stack_encrypt::{DecryptInto, EncryptFrom, StackCipher, StackCipherText};
/// use stack_kms::FakeDataKeySource;
///
/// #[derive(EncryptFrom, DecryptInto)]
/// #[stash(plaintext = u32)]
/// struct Rec {
///     #[stash(context = "rec/c")]
///     c: StackCipherText,
///     hm: EqualityTerm,
/// }
///
/// async fn decrypt(cipher: &StackCipher<FakeDataKeySource>, rec: Rec) {
///     // `true` is neither `()` nor a `NonEmpty<_>`: a compile error, not a
///     // value the term fields quietly swallow.
///     let _: u32 = rec.decrypt_into(cipher, true).await.unwrap();
/// }
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not decrypt to `{P}` under a `{Ctx}` context",
    label = "not `DecryptInto<{P}, _, {Ctx}>`",
    note = "a leaf decrypts only under a `NonEmpty<_>` context — the one it was encrypted under \
            (`decrypt_into(&cipher, context)` / `decrypt_from_with_context`); an output whose \
            fields carry their own opens under `()` (`decrypt_from`) as well"
)]
pub trait DecryptInto<P, C: DecryptTarget, Ctx>: Sized {
    /// Decrypt `self` into `P`, authenticating against `context` — which
    /// must match the context the value was encrypted under.
    fn decrypt_into<'a>(self, cipher: &'a C, context: Ctx) -> C::Output<'a, P>
    where
        Self: 'a,
        P: 'a;
}

/// Call-site sugar: `value.encrypt_into(&cipher)` and
/// `value.encrypt_into_with_context(&cipher, context)`.
///
/// The `Into` to [`EncryptFrom`]'s `From` — blanket-implemented for every
/// type, never implemented by hand. The target type is usually inferred from
/// the binding. A leaf, or a record that hands the caller's context to one,
/// exists only under a [`NonEmpty<T>`] and takes the second form; a record
/// whose fields name their own contexts takes either — the first as it is,
/// the second with every field's context extended by the caller's. The
/// split is vitaminc's `encrypt` / `encrypt_with_aad`, decided by the type.
///
/// ```
/// use stack_encrypt::sem::EqualityTerm;
/// use stack_encrypt::target::EncryptInto;
/// use stack_encrypt::{nonempty, NonEmpty, StackCipher};
/// use stack_kms::FakeDataKeySource;
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// let cipher = StackCipher::builder()
///     .kms(FakeDataKeySource::new())
///     .init()
///     .await
///     .unwrap();
/// let keyset = cipher.default_keyset();
///
/// // A literal, checked at compile time.
/// let term: EqualityTerm = "alice"
///     .encrypt_into_with_context(&keyset, nonempty!("users/email"))
///     .await?;
/// // A runtime value, checked once where it is built.
/// let column = String::from("users/email");
/// let same: EqualityTerm = "alice"
///     .encrypt_into_with_context(&keyset, NonEmpty::new(column)?)
///     .await?;
/// assert_eq!(term, same);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
pub trait EncryptInto {
    /// Encrypt `self` into a `T` that needs no context from the caller —
    /// a record whose fields carry their own. See [`EncryptFrom`].
    ///
    /// Passes `()`, so this exists only for `T: EncryptFrom<Self, C, ()>`:
    /// against a leaf the compiler says to use
    /// [`encrypt_into_with_context`](Self::encrypt_into_with_context).
    fn encrypt_into<'a, T, C>(&'a self, cipher: &'a C) -> C::Output<'a, T>
    where
        C: EncryptTarget,
        T: EncryptFrom<Self, C, ()> + 'a,
        Self: Sized;

    /// Encrypt `self` into `T` under `context`. See [`EncryptFrom`].
    ///
    /// The context is anything that converts into a [`NonEmpty<T>`]: a
    /// `NonEmpty` itself — [`nonempty!`](crate::nonempty) for a literal,
    /// [`NonEmpty::new`] for a runtime value — or a bare integer, which is
    /// never empty. Passing `()` here is a compile error, with
    /// [`encrypt_into`](Self::encrypt_into) as the answer.
    fn encrypt_into_with_context<'a, T, C, N, Ctx>(
        &'a self,
        cipher: &'a C,
        context: Ctx,
    ) -> C::Output<'a, T>
    where
        C: EncryptTarget,
        T: EncryptFrom<Self, C, NonEmpty<N>> + 'a,
        Ctx: Into<NonEmpty<N>>,
        Self: Sized;
}

impl<S> EncryptInto for S {
    fn encrypt_into<'a, T, C>(&'a self, cipher: &'a C) -> C::Output<'a, T>
    where
        C: EncryptTarget,
        T: EncryptFrom<Self, C, ()> + 'a,
    {
        T::encrypt_from(self, cipher, ())
    }

    fn encrypt_into_with_context<'a, T, C, N, Ctx>(
        &'a self,
        cipher: &'a C,
        context: Ctx,
    ) -> C::Output<'a, T>
    where
        C: EncryptTarget,
        T: EncryptFrom<Self, C, NonEmpty<N>> + 'a,
        Ctx: Into<NonEmpty<N>>,
    {
        T::encrypt_from(self, cipher, context.into())
    }
}

/// Call-site sugar: `Plaintext::decrypt_from(encrypted, &cipher)` and
/// `Plaintext::decrypt_from_with_context(encrypted, &cipher, context)` — the
/// `From` to [`DecryptInto`]'s `Into`, and the decrypt-side [`EncryptInto`],
/// with the same two forms for the same reason. Blanket-implemented for every
/// plaintext; never implemented by hand.
///
/// (The implemented trait, [`DecryptInto`], always takes a context:
/// `encrypted.decrypt_into(&cipher, nonempty!("users/age"))` is the
/// method-call form for a value that needs one.)
pub trait DecryptFrom: Sized {
    /// Decrypt `source` — an encrypted type that needs no context from the
    /// caller — into `Self`. See [`DecryptInto`].
    fn decrypt_from<'a, S, C>(source: S, cipher: &'a C) -> C::Output<'a, Self>
    where
        C: DecryptTarget,
        S: DecryptInto<Self, C, ()> + 'a,
        Self: 'a;

    /// Decrypt `source` into `Self`, authenticating against `context`. See
    /// [`DecryptInto`].
    ///
    /// The context is anything that converts into a [`NonEmpty<T>`], as for
    /// [`encrypt_into_with_context`](EncryptInto::encrypt_into_with_context),
    /// and must be the one the value was encrypted under.
    fn decrypt_from_with_context<'a, S, C, N, Ctx>(
        source: S,
        cipher: &'a C,
        context: Ctx,
    ) -> C::Output<'a, Self>
    where
        C: DecryptTarget,
        S: DecryptInto<Self, C, NonEmpty<N>> + 'a,
        Ctx: Into<NonEmpty<N>>,
        Self: 'a;
}

impl<P> DecryptFrom for P {
    fn decrypt_from<'a, S, C>(source: S, cipher: &'a C) -> C::Output<'a, Self>
    where
        C: DecryptTarget,
        S: DecryptInto<Self, C, ()> + 'a,
        Self: 'a,
    {
        source.decrypt_into(cipher, ())
    }

    fn decrypt_from_with_context<'a, S, C, N, Ctx>(
        source: S,
        cipher: &'a C,
        context: Ctx,
    ) -> C::Output<'a, Self>
    where
        C: DecryptTarget,
        S: DecryptInto<Self, C, NonEmpty<N>> + 'a,
        Ctx: Into<NonEmpty<N>>,
        Self: 'a,
    {
        source.decrypt_into(cipher, context.into())
    }
}

/// Whether a type is a ciphertext that decryption opens, or an index term
/// that it passes over.
///
/// Every type that can be a field of a derived record implements this —
/// it is what lets `#[derive(DecryptInto)]` find the ciphertext field on its
/// own, with no attribute: the derive counts the fields whose
/// [`DECRYPTABLE`](Self::DECRYPTABLE) is `true` and requires exactly one
/// (per plaintext field, for a `struct = ..` derive). `#[derive(EncryptFrom)]` emits it for
/// a record — a record is decryptable if any of its fields is, or outright
/// when `#[stash(decrypt)]` names the opened fields — and the
/// built-in leaves implement it by hand: [`StackCipherText`] is, the
/// [`sem`](crate::sem) terms are not.
///
/// A third-party leaf implements it alongside [`EncryptFrom`], together
/// with [`DecryptField`]; see the
/// [module docs](self#extending-with-your-own-sem-type).
///
/// For a *generic* record the exactly-one count cannot be checked at the
/// definition (a `const _` item cannot name the record's generic
/// parameters), so the derive defers it to an inline `const` evaluated per
/// instantiation: the record compiles where it is defined and the error
/// fires at the first *use* that is actually codegenned — possibly in a
/// downstream crate. The message is the same one a concrete record gets at
/// its definition:
///
/// ```compile_fail
/// use stack_encrypt::target::Pending;
/// use stack_encrypt::{DecryptInto, StackCipher, StackCipherText};
/// use stack_kms::FakeDataKeySource;
///
/// #[derive(DecryptInto)]
/// struct Doubled<T> {
///     a: StackCipherText,
///     b: StackCipherText,
///     #[stash(default)]
///     tag: T,
/// }
///
/// // Compiles fine: the two-ciphertext mistake is not yet instantiated.
/// fn open<'a>(
///     cipher: &'a StackCipher<FakeDataKeySource>,
///     doubled: Doubled<u8>,
/// ) -> Pending<'a, u32, FakeDataKeySource> {
///     doubled.decrypt_into(cipher, "d")
/// }
///
/// // The first reachable instantiation trips the deferred check:
/// // "`Doubled` has several decryptable fields: mark the one decryption
/// // opens `#[stash(decrypt)]`".
/// let _ = open
///     as for<'a> fn(
///         &'a StackCipher<FakeDataKeySource>,
///         Doubled<u8>,
///     ) -> Pending<'a, u32, FakeDataKeySource>;
/// ```
pub trait Decryptable {
    /// `true` if decryption opens a value of this type, `false` if it is a
    /// one-way term with no plaintext to recover.
    const DECRYPTABLE: bool;
}

/// Decryption of one field of a derived record, which either opens the field
/// (`Some`) or passes over it (`None`, for an index term).
///
/// The derive calls this on every candidate field and takes the one `Some`;
/// [`Decryptable`] has already established, at compile time, that there is
/// exactly one. Implemented alongside `Decryptable`: decryptable types wrap
/// their [`DecryptInto`], terms return `None` for every `P`. (Not a
/// supertrait relationship: `#[derive(DecryptInto)]` emits this for every
/// record, and a record that only decrypts — no `EncryptFrom` derive to
/// emit its `Decryptable` — must still be a field of a record in the explicit
/// mode.)
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be a field of an automatically decrypted record",
    label = "no `DecryptField<{P}, ..>` implementation",
    note = "a term-only bundle — `#[derive(EncryptFrom)]` alone, nothing to open — has no \
            `DecryptField`: mark the outer record's real ciphertext `#[stash(decrypt)]` so only \
            the marked fields are considered",
    note = "a hand-written term type implements `DecryptField` (returning `None`) alongside \
            `Decryptable`; a hand-written ciphertext type wraps its `DecryptInto`"
)]
pub trait DecryptField<P, C: DecryptTarget, Ctx> {
    /// [`DecryptInto::decrypt_into`] if `Self` is decryptable, `None` if not.
    fn decrypt_field<'a>(self, cipher: &'a C, context: Ctx) -> Option<C::Output<'a, P>>
    where
        Self: 'a,
        P: 'a;
}

impl Decryptable for StackCipherText {
    const DECRYPTABLE: bool = true;
}

impl<P, K, Ctx> DecryptField<P, StackCipher<K>, Ctx> for StackCipherText
where
    Self: DecryptInto<P, StackCipher<K>, Ctx>,
{
    fn decrypt_field<'a>(
        self,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Option<Pending<'a, P, K>>
    where
        Self: 'a,
        P: 'a,
    {
        Some(self.decrypt_into(cipher, context))
    }
}

/// A collection is decryptable if its elements are.
impl<S: Decryptable> Decryptable for Vec<S> {
    const DECRYPTABLE: bool = S::DECRYPTABLE;
}

impl<S, T, K, Ctx> DecryptField<Vec<T>, StackCipher<K>, Ctx> for Vec<S>
where
    S: Decryptable + DecryptField<T, StackCipher<K>, Ctx>,
    Ctx: ElementContext,
{
    fn decrypt_field<'a>(
        self,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Option<Pending<'a, Vec<T>, K>>
    where
        Self: 'a,
        Vec<T>: 'a,
    {
        if !S::DECRYPTABLE {
            return None;
        }
        if !self.is_empty() {
            if let Err(e) = context.check_descriptor() {
                return Some(Pending::failed(cipher, e));
            }
        }
        let items = self
            .into_iter()
            .map(|item| {
                item.decrypt_field(cipher, context.clone())
                    .unwrap_or_else(|| Pending::failed(cipher, Error::NotOpened))
            })
            .collect();
        Some(Pending::all(cipher, items))
    }
}

/// An optional value is decryptable if its content is.
impl<S: Decryptable> Decryptable for Option<S> {
    const DECRYPTABLE: bool = S::DECRYPTABLE;
}

impl<S, T, K, Ctx> DecryptField<Option<T>, StackCipher<K>, Ctx> for Option<S>
where
    S: Decryptable + DecryptField<T, StackCipher<K>, Ctx>,
    T: MaybeSend,
{
    fn decrypt_field<'a>(
        self,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Option<Pending<'a, Option<T>, K>>
    where
        Self: 'a,
        Option<T>: 'a,
    {
        if !S::DECRYPTABLE {
            return None;
        }
        Some(match self {
            Some(value) => value
                .decrypt_field(cipher, context)
                .unwrap_or_else(|| Pending::failed(cipher, Error::NotOpened))
                .map(Some),
            None => Pending::ready(cipher, Ok(None)),
        })
    }
}

// =============================================================================
// Leaf implementations: the record ciphertext
// =============================================================================

/// The record ciphertext: any vitaminc [`Encrypt`] value, sealed by a
/// [`KeysetCipher`] under per-leaf ZeroKMS data keys minted under its
/// keyset. The context becomes the AEAD associated data, binding the
/// ciphertext to the field it was encrypted for.
///
/// The build is synchronous: the value's `Encrypt` impl drives the cipher to
/// a pending tree (no I/O), and the returned [`Pending`] carries one
/// data-key request per leaf. Sealing happens in the fulfilment, key material
/// drawn in the same traversal order the tree was built in.
///
/// A leaf has nothing of its own to authenticate under, so it exists only
/// for a [`NonEmpty<T>`]: `()` is a compile error here. (An empty context
/// would leave the leaf AAD carrying only the key tag, making ciphertexts
/// transplantable between empty-context fields — see the
/// [module docs](self#contexts).)
impl<'c, 'k, S, K, T> EncryptFrom<S, KeysetCipher<'k, K>, NonEmpty<T>> for StackCipherText
where
    S: Encrypt + Clone,
    T: IntoAad<'c>,
{
    fn encrypt_from<'a>(
        source: &'a S,
        cipher: &'a KeysetCipher<'k, K>,
        context: NonEmpty<T>,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        let context = context.into_aad_piece();
        let descriptor = Descriptor::from_piece(&context);
        let aad = context.into_aad().into_owned();
        match source.clone().encrypt_with_aad(cipher, aad) {
            Ok(tree) => seal_pending(cipher, tree, descriptor),
            Err(_) => Pending::ready(cipher, Err(Error::Aead)),
        }
    }
}

/// Seal a pending tree: one [`Request::generate_data_key`] per keyed leaf,
/// every one under `descriptor` — the tree's root context, rendered — with
/// keys drawn back in the same traversal order the tree was built in.
///
/// Both ways of encrypting go through here — the target-directed
/// `encrypt_into_with_context` into a [`StackCipherText`] above and the
/// cipher-directed
/// [`PendingStackCipherText::seal`] behind [`KeysetCipher::encrypt`] — so
/// there is one definition of how a tree is sealed and one path to ZeroKMS.
pub(crate) fn seal_pending<'a, K>(
    cipher: &'a KeysetCipher<'_, K>,
    tree: PendingStackCipherText,
    descriptor: Descriptor,
) -> Pending<'a, StackCipherText, K> {
    // Fast path: refuse an over-long descriptor before a single request
    // exists, not after one per leaf has been built. `dispatch` is the gate
    // proper, and checks every request's descriptor.
    if let Err(e) = descriptor.check() {
        return Pending::ready(cipher, Err(e));
    }
    let keyset_id = cipher.keyset_id();
    let requests = std::iter::repeat_with(|| Request::generate_data_key(descriptor.clone()))
        .take(tree.key_count())
        .collect();
    Pending::request(cipher, requests, move |responses| {
        let mut keys = responses.drain_generated();
        tree.seal_with(keyset_id, &mut keys).map_err(Error::from)
    })
}

/// Bind retrieved keys onto a ciphertext: one [`Request::retrieve_data_key`]
/// per keyed leaf, every one under `descriptor` (the one the tree was
/// sealed under), keys zipped back on in the same depth-first order. The
/// decrypt twin of [`seal_pending`], behind the cipher-directed
/// [`StackCipher::decipher`]. The target-directed `decrypt_into` below
/// shares both halves — [`retrieve_requests`] and
/// [`decipher_from_responses`] — but runs the value's `Decrypt` impl in the
/// same fulfilment rather than composing a second pending over this one.
pub(crate) fn decipher_pending<'a, K>(
    scope: impl CipherScope<'a, K>,
    ciphertext: StackCipherText,
    descriptor: Descriptor,
) -> Pending<'a, StackDecipher, K> {
    // Fast path, as in `seal_pending`; `dispatch` is the gate.
    if let Err(e) = descriptor.check() {
        return Pending::ready(scope, Err(e));
    }
    let requests = retrieve_requests(&ciphertext, &descriptor);
    Pending::request(scope, requests, move |responses| {
        decipher_from_responses(ciphertext, responses)
    })
}

/// The fulfilment half of [`decipher_pending`], shared with `decrypt_into`
/// (which runs the value's `Decrypt` impl over the result in the same
/// fulfilment rather than composing two pendings).
fn decipher_from_responses(
    ciphertext: StackCipherText,
    responses: &mut Responses,
) -> Result<StackDecipher, Error> {
    let mut keys = responses.drain_retrieved();
    // Too few keys for the tree, or keys left over once it is bound, both
    // mean `retrieve_requests` and `bind_keys` disagreed about the tree's
    // shape: a composition bug in this module, not a data error — so
    // `ResponseShape`, never `Aead`, which would read as tampering.
    let keyed = bind_keys(ciphertext, &mut keys).map_err(|_| Error::ResponseShape)?;
    if keys.next().is_some() {
        return Err(Error::ResponseShape);
    }
    Ok(StackDecipher::over(keyed))
}

/// The decrypt mirror: any vitaminc [`Decrypt`] value recovers from a
/// [`StackCipherText`]. The pending carries one retrieve request per leaf
/// (`iv` + `tag` are lifted out of the tree during the synchronous build);
/// the fulfilment binds the retrieved keys back onto the leaves and lets the
/// value's `Decrypt` impl drive the opening.
///
/// Symmetric with the encrypt side: the target layer never encrypts under an
/// empty context, so it never decrypts under one either — the context is a
/// [`NonEmpty<T>`] here too.
impl<'c, T, K, A> DecryptInto<T, StackCipher<K>, NonEmpty<A>> for StackCipherText
where
    T: Decrypt<'static> + 'static,
    A: IntoAad<'c>,
{
    fn decrypt_into<'a>(self, cipher: &'a StackCipher<K>, context: NonEmpty<A>) -> Pending<'a, T, K>
    where
        Self: 'a,
        T: 'a,
    {
        let context = context.into_aad_piece();
        let descriptor = Descriptor::from_piece(&context);
        // Fast path, as in `seal_pending`; `dispatch` is the gate.
        if let Err(e) = descriptor.check() {
            return Pending::ready(cipher, Err(e));
        }
        let requests = retrieve_requests(&self, &descriptor);
        let aad = context.into_aad().into_owned();
        Pending::request(cipher, requests, move |responses| {
            let decipher = decipher_from_responses(self, responses)?;
            T::decrypt_with_aad(decipher, aad).map_err(Error::from)
        })
    }
}

/// One [`Request::retrieve_data_key`] per keyed leaf, all under
/// `descriptor`, in the same depth-first order `bind_keys` will consume the
/// responses.
fn retrieve_requests(ciphertext: &StackCipherText, descriptor: &Descriptor) -> Vec<Request> {
    let mut out = Vec::new();
    collect_retrieve_requests(ciphertext, descriptor, &mut out);
    out
}

fn collect_retrieve_requests(
    ciphertext: &StackCipherText,
    descriptor: &Descriptor,
    out: &mut Vec<Request>,
) {
    match ciphertext {
        CipherText::Single(leaf)
        | CipherText::None(leaf)
        | CipherText::EmptySequence(leaf)
        | CipherText::EmptyMap(leaf) => {
            out.push(Request::retrieve_data_key(
                *leaf.iv(),
                leaf.tag().to_vec(),
                descriptor.clone(),
                leaf.keyset_id(),
            ));
        }
        CipherText::Sequence(items) => {
            for item in items {
                collect_retrieve_requests(item, descriptor, out);
            }
        }
        CipherText::Map(entries) => {
            for (_, value) in entries {
                collect_retrieve_requests(value, descriptor, out);
            }
        }
        CipherText::Passthrough(_) => {}
    }
}

// =============================================================================
// Structural implementations: columns and optionals
// =============================================================================

/// A column: each element encrypts independently under the **same** context
/// (a column is one field), and the whole column settles in one batched call.
///
/// Distinct from `Vec<S> → StackCipherText` (via [`Encrypt`]), which is one
/// record whose value is a list — see the [module docs](self).
///
/// The context is passed through untouched, and so is the obligation: a
/// column of leaves needs a [`NonEmpty<T>`] because its leaves do, a column
/// of records whose fields carry their own contexts accepts `()` as well
/// because they do. Neither is decided here. What *is* decided here is
/// that an over-long context is refused once, before the column is walked
/// ([`ElementContext`]), not once per element.
impl<'k, S, T, K, Ctx> EncryptFrom<Vec<S>, KeysetCipher<'k, K>, Ctx> for Vec<T>
where
    T: EncryptFrom<S, KeysetCipher<'k, K>, Ctx>,
    Ctx: ElementContext,
{
    const KEYED: bool = T::KEYED;

    fn encrypt_from<'a>(
        source: &'a Vec<S>,
        cipher: &'a KeysetCipher<'k, K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        if T::KEYED && !source.is_empty() {
            if let Err(e) = context.check_descriptor() {
                return Pending::failed(cipher, e);
            }
        }
        let items = source
            .iter()
            .map(|item| T::encrypt_from(item, cipher, context.clone()))
            .collect();
        Pending::all(cipher, items)
    }
}

/// The column decrypt mirror: one batched retrieve for every element.
impl<S, T, K, Ctx> DecryptInto<Vec<T>, StackCipher<K>, Ctx> for Vec<S>
where
    S: DecryptInto<T, StackCipher<K>, Ctx>,
    Ctx: ElementContext,
{
    fn decrypt_into<'a>(self, cipher: &'a StackCipher<K>, context: Ctx) -> Pending<'a, Vec<T>, K>
    where
        Self: 'a,
        Vec<T>: 'a,
    {
        // Every `DecryptInto` opens keyed leaves (terms are one-way), so
        // the only column with nothing to bind is the empty one.
        if !self.is_empty() {
            if let Err(e) = context.check_descriptor() {
                return Pending::failed(cipher, e);
            }
        }
        let items = self
            .into_iter()
            .map(|item| item.decrypt_into(cipher, context.clone()))
            .collect();
        Pending::all(cipher, items)
    }
}

/// The context a column hands to each of its elements: `()` or a
/// [`NonEmpty<T>`], the two shapes the target layer takes.
///
/// A column clones its context into every element, and every keyed element
/// renders it as its ZeroKMS [`Descriptor`]. The rendering is bounded
/// ([`Descriptor::MAX_LEN`]) but the context is not, so a column checks the
/// rendering **once**, here, before it walks its elements: an over-long
/// context costs one rendering and is refused whole, not one rendering per
/// element before [`Pending::all`] surfaces the first refusal. Under `()`
/// the elements carry their own contexts and there is nothing to check.
///
/// The check is on the context the column was given. A derived record
/// extends it with each field's own literal before its leaves render it,
/// and that extension can exceed the limit where the caller's part alone
/// did not; the leaf then refuses it, once per row — each such rendering
/// bounded by [`Descriptor::MAX_LEN`] plus the literal, since the caller's
/// part has already been shown to fit. And a column whose elements request
/// no keys under the context ([`EncryptFrom::KEYED`] is `false`, as for a
/// column of terms), or that has no elements, is not checked at all: there
/// is no descriptor to bind.
///
/// Sealed: the two implementations are the two shapes.
pub trait ElementContext: Clone + sealed::Sealed {
    /// Render the descriptor the elements will render, and refuse it now if
    /// ZeroKMS could not bind it.
    fn check_descriptor(&self) -> Result<(), Error>;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for () {}
    impl<T> Sealed for vitaminc_protected::NonEmpty<T> {}
}

impl ElementContext for () {
    fn check_descriptor(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl<'c, T> ElementContext for NonEmpty<T>
where
    T: IntoAad<'c> + Clone,
{
    fn check_descriptor(&self) -> Result<(), Error> {
        Descriptor::of(self.clone()).check()
    }
}

/// An optional field: `None` encrypts to `None` at the target layer (an
/// absent *record field*, carrying no requests). This is distinct from
/// `Option<S> → StackCipherText` via [`Encrypt`], which produces an
/// *authenticated* absence marker inside one ciphertext.
impl<'k, S, T, K, Ctx> EncryptFrom<Option<S>, KeysetCipher<'k, K>, Ctx> for Option<T>
where
    T: EncryptFrom<S, KeysetCipher<'k, K>, Ctx> + MaybeSend,
{
    const KEYED: bool = T::KEYED;

    fn encrypt_from<'a>(
        source: &'a Option<S>,
        cipher: &'a KeysetCipher<'k, K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        match source {
            Some(value) => T::encrypt_from(value, cipher, context).map(Some),
            None => Pending::ready(cipher, Ok(None)),
        }
    }
}

/// The optional decrypt mirror of the [`Option`] encrypt implementation.
impl<S, T, K, Ctx> DecryptInto<Option<T>, StackCipher<K>, Ctx> for Option<S>
where
    S: DecryptInto<T, StackCipher<K>, Ctx>,
    T: MaybeSend,
{
    fn decrypt_into<'a>(self, cipher: &'a StackCipher<K>, context: Ctx) -> Pending<'a, Option<T>, K>
    where
        Self: 'a,
        Option<T>: 'a,
    {
        match self {
            Some(value) => value.decrypt_into(cipher, context).map(Some),
            None => Pending::ready(cipher, Ok(None)),
        }
    }
}
