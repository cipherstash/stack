//! Target-directed encryption: the *output* type decides what gets derived,
//! and the *cipher* decides the async shape.
//!
//! A stored encrypted value is rarely just a ciphertext — it is a record: the
//! AEAD ciphertext of the plaintext plus zero or more index terms derived from
//! the same plaintext by different primitives. [`EncryptFrom`] puts that
//! record shape in charge:
//!
//! ```text
//! let term: EqualityTerm = value.encrypt_into_with_context(&cipher, "users/email").await?;
//! let row: EncryptedUser = user.encrypt_into(&cipher).await?;
//! ```
//!
//! compiles only when the output type declares itself an encrypted form of
//! the value's type, producible by that cipher, under that context — and a
//! context is something the output type may already have. A leaf takes the
//! caller's; a row whose fields each name their own column needs none, and
//! the second line is the whole call.
//!
//! # The pieces
//!
//! * [`EncryptFrom<S, C, Ctx>`] — implemented by an *output* type: "`Self` is
//!   an encrypted representation of `S`, producible by a cipher `C`, under a
//!   context `Ctx`". The context is a parameter of the *trait* so that an
//!   implementation can say which contexts it accepts: the leaves accept
//!   only a [`SuppliedContext`], a record passes the obligation through to
//!   its fields, and a row whose fields carry their own contexts accepts
//!   `()` alone. Leaf
//!   implementations exist for [`StackCipherText`] (the AEAD ciphertext, via
//!   vitaminc's [`Encrypt`]) and for the SEM term types in [`sem`]
//!   ([`EqualityTerm`], [`MatchTerm`], [`OreTerm`], [`OpeTerm`]). Composite
//!   record types — a struct of leaves, or a row of records — get theirs from
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
//!   [`encrypt_into(&cipher)`](EncryptInto::encrypt_into) for an output that
//!   needs no context from the caller, and
//!   [`encrypt_into_with_context(&cipher, ctx)`](EncryptInto::encrypt_into_with_context)
//!   for one that does — the split of vitaminc's `encrypt` /
//!   `encrypt_with_aad`, decided by the output type at compile time. Never
//!   implemented by hand.
//! * [`EncryptTarget`] / [`DecryptTarget`] — implemented by ciphers; their
//!   `Output` type decides what a call site gets back. A synchronous cipher
//!   returns `Result<T, E>` directly; [`StackCipher`] returns a [`Pending`],
//!   which does its ZeroKMS I/O — **one batched call** — when awaited.
//! * [`EncryptContext`] — one context value per field, convertible to both an
//!   AEAD [`Aad`] and a
//!   [`PrfContext`](vitaminc_prf::PrfContext), so the same identifier that
//!   domain-separates the index terms also *authenticates* the ciphertext.
//!   `&str` and `String` qualify. [`SuppliedContext`] marks the ones a
//!   caller actually passed — everything but `()` — and is what a leaf
//!   demands; the context must also be **non-empty**.
//!
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
//! use stack_encrypt::{StackCipher, StackCipherText};
//! use stack_kms::FakeDataKeySource;
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let cipher = StackCipher::builder()
//!     .kms(FakeDataKeySource::new())
//!     .init()
//!     .await
//!     .unwrap();
//!
//! let ages: Vec<u32> = vec![29, 34, 41];
//!
//! // A column of independently sealed ciphertexts: ONE generate_keys call.
//! let sealed: Vec<StackCipherText> = ages
//!     .encrypt_into_with_context(&cipher, "users/age")
//!     .await?;
//!
//! // And back: ONE retrieve_keys call for the whole column.
//! let roundtrip: Vec<u32> = sealed.decrypt_into(&cipher, "users/age").await?;
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
//! [`EncryptFrom`] for it against [`StackCipher`], build the result with
//! [`Pending::ready`] (local derivation) or [`Pending::request`] (derivation
//! needing ZeroKMS responses). Every built-in term type is implemented with
//! **exactly** this recipe — they use no privileged access — so [`sem`]
//! doubles as worked examples.
//!
//! The one thing every searchable-encryption scheme needs is a keyed,
//! deterministic derivation — the cipher's PRF. Under the local HMAC backend
//! the PRF completes synchronously (`into_result`), so the pending carries no
//! requests; a future 2-party ZeroKMS PRF backend moves the same visitor
//! behind a PRF request instead, joining the record's one batched call.
//!
//! ```
//! use stack_encrypt::target::{
//!     is_degenerate_prf_context, DecryptField, DecryptTarget, Decryptable, EncryptContext,
//!     EncryptFrom, Pending, SuppliedContext,
//! };
//! use stack_encrypt::{Error, StackCipher};
//! use vitaminc_prf::{IntoPrfContext, PrfContext, PrfValue, PrfVisitor, PrfVisitorError};
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
//! // A leaf owns the context policy, and states it in the impl header:
//! // `SuppliedContext` refuses `()` at compile time (nothing above a leaf
//! // checks, since a column of rows has no context of its own). The
//! // lifetime is the context's own, as in the `IntoAad<'c>` it implements.
//! impl<'c, S, K, Ctx> EncryptFrom<S, StackCipher<K>, Ctx> for MyTerm
//! where
//!     S: PrfValue + Clone,
//!     Ctx: EncryptContext<'c> + SuppliedContext<'c>,
//! {
//!     fn encrypt_from<'a>(
//!         source: &'a S,
//!         cipher: &'a StackCipher<K>,
//!         context: Ctx,
//!     ) -> Pending<'a, Self, K>
//!     where
//!         Self: 'a,
//!     {
//!         // The type rules out an absent context; an empty one is still a
//!         // runtime check, the same one the built-in leaves make (the
//!         // encoding is framed, so `as_bytes().is_empty()` would never be
//!         // true). Then domain-separate under your own label so your terms
//!         // can never collide with another scheme's under the same context.
//!         let context = context.into_prf_context().into_owned();
//!         if is_degenerate_prf_context(context.as_bytes()) {
//!             return Pending::ready(cipher, Err(Error::EmptyContext));
//!         }
//!         let context = PrfContext::pae(&[b"my-crate/my-term/v1".as_slice(), context.as_bytes()]);
//!         let term = source
//!             .clone()
//!             .prf_visit_with_context(cipher.prf().clone(), context, MyVisitor)
//!             .into_result()
//!             .map_err(|e| Error::Other(Box::new(e)));
//!         Pending::ready(cipher, term)
//!     }
//! }
//!
//! // A term is one-way. Saying so is what lets `#[derive(DecryptInto)]`
//! // pass over a `MyTerm` field and open the ciphertext beside it.
//! impl Decryptable for MyTerm {
//!     const DECRYPTABLE: bool = false;
//! }
//!
//! impl<P, C: DecryptTarget, Ctx> DecryptField<P, C, Ctx> for MyTerm {
//!     fn decrypt_field<'a>(self, _: &'a C, _: Ctx) -> Option<C::Output<'a, P>>
//!     where
//!         Self: 'a,
//!         P: 'a,
//!     {
//!         None
//!     }
//! }
//! ```
//!
//! A third-party *ciphertext* type implements `DecryptInto` as well, sets
//! `DECRYPTABLE` to `true`, and has `decrypt_field` return
//! `Some(self.decrypt_into(cipher, context))`.
//!
//! A scheme needing state the cipher does not carry defines its own
//! capability trait and implements it for [`StackCipher`] (a local trait on a
//! foreign type is orphan-rule-legal) using its public accessors
//! ([`keyset_id`](StackCipher::keyset_id), [`prf`](StackCipher::prf),
//! [`kms`](StackCipher::kms)).
//!
//! **Not yet here:** the `ore_rs` *block* ORE scheme (`OreBlock256`) that EQL
//! and `cipherstash-client` use. The ORE/OPE terms in [`sem`] are CLLW, a
//! different construction; the block scheme lands as a third-party term type
//! in `eql-bindings`, built with exactly the recipe above.
//!
//! # Records and rows: `#[derive(EncryptFrom)]`
//!
//! A struct of leaves is a *record*; a struct of records, each derived from
//! one field of the source under its own column context, is a *row*. Both
//! are the same derive, and both settle as one batched call:
//!
//! ```
//! use stack_encrypt::sem::{EqualityTerm, OreTerm};
//! use stack_encrypt::target::{DecryptFrom, EncryptInto};
//! use stack_encrypt::{DecryptInto, EncryptFrom, StackCipher, StackCipherText};
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
//! #[derive(EncryptFrom, DecryptInto)]
//! #[stash(plaintext = User)]
//! struct EncryptedUser {
//!     #[stash(from = age, context = "users/age")]
//!     age: EncryptedAge,
//!     #[stash(from = email, context = "users/email")]
//!     email: StackCipherText,
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let cipher = StackCipher::builder()
//!     .kms(FakeDataKeySource::new())
//!     .init()
//!     .await
//!     .unwrap();
//!
//! let user = User { age: 42, email: "alice@example.com".into() };
//! // Every field names its own context, so the row needs none from the
//! // caller — and the context-free forms are the only ones that apply.
//! let row: EncryptedUser = user.encrypt_into(&cipher).await?;
//! // A query site derives the same term under the same literal.
//! let probe: EqualityTerm = 42u32
//!     .encrypt_into_with_context(&cipher, "users/age")
//!     .await?;
//! assert_eq!(row.age.hm, probe);
//!
//! let recovered = User::decrypt_from(row, &cipher).await?;
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

use std::borrow::Cow;

use stack_kms::MaybeSend;
use vitaminc_aead::{Aad, CipherText, Decrypt, Encrypt, IntoAad};
use vitaminc_prf::IntoPrfContext;

use crate::cipher::{bind_keys, PendingStackCipherText, StackDecipher};
use crate::{Error, StackCipher, StackCipherText};

mod pending;
mod request;

pub use pending::{Pending, PendingFuture};
pub use request::{Request, Responses};
pub use stack_encrypt_derive::{DecryptInto, EncryptFrom};

// =============================================================================
// Contexts
// =============================================================================

/// Per-field encryption context: one value that domain-separates every
/// primitive a record field can use — it becomes the AEAD associated data of
/// the ciphertext *and* the PRF context of any index term.
///
/// Blanket-implemented; never implement it directly. `&str` and `String`
/// qualify. `Clone` is required because one context fans out to every field
/// of a record.
///
/// The context must be **non-empty**: with an empty context, equal plaintexts
/// in different fields produce identical index terms (cross-field equality
/// leakage), every field shares one ORE/OPE key (values become mutually
/// order-comparable), and ciphertexts become transplantable between fields.
/// That is enforced in two layers. An *absent* context — `()`, what
/// [`encrypt_into`](EncryptInto::encrypt_into) passes — is refused by the
/// type: every leaf demands a [`SuppliedContext`], and containers (`Vec`,
/// `Option`) and derived records pass that demand through to their elements
/// and fields untouched, so only a record whose fields all carry contexts of
/// their own — a [`#[derive(EncryptFrom)]`](macro@EncryptFrom) row — accepts
/// `()`. An *empty* one — `""`, `b""`, `None`, `Some("")`, `("", "")`,
/// anything that encodes to nothing but vitaminc framing — is refused by
/// every built-in leaf during the synchronous build, before any I/O
/// ([`Error::EmptyContext`]). That check is structural over the PAE encoding
/// vitaminc uses, so a nested empty context cannot hide behind an `Option`
/// or tuple wrapper. (An integer context whose bytes coincide with an empty
/// encoding — `0u64` — is rejected too: it is byte-identical to `None`.)
pub trait EncryptContext<'a>: IntoAad<'a> + IntoPrfContext<'a> + Clone {}

impl<'a, T> EncryptContext<'a> for T where T: IntoAad<'a> + IntoPrfContext<'a> + Clone {}

/// Per-field decryption context: must convert to the AEAD associated data the
/// value was encrypted under. Decryption derives nothing, so no PRF bound.
/// Blanket-implemented; `&str`, `String` and [`Aad`]
/// qualify.
///
/// This is the bound [`#[derive(DecryptInto)]`](macro@DecryptInto) places on
/// a record's caller-supplied decrypt context, and the supertrait of
/// [`SuppliedContext`]. It holds even when only term fields would see the
/// caller's context — a term opens nothing and would accept anything, so
/// without it a record whose ciphertext field carries a literal would take,
/// and silently discard, a value that is not a context at all:
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
///     // `42u8` is not a context (no `IntoAad`): a compile error, not a
///     // value the term fields quietly swallow.
///     let _: u32 = rec.decrypt_into(cipher, 42u8).await.unwrap();
/// }
/// ```
pub trait DecryptContext<'a>: IntoAad<'a> + Clone {}

impl<'a, T> DecryptContext<'a> for T where T: IntoAad<'a> + Clone {}

/// A context the caller actually passed, as opposed to `()` — the absence of
/// one.
///
/// This is what lets an output type decide, at compile time, whether the
/// call site owes it a context. The leaves ([`StackCipherText`], the
/// [`sem`](crate::sem) terms) implement [`EncryptFrom`] and [`DecryptInto`]
/// only for a `SuppliedContext`, so `value.encrypt_into(&cipher)` — which
/// passes `()` — does not compile against them, nor against a record that
/// hands its context on to one of them. A row whose fields each carry a
/// context of their own never passes the caller's anywhere: it implements
/// the traits for `()` alone, and is encrypted with no context at all.
///
/// Implemented for every context type vitaminc provides except `()` — and
/// except a composite that contains `()`, such as `("users/email", ())` or
/// `Option<()>`, whose `()` half adds no domain separation: `&str`,
/// `String`, byte strings, [`Aad`], `u64`, and `Option`s
/// and pairs of those. A context type of your own opts in with an empty
/// `impl SuppliedContext<'_> for MyContext {}` alongside its `IntoAad` /
/// `IntoPrfContext`; without it the leaves refuse the type.
///
/// The marker is about the *type*: `""` is a `&str` and therefore supplied.
/// Whether what was supplied is non-empty stays a runtime check at the leaf
/// ([`Error::EmptyContext`]) until vitaminc carries non-emptiness in the
/// type itself (cipherstash/vitaminc#291), at which point the bound tightens
/// to that.
///
/// [`DecryptContext`] (the same `IntoAad + Clone`) is a supertrait, so the
/// implication holds by construction and a decrypt leaf bounds its context
/// by this marker alone.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a context the caller supplied",
    label = "this leaf needs a context",
    note = "`()` is what `encrypt_into` / `decrypt_from` pass, and what a derived row hands a \
            `from` field with no `context = \"..\"` of its own: an output that reaches a leaf \
            needs `encrypt_into_with_context` / `decrypt_from_with_context`, or the literal",
    note = "a context type of your own opts in with an empty `impl SuppliedContext<'_> for MyContext {{}}`"
)]
pub trait SuppliedContext<'a>: DecryptContext<'a> {}

impl<'a> SuppliedContext<'a> for &'a str {}
impl SuppliedContext<'_> for String {}
impl<'a> SuppliedContext<'a> for &'a [u8] {}
impl<'a, const N: usize> SuppliedContext<'a> for &'a [u8; N] {}
impl<const N: usize> SuppliedContext<'_> for [u8; N] {}
impl SuppliedContext<'_> for Vec<u8> {}
impl<'a> SuppliedContext<'a> for Cow<'a, [u8]> {}
impl<'a> SuppliedContext<'a> for Aad<'a> {}
impl SuppliedContext<'_> for u64 {}
impl<'a, T: SuppliedContext<'a>> SuppliedContext<'a> for Option<T> {}
impl<'a, A: SuppliedContext<'a>, B: SuppliedContext<'a>> SuppliedContext<'a> for (A, B) {}

// The two checks below reconstruct, at runtime and from the outside, an
// invariant that should be carried by the type: "this context was built
// from something the caller supplied". Doing it this way means parsing an
// encoding we do not own, mirroring constants that are private upstream,
// and re-deriving the answer on every encrypt.
//
// It works, and the tests pin it — but the shape of it is a symptom, not a
// design. cipherstash/vitaminc#291 tracks the type-level replacement (a
// non-empty context that checks once at construction, without giving up the
// plain-string call site). When that lands, this module, both predicates and
// `Error::EmptyContext` all go away, and the `EncryptContext` bound tightens
// to the upstream marker instead.
//
// This code stays as it is until then: the check is correct, just weaker and
// more fragile than an invariant would be. The prefix-versus-position bug the
// review found here is exactly the fragility being described.

/// The framing tags vitaminc's PRF context encoding inserts, each of which
/// occupies **piece 0** of the PAE node it labels. Matched exactly and only
/// in that position — a prefix test would classify any caller string
/// beginning `vitaminc/` as framing (`Some("vitaminc/customer")` would read
/// as empty), which is the opposite of what this check is for.
///
/// # Why these exist at all
///
/// They are mirrored from `vitaminc_prf::context`, where they are private,
/// and nothing about the *check* requires them. They are a consequence of
/// *where* the check runs:
///
/// 1. [`EncryptContext`] is a blanket bound over vitaminc's `IntoAad +
///    IntoPrfContext`, so inside `encrypt_from` the context is an opaque
///    generic. The only thing this crate can do with it is encode it.
/// 2. The encoding is framed: `"".into_prf_context()` is
///    `pae([context-value, utf8-label, ""])`, not zero bytes. Seeing whether
///    the *value* is empty means parsing past the tags.
/// 3. Parsing past the tags means knowing which pieces are tags.
///
/// So the crate ends up parsing an encoding it does not own, restating
/// constants it cannot import, and re-deriving on every encrypt an answer
/// that was knowable once, at construction. If vitaminc renames a domain
/// these literals drift silently: the byte pins still pass and the check
/// quietly starts admitting empties.
///
/// That is the case for <https://github.com/cipherstash/vitaminc/issues/291>:
/// a context that carries non-emptiness in its type, checked once where it
/// is built. When it lands, this module, both predicates below and
/// [`Error::EmptyContext`] are deleted and the [`EncryptContext`] bound
/// tightens to the upstream marker. Until then the literals are pinned by
/// `context_tests`, which build every shape through the public API rather
/// than asserting the strings.
mod prf_framing {
    /// `pae([CONTEXT_VALUE, <encoding label>, value])` — a typed leaf.
    pub(super) const CONTEXT_VALUE: &[u8] = b"vitaminc/prf/context-value/v1";
    /// `pae([OPTION_SOME, inner])`.
    pub(super) const OPTION_SOME: &[u8] = b"vitaminc/prf/option-some/v1";
    /// `pae([MAP_ENTRY, base, key])` — `key` is raw caller bytes.
    pub(super) const MAP_ENTRY: &[u8] = b"vitaminc/prf/map-entry/v1";
    /// `pae([REFINE, base, component])` — both are encoded contexts.
    pub(super) const REFINE: &[u8] = b"vitaminc/prf/refine/v1";
}

/// Do encoded **AAD** bytes carry no caller-supplied information? See
/// [`EncryptContext`] for what that means and why it is rejected.
///
/// The AAD channel carries no framing tags of its own: a leaf is its own raw
/// bytes (`"x".into_aad() == b"x"`), and `None`, `Some(_)` and tuples are
/// bare PAE nodes. So the rule is purely structural — degenerate if empty, or
/// if it parses as a PAE (`LE64(count) || (LE64(len) || piece)*`) whose every
/// piece is itself degenerate. Bytes that are not a well-formed PAE are
/// caller content and count as information.
///
/// Covers `()`, `""`, `b""`, `None` (`pae([])`), `Some(<empty>)` and tuples
/// of empties at any nesting depth — and `0u64`, whose eight zero bytes are
/// byte-identical to `pae([])`.
///
/// (The tags vitaminc applies *inside* the cipher — `Aad::for_leaf`,
/// `for_map_entry`, the markers — are derived after this check runs, from
/// the caller-visible AAD this sees.)
///
/// **Transitional.** Public only so a third-party leaf can make the same
/// runtime check the built-ins make (the recipe in the
/// [module docs](self#extending-with-your-own-sem-type)). When
/// [vitaminc#291](https://github.com/cipherstash/vitaminc/issues/291) carries
/// non-emptiness in the context type, both predicates and
/// [`Error::EmptyContext`] are **deleted**, not deprecated — do not build on
/// them beyond that recipe.
pub fn is_degenerate_aad(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    match parse_pae(bytes) {
        Some(pieces) => pieces.iter().all(|piece| is_degenerate_aad(piece)),
        None => false,
    }
}

/// Do encoded **PRF context** bytes carry no caller-supplied information?
///
/// Unlike the AAD channel, every caller value here is wrapped in a framing
/// node — `"x".into_prf_context()` is `pae([CONTEXT_VALUE, <utf8 label>,
/// b"x"])` — so the check has to see past the framing to reach the value.
/// Framing is recognised by exact tag *and* arity at piece 0, and the
/// recursion descends only into the positions that actually hold caller
/// data. That is what keeps caller bytes from ever being mistaken for a tag:
/// caller data never lands at piece 0 of a framing node, because it is always
/// wrapped one level deeper.
///
/// A node that is not framing (a tuple, or a `PrfContext` the caller built by
/// hand) is degenerate only if every one of its pieces is. Bytes that are not
/// a well-formed PAE are caller content.
///
/// **Transitional**, on the same terms as [`is_degenerate_aad`]: deleted,
/// not deprecated, when
/// [vitaminc#291](https://github.com/cipherstash/vitaminc/issues/291) lands.
pub fn is_degenerate_prf_context(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let Some(pieces) = parse_pae(bytes) else {
        return false;
    };
    match (pieces.first(), pieces.len()) {
        // The value is raw caller bytes, not a nested context: judge it
        // structurally. This is what still rejects `0u64` — eight zero bytes
        // are byte-identical to `pae([])`.
        (Some(&tag), 3) if tag == prf_framing::CONTEXT_VALUE => is_degenerate_aad(pieces[2]),
        (Some(&tag), 2) if tag == prf_framing::OPTION_SOME => is_degenerate_prf_context(pieces[1]),
        (Some(&tag), 3) if tag == prf_framing::MAP_ENTRY => {
            is_degenerate_prf_context(pieces[1]) && pieces[2].is_empty()
        }
        (Some(&tag), 3) if tag == prf_framing::REFINE => {
            is_degenerate_prf_context(pieces[1]) && is_degenerate_prf_context(pieces[2])
        }
        _ => pieces.iter().all(|piece| is_degenerate_prf_context(piece)),
    }
}

/// Parse `bytes` as exactly one PAE encoding: `LE64(count)` then `count`
/// `LE64(len) || piece` frames, consuming every byte. `None` if the bytes are
/// not that shape.
fn parse_pae(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    fn le64(bytes: &[u8]) -> Option<(usize, &[u8])> {
        let (head, rest) = bytes.split_first_chunk::<8>()?;
        let n = usize::try_from(u64::from_le_bytes(*head)).ok()?;
        Some((n, rest))
    }
    let (count, mut rest) = le64(bytes)?;
    let mut pieces = Vec::with_capacity(count.min(16));
    for _ in 0..count {
        let (len, after_len) = le64(rest)?;
        if after_len.len() < len {
            return None;
        }
        let (piece, tail) = after_len.split_at(len);
        pieces.push(piece);
        rest = tail;
    }
    rest.is_empty().then_some(pieces)
}

// =============================================================================
// Cipher-owned output types
// =============================================================================

/// Implemented by ciphers: decides what an [`EncryptFrom`] implementation
/// hands back. A cipher that does no I/O sets
/// `Output<'a, T> = Result<T, Self::Error>` — no future, no `.await`.
/// [`StackCipher`] sets `Output<'a, T> = Pending<'a, T, K>`, a request
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

impl<K> EncryptTarget for StackCipher<K> {
    type Error = Error;
    type Output<'a, T>
        = Pending<'a, T, K>
    where
        Self: 'a,
        T: 'a;
}

impl<K> DecryptTarget for StackCipher<K> {
    type Error = Error;
    type Output<'a, T>
        = Pending<'a, T, K>
    where
        Self: 'a,
        T: 'a;
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
/// implementation can say which contexts it accepts: a leaf demands a
/// [`SuppliedContext`] (it has nothing else to authenticate under), a record
/// passes whatever it is given on to its fields and inherits their demands
/// through its where clause, and a row whose fields carry their own contexts
/// is implemented for `()` alone — a context handed to it would go nowhere.
/// The call site then gets one of two answers from the compiler:
/// [`encrypt_into(&cipher)`](EncryptInto::encrypt_into) resolves against
/// `EncryptFrom<S, C, ()>` and exists exactly for the outputs that need no
/// context; everything else takes
/// [`encrypt_into_with_context`](EncryptInto::encrypt_into_with_context).
///
/// The trait itself places no bound on `Ctx`; an implementation that uses the
/// context bounds it as [`EncryptContext<'c>`] with the context's own
/// lifetime as an impl parameter (see the
/// [module docs](self#extending-with-your-own-sem-type)).
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not an encrypted form of `{S}` under a `{Ctx}` context",
    label = "not `EncryptFrom<{S}, _, {Ctx}>`",
    note = "an output that reaches a leaf exists only under a supplied context \
            (`encrypt_into_with_context`); one whose fields carry their own, only under `()` \
            (`encrypt_into`)"
)]
pub trait EncryptFrom<S, C: EncryptTarget, Ctx>: Sized {
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
/// leaves accept only a [`SuppliedContext`], so an encrypted type that needs
/// no context from the caller is exactly one that implements
/// `DecryptInto<P, C, ()>` — what [`DecryptFrom::decrypt_from`] asks for.
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not decrypt to `{P}` under a `{Ctx}` context",
    label = "not `DecryptInto<{P}, _, {Ctx}>`",
    note = "a value that reaches a leaf decrypts only under the context it was encrypted under \
            (`decrypt_into(&cipher, context)` / `decrypt_from_with_context`); one whose fields \
            carry their own, only under `()` (`decrypt_from`)"
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
/// the binding. Which of the two methods applies is not a choice: a leaf, or
/// a record that hands the caller's context to one, exists only under a
/// [`SuppliedContext`] and takes the second; a row whose fields name their
/// own contexts needs nothing from the caller and takes the first. The
/// split is vitaminc's `encrypt` / `encrypt_with_aad`, decided by the type.
///
/// ```
/// use stack_encrypt::sem::EqualityTerm;
/// use stack_encrypt::target::EncryptInto;
/// use stack_encrypt::StackCipher;
/// use stack_kms::FakeDataKeySource;
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// let cipher = StackCipher::builder()
///     .kms(FakeDataKeySource::new())
///     .init()
///     .await
///     .unwrap();
///
/// let term: EqualityTerm = "alice"
///     .encrypt_into_with_context(&cipher, "users/email")
///     .await?;
/// # Ok::<(), stack_encrypt::Error>(())
/// # }).unwrap();
/// ```
pub trait EncryptInto {
    /// Encrypt `self` into a `T` that needs no context from the caller —
    /// a row whose fields carry their own. See [`EncryptFrom`].
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
    /// The context must be one the caller actually supplies
    /// ([`SuppliedContext`]): passing `()` here, or a supplied context to an
    /// output that takes none — a row — is a compile error either way, with
    /// [`encrypt_into`](Self::encrypt_into) as the answer to both.
    fn encrypt_into_with_context<'a, 'c, T, C, Ctx>(
        &'a self,
        cipher: &'a C,
        context: Ctx,
    ) -> C::Output<'a, T>
    where
        C: EncryptTarget,
        T: EncryptFrom<Self, C, Ctx> + 'a,
        Ctx: SuppliedContext<'c>,
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

    fn encrypt_into_with_context<'a, 'c, T, C, Ctx>(
        &'a self,
        cipher: &'a C,
        context: Ctx,
    ) -> C::Output<'a, T>
    where
        C: EncryptTarget,
        T: EncryptFrom<Self, C, Ctx> + 'a,
        Ctx: SuppliedContext<'c>,
    {
        T::encrypt_from(self, cipher, context)
    }
}

/// Call-site sugar: `Plaintext::decrypt_from(encrypted, &cipher)` and
/// `Plaintext::decrypt_from_with_context(encrypted, &cipher, context)` — the
/// `From` to [`DecryptInto`]'s `Into`, and the decrypt-side [`EncryptInto`],
/// with the same two forms for the same reason. Blanket-implemented for every
/// plaintext; never implemented by hand.
///
/// (The implemented trait, [`DecryptInto`], always takes a context:
/// `encrypted.decrypt_into(&cipher, "users/age")` is the method-call form
/// for a value that needs one.)
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
    /// The context must be one the caller actually supplies
    /// ([`SuppliedContext`]): passing `()` here, or a supplied context to an
    /// encrypted type that takes none — a row — is a compile error either
    /// way, with [`decrypt_from`](Self::decrypt_from) as the answer to both.
    fn decrypt_from_with_context<'a, 'c, S, C, Ctx>(
        source: S,
        cipher: &'a C,
        context: Ctx,
    ) -> C::Output<'a, Self>
    where
        C: DecryptTarget,
        S: DecryptInto<Self, C, Ctx> + 'a,
        Ctx: SuppliedContext<'c>,
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

    fn decrypt_from_with_context<'a, 'c, S, C, Ctx>(
        source: S,
        cipher: &'a C,
        context: Ctx,
    ) -> C::Output<'a, Self>
    where
        C: DecryptTarget,
        S: DecryptInto<Self, C, Ctx> + 'a,
        Ctx: SuppliedContext<'c>,
        Self: 'a,
    {
        source.decrypt_into(cipher, context)
    }
}

/// Whether a type is a ciphertext that decryption opens, or an index term
/// that it passes over.
///
/// Every type that can be a field of a derived record implements this —
/// it is what lets `#[derive(DecryptInto)]` find the ciphertext field on its
/// own, with no attribute: the derive counts the fields whose
/// [`DECRYPTABLE`](Self::DECRYPTABLE) is `true` and requires exactly one
/// (per plaintext field, for a row). `#[derive(EncryptFrom)]` emits it for
/// a record — a record is decryptable if any of its fields is, or outright
/// when `#[stash(decrypt)]` names the opened fields — and the
/// built-in leaves implement it by hand: [`StackCipherText`] is, the
/// [`sem`](crate::sem) terms are not.
///
/// A third-party leaf implements it alongside [`EncryptFrom`], together
/// with [`DecryptField`]; see the
/// [module docs](self#extending-with-your-own-sem-type).
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
/// emit its `Decryptable` — must still be a field of a row in the explicit
/// mode.)
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

impl<P, C, Ctx> DecryptField<P, C, Ctx> for StackCipherText
where
    C: DecryptTarget,
    Self: DecryptInto<P, C, Ctx>,
{
    fn decrypt_field<'a>(self, cipher: &'a C, context: Ctx) -> Option<C::Output<'a, P>>
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
    Ctx: Clone,
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

/// The record ciphertext: any vitaminc [`Encrypt`] value, sealed by the
/// [`StackCipher`] under per-leaf ZeroKMS data keys. The context becomes the
/// AEAD associated data, binding the ciphertext to the field it was encrypted
/// for.
///
/// The build is synchronous: the value's `Encrypt` impl drives the cipher to
/// a pending tree (no I/O), and the returned [`Pending`] carries one
/// data-key request per leaf. Sealing happens in the fulfilment, key material
/// drawn in the same traversal order the tree was built in.
///
/// A leaf has nothing of its own to authenticate under, so it exists only
/// for a [`SuppliedContext`]: `()` is a compile error here.
impl<'c, S, K, Ctx> EncryptFrom<S, StackCipher<K>, Ctx> for StackCipherText
where
    S: Encrypt + Clone,
    Ctx: EncryptContext<'c> + SuppliedContext<'c>,
{
    fn encrypt_from<'a>(
        source: &'a S,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        let aad = context.into_aad().into_owned();
        // An empty context would leave the leaf AAD carrying only the key
        // tag, making ciphertexts transplantable between empty-context
        // fields — see `EncryptContext`.
        if is_degenerate_aad(aad.as_bytes()) {
            return Pending::failed(cipher, Error::EmptyContext);
        }
        match source.clone().encrypt_with_aad(cipher, aad) {
            Ok(tree) => seal_pending(cipher, tree),
            Err(_) => Pending::ready(cipher, Err(Error::Aead)),
        }
    }
}

/// Seal a pending tree: one [`Request::generate_data_key`] per keyed leaf,
/// keys drawn back in the same traversal order the tree was built in.
///
/// Both ways of encrypting go through here — the target-directed
/// `encrypt_into_with_context` into a [`StackCipherText`] above and the
/// cipher-directed
/// [`PendingStackCipherText::seal`] behind [`StackCipher::encrypt`] — so
/// there is one definition of how a tree is sealed and one path to ZeroKMS.
pub(crate) fn seal_pending<'a, K>(
    cipher: &'a StackCipher<K>,
    tree: PendingStackCipherText,
) -> Pending<'a, StackCipherText, K> {
    let requests = std::iter::repeat_with(Request::generate_data_key)
        .take(tree.key_count())
        .collect();
    Pending::request(cipher, requests, move |responses| {
        let mut keys = responses.drain_generated();
        tree.seal_with(&mut keys).map_err(Error::from)
    })
}

/// Bind retrieved keys onto a ciphertext: one [`Request::retrieve_data_key`]
/// per keyed leaf, keys zipped back on in the same depth-first order. The
/// decrypt twin of [`seal_pending`], and likewise the single path for both
/// `decrypt_into` and the cipher-directed [`StackCipher::decipher`].
pub(crate) fn decipher_pending<'a, K>(
    cipher: &'a StackCipher<K>,
    ciphertext: StackCipherText,
) -> Pending<'a, StackDecipher, K> {
    let requests = retrieve_requests(&ciphertext);
    Pending::request(cipher, requests, move |responses| {
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
impl<'c, T, K, Ctx> DecryptInto<T, StackCipher<K>, Ctx> for StackCipherText
where
    T: Decrypt<'static> + 'static,
    Ctx: SuppliedContext<'c>,
{
    fn decrypt_into<'a>(self, cipher: &'a StackCipher<K>, context: Ctx) -> Pending<'a, T, K>
    where
        Self: 'a,
        T: 'a,
    {
        let aad = context.into_aad().into_owned();
        // Symmetric with the encrypt side: the target layer never encrypts
        // under an empty context, so it never decrypts under one either.
        if is_degenerate_aad(aad.as_bytes()) {
            return Pending::failed(cipher, Error::EmptyContext);
        }
        let requests = retrieve_requests(&self);
        Pending::request(cipher, requests, move |responses| {
            let decipher = decipher_from_responses(self, responses)?;
            T::decrypt_with_aad(decipher, aad).map_err(Error::from)
        })
    }
}

/// One [`Request::retrieve_data_key`] per keyed leaf, in the same depth-first
/// order `bind_keys` will consume the responses.
fn retrieve_requests(ciphertext: &StackCipherText) -> Vec<Request> {
    let mut out = Vec::new();
    collect_retrieve_requests(ciphertext, &mut out);
    out
}

fn collect_retrieve_requests(ciphertext: &StackCipherText, out: &mut Vec<Request>) {
    match ciphertext {
        CipherText::Single(leaf)
        | CipherText::None(leaf)
        | CipherText::EmptySequence(leaf)
        | CipherText::EmptyMap(leaf) => {
            out.push(Request::retrieve_data_key(*leaf.iv(), leaf.tag().to_vec()));
        }
        CipherText::Sequence(items) => {
            for item in items {
                collect_retrieve_requests(item, out);
            }
        }
        CipherText::Map(entries) => {
            for (_, value) in entries {
                collect_retrieve_requests(value, out);
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
/// column of leaves needs a [`SuppliedContext`] because its leaves do, a
/// column of rows accepts `()` because its rows do. Neither is decided here,
/// and neither is an empty context, which the leaves reject the moment a
/// value reaches them.
impl<S, T, K, Ctx> EncryptFrom<Vec<S>, StackCipher<K>, Ctx> for Vec<T>
where
    T: EncryptFrom<S, StackCipher<K>, Ctx>,
    Ctx: Clone,
{
    fn encrypt_from<'a>(
        source: &'a Vec<S>,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        let items = source
            .iter()
            .map(|item| T::encrypt_from(item, cipher, context.clone()))
            .collect();
        Pending::all(cipher, items)
    }
}

/// The column decrypt mirror: one batched retrieve for every row.
impl<S, T, K, Ctx> DecryptInto<Vec<T>, StackCipher<K>, Ctx> for Vec<S>
where
    S: DecryptInto<T, StackCipher<K>, Ctx>,
    Ctx: Clone,
{
    fn decrypt_into<'a>(self, cipher: &'a StackCipher<K>, context: Ctx) -> Pending<'a, Vec<T>, K>
    where
        Self: 'a,
        Vec<T>: 'a,
    {
        let items = self
            .into_iter()
            .map(|item| item.decrypt_into(cipher, context.clone()))
            .collect();
        Pending::all(cipher, items)
    }
}

/// An optional field: `None` encrypts to `None` at the target layer (an
/// absent *record field*, carrying no requests). This is distinct from
/// `Option<S> → StackCipherText` via [`Encrypt`], which produces an
/// *authenticated* absence marker inside one ciphertext.
impl<S, T, K, Ctx> EncryptFrom<Option<S>, StackCipher<K>, Ctx> for Option<T>
where
    T: EncryptFrom<S, StackCipher<K>, Ctx> + MaybeSend,
{
    fn encrypt_from<'a>(
        source: &'a Option<S>,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        // `None` derives nothing and checks nothing: the context is the
        // leaf's to validate (see the `Vec` implementation above).
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

#[cfg(test)]
mod context_tests {
    use vitaminc_aead::{Aad, IntoAad};
    use vitaminc_prf::{IntoPrfContext, PrfContext};

    use super::{is_degenerate_aad, is_degenerate_prf_context};

    fn aad<'a>(ctx: impl IntoAad<'a>) -> bool {
        is_degenerate_aad(ctx.into_aad().as_bytes())
    }

    fn prf<'a>(ctx: impl IntoPrfContext<'a>) -> bool {
        is_degenerate_prf_context(ctx.into_prf_context().as_bytes())
    }

    #[test]
    fn empty_encodings_are_degenerate_on_both_channels() {
        assert!(aad(()));
        assert!(aad(""));
        assert!(aad(b"".as_slice()));
        assert!(aad(None::<&str>));
        assert!(aad(Some("")));
        assert!(aad(("", "")));
        assert!(aad(Some(None::<&str>)));
        assert!(aad((None::<&str>, Some(""))));

        assert!(prf(()));
        assert!(prf(""));
        assert!(prf(b"".as_slice()));
        assert!(prf(None::<&str>));
        assert!(prf(Some("")));
        assert!(prf(("", "")));
        assert!(prf(Some(None::<&str>)));
        assert!(prf(PrfContext::empty()));
        assert!(prf(PrfContext::pae(&[])));
    }

    #[test]
    fn contexts_carrying_information_are_not() {
        assert!(!aad("users/email"));
        assert!(!aad("x"));
        assert!(!aad(Some("users/email")));
        assert!(!aad(("users", "email")));
        assert!(!aad(("", "email")));
        assert!(!aad(Aad::from_slice(b"raw")));
        assert!(!aad(7u64));

        assert!(!prf("users/email"));
        assert!(!prf("x"));
        assert!(!prf(Some("users/email")));
        assert!(!prf(("users", "email")));
        assert!(!prf(("", "email")));
        assert!(!prf(7u64));
        assert!(!prf(PrfContext::from_slice(b"raw")));
    }

    /// Caller data that *looks* like vitaminc framing is still caller data.
    ///
    /// The tags are matched by exact value at piece 0 of a framing node, and
    /// caller data never lands there — on the PRF channel it is wrapped a
    /// level deeper by `CONTEXT_VALUE`, and the AAD channel has no tags at
    /// all. A prefix test over every piece got all of these wrong, rejecting
    /// a legitimate context as empty.
    #[test]
    fn caller_data_shaped_like_framing_still_carries_information() {
        for tag in [
            "vitaminc/customer",
            "vitaminc/",
            "vitaminc/prf/context-value/v1",
            "vitaminc/prf/option-some/v1",
            "vitaminc/prf/map-entry/v1",
            "vitaminc/prf/refine/v1",
            "vitaminc/prf/encoding/utf8/v1",
            "vitaminc/aead/leaf",
        ] {
            assert!(!aad(tag), "aad({tag:?})");
            assert!(!aad(Some(tag)), "aad(Some({tag:?}))");
            assert!(!aad((tag, "")), "aad(({tag:?}, \"\"))");
            assert!(!prf(tag), "prf({tag:?})");
            assert!(!prf(Some(tag)), "prf(Some({tag:?}))");
            assert!(!prf((tag, "")), "prf(({tag:?}, \"\"))");
        }
    }

    /// A hand-built `PrfContext` that impersonates a framing node is judged
    /// on the data it actually frames — the tag alone buys nothing.
    #[test]
    fn a_hand_built_framing_node_is_judged_on_its_payload() {
        let some =
            |inner: &[u8]| PrfContext::pae(&[b"vitaminc/prf/option-some/v1", inner]).into_owned();
        // Framing a real value: information.
        assert!(!prf(some("users/email".into_prf_context().as_bytes())));
        // Framing an empty value: still empty, and still rejected.
        assert!(prf(some("".into_prf_context().as_bytes())));
        // A bare tag with nothing under it is not a well-formed framing node
        // and is read as a one-piece PAE of caller bytes.
        assert!(!prf(PrfContext::pae(&[b"vitaminc/prf/option-some/v1"])));
    }

    /// The arity check matters: a node carrying the right tag but the wrong
    /// number of pieces is not that framing shape and is judged piecewise.
    #[test]
    fn a_framing_tag_with_the_wrong_arity_is_not_framing() {
        let wrong = PrfContext::pae(&[
            b"vitaminc/prf/context-value/v1",
            b"vitaminc/prf/encoding/utf8/v1",
            b"users",
            b"email",
        ]);
        assert!(!prf(wrong));
    }

    #[test]
    fn a_zero_u64_is_byte_identical_to_none_and_rejected_with_it() {
        assert_eq!(
            0u64.into_aad().as_bytes(),
            None::<&str>.into_aad().as_bytes()
        );
        assert!(aad(0u64));
    }

    #[test]
    fn a_truncated_or_overlong_pae_is_caller_content() {
        // Looks like a count of two but carries only one frame.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        assert!(!is_degenerate_aad(&bytes));
        // A well-formed empty PAE followed by a trailing byte.
        let mut bytes = 0u64.to_le_bytes().to_vec();
        bytes.push(0);
        assert!(!is_degenerate_aad(&bytes));
    }
}
