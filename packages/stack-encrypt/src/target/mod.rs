//! Target-directed encryption: the *output* type decides what gets derived,
//! and the *cipher* decides the async shape.
//!
//! A stored encrypted value is rarely just a ciphertext — it is a record: the
//! AEAD ciphertext of the plaintext plus zero or more index terms derived from
//! the same plaintext by different primitives. [`EncryptFrom`] puts that
//! record shape in charge:
//!
//! ```text
//! let term: EqualityTerm = value.encrypt_into(&cipher, "users/email").await?;
//! ```
//!
//! compiles only when `EqualityTerm` declares itself an encrypted form of the
//! value's type, producible by that cipher.
//!
//! # The pieces
//!
//! * [`EncryptFrom<S, C>`] — implemented by an *output* type: "`Self` is an
//!   encrypted representation of `S`, producible by a cipher `C`". Leaf
//!   implementations exist for [`StackCipherText`] (the AEAD ciphertext, via
//!   vitaminc's [`Encrypt`]) and for the SEM term types in [`sem`]
//!   ([`EqualityTerm`], [`MatchTerm`], [`OreTerm`], [`OpeTerm`]). Composite
//!   record types — a struct of leaves, or a row of records — get theirs from
//!   [`#[derive(Encrypted)]`](Encrypted), which combines the fields' pendings
//!   with [`Pending::zip`] / [`Pending::map`] exactly as a hand-written impl
//!   would.
//! * [`DecryptFrom<S, C>`] — the mirror, implemented by the *plaintext*
//!   type: "`Self` is recoverable from the encrypted `S`". Only ciphertext
//!   fields participate — index terms are one-way by construction.
//!   [`#[derive(DecryptFrom)]`](macro@DecryptFrom) on the record emits it for the
//!   record's named source type(s).
//! * [`EncryptInto::encrypt_into`] / [`DecryptInto::decrypt_into`] — blanket
//!   call-site sugar, the `Into` to the `From` above. Never implemented by
//!   hand.
//! * [`EncryptTarget`] / [`DecryptTarget`] — implemented by ciphers; their
//!   `Output` type decides what a call site gets back. A synchronous cipher
//!   returns `Result<T, E>` directly; [`StackCipher`] returns a [`Pending`],
//!   which does its ZeroKMS I/O — **one batched call** — when awaited.
//! * [`EncryptContext`] — one context value per field, convertible to both an
//!   AEAD [`Aad`](vitaminc_aead::Aad) and a
//!   [`PrfContext`](vitaminc_prf::PrfContext), so the same identifier that
//!   domain-separates the index terms also *authenticates* the ciphertext.
//!   `&str` and `String` qualify. The context must be **non-empty**.
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
//! let sealed: Vec<StackCipherText> = ages.encrypt_into(&cipher, "users/age").await?;
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
//! use stack_encrypt::target::{EncryptContext, EncryptFrom, Pending};
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
//! impl<S, K> EncryptFrom<S, StackCipher<K>> for MyTerm
//! where
//!     S: PrfValue + Clone,
//! {
//!     fn encrypt_from<'a, 'c, Ctx>(
//!         source: &'a S,
//!         cipher: &'a StackCipher<K>,
//!         context: Ctx,
//!     ) -> Pending<'a, Self, K>
//!     where
//!         Ctx: EncryptContext<'c>,
//!         Self: 'a,
//!     {
//!         // Domain-separate under your own label so your terms can never
//!         // collide with another scheme's under the same context.
//!         let context = context.into_prf_context().into_owned();
//!         let context = PrfContext::pae(&[b"my-crate/my-term/v1".as_slice(), context.as_bytes()]);
//!         let term = source
//!             .clone()
//!             .prf_visit_with_context(cipher.prf().clone(), context, MyVisitor)
//!             .into_result()
//!             .map_err(|e| Error::Other(Box::new(e)));
//!         Pending::ready(cipher, term)
//!     }
//! }
//! ```
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
//! # Records and rows: `#[derive(Encrypted)]`
//!
//! A struct of leaves is a *record*; a struct of records, each derived from
//! one field of the source under its own column context, is a *row*. Both
//! are the same derive, and both settle as one batched call:
//!
//! ```
//! use stack_encrypt::sem::{EqualityTerm, OreTerm};
//! use stack_encrypt::target::{DecryptInto, EncryptInto};
//! use stack_encrypt::{DecryptFrom, Encrypted, StackCipher, StackCipherText};
//! use stack_kms::FakeDataKeySource;
//!
//! /// An encrypted `u32`, queryable by equality and range.
//! #[derive(Encrypted, DecryptFrom)]
//! #[encrypted(source = u32)]
//! struct EncryptedAge {
//!     #[encrypted(decrypt)]
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
//! #[derive(Encrypted, DecryptFrom)]
//! #[encrypted(source = User)]
//! struct EncryptedUser {
//!     #[encrypted(from = age, context = "users/age", decrypt)]
//!     age: EncryptedAge,
//!     #[encrypted(from = email, context = "users/email", decrypt)]
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
//! // Every field names its own context, so the row has none: `()`.
//! let row: EncryptedUser = user.encrypt_into(&cipher, ()).await?;
//! // A query site derives the same term under the same literal.
//! let probe: EqualityTerm = 42u32.encrypt_into(&cipher, "users/age").await?;
//! assert_eq!(row.age.hm, probe);
//!
//! let recovered: User = row.decrypt_into(&cipher, ()).await?;
//! assert_eq!(recovered, user);
//! # Ok::<(), stack_encrypt::Error>(())
//! # }).unwrap();
//! ```
//!
//! The attributes, and what the derive commits to, are documented on
//! [`Encrypted`].
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
use vitaminc_prf::IntoPrfContext;

use crate::cipher::{bind_keys, PendingStackCipherText, StackDecipher};
use crate::{Error, StackCipher, StackCipherText};

mod pending;
mod request;

pub use pending::{Pending, PendingFuture};
pub use request::{Request, Responses};
pub use stack_encrypt_derive::{DecryptFrom, Encrypted};

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
/// Every leaf implementation rejects an empty context during the synchronous
/// build, before any I/O. Containers (`Vec`, `Option`) and derived records
/// pass the context through to their elements and fields untouched, so a
/// container of records whose fields carry their own contexts — a
/// [`Encrypted`]-derived row — is given `()`, and an empty context still
/// fails the moment a value reaches a leaf.
///
/// "Empty" means *carrying no caller-supplied information*, not merely zero
/// bytes: `()`, `""`, `b""`, `None`, `Some("")` and `("", "")` all encode to
/// nothing but vitaminc framing and are all rejected
/// ([`Error::EmptyContext`]). The check is structural over the PAE encoding
/// vitaminc uses, so a nested empty context cannot hide behind an `Option`
/// or tuple wrapper. (An integer context whose bytes coincide with an empty
/// encoding — `0u64` — is rejected too: it is byte-identical to `None`.)
pub trait EncryptContext<'a>: IntoAad<'a> + IntoPrfContext<'a> + Clone {}

impl<'a, T> EncryptContext<'a> for T where T: IntoAad<'a> + IntoPrfContext<'a> + Clone {}

/// Per-field decryption context: must convert to the AEAD associated data the
/// value was encrypted under. Decryption derives nothing, so no PRF bound.
/// Blanket-implemented; `&str`, `String` and [`Aad`](vitaminc_aead::Aad)
/// qualify.
pub trait DecryptContext<'a>: IntoAad<'a> + Clone {}

impl<'a, T> DecryptContext<'a> for T where T: IntoAad<'a> + Clone {}

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
pub(crate) fn is_degenerate_aad(bytes: &[u8]) -> bool {
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
pub(crate) fn is_degenerate_prf_context(bytes: &[u8]) -> bool {
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
pub trait EncryptFrom<S, C: EncryptTarget>: Sized {
    /// Encrypt `source` into `Self` under `context`, returning the cipher's
    /// [`Output`](EncryptTarget::Output). No I/O happens here; work needing
    /// ZeroKMS is carried as requests and settles when the output is awaited.
    ///
    /// Borrows the source because a composite record hands the same source to
    /// several field implementations; each takes what it needs (typically one
    /// clone).
    fn encrypt_from<'a, 'c, Ctx>(source: &'a S, cipher: &'a C, context: Ctx) -> C::Output<'a, Self>
    where
        Ctx: EncryptContext<'c>,
        Self: 'a;
}

/// `Self` is recoverable from the encrypted `S` by a cipher `C` — the mirror
/// of [`EncryptFrom`], implemented on the *plaintext* type.
///
/// Takes the source by value: decryption consumes the ciphertext, and index
/// terms (which have no plaintext to recover) simply do not participate.
pub trait DecryptFrom<S, C: DecryptTarget>: Sized {
    /// Decrypt `source` into `Self`, authenticating against `context` — which
    /// must match the context the value was encrypted under.
    fn decrypt_from<'a, 'c, Ctx>(source: S, cipher: &'a C, context: Ctx) -> C::Output<'a, Self>
    where
        Ctx: DecryptContext<'c>,
        S: 'a,
        Self: 'a;
}

/// Call-site sugar: `value.encrypt_into::<Target>(&cipher, context)`.
///
/// The `Into` to [`EncryptFrom`]'s `From` — blanket-implemented for every
/// type, never implemented by hand. The target type is usually inferred from
/// the binding:
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
/// let term: EqualityTerm = "alice".encrypt_into(&cipher, "users/email").await?;
/// # Ok::<(), stack_encrypt::Error>(())
/// # }).unwrap();
/// ```
pub trait EncryptInto {
    /// Encrypt `self` into `T` under `context`. See [`EncryptFrom`].
    fn encrypt_into<'a, 'c, T, C, Ctx>(&'a self, cipher: &'a C, context: Ctx) -> C::Output<'a, T>
    where
        C: EncryptTarget,
        T: EncryptFrom<Self, C> + 'a,
        Ctx: EncryptContext<'c>,
        Self: Sized;
}

impl<S> EncryptInto for S {
    fn encrypt_into<'a, 'c, T, C, Ctx>(&'a self, cipher: &'a C, context: Ctx) -> C::Output<'a, T>
    where
        C: EncryptTarget,
        T: EncryptFrom<Self, C> + 'a,
        Ctx: EncryptContext<'c>,
    {
        T::encrypt_from(self, cipher, context)
    }
}

/// Call-site sugar: `encrypted.decrypt_into::<T>(&cipher, context)` — the
/// decrypt-side [`EncryptInto`]. Blanket-implemented; never implemented by
/// hand.
pub trait DecryptInto: Sized {
    /// Decrypt `self` into `T`, authenticating against `context`. See
    /// [`DecryptFrom`].
    fn decrypt_into<'a, 'c, T, C, Ctx>(self, cipher: &'a C, context: Ctx) -> C::Output<'a, T>
    where
        C: DecryptTarget,
        T: DecryptFrom<Self, C> + 'a,
        Ctx: DecryptContext<'c>,
        Self: 'a;
}

impl<S> DecryptInto for S {
    fn decrypt_into<'a, 'c, T, C, Ctx>(self, cipher: &'a C, context: Ctx) -> C::Output<'a, T>
    where
        C: DecryptTarget,
        T: DecryptFrom<Self, C> + 'a,
        Ctx: DecryptContext<'c>,
        Self: 'a,
    {
        T::decrypt_from(self, cipher, context)
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
impl<S, K> EncryptFrom<S, StackCipher<K>> for StackCipherText
where
    S: Encrypt + Clone,
{
    fn encrypt_from<'a, 'c, Ctx>(
        source: &'a S,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Ctx: EncryptContext<'c>,
        Self: 'a,
    {
        let aad = context.into_aad().into_owned();
        // An empty context would leave the leaf AAD carrying only the key
        // tag, making ciphertexts transplantable between ()-context fields —
        // see `EncryptContext`.
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
/// `encrypt_into::<StackCipherText>` above and the cipher-directed
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
impl<T, K> DecryptFrom<StackCipherText, StackCipher<K>> for T
where
    T: Decrypt<'static> + 'static,
{
    fn decrypt_from<'a, 'c, Ctx>(
        source: StackCipherText,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Pending<'a, T, K>
    where
        Ctx: DecryptContext<'c>,
        StackCipherText: 'a,
        Self: 'a,
    {
        let aad = context.into_aad().into_owned();
        // Symmetric with the encrypt side: the target layer never encrypts
        // under an empty context, so it never decrypts under one either.
        if is_degenerate_aad(aad.as_bytes()) {
            return Pending::failed(cipher, Error::EmptyContext);
        }
        let requests = retrieve_requests(&source);
        Pending::request(cipher, requests, move |responses| {
            let decipher = decipher_from_responses(source, responses)?;
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
impl<S, T, K> EncryptFrom<Vec<S>, StackCipher<K>> for Vec<T>
where
    T: EncryptFrom<S, StackCipher<K>>,
{
    fn encrypt_from<'a, 'c, Ctx>(
        source: &'a Vec<S>,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Ctx: EncryptContext<'c>,
        Self: 'a,
    {
        // The context is passed through untouched, not validated here: a
        // column of records whose fields carry their own contexts (a derived
        // row) has none of its own, and the leaves reject an empty one the
        // moment a value reaches them.
        let items = source
            .iter()
            .map(|item| T::encrypt_from(item, cipher, context.clone()))
            .collect();
        Pending::all(cipher, items)
    }
}

/// The column decrypt mirror: one batched retrieve for every row.
impl<S, T, K> DecryptFrom<Vec<S>, StackCipher<K>> for Vec<T>
where
    T: DecryptFrom<S, StackCipher<K>>,
{
    fn decrypt_from<'a, 'c, Ctx>(
        source: Vec<S>,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Ctx: DecryptContext<'c>,
        S: 'a,
        Self: 'a,
    {
        let items = source
            .into_iter()
            .map(|item| T::decrypt_from(item, cipher, context.clone()))
            .collect();
        Pending::all(cipher, items)
    }
}

/// An optional field: `None` encrypts to `None` at the target layer (an
/// absent *record field*, carrying no requests). This is distinct from
/// `Option<S> → StackCipherText` via [`Encrypt`], which produces an
/// *authenticated* absence marker inside one ciphertext.
impl<S, T, K> EncryptFrom<Option<S>, StackCipher<K>> for Option<T>
where
    T: EncryptFrom<S, StackCipher<K>> + MaybeSend,
{
    fn encrypt_from<'a, 'c, Ctx>(
        source: &'a Option<S>,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Ctx: EncryptContext<'c>,
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
impl<S, T, K> DecryptFrom<Option<S>, StackCipher<K>> for Option<T>
where
    T: DecryptFrom<S, StackCipher<K>> + MaybeSend,
{
    fn decrypt_from<'a, 'c, Ctx>(
        source: Option<S>,
        cipher: &'a StackCipher<K>,
        context: Ctx,
    ) -> Pending<'a, Self, K>
    where
        Ctx: DecryptContext<'c>,
        S: 'a,
        Self: 'a,
    {
        match source {
            Some(value) => T::decrypt_from(value, cipher, context).map(Some),
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
