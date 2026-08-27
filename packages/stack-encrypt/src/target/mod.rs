//! Target-directed encryption: the *output* type decides what gets derived,
//! and the *cipher* decides the async shape.
//!
//! A stored encrypted value is rarely just a ciphertext — it is a record: the
//! AEAD ciphertext of the plaintext plus zero or more index terms derived from
//! the same plaintext by different primitives. [`EncryptedFrom`] puts that
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
//! * [`EncryptedFrom<S, C>`] — implemented by an *output* type: "`Self` is an
//!   encrypted representation of `S`, producible by a cipher `C`". Leaf
//!   implementations exist for [`StackCipherText`] (the AEAD ciphertext, via
//!   vitaminc's [`Encrypt`]) and for the SEM term types in [`sem`]
//!   ([`EqualityTerm`], [`MatchTerm`], [`OreTerm`], [`OpeTerm`]). Composite
//!   record types implement it by combining their fields' pendings with
//!   [`Pending::zip`] / [`Pending::map`].
//! * [`DecryptedFrom<S, C>`] — the mirror, implemented by the *plaintext*
//!   type: "`Self` is recoverable from the encrypted `S`". Only ciphertext
//!   fields participate — index terms are one-way by construction.
//! * [`EncryptExt::encrypt_into`] / [`DecryptExt::decrypt_into`] — blanket
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
//! use stack_encrypt::target::{DecryptExt, EncryptExt};
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
//! [`EncryptedFrom`] for it against [`StackCipher`], build the result with
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
//! use stack_encrypt::target::{EncryptContext, EncryptedFrom, Pending};
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
//! impl<S, K> EncryptedFrom<S, StackCipher<K>> for MyTerm
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

use crate::cipher::{bind_keys, StackDecipher};
use crate::{Error, StackCipher, StackCipherText};

mod pending;
mod request;

pub use pending::{Pending, PendingFuture};
pub use request::{Request, Responses};

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
/// Every built-in implementation rejects an empty context during the
/// synchronous build — before any I/O.
pub trait EncryptContext<'a>: IntoAad<'a> + IntoPrfContext<'a> + Clone {}

impl<'a, T> EncryptContext<'a> for T where T: IntoAad<'a> + IntoPrfContext<'a> + Clone {}

/// Per-field decryption context: must convert to the AEAD associated data the
/// value was encrypted under. Decryption derives nothing, so no PRF bound.
/// Blanket-implemented; `&str`, `String` and [`Aad`](vitaminc_aead::Aad)
/// qualify.
pub trait DecryptContext<'a>: IntoAad<'a> + Clone {}

impl<'a, T> DecryptContext<'a> for T where T: IntoAad<'a> + Clone {}

// =============================================================================
// Cipher-owned output types
// =============================================================================

/// Implemented by ciphers: decides what an [`EncryptedFrom`] implementation
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
pub trait EncryptedFrom<S, C: EncryptTarget>: Sized {
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
/// of [`EncryptedFrom`], implemented on the *plaintext* type.
///
/// Takes the source by value: decryption consumes the ciphertext, and index
/// terms (which have no plaintext to recover) simply do not participate.
pub trait DecryptedFrom<S, C: DecryptTarget>: Sized {
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
/// The `Into` to [`EncryptedFrom`]'s `From` — blanket-implemented for every
/// type, never implemented by hand. The target type is usually inferred from
/// the binding:
///
/// ```
/// use stack_encrypt::sem::EqualityTerm;
/// use stack_encrypt::target::EncryptExt;
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
pub trait EncryptExt {
    /// Encrypt `self` into `T` under `context`. See [`EncryptedFrom`].
    fn encrypt_into<'a, 'c, T, C, Ctx>(&'a self, cipher: &'a C, context: Ctx) -> C::Output<'a, T>
    where
        C: EncryptTarget,
        T: EncryptedFrom<Self, C> + 'a,
        Ctx: EncryptContext<'c>,
        Self: Sized;
}

impl<S> EncryptExt for S {
    fn encrypt_into<'a, 'c, T, C, Ctx>(&'a self, cipher: &'a C, context: Ctx) -> C::Output<'a, T>
    where
        C: EncryptTarget,
        T: EncryptedFrom<Self, C> + 'a,
        Ctx: EncryptContext<'c>,
    {
        T::encrypt_from(self, cipher, context)
    }
}

/// Call-site sugar: `encrypted.decrypt_into::<T>(&cipher, context)` — the
/// decrypt-side [`EncryptExt`]. Blanket-implemented; never implemented by
/// hand.
pub trait DecryptExt: Sized {
    /// Decrypt `self` into `T`, authenticating against `context`. See
    /// [`DecryptedFrom`].
    fn decrypt_into<'a, 'c, T, C, Ctx>(self, cipher: &'a C, context: Ctx) -> C::Output<'a, T>
    where
        C: DecryptTarget,
        T: DecryptedFrom<Self, C> + 'a,
        Ctx: DecryptContext<'c>,
        Self: 'a;
}

impl<S> DecryptExt for S {
    fn decrypt_into<'a, 'c, T, C, Ctx>(self, cipher: &'a C, context: Ctx) -> C::Output<'a, T>
    where
        C: DecryptTarget,
        T: DecryptedFrom<Self, C> + 'a,
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
impl<S, K> EncryptedFrom<S, StackCipher<K>> for StackCipherText
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
        if aad.as_bytes().is_empty() {
            return Pending::ready(cipher, Err(Error::EmptyContext));
        }
        let tree = match source.clone().encrypt_with_aad(cipher, aad) {
            Ok(tree) => tree,
            Err(_) => return Pending::ready(cipher, Err(Error::Aead)),
        };
        let count = tree.key_count();
        let requests = std::iter::repeat_with(Request::generate_data_key)
            .take(count)
            .collect();
        Pending::request(cipher, requests, move |responses| {
            let mut keys = responses.drain_generated();
            tree.seal_with(&mut keys).map_err(|_| Error::Aead)
        })
    }
}

/// The decrypt mirror: any vitaminc [`Decrypt`] value recovers from a
/// [`StackCipherText`]. The pending carries one retrieve request per leaf
/// (`iv` + `tag` are lifted out of the tree during the synchronous build);
/// the fulfilment binds the retrieved keys back onto the leaves and lets the
/// value's `Decrypt` impl drive the opening.
impl<T, K> DecryptedFrom<StackCipherText, StackCipher<K>> for T
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
        if aad.as_bytes().is_empty() {
            return Pending::ready(cipher, Err(Error::EmptyContext));
        }
        let mut requests = Vec::new();
        collect_retrieve_requests(&source, &mut requests);
        Pending::request(cipher, requests, move |responses| {
            let mut keys = responses.drain_retrieved();
            let keyed = bind_keys(source, &mut keys).map_err(|_| Error::Aead)?;
            drop(keys);
            T::decrypt_with_aad(StackDecipher::over(keyed), aad).map_err(Error::from)
        })
    }
}

/// One [`Request::retrieve_data_key`] per keyed leaf, in the same depth-first
/// order `bind_keys` will consume the responses.
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
impl<S, T, K> EncryptedFrom<Vec<S>, StackCipher<K>> for Vec<T>
where
    T: EncryptedFrom<S, StackCipher<K>>,
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
        let items = source
            .iter()
            .map(|item| T::encrypt_from(item, cipher, context.clone()))
            .collect();
        Pending::all(cipher, items)
    }
}

/// The column decrypt mirror: one batched retrieve for every row.
impl<S, T, K> DecryptedFrom<Vec<S>, StackCipher<K>> for Vec<T>
where
    T: DecryptedFrom<S, StackCipher<K>>,
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
impl<S, T, K> EncryptedFrom<Option<S>, StackCipher<K>> for Option<T>
where
    T: EncryptedFrom<S, StackCipher<K>> + MaybeSend,
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
        match source {
            Some(value) => T::encrypt_from(value, cipher, context).map(Some),
            None => Pending::ready(cipher, Ok(None)),
        }
    }
}

/// The optional decrypt mirror of the [`Option`] encrypt implementation.
impl<S, T, K> DecryptedFrom<Option<S>, StackCipher<K>> for Option<T>
where
    T: DecryptedFrom<S, StackCipher<K>> + MaybeSend,
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
