//! Searchable Encrypted Metadata (SEM) term types.
//!
//! Index terms are stored alongside a
//! [`StackCipherText`](crate::StackCipherText) so encrypted values can be
//! queried without decryption. Each term type implements
//! [`EncryptedFrom`], so the usual entry point is
//! target-directed:
//!
//! ```text
//! let term: EqualityTerm = value.encrypt_into(&cipher, "users/email").await?;
//! ```
//!
//! * [`EqualityTerm`] — a PRF of the whole value; exact-match queries.
//! * [`MatchTerm`] — the value is tokenized locally, each token is PRF'd, and
//!   the outputs fold into Bloom-filter bit positions; full-text match
//!   queries. Tokenizer/filter parameters are a *type-level* config
//!   ([`MatchConfig`]) so write-time and query-time terms agree by
//!   construction.
//! * [`OreTerm`] / [`OpeTerm`] — CLLW order-revealing / order-preserving
//!   ciphertexts produced *inside the PRF visitor* from a per-context key
//!   derived through the PRF; range queries.
//!
//! Every term type here is built on exactly one thing the cipher exposes
//! publicly — its PRF ([`StackCipher::prf`]) — with no privileged access, so
//! they double as worked examples for defining your own term types in another
//! crate (see [`target`](crate::target#extending-with-your-own-sem-type)).
//!
//! Alongside the target-directed path, the cipher carries descriptor-string
//! methods ([`StackCipher::equality_term`] and friends) for call sites that
//! want a single term rather than a whole record — query builders, mostly.
//! They derive no data keys, so building a probe never calls ZeroKMS.
//!
//! # PRF backends, visitors, and the 2-party future
//!
//! The PRF backend produces **blocks**; a [`PrfVisitor`] shapes blocks into
//! the term (`EqualityVisitor`, `BloomVisitor`, `OreVisitor`, `OpeVisitor` —
//! all private). The shaping is pure and synchronous by construction: only block
//! production can involve I/O, so a visitor never knows which side of a
//! round-trip it runs on. All pure work — context validation, option
//! validation, tokenization — happens *before* the PRF is invoked.
//!
//! The backend today is the local
//! [`HmacSha256Prf`] — keyed by the
//! deterministic per-keyset [`IndexKey`](stack_kms::IndexKey) from
//! [`stack_kms::IndexKeySource`] — so every derivation completes with no I/O
//! and an [`EncryptedFrom`] term carries **no requests** in its
//! [`Pending`]. The next ZeroKMS release adds 2-party PRF generation; under
//! that backend a term's `encrypt_from` pushes a PRF *request* instead and
//! runs the **same visitor** over the blocks the server returns — the shaping
//! code does not change, and terms then share the one batched ZeroKMS call
//! with the record's data keys. This is also why ORE/OPE *keys* are derived
//! through the PRF (from the field context, never the plaintext): under a
//! 2-party backend, per-field key derivation becomes a visible, auditable
//! ZeroKMS event while plaintext stays local.
//!
//! # Determinism and domain separation
//!
//! Index terms are deterministic by design — the same value under the same
//! context always yields the same term, which is what makes them queryable
//! (and is the usual SEM leakage trade-off: equal values are visibly equal).
//! Every term kind derives under its own PAE-encoded domain, bound to the
//! caller's context, so the same value indexed as an equality term, a match
//! token, or an ORE key can never produce colliding PRF outputs.
//!
//! This is a fresh (v2) term format: PRF inputs are framed with vitaminc's PAE
//! context encoding, so terms are intentionally **not** byte-compatible with
//! `cipherstash-client`'s existing `IndexTerm` values.

mod tokenize;

pub use tokenize::Tokenizer;

use std::fmt;
use std::marker::PhantomData;

use cllw_ore::{CllwOpeEncrypt, CllwOreEncrypt};
use vitaminc_hmac::HmacSha256Prf;
use vitaminc_prf::{
    BlockVisitor, IntoPrfContext, MapAccess, PrfContext, PrfError, PrfValue, PrfVisitor,
    PrfVisitorError, SeqAccess,
};
use zeroize::Zeroize;

use crate::target::{EncryptContext, EncryptedFrom, Pending};
use crate::{Error, StackCipher};

// The `/v1` suffix versions the *derivation* (domain + input framing), not the
// crate. Any change to the bytes a term derives from must bump it: a changed
// derivation under an unchanged domain makes every existing term silently
// unfindable, with no error to notice. The byte-level pins in
// `tests/term_bytes.rs` are what force that bump to be deliberate.

/// PAE domain for equality (exact-match) terms.
const EQUALITY_DOMAIN: &[u8] = b"stack-encrypt/sem/equality/v1";
/// PAE domain for match (full-text) token terms.
const MATCH_DOMAIN: &[u8] = b"stack-encrypt/sem/match/v1";
/// PAE domain for ORE key derivation.
const ORE_KEY_DOMAIN: &[u8] = b"stack-encrypt/sem/ore-key/v1";
/// PAE domain for OPE key derivation (distinct from ORE: OPE ciphertexts are
/// encrypt-only, so the two schemes must never share a key).
const OPE_KEY_DOMAIN: &[u8] = b"stack-encrypt/sem/ope-key/v1";

/// Errors from SEM term generation.
#[derive(Debug, thiserror::Error)]
pub enum TermError {
    /// The PRF backend failed (for a remote 2-party backend this includes
    /// transport errors).
    #[error("PRF failed: {0}")]
    Prf(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// CLLW ORE/OPE encryption failed.
    #[error("ORE/OPE encryption failed: {0}")]
    Ore(#[from] cllw_ore::Error),
    /// The supplied [`MatchOptions`] are invalid.
    #[error("invalid match options: {0}")]
    InvalidOptions(&'static str),
    /// The text produced no tokens under the configured tokenizer — empty or
    /// separator-only text, or (for n-grams, as in the v1 match indexer) text
    /// shorter than the n-gram length. Rejected at generation time for both
    /// the write and query paths: an empty term used as a query would
    /// vacuously match every stored row, and a sub-gram-length probe could
    /// never match anything (a silent false negative).
    #[error(
        "text produces no match tokens (empty, separator-only, or shorter than the n-gram length)"
    )]
    EmptyTermText,
    /// The encryption context (field descriptor) was empty. An empty context
    /// defeats per-field domain separation: equal plaintexts in different
    /// fields would produce identical terms, and every field would share one
    /// ORE/OPE key. See
    /// [`EncryptContext`].
    #[error("the encryption context must not be empty (it domain-separates fields)")]
    EmptyContext,
}

impl TermError {
    fn from_prf<E>(err: PrfError<E>) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Prf(Box::new(err))
    }
}

/// Reject an empty context before any derivation — see
/// [`TermError::EmptyContext`].
///
/// `()` (and `PrfContext::empty()`) produce literally empty context bytes; an
/// empty string or empty byte-slice context produces vitaminc's *typed*
/// framing around an empty payload. All are degenerate the same way — every
/// field using one shares a single derivation domain — so all are rejected.
fn require_context(context: &PrfContext<'_>) -> Result<(), TermError> {
    let bytes = context.as_bytes();
    if bytes.is_empty()
        || bytes == "".into_prf_context().as_bytes()
        || bytes == b"".as_slice().into_prf_context().as_bytes()
    {
        return Err(TermError::EmptyContext);
    }
    Ok(())
}

// =============================================================================
// Equality
// =============================================================================

/// An equality (exact-match) index term: one PRF block over the whole value.
///
/// Terms are pseudorandom under the index key; they are stored server-side and
/// are not secret key material.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EqualityTerm([u8; 32]);

impl EqualityTerm {
    /// Rebuild a term from stored bytes — the inverse of
    /// [`into_bytes`](Self::into_bytes), for terms persisted server-side.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<EqualityTerm> for Vec<u8> {
    fn from(term: EqualityTerm) -> Self {
        term.0.to_vec()
    }
}

/// A [`PrfVisitor`] that wraps one PRF block as an [`EqualityTerm`].
struct EqualityVisitor;

impl<P: Send + 'static> PrfVisitor<[u8; 32], P> for EqualityVisitor {
    type Value = EqualityTerm;

    fn visit_block(self, block: [u8; 32]) -> Result<Self::Value, PrfVisitorError> {
        Ok(EqualityTerm(block))
    }
}

/// Derive an equality term. Synchronous: the local HMAC backend does no I/O,
/// and the visitor does all the shaping (see the module docs — under a
/// deferred backend the same visitor runs after the round-trip instead).
fn equality<T>(
    prf: HmacSha256Prf,
    value: T,
    context: PrfContext<'_>,
) -> Result<EqualityTerm, TermError>
where
    T: PrfValue,
{
    require_context(&context)?;
    let context = PrfContext::pae(&[EQUALITY_DOMAIN, context.as_bytes()]);
    value
        .prf_visit_with_context(prf, context, EqualityVisitor)
        .into_result()
        .map_err(TermError::from_prf)
}

/// An equality term of any [`PrfValue`] source. Derived locally during the
/// synchronous build — the returned [`Pending`] carries no requests.
impl<S, K> EncryptedFrom<S, StackCipher<K>> for EqualityTerm
where
    S: PrfValue + Clone,
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
        let context = context.into_prf_context().into_owned();
        let term = equality(cipher.prf().clone(), source.clone(), context).map_err(Error::from);
        Pending::ready(cipher, term)
    }
}

// =============================================================================
// Match
// =============================================================================

/// Options controlling match-term generation. The defaults mirror the existing
/// match indexer: 3-gram tokens, downcased, `k = 3` hash slices into an
/// `m = 256`-bit filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchOptions {
    /// How text splits into tokens.
    pub tokenizer: Tokenizer,
    /// Lower-case the text before tokenization (case-insensitive matching).
    pub downcase: bool,
    /// Number of bit positions derived per token, `3..=16` (the v1 match
    /// indexer's bounds; the upper bound is also the PRF block size — each
    /// position consumes 2 bytes of the 32-byte block).
    pub k: usize,
    /// Bloom filter size in bits. Must be a power of two in `[32, 65536]`
    /// (the v1 match indexer's bounds).
    pub m: u32,
}

impl Default for MatchOptions {
    fn default() -> Self {
        Self {
            tokenizer: Tokenizer::default(),
            downcase: true,
            k: 3,
            m: 256,
        }
    }
}

impl MatchOptions {
    // Bounds mirror the v1 match indexer (`cipherstash-core`'s
    // `bloom_filter`: K_MIN/K_MAX/M_MIN/M_MAX) so the same configuration
    // validates identically across the two stacks.
    fn validate(&self) -> Result<u16, TermError> {
        if let Tokenizer::Ngram { length: 0 } = self.tokenizer {
            return Err(TermError::InvalidOptions(
                "n-gram length must be at least 1",
            ));
        }
        if !(3..=16).contains(&self.k) {
            return Err(TermError::InvalidOptions("k must be in 3..=16"));
        }
        if !self.m.is_power_of_two() || !(32..=65536).contains(&self.m) {
            return Err(TermError::InvalidOptions(
                "m must be a power of two in [32, 65536]",
            ));
        }
        // For m = 65536 the mask is u16::MAX; positions always fit in u16.
        Ok((self.m - 1) as u16)
    }
}

/// Type-level match configuration: the [`MatchOptions`] a [`MatchTerm<Self>`]
/// is generated with. Putting the configuration on the *type* means a record
/// field and the query probing it agree on tokenizer and filter parameters by
/// construction. Define your own by implementing this on a marker type.
pub trait MatchConfig: Send + Sync + 'static {
    fn options() -> MatchOptions;
}

/// The default [`MatchConfig`]: [`MatchOptions::default`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DefaultMatch;

impl MatchConfig for DefaultMatch {
    fn options() -> MatchOptions {
        MatchOptions::default()
    }
}

/// A match (full-text) index term: the set bit positions of a Bloom filter over
/// the PRF outputs of the value's tokens, generated under the [`MatchConfig`]
/// `O`. Positions are sorted and de-duplicated.
pub struct MatchTerm<O = DefaultMatch> {
    positions: Vec<u16>,
    _config: PhantomData<fn() -> O>,
}

impl<O> MatchTerm<O> {
    /// Rebuild a term from stored positions — the inverse of
    /// [`positions`](Self::positions) /
    /// [`into_positions`](Self::into_positions), for terms persisted
    /// server-side. Sorts and de-duplicates, so any ordering is accepted;
    /// the caller asserts (via `O`) that the positions were generated under
    /// the same [`MatchConfig`].
    pub fn from_positions(mut positions: Vec<u16>) -> Self {
        positions.sort_unstable();
        positions.dedup();
        Self {
            positions,
            _config: PhantomData,
        }
    }

    /// The set Bloom-filter bit positions, sorted ascending, no duplicates.
    pub fn positions(&self) -> &[u16] {
        &self.positions
    }

    /// Unwrap into the stored positions.
    pub fn into_positions(self) -> Vec<u16> {
        self.positions
    }

    /// Whether this term's positions are a superset of `query`'s — the Bloom
    /// containment check used to evaluate a match query (with the usual Bloom
    /// false-positive rate; a query that generates tokens can never produce a
    /// false negative).
    ///
    /// An empty `query` returns `false`: containment of zero positions is
    /// vacuously true, which would turn an empty probe into a match-every-row
    /// query. Term generation already refuses to build such a term
    /// ([`TermError::EmptyTermText`]); this guards any other
    /// (e.g. deserialized) source of an empty term.
    pub fn contains(&self, query: &MatchTerm<O>) -> bool {
        !query.positions.is_empty()
            && query
                .positions
                .iter()
                .all(|p| self.positions.binary_search(p).is_ok())
    }
}

impl<O> fmt::Debug for MatchTerm<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MatchTerm")
            .field("positions", &self.positions)
            .finish()
    }
}

impl<O> Clone for MatchTerm<O> {
    fn clone(&self) -> Self {
        Self::from_positions(self.positions.clone())
    }
}

impl<O> PartialEq for MatchTerm<O> {
    fn eq(&self, other: &Self) -> bool {
        self.positions == other.positions
    }
}

impl<O> Eq for MatchTerm<O> {}

/// A [`PrfVisitor`] that folds a sequence of per-token PRF blocks into
/// Bloom-filter bit positions: `k` little-endian 2-byte slices of each block,
/// masked to the filter size.
///
/// The PRF input for a match term is the *sequence* of tokens the text was
/// cut into (n-grams or words — see [`Tokenizer`]), and the backend evaluates
/// the PRF once per token. The resolved output therefore arrives as a
/// sequence of blocks, one per token, which is why this visitor implements
/// `visit_seq` rather than `visit_block`: it walks the per-token blocks and
/// turns each one into that token's `k` Bloom-filter bits.
struct BloomVisitor {
    k: usize,
    mask: u16,
}

impl<P: Send + 'static> PrfVisitor<[u8; 32], P> for BloomVisitor {
    type Value = Vec<u16>;

    fn visit_seq(self, seq: SeqAccess<[u8; 32], P>) -> Result<Self::Value, PrfVisitorError> {
        // One node per token, in token order. Each node is the PRF output for
        // that token alone; `BlockVisitor` unwraps it to the raw 32-byte block.
        let mut positions: Vec<u16> = Vec::with_capacity(seq.len() * self.k);
        for node in seq {
            let block = node.visit(BlockVisitor)?;
            // A token sets `k` bits of the filter. The block is 32 bytes and
            // `k <= 16` (checked in `MatchOptions::validate`), so the `k`
            // 2-byte slices are disjoint; masking to `m - 1` maps each u16 into
            // the filter's `m` positions. The same token in a query text hits
            // the same `k` positions, which is what `MatchTerm::contains` tests.
            for i in 0..self.k {
                let chunk = [block[2 * i], block[2 * i + 1]];
                positions.push(u16::from_le_bytes(chunk) & self.mask);
            }
        }
        // The stored term is a set of positions: order and multiplicity carry
        // no information, and sorting makes `contains` a binary search.
        positions.sort_unstable();
        positions.dedup();
        Ok(positions)
    }

    // A map-shaped input is not a token stream.
    fn visit_map(self, _map: MapAccess<[u8; 32], P>) -> Result<Self::Value, PrfVisitorError> {
        Err(PrfVisitorError::UnexpectedShape)
    }
}

/// Derive a match term. Synchronous — see [`equality`]: validation and
/// tokenization run before the PRF, the visitor folds blocks into positions.
fn match_term<O>(
    prf: HmacSha256Prf,
    text: &str,
    context: PrfContext<'_>,
    options: MatchOptions,
) -> Result<MatchTerm<O>, TermError> {
    require_context(&context)?;
    let mask = options.validate()?;
    let tokens = tokenize::tokenize(text, options.tokenizer, options.downcase);
    if tokens.is_empty() {
        return Err(TermError::EmptyTermText);
    }
    let context = PrfContext::pae(&[MATCH_DOMAIN, context.as_bytes()]);

    let positions = tokens
        .prf_visit_with_context(prf, context, BloomVisitor { k: options.k, mask })
        .into_result()
        .map_err(TermError::from_prf)?;
    Ok(MatchTerm::from_positions(positions))
}

/// A match term of any text source, generated under `O`'s options. Derived
/// locally during the synchronous build — the returned [`Pending`] carries no
/// requests (tokenize makes the one necessary copy of the text).
impl<S, K, O> EncryptedFrom<S, StackCipher<K>> for MatchTerm<O>
where
    S: AsRef<str>,
    O: MatchConfig,
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
        let context = context.into_prf_context().into_owned();
        let term = match_term(cipher.prf().clone(), source.as_ref(), context, O::options())
            .map_err(Error::from);
        Pending::ready(cipher, term)
    }
}

// =============================================================================
// ORE / OPE
// =============================================================================

/// An order-revealing (CLLW ORE) index term for a source value of type `T`.
/// Wraps the CLLW ciphertext ([`CllwOreEncrypt::Output`]); comparisons order
/// like the plaintexts.
///
/// The type parameter is the *source* type: `OreTerm<u64>` in a record type
/// declares "this field is the ORE term of a `u64`".
pub struct OreTerm<T: CllwOreEncrypt>(T::Output);

/// An order-preserving (CLLW OPE) index term for a source value of type `T`
/// (see [`OreTerm`]). The wrapped ciphertext compares with plain
/// lexicographic byte order.
pub struct OpeTerm<T: CllwOpeEncrypt>(T::Output);

macro_rules! term_wrapper {
    ($name:ident, $bound:ident) => {
        impl<T: $bound> $name<T> {
            /// Wrap an already-generated CLLW ciphertext.
            pub fn new(output: T::Output) -> Self {
                Self(output)
            }

            /// The wrapped CLLW ciphertext.
            pub fn inner(&self) -> &T::Output {
                &self.0
            }

            /// Unwrap into the CLLW ciphertext.
            pub fn into_inner(self) -> T::Output {
                self.0
            }
        }

        impl<T: $bound> fmt::Debug for $name<T>
        where
            T::Output: fmt::Debug,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl<T: $bound> Clone for $name<T>
        where
            T::Output: Clone,
        {
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }

        impl<T: $bound> PartialEq for $name<T>
        where
            T::Output: PartialEq,
        {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }

        impl<T: $bound> Eq for $name<T> where T::Output: Eq {}

        impl<T: $bound> PartialOrd for $name<T>
        where
            T::Output: PartialOrd,
        {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                self.0.partial_cmp(&other.0)
            }
        }

        impl<T: $bound> Ord for $name<T>
        where
            T::Output: Ord,
        {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.0.cmp(&other.0)
            }
        }
    };
}

term_wrapper!(OreTerm, CllwOreEncrypt);
term_wrapper!(OpeTerm, CllwOpeEncrypt);

/// A [`PrfVisitor`] that carries the plaintext in and hands the CLLW ORE
/// ciphertext out. The PRF block becomes the CLLW [`Key`](cllw_ore::Key)
/// *inside* `visit_block` and dies there: the block arrives by value and is
/// copied into the `ZeroizeOnDrop` key (`[u8; 32]` is `Copy`, so `Key::from`
/// wipes its copy and this visitor wipes the one it still holds), the value
/// is encrypted, and only the ciphertext leaves. No key is ever returned to
/// the caller.
///
/// This is the shape a 2-party PRF needs: the caller supplies a PRF input
/// (the context) and receives a term, and where the key comes from — or
/// whether one exists at all — is the visitor's business. Swapping the
/// backend for one that returns per-prefix PRF outputs instead of a key
/// changes this visitor, not its callers.
///
/// The plaintext is owned (`T: 'static`) because the visitor outlives the
/// call under an asynchronous backend; `Send` for the same reason. CLLW
/// failures surface through the visitor's `Value` rather than
/// [`PrfVisitorError`] so they keep their own error type.
struct OreVisitor<T>(T);

impl<T, P> PrfVisitor<[u8; 32], P> for OreVisitor<T>
where
    T: CllwOreEncrypt + Send + 'static,
    T::Output: Send + 'static,
    P: Send + 'static,
{
    type Value = Result<T::Output, cllw_ore::Error>;

    fn visit_block(self, mut block: [u8; 32]) -> Result<Self::Value, PrfVisitorError> {
        let key = cllw_ore::Key::from(block);
        block.zeroize();
        Ok(self.0.encrypt(&key))
    }
}

/// The OPE twin of [`OreVisitor`]: same key handling, produces a CLLW OPE
/// ciphertext (byte order is plaintext order).
struct OpeVisitor<T>(T);

impl<T, P> PrfVisitor<[u8; 32], P> for OpeVisitor<T>
where
    T: CllwOpeEncrypt + Send + 'static,
    T::Output: Send + 'static,
    P: Send + 'static,
{
    type Value = Result<T::Output, cllw_ore::Error>;

    fn visit_block(self, mut block: [u8; 32]) -> Result<Self::Value, PrfVisitorError> {
        let key = cllw_ore::Key::from(block);
        block.zeroize();
        Ok(self.0.encrypt_ope(&key))
    }
}

/// Derive an ORE term: PRF of the encoded context under a PAE-encoded
/// `[domain, context]` framing — the same framing every other term kind uses
/// (see the module docs), so no reimplementation of this derivation can
/// collide with an equality or match derivation. Only the context enters the
/// PRF — never the plaintext, which rides in the visitor and is encrypted
/// there. Deterministic, so write-time and query-time terms agree; under a
/// 2-party PRF backend this derivation is a visible ZeroKMS event.
fn ore<T>(prf: HmacSha256Prf, value: T, context: PrfContext<'_>) -> Result<OreTerm<T>, TermError>
where
    T: CllwOreEncrypt + Send + 'static,
    T::Output: Send + 'static,
{
    require_context(&context)?;
    let context_bytes = context.as_bytes();
    context_bytes
        .prf_visit_with_context(
            prf,
            PrfContext::pae(&[ORE_KEY_DOMAIN, context_bytes]),
            OreVisitor(value),
        )
        .into_result()
        .map_err(TermError::from_prf)?
        .map(OreTerm)
        .map_err(TermError::Ore)
}

/// Derive an OPE term — as [`ore`], under the OPE domain so the two schemes
/// never share a key.
fn ope<T>(prf: HmacSha256Prf, value: T, context: PrfContext<'_>) -> Result<OpeTerm<T>, TermError>
where
    T: CllwOpeEncrypt + Send + 'static,
    T::Output: Send + 'static,
{
    require_context(&context)?;
    let context_bytes = context.as_bytes();
    context_bytes
        .prf_visit_with_context(
            prf,
            PrfContext::pae(&[OPE_KEY_DOMAIN, context_bytes]),
            OpeVisitor(value),
        )
        .into_result()
        .map_err(TermError::from_prf)?
        .map(OpeTerm)
        .map_err(TermError::Ore)
}

/// An ORE term of any [`CllwOreEncrypt`] source. Derived locally during the
/// synchronous build — the returned [`Pending`] carries no requests.
impl<S, K> EncryptedFrom<S, StackCipher<K>> for OreTerm<S>
where
    S: CllwOreEncrypt + Clone + Send + 'static,
    S::Output: Send + 'static,
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
        let context = context.into_prf_context().into_owned();
        let term = ore(cipher.prf().clone(), source.clone(), context).map_err(Error::from);
        Pending::ready(cipher, term)
    }
}

/// An OPE term of any [`CllwOpeEncrypt`] source. Derived locally during the
/// synchronous build — the returned [`Pending`] carries no requests.
impl<S, K> EncryptedFrom<S, StackCipher<K>> for OpeTerm<S>
where
    S: CllwOpeEncrypt + Clone + Send + 'static,
    S::Output: Send + 'static,
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
        let context = context.into_prf_context().into_owned();
        let term = ope(cipher.prf().clone(), source.clone(), context).map_err(Error::from);
        Pending::ready(cipher, term)
    }
}

// =============================================================================
// Term generation on the cipher
// =============================================================================

/// Descriptor-string term generation, for call sites that want one term rather
/// than a whole record: query builders probing an index, re-indexers, tests of
/// a single scheme.
///
/// Every [`StackCipher`] carries the PRF keyed by its keyset's index key, so
/// these need no data-key traffic at all — a query builder holding a cipher
/// never touches ZeroKMS to build a probe. Each is byte-identical to the
/// target-directed path for the same descriptor, so a term generated here
/// compares against one generated by `encrypt_into`.
impl<K> StackCipher<K> {
    /// Generate an equality (exact-match) term for `value` under the field
    /// `descriptor`. Deterministic: the same value + descriptor always yields
    /// the same term, at write time and at query time. Byte-identical to
    /// `value.encrypt_into::<EqualityTerm>(&cipher, descriptor)`.
    pub async fn equality_term<T>(
        &self,
        value: T,
        descriptor: &str,
    ) -> Result<EqualityTerm, TermError>
    where
        T: PrfValue,
    {
        equality(self.prf().clone(), value, descriptor.into_prf_context())
    }

    /// Generate a match (full-text) term for `text` under the field
    /// `descriptor` and the type-level config `O`: tokenize locally, PRF each
    /// token, fold the outputs into Bloom-filter bit positions.
    ///
    /// The config is a *type* parameter (not runtime options) so write-time
    /// and query-time terms agree by construction — a term generated under
    /// one config cannot be compared against a term generated under another,
    /// which would otherwise silently return false negatives. Byte-identical
    /// to the target-directed path for the same `O`. For custom options,
    /// define a marker type implementing [`MatchConfig`].
    ///
    /// The same call serves both write time (index the stored text) and query
    /// time (index the probe text, then test [`MatchTerm::contains`]
    /// server-side).
    ///
    /// Returns [`TermError::EmptyTermText`] when the text yields no tokens —
    /// empty or separator-only text, or an n-gram probe shorter than the gram
    /// length (which could never match; see [`Tokenizer::Ngram`]).
    pub async fn match_terms<O: MatchConfig>(
        &self,
        text: &str,
        descriptor: &str,
    ) -> Result<MatchTerm<O>, TermError> {
        match_term(
            self.prf().clone(),
            text,
            descriptor.into_prf_context(),
            O::options(),
        )
    }

    /// Generate an order-revealing (CLLW ORE) term for a range-queryable value
    /// under the field `descriptor`. The PRF input is the descriptor alone —
    /// the plaintext never enters the PRF; it travels in the visitor, which
    /// derives the per-descriptor CLLW key from the PRF block and encrypts
    /// under it in one step. The key never leaves the visitor.
    ///
    /// Supported inputs: `u16`/`u32`/`u64`/`u128`, `&'static str`, `String`,
    /// `Vec<u8>` (via [`CllwOreEncrypt`]). The value must be owned
    /// (`'static`) because the visitor carries it; pass a `String` for
    /// borrowed text. Returns the raw CLLW ciphertext; the target-directed
    /// path wraps the same bytes in [`OreTerm`].
    pub async fn ore_term<T>(&self, value: T, descriptor: &str) -> Result<T::Output, TermError>
    where
        T: CllwOreEncrypt + Send + 'static,
        T::Output: Send + 'static,
    {
        ore(self.prf().clone(), value, descriptor.into_prf_context()).map(OreTerm::into_inner)
    }

    /// Generate an order-preserving (CLLW OPE) term: ciphertexts compare with
    /// plain lexicographic byte order, no custom comparator required.
    /// Encrypt-only — pair with the record ciphertext for round-trips. Key
    /// handling and input bounds as for [`ore_term`](Self::ore_term).
    pub async fn ope_term<T>(&self, value: T, descriptor: &str) -> Result<T::Output, TermError>
    where
        T: CllwOpeEncrypt + Send + 'static,
        T::Output: Send + 'static,
    {
        ope(self.prf().clone(), value, descriptor.into_prf_context()).map(OpeTerm::into_inner)
    }
}
