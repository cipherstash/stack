//! Searchable Encrypted Metadata (SEM) term types.
//!
//! Index terms are stored alongside a
//! [`StackCipherText`](crate::StackCipherText) so encrypted values can be
//! queried without decryption. Each term type implements
//! [`EncryptFrom`](crate::EncryptFrom), so the usual entry point is
//! target-directed:
//!
//! ```text
//! let term: EqualityTerm = value.encrypt_into_with_context(&cipher, nonempty!("users").with("email")).await?;
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
//! publicly — its PRF ([`KeysetCipher::prf`], keyed by the index key of the
//! keyset the handle is bound to). These core implementations own term
//! generation; downstream storage types can wrap the supported operations or
//! consume their native output with a visitor (see [`target`](crate::target)).
//! Terms bind to a keyset the way sealed values do: a term derived through
//! one tenant's [`KeysetCipher`] compares only against terms derived through
//! the same keyset.
//!
//! Alongside the target-directed path, the keyset cipher carries descriptor
//! methods ([`KeysetCipher::equality_term`] and friends) for call sites that
//! want a single term rather than a whole record — query builders, mostly.
//! Each returns a [`Pending`], as the record path does; they derive no data
//! keys, and under the local HMAC backend the pending carries no requests,
//! so a probe settles without a ZeroKMS call — though a backend that derives
//! terms at ZeroKMS settles it through the same pending. The
//! descriptor is the same [`NonEmpty`] context the target-directed path
//! takes, so the two agree byte for byte.
//!
//! # PRF backends, visitors, and the 2-party future
//!
//! The PRF backend produces **blocks**; a [`PrfVisitor`] shapes blocks into
//! the term (`EqualityVisitor`, `BloomVisitor`, `OreVisitor`, `OpeVisitor` —
//! all private). The shaping is pure and synchronous by construction: only block
//! production can involve I/O, so a visitor never knows which side of a
//! round-trip it runs on. All pure work — option validation, tokenization —
//! happens *before* the PRF is invoked.
//!
//! The backend today is the local
//! [`HmacSha256Prf`] — keyed by the
//! deterministic per-keyset [`IndexKey`](crate::kms::IndexKey) from
//! [`kms::IndexKeySource`](crate::kms::IndexKeySource), loaded when the keyset is selected — so
//! every derivation completes with no I/O and an [`EncryptFrom`](crate::EncryptFrom) term
//! carries **no requests** in its [`Pending`]. That is the backend's
//! property, not the API's: the term is a `Pending` either way. The next
//! ZeroKMS release adds 2-party PRF generation; under
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
//!
//! # Byte encodings
//!
//! Terms cross the wasm/FFI boundary into other languages, so each term kind
//! commits to one frozen **transport** encoding — the bytes a language
//! binding decodes:
//!
//! * [`EqualityTerm`] — the 32 PRF bytes as-is
//!   ([`as_bytes`](EqualityTerm::as_bytes) /
//!   [`to_bytes`](EqualityTerm::to_bytes) /
//!   [`from_bytes`](EqualityTerm::from_bytes)).
//! * [`MatchTerm`] — the sorted, de-duplicated bit positions, each a
//!   little-endian `u16` ([`to_bytes`](MatchTerm::to_bytes) /
//!   [`from_bytes`](MatchTerm::from_bytes)).
//! * [`OreTerm`] / [`OpeTerm`] — the raw CLLW ciphertext bytes, unframed
//!   ([`as_bytes`](OreTerm::as_bytes) / [`to_bytes`](OreTerm::to_bytes) /
//!   [`from_bytes`](OreTerm::from_bytes)).
//!
//! Every kind decodes through `TryFrom<&[u8]>` as well, failing with a
//! [`TermBytesError`]; [`EqualityTerm`] additionally keeps an infallible
//! [`from_bytes`](EqualityTerm::from_bytes) over a `[u8; 32]`. `as_bytes`
//! exists only where the term *is* a contiguous buffer (equality, ORE, OPE);
//! a [`MatchTerm`] is canonically a position list, so it has none.
//!
//! For equality and ORE/OPE the transport bytes are also the stored form,
//! and they share the *shape* of the v1 / `cipherstash-client` encodings — a
//! 32-byte HMAC for equality, raw CLLW bytes for ORE/OPE, the same bytes EQL
//! hex-encodes into its `hm` / `oc` / `op` fields with its hex and JSON
//! framing sitting *above* them. A match term is the exception: what is
//! stored and queried is the position list
//! ([`positions`](MatchTerm::positions)), which maps to an integer-array
//! column (EQL sends `bf` as a JSON integer array) — no column holds the
//! `u16` byte string, which is stack-encrypt's own shape and exists so a
//! binding can carry the term across the boundary without inventing a
//! framing.
//!
//! The **values are not comparable**: as noted above the derivations differ,
//! and stack-encrypt has no EQL integration of its own. A term compares only
//! against terms produced by the same stack-encrypt keyset — never against a
//! row `cipherstash-client` or EQL v1 wrote. What the shared shape buys is a
//! decoder: a language binding reading these bytes needs no framing of its
//! own. There is deliberately no version byte or framing here: a term is an
//! opaque comparand and its derivation is already versioned by the PAE domain
//! labels above. The pins in `tests/term_bytes.rs` and
//! `tests/frozen_bytes.rs` hold both the derivations and the encodings in
//! place: a binding depends on the transport bytes, so they are frozen even
//! where no column holds them.

mod tokenize;

pub use tokenize::Tokenizer;

use std::fmt;
use std::marker::PhantomData;

// Re-exported because they appear in this module's public bounds
// ([`KeysetCipher::ore_term`], [`OreTerm`], ...): a caller writing a generic
// wrapper over the term APIs has to be able to name them without depending
// on `cllw-ore` directly.
pub use cllw_ore::{CllwOpeEncrypt, CllwOreEncrypt};
use vitaminc_hmac::HmacSha256Prf;
use vitaminc_prf::{
    BlockVisitor, Context, IntoPrfContext, MapAccess, PrfError, PrfValue, PrfVisitor,
    PrfVisitorError, SeqAccess,
};
use vitaminc_protected::NonEmpty;
use zeroize::Zeroize;

use stack_kms::MaybeSend;

use crate::target::core::Term;
use crate::target::{DecryptField, Decryptable, Decryption};
use crate::{Error, KeysetCipher, Pending};

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
#[non_exhaustive]
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
    /// Term bytes do not decode under the term kind's frozen encoding — see
    /// [`TermBytesError`].
    #[error(transparent)]
    Bytes(#[from] TermBytesError),
}

/// A term's frozen byte encoding failed to decode (see the
/// [module docs](self#byte-encodings)). Purely structural — a term that
/// *decodes* has proven nothing about being a genuine term derived under any
/// particular keyset; bytes that fail here were never a valid encoding of
/// that term kind at all.
///
/// Kept separate from the rest of [`TermError`] (which it converts into) so
/// decoding has an error a caller can compare: the generation variants carry
/// boxed and opaque sources that are not [`PartialEq`].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TermBytesError {
    /// Equality-term bytes are not the 32 PRF bytes.
    #[error("equality-term bytes must be exactly 32 bytes, got {0}")]
    WrongEqualityTermLength(usize),
    /// Match-term bytes are not a whole number of little-endian `u16`
    /// positions.
    #[error("match-term bytes must be little-endian u16 positions, got an odd length of {0}")]
    OddMatchTermLength(usize),
    /// A decoded position lies outside the Bloom filter the term's
    /// [`MatchConfig`] fixes. Genuine positions are always masked into
    /// `0..m`, so an out-of-range one means the bytes were not written by
    /// this encoding — a wrong-endian decoder, most often, which would
    /// otherwise decode cleanly and then silently never match.
    #[error("match position {position} is outside the {filter_size}-bit filter")]
    MatchPositionOutOfRange {
        /// The offending position.
        position: u16,
        /// The filter size (`m`) the [`MatchConfig`] fixes.
        filter_size: u32,
    },
    /// The buffer's length is not one this CLLW ciphertext shape can have.
    /// (The length is all there is to report: `cllw_ore::Error` is
    /// deliberately contentless, so its message would say strictly less.)
    #[error("{0} bytes do not fit this CLLW ciphertext shape")]
    MalformedCllwCiphertext(usize),
}

impl TermError {
    fn from_prf<E>(err: PrfError<E>) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Prf(Box::new(err))
    }
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
    /// Infallible: the width is in the type. For a slice of unknown length
    /// use `TryFrom<&[u8]>`.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Owned copy of [`as_bytes`](Self::as_bytes) — the same `to_bytes` every
    /// other term kind offers (see the [module docs](self#byte-encodings)).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Decode a slice of unknown length — the fallible counterpart of
/// [`EqualityTerm::from_bytes`], and the same `TryFrom<&[u8]>` every other
/// term kind offers.
impl TryFrom<&[u8]> for EqualityTerm {
    type Error = TermBytesError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(bytes)
            .map(Self)
            .map_err(|_| TermBytesError::WrongEqualityTermLength(bytes.len()))
    }
}

impl From<EqualityTerm> for Vec<u8> {
    fn from(term: EqualityTerm) -> Self {
        term.0.to_vec()
    }
}

/// The frozen byte encoding — the 32 PRF bytes as-is (see the
/// [module docs](self#byte-encodings)).
impl AsRef<[u8]> for EqualityTerm {
    fn as_ref(&self) -> &[u8] {
        &self.0
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
/// `context` is the encoding of a [`NonEmpty`] — every caller holds one —
/// so there is nothing left to validate here.
fn equality<T>(
    prf: &HmacSha256Prf,
    value: T,
    context: Context<'_>,
) -> Result<EqualityTerm, TermError>
where
    T: PrfValue,
{
    let context = Context::pae(&[EQUALITY_DOMAIN, context.as_bytes()]);
    value
        .prf_visit_with_context(prf, context, EqualityVisitor)
        .into_result()
        .map_err(TermError::from_prf)
}

/// An equality term of any [`PrfValue`] source. Under the local HMAC
/// backend, derived during the synchronous build — the returned [`Pending`]
/// carries no requests.
impl<'c, S, K, T> Term<S, K, NonEmpty<T>> for EqualityTerm
where
    S: PrfValue + Clone,
    T: IntoPrfContext<'c>,
{
    // Derived locally: no data key, no descriptor.

    fn encrypt_from<'a>(
        source: &S,
        cipher: &'a KeysetCipher<'_, K>,
        context: NonEmpty<T>,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        let context = context.into_prf_context().into_owned();
        let term = equality(cipher.prf(), source.clone(), context).map_err(Error::from);
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
    /// Wrap positions that are already known to be in range — sorting and
    /// de-duplicating them into the canonical order. Private because nothing
    /// outside can know the range holds: the generator's positions are masked
    /// into `0..m` by construction, and every caller-supplied list goes
    /// through [`from_positions`](Self::from_positions) instead.
    fn normalised(mut positions: Vec<u16>) -> Self {
        positions.sort_unstable();
        positions.dedup();
        Self {
            positions,
            _config: PhantomData,
        }
    }

    /// The transport byte encoding: each position as a little-endian `u16`,
    /// in the canonical order [`positions`](Self::positions) holds them
    /// (sorted ascending, no duplicates). See the
    /// [module docs](self#byte-encodings) — what is stored and queried is the
    /// position list; this is the frozen form a language binding carries
    /// across the wasm/FFI boundary. The inverse of
    /// [`from_bytes`](Self::from_bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.positions
            .iter()
            .flat_map(|p| p.to_le_bytes())
            .collect()
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

/// Rebuilding a term needs the [`MatchConfig`]: it fixes the filter size `m`
/// every genuine position is below, and a position outside it is a decoding
/// bug rather than a term.
impl<O: MatchConfig> MatchTerm<O> {
    /// Rebuild a term from stored positions — the inverse of
    /// [`positions`](Self::positions) /
    /// [`into_positions`](Self::into_positions), for terms persisted
    /// server-side. Sorts and de-duplicates, so any ordering is accepted;
    /// the caller asserts (via `O`) that the positions were generated under
    /// the same [`MatchConfig`], and that much is checked: a position at or
    /// beyond `O`'s filter size `m` is rejected with
    /// [`TermBytesError::MatchPositionOutOfRange`].
    pub fn from_positions(positions: Vec<u16>) -> Result<Self, TermBytesError> {
        let filter_size = O::options().m;
        for &position in &positions {
            if u32::from(position) >= filter_size {
                return Err(TermBytesError::MatchPositionOutOfRange {
                    position,
                    filter_size,
                });
            }
        }
        Ok(Self::normalised(positions))
    }

    /// Decode the transport byte encoding — little-endian `u16` positions —
    /// the inverse of [`to_bytes`](Self::to_bytes). Like
    /// [`from_positions`](Self::from_positions), any ordering is accepted and
    /// normalised, and positions outside `O`'s filter are rejected: without
    /// that check a wrong-endian decoder on the other side of the FFI
    /// boundary would produce a term that decodes cleanly and then silently
    /// never matches. Rejects an odd-length buffer.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TermBytesError> {
        if !bytes.len().is_multiple_of(2) {
            return Err(TermBytesError::OddMatchTermLength(bytes.len()));
        }
        Self::from_positions(
            bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect(),
        )
    }
}

/// [`MatchTerm::from_bytes`] as a std conversion — the same decoder.
impl<O: MatchConfig> TryFrom<&[u8]> for MatchTerm<O> {
    type Error = TermBytesError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
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
        Self::normalised(self.positions.clone())
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
    prf: &HmacSha256Prf,
    text: &str,
    context: Context<'_>,
    options: MatchOptions,
) -> Result<MatchTerm<O>, TermError> {
    let mask = options.validate()?;
    let tokens = tokenize::tokenize(text, options.tokenizer, options.downcase);
    if tokens.is_empty() {
        return Err(TermError::EmptyTermText);
    }
    let context = Context::pae(&[MATCH_DOMAIN, context.as_bytes()]);

    let positions = tokens
        .prf_visit_with_context(prf, context, BloomVisitor { k: options.k, mask })
        .into_result()
        .map_err(TermError::from_prf)?;
    // Every position came out of the visitor masked to `m - 1`, so the range
    // check `from_positions` applies is already satisfied by construction.
    Ok(MatchTerm::normalised(positions))
}

/// A match term of any text source, generated under `O`'s options. Under
/// the local HMAC backend, derived during the synchronous build — the
/// returned [`Pending`] carries no requests (tokenize makes the one
/// necessary copy of the text).
impl<'c, S, K, O, T> Term<S, K, NonEmpty<T>> for MatchTerm<O>
where
    S: AsRef<str>,
    O: MatchConfig,
    T: IntoPrfContext<'c>,
{
    // Derived locally: no data key, no descriptor.

    fn encrypt_from<'a>(
        source: &S,
        cipher: &'a KeysetCipher<'_, K>,
        context: NonEmpty<T>,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        let context = context.into_prf_context().into_owned();
        let term =
            match_term(cipher.prf(), source.as_ref(), context, O::options()).map_err(Error::from);
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

/// Index terms are one-way: decryption passes over them. `Decryptable` and
/// `DecryptField` say so, which is how a derived record finds its ciphertext
/// field among them without being told.
macro_rules! index_term {
    ($ty:ty $(, $param:ident: $bound:path)?) => {
        impl<$($param: $bound)?> Decryptable for $ty {
            const DECRYPTABLE: bool = false;
        }
        impl<P, Ctx $(, $param: $bound)?> DecryptField<P, Ctx> for $ty {
            fn decryption_field<K: 'static>(self, _: Ctx) -> Option<Decryption<P, K>> {
                None
            }
        }
    };
}

index_term!(EqualityTerm);
index_term!(MatchTerm<O>, O: MatchConfig);
index_term!(OreTerm<T>, T: CllwOreEncrypt);
index_term!(OpeTerm<T>, T: CllwOpeEncrypt);

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

            /// Decode a term from its frozen byte encoding — the raw CLLW
            /// ciphertext bytes, the inverse of [`as_bytes`](Self::as_bytes)
            /// — for terms persisted server-side. Structural only (length
            /// checks); the caller asserts the bytes were generated for this
            /// source type `T` and under the same context.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, TermBytesError>
            where
                for<'a> T::Output: TryFrom<&'a [u8]>,
            {
                T::Output::try_from(bytes)
                    .map(Self)
                    .map_err(|_| TermBytesError::MalformedCllwCiphertext(bytes.len()))
            }
        }

        /// The inherent `from_bytes` as a std conversion — the same decoder.
        impl<T: $bound> TryFrom<&[u8]> for $name<T>
        where
            for<'a> T::Output: TryFrom<&'a [u8]>,
        {
            type Error = TermBytesError;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                Self::from_bytes(bytes)
            }
        }

        impl<T: $bound> $name<T>
        where
            T::Output: AsRef<[u8]>,
        {
            /// The frozen byte encoding: the raw CLLW ciphertext bytes,
            /// unframed — the same *shape* the EQL layer hex-encodes, but
            /// not comparable with rows it wrote (see the
            /// [module docs](self#byte-encodings)).
            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_ref()
            }

            /// Owned copy of [`as_bytes`](Self::as_bytes).
            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.as_ref().to_vec()
            }
        }

        /// The frozen byte encoding — the same bytes as the inherent
        /// `as_bytes`.
        impl<T: $bound> AsRef<[u8]> for $name<T>
        where
            T::Output: AsRef<[u8]>,
        {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
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
fn ore<T>(prf: &HmacSha256Prf, value: T, context: Context<'_>) -> Result<OreTerm<T>, TermError>
where
    T: CllwOreEncrypt + Send + 'static,
    T::Output: Send + 'static,
{
    let context_bytes = context.as_bytes();
    context_bytes
        .prf_visit_with_context(
            prf,
            Context::pae(&[ORE_KEY_DOMAIN, context_bytes]),
            OreVisitor(value),
        )
        .into_result()
        .map_err(TermError::from_prf)?
        .map(OreTerm)
        .map_err(TermError::Ore)
}

/// Derive an OPE term — as [`ore`], under the OPE domain so the two schemes
/// never share a key.
fn ope<T>(prf: &HmacSha256Prf, value: T, context: Context<'_>) -> Result<OpeTerm<T>, TermError>
where
    T: CllwOpeEncrypt + Send + 'static,
    T::Output: Send + 'static,
{
    let context_bytes = context.as_bytes();
    context_bytes
        .prf_visit_with_context(
            prf,
            Context::pae(&[OPE_KEY_DOMAIN, context_bytes]),
            OpeVisitor(value),
        )
        .into_result()
        .map_err(TermError::from_prf)?
        .map(OpeTerm)
        .map_err(TermError::Ore)
}

/// An ORE term of any [`CllwOreEncrypt`] source. Under the local HMAC
/// backend, derived during the synchronous build — the returned [`Pending`]
/// carries no requests.
impl<'c, S, K, T> Term<S, K, NonEmpty<T>> for OreTerm<S>
where
    S: CllwOreEncrypt + Clone + Send + 'static,
    S::Output: Send + 'static,
    T: IntoPrfContext<'c>,
{
    // Derived locally: no data key, no descriptor.

    fn encrypt_from<'a>(
        source: &S,
        cipher: &'a KeysetCipher<'_, K>,
        context: NonEmpty<T>,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        let context = context.into_prf_context().into_owned();
        let term = ore(cipher.prf(), source.clone(), context).map_err(Error::from);
        Pending::ready(cipher, term)
    }
}

/// An OPE term of any [`CllwOpeEncrypt`] source. Under the local HMAC
/// backend, derived during the synchronous build — the returned [`Pending`]
/// carries no requests.
impl<'c, S, K, T> Term<S, K, NonEmpty<T>> for OpeTerm<S>
where
    S: CllwOpeEncrypt + Clone + Send + 'static,
    S::Output: Send + 'static,
    T: IntoPrfContext<'c>,
{
    // Derived locally: no data key, no descriptor.

    fn encrypt_from<'a>(
        source: &S,
        cipher: &'a KeysetCipher<'_, K>,
        context: NonEmpty<T>,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        let context = context.into_prf_context().into_owned();
        let term = ope(cipher.prf(), source.clone(), context).map_err(Error::from);
        Pending::ready(cipher, term)
    }
}

// =============================================================================
// Term generation on the cipher
// =============================================================================

/// Descriptor term generation, for call sites that want one term rather than
/// a whole record: query builders probing an index, re-indexers, tests of a
/// single scheme.
///
/// Each returns a [`Pending`], the same carrier the record path hands back,
/// so probes combine ([`Pending::zip`], [`Pending::all`]) and a batch of
/// them settles as one. Under the local HMAC backend a term is derived
/// during the synchronous build and the pending carries no requests —
/// awaiting it does no I/O — but that is the backend's property, not the
/// API's: a backend that derives terms at ZeroKMS settles them the way it
/// settles data keys, through the same pending.
///
/// # These are the query-probe path
///
/// A term derived here is bound to the descriptor you pass and to nothing
/// else: it builds no [`Descriptor`](crate::Descriptor), makes no ZeroKMS
/// request, and has no relation to the ciphertext of the field it indexes.
/// Nothing checks that the two agree, and the two mistakes fail differently —
/// a ciphertext under the wrong context is refused at first read, while a
/// term under the wrong context is a valid term in another domain that
/// matches nothing, forever, with no error anywhere.
///
/// So derive a term here to *query*: a probe has no ciphertext to agree with,
/// and needs the field's context because that is what it is matching against.
/// A term that is going to be **stored** should come from a target instead,
/// where the one context the target is handed reaches the ciphertext and the
/// term beside it alike, and giving either a context of its own is written
/// in the declaration rather than plumbed (ADR-0004). A derived record does
/// this per field and cannot get it wrong; a hand-written target can still
/// put a subtree under its own context, but has to say so. The bytes are
/// identical either way; what differs is whether anything holds the two in
/// agreement.
///
/// The descriptor is a context
/// as the target-directed leaves take it — a [`NonEmpty<T>`]:
/// `nonempty!("users").with("email")`, `NonEmpty::new(column)?`,
/// `nonempty!("users").with("email").with(row_id)` — and each method is
/// byte-identical to that path for the same descriptor, so a term generated
/// here compares against one generated by `encrypt_into_with_context`.
impl<K> KeysetCipher<'_, K> {
    /// Generate an equality (exact-match) term for `value` under the field
    /// `descriptor`. Deterministic: the same value + descriptor always yields
    /// the same term, at write time and at query time. Byte-identical to
    /// `value.encrypt_into_with_context(&keyset, descriptor)` into an
    /// `EqualityTerm`.
    pub fn equality_term<'c, T>(
        &self,
        value: T,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
    ) -> Pending<'_, EqualityTerm, K>
    where
        T: PrfValue,
    {
        let term = equality(self.prf(), value, descriptor.into_prf_context());
        Pending::ready(self, term.map_err(Error::from))
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
    /// Fails with [`TermError::EmptyTermText`] — as
    /// [`Error::Term`], once awaited — when the text
    /// yields no tokens: empty or separator-only text, or an n-gram probe
    /// shorter than the gram length (which could never match; see
    /// [`Tokenizer::Ngram`]).
    pub fn match_terms<'c, O>(
        &self,
        text: &str,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
    ) -> Pending<'_, MatchTerm<O>, K>
    where
        O: MatchConfig + MaybeSend,
    {
        let term = match_term(
            self.prf(),
            text,
            descriptor.into_prf_context(),
            O::options(),
        );
        Pending::ready(self, term.map_err(Error::from))
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
    pub fn ore_term<'c, T>(
        &self,
        value: T,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
    ) -> Pending<'_, T::Output, K>
    where
        T: CllwOreEncrypt + Send + 'static,
        T::Output: Send + 'static,
    {
        let term = ore(self.prf(), value, descriptor.into_prf_context()).map(OreTerm::into_inner);
        Pending::ready(self, term.map_err(Error::from))
    }

    /// Generate an order-preserving (CLLW OPE) term: ciphertexts compare with
    /// plain lexicographic byte order, no custom comparator required.
    /// Encrypt-only — pair with the record ciphertext for round-trips. Key
    /// handling and input bounds as for [`ore_term`](Self::ore_term).
    pub fn ope_term<'c, T>(
        &self,
        value: T,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
    ) -> Pending<'_, T::Output, K>
    where
        T: CllwOpeEncrypt + Send + 'static,
        T::Output: Send + 'static,
    {
        let term = ope(self.prf(), value, descriptor.into_prf_context()).map(OpeTerm::into_inner);
        Pending::ready(self, term.map_err(Error::from))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use vitaminc_prf::PrfKeyInit;
    use vitaminc_protected::Protected;

    use super::*;

    /// The Bloom fold reads a token *stream*: handed a map-shaped PRF input
    /// it refuses, rather than folding the entries' blocks as if they were
    /// tokens.
    #[test]
    fn the_bloom_fold_refuses_a_map_shaped_input() {
        let prf = HmacSha256Prf::new(Protected::new([7; 32]));
        let input = BTreeMap::from([("a".to_string(), "alice".to_string())]);

        let result = input
            .prf_visit_with_context(&prf, (), BloomVisitor { k: 3, mask: 255 })
            .into_result();
        assert!(
            matches!(
                result,
                Err(PrfError::Visitor(PrfVisitorError::UnexpectedShape))
            ),
            "{result:?}"
        );
    }
}
