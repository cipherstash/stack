//! Searchable Encrypted Metadata (SEM) term generation.
//!
//! [`TermGenerator`] produces the index terms stored alongside a
//! [`StackCipherText`](crate::StackCipherText) so encrypted values can be
//! queried without decryption:
//!
//! * **Equality terms** ([`TermGenerator::equality_term`]) — a PRF of the whole
//!   value; supports exact-match queries.
//! * **Match terms** ([`TermGenerator::match_terms`]) — the value is tokenized
//!   locally, each token is PRF'd, and the outputs fold into Bloom-filter bit
//!   positions; supports full-text match queries.
//! * **ORE / OPE terms** ([`TermGenerator::ore_term`] /
//!   [`TermGenerator::ope_term`]) — CLLW order-revealing / order-preserving
//!   ciphertexts under a per-descriptor key derived *through the PRF*; support
//!   range queries.
//!
//! # PRF backends and the 2-party future
//!
//! The generator is generic over `P:`[`Prf`], and every term method awaits the
//! PRF output ([`Prf::Ok`] is `IntoFuture`). With the local
//! [`HmacSha256Prf`](vitaminc_hmac::HmacSha256Prf) backend — keyed by the
//! deterministic per-keyset [`IndexKey`](stack_kms::IndexKey) from
//! [`stack_kms::IndexKeySource`] — outputs are immediately ready. The next
//! ZeroKMS release adds 2-party PRF generation; that backend returns deferred
//! outputs resolved by a server round-trip, and slots in behind the same `P`
//! parameter with no API change. This is also why ORE/OPE *keys* are derived
//! through the PRF (from the field descriptor, never the plaintext): under a
//! 2-party backend, per-field key derivation becomes a visible, auditable
//! ZeroKMS event while plaintext stays local.
//!
//! # Determinism and domain separation
//!
//! Index terms are deterministic by design — the same value under the same
//! descriptor always yields the same term, which is what makes them queryable
//! (and is the usual SEM leakage trade-off: equal values are visibly equal).
//! Every term kind derives under its own PAE-encoded domain, bound to the
//! caller's field `descriptor`, so the same value indexed as an equality term,
//! a match token, or an ORE key can never produce colliding PRF outputs.
//!
//! This is a fresh (v2) term format: PRF inputs are framed with vitaminc's PAE
//! context encoding, so terms are intentionally **not** byte-compatible with
//! `cipherstash-client`'s existing `IndexTerm` values.

mod tokenize;

pub use tokenize::Tokenizer;

use cllw_ore::{CllwOpeEncrypt, CllwOreEncrypt};
use vitaminc_prf::{
    BlockVisitor, MapAccess, Prf, PrfContext, PrfError, PrfValue, PrfVisitor, PrfVisitorError,
    SeqAccess,
};
use vitaminc_protected::Protected;
use zeroize::Zeroize;

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
}

impl TermError {
    fn from_prf<E>(err: PrfError<E>) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Prf(Box::new(err))
    }
}

/// An equality (exact-match) index term: one PRF block over the whole value.
///
/// Terms are pseudorandom under the index key; they are stored server-side and
/// are not secret key material.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EqualityTerm([u8; 32]);

impl EqualityTerm {
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

/// A match (full-text) index term: the set bit positions of a Bloom filter over
/// the PRF outputs of the value's tokens. Positions are sorted and de-duplicated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchTerm {
    positions: Vec<u16>,
}

impl MatchTerm {
    /// The set Bloom-filter bit positions, sorted ascending, no duplicates.
    pub fn positions(&self) -> &[u16] {
        &self.positions
    }

    /// Whether this term's positions are a superset of `query`'s — the Bloom
    /// containment check used to evaluate a match query (with the usual Bloom
    /// false-positive rate; a query that generates tokens can never produce a
    /// false negative).
    ///
    /// An empty `query` returns `false`: containment of zero positions is
    /// vacuously true, which would turn an empty probe into a match-every-row
    /// query. [`TermGenerator::match_terms`] already refuses to build such a
    /// term ([`TermError::EmptyTermText`]); this guards any other
    /// (e.g. deserialized) source of an empty term.
    pub fn contains(&self, query: &MatchTerm) -> bool {
        !query.positions.is_empty()
            && query
                .positions
                .iter()
                .all(|p| self.positions.binary_search(p).is_ok())
    }
}

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

/// A [`PrfVisitor`] that folds a sequence of per-token PRF blocks into
/// Bloom-filter bit positions: `k` little-endian 2-byte slices of each block,
/// masked to the filter size.
struct BloomVisitor {
    k: usize,
    mask: u16,
}

impl<P: Send + 'static> PrfVisitor<[u8; 32], P> for BloomVisitor {
    type Value = MatchTerm;

    fn visit_seq(self, seq: SeqAccess<[u8; 32], P>) -> Result<Self::Value, PrfVisitorError> {
        let mut positions: Vec<u16> = Vec::with_capacity(seq.len() * self.k);
        for node in seq {
            let block = node.visit(BlockVisitor)?;
            for i in 0..self.k {
                let chunk = [block[2 * i], block[2 * i + 1]];
                positions.push(u16::from_le_bytes(chunk) & self.mask);
            }
        }
        positions.sort_unstable();
        positions.dedup();
        Ok(MatchTerm { positions })
    }

    // A map-shaped input is not a token stream.
    fn visit_map(self, _map: MapAccess<[u8; 32], P>) -> Result<Self::Value, PrfVisitorError> {
        Err(PrfVisitorError::UnexpectedShape)
    }
}

/// Generates Searchable Encrypted Metadata terms over a PRF backend `P`.
///
/// Construct from a per-keyset index key with [`from_index_key`]
/// (local HMAC backend), or from any [`Prf`] backend with [`new`] — see the
/// module docs for the 2-party story.
///
/// [`from_index_key`]: TermGenerator::from_index_key
/// [`new`]: TermGenerator::new
#[derive(Clone)]
pub struct TermGenerator<P> {
    prf: P,
}

impl TermGenerator<vitaminc_hmac::HmacSha256Prf> {
    /// Build a generator over the local HMAC-SHA256 PRF, keyed by the
    /// deterministic per-keyset index key (see
    /// [`stack_kms::IndexKeySource::load_index_key`]).
    pub fn from_index_key(index_key: &stack_kms::IndexKey) -> Self {
        Self::new(vitaminc_hmac::HmacSha256Prf::new(Protected::new(
            *index_key.key(),
        )))
    }
}

impl<P> TermGenerator<P> {
    /// Build a generator over an arbitrary PRF backend.
    pub fn new(prf: P) -> Self {
        Self { prf }
    }
}

impl<P> TermGenerator<P>
where
    P: Prf<Block = [u8; 32]> + Clone,
{
    /// Generate an equality (exact-match) term for `value` under the field
    /// `descriptor`. Deterministic: the same value + descriptor always yields
    /// the same term, at write time and at query time.
    pub async fn equality_term<T>(
        &self,
        value: T,
        descriptor: &str,
    ) -> Result<EqualityTerm, TermError>
    where
        T: PrfValue,
    {
        let context = PrfContext::pae(&[EQUALITY_DOMAIN, descriptor.as_bytes()]);
        let block = value
            .prf_with_context(self.prf.clone(), context)
            .await
            .map_err(TermError::from_prf)?;
        Ok(EqualityTerm(block))
    }

    /// Generate a match (full-text) term for `text` under the field
    /// `descriptor`: tokenize locally, PRF each token, fold the outputs into
    /// Bloom-filter bit positions.
    ///
    /// The same call serves both write time (index the stored text) and query
    /// time (index the probe text, then test
    /// [`MatchTerm::contains`] server-side).
    ///
    /// Returns [`TermError::EmptyTermText`] when the text yields no tokens —
    /// empty or separator-only text, or an n-gram probe shorter than the gram
    /// length (which could never match; see [`Tokenizer::Ngram`]).
    pub async fn match_terms(
        &self,
        text: &str,
        descriptor: &str,
        options: &MatchOptions,
    ) -> Result<MatchTerm, TermError> {
        let mask = options.validate()?;
        let tokens = tokenize::tokenize(text, options.tokenizer, options.downcase);
        if tokens.is_empty() {
            return Err(TermError::EmptyTermText);
        }
        let context = PrfContext::pae(&[MATCH_DOMAIN, descriptor.as_bytes()]);

        tokens
            .prf_visit_with_context(
                self.prf.clone(),
                context,
                BloomVisitor { k: options.k, mask },
            )
            .await
            .map_err(TermError::from_prf)
    }

    /// Generate an order-revealing (CLLW ORE) term for a range-queryable value
    /// under the field `descriptor`. The ORE key is derived through the PRF
    /// from the descriptor alone — the plaintext never enters the PRF.
    ///
    /// Supported inputs: `u16`/`u32`/`u64`/`u128`, `&str`, `&[u8]` (via
    /// [`CllwOreEncrypt`]).
    pub async fn ore_term<T>(&self, value: T, descriptor: &str) -> Result<T::Output, TermError>
    where
        T: CllwOreEncrypt,
    {
        let key = self.derive_cllw_key(ORE_KEY_DOMAIN, descriptor).await?;
        value.encrypt(&key).map_err(TermError::Ore)
    }

    /// Generate an order-preserving (CLLW OPE) term: ciphertexts compare with
    /// plain lexicographic byte order, no custom comparator required.
    /// Encrypt-only — pair with the record ciphertext for round-trips.
    pub async fn ope_term<T>(&self, value: T, descriptor: &str) -> Result<T::Output, TermError>
    where
        T: CllwOpeEncrypt,
    {
        let key = self.derive_cllw_key(OPE_KEY_DOMAIN, descriptor).await?;
        value.encrypt_ope(&key).map_err(TermError::Ore)
    }

    /// Derive a per-descriptor CLLW key: PRF of the descriptor under a
    /// PAE-encoded `[domain, descriptor]` context — the same framing every
    /// other term kind uses (see the module docs), so no reimplementation of
    /// this derivation can collide with an equality or match derivation.
    /// Deterministic, so write-time and query-time terms agree; under a
    /// 2-party PRF backend this derivation is a visible ZeroKMS event.
    async fn derive_cllw_key(
        &self,
        domain: &'static [u8],
        descriptor: &str,
    ) -> Result<cllw_ore::Key, TermError> {
        let context = PrfContext::pae(&[domain, descriptor.as_bytes()]);
        let mut block = descriptor
            .prf_with_context(self.prf.clone(), context)
            .await
            .map_err(TermError::from_prf)?;
        // `Key` wipes itself on drop; wipe the stack copy the move leaves
        // behind ([u8; 32] is `Copy`).
        let key = cllw_ore::Key::from(block);
        block.zeroize();
        Ok(key)
    }
}
