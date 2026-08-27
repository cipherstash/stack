//! Searchable Encrypted Metadata (SEM) term generation.
//!
//! [`StackCipher`] produces the index terms stored alongside a
//! [`StackCipherText`](crate::StackCipherText) so encrypted values can be
//! queried without decryption:
//!
//! * **Equality terms** ([`StackCipher::equality_term`]) — a PRF of the whole
//!   value; supports exact-match queries.
//! * **Match terms** ([`StackCipher::match_terms`]) — the value is tokenized
//!   locally, each token is PRF'd, and the outputs fold into Bloom-filter bit
//!   positions; supports full-text match queries.
//! * **ORE / OPE terms** ([`StackCipher::ore_term`] /
//!   [`StackCipher::ope_term`]) — CLLW order-revealing / order-preserving
//!   ciphertexts produced *inside the PRF visitor* from a per-descriptor key
//!   derived through the PRF; support range queries.
//!
//! # PRF backends, visitors, and the 2-party future
//!
//! The PRF backend produces **blocks**; a [`PrfVisitor`] shapes blocks into
//! the term (`EqualityVisitor`, `BloomVisitor`, `OreVisitor`, `OpeVisitor` —
//! all private). The shaping is pure and synchronous by construction: only
//! the block production can involve I/O, so a visitor never knows which side
//! of a round-trip it runs on. All pure work — option validation,
//! tokenization, context framing — happens *before* the PRF is invoked.
//!
//! Every term method awaits its PRF output ([`Prf::Ok`](vitaminc_prf::Prf::Ok)
//! is `IntoFuture`). The backend today is the local
//! [`HmacSha256Prf`](vitaminc_hmac::HmacSha256Prf), keyed by the deterministic
//! per-keyset [`IndexKey`](stack_kms::IndexKey) the cipher loads during
//! construction, so outputs are immediately ready. The next ZeroKMS release
//! adds 2-party PRF generation: that backend returns deferred outputs resolved
//! by a server round-trip, and it slots in without touching any shaping code —
//! the same visitor runs over the blocks the server returns, and every
//! derivation is already behind an `await`.
//!
//! This is also why ORE/OPE *keys* are derived through the PRF (from the field
//! descriptor, never the plaintext): under a 2-party backend, per-field key
//! derivation becomes a visible, auditable ZeroKMS event while plaintext stays
//! local.
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
//! This is a fresh term format: PRF inputs are framed with vitaminc's PAE
//! context encoding, so terms are intentionally **not** byte-compatible with
//! `cipherstash-client`'s existing `IndexTerm` values.

mod tokenize;

pub use tokenize::Tokenizer;

use cllw_ore::{CllwOpeEncrypt, CllwOreEncrypt};
use vitaminc_prf::{
    BlockVisitor, MapAccess, PrfContext, PrfError, PrfValue, PrfVisitor, PrfVisitorError, SeqAccess,
};
use zeroize::Zeroize;

use crate::StackCipher;

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

/// A [`PrfVisitor`] that wraps one PRF block as an [`EqualityTerm`].
struct EqualityVisitor;

impl<P: Send + 'static> PrfVisitor<[u8; 32], P> for EqualityVisitor {
    type Value = EqualityTerm;

    fn visit_block(self, block: [u8; 32]) -> Result<Self::Value, PrfVisitorError> {
        Ok(EqualityTerm(block))
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
    /// query. [`StackCipher::match_terms`] already refuses to build such a
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
    type Value = MatchTerm;

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
        Ok(MatchTerm { positions })
    }

    // A map-shaped input is not a token stream.
    fn visit_map(self, _map: MapAccess<[u8; 32], P>) -> Result<Self::Value, PrfVisitorError> {
        Err(PrfVisitorError::UnexpectedShape)
    }
}

/// A [`PrfVisitor`] that carries the plaintext in and hands the CLLW ORE
/// ciphertext out. The PRF block becomes the CLLW [`Key`](cllw_ore::Key)
/// *inside* `visit_block` and dies there: the block arrives by value, is moved
/// into the `ZeroizeOnDrop` key, the stack copy left behind (`[u8; 32]` is
/// `Copy`) is wiped, the value is encrypted, and only the ciphertext leaves.
/// No key is ever returned to the caller.
///
/// This is the shape a 2-party PRF needs: the caller supplies a PRF input
/// (the descriptor) and receives a term, and where the key comes from — or
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

/// Term generation on the cipher itself: every [`StackCipher`] carries the PRF
/// keyed by its keyset's index key, so the same handle that seals a value
/// derives the terms stored beside it, and a query builder holding a cipher
/// derives probe terms with no data-key traffic at all.
///
/// Terms are deterministic: the same value and descriptor yield the same term
/// at write time and at query time. They are pseudorandom under the index key
/// and are stored server-side — they are not secret key material.
impl<K> StackCipher<K> {
    /// Generate an equality (exact-match) term for `value` under the field
    /// `descriptor`.
    pub async fn equality_term<T>(
        &self,
        value: T,
        descriptor: &str,
    ) -> Result<EqualityTerm, TermError>
    where
        T: PrfValue,
    {
        let context = PrfContext::pae(&[EQUALITY_DOMAIN, descriptor.as_bytes()]);
        value
            .prf_visit_with_context(self.prf().clone(), context, EqualityVisitor)
            .await
            .map_err(TermError::from_prf)
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
                self.prf().clone(),
                context,
                BloomVisitor { k: options.k, mask },
            )
            .await
            .map_err(TermError::from_prf)
    }

    /// Generate an order-revealing (CLLW ORE) term for a range-queryable value
    /// under the field `descriptor`. The PRF input is the descriptor alone —
    /// the plaintext never enters the PRF; it travels in the visitor, which
    /// derives the per-descriptor CLLW key from the PRF block and encrypts
    /// under it in one step (`OreVisitor`). The key never leaves the
    /// visitor.
    ///
    /// The derivation is deterministic, so write-time and query-time terms
    /// agree; under a 2-party PRF backend it is a visible ZeroKMS event. The
    /// PRF context is PAE-encoded `[domain, descriptor]` — the same framing
    /// every other term kind uses (see the module docs), so no reimplementation
    /// of this derivation can collide with an equality or match derivation.
    ///
    /// Supported inputs: `u16`/`u32`/`u64`/`u128`, `&'static str`, `String`,
    /// `Vec<u8>` (via [`CllwOreEncrypt`]). The value must be owned
    /// (`'static`) because the visitor carries it; pass a `String` for
    /// borrowed text.
    pub async fn ore_term<T>(&self, value: T, descriptor: &str) -> Result<T::Output, TermError>
    where
        T: CllwOreEncrypt + Send + 'static,
        T::Output: Send + 'static,
    {
        let context = PrfContext::pae(&[ORE_KEY_DOMAIN, descriptor.as_bytes()]);
        descriptor
            .prf_visit_with_context(self.prf().clone(), context, OreVisitor(value))
            .await
            .map_err(TermError::from_prf)?
            .map_err(TermError::Ore)
    }

    /// Generate an order-preserving (CLLW OPE) term: ciphertexts compare with
    /// plain lexicographic byte order, no custom comparator required.
    /// Encrypt-only — pair with the record ciphertext for round-trips. Key
    /// handling and input bounds as for [`ore_term`](Self::ore_term); the OPE
    /// key derives under its own domain so the two schemes never share one.
    pub async fn ope_term<T>(&self, value: T, descriptor: &str) -> Result<T::Output, TermError>
    where
        T: CllwOpeEncrypt + Send + 'static,
        T::Output: Send + 'static,
    {
        let context = PrfContext::pae(&[OPE_KEY_DOMAIN, descriptor.as_bytes()]);
        descriptor
            .prf_visit_with_context(self.prf().clone(), context, OpeVisitor(value))
            .await
            .map_err(TermError::from_prf)?
            .map_err(TermError::Ore)
    }
}
