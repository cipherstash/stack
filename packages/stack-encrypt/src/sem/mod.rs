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
//! * [`MatchTerms`] — the value is tokenized locally, each token is PRF'd, and
//!   the outputs fold into Bloom-filter bit positions; full-text match
//!   queries. Tokenizer/filter parameters are a *type-level* config
//!   ([`MatchConfig`]) so write-time and query-time terms agree by
//!   construction.
//! * [`OreTerm`] / [`OpeTerm`] — CLLW order-revealing / order-preserving
//!   ciphertexts produced *inside the PRF visitor* from a per-context key
//!   derived through the PRF; range queries. A `Between` query sends both
//!   bounds' terms as one [`RangeQuery`].
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
//! * [`MatchTerms`] — the sorted, de-duplicated bit positions, each a
//!   little-endian `u16` ([`to_bytes`](MatchTerms::to_bytes) /
//!   [`from_bytes`](MatchTerms::from_bytes)).
//! * [`OreTerm`] / [`OpeTerm`] — the raw CLLW ciphertext bytes, unframed
//!   ([`as_bytes`](OreTerm::as_bytes) / [`to_bytes`](OreTerm::to_bytes) /
//!   [`from_bytes`](OreTerm::from_bytes)).
//!
//! Every kind decodes through `TryFrom<&[u8]>` as well, failing with a
//! [`TermBytesError`]; [`EqualityTerm`] additionally keeps an infallible
//! [`from_bytes`](EqualityTerm::from_bytes) over a `[u8; 32]`. `as_bytes`
//! exists only where the term *is* a contiguous buffer (equality, ORE, OPE);
//! a [`MatchTerms`] is canonically a position list, so it has none.
//!
//! For equality and ORE/OPE the transport bytes are also the stored form,
//! and they share the *shape* of the v1 / `cipherstash-client` encodings — a
//! 32-byte HMAC for equality, raw CLLW bytes for ORE/OPE, the same bytes EQL
//! hex-encodes into its `hm` / `oc` / `op` fields with its hex and JSON
//! framing sitting *above* them. A match term is the exception: what is
//! stored and queried is the position list
//! ([`positions`](MatchTerms::positions)), which maps to an integer-array
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

use std::collections::HashSet;
use std::fmt;
use std::marker::PhantomData;

// Re-exported because they appear in this module's public bounds
// ([`KeysetCipher::ore_term`], [`OreTerm`], ...): a caller writing a generic
// wrapper over the term APIs has to be able to name them without depending
// on `cllw-ore` directly.
pub use cllw_ore::{CllwOpeEncrypt, CllwOreEncrypt};
use vitaminc_aead::Encrypt;
use vitaminc_hmac::HmacSha256Prf;
use vitaminc_normalize::{terms, NormalizeError, Normalized};
use vitaminc_prf::{
    BlockVisitor, Context, IntoPrfContext, MapAccess, PrfError, PrfValue, PrfVisitor,
    PrfVisitorError, SeqAccess,
};
use vitaminc_protected::NonEmpty;
use zeroize::{Zeroize, Zeroizing};

use stack_kms::MaybeSend;

use crate::target::core::Term;
use crate::target::{DecryptField, Decryptable, Decryption};
use crate::{Error, KeysetCipher, Pending};

// The version suffix (`/v1`, `/v2`) versions the *derivation* (domain +
// input framing), not the crate. Any change to the bytes a term derives from must bump it: a changed
// derivation under an unchanged domain makes every existing term silently
// unfindable, with no error to notice. The byte-level pins in
// `tests/term_bytes.rs` are what force that bump to be deliberate.

/// PAE domain for equality (exact-match) terms.
///
/// `v2`: the PRF input is the value's `vitaminc-normalize` encoding under
/// its domain, where `v1` was the value's own PRF encoding.
const EQUALITY_DOMAIN: &[u8] = b"stack-encrypt/sem/equality/v2";
/// PAE domain for match (full-text) token terms.
///
/// `v2`: the text is tokenized in Unicode 16 NFC, where `v1` tokenized it as
/// written.
const MATCH_DOMAIN: &[u8] = b"stack-encrypt/sem/match/v2";
/// PAE domain for ORE key derivation.
const ORE_KEY_DOMAIN: &[u8] = b"stack-encrypt/sem/ore-key/v1";
/// PAE domain for OPE key derivation (distinct from ORE: OPE ciphertexts are
/// encrypt-only, so the two schemes must never share a key).
const OPE_KEY_DOMAIN: &[u8] = b"stack-encrypt/sem/ope-key/v1";

/// Errors from SEM term generation.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum TermError {
    /// The PRF backend failed (for a remote 2-party backend this includes
    /// transport errors). The backend's error is the
    /// [`source`](std::error::Error::source), not part of this message: it
    /// is another library's text.
    #[error("PRF failed")]
    #[diagnostic(code(stack_encrypt::prf_failed))]
    Prf(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// CLLW ORE/OPE encryption failed. (`cllw_ore::Error` is deliberately
    /// contentless, so its message is fixed text.)
    #[error("ORE/OPE encryption failed: {0}")]
    #[diagnostic(code(stack_encrypt::ore_failed))]
    Ore(#[from] cllw_ore::Error),
    /// The supplied [`MatchOptions`] are invalid.
    #[error("invalid match options: {0}")]
    #[diagnostic(code(stack_encrypt::invalid_match_options))]
    InvalidOptions(&'static str),
    /// A match query's text produced no tokens under the index's tokenizer:
    /// empty or separator-only text, or (for n-grams, as in the v1 match
    /// indexer) text shorter than the n-gram length. A query with no tokens
    /// would match every row, so the query chain refuses it when the query
    /// is awaited, before a term exists. A *stored* value with no tokens is
    /// not refused: it is stored as the empty filter, which no query
    /// matches, so a short or empty value is a valid thing to hold in a
    /// match column (ADR-0009).
    #[error(
        "the query's text produces no match tokens (empty, separator-only, or shorter than the n-gram length)"
    )]
    #[diagnostic(
        code(stack_encrypt::empty_term_text),
        help("A match query needs text with at least one token: a query with none would match every row, and one shorter than the n-gram length could match none. Query on longer text, or leave the match condition out.")
    )]
    EmptyTermText,
    /// A `Between` query's low bound is above its high bound, so the range
    /// holds nothing. Refused when the query is awaited, before a term
    /// exists. The range is inclusive at both ends, so equal bounds are one
    /// value, not an error.
    #[error("the range's low bound is above its high bound")]
    #[diagnostic(
        code(stack_encrypt::inverted_range),
        help("Give `op::Between` its bounds as `(lo, hi)` with `lo <= hi`. The range is inclusive at both ends, so one value is `(v, v)`.")
    )]
    InvertedRange,
    /// The value is not one scalar an equality term is defined for: a
    /// null, a boolean, a container, or a value of a logical type vitaminc
    /// gives no equality domain. Equality derives over one scalar, in the
    /// domain `vitaminc-normalize` gives its kind (every integer width one
    /// domain, both float widths one, text, bytes, and the dates,
    /// timestamps, decimals and uuids that opt in); there is no term for
    /// anything else.
    #[error("no equality term is defined for this value")]
    #[diagnostic(
        code(stack_encrypt::no_equality_term),
        help("An equality term is defined for one integer, float, text, bytes, date, timestamp, decimal or uuid value, not for a boolean, a null or a container.")
    )]
    NoEqualityTerm,
    /// No order term (ORE or OPE) is defined for a boolean: with two values,
    /// an order term would tell anyone holding the column which rows are
    /// `true`. Refused on the typed path as the dynamic path refuses it
    /// (`dynamic::admits`).
    #[error("no order term is defined for a boolean")]
    #[diagnostic(
        code(stack_encrypt::no_order_term),
        help("A boolean column cannot be ordered without revealing which rows are true. Store it with no order index, and with no equality index either: a boolean has no equality term.")
    )]
    NoOrderTerm,
    /// The value cannot be normalized for its term: text with a code point
    /// unassigned in Unicode 16 (an equality or match term), or a value not
    /// valid for its logical type. The reason is vitaminc's, and names no
    /// part of the value.
    #[error("the value cannot be normalized for its term: {0}")]
    #[diagnostic(code(stack_encrypt::term_normalize))]
    Normalize(#[from] NormalizeError),
    /// Term bytes do not decode under the term kind's frozen encoding — see
    /// [`TermBytesError`].
    #[error(transparent)]
    #[diagnostic(transparent)]
    Bytes(#[from] TermBytesError),
}

impl crate::ErrorPayload for TermError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            Self::Bytes(error) => error.payload(),
            Self::Prf(_)
            | Self::Ore(_)
            | Self::InvalidOptions(_)
            | Self::EmptyTermText
            | Self::InvertedRange
            | Self::NoEqualityTerm
            | Self::NoOrderTerm
            | Self::Normalize(_) => serde_json::Map::new(),
        }
    }
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
///
/// No message carries a byte of the term: lengths and the filter size only.
#[derive(Debug, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum TermBytesError {
    /// Equality-term bytes are not the 32 PRF bytes.
    #[error("equality-term bytes must be exactly 32 bytes, got {0}")]
    #[diagnostic(code(stack_encrypt::equality_term_length))]
    WrongEqualityTermLength(usize),
    /// Match-term bytes are not a whole number of little-endian `u16`
    /// positions.
    #[error("match-term bytes must be little-endian u16 positions, got an odd length of {0}")]
    #[diagnostic(code(stack_encrypt::match_term_length))]
    OddMatchTermsLength(usize),
    /// A decoded position lies outside the Bloom filter the term's
    /// [`MatchConfig`] fixes. Genuine positions are always masked into
    /// `0..m`, so an out-of-range one means the bytes were not written by
    /// this encoding — a wrong-endian decoder, most often, which would
    /// otherwise decode cleanly and then silently never match.
    ///
    /// `position` is kept for a caller in this process; the message leaves
    /// it out, since it is a value read from the term's bytes.
    #[error("a match position is outside the {filter_size}-bit filter")]
    #[diagnostic(
        code(stack_encrypt::match_position_out_of_range),
        help("The bytes were not written by this match-term encoding: check they are little-endian, and decoded under the same match options they were derived with.")
    )]
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
    #[diagnostic(code(stack_encrypt::cllw_ciphertext_length))]
    MalformedCllwCiphertext(usize),
}

impl crate::ErrorPayload for TermBytesError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        use crate::diagnostic::payload;
        match self {
            Self::WrongEqualityTermLength(len)
            | Self::OddMatchTermsLength(len)
            | Self::MalformedCllwCiphertext(len) => payload([("len", (*len).into())]),
            Self::MatchPositionOutOfRange { filter_size, .. } => {
                payload([("filter_size", (*filter_size).into())])
            }
        }
    }
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

/// An equality (exact-match) index term: one PRF block over the value's
/// normalized bytes (see [`KeysetCipher::equality_term`]).
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
///
/// The value is normalized first, by `vitaminc-normalize`'s [`terms`] sink:
/// it must be one scalar with an equality domain, and the PRF derives over
/// that scalar's [`Normalized`] bytes under its domain. So every integer
/// width of one number is one term, both float widths of one number are
/// one term, and text is compared in Unicode 16 NFC: `café` written with a
/// precomposed `é` and with `e` and a combining accent is one term.
fn equality<T>(
    prf: &HmacSha256Prf,
    value: T,
    context: Context<'_>,
) -> Result<EqualityTerm, TermError>
where
    T: Encrypt,
{
    equality_of_normalized(prf, normalized(value)?, context)
}

/// The equality term of a scalar already normalized: the PRF over its
/// bytes, under its `vitaminc-normalize` domain and the PAE-framed
/// `[EQUALITY_DOMAIN, context]`. [`equality`] and the `dynamic` path, which
/// normalizes the one scalar it walks to, both end here.
fn equality_of_normalized(
    prf: &HmacSha256Prf,
    normalized: Normalized,
    context: Context<'_>,
) -> Result<EqualityTerm, TermError> {
    let context = Context::pae(&[EQUALITY_DOMAIN, context.as_bytes()]);
    normalized
        .prf_visit_with_context(prf, context, EqualityVisitor)
        .into_result()
        .map_err(TermError::from_prf)
}

/// The one [`Normalized`] scalar of a value, as `vitaminc-normalize`'s
/// [`terms`] sink derives it: [`TermError::NoEqualityTerm`] unless the value
/// is one scalar with an equality domain, and [`TermError::Normalize`] for a
/// scalar the sink refuses (text with a code point unassigned in Unicode 16,
/// a value not valid for its logical type).
pub(crate) fn normalized<T: Encrypt>(value: T) -> Result<Normalized, TermError> {
    let mut terms = terms(value).map_err(|error| match error.term() {
        Some(refused) => TermError::Normalize(refused.error()),
        // A shape refusal or a source failure: not one scalar the sink could
        // read, so there is no term.
        None => TermError::NoEqualityTerm,
    })?;
    match (terms.pop(), terms.is_empty()) {
        // One term, and at the root: the value is that scalar. A container
        // with one indexable scalar inside is not a scalar, and a null or a
        // boolean produces no term at all.
        (Some(term), true) if term.path.steps().is_empty() => Ok(term.normalized),
        _ => Err(TermError::NoEqualityTerm),
    }
}

/// An equality term of any [`Encrypt`] source that is one scalar with an
/// equality domain (see [`equality`]). Under the local HMAC backend,
/// derived during the synchronous build — the returned [`Pending`] carries
/// no requests.
impl<'c, S, K, T> Term<S, K, NonEmpty<T>> for EqualityTerm
where
    S: Encrypt,
    T: IntoPrfContext<'c>,
{
    // Derived locally: no data key, no descriptor.

    fn encrypt_from<'a>(
        source: S,
        cipher: &'a KeysetCipher<'_, K>,
        context: NonEmpty<T>,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        let context = context.into_prf_context().into_owned();
        let term = equality(cipher.prf(), source, context).map_err(Error::from);
        Pending::ready(cipher, term)
    }
}

// =============================================================================
// Match
// =============================================================================

/// Options controlling match-term generation. The defaults mirror the existing
/// match indexer: 3-gram tokens, downcased, `k = 3` hash slices into an
/// `m = 256`-bit filter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    pub(crate) fn validate(&self) -> Result<u16, TermError> {
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

/// Type-level match configuration: the [`MatchOptions`] a [`MatchTerms<Self>`]
/// is generated with. Putting the configuration on the *type* means a record
/// field and the query probing it agree on tokenizer and filter parameters by
/// construction. Define your own by implementing this on a marker type.
pub trait MatchConfig: Send + Sync + 'static {
    fn options() -> MatchOptions;

    /// The typical number of distinct tokens in a value this index stores:
    /// 20 for a name column, 200 for a notes column. A prior, used to size a query's
    /// fetch ([`Stats::declared`](crate::op::Stats::declared)) before the
    /// column's filters have been measured. It is not part of the index's
    /// identity and changes no term. `None`, the default, declares no
    /// prior.
    fn expected_tokens() -> Option<u32> {
        None
    }
}

/// The default [`MatchConfig`]: [`MatchOptions::default`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DefaultMatch;

impl MatchConfig for DefaultMatch {
    fn options() -> MatchOptions {
        MatchOptions::default()
    }
}

/// The match (full-text) terms of a value: the set bit positions of a Bloom
/// filter over the PRF outputs of the value's tokens, generated under the
/// [`MatchConfig`] `O`. Positions are sorted and de-duplicated.
///
/// The name is plural because the value is a *set*: every token contributes
/// `k` positions, and a query matches when its positions are a subset of the
/// stored ones ([`contains`](Self::contains)). An equality or ORE term is one
/// comparand; this is many. (It was named `MatchTerm` in stack-encrypt 0.2.)
pub struct MatchTerms<O = DefaultMatch> {
    positions: Vec<u16>,
    _config: PhantomData<fn() -> O>,
}

/// Renamed to [`MatchTerms`]: the value is a set of terms, not one.
#[deprecated(since = "0.3.0", note = "renamed to `MatchTerms`")]
pub type MatchTerm<O = DefaultMatch> = MatchTerms<O>;

impl<O> MatchTerms<O> {
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
    /// vacuously true, which would turn an empty query into a match-every-row
    /// query. A query chain already refuses to build such a query
    /// ([`TermError::EmptyTermText`]); this guards any other (e.g.
    /// deserialized) source of an empty one. The stored side is the other
    /// way round: a value with no tokens is stored as the empty filter, and
    /// holds no query's positions, so no query matches it.
    pub fn matches(&self, query: &MatchQuery<O>) -> bool {
        self.contains(query.filter())
    }

    /// Whether this term's positions are a superset of `other`'s, for two
    /// stored terms: `other` is a filter over a whole stored value, not a
    /// query. [`matches`](Self::matches) is the check for a query, and the
    /// only one that takes a [`MatchQuery`].
    ///
    /// An empty `other` returns `false`, as an empty query does.
    pub fn contains(&self, other: &MatchTerms<O>) -> bool {
        !other.positions.is_empty()
            && other
                .positions
                .iter()
                .all(|p| self.positions.binary_search(p).is_ok())
    }
}

/// Rebuilding a term needs the [`MatchConfig`]: it fixes the filter size `m`
/// every genuine position is below, and a position outside it is a decoding
/// bug rather than a term.
impl<O: MatchConfig> MatchTerms<O> {
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
            return Err(TermBytesError::OddMatchTermsLength(bytes.len()));
        }
        Self::from_positions(
            bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect(),
        )
    }
}

/// [`MatchTerms::from_bytes`] as a std conversion — the same decoder.
impl<O: MatchConfig> TryFrom<&[u8]> for MatchTerms<O> {
    type Error = TermBytesError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

impl<O> fmt::Debug for MatchTerms<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MatchTerms")
            .field("positions", &self.positions)
            .finish()
    }
}

impl<O> Clone for MatchTerms<O> {
    fn clone(&self) -> Self {
        Self::normalised(self.positions.clone())
    }
}

impl<O> PartialEq for MatchTerms<O> {
    fn eq(&self, other: &Self) -> bool {
        self.positions == other.positions
    }
}

impl<O> Eq for MatchTerms<O> {}

/// The query term of a match index: a Bloom filter over the *query's*
/// tokens, where the stored [`MatchTerms`] is a filter over the whole
/// stored value's. A row matches when its stored filter holds every position of
/// the query's ([`MatchTerms::matches`]).
///
/// The two are different types because they are different things, even
/// where their bytes share an encoding: a query is never stored, and a
/// stored filter is never sent as a query. ADR-0009 records why. A
/// `MatchQuery` comes from a query chain ([`op::Matches`](struct@crate::op::Matches)),
/// never from a target.
///
/// A Bloom filter can hold every bit of the query without the value holding
/// the query's text, so a match query is
/// [`Probabilistic`](crate::op::Probabilistic): it keeps the query's tokens,
/// as the index cut them, and [`verify`](crate::op::Probabilistic::verify)
/// checks a decrypted value against them. The tokens are plaintext: they
/// never leave the process, never appear in `Debug`, and are zeroized when
/// the query is dropped.
pub struct MatchQuery<O = DefaultMatch> {
    terms: MatchTerms<O>,
    tokens: QueryTokens,
}

impl<O> MatchQuery<O> {
    /// The query term of the filter `terms`, derived over the value whose
    /// tokens are `tokens`.
    pub(crate) fn new(terms: MatchTerms<O>, tokens: QueryTokens) -> Self {
        Self { terms, tokens }
    }

    /// The set positions of the query's filter, sorted ascending, no
    /// duplicates: what the server tests a stored filter for.
    pub fn positions(&self) -> &[u16] {
        self.terms.positions()
    }

    /// The transport byte encoding, as [`MatchTerms::to_bytes`].
    pub fn to_bytes(&self) -> Vec<u8> {
        self.terms.to_bytes()
    }

    /// The query's filter.
    pub(crate) fn filter(&self) -> &MatchTerms<O> {
        &self.terms
    }
}

/// A row is a real match when every token of the query is a token of the
/// value, cut by the index's own tokenizer and case folding. That is the
/// meaning a Bloom match approximates, so `verify` keeps every row the
/// filter would have kept had it no false positives: order and repetition
/// do not count, and a match is not a substring test.
impl<O: MatchConfig> crate::op::Probabilistic for MatchQuery<O> {
    type Plaintext = str;

    fn verify(&self, value: &str) -> bool {
        self.tokens.verify(value, &O::options())
    }

    /// `want` plus the false positives expected among the rows `stats`
    /// scans: the query sets `b` bits ([`positions`](Self::positions)), and
    /// a stored filter of fill `f` holds them all with probability `f^b`.
    /// The fill comes from the measured histogram in `stats`, or else from
    /// the configuration's
    /// [`expected_tokens`](MatchConfig::expected_tokens) prior; with
    /// neither, the answer is
    /// [`Limit::Unbounded`](crate::op::Limit::Unbounded).
    fn target_limit(&self, want: u64, stats: &crate::op::Stats) -> crate::op::Limit {
        match_limit(
            self.positions().len(),
            &O::options(),
            O::expected_tokens(),
            want,
            stats,
        )
    }
}

/// Positions only: the tokens are plaintext.
impl<O> fmt::Debug for MatchQuery<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MatchQuery")
            .field("positions", &self.terms.positions)
            .finish_non_exhaustive()
    }
}

impl<O> Clone for MatchQuery<O> {
    fn clone(&self) -> Self {
        Self {
            terms: self.terms.clone(),
            tokens: self.tokens.clone(),
        }
    }
}

/// Two queries are equal when they send the same filter. This compares no
/// plaintext. Two query values can share a filter by chance, as a short
/// value under a small filter does, and those queries are equal here yet
/// verify differently: equal queries select the same rows, not the same
/// matches.
impl<O> PartialEq for MatchQuery<O> {
    fn eq(&self, other: &Self) -> bool {
        self.terms == other.terms
    }
}

impl<O> Eq for MatchQuery<O> {}

/// The query term of [`op::Between`](crate::op::Between): the index's
/// terms for both bounds, as one value. Inclusive at both ends.
///
/// One query derives both bounds under one context, and the term stays
/// one value in SQL (ADR-0009, decision 7), so no statement can pair the
/// low bound of one query with the high bound of another, or bind them the
/// wrong way round. `T` is the index's term: `OreTerm<u32>` for a range
/// over an ORE index of `u32`, `OpeTerm<i64>` over an OPE index. The
/// bounds are read with [`lo`](Self::lo) and [`hi`](Self::hi), each the
/// term the index would send for that value alone, which is how a query
/// domain that carries a range serialises it.
///
/// It comes only from a query chain: a range is never stored, and the
/// chain refuses one whose low bound is above its high bound
/// ([`TermError::InvertedRange`]) before either term is derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeQuery<T> {
    lo: T,
    hi: T,
}

impl<T> RangeQuery<T> {
    /// The range `lo..=hi`, from the index's terms for its bounds.
    pub(crate) fn new(lo: T, hi: T) -> Self {
        Self { lo, hi }
    }

    /// The term of the low bound, inclusive.
    pub fn lo(&self) -> &T {
        &self.lo
    }

    /// The term of the high bound, inclusive.
    pub fn hi(&self) -> &T {
        &self.hi
    }

    /// The two bounds' terms, low then high.
    pub fn into_bounds(self) -> (T, T) {
        (self.lo, self.hi)
    }
}

/// The query's tokens, as a match index cuts them from the query's value:
/// a match query's verifier, which a [`MatchQuery`] keeps to verify a row. Plaintext, so it is
/// zeroized on drop and has no `Debug`.
/// [`Supports::verifier`](crate::op::Supports::verifier) makes one; only a query
/// chain can join it to a filter
/// ([`Supports::query`](crate::op::Supports::query) takes a token no caller
/// can make), so one query's tokens never verify rows for another value's
/// filter.
#[derive(Clone, Default)]
pub struct QueryTokens(Zeroizing<Vec<String>>);

impl QueryTokens {
    /// The tokens of `text` under `O`'s tokenizer and case folding.
    ///
    /// # Errors
    ///
    /// [`TermError::Normalize`] for text the index cannot normalize (a code
    /// point unassigned in Unicode 16).
    pub(crate) fn of<O: MatchConfig>(text: &str) -> Result<Self, TermError> {
        Self::under(text, &O::options())
    }

    /// The tokens of `text` under `options`' tokenizer and case folding.
    ///
    /// # Errors
    ///
    /// As for [`of`](Self::of).
    pub(crate) fn under(text: &str, options: &MatchOptions) -> Result<Self, TermError> {
        Ok(Self(Zeroizing::new(tokenize::tokens(
            text,
            options.tokenizer,
            options.downcase,
        )?)))
    }

    /// The tokens of a query's `text` under `options`, or why the query is
    /// refused: options the index cannot use
    /// ([`TermError::InvalidOptions`]), checked before the text is
    /// tokenised, or text that cuts no token ([`TermError::EmptyTermText`]),
    /// whose filter would match every row. The one rule for a match query:
    /// the query chain and the `dynamic` path both apply it, so they cannot
    /// disagree on what they refuse. The stored side keeps token-less text
    /// as the empty filter instead.
    pub(crate) fn of_query(text: &str, options: &MatchOptions) -> Result<Self, TermError> {
        let _mask = options.validate()?;
        let tokens = Self::under(text, options)?;
        if tokens.0.is_empty() {
            return Err(TermError::EmptyTermText);
        }
        Ok(tokens)
    }

    /// Whether `value` holds every one of these tokens, cut under the same
    /// `options` the tokens were: what [`MatchQuery`]'s `verify` asks, with
    /// the options a value rather than a type, so a match index declared as
    /// data verifies by the same code. No tokens verify nothing, and a value
    /// the index cannot normalize holds no token of any query.
    pub(crate) fn verify(&self, value: &str, options: &MatchOptions) -> bool {
        let Ok(tokens) = tokenize::tokens(value, options.tokenizer, options.downcase) else {
            return false;
        };
        let tokens = Zeroizing::new(tokens);
        let have: HashSet<&str> = tokens.iter().map(String::as_str).collect();
        !self.0.is_empty() && self.0.iter().all(|t| have.contains(t.as_str()))
    }
}

/// The fetch for `want` real matches of a match query whose filter sets
/// `bits` positions, under `options` and the index's `expected_tokens`
/// prior: what [`MatchQuery`]'s `target_limit` answers, with the options a
/// value rather than a type, so a match index declared as data sizes its
/// fetch by the same code.
pub(crate) fn match_limit(
    bits: usize,
    options: &MatchOptions,
    expected_tokens: Option<u32>,
    want: u64,
    stats: &crate::op::Stats,
) -> crate::op::Limit {
    let declared =
        expected_tokens.map(|tokens| crate::op::stats::expected_fill(tokens, options.k, options.m));
    let bits = u32::try_from(bits).unwrap_or(u32::MAX);
    stats.limit(want, stats.pass_rate(bits, options.m, declared))
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
            // the same `k` positions, which is what `MatchTerms::contains` tests.
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
///
/// Text that cuts no token (empty, separator-only, or shorter than the
/// n-gram length) is the empty filter: no position set, no PRF call. Stored,
/// it is a value no query matches, since a query always has at least one
/// token and the empty filter holds none of its positions. This is the
/// *stored* side's answer; a query of such text is refused by the query
/// chain before it gets here ([`TermError::EmptyTermText`]).
fn match_term<O>(
    prf: &HmacSha256Prf,
    text: &str,
    context: Context<'_>,
    options: MatchOptions,
) -> Result<MatchTerms<O>, TermError> {
    let mask = options.validate()?;
    let tokens = tokenize::tokens(text, options.tokenizer, options.downcase)?;
    if tokens.is_empty() {
        return Ok(MatchTerms::normalised(Vec::new()));
    }
    let context = Context::pae(&[MATCH_DOMAIN, context.as_bytes()]);

    // The PRF takes the tokens by value and moves each `String`'s buffer
    // into a `Protected`, which zeroizes it on drop: the tokens are wiped
    // there, not here. The `Vec` itself holds only their pointers.

    let positions = tokens
        .prf_visit_with_context(prf, context, BloomVisitor { k: options.k, mask })
        .into_result()
        .map_err(TermError::from_prf)?;
    // Every position came out of the visitor masked to `m - 1`, so the range
    // check `from_positions` applies is already satisfied by construction.
    Ok(MatchTerms::normalised(positions))
}

/// A match term of any text source, generated under `O`'s options. Under
/// the local HMAC backend, derived during the synchronous build — the
/// returned [`Pending`] carries no requests (tokenize makes the one
/// necessary copy of the text).
impl<'c, S, K, O, T> Term<S, K, NonEmpty<T>> for MatchTerms<O>
where
    S: AsRef<str>,
    O: MatchConfig,
    T: IntoPrfContext<'c>,
{
    // Derived locally: no data key, no descriptor.

    fn encrypt_from<'a>(
        source: S,
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
index_term!(MatchTerms<O>, O: MatchConfig);
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
    refuse_bool::<T>()?;
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

/// cllw-ore orders a `bool`, and its two values would split a column into
/// its `true` and `false` rows, so no order term is derived for one, on the
/// typed path as on the dynamic one.
fn refuse_bool<T: 'static>() -> Result<(), TermError> {
    if std::any::TypeId::of::<T>() == std::any::TypeId::of::<bool>() {
        return Err(TermError::NoOrderTerm);
    }
    Ok(())
}

/// Derive an OPE term — as [`ore`], under the OPE domain so the two schemes
/// never share a key.
fn ope<T>(prf: &HmacSha256Prf, value: T, context: Context<'_>) -> Result<OpeTerm<T>, TermError>
where
    T: CllwOpeEncrypt + Send + 'static,
    T::Output: Send + 'static,
{
    refuse_bool::<T>()?;
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
    S: CllwOreEncrypt + Send + 'static,
    S::Output: Send + 'static,
    T: IntoPrfContext<'c>,
{
    // Derived locally: no data key, no descriptor.

    fn encrypt_from<'a>(
        source: S,
        cipher: &'a KeysetCipher<'_, K>,
        context: NonEmpty<T>,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        let context = context.into_prf_context().into_owned();
        let term = ore(cipher.prf(), source, context).map_err(Error::from);
        Pending::ready(cipher, term)
    }
}

/// An OPE term of any [`CllwOpeEncrypt`] source. Under the local HMAC
/// backend, derived during the synchronous build — the returned [`Pending`]
/// carries no requests.
impl<'c, S, K, T> Term<S, K, NonEmpty<T>> for OpeTerm<S>
where
    S: CllwOpeEncrypt + Send + 'static,
    S::Output: Send + 'static,
    T: IntoPrfContext<'c>,
{
    // Derived locally: no data key, no descriptor.

    fn encrypt_from<'a>(
        source: S,
        cipher: &'a KeysetCipher<'_, K>,
        context: NonEmpty<T>,
    ) -> Pending<'a, Self, K>
    where
        Self: 'a,
    {
        let context = context.into_prf_context().into_owned();
        let term = ope(cipher.prf(), source, context).map_err(Error::from);
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
    ///
    /// The value is one scalar, normalized by `vitaminc-normalize` before the
    /// PRF sees it: every integer width of one number is one term
    /// (`34u32` and `34i64` match), both float widths of one number are one
    /// term, text is compared in Unicode 16 NFC, and a date, timestamp,
    /// decimal or uuid derives in a domain of its own. A boolean, a null or
    /// a container has no term ([`TermError::NoEqualityTerm`]), and text with
    /// a code point unassigned in Unicode 16 is refused
    /// ([`TermError::Normalize`]).
    pub fn equality_term<'c, T>(
        &self,
        value: T,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
    ) -> Pending<'_, EqualityTerm, K>
    where
        T: Encrypt,
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
    /// This derives the *stored* filter. Text that yields no tokens (empty
    /// or separator-only text, or text shorter than the n-gram length; see
    /// [`Tokenizer::Ngram`]) is the empty filter, which no query matches,
    /// so a short value can be stored. A query is the other type,
    /// [`MatchQuery`], and comes from the query chain
    /// (`cipher.query(op::Matches, ..)`), which refuses a query of such
    /// text ([`TermError::EmptyTermText`]) because its filter would match
    /// every row; this method does not know which it is deriving and
    /// refuses nothing.
    pub fn match_terms<'c, O>(
        &self,
        text: &str,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
    ) -> Pending<'_, MatchTerms<O>, K>
    where
        O: MatchConfig + MaybeSend,
    {
        self.match_terms_under(text, descriptor, O::options())
    }

    /// [`equality_term`](Self::equality_term) of one scalar the caller has
    /// normalized already, for the `dynamic` path, which walks a value to
    /// its one scalar and normalizes it there, with the same
    /// `vitaminc_normalize::normalize` the typed path's sink applies.
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    pub(crate) fn equality_term_normalized<'c>(
        &self,
        normalized: Normalized,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
    ) -> Pending<'_, EqualityTerm, K> {
        let term = equality_of_normalized(self.prf(), normalized, descriptor.into_prf_context());
        Pending::ready(self, term.map_err(Error::from))
    }

    /// [`match_terms`](Self::match_terms) under runtime options, for the
    /// `dynamic` path, whose plan carries a match index's options as data
    /// (an `IndexSpec::Match`). Not public: the typed API keeps the options
    /// on the type so a stored field and its probe cannot disagree, and a
    /// binding reaches this only through a plan that names the options for
    /// both.
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    pub(crate) fn match_terms_under<'c, O>(
        &self,
        text: &str,
        descriptor: NonEmpty<impl IntoPrfContext<'c>>,
        options: MatchOptions,
    ) -> Pending<'_, MatchTerms<O>, K>
    where
        O: MatchConfig + MaybeSend,
    {
        let term = match_term(self.prf(), text, descriptor.into_prf_context(), options);
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

    #[test]
    fn a_match_query_with_no_tokens_verifies_nothing() {
        // A query chain refuses token-less text before a term exists, so
        // this cannot reach a `MatchQuery` through the API; the guard is for
        // one built any other way, which must never match every row.
        let query = MatchQuery::<DefaultMatch>::new(
            MatchTerms::normalised(vec![1, 2, 3]),
            QueryTokens(Zeroizing::new(Vec::new())),
        );
        assert!(!crate::op::Probabilistic::verify(&query, "anything at all"));
        assert!(!crate::op::Probabilistic::verify(&query, ""));
    }

    /// An equality term is one scalar's: a container, even one holding one
    /// scalar, and a scalar with no equality domain have none, and text with
    /// no normal form is refused for that reason.
    #[test]
    fn equality_is_defined_for_one_scalar_with_a_domain() {
        let prf = HmacSha256Prf::new(Protected::new([7; 32]));
        let derive = |value| equality(&prf, value, Context::empty());
        assert!(equality(&prf, 34u32, Context::empty()).is_ok());
        for (what, refused) in [
            ("a boolean", equality(&prf, true, Context::empty())),
            ("a null", equality(&prf, None::<u32>, Context::empty())),
            (
                "a sequence of one",
                equality(&prf, vec![34u32], Context::empty()),
            ),
            (
                "a map of one",
                equality(&prf, BTreeMap::from([("a", 34u32)]), Context::empty()),
            ),
            (
                "a map of two",
                equality(
                    &prf,
                    BTreeMap::from([("a", 34u32), ("b", 35u32)]),
                    Context::empty(),
                ),
            ),
        ] {
            assert!(
                matches!(refused, Err(TermError::NoEqualityTerm)),
                "{what}: {refused:?}"
            );
        }
        assert!(matches!(
            derive("a\u{378}b"),
            Err(TermError::Normalize(NormalizeError::UnassignedCodePoint))
        ));
    }

    /// A match query's one rule: options the index cannot use are refused
    /// before the text is tokenised, then text that cuts no token; text
    /// that cuts one comes back as its tokens.
    #[test]
    fn a_query_is_refused_for_its_options_then_for_cutting_no_token() {
        let zero = MatchOptions {
            tokenizer: Tokenizer::Ngram { length: 0 },
            ..Default::default()
        };
        assert!(matches!(
            QueryTokens::of_query("", &zero),
            Err(TermError::InvalidOptions(_))
        ));
        let options = MatchOptions::default();
        assert!(matches!(
            QueryTokens::of_query("al", &options),
            Err(TermError::EmptyTermText)
        ));
        let tokens = QueryTokens::of_query("ALICE", &options).expect("cuts tokens");
        assert_eq!(
            tokens.0.as_slice(),
            QueryTokens::under("alice", &options)
                .expect("normalizes")
                .0
                .as_slice()
        );
    }

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
