//! What a query is refused for before any term exists, written once.
//!
//! Both paths call these: the typed query chain through each index's
//! [`Supports::prepare`](crate::op::Supports::prepare), and the dynamic
//! path at its boundary (`dynamic::check_query`) and before it derives a
//! term (`dynamic::query_term`, `dynamic::verify`). So what a binding
//! refuses is what the typed chain refuses, with the same error, and
//! neither has a copy of the rule. Every refusal here needs no key, so a
//! refused query costs no request.
//!
//! The rules: a match query's options must be ones the index can use
//! ([`TermError::InvalidOptions`]), its text must normalize and must cut
//! a token ([`TermError::EmptyTermText`]: a filter with no token would
//! match every row); equality and order text must normalize
//! ([`TermError::Normalize`]: a code point Unicode 16 does not assign);
//! block ORE text must also fit the scheme's limit and not end in NUL
//! ([`TermError::OreBlockTooLong`], [`TermError::OreBlockTrailingNul`]).
//! A range whose low bound is above its high bound is not refused: as
//! SQL's `BETWEEN`, it matches nothing.
use vitaminc_aead::Encrypt;

use super::{normalized, sealed, MatchOptions, Orderable, QueryTokens, TermError};

/// An equality query of `value`: refused when the value has no equality
/// term, or is text the index cannot normalize. The value is consumed as
/// it is normalized, so a caller that still needs it passes a copy, as the
/// typed `Equality::prepare` does; vitaminc wipes what it reads.
///
/// # Errors
///
/// [`TermError::Normalize`] for text with no normal form;
/// [`TermError::NoEqualityTerm`] for a value that is not one scalar with
/// an equality domain.
pub(crate) fn equality<T: Encrypt>(value: T) -> Result<(), TermError> {
    normalized(value).map(drop)
}

/// An order query of `value`, through the CLLW indexes (`block` false) or
/// block ORE (`block` true): refused for text the fold cannot take, and
/// under block ORE for a fold over the scheme's limit or ending in NUL.
/// Every other orderable value has nothing to refuse.
///
/// # Errors
///
/// [`TermError::Normalize`], [`TermError::OreBlockTooLong`],
/// [`TermError::OreBlockTrailingNul`].
pub(crate) fn order<T: Orderable>(value: &T, block: bool) -> Result<(), TermError> {
    sealed::Sealed::check_query(value, block)
}

/// [`order`] for text read from a frame, where the type is known only at
/// run time: the dynamic path's form of the same rule.
///
/// # Errors
///
/// As [`order`].
pub(crate) fn order_text(text: &str, block: bool) -> Result<(), TermError> {
    if block {
        return super::ore_block_text(text);
    }
    vitaminc_ore::text(text)
        .map(drop)
        .map_err(TermError::Normalize)
}

/// A match query of `text` under `options`: the tokens the query keeps,
/// or why it is refused. The options are checked before the text is
/// tokenised (an n-gram length of zero would otherwise reach the
/// tokenizer), then text that cuts no token is refused, since its filter
/// would match every row. The stored side keeps token-less text as the
/// empty filter, which no query matches.
///
/// # Errors
///
/// [`TermError::InvalidOptions`], [`TermError::Normalize`],
/// [`TermError::EmptyTermText`].
pub(crate) fn match_tokens(text: &str, options: &MatchOptions) -> Result<QueryTokens, TermError> {
    QueryTokens::of_query(text, options)
}
