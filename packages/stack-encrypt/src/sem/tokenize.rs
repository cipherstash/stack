//! Tokenization for match (full-text) index terms.
//!
//! Tokens are derived locally from the plaintext *before* any PRF is applied;
//! only the PRF outputs (Bloom-filter bit positions) leave the process.
//!
//! Semantics mirror the v1 match indexer (`cipherstash-client`'s
//! `encryption::text::Tokenizer`) so v2 match queries behave like existing
//! ones: n-grams yield nothing for text shorter than the gram length, and
//! `Standard` splits on the same separator set. The one deliberate divergence
//! is that empty tokens are dropped (v1 keeps the empty strings its separator
//! split produces, which only add noise bits to every filter).

use vitaminc_normalize::NormalizeError;
use vitaminc_protected::Controlled;
use zeroize::Zeroizing;

/// How text is split into tokens before each token is run through the PRF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tokenizer {
    /// Sliding character n-grams of the given length over the whole text
    /// (whitespace included). Text shorter than `length` yields **no tokens**,
    /// exactly like the v1 match indexer — so a query shorter than the gram
    /// length is refused by the query chain
    /// ([`TermError::EmptyTermText`](crate::sem::TermError::EmptyTermText))
    /// rather than silently never matching, and a stored value shorter than
    /// it is the empty filter, which no query matches. This is the default,
    /// matching the existing match indexer's 3-gram configuration.
    Ngram { length: usize },
    /// Split on the v1 match indexer's separator set — space, comma,
    /// semicolon, colon and exclamation mark — one token per run of
    /// non-separator characters.
    Standard,
}

/// The separators `Tokenizer::Standard` splits on, as in the v1 match
/// indexer's `process_standard`.
const STANDARD_SEPARATORS: [char; 5] = [' ', ',', ';', ':', '!'];

impl Default for Tokenizer {
    fn default() -> Self {
        Self::Ngram { length: 3 }
    }
}

/// Split `text` into tokens as a match index does: in Unicode 16 NFC, the
/// form `vitaminc-normalize` gives text, then [`tokenize`]d. So text written
/// with a precomposed `é` and with `e` and a combining accent cuts the same
/// tokens, as it derives one equality term. Text holding a code point
/// unassigned in Unicode 16 is refused, as equality refuses it: its NFC
/// form could change when the code point is assigned.
///
/// The normalized copy is held in [`Protected`](vitaminc_protected::Protected)
/// and wiped on drop.
pub(crate) fn tokens(
    text: &str,
    tokenizer: Tokenizer,
    downcase: bool,
) -> Result<Vec<String>, NormalizeError> {
    let normalized = vitaminc_normalize::text(text)?;
    // `text` returns the UTF-8 of a `str`, so this does not fail; a failure
    // would be a bug there, refused rather than tokenized.
    let normalized =
        std::str::from_utf8(normalized.risky_ref()).map_err(|_| NormalizeError::Invalid)?;
    Ok(tokenize(normalized, tokenizer, downcase))
}

/// Split `text` into tokens. `downcase` lower-cases the text first so matches
/// are case-insensitive.
///
/// May return no tokens (empty text, separator-only text, or text shorter
/// than the n-gram length). A stored value with none is the empty filter; a
/// query with none is refused before a term exists, because its filter would
/// match every row (ADR-0009).
///
/// The tokenizer must be valid: an n-gram length of zero panics. Callers
/// validate the [`MatchOptions`](super::MatchOptions) first.
///
/// An n-gram length of zero yields no tokens rather than panicking, so a
/// caller that tokenizes before validating the options (a query's verifier)
/// still reaches [`MatchOptions::validate`]'s refusal.
///
/// The text is plaintext, so the copies made on the way are zeroized when
/// they are dropped: the folded text, its characters, which are collected
/// into a buffer sized up front, and each n-gram, which is built at its
/// final size. Neither reallocates, so no freed buffer holds plaintext. The
/// one exception is inside `str::to_lowercase`, which grows its output when
/// folding lengthens the text (as `İ` does). The tokens returned are the
/// caller's to zeroize.
///
/// [`MatchOptions::validate`]: super::MatchOptions
pub(crate) fn tokenize(text: &str, tokenizer: Tokenizer, downcase: bool) -> Vec<String> {
    let text = Zeroizing::new(if downcase {
        text.to_lowercase()
    } else {
        text.to_string()
    });

    match tokenizer {
        Tokenizer::Standard => text
            .split(STANDARD_SEPARATORS)
            .filter(|token| !token.is_empty())
            .map(str::to_string)
            .collect(),
        Tokenizer::Ngram { length } => {
            // `collect` would size the buffer from `Chars::size_hint`, about
            // a quarter of the text, and grow it, leaving plaintext in each
            // buffer it frees.
            let mut chars: Zeroizing<Vec<char>> =
                Zeroizing::new(Vec::with_capacity(text.chars().count()));
            chars.extend(text.chars());
            // As in the v1 indexer's `process_ngram`: shorter than one gram
            // means no tokens (never a partial or whole-text token, which
            // could not match any stored gram).
            if length == 0 || chars.len() < length {
                Vec::new()
            } else {
                chars.windows(length).map(gram).collect()
            }
        }
    }
}

/// One n-gram as a `String` allocated at its final size, so building it
/// leaves no reallocated copy behind.
fn gram(chars: &[char]) -> String {
    let mut gram = String::with_capacity(chars.iter().map(|c| c.len_utf8()).sum());
    gram.extend(chars);
    gram
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_cut_from_the_nfc_form() {
        let standard = |text| tokens(text, Tokenizer::Standard, false).expect("tokens");
        assert_eq!(
            standard("cafe\u{301} au lait"),
            standard("caf\u{e9} au lait"),
            "a combining accent and the precomposed letter cut the same tokens"
        );
        assert_eq!(standard("caf\u{e9}"), vec!["caf\u{e9}"], "the token is NFC");
    }

    #[test]
    fn tokens_refuse_a_code_point_unassigned_in_unicode_16() {
        assert_eq!(
            tokens("a\u{378}b", Tokenizer::Standard, true),
            Err(NormalizeError::UnassignedCodePoint)
        );
    }

    #[test]
    fn ngram_tokenizes_sliding_windows() {
        assert_eq!(
            tokenize("hello", Tokenizer::Ngram { length: 3 }, true),
            vec!["hel", "ell", "llo"]
        );
    }

    #[test]
    fn a_zero_ngram_length_yields_no_tokens_rather_than_panicking() {
        assert!(tokenize("hello", Tokenizer::Ngram { length: 0 }, true).is_empty());
    }

    #[test]
    fn ngram_gram_length_text_yields_one_token() {
        assert_eq!(
            tokenize("hey", Tokenizer::Ngram { length: 3 }, true),
            vec!["hey"]
        );
    }

    #[test]
    fn ngram_short_text_yields_no_tokens() {
        // Mirrors the v1 indexer: a sub-gram-length probe can never match a
        // stored gram, so it must not produce a token at all.
        assert!(tokenize("hi", Tokenizer::Ngram { length: 3 }, true).is_empty());
    }

    #[test]
    fn ngram_empty_text_yields_no_tokens() {
        assert!(tokenize("", Tokenizer::Ngram { length: 3 }, true).is_empty());
    }

    #[test]
    fn standard_splits_on_the_v1_separator_set() {
        assert_eq!(
            tokenize("Hello, World! again", Tokenizer::Standard, true),
            vec!["hello", "world", "again"]
        );
    }

    #[test]
    fn standard_drops_empty_tokens() {
        assert!(tokenize("  ,;:!  ", Tokenizer::Standard, true).is_empty());
    }

    #[test]
    fn standard_does_not_split_on_other_whitespace() {
        // The v1 separator set is exactly ' ', ',', ';', ':', '!' — tabs and
        // newlines are part of the token, as in v1.
        assert_eq!(tokenize("a\tb", Tokenizer::Standard, true), vec!["a\tb"]);
    }

    #[test]
    fn downcase_can_be_disabled() {
        assert_eq!(tokenize("Hi", Tokenizer::Standard, false), vec!["Hi"]);
    }
}
