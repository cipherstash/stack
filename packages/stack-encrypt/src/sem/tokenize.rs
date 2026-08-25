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

/// How text is split into tokens before each token is run through the PRF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tokenizer {
    /// Sliding character n-grams of the given length over the whole text
    /// (whitespace included). Text shorter than `length` yields **no tokens**,
    /// exactly like the v1 match indexer — so a probe shorter than the gram
    /// length is rejected by
    /// [`match_terms`](crate::StackCipher::match_terms) rather than
    /// silently never matching. This is the default, matching the existing
    /// match indexer's 3-gram configuration.
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

/// Split `text` into tokens. `downcase` lower-cases the text first so matches
/// are case-insensitive.
///
/// May return no tokens (empty text, separator-only text, or text shorter
/// than the n-gram length); [`match_terms`] rejects that case so an empty
/// term can never reach a query.
///
/// [`match_terms`]: crate::StackCipher::match_terms
pub(crate) fn tokenize(text: &str, tokenizer: Tokenizer, downcase: bool) -> Vec<String> {
    let text = if downcase {
        text.to_lowercase()
    } else {
        text.to_string()
    };

    match tokenizer {
        Tokenizer::Standard => text
            .split(STANDARD_SEPARATORS)
            .filter(|token| !token.is_empty())
            .map(str::to_string)
            .collect(),
        Tokenizer::Ngram { length } => {
            let chars: Vec<char> = text.chars().collect();
            // As in the v1 indexer's `process_ngram`: shorter than one gram
            // means no tokens (never a partial or whole-text token, which
            // could not match any stored gram).
            if chars.len() < length {
                Vec::new()
            } else {
                chars.windows(length).map(|w| w.iter().collect()).collect()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ngram_tokenizes_sliding_windows() {
        assert_eq!(
            tokenize("hello", Tokenizer::Ngram { length: 3 }, true),
            vec!["hel", "ell", "llo"]
        );
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
