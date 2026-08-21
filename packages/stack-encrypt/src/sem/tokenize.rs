//! Tokenization for match (full-text) index terms.
//!
//! Tokens are derived locally from the plaintext *before* any PRF is applied;
//! only the PRF outputs (Bloom-filter bit positions) leave the process.

/// How text is split into tokens before each token is run through the PRF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tokenizer {
    /// Sliding character n-grams of the given length over the whole text
    /// (whitespace included). Text shorter than `length` yields a single token
    /// of the whole text. This is the default, matching the existing match
    /// indexer's 3-gram configuration.
    Ngram { length: usize },
    /// Split on Unicode whitespace, one token per word.
    Standard,
}

impl Default for Tokenizer {
    fn default() -> Self {
        Self::Ngram { length: 3 }
    }
}

/// Split `text` into tokens. `downcase` lower-cases the text first so matches
/// are case-insensitive.
pub(crate) fn tokenize(text: &str, tokenizer: Tokenizer, downcase: bool) -> Vec<String> {
    let text = if downcase {
        text.to_lowercase()
    } else {
        text.to_string()
    };

    match tokenizer {
        Tokenizer::Standard => text.split_whitespace().map(str::to_string).collect(),
        Tokenizer::Ngram { length } => {
            let chars: Vec<char> = text.chars().collect();
            if chars.is_empty() {
                Vec::new()
            } else if chars.len() <= length {
                vec![text]
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
    fn ngram_short_text_yields_whole_text() {
        assert_eq!(
            tokenize("hi", Tokenizer::Ngram { length: 3 }, true),
            vec!["hi"]
        );
    }

    #[test]
    fn ngram_empty_text_yields_no_tokens() {
        assert!(tokenize("", Tokenizer::Ngram { length: 3 }, true).is_empty());
    }

    #[test]
    fn standard_splits_on_whitespace_and_downcases() {
        assert_eq!(
            tokenize("Hello  World", Tokenizer::Standard, true),
            vec!["hello", "world"]
        );
    }

    #[test]
    fn downcase_can_be_disabled() {
        assert_eq!(tokenize("Hi", Tokenizer::Standard, false), vec!["Hi"]);
    }
}
