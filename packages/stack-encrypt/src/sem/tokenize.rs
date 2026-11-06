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
//!
//! Beside the tokenizer's tokens, an n-gram index with
//! [`MatchOptions::short_words`] on cuts one more kind: each word too short to
//! hold an n-gram, whole. The two kinds are kept apart ([`Tokens`]) because
//! each is run through the PRF under a domain of its own.

use std::collections::HashSet;

use vitaminc_normalize::NormalizeError;
use vitaminc_protected::Controlled;
use zeroize::{Zeroize, Zeroizing};

use super::MatchOptions;

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
    ///
    /// The n-grams are cut over the whole text, so a word shorter than
    /// `length` is only ever seen inside the n-grams that cross its edges:
    /// a query of a two-letter word cuts nothing under 3-grams. With
    /// [`MatchOptions::short_words`] on, each such word is also one token of
    /// its own.
    Ngram { length: usize },
    /// Split on the v1 match indexer's separator set — space, comma,
    /// semicolon, colon and exclamation mark — one token per run of
    /// non-separator characters.
    Standard,
}

/// The separators `Tokenizer::Standard` splits on, as in the v1 match
/// indexer's `process_standard`. The short-word filter splits words on the
/// same set (see [`Tokens::short_words`]).
const STANDARD_SEPARATORS: [char; 5] = [' ', ',', ';', ':', '!'];

/// The shortest word the short-word filter indexes, in characters. A
/// one-character word would be one of a few dozen tokens per alphabet, which
/// says more about a row than it finds.
const SHORTEST_WORD: usize = 2;

/// The tokens a match index cuts from one text, by kind. Each kind is run
/// through the PRF under a domain of its own, so a word token can never
/// derive the bits of an n-gram of the same characters.
///
/// Plaintext: the caller zeroizes it, through [`Zeroize`] (wrap it in
/// [`Zeroizing`]), or moves the strings on to something that does.
#[derive(Clone, Default)]
pub(crate) struct Tokens {
    /// The tokenizer's tokens: the n-grams of the whole text, or the words
    /// [`Tokenizer::Standard`] splits it into.
    pub(crate) tokenizer: Vec<String>,
    /// The short-word tokens, empty unless [`MatchOptions::short_words`] is
    /// on: every word of the text at least 2 characters long and shorter
    /// than the n-gram length, whole, in the order the text holds them.
    ///
    /// A word is a run of characters between the separators
    /// [`Tokenizer::Standard`] splits on (space, comma, semicolon, colon and
    /// exclamation mark), so a short word is exactly a token the standard
    /// tokenizer would cut, of that length: "Ng, Mike" holds the word `ng`.
    /// Length is counted in characters of the NFC text after case folding
    /// (the text the n-grams are cut from), so `李明` is a word of two, and
    /// `İz`, which folds to three characters, is not.
    pub(crate) short_words: Vec<String>,
}

impl Tokens {
    /// Whether no token of either kind was cut.
    pub(crate) fn is_empty(&self) -> bool {
        self.tokenizer.is_empty() && self.short_words.is_empty()
    }

    /// Whether `self` holds every token of `query`, kind by kind: what a
    /// match query's verifier asks of a row. A token of one kind never
    /// stands in for a token of the other.
    pub(crate) fn hold(&self, query: &Tokens) -> bool {
        fn holds(have: &[String], want: &[String]) -> bool {
            let have: HashSet<&str> = have.iter().map(String::as_str).collect();
            want.iter().all(|token| have.contains(token.as_str()))
        }
        holds(&self.tokenizer, &query.tokenizer) && holds(&self.short_words, &query.short_words)
    }
}

impl Zeroize for Tokens {
    fn zeroize(&mut self) {
        self.tokenizer.zeroize();
        self.short_words.zeroize();
    }
}

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
pub(crate) fn tokens(text: &str, options: &MatchOptions) -> Result<Tokens, NormalizeError> {
    let normalized = vitaminc_normalize::text(text)?;
    // `text` returns the UTF-8 of a `str`, so this does not fail; a failure
    // would be a bug there, refused rather than tokenized.
    let normalized =
        std::str::from_utf8(normalized.risky_ref()).map_err(|_| NormalizeError::Invalid)?;
    Ok(tokenize(normalized, options))
}

/// Split `text` into tokens under `options`' tokenizer, case folding and
/// short-word filter. `downcase` lower-cases the text first so matches are
/// case-insensitive.
///
/// May return no tokens (empty text, separator-only text, or text shorter
/// than the n-gram length that holds no short word). A stored value with
/// none is the empty filter; a query with none is refused before a term
/// exists, because its filter would match every row (ADR-0009).
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
/// folding lengthens the text (as `İ` does). A short word is copied out of
/// the folded text at its final size. The tokens returned are the caller's
/// to zeroize.
///
/// [`MatchOptions::validate`]: super::MatchOptions
pub(crate) fn tokenize(text: &str, options: &MatchOptions) -> Tokens {
    let text = Zeroizing::new(if options.downcase {
        text.to_lowercase()
    } else {
        text.to_string()
    });
    let short_words = match options.tokenizer {
        Tokenizer::Ngram { length } if options.short_words => short_words(&text, length),
        // `MatchOptions::validate` refuses the option beside the standard
        // tokenizer, whose tokens already are the words.
        _ => Vec::new(),
    };
    Tokens {
        tokenizer: tokenizer_tokens(&text, options.tokenizer),
        short_words,
    }
}

/// Every word of `text` at least [`SHORTEST_WORD`] characters long and
/// shorter than `length`, whole, in order (see [`Tokens::short_words`]).
fn short_words(text: &str, length: usize) -> Vec<String> {
    words(text)
        .filter(|word| (SHORTEST_WORD..length).contains(&word.chars().count()))
        .map(str::to_string)
        .collect()
}

/// The words of `text`: the runs between [`STANDARD_SEPARATORS`], empty runs
/// dropped. The standard tokenizer's tokens and the short-word filter's
/// words are both these, so a short word is exactly a standard token.
fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(STANDARD_SEPARATORS)
        .filter(|word| !word.is_empty())
}

/// The tokens `tokenizer` cuts from `text`, already case folded.
fn tokenizer_tokens(text: &str, tokenizer: Tokenizer) -> Vec<String> {
    match tokenizer {
        Tokenizer::Standard => words(text).map(str::to_string).collect(),
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

    /// The tokenizer's tokens of `text` under `tokenizer`, with or without
    /// case folding and no short words: the tokens the index cut before the
    /// short-word filter existed.
    fn cut(text: &str, tokenizer: Tokenizer, downcase: bool) -> Vec<String> {
        let tokens = tokenize(
            text,
            &MatchOptions {
                tokenizer,
                downcase,
                ..MatchOptions::default()
            },
        );
        assert!(
            tokens.short_words.is_empty(),
            "no short word is cut with the option off: {:?}",
            tokens.short_words
        );
        tokens.tokenizer
    }

    #[test]
    fn tokens_are_cut_from_the_nfc_form() {
        let standard = |text| {
            tokens(
                text,
                &MatchOptions {
                    tokenizer: Tokenizer::Standard,
                    downcase: false,
                    ..MatchOptions::default()
                },
            )
            .expect("tokens")
            .tokenizer
        };
        assert_eq!(
            standard("cafe\u{301} au lait"),
            standard("caf\u{e9} au lait"),
            "a combining accent and the precomposed letter cut the same tokens"
        );
        assert_eq!(standard("caf\u{e9}"), vec!["caf\u{e9}"], "the token is NFC");
    }

    #[test]
    fn tokens_refuse_a_code_point_unassigned_in_unicode_16() {
        assert!(
            matches!(
                tokens(
                    "a\u{378}b",
                    &MatchOptions {
                        tokenizer: Tokenizer::Standard,
                        ..MatchOptions::default()
                    }
                ),
                Err(NormalizeError::UnassignedCodePoint)
            ),
            "an unassigned code point has no normal form to tokenize"
        );
    }

    #[test]
    fn ngram_tokenizes_sliding_windows() {
        assert_eq!(
            cut("hello", Tokenizer::Ngram { length: 3 }, true),
            vec!["hel", "ell", "llo"]
        );
    }

    #[test]
    fn a_zero_ngram_length_yields_no_tokens_rather_than_panicking() {
        assert!(cut("hello", Tokenizer::Ngram { length: 0 }, true).is_empty());
    }

    #[test]
    fn ngram_gram_length_text_yields_one_token() {
        assert_eq!(
            cut("hey", Tokenizer::Ngram { length: 3 }, true),
            vec!["hey"]
        );
    }

    #[test]
    fn ngram_short_text_yields_no_tokens() {
        // Mirrors the v1 indexer: a sub-gram-length probe can never match a
        // stored gram, so it must not produce a token at all.
        assert!(cut("hi", Tokenizer::Ngram { length: 3 }, true).is_empty());
    }

    #[test]
    fn ngram_empty_text_yields_no_tokens() {
        assert!(cut("", Tokenizer::Ngram { length: 3 }, true).is_empty());
    }

    #[test]
    fn standard_splits_on_the_v1_separator_set() {
        assert_eq!(
            cut("Hello, World! again", Tokenizer::Standard, true),
            vec!["hello", "world", "again"]
        );
    }

    #[test]
    fn standard_drops_empty_tokens() {
        assert!(cut("  ,;:!  ", Tokenizer::Standard, true).is_empty());
    }

    #[test]
    fn standard_does_not_split_on_other_whitespace() {
        // The v1 separator set is exactly ' ', ',', ';', ':', '!' — tabs and
        // newlines are part of the token, as in v1.
        assert_eq!(cut("a\tb", Tokenizer::Standard, true), vec!["a\tb"]);
    }

    #[test]
    fn downcase_can_be_disabled() {
        assert_eq!(cut("Hi", Tokenizer::Standard, false), vec!["Hi"]);
    }

    /// Tokens are plaintext: zeroizing them wipes and drops both kinds,
    /// which is what a `Zeroizing<Tokens>` does when a query is dropped.
    #[test]
    fn zeroizing_tokens_clears_both_kinds() {
        let mut tokens = tokenize(
            "Mike Ng",
            &MatchOptions {
                short_words: true,
                ..MatchOptions::default()
            },
        );
        assert!(
            !tokens.tokenizer.is_empty() && !tokens.short_words.is_empty(),
            "both kinds are cut before"
        );
        tokens.zeroize();
        assert!(tokens.is_empty(), "no token of either kind is left after");
    }

    mod given_short_words {
        use super::*;

        /// The tokens of `text` under `length`-grams, downcased, with the
        /// short-word filter on.
        fn cut(text: &str, length: usize) -> Tokens {
            tokenize(
                text,
                &MatchOptions {
                    tokenizer: Tokenizer::Ngram { length },
                    short_words: true,
                    ..MatchOptions::default()
                },
            )
        }

        #[test]
        fn a_two_letter_word_is_one_token_at_the_start_middle_and_end() {
            for (text, words) in [
                ("Ng Mike", vec!["ng"]),
                ("Mike Ng Smith", vec!["ng"]),
                ("Mike Ng", vec!["ng"]),
                ("Ng", vec!["ng"]),
                ("Li Wu Ho", vec!["li", "wu", "ho"]),
            ] {
                assert_eq!(
                    cut(text, 3).short_words,
                    words,
                    "the short words of {text:?}"
                );
            }
        }

        #[test]
        fn the_ngrams_of_the_whole_text_are_cut_as_without_the_option() {
            for text in ["Mike Ng", "Ng", "a b", "", "Nguyen", "Ng, Mike!"] {
                assert_eq!(
                    cut(text, 3).tokenizer,
                    super::cut(text, Tokenizer::Ngram { length: 3 }, true),
                    "the n-grams of {text:?} do not move"
                );
            }
        }

        #[test]
        fn a_one_letter_word_is_no_token() {
            let tokens = cut("J R R Tolkien", 3);
            assert!(
                tokens.short_words.is_empty(),
                "one-letter words are ignored: {:?}",
                tokens.short_words
            );
            assert!(cut("a", 3).is_empty(), "a one-letter text cuts nothing");
        }

        #[test]
        fn a_word_as_long_as_an_ngram_is_no_word_token() {
            let tokens = cut("Ngo Nguyen", 3);
            assert!(
                tokens.short_words.is_empty(),
                "a word of three letters or more is found by its trigrams: {:?}",
                tokens.short_words
            );
        }

        #[test]
        fn a_four_gram_index_takes_two_and_three_letter_words() {
            let tokens = cut("Le Ngo Nguyen x", 4);
            assert_eq!(
                tokens.short_words,
                vec!["le", "ngo"],
                "under 4-grams, words of 2 and 3 characters are short"
            );
        }

        #[test]
        fn words_split_on_the_standard_separators() {
            assert_eq!(
                cut("Ng,Mike;Li:Wu!Ho Yu", 3).short_words,
                vec!["ng", "li", "wu", "ho", "yu"],
                "space, comma, semicolon, colon and exclamation mark end a word"
            );
            assert_eq!(
                cut("ng\tli", 3).short_words,
                Vec::<String>::new(),
                "a tab does not end a word, as it does not for the standard tokenizer"
            );
            assert_eq!(
                cut("ng.", 3).short_words,
                Vec::<String>::new(),
                "a full stop is part of the word, so `ng.` is three characters"
            );
        }

        #[test]
        fn a_word_is_counted_in_characters_not_bytes() {
            // Six bytes of UTF-8 each, two characters.
            assert_eq!(
                cut("\u{674e}\u{660e} \u{e9}\u{e9}", 3).short_words,
                vec!["\u{674e}\u{660e}", "\u{e9}\u{e9}"],
                "two-character words outside ASCII are short"
            );
            assert_eq!(
                tokens(
                    "e\u{301}e\u{301}",
                    &MatchOptions {
                        short_words: true,
                        ..MatchOptions::default()
                    }
                )
                .expect("normalizes")
                .short_words,
                vec!["\u{e9}\u{e9}"],
                "the characters are counted in NFC: `e` and a combining accent are one"
            );
        }

        #[test]
        fn the_word_is_case_folded_as_the_ngrams_are() {
            let folded = cut("NG", 3);
            assert_eq!(folded.short_words, vec!["ng"], "downcased");
            let kept = tokenize(
                "NG",
                &MatchOptions {
                    downcase: false,
                    short_words: true,
                    ..MatchOptions::default()
                },
            );
            assert_eq!(kept.short_words, vec!["NG"], "kept as written");
        }

        #[test]
        fn the_standard_tokenizer_cuts_no_word_token() {
            // `MatchOptions::validate` refuses the pair; tokenizing before
            // the check cuts no second copy of the words.
            let tokens = tokenize(
                "Mike Ng",
                &MatchOptions {
                    tokenizer: Tokenizer::Standard,
                    short_words: true,
                    ..MatchOptions::default()
                },
            );
            assert!(
                tokens.short_words.is_empty(),
                "the standard tokenizer's words are its own tokens: {:?}",
                tokens.short_words
            );
        }

        mod given_random_text {
            use super::*;
            use proptest::prelude::*;

            /// A word of one to six characters, Latin and not, so words
            /// fall either side of every short-word length and length is
            /// counted in characters.
            fn word() -> impl Strategy<Value = String> {
                prop::collection::vec(
                    prop::sample::select(vec!['a', 'n', 'g', 'é', 'ü', '李', '明']),
                    1..=6,
                )
                .prop_map(|chars| chars.into_iter().collect())
            }

            /// Words and the separators between them: runs of the standard
            /// separators, and empty runs at either end.
            fn text() -> impl Strategy<Value = (Vec<String>, String)> {
                let gap = prop::collection::vec(
                    prop::sample::select(STANDARD_SEPARATORS.to_vec()),
                    1..=2,
                )
                .prop_map(|gap| gap.into_iter().collect::<String>());
                (
                    prop::collection::vec((word(), gap), 0..10),
                    prop::sample::select(vec!["", " ", ","]),
                )
                    .prop_map(|(words, lead)| {
                        let mut text = lead.to_owned();
                        for (word, gap) in &words {
                            text.push_str(word);
                            text.push_str(gap);
                        }
                        (words.into_iter().map(|(word, _)| word).collect(), text)
                    })
            }

            proptest! {
                /// Every word of 2 characters up to the n-gram length is
                /// exactly one word token, in order, and nothing else is.
                #[test]
                fn every_short_word_is_one_token_and_no_other_word_is(
                    (words, text) in text(),
                    length in 3usize..=5,
                ) {
                    let want: Vec<&str> = words
                        .iter()
                        .map(String::as_str)
                        .filter(|word| (2..length).contains(&word.chars().count()))
                        .collect();
                    let tokens = cut(&text, length);
                    prop_assert_eq!(
                        &tokens.short_words,
                        &want,
                        "the short words of {:?} under {}-grams",
                        text,
                        length
                    );
                    for word in &tokens.short_words {
                        let chars = word.chars().count();
                        prop_assert!(
                            (2..length).contains(&chars),
                            "{:?} is {} characters, outside 2..{}",
                            word,
                            chars,
                            length
                        );
                    }
                }

                /// The n-grams do not depend on the option: it adds word
                /// tokens and moves nothing else.
                #[test]
                fn the_option_adds_word_tokens_and_moves_no_ngram(
                    (_, text) in text(),
                    length in 3usize..=5,
                ) {
                    prop_assert_eq!(
                        cut(&text, length).tokenizer,
                        super::super::cut(&text, Tokenizer::Ngram { length }, true),
                        "the n-grams of {:?}",
                        text
                    );
                }
            }
        }

        #[test]
        fn a_row_holds_a_query_kind_by_kind() {
            let row = cut("Mike Ng", 3);
            assert!(row.hold(&cut("Ng", 3)), "the word query is held");
            assert!(row.hold(&cut("Mike Ng", 3)), "the whole query is held");
            assert!(
                !cut("Nguyen", 3).hold(&cut("Ng", 3)),
                "Nguyen has no word ng"
            );
            let as_gram = Tokens {
                tokenizer: vec!["ng".into()],
                short_words: Vec::new(),
            };
            assert!(
                !row.hold(&as_gram),
                "a word token does not stand in for a token of the tokenizer's"
            );
        }
    }
}
