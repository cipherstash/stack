//! A match index with short-word tokens (`MatchOptions::short_words`): a
//! word too short to hold an n-gram, such as the surname "Ng" under
//! 3-grams, is one token of its own, stored and queried.
//!
//! - **Round trip.** "Ng" stored is found by the query "Ng"; "Mike Ng" is
//!   found by "Ng" and by "Mike Ng"; "Nguyen" is not found by "Ng".
//! - **Queries.** A query keeps its short words only when it cuts no
//!   n-gram: "Ng" is its word token, and "Mike Ng" its trigrams alone, so it
//!   finds "Mike Nguyen" as it does with the option off. The filter and
//!   `verify` agree.
//! - **Identity.** The option is part of the index, which is the field's
//!   type: a field is stored and queried under the options its type
//!   declares, and options the index cannot use are refused on both sides.
//! - **Containment.** For random text, the stored filter holds the filter of
//!   any run of its whole words, and of any run of its characters that cuts
//!   an n-gram.
//! - **Calibration.** A one-word query sets as many bits as a one-trigram
//!   query, and a row's chance of matching either falsely is the same.

mod common;

use common::stack_cipher;
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, RngAlgorithm, RngSeed, TestRng, TestRunner};
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::op::Probabilistic;
use stack_encrypt::sem::{MatchConfig, MatchOptions, MatchQuery, MatchTerms, TermError, Tokenizer};
use stack_encrypt::target::EncryptTarget;
use stack_encrypt::{nonempty, EncryptInto, Encrypted, Error, KeysetCipher};
use zeroize::Zeroize;

/// 3-grams, downcased, with short-word tokens: the default index with the
/// option on.
struct ShortWords;
impl MatchConfig for ShortWords {
    fn options() -> MatchOptions {
        MatchOptions {
            short_words: true,
            ..MatchOptions::default()
        }
    }
}

/// Short words beside the standard tokenizer, which already indexes whole
/// words: options the index refuses.
struct StandardShortWords;
impl MatchConfig for StandardShortWords {
    fn options() -> MatchOptions {
        MatchOptions {
            tokenizer: Tokenizer::Standard,
            short_words: true,
            ..MatchOptions::default()
        }
    }
}

type Keyset<'a> = KeysetCipher<'a, FakeDataKeySource>;

#[derive(Clone, Zeroize)]
struct Person {
    name: String,
}

/// A person whose name is under the short-word match index.
#[derive(EncryptTarget)]
#[stash(struct = Person, scope = "people")]
struct EncryptedPerson {
    name: Encrypted<MatchTerms<ShortWords>>,
}

/// The stored filter of `text` as a person's name.
async fn store(keyset: &Keyset<'_>, text: &str) -> MatchTerms<ShortWords> {
    let stored: EncryptedPerson = Person { name: text.into() }
        .encrypt_into(keyset)
        .await
        .unwrap_or_else(|error| panic!("{text:?} stores: {error}"));
    stored.name.terms
}

/// A match query of `text` on a person's name, from the field reference.
async fn query(keyset: &Keyset<'_>, text: &str) -> Result<MatchQuery<ShortWords>, Error> {
    EncryptedPerson::NAME.matches(text).encrypt(keyset).await
}

mod given_short_words {
    use super::*;

    #[tokio::test]
    async fn a_two_letter_value_stores_one_token_and_the_two_letter_query_finds_it() {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();
        let stored = store(&keyset, "Ng").await;
        assert!(
            !stored.positions().is_empty(),
            "\"Ng\" stores a token, not the empty filter"
        );
        let ng = query(&keyset, "Ng").await.expect("\"Ng\" is a query");
        assert!(stored.matches(&ng), "the query \"Ng\" finds \"Ng\"");
        assert!(ng.verify("Ng"), "and the row verifies");
        assert_eq!(
            ng.positions(),
            stored.positions(),
            "a query's filter is the filter the index stores for the same text"
        );
    }

    #[tokio::test]
    async fn a_two_letter_query_finds_the_word_and_not_a_longer_word_it_begins() {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();
        let ng = query(&keyset, "ng").await.expect("a query");
        for (text, found) in [
            ("Ng", true),
            ("Mike Ng", true),
            ("Ng, Mike", true),
            ("NG Mike Smith", true),
            ("Nguyen", false),
            ("Mike Nguyen", false),
            ("Long", false),
        ] {
            let stored = store(&keyset, text).await;
            // The filter alone: a row without the word could hold its bits
            // by chance, but under the test key and these rows none does,
            // so a stored side that set the word's bits for a longer word
            // fails here.
            assert_eq!(
                stored.matches(&ng),
                found,
                "the filter of the query \"ng\" on {text:?}"
            );
            assert_eq!(
                ng.verify(text),
                found,
                "verify agrees with the filter on {text:?}"
            );
        }
    }

    /// A query that cuts an n-gram asks for its n-grams alone, so a short
    /// word in it need not be a whole word of the row: a name typed in part
    /// finds its row, as it does with the option off. A query of one short
    /// word is that word, whole. The filter and `verify` agree on every row.
    #[tokio::test]
    async fn a_query_keeps_its_short_words_only_when_it_cuts_no_ngram() {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();
        for (asked, text, found) in [
            ("Ng", "Ng", true),
            ("Ng", "Mike Ng", true),
            ("Ng", "Mike Nguyen", false),
            ("Mike Ng", "Mike Ng", true),
            ("Mike Ng", "mike ng", true),
            ("Mike Ng", "Mike Nguyen", true),
            ("Mike Ng", "Mike Ngo", true),
            ("Mike Ng", "Ng", false),
            ("Mike Ng", "Mike Smith", false),
            ("ke Ng", "Mike Ng", true),
            ("san fr", "San Francisco", true),
            ("Li Wu", "Li Wu", true),
            ("Li Wu", "Li Wuhan", true),
            ("Li Wu", "Wu Li", false),
        ] {
            let query = query(&keyset, asked)
                .await
                .unwrap_or_else(|error| panic!("{asked:?} is a query: {error}"));
            let stored = store(&keyset, text).await;
            // The filter alone: a row without the tokens could hold their
            // bits by chance, but under the test key and these rows none
            // does.
            assert_eq!(
                stored.matches(&query),
                found,
                "the filter of {asked:?} on {text:?}"
            );
            assert_eq!(
                query.verify(text),
                found,
                "verify agrees with the filter of {asked:?} on {text:?}"
            );
        }
    }

    /// A person whose name is under the default match index, under the
    /// same label as [`EncryptedPerson`]'s.
    #[derive(EncryptTarget)]
    #[stash(struct = Person, scope = "people")]
    struct PlainPerson {
        name: Encrypted<MatchTerms>,
    }

    /// A query that cuts an n-gram sends the filter the index without the
    /// option stores for the same text: its n-grams, and no word.
    #[tokio::test]
    async fn a_query_of_ngrams_is_the_filter_the_index_without_the_option_stores() {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();
        let asked = query(&keyset, "Mike Ng").await.expect("a query");
        let plain: PlainPerson = Person {
            name: "Mike Ng".into(),
        }
        .encrypt_into(&keyset)
        .await
        .expect("stores");
        let trigrams = plain.name.terms;
        assert_eq!(
            asked.positions(),
            trigrams.positions(),
            "\"Mike Ng\" sends its trigrams alone"
        );
        assert_ne!(
            asked.positions(),
            store(&keyset, "Mike Ng").await.positions(),
            "not the stored filter, which holds the word token too"
        );
    }

    #[tokio::test]
    async fn a_query_that_cuts_nothing_is_still_refused() {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();
        for text in ["N", "", "  ", "n "] {
            let refused = query(&keyset, text).await;
            assert!(
                matches!(refused, Err(Error::Term(TermError::EmptyTermText))),
                "{text:?}: {refused:?}"
            );
        }
        let stored = store(&keyset, "N").await;
        assert!(
            stored.positions().is_empty(),
            "a one-letter value is still the empty filter"
        );
    }

    /// The query cut run on its own, as a binding or an index defined
    /// elsewhere runs it, refuses text that cuts no token as a field query
    /// does: its empty filter would match every row. The stored cut keeps
    /// such text as the empty filter.
    mod given_the_query_cut_alone {
        use super::*;
        use stack_encrypt::sem::DefaultMatch;
        use stack_encrypt::target::{matching, matching_query, Borrowed, CallerContext};

        fn caller() -> CallerContext {
            CallerContext::from(nonempty!("people/name"))
        }

        async fn derive_query<O: MatchConfig>(
            keyset: &Keyset<'_>,
            text: &str,
        ) -> Result<MatchTerms<O>, Error> {
            keyset
                .run(
                    matching_query::<_, _, Borrowed, O>(),
                    &text.to_owned(),
                    caller(),
                )
                .await
        }

        #[tokio::test]
        async fn text_that_cuts_no_token_is_refused() {
            let cipher = stack_cipher().await;
            let keyset = cipher.default_keyset();
            for text in ["", "a", "Ng", "  "] {
                assertions::refused_as_empty(
                    text,
                    derive_query::<DefaultMatch>(&keyset, text).await,
                );
            }
            for text in ["", "N", "n "] {
                assertions::refused_as_empty(text, derive_query::<ShortWords>(&keyset, text).await);
            }
        }

        #[tokio::test]
        async fn the_stored_cut_of_that_text_is_the_empty_filter() {
            let cipher = stack_cipher().await;
            let keyset = cipher.default_keyset();
            let stored: MatchTerms = keyset
                .run(
                    matching::<_, _, Borrowed, DefaultMatch>(),
                    &"Ng".to_owned(),
                    caller(),
                )
                .await
                .expect("a stored value of short text derives");
            assert!(
                stored.positions().is_empty(),
                "\"Ng\" stores the empty filter under the default index: {:?}",
                stored.positions()
            );
        }

        #[tokio::test]
        async fn text_that_cuts_a_token_derives_its_filter() {
            let cipher = stack_cipher().await;
            let keyset = cipher.default_keyset();
            let queried = derive_query::<ShortWords>(&keyset, "Ng")
                .await
                .expect("a short word is a token of the short-word index");
            assert!(
                !queried.positions().is_empty(),
                "the word token sets positions"
            );
        }

        mod assertions {
            use super::*;

            pub(super) fn refused_as_empty<O: MatchConfig>(
                text: &str,
                derived: Result<MatchTerms<O>, Error>,
            ) {
                assert!(
                    matches!(derived, Err(Error::Term(TermError::EmptyTermText))),
                    "{text:?} cuts no token, and its query is refused: {:?}",
                    derived.map(|terms| terms.positions().to_vec())
                );
            }
        }
    }

    /// A person with one name under each index: the short-word index on
    /// `name`, the default on `alias`.
    #[derive(Clone, Zeroize)]
    struct Aliased {
        name: String,
        alias: String,
    }

    #[derive(EncryptTarget)]
    #[stash(struct = Aliased, scope = "aliased")]
    struct EncryptedAliased {
        name: Encrypted<MatchTerms<ShortWords>>,
        alias: Encrypted<MatchTerms>,
    }

    /// The option is part of the index, and a field's index is its type:
    /// each field is stored and queried under its own setting. The
    /// two-letter word is a token of the short-word field, and cuts nothing
    /// under the default field.
    #[tokio::test]
    async fn a_field_is_queried_under_the_options_its_type_declares() {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedAliased = Aliased {
            name: "Mike Ng".into(),
            alias: "Mike Ng".into(),
        }
        .encrypt_into(&keyset)
        .await
        .expect("stores");

        let found: MatchQuery<ShortWords> = EncryptedAliased::NAME
            .matches("Ng")
            .encrypt(&keyset)
            .await
            .expect("the field's own options answer");
        assert!(stored.name.terms.matches(&found), "and find the row");

        let refused = EncryptedAliased::ALIAS.matches("Ng").encrypt(&keyset).await;
        assert!(
            matches!(refused, Err(Error::Term(TermError::EmptyTermText))),
            "the default index has no token for a two-letter word: {refused:?}"
        );
        let mike: MatchQuery = EncryptedAliased::ALIAS
            .matches("Mike")
            .encrypt(&keyset)
            .await
            .expect("a trigram query");
        assert!(stored.alias.terms.matches(&mike));
        assert!(
            mike.verify("Mike Ng") && !mike.verify("Ng"),
            "the default index verifies by trigrams alone"
        );
    }

    /// A person whose name is under options the match index cannot use.
    #[derive(EncryptTarget)]
    #[stash(struct = Person, scope = "people")]
    #[allow(dead_code)]
    struct Unusable {
        name: Encrypted<MatchTerms<StandardShortWords>>,
    }

    #[tokio::test]
    async fn options_the_index_cannot_use_are_refused_stored_and_queried() {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();
        let stored: Result<Unusable, Error> = Person {
            name: "Mike Ng".into(),
        }
        .encrypt_into(&keyset)
        .await;
        assert!(
            matches!(stored, Err(Error::Term(TermError::InvalidOptions(_)))),
            "stored: {:?}",
            stored.err()
        );
        let queried = Unusable::NAME.matches("Mike Ng").encrypt(&keyset).await;
        assert!(
            matches!(queried, Err(Error::Term(TermError::InvalidOptions(_)))),
            "queried: {queried:?}"
        );
    }
}

/// proptest's defaults, which read `PROPTEST_CASES` and
/// `PROPTEST_RNG_SEED`, with a fixed seed when none is set, so CI runs the
/// same cases every time.
fn config() -> Config {
    let mut config = Config {
        cases: 64,
        ..Config::default()
    };
    if config.rng_seed == RngSeed::Random {
        config.rng_seed = RngSeed::Fixed(0x5d0f_1396);
    }
    config.rng_algorithm = RngAlgorithm::ChaCha;
    config
}

/// `proptest!` runs each case through a plain closure, so a property
/// builds one runtime and `block_on`s its case.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A word of one to five characters, Latin and not, so words fall either
/// side of the short-word length and length is counted in characters.
fn word() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select(vec!['a', 'b', 'n', 'g', 'é', '李']),
        1..=5,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

/// A separator the short-word filter splits on.
fn separator() -> impl Strategy<Value = char> {
    prop::sample::select(vec![' ', ',', ';', ':', '!'])
}

mod given_random_text {
    use super::*;

    proptest! {
        #![proptest_config(config())]

        /// The stored filter of a text holds the query filter of any run
        /// of its whole words: every n-gram of the run is an n-gram of the
        /// text, and every short word of the run a word of it.
        #[test]
        fn the_stored_filter_holds_any_run_of_its_whole_words(
            words in prop::collection::vec(word(), 1..8),
            separators in prop::collection::vec(separator(), 8),
            run in (0usize..8, 0usize..8),
        ) {
            let mut text = String::new();
            let mut spans = Vec::with_capacity(words.len());
            for (i, word) in words.iter().enumerate() {
                if i > 0 {
                    text.push(separators[i - 1]);
                }
                spans.push((text.len(), text.len() + word.len()));
                text.push_str(word);
            }
            let (first, last) = (run.0 % words.len(), run.1 % words.len());
            let (first, last) = (first.min(last), first.max(last));
            let asked = &text[spans[first].0..spans[last].1];

            runtime().block_on(async {
                let cipher = stack_cipher().await;
                let keyset = cipher.default_keyset();
                let stored = store(&keyset, &text).await;
                match query(&keyset, asked).await {
                    Ok(query) => {
                        prop_assert!(
                            stored.matches(&query),
                            "{text:?} holds the filter of {asked:?}"
                        );
                        prop_assert!(query.verify(&text), "{text:?} verifies {asked:?}");
                    }
                    // A run of one one-letter word cuts nothing.
                    Err(Error::Term(TermError::EmptyTermText)) => {
                        prop_assert!(
                            asked.chars().count() < 2,
                            "only a run too short for any token cuts nothing: {asked:?}"
                        );
                    }
                    Err(error) => prop_assert!(false, "{asked:?}: {error}"),
                }
                Ok(())
            })?;
        }

        /// A query of any run of a text's characters that cuts an n-gram
        /// finds the text, filter and `verify` alike, whether or not the
        /// run starts or ends inside a word: typeahead and partial names
        /// find their rows with short words on.
        #[test]
        fn a_run_of_characters_that_cuts_an_ngram_finds_its_text(
            words in prop::collection::vec(word(), 1..8),
            separators in prop::collection::vec(separator(), 8),
            run in (0usize..40, 0usize..40),
        ) {
            let mut text = String::new();
            for (i, word) in words.iter().enumerate() {
                if i > 0 {
                    text.push(separators[i - 1]);
                }
                text.push_str(word);
            }
            let chars: Vec<char> = text.chars().collect();
            let (first, last) = (run.0 % chars.len(), run.1 % chars.len());
            let asked: String = chars[first.min(last)..=first.max(last)].iter().collect();
            prop_assume!(asked.chars().count() >= 3, "a run too short for a trigram");

            runtime().block_on(async {
                let cipher = stack_cipher().await;
                let keyset = cipher.default_keyset();
                let stored = store(&keyset, &text).await;
                let query = query(&keyset, &asked)
                    .await
                    .map_err(|error| TestCaseError::fail(format!("{asked:?}: {error}")))?;
                prop_assert!(
                    stored.matches(&query),
                    "{text:?} holds the filter of {asked:?}"
                );
                prop_assert!(query.verify(&text), "{text:?} verifies {asked:?}");
                Ok(())
            })?;
        }
    }
}

/// The false positives of a one-token query: a row whose filter holds the
/// query's bits without holding its token.
mod calibration {
    use super::*;

    /// Rows of three words of four to six letters: a filter of about
    /// fifteen trigrams and no short word, under `k = 3`, `m = 256`.
    const ROWS: usize = 3000;
    /// Queries of each kind.
    const QUERIES: usize = 60;

    fn draw<S: Strategy>(runner: &mut TestRunner, strategy: S) -> S::Value {
        strategy.new_tree(runner).expect("draws a value").current()
    }

    /// The share of `rows` whose filter matches `query` falsely, over the
    /// rows that do not hold its text.
    fn false_positive_rate(
        rows: &[(String, MatchTerms<ShortWords>)],
        query: &MatchTerms<ShortWords>,
        holds: impl Fn(&str) -> bool,
    ) -> (usize, usize) {
        let negatives = rows.iter().filter(|(text, _)| !holds(text));
        let mut seen = 0;
        let mut false_positives = 0;
        for (_, filter) in negatives {
            seen += 1;
            if filter.contains(query) {
                false_positives += 1;
            }
        }
        (false_positives, seen)
    }

    /// A one-word query is one token, as a one-trigram query is: it sets
    /// the same number of bits by the same fold of a PRF block, so a row
    /// holds it falsely as often. Measured over a fixed random column: the
    /// two rates agree, and both agree with the rate the filters' fill
    /// predicts. A query of five letters, "ab cd", is the control: three
    /// trigrams and two words set five times the bits, its rate is far
    /// lower, so the measurement can tell a different profile apart.
    #[tokio::test]
    async fn a_one_word_query_has_the_false_positive_profile_of_a_one_trigram_query() {
        let cipher = stack_cipher().await;
        let keyset = cipher.default_keyset();
        let mut runner = TestRunner::new_with_rng(
            Config::default(),
            TestRng::from_seed(RngAlgorithm::ChaCha, &[7; 32]),
        );
        let derive = |text: String| {
            let keyset = &keyset;
            async move {
                let filter = keyset
                    .match_terms::<ShortWords>(&text, nonempty!("people/name"))
                    .await
                    .expect("derives");
                (text, filter)
            }
        };

        let mut rows = Vec::with_capacity(ROWS);
        for _ in 0..ROWS {
            let words = draw(&mut runner, prop::collection::vec("[a-z]{4,6}", 3));
            rows.push(derive(words.join(" ")).await);
        }
        let fill: f64 = rows
            .iter()
            .map(|(_, filter)| (filter.positions().len() as f64 / 256.0).powi(3))
            .sum::<f64>()
            / ROWS as f64;

        let mut queries = Vec::new();
        for _ in 0..QUERIES {
            queries.push(("word", draw(&mut runner, "[a-z]{2}")));
            queries.push(("trigram", draw(&mut runner, "[a-z]{3}")));
            queries.push(("five letters", draw(&mut runner, "[a-z]{2} [a-z]{2}")));
        }

        let mut totals = std::collections::BTreeMap::<&str, (usize, usize, usize)>::new();
        for (kind, text) in queries {
            let (_, filter) = derive(text.clone()).await;
            // No row holds a short word, so every match of a query with one
            // is false; a trigram is held by the rows that contain it.
            let (false_positives, seen) = match kind {
                "trigram" => false_positive_rate(&rows, &filter, |row| row.contains(text.as_str())),
                _ => false_positive_rate(&rows, &filter, |_| false),
            };
            let total = totals.entry(kind).or_default();
            total.0 += false_positives;
            total.1 += seen;
            total.2 += filter.positions().len();
        }
        let rate_of = |kind: &str| {
            let (false_positives, seen, _) = totals[kind];
            false_positives as f64 / seen as f64
        };
        let bits_of = |kind: &str| totals[kind].2 as f64 / QUERIES as f64;

        let (word, trigram, five) = (rate_of("word"), rate_of("trigram"), rate_of("five letters"));
        assert!(
            (bits_of("word") - bits_of("trigram")).abs() < 0.2,
            "a word and a trigram set as many bits: {} and {}",
            bits_of("word"),
            bits_of("trigram")
        );
        assert!(
            (word - trigram).abs() <= 0.25 * trigram,
            "a word query's false-positive rate {word:.5} is a trigram query's {trigram:.5}"
        );
        for (kind, rate) in [("word", word), ("trigram", trigram)] {
            assert!(
                (rate - fill).abs() <= 0.25 * fill,
                "the {kind} rate {rate:.5} is the rate the fill predicts, {fill:.5}"
            );
        }
        assert!(
            five < word / 5.0,
            "the control: five letters, three trigrams and two words, match falsely far less ({five:.5} against {word:.5})"
        );
    }
}
