//! A match index with short-word tokens (`MatchOptions::short_words`): a
//! word too short to hold an n-gram, such as the surname "Ng" under
//! 3-grams, is one token of its own, stored and queried.
//!
//! - **Round trip.** "Ng" stored is found by the query "Ng"; "Mike Ng" is
//!   found by "Ng" and by "Mike Ng"; "Nguyen" is not found by "Ng".
//! - **Identity.** The option is part of the index: a query asked under
//!   other options than the field declares is refused, and options the
//!   index cannot use are refused on both sides.
//! - **Containment.** For random text, the stored filter holds the filter of
//!   any run of its whole words.
//! - **Calibration.** A one-word query sets as many bits as a one-trigram
//!   query, and a row's chance of matching either falsely is the same.

mod common;

use common::stack_cipher;
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, RngAlgorithm, RngSeed, TestRng, TestRunner};
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::op::{self, MatchCase, Probabilistic};
use stack_encrypt::plan::{Field, FieldSchema, Fields, Indexed, PlanError, ValuePlan};
use stack_encrypt::sem::{MatchConfig, MatchOptions, MatchQuery, MatchTerms, TermError, Tokenizer};
use stack_encrypt::target::{Encrypted, IndexSpec};
use stack_encrypt::{nonempty, Error, Match, Plan, StackCipher};

/// A one-value plan of text under one match index of the configuration `C`.
type MatchPlan<C> = ValuePlan<String, Indexed<Match<C>>>;

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
impl MatchCase for ShortWords {
    type Case = op::CaseInsensitive;
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
impl MatchCase for StandardShortWords {
    type Case = op::CaseInsensitive;
}

type Cipher = StackCipher<FakeDataKeySource>;

fn plan() -> MatchPlan<ShortWords> {
    Plan::context("people/name")
        .with::<String, _>(Match::<ShortWords>::new())
        .build()
        .expect("a valid plan")
}

async fn store(
    cipher: &Cipher,
    plan: &MatchPlan<ShortWords>,
    text: &str,
) -> MatchTerms<ShortWords> {
    let stored: Encrypted<MatchTerms<ShortWords>> = cipher
        .encrypt(&text.to_owned())
        .using(plan)
        .await
        .unwrap_or_else(|error| panic!("{text:?} stores: {error}"));
    stored.terms
}

async fn query(
    cipher: &Cipher,
    plan: &MatchPlan<ShortWords>,
    text: &str,
) -> Result<MatchQuery<ShortWords>, Error> {
    cipher
        .query(op::Matches, text)
        .via(Match::<ShortWords>::new())
        .on(plan)
        .await
}

fn plan_error<T>(result: Result<T, Error>) -> PlanError {
    match result {
        Err(Error::Plan(error)) => error,
        Err(other) => panic!("expected a plan error, got {other:?}"),
        Ok(_) => panic!("expected a plan error, got a value"),
    }
}

mod given_short_words {
    use super::*;

    #[tokio::test]
    async fn a_two_letter_value_stores_one_token_and_the_two_letter_query_finds_it() {
        let cipher = stack_cipher().await;
        let plan = plan();
        let stored = store(&cipher, &plan, "Ng").await;
        assert!(
            !stored.positions().is_empty(),
            "\"Ng\" stores a token, not the empty filter"
        );
        let ng = query(&cipher, &plan, "Ng")
            .await
            .expect("\"Ng\" is a query");
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
        let plan = plan();
        let ng = query(&cipher, &plan, "ng").await.expect("a query");
        for (text, found) in [
            ("Ng", true),
            ("Mike Ng", true),
            ("Ng, Mike", true),
            ("NG Mike Smith", true),
            ("Nguyen", false),
            ("Mike Nguyen", false),
            ("Long", false),
        ] {
            let stored = store(&cipher, &plan, text).await;
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

    #[tokio::test]
    async fn a_query_of_words_and_ngrams_needs_every_short_word_whole() {
        let cipher = stack_cipher().await;
        let plan = plan();
        let mike_ng = query(&cipher, &plan, "Mike Ng").await.expect("a query");
        let stored = store(&cipher, &plan, "Mike Ng").await;
        assert!(stored.matches(&mike_ng), "\"Mike Ng\" finds itself");
        assert!(mike_ng.verify("mike ng"), "case folded");
        let longer = store(&cipher, &plan, "Mike Nguyen").await;
        assert!(
            !mike_ng.verify("Mike Nguyen"),
            "the query's short word must be a whole word of the row"
        );
        assert!(
            !longer.matches(&mike_ng),
            "and the filter says so: \"Mike Nguyen\" has no word token ng"
        );
        let mike = query(&cipher, &plan, "Mike").await.expect("a query");
        assert!(
            longer.matches(&mike) && stored.matches(&mike),
            "a query of trigrams alone finds both"
        );
    }

    #[tokio::test]
    async fn a_query_that_cuts_nothing_is_still_refused() {
        let cipher = stack_cipher().await;
        let plan = plan();
        for text in ["N", "", "  ", "n "] {
            let refused = query(&cipher, &plan, text).await;
            assert!(
                matches!(refused, Err(Error::Term(TermError::EmptyTermText))),
                "{text:?}: {refused:?}"
            );
        }
        let stored = store(&cipher, &plan, "N").await;
        assert!(
            stored.positions().is_empty(),
            "a one-letter value is still the empty filter"
        );
    }

    /// A person with one name under each index: the short-word index on
    /// `name`, the default on `alias`.
    struct Person {
        name: String,
        alias: String,
    }
    impl Fields for Person {
        fn field_names(&self) -> Vec<&str> {
            vec!["name", "alias"]
        }
        fn schema() -> Option<Vec<FieldSchema>> {
            Some(vec![
                FieldSchema::of::<String>("name"),
                FieldSchema::of::<String>("alias"),
            ])
        }
    }
    impl Field<String> for Person {
        fn field(&self, name: &str) -> Option<&String> {
            match name {
                "name" => Some(&self.name),
                "alias" => Some(&self.alias),
                _ => None,
            }
        }
    }

    /// The option is part of the index: asking a field for a match index
    /// under the other setting is refused, as a mismatched `k` is.
    #[tokio::test]
    async fn a_query_under_other_options_than_the_field_declares_is_refused() {
        let cipher = stack_cipher().await;
        let plan: Plan<Person, FakeDataKeySource> = Plan::context("people")
            .fields()
            .encrypt_index::<String>("name", Match::<ShortWords>::new())
            .encrypt_index::<String>("alias", Match)
            .build()
            .expect("a valid plan");
        let name = plan.field("name").expect("declared");
        let alias = plan.field("alias").expect("declared");
        assert_eq!(
            plan_error(cipher.query(op::Matches, "Mike").on(&name).await),
            PlanError::IndexOptions {
                field: "name".into(),
                declared: IndexSpec::Match(ShortWords::options()),
                asked: IndexSpec::Match(MatchOptions::default()),
            },
            "the default index is not the field's"
        );
        assert_eq!(
            plan_error(
                cipher
                    .query(op::Matches, "Mike")
                    .via(Match::<ShortWords>::new())
                    .on(&alias)
                    .await
            ),
            PlanError::IndexOptions {
                field: "alias".into(),
                declared: IndexSpec::Match(MatchOptions::default()),
                asked: IndexSpec::Match(ShortWords::options()),
            },
            "nor is the short-word index a default field's"
        );
        let found: MatchQuery<ShortWords> = cipher
            .query(op::Matches, "Ng")
            .via(Match::<ShortWords>::new())
            .on(&name)
            .await
            .expect("the field's own options answer");
        let mut row = cipher
            .encrypt(&Person {
                name: "Mike Ng".into(),
                alias: "Mike Ng".into(),
            })
            .using(&plan)
            .await
            .expect("stores");
        let stored: Encrypted<MatchTerms<ShortWords>> = row.take("name").expect("a name");
        assert!(stored.terms.matches(&found), "and find the row");
    }

    #[tokio::test]
    async fn options_the_index_cannot_use_are_refused_stored_and_queried() {
        let cipher = stack_cipher().await;
        let plan: MatchPlan<StandardShortWords> = Plan::context("people/name")
            .with::<String, _>(Match::<StandardShortWords>::new())
            .build()
            .expect("the plan does not read the options");
        let stored = cipher.encrypt(&"Mike Ng".to_owned()).using(&plan).await;
        assert!(
            matches!(stored, Err(Error::Term(TermError::InvalidOptions(_)))),
            "stored: {stored:?}"
        );
        let queried = cipher
            .query(op::Matches, "Mike Ng")
            .via(Match::<StandardShortWords>::new())
            .on(&plan)
            .await;
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
                let plan = plan();
                let stored = store(&cipher, &plan, &text).await;
                match query(&cipher, &plan, asked).await {
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
