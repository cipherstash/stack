//! SEM term-generation tests against the local HMAC PRF backend, keyed by the
//! deterministic fake index key — no ZeroKMS credentials or network required.

use std::cmp::Ordering;

use stack_encrypt::nonempty;
use stack_encrypt::sem::{DefaultMatch, MatchConfig, MatchOptions, MatchTerm, Tokenizer};
use stack_encrypt::{Error, StackCipher};
use stack_kms::{FakeDataKeySource, IdentifiedBy};
use uuid::Uuid;

/// Type-level config with the v1 `Standard` (word) tokenizer.
struct WordMatch;

impl MatchConfig for WordMatch {
    fn options() -> MatchOptions {
        MatchOptions {
            tokenizer: Tokenizer::Standard,
            ..Default::default()
        }
    }
}

/// A config whose options fail validation at term-generation time.
macro_rules! bad_config {
    ($name:ident, $($field:ident: $value:expr),+ $(,)?) => {
        struct $name;
        impl MatchConfig for $name {
            fn options() -> MatchOptions {
                MatchOptions { $($field: $value,)+ ..Default::default() }
            }
        }
    };
}

bad_config!(TooBigK, k: 17);
bad_config!(TooSmallK, k: 1);
bad_config!(NonPowerOfTwoM, m: 100);
bad_config!(TooSmallM, m: 16);
bad_config!(ZeroNgram, tokenizer: Tokenizer::Ngram { length: 0 });

async fn generator() -> StackCipher<FakeDataKeySource> {
    StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await
        .expect("build cipher")
}

async fn generator_for(keyset: Uuid) -> StackCipher<FakeDataKeySource> {
    let cipher = generator().await;
    // Warm the cache so the caller's `keyset(..)` is a lookup; the cipher's
    // own default stays the client's, which is not ours to choose.
    let _ = cipher
        .keyset(IdentifiedBy::Uuid(keyset))
        .await
        .expect("select keyset");
    cipher
}

#[tokio::test]
async fn equality_terms_are_deterministic() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();
    let a = gen
        .equality_term("alice", nonempty!("users/email"))
        .await
        .unwrap();
    let b = gen
        .equality_term("alice", nonempty!("users/email"))
        .await
        .unwrap();
    assert_eq!(a, b, "same value + descriptor must yield the same term");
}

#[tokio::test]
async fn equality_terms_bind_the_descriptor() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();
    let a = gen
        .equality_term("alice", nonempty!("users/email"))
        .await
        .unwrap();
    let b = gen
        .equality_term("alice", nonempty!("users/name"))
        .await
        .unwrap();
    assert_ne!(a, b, "the descriptor must domain-separate terms");
}

#[tokio::test]
async fn equality_terms_differ_by_value() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();
    let a = gen
        .equality_term("alice", nonempty!("users/email"))
        .await
        .unwrap();
    let b = gen
        .equality_term("bob", nonempty!("users/email"))
        .await
        .unwrap();
    assert_ne!(a, b);
}

#[tokio::test]
async fn equality_terms_bind_the_index_key() {
    let cipher_a = generator_for(Uuid::from_u128(1)).await;
    let cipher_b = generator_for(Uuid::from_u128(2)).await;
    let gen_a = cipher_a
        .keyset(IdentifiedBy::Uuid(Uuid::from_u128(1)))
        .await
        .expect("keyset 1");
    let gen_b = cipher_b
        .keyset(IdentifiedBy::Uuid(Uuid::from_u128(2)))
        .await
        .expect("keyset 2");
    let a = gen_a
        .equality_term("alice", nonempty!("users/email"))
        .await
        .unwrap();
    let b = gen_b
        .equality_term("alice", nonempty!("users/email"))
        .await
        .unwrap();
    assert_ne!(a, b, "different keysets must yield different terms");
}

#[tokio::test]
async fn match_query_terms_are_contained_in_stored_terms() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();

    let stored = gen
        .match_terms::<DefaultMatch>("alice wonderland", nonempty!("users/bio"))
        .await
        .unwrap();
    let query = gen
        .match_terms::<DefaultMatch>("wonder", nonempty!("users/bio"))
        .await
        .unwrap();

    assert!(
        stored.contains(&query),
        "a substring's tokens must be contained in the stored term"
    );
}

/// Containment is a superset test, not an overlap test, and an empty probe
/// matches nothing — pinned on positions directly, so the verdict does not
/// hang on which bits a PRF happened to set.
#[test]
fn match_containment_needs_every_query_position() {
    let term = |positions: &[u16]| {
        MatchTerm::<DefaultMatch>::from_positions(positions.to_vec())
            .expect("positions inside the default filter")
    };
    let stored = term(&[3, 17, 200]);

    assert!(stored.contains(&term(&[3, 200])), "a subset is contained");
    assert!(
        stored.contains(&term(&[3, 17, 200])),
        "the set itself is contained"
    );
    assert!(
        !stored.contains(&term(&[3, 18])),
        "one missing position is enough to miss"
    );
    assert!(
        !stored.contains(&term(&[])),
        "an empty probe must not match every row"
    );
    assert!(
        !term(&[]).contains(&term(&[])),
        "not even against an empty term"
    );
}

#[tokio::test]
async fn match_query_terms_for_other_text_are_not_contained() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();

    let stored = gen
        .match_terms::<DefaultMatch>("alice wonderland", nonempty!("users/bio"))
        .await
        .unwrap();
    let query = gen
        .match_terms::<DefaultMatch>("zebra", nonempty!("users/bio"))
        .await
        .unwrap();

    assert!(
        !stored.contains(&query),
        "text sharing no token with the stored value must not match"
    );
}

#[tokio::test]
async fn match_is_case_insensitive_by_default() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();

    let stored = gen
        .match_terms::<DefaultMatch>("Alice", nonempty!("users/name"))
        .await
        .unwrap();
    let query = gen
        .match_terms::<DefaultMatch>("alice", nonempty!("users/name"))
        .await
        .unwrap();
    assert_eq!(stored, query);
}

#[tokio::test]
async fn match_binds_the_descriptor() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();

    let stored = gen
        .match_terms::<DefaultMatch>("alice", nonempty!("users/bio"))
        .await
        .unwrap();
    let query = gen
        .match_terms::<DefaultMatch>("alice", nonempty!("users/name"))
        .await
        .unwrap();
    assert_ne!(stored, query, "match tokens must be descriptor-bound");
}

#[tokio::test]
async fn match_positions_stay_within_the_filter() {
    struct SmallFilter;
    impl MatchConfig for SmallFilter {
        fn options() -> MatchOptions {
            MatchOptions {
                m: 64,
                ..Default::default()
            }
        }
    }

    let cipher = generator().await;
    let gen = cipher.default_keyset();
    let term = gen
        .match_terms::<SmallFilter>("a longer piece of text", nonempty!("users/bio"))
        .await
        .unwrap();
    assert!(!term.positions().is_empty());
    assert!(term.positions().iter().all(|&p| u32::from(p) < 64));
    // Sorted + deduped.
    assert!(term.positions().windows(2).all(|w| w[0] < w[1]));
}

#[tokio::test]
async fn match_rejects_invalid_options() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();

    // The v1 match indexer's bounds apply: k in 3..=16, m a power of two in
    // [32, 65536].
    assert!(gen
        .match_terms::<TooBigK>("xxx", nonempty!("d"))
        .await
        .is_err());
    assert!(gen
        .match_terms::<TooSmallK>("xxx", nonempty!("d"))
        .await
        .is_err());
    assert!(gen
        .match_terms::<NonPowerOfTwoM>("xxx", nonempty!("d"))
        .await
        .is_err());
    assert!(gen
        .match_terms::<TooSmallM>("xxx", nonempty!("d"))
        .await
        .is_err());

    // A zero-length n-gram must be an options error, not a panic.
    assert!(matches!(
        gen.match_terms::<ZeroNgram>("xxx", nonempty!("d")).await,
        Err(Error::Term(stack_encrypt::sem::TermError::InvalidOptions(
            _
        )))
    ));
}

#[tokio::test]
async fn match_rejects_text_that_yields_no_tokens() {
    use stack_encrypt::sem::TermError;

    let cipher = generator().await;
    let gen = cipher.default_keyset();

    // An empty term used as a query would vacuously match every stored row.
    for text in ["", "  "] {
        assert!(
            matches!(
                gen.match_terms::<DefaultMatch>(text, nonempty!("users/bio"))
                    .await,
                Err(Error::Term(TermError::EmptyTermText))
            ),
            "{text:?} must be rejected"
        );
    }

    // A probe shorter than the n-gram length could never match a stored gram
    // (v1 indexer semantics) — rejected instead of a silent false negative.
    assert!(matches!(
        gen.match_terms::<DefaultMatch>("hi", nonempty!("users/bio"))
            .await,
        Err(Error::Term(TermError::EmptyTermText))
    ));

    // Separator-only text under the Standard tokenizer.
    assert!(matches!(
        gen.match_terms::<WordMatch>(" ,;:! ", nonempty!("users/bio"))
            .await,
        Err(Error::Term(TermError::EmptyTermText))
    ));
}

#[tokio::test]
async fn word_tokenizer_matches_whole_words() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();

    let stored = gen
        .match_terms::<WordMatch>("alice in wonderland", nonempty!("users/bio"))
        .await
        .unwrap();
    let query = gen
        .match_terms::<WordMatch>("wonderland", nonempty!("users/bio"))
        .await
        .unwrap();
    assert!(stored.contains(&query));
}

#[tokio::test]
async fn ore_terms_preserve_order_and_determinism() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();

    let ten = gen.ore_term(10u64, nonempty!("users/age")).await.unwrap();
    let ten_again = gen.ore_term(10u64, nonempty!("users/age")).await.unwrap();
    let twenty = gen.ore_term(20u64, nonempty!("users/age")).await.unwrap();

    assert_eq!(ten, ten_again, "ORE terms must be deterministic");
    assert_eq!(ten.cmp(&twenty), Ordering::Less);
}

#[tokio::test]
async fn ore_terms_bind_the_descriptor() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();
    let a = gen.ore_term(10u64, nonempty!("users/age")).await.unwrap();
    let b = gen
        .ore_term(10u64, nonempty!("users/height"))
        .await
        .unwrap();
    assert_ne!(a, b, "per-descriptor ORE keys must differ");
}

#[tokio::test]
async fn string_ore_terms_preserve_lexicographic_order() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();
    let apple = gen
        .ore_term("apple", nonempty!("users/name"))
        .await
        .unwrap();
    let banana = gen
        .ore_term("banana", nonempty!("users/name"))
        .await
        .unwrap();
    assert_eq!(apple.cmp(&banana), Ordering::Less);
}

#[tokio::test]
async fn ope_terms_compare_with_plain_byte_order() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();

    let ten = gen.ope_term(10u64, nonempty!("users/age")).await.unwrap();
    let twenty = gen.ope_term(20u64, nonempty!("users/age")).await.unwrap();

    // OPE ciphertexts order with standard lexicographic comparison.
    assert!(ten.as_ref() < twenty.as_ref());
}

#[tokio::test]
async fn ore_and_ope_keys_are_domain_separated() {
    // The same descriptor must not derive the same key material for both
    // schemes; equal plaintexts should produce different ciphertext bytes.
    let cipher = generator().await;
    let gen = cipher.default_keyset();
    let ore = gen.ore_term(42u64, nonempty!("users/age")).await.unwrap();
    let ope = gen.ope_term(42u64, nonempty!("users/age")).await.unwrap();
    assert_ne!(ore.as_ref(), ope.as_ref());
}

#[tokio::test]
async fn owned_and_borrowed_text_yield_identical_ore_and_ope_terms() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();
    let borrowed = gen
        .ore_term("apple", nonempty!("users/name"))
        .await
        .unwrap();
    let owned = gen
        .ore_term(String::from("apple"), nonempty!("users/name"))
        .await
        .unwrap();
    assert_eq!(borrowed.as_ref(), owned.as_ref());

    let borrowed = gen
        .ope_term("apple", nonempty!("users/name"))
        .await
        .unwrap();
    let owned = gen
        .ope_term(String::from("apple"), nonempty!("users/name"))
        .await
        .unwrap();
    assert_eq!(borrowed.as_ref(), owned.as_ref());
}
