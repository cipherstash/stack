//! SEM term-generation tests against the local HMAC PRF backend, keyed by the
//! deterministic fake index key — no ZeroKMS credentials or network required.

use std::cmp::Ordering;

use stack_encrypt::sem::{MatchOptions, TermGenerator, Tokenizer};
use stack_kms::{FakeDataKeySource, IdentifiedBy, IndexKeySource};
use uuid::Uuid;

async fn generator() -> TermGenerator<vitaminc_hmac::HmacSha256Prf> {
    let (_, index_key) = FakeDataKeySource::new()
        .load_index_key(None)
        .await
        .expect("load index key");
    TermGenerator::from_index_key(&index_key)
}

async fn generator_for(keyset: Uuid) -> TermGenerator<vitaminc_hmac::HmacSha256Prf> {
    let (_, index_key) = FakeDataKeySource::new()
        .load_index_key(Some(IdentifiedBy::Uuid(keyset)))
        .await
        .expect("load index key");
    TermGenerator::from_index_key(&index_key)
}

#[tokio::test]
async fn equality_terms_are_deterministic() {
    let gen = generator().await;
    let a = gen.equality_term("alice", "users/email").await.unwrap();
    let b = gen.equality_term("alice", "users/email").await.unwrap();
    assert_eq!(a, b, "same value + descriptor must yield the same term");
}

#[tokio::test]
async fn equality_terms_bind_the_descriptor() {
    let gen = generator().await;
    let a = gen.equality_term("alice", "users/email").await.unwrap();
    let b = gen.equality_term("alice", "users/name").await.unwrap();
    assert_ne!(a, b, "the descriptor must domain-separate terms");
}

#[tokio::test]
async fn equality_terms_differ_by_value() {
    let gen = generator().await;
    let a = gen.equality_term("alice", "users/email").await.unwrap();
    let b = gen.equality_term("bob", "users/email").await.unwrap();
    assert_ne!(a, b);
}

#[tokio::test]
async fn equality_terms_bind_the_index_key() {
    let gen_a = generator_for(Uuid::from_u128(1)).await;
    let gen_b = generator_for(Uuid::from_u128(2)).await;
    let a = gen_a.equality_term("alice", "users/email").await.unwrap();
    let b = gen_b.equality_term("alice", "users/email").await.unwrap();
    assert_ne!(a, b, "different keysets must yield different terms");
}

#[tokio::test]
async fn match_query_terms_are_contained_in_stored_terms() {
    let gen = generator().await;
    let opts = MatchOptions::default();

    let stored = gen
        .match_terms("alice wonderland", "users/bio", &opts)
        .await
        .unwrap();
    let query = gen.match_terms("wonder", "users/bio", &opts).await.unwrap();

    assert!(
        stored.contains(&query),
        "a substring's tokens must be contained in the stored term"
    );
}

#[tokio::test]
async fn match_is_case_insensitive_by_default() {
    let gen = generator().await;
    let opts = MatchOptions::default();

    let stored = gen.match_terms("Alice", "users/name", &opts).await.unwrap();
    let query = gen.match_terms("alice", "users/name", &opts).await.unwrap();
    assert_eq!(stored, query);
}

#[tokio::test]
async fn match_binds_the_descriptor() {
    let gen = generator().await;
    let opts = MatchOptions::default();

    let stored = gen.match_terms("alice", "users/bio", &opts).await.unwrap();
    let query = gen.match_terms("alice", "users/name", &opts).await.unwrap();
    assert_ne!(stored, query, "match tokens must be descriptor-bound");
}

#[tokio::test]
async fn match_positions_stay_within_the_filter() {
    let gen = generator().await;
    let opts = MatchOptions {
        m: 64,
        ..Default::default()
    };

    let term = gen
        .match_terms("a longer piece of text", "users/bio", &opts)
        .await
        .unwrap();
    assert!(!term.positions().is_empty());
    assert!(term.positions().iter().all(|&p| u32::from(p) < opts.m));
    // Sorted + deduped.
    assert!(term.positions().windows(2).all(|w| w[0] < w[1]));
}

#[tokio::test]
async fn match_rejects_invalid_options() {
    let gen = generator().await;
    let bad_k = MatchOptions {
        k: 17,
        ..Default::default()
    };
    assert!(gen.match_terms("xxx", "d", &bad_k).await.is_err());

    // The v1 match indexer's lower bounds apply: k >= 3, m >= 32.
    let small_k = MatchOptions {
        k: 1,
        ..Default::default()
    };
    assert!(gen.match_terms("xxx", "d", &small_k).await.is_err());

    let bad_m = MatchOptions {
        m: 100,
        ..Default::default()
    };
    assert!(gen.match_terms("xxx", "d", &bad_m).await.is_err());

    let small_m = MatchOptions {
        m: 16,
        ..Default::default()
    };
    assert!(gen.match_terms("xxx", "d", &small_m).await.is_err());

    // A zero-length n-gram must be an options error, not a panic.
    let bad_ngram = MatchOptions {
        tokenizer: Tokenizer::Ngram { length: 0 },
        ..Default::default()
    };
    assert!(matches!(
        gen.match_terms("xxx", "d", &bad_ngram).await,
        Err(stack_encrypt::sem::TermError::InvalidOptions(_))
    ));
}

#[tokio::test]
async fn match_rejects_text_that_yields_no_tokens() {
    use stack_encrypt::sem::TermError;

    let gen = generator().await;
    let opts = MatchOptions::default();

    // An empty term used as a query would vacuously match every stored row.
    for text in ["", "  "] {
        assert!(
            matches!(
                gen.match_terms(text, "users/bio", &opts).await,
                Err(TermError::EmptyTermText)
            ),
            "{text:?} must be rejected"
        );
    }

    // A probe shorter than the n-gram length could never match a stored gram
    // (v1 indexer semantics) — rejected instead of a silent false negative.
    assert!(matches!(
        gen.match_terms("hi", "users/bio", &opts).await,
        Err(TermError::EmptyTermText)
    ));

    // Separator-only text under the Standard tokenizer.
    let standard = MatchOptions {
        tokenizer: Tokenizer::Standard,
        ..Default::default()
    };
    assert!(matches!(
        gen.match_terms(" ,;:! ", "users/bio", &standard).await,
        Err(TermError::EmptyTermText)
    ));
}

#[tokio::test]
async fn word_tokenizer_matches_whole_words() {
    let gen = generator().await;
    let opts = MatchOptions {
        tokenizer: Tokenizer::Standard,
        ..Default::default()
    };

    let stored = gen
        .match_terms("alice in wonderland", "users/bio", &opts)
        .await
        .unwrap();
    let query = gen
        .match_terms("wonderland", "users/bio", &opts)
        .await
        .unwrap();
    assert!(stored.contains(&query));
}

#[tokio::test]
async fn ore_terms_preserve_order_and_determinism() {
    let gen = generator().await;

    let ten = gen.ore_term(10u64, "users/age").await.unwrap();
    let ten_again = gen.ore_term(10u64, "users/age").await.unwrap();
    let twenty = gen.ore_term(20u64, "users/age").await.unwrap();

    assert_eq!(ten, ten_again, "ORE terms must be deterministic");
    assert_eq!(ten.cmp(&twenty), Ordering::Less);
}

#[tokio::test]
async fn ore_terms_bind_the_descriptor() {
    let gen = generator().await;
    let a = gen.ore_term(10u64, "users/age").await.unwrap();
    let b = gen.ore_term(10u64, "users/height").await.unwrap();
    assert_ne!(a, b, "per-descriptor ORE keys must differ");
}

#[tokio::test]
async fn string_ore_terms_preserve_lexicographic_order() {
    let gen = generator().await;
    let apple = gen.ore_term("apple", "users/name").await.unwrap();
    let banana = gen.ore_term("banana", "users/name").await.unwrap();
    assert_eq!(apple.cmp(&banana), Ordering::Less);
}

#[tokio::test]
async fn ope_terms_compare_with_plain_byte_order() {
    let gen = generator().await;

    let ten = gen.ope_term(10u64, "users/age").await.unwrap();
    let twenty = gen.ope_term(20u64, "users/age").await.unwrap();

    // OPE ciphertexts order with standard lexicographic comparison.
    assert!(ten.as_ref() < twenty.as_ref());
}

#[tokio::test]
async fn ore_and_ope_keys_are_domain_separated() {
    // The same descriptor must not derive the same key material for both
    // schemes; equal plaintexts should produce different ciphertext bytes.
    let gen = generator().await;
    let ore = gen.ore_term(42u64, "users/age").await.unwrap();
    let ope = gen.ope_term(42u64, "users/age").await.unwrap();
    assert_ne!(ore.as_ref(), ope.as_ref());
}
