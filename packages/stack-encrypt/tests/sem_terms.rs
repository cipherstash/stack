//! SEM term-generation tests against the local HMAC PRF backend, keyed by the
//! deterministic fake index key — no ZeroKMS credentials or network required.
//!
//! Each test derives a stored term by encrypting a value into its term
//! type. A match query comes from the query target, `matching_query`.

use std::cmp::Ordering;

use stack_encrypt::sem::{
    DefaultMatch, EqualityTerm, MatchConfig, MatchOptions, MatchTerms, OpeTerm, OreTerm, Tokenizer,
};
use stack_encrypt::target::{matching_query, AcceptsContext, Borrowed, CallerContext};
use stack_encrypt::{EncryptInto, EncryptTarget, Error, KeysetCipher, NonEmpty, StackCipher};
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

type Keyset<'a> = KeysetCipher<'a, FakeDataKeySource>;

fn field(name: &'static str) -> NonEmpty<&'static str> {
    NonEmpty::new(name).expect("a field name")
}

/// The term `value` stores as a `T` under `name`: the value encrypted into
/// its term type.
async fn stored<S, T>(keyset: &Keyset<'_>, value: S, name: &'static str) -> Result<T, Error>
where
    S: EncryptInto,
    T: EncryptTarget<S> + 'static,
    T::ContextInput: AcceptsContext,
    NonEmpty<&'static str>: Into<<T::ContextInput as AcceptsContext>::Value>,
{
    value.encrypt_into_with_context(keyset, field(name)).await
}

/// The equality term of `text` under `name`.
async fn equality(keyset: &Keyset<'_>, text: &str, name: &'static str) -> EqualityTerm {
    stored(keyset, text.to_owned(), name)
        .await
        .expect("an equality term derives")
}

/// The match filter `text` stores under `name`, cut as `O` declares.
async fn filter<O: MatchConfig>(
    keyset: &Keyset<'_>,
    text: &str,
    name: &'static str,
) -> Result<MatchTerms<O>, Error> {
    stored(keyset, text.to_owned(), name).await
}

/// The match filter a query of `text` under `name` sends, cut as `O`
/// declares.
async fn query<O: MatchConfig>(
    keyset: &Keyset<'_>,
    text: &str,
    name: &'static str,
) -> MatchTerms<O> {
    keyset
        .run(
            matching_query::<_, _, Borrowed, O>(),
            &text.to_owned(),
            CallerContext::from(field(name)),
        )
        .await
        .expect("a query of text that cuts a token derives")
}

async fn generator_for(keyset: Uuid) -> StackCipher<FakeDataKeySource> {
    let cipher = generator().await;
    // Warm the cache so the caller's `keyset(..)` is a lookup; the cipher's
    // own default stays the client's, which is not ours to choose.
    let _ = cipher.keyset(IdentifiedBy::Uuid(keyset));
    cipher
}

#[tokio::test]
async fn equality_terms_are_deterministic() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();
    let a = equality(&gen, "alice", "users/email").await;
    let b = equality(&gen, "alice", "users/email").await;
    assert_eq!(a, b, "same value + descriptor must yield the same term");
}

#[tokio::test]
async fn equality_terms_bind_the_descriptor() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();
    let a = equality(&gen, "alice", "users/email").await;
    let b = equality(&gen, "alice", "users/name").await;
    assert_ne!(a, b, "the descriptor must domain-separate terms");
}

#[tokio::test]
async fn equality_terms_differ_by_value() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();
    let a = equality(&gen, "alice", "users/email").await;
    let b = equality(&gen, "bob", "users/email").await;
    assert_ne!(a, b, "different values must yield different terms");
}

#[tokio::test]
async fn equality_terms_bind_the_index_key() {
    let cipher_a = generator_for(Uuid::from_u128(1)).await;
    let cipher_b = generator_for(Uuid::from_u128(2)).await;
    let gen_a = cipher_a.keyset(IdentifiedBy::Uuid(Uuid::from_u128(1)));
    let gen_b = cipher_b.keyset(IdentifiedBy::Uuid(Uuid::from_u128(2)));
    let a = equality(&gen_a, "alice", "users/email").await;
    let b = equality(&gen_b, "alice", "users/email").await;
    assert_ne!(a, b, "different keysets must yield different terms");
}

#[tokio::test]
async fn match_query_terms_are_contained_in_stored_terms() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();

    let stored = filter::<DefaultMatch>(&gen, "alice wonderland", "users/bio")
        .await
        .unwrap();
    let query = query::<DefaultMatch>(&gen, "wonder", "users/bio").await;

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
        MatchTerms::<DefaultMatch>::from_positions(positions.to_vec())
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

    let stored = filter::<DefaultMatch>(&gen, "alice wonderland", "users/bio")
        .await
        .unwrap();
    let query = query::<DefaultMatch>(&gen, "zebra", "users/bio").await;

    assert!(
        !stored.contains(&query),
        "text sharing no token with the stored value must not match"
    );
}

#[tokio::test]
async fn match_is_case_insensitive_by_default() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();

    let stored = filter::<DefaultMatch>(&gen, "Alice", "users/name")
        .await
        .unwrap();
    let query = query::<DefaultMatch>(&gen, "alice", "users/name").await;
    assert_eq!(
        stored, query,
        "a query in another case is the stored filter"
    );
}

#[tokio::test]
async fn match_binds_the_descriptor() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();

    let stored = filter::<DefaultMatch>(&gen, "alice", "users/bio")
        .await
        .unwrap();
    let query = query::<DefaultMatch>(&gen, "alice", "users/name").await;
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
    let term = filter::<SmallFilter>(&gen, "a longer piece of text", "users/bio")
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
    assert!(
        filter::<TooBigK>(&gen, "xxx", "d").await.is_err(),
        "k above 16 is refused"
    );
    assert!(
        filter::<TooSmallK>(&gen, "xxx", "d").await.is_err(),
        "k below 3 is refused"
    );
    assert!(
        filter::<NonPowerOfTwoM>(&gen, "xxx", "d").await.is_err(),
        "an m that is not a power of two is refused"
    );
    assert!(
        filter::<TooSmallM>(&gen, "xxx", "d").await.is_err(),
        "an m below 32 is refused"
    );

    // A zero-length n-gram must be an options error, not a panic.
    let zero = filter::<ZeroNgram>(&gen, "xxx", "d").await;
    assert!(
        matches!(
            zero,
            Err(Error::Term(stack_encrypt::sem::TermError::InvalidOptions(
                _
            )))
        ),
        "a zero-length n-gram is an options error: {zero:?}"
    );
}

#[tokio::test]
async fn match_stores_text_that_yields_no_tokens_as_the_empty_filter() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();
    let query = query::<DefaultMatch>(&gen, "hello", "users/bio").await;

    // Empty or separator-only text, and text shorter than the n-gram, cut
    // no token. The stored side keeps such a value as the empty filter: a
    // query always has a token, and the empty filter holds none of its
    // positions, so no query matches the value. (A query of such text is
    // refused by the query chain instead; `tests/op.rs` holds that.)
    for text in ["", "  ", "hi"] {
        let stored = filter::<DefaultMatch>(&gen, text, "users/bio")
            .await
            .unwrap_or_else(|error| panic!("{text:?} stores: {error}"));
        assert!(
            stored.positions().is_empty(),
            "{text:?} is the empty filter"
        );
        assert!(stored.to_bytes().is_empty());
        assert!(!stored.contains(&query), "{text:?}: no query matches it");
        assert!(
            !query.contains(&stored),
            "{text:?}: and the empty filter, as a query, matches nothing"
        );
        assert_eq!(
            MatchTerms::<DefaultMatch>::from_bytes(&stored.to_bytes()).unwrap(),
            stored,
            "{text:?}: the empty filter round-trips through its bytes"
        );
    }

    // Separator-only text under the Standard tokenizer.
    let stored = filter::<WordMatch>(&gen, " ,;:! ", "users/bio")
        .await
        .unwrap();
    assert!(
        stored.positions().is_empty(),
        "separator-only text is the empty filter"
    );
}

#[tokio::test]
async fn word_tokenizer_matches_whole_words() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();

    let stored = filter::<WordMatch>(&gen, "alice in wonderland", "users/bio")
        .await
        .unwrap();
    let query = query::<WordMatch>(&gen, "wonderland", "users/bio").await;
    assert!(stored.contains(&query), "a whole word is contained");
}

#[tokio::test]
async fn ore_terms_preserve_order_and_determinism() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();

    let ten: OreTerm<u64> = stored(&gen, 10u64, "users/age").await.unwrap();
    let ten_again: OreTerm<u64> = stored(&gen, 10u64, "users/age").await.unwrap();
    let twenty: OreTerm<u64> = stored(&gen, 20u64, "users/age").await.unwrap();

    assert_eq!(ten, ten_again, "ORE terms must be deterministic");
    assert_eq!(ten.cmp(&twenty), Ordering::Less, "10 orders below 20");
}

#[tokio::test]
async fn ore_terms_bind_the_descriptor() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();
    let a: OreTerm<u64> = stored(&gen, 10u64, "users/age").await.unwrap();
    let b: OreTerm<u64> = stored(&gen, 10u64, "users/height").await.unwrap();
    assert_ne!(a, b, "per-descriptor ORE keys must differ");
}

#[tokio::test]
async fn string_ore_terms_preserve_lexicographic_order() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();
    let apple: OreTerm<String> = stored(&gen, "apple".to_string(), "users/name")
        .await
        .unwrap();
    let banana: OreTerm<String> = stored(&gen, "banana".to_string(), "users/name")
        .await
        .unwrap();
    assert_eq!(
        apple.cmp(&banana),
        Ordering::Less,
        "\"apple\" orders below \"banana\""
    );
}

#[tokio::test]
async fn ope_terms_compare_with_plain_byte_order() {
    let cipher = generator().await;
    let gen = cipher.default_keyset();

    let ten: OpeTerm<u64> = stored(&gen, 10u64, "users/age").await.unwrap();
    let twenty: OpeTerm<u64> = stored(&gen, 20u64, "users/age").await.unwrap();

    // OPE ciphertexts order with standard lexicographic comparison.
    assert!(
        ten.as_bytes() < twenty.as_bytes(),
        "the bytes of 10 order below those of 20"
    );
}

#[tokio::test]
async fn ore_and_ope_keys_are_domain_separated() {
    // The same descriptor must not derive the same key material for both
    // schemes; equal plaintexts should produce different ciphertext bytes.
    let cipher = generator().await;
    let gen = cipher.default_keyset();
    let ore: OreTerm<u64> = stored(&gen, 42u64, "users/age").await.unwrap();
    let ope: OpeTerm<u64> = stored(&gen, 42u64, "users/age").await.unwrap();
    assert_ne!(
        ore.as_bytes(),
        ope.as_bytes(),
        "ORE and OPE derive under different keys"
    );
}
