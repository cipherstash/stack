//! Operator-typed queries (`stack_encrypt::op`, ADR-0009): a query names an
//! operator, the plan finds the index that answers it, and the term that
//! comes back is the query term for that operator, which for a match index
//! is not the stored term.
mod common;

use common::{loads_counting_cipher, stack_cipher};
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::op::{self, Limit, MatchCase, Probabilistic, Stats};
use stack_encrypt::plan::{Field, FieldSchema, Fields, PlanError};
use stack_encrypt::sem::{
    EqualityTerm, MatchConfig, MatchOptions, MatchQuery, MatchTerms, OpeTerm, OreTerm, RangeQuery,
    TermError, Tokenizer,
};
use stack_encrypt::target::{Encrypted, IndexSpec};
use stack_encrypt::{Equality, Error, Match, Ope, Ore, Plan};

/// A match configuration that keeps case, so its index answers only a
/// case-sensitive `Matches`.
struct Exact;
impl MatchConfig for Exact {
    fn options() -> MatchOptions {
        MatchOptions {
            downcase: false,
            ..Default::default()
        }
    }
}
impl MatchCase for Exact {
    type Case = op::CaseSensitive;
}

/// A match configuration the index cannot use: an n-gram length of zero.
struct ZeroGram;
impl MatchConfig for ZeroGram {
    fn options() -> MatchOptions {
        MatchOptions {
            tokenizer: Tokenizer::Ngram { length: 0 },
            ..Default::default()
        }
    }
}
impl MatchCase for ZeroGram {
    type Case = op::CaseInsensitive;
}

#[derive(Clone)]
struct Person {
    email: String,
    name: String,
}

impl Fields for Person {
    fn field_names(&self) -> Vec<&str> {
        vec!["email", "name"]
    }
    fn schema() -> Option<Vec<FieldSchema>> {
        Some(vec![
            FieldSchema::of::<String>("email"),
            FieldSchema::of::<String>("name"),
        ])
    }
}
impl Field<String> for Person {
    fn field(&self, name: &str) -> Option<&String> {
        match name {
            "email" => Some(&self.email),
            "name" => Some(&self.name),
            _ => None,
        }
    }
}

fn person() -> Person {
    Person {
        email: "bob@example.com".into(),
        name: "Alice Nguyen".into(),
    }
}

fn people_plan() -> Plan<Person, FakeDataKeySource> {
    Plan::context("people")
        .fields()
        .encrypt_index::<String>("email", (Equality, Match))
        .encrypt_index::<String>("name", Match::<Exact>::new())
        .build()
        .expect("a valid plan")
}

fn plan_error<T>(result: Result<T, Error>) -> PlanError {
    match result {
        Err(Error::Plan(error)) => error,
        Err(other) => panic!("expected a plan error, got {other:?}"),
        Ok(_) => panic!("expected a plan error, got a value"),
    }
}

#[tokio::test]
async fn an_eq_query_is_the_stored_equality_term() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let mut row = cipher.encrypt(&person()).using(&plan).await.unwrap();
    let email: Encrypted<(EqualityTerm, MatchTerms)> = row.take("email").unwrap();

    let query: EqualityTerm = cipher
        .query(op::Eq, "bob@example.com")
        .on(&plan.field("email").unwrap())
        .await
        .unwrap();
    assert_eq!(query, email.terms.0, "HMAC equality sends what it stores");
}

#[tokio::test]
async fn a_matches_query_is_a_filter_over_the_query_value_that_the_stored_filter_holds() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let mut row = cipher.encrypt(&person()).using(&plan).await.unwrap();
    let email: Encrypted<(EqualityTerm, MatchTerms)> = row.take("email").unwrap();
    let stored = email.terms.1;
    let email_plan = plan.field("email").unwrap();

    let query: MatchQuery = cipher
        .query(op::Matches, "BOB")
        .on(&email_plan)
        .await
        .unwrap();
    assert!(stored.matches(&query), "a case-folding index matches BOB");
    assert!(
        query.positions().len() < stored.positions().len(),
        "the query is the query value's filter, not the stored value's"
    );

    // The query's filter is the filter the index would store for the same
    // text, under the same label.
    let mut same_text = cipher
        .encrypt(&Person {
            email: "BOB".into(),
            name: "x".into(),
        })
        .using(&plan)
        .await
        .unwrap();
    let as_stored: Encrypted<(EqualityTerm, MatchTerms)> = same_text.take("email").unwrap();
    assert_eq!(query.to_bytes(), as_stored.terms.1.to_bytes());
    assert_eq!(query.positions(), as_stored.terms.1.positions());
    assert_eq!(query.clone(), query);

    let elsewhere: MatchQuery = cipher
        .query(op::Matches, "zzz")
        .on(&email_plan)
        .await
        .unwrap();
    assert!(!stored.matches(&elsewhere));
    assert_ne!(elsewhere, query);
}

#[tokio::test]
async fn a_match_index_with_its_own_configuration_is_named_with_via() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let mut row = cipher.encrypt(&person()).using(&plan).await.unwrap();
    let name: Encrypted<MatchTerms<Exact>> = row.take("name").unwrap();
    let name_plan = plan.field("name").unwrap();

    let exact = |value: &'static str| {
        cipher
            .query(op::Matches.case_sensitive(), value)
            .via(Match::<Exact>::new())
            .on(&name_plan)
    };
    let hit: MatchQuery<Exact> = exact("Nguyen").await.unwrap();
    assert!(name.terms.matches(&hit));
    let miss: MatchQuery<Exact> = exact("nguyen").await.unwrap();
    assert!(
        !name.terms.matches(&miss),
        "a case-sensitive index does not fold the query"
    );

    // The operator's default index is the default configuration, which
    // this field does not declare.
    assert_eq!(
        plan_error(cipher.query(op::Matches, "Nguyen").on(&name_plan).await),
        PlanError::IndexOptions {
            field: "name".into(),
            declared: IndexSpec::Match(Exact::options()),
            asked: IndexSpec::Match(MatchOptions::default()),
        }
    );
}

#[tokio::test]
async fn an_operator_the_field_has_no_index_for_is_refused_when_awaited() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    assert_eq!(
        plan_error(
            cipher
                .query(op::Eq, "Alice")
                .on(&plan.field("name").unwrap())
                .await
        ),
        PlanError::IndexNotDeclared {
            field: "name".into(),
            index: "eq"
        }
    );
}

#[tokio::test]
async fn a_one_value_plan_answers_from_its_indexes_by_type() {
    let cipher = stack_cipher().await;
    let plan = Plan::context("users/email")
        .with::<String, _>((Equality, Match))
        .build()
        .unwrap();
    let stored: Encrypted<(EqualityTerm, MatchTerms)> = cipher
        .encrypt(&"bob@example.com".to_owned())
        .using(&plan)
        .await
        .unwrap();

    let eq = cipher
        .query(op::Eq, "bob@example.com")
        .on(&plan)
        .await
        .unwrap();
    assert_eq!(eq, stored.terms.0);
    let matches = cipher
        .query(op::Matches, "example")
        .on(&plan)
        .await
        .unwrap();
    assert!(stored.terms.1.matches(&matches));

    let exact_plan = Plan::context("users/name")
        .with::<String, _>(Match::<Exact>::new())
        .build()
        .unwrap();
    let name: Encrypted<MatchTerms<Exact>> = cipher
        .encrypt(&"Alice".to_owned())
        .using(&exact_plan)
        .await
        .unwrap();
    let query = cipher
        .query(op::Matches.case_sensitive(), "Ali")
        .via(Match::<Exact>::new())
        .on(&exact_plan)
        .await
        .unwrap();
    assert!(name.terms.matches(&query));
}

#[tokio::test]
async fn a_target_answers_an_operator_through_the_index_it_names() {
    let cipher = stack_cipher().await;
    let eq_plan = Plan::value::<String>()
        .context("users/email")
        .encrypt_into::<EqualityTerm>()
        .build()
        .unwrap();
    let stored: EqualityTerm = cipher
        .encrypt(&"bob@example.com".to_owned())
        .using(&eq_plan)
        .await
        .unwrap();
    let query = cipher
        .query(op::Eq, "bob@example.com")
        .on(&eq_plan)
        .await
        .unwrap();
    assert_eq!(query, stored);

    let match_plan = Plan::value::<String>()
        .context("users/email")
        .encrypt_into::<MatchTerms>()
        .build()
        .unwrap();
    let stored: MatchTerms = cipher
        .encrypt(&"bob@example.com".to_owned())
        .using(&match_plan)
        .await
        .unwrap();
    let query = cipher
        .query(op::Matches, "bob")
        .on(&match_plan)
        .await
        .unwrap();
    assert!(stored.matches(&query));
}

#[tokio::test]
async fn a_target_with_several_terms_names_the_index_with_via() {
    let cipher = stack_cipher().await;
    let plan = Plan::value::<String>()
        .context("users/email")
        .encrypt_into::<Encrypted<(EqualityTerm, MatchTerms)>>()
        .build()
        .unwrap();
    let stored = cipher
        .encrypt(&"bob@example.com".to_owned())
        .using(&plan)
        .await
        .unwrap();
    let eq = cipher
        .query(op::Eq, "bob@example.com")
        .via(Equality)
        .on(&plan)
        .await
        .unwrap();
    assert_eq!(eq, stored.terms.0);
    let matches = cipher
        .query(op::Matches, "bob")
        .via(Match)
        .on(&plan)
        .await
        .unwrap();
    assert!(stored.terms.1.matches(&matches));

    // An index the target does not declare is refused when awaited.
    let one_term = Plan::value::<String>()
        .context("users/email")
        .encrypt_into::<Encrypted<EqualityTerm>>()
        .build()
        .unwrap();
    assert_eq!(
        plan_error(
            cipher
                .query(op::Matches, "bob")
                .via(Match)
                .on(&one_term)
                .await
        ),
        PlanError::IndexNotDeclared {
            field: "the value".into(),
            index: "match"
        }
    );
    let eq = cipher.query(op::Eq, "bob").on(&one_term).await;
    assert!(eq.is_ok(), "one term answers what the term answers");
}

#[tokio::test]
async fn operator_queries_settle_together_and_extend_like_the_write() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let mut row = cipher
        .encrypt(&person())
        .using(&plan)
        .extend(7u64)
        .await
        .unwrap();
    let email: Encrypted<(EqualityTerm, MatchTerms)> = row.take("email").unwrap();
    let email_plan = plan.field("email").unwrap();

    let (eq, matches) = stack_encrypt::all((
        cipher
            .query(op::Eq, "bob@example.com")
            .on(&email_plan)
            .extend(7u64),
        cipher
            .query(op::Matches, "bob")
            .on(&email_plan)
            .extend(7u64),
    ))
    .await
    .unwrap();
    assert_eq!(eq, email.terms.0);
    assert!(email.terms.1.matches(&matches));

    let unextended = cipher
        .query(op::Eq, "bob@example.com")
        .on(&email_plan)
        .await
        .unwrap();
    assert_ne!(
        unextended, email.terms.0,
        "the query is derived under the extended label"
    );
}

#[tokio::test]
async fn a_query_chain_debugs_without_its_value() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let email_plan = plan.field("email").unwrap();
    let secret = "bob@example.com";
    let shown = format!("{:?}", cipher.query(op::Eq, secret).on(&email_plan));
    assert_eq!(shown, "QueryOp { .. }");
}

/// A configuration whose `MatchCase` says it folds case while its options
/// keep it: the type cannot see the options, so the query is refused.
struct Mislabelled;
impl MatchConfig for Mislabelled {
    fn options() -> MatchOptions {
        MatchOptions {
            downcase: false,
            ..Default::default()
        }
    }
}
impl MatchCase for Mislabelled {
    type Case = op::CaseInsensitive;
}

#[tokio::test]
async fn a_match_case_that_disagrees_with_its_options_is_refused() {
    let cipher = stack_cipher().await;
    let plan = Plan::context("users/name")
        .with::<String, _>(Match::<Mislabelled>::new())
        .build()
        .unwrap();
    let refused = plan_error(
        cipher
            .query(op::Matches, "Bob")
            .via(Match::<Mislabelled>::new())
            .on(&plan)
            .await,
    );
    assert_eq!(
        refused,
        PlanError::MatchCase {
            declared: "CaseInsensitive",
            folds: false
        }
    );
    assert_eq!(
        refused.to_string(),
        "a match configuration declares the case CaseInsensitive but its options keep case"
    );
}

#[tokio::test]
async fn an_undeclared_index_is_refused_before_its_case_is_checked() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let refused = plan_error(
        cipher
            .query(op::Matches, "Bob")
            .via(Match::<Mislabelled>::new())
            .on(&plan.field("email").unwrap())
            .await,
    );
    assert!(
        matches!(refused, PlanError::IndexOptions { ref field, .. } if field == "email"),
        "the plan's refusal comes first, not the case: {refused:?}"
    );

    let no_context: Plan<Person, FakeDataKeySource> = Plan::fields()
        .encrypt::<String>("email")
        .encrypt_index::<String>("name", Match::<Mislabelled>::new())
        .build()
        .unwrap();
    let refused = plan_error(
        cipher
            .query(op::Matches, "Bob")
            .via(Match::<Mislabelled>::new())
            .on(&no_context.field("name").unwrap())
            .await,
    );
    assert_eq!(refused, PlanError::NoContext);
}

#[tokio::test]
async fn a_query_names_its_context_before_or_after_the_index() {
    let cipher = stack_cipher().await;
    let plan: Plan<Person, FakeDataKeySource> = Plan::fields()
        .encrypt_index::<String>("email", Match)
        .encrypt::<String>("name")
        .build()
        .unwrap();
    let email_plan = plan.field("email").unwrap();
    let before = cipher
        .query(op::Matches, "bob")
        .context("people")
        .via(Match)
        .on(&email_plan)
        .await
        .unwrap();
    let after = cipher
        .query(op::Matches, "bob")
        .via(Match)
        .context("people")
        .on(&email_plan)
        .await
        .unwrap();
    assert_eq!(before, after);
}

#[tokio::test]
async fn a_refused_operator_query_loads_no_keyset() {
    let (cipher, loads) = loads_counting_cipher().await;
    let plan: Plan<Person, common::CountingSource> = Plan::context("people")
        .fields()
        .encrypt::<String>("email")
        .encrypt_index::<String>("name", Match::<Exact>::new())
        .build()
        .unwrap();
    let refused = cipher
        .query(op::Eq, "Alice")
        .on(&plan.field("name").unwrap())
        .keyset("tenant")
        .await;
    assert_eq!(
        plan_error(refused),
        PlanError::IndexNotDeclared {
            field: "name".into(),
            index: "eq"
        }
    );
    assert_eq!(
        loads.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "refused before the named keyset is loaded"
    );
}

#[tokio::test]
async fn an_operator_query_runs_under_the_keyset_it_names() {
    let cipher = stack_cipher().await;
    let plan = Plan::context("users/email")
        .with::<String, _>(Equality)
        .build()
        .unwrap();
    let stored: Encrypted<EqualityTerm> = cipher
        .encrypt(&"bob@example.com".to_owned())
        .using(&plan)
        .keyset("tenant")
        .await
        .unwrap();
    let under_tenant = cipher
        .query(op::Eq, "bob@example.com")
        .on(&plan)
        .keyset("tenant")
        .await
        .unwrap();
    assert_eq!(under_tenant, stored.terms);
    let under_default = cipher
        .query(op::Eq, "bob@example.com")
        .on(&plan)
        .await
        .unwrap();
    assert_ne!(under_default, stored.terms, "another keyset, another key");
}

/// A match configuration with the smallest filter allowed, so a long value
/// sets nearly every bit and false positives are easy to find.
struct Tiny;
impl MatchConfig for Tiny {
    fn options() -> MatchOptions {
        MatchOptions {
            m: 32,
            ..Default::default()
        }
    }
}
impl MatchCase for Tiny {
    type Case = op::CaseInsensitive;
}

#[tokio::test]
async fn verify_keeps_every_real_match_and_folds_case_as_the_index_does() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let email_plan = plan.field("email").unwrap();
    let name_plan = plan.field("name").unwrap();

    let query = cipher
        .query(op::Matches, "BOB@Example")
        .on(&email_plan)
        .await
        .unwrap();
    assert!(query.verify("bob@example.com"));
    assert!(query.verify(&String::from("say hi to Bob@example.org")));
    assert!(!query.verify("alice@example.com"));
    assert!(query.clone().verify("bob@example.com"));

    let exact = cipher
        .query(op::Matches.case_sensitive(), "Nguyen")
        .via(Match::<Exact>::new())
        .on(&name_plan)
        .await
        .unwrap();
    assert!(exact.verify("Alice Nguyen"));
    assert!(
        !exact.verify("alice nguyen"),
        "a case-sensitive index keeps case"
    );
}

/// A match query is cut in Unicode 16 NFC, as the stored value is, so a
/// query and a row that spell one string in its two normal forms match and
/// verify. Text holding a code point unassigned in Unicode 16 has no normal
/// form: the query is refused, and such a row verifies against nothing.
#[tokio::test]
async fn a_match_query_is_cut_in_nfc_and_refuses_text_with_no_normal_form() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let email_plan = plan.field("email").unwrap();

    let query = cipher
        .query(op::Matches, "Rene\u{301}e")
        .on(&email_plan)
        .await
        .unwrap();
    let precomposed = cipher
        .query(op::Matches, "Ren\u{e9}e")
        .on(&email_plan)
        .await
        .unwrap();
    assert_eq!(query, precomposed, "one string, one filter");
    assert!(query.verify("Ren\u{e9}e Martin"));
    assert!(precomposed.verify("Rene\u{301}e Martin"));
    assert!(
        !query.verify("Ren\u{e9}e \u{378}"),
        "a value with no normal form verifies against nothing"
    );

    let refused = cipher
        .query(op::Matches, "Ren\u{378}e")
        .on(&email_plan)
        .await;
    assert!(
        matches!(
            refused,
            Err(Error::Term(TermError::Normalize(
                vitaminc_normalize::NormalizeError::UnassignedCodePoint
            )))
        ),
        "{refused:?}"
    );
}

#[tokio::test]
async fn verify_drops_a_row_the_filter_matched_by_chance() {
    let cipher = stack_cipher().await;
    let plan = Plan::context("notes/body")
        .with::<String, _>(Match::<Tiny>::new())
        .build()
        .unwrap();
    let value = "the quick brown fox jumps over the lazy dog and keeps running";
    let stored: Encrypted<MatchTerms<Tiny>> = cipher
        .encrypt(&value.to_owned())
        .using(&plan)
        .await
        .unwrap();

    let real = cipher
        .query(op::Matches, "lazy dog")
        .via(Match::<Tiny>::new())
        .on(&plan)
        .await
        .unwrap();
    assert!(stored.terms.matches(&real) && real.verify(value));

    // The value holds no digit, so no query with one is in it; a 32-bit
    // filter this full holds some of their filters anyway.
    let mut false_positive = None;
    for i in 0..1000 {
        let digits = format!("{i:04}");
        let query = cipher
            .query(op::Matches, &digits)
            .via(Match::<Tiny>::new())
            .on(&plan)
            .await
            .unwrap();
        if stored.terms.matches(&query) {
            false_positive = Some(query);
            break;
        }
    }
    let query = false_positive.expect("a 32-bit filter this full matches some query by chance");
    assert!(
        !query.verify(value),
        "the server would return this row; verify does not keep it"
    );
}

#[tokio::test]
async fn a_match_query_debugs_without_its_tokens() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let query = cipher
        .query(op::Matches, "needle")
        .on(&plan.field("email").unwrap())
        .await
        .unwrap();
    let shown = format!("{query:?}");
    assert_eq!(
        shown,
        format!("MatchQuery {{ positions: {:?}, .. }}", query.positions())
    );
    for token in ["nee", "eed", "edl", "dle", "needle"] {
        assert!(!shown.contains(token), "{shown}");
    }
}

/// Whole words, as the v1 match indexer's standard tokenizer splits them.
struct Words;
impl MatchConfig for Words {
    fn options() -> MatchOptions {
        MatchOptions {
            tokenizer: stack_encrypt::sem::Tokenizer::Standard,
            ..Default::default()
        }
    }
}
impl MatchCase for Words {
    type Case = op::CaseInsensitive;
}

/// A Bloom match asks for the query's tokens, in any order and anywhere;
/// it is not a substring test, and `verify` must not become one, or it
/// would drop rows the index rightly returned.
#[tokio::test]
async fn verify_is_a_token_test_not_a_substring_test() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let query = cipher
        .query(op::Matches, "abcd")
        .on(&plan.field("email").unwrap())
        .await
        .unwrap();
    assert!(query.verify("abc bcd"), "both 3-grams, never adjacent");
    assert!(!query.verify("abc"), "one 3-gram of two");

    let words = Plan::context("notes/body")
        .with::<String, _>(Match::<Words>::new())
        .build()
        .unwrap();
    let stored: Encrypted<MatchTerms<Words>> = cipher
        .encrypt(&"Hello, big World!".to_owned())
        .using(&words)
        .await
        .unwrap();
    let query = cipher
        .query(op::Matches, "world hello")
        .via(Match::<Words>::new())
        .on(&words)
        .await
        .unwrap();
    assert!(stored.terms.matches(&query));
    assert!(query.verify("Hello, big World!"));
    assert!(
        !query.verify("worldly hello"),
        "a word is a token, not a prefix"
    );
}

/// EQL v4's match parameters, with a notes column's prior.
struct Notes;
impl MatchConfig for Notes {
    fn options() -> MatchOptions {
        MatchOptions {
            k: 6,
            m: 2048,
            ..Default::default()
        }
    }
    fn expected_tokens() -> Option<u32> {
        Some(200)
    }
}
impl MatchCase for Notes {
    type Case = op::CaseInsensitive;
}

#[tokio::test]
async fn target_limit_sizes_the_fetch_from_the_query_and_the_prior() {
    let cipher = stack_cipher().await;
    let plan = Plan::context("notes/body")
        .with::<String, _>(Match::<Notes>::new())
        .build()
        .unwrap();
    let query = |text: &'static str| {
        cipher
            .query(op::Matches, text)
            .via(Match::<Notes>::new())
            .on(&plan)
    };
    let stats = Stats::declared(1_000_000);

    let short = query("ali").await.unwrap();
    let long = query("alice nguyen").await.unwrap();
    let (Limit::Rows(short_rows), Limit::Rows(long_rows)) = (
        short.target_limit(10, &stats),
        long.target_limit(10, &stats),
    ) else {
        panic!("a declared prior gives a finite fetch");
    };
    assert!(
        short_rows > 1_000,
        "three letters against long text match thousands of rows by chance: {short_rows}"
    );
    assert!(long_rows < 20, "a long query sets enough bits: {long_rows}");
    assert!(long_rows >= 10, "never fewer than `want`");

    // A tighter confidence asks for more.
    let strict = short.target_limit(10, &stats.clone().with_confidence(0.9999));
    assert!(strict.rows().unwrap() > short_rows);
}

#[tokio::test]
async fn target_limit_without_a_prior_needs_a_measured_column() {
    let cipher = stack_cipher().await;
    let plan = people_plan();
    let email_plan = plan.field("email").unwrap();
    let query = cipher
        .query(op::Matches, "bob")
        .on(&email_plan)
        .await
        .unwrap();

    // The default configuration declares no prior.
    assert_eq!(
        query.target_limit(10, &Stats::declared(1_000)),
        Limit::Unbounded
    );

    // Measure the column: the set-bit count of each stored filter.
    let mut histogram = std::collections::BTreeMap::<u32, u64>::new();
    for email in [
        "bob@example.com",
        "alice@example.org",
        "carol.smith@example.net",
    ] {
        let mut row = cipher
            .encrypt(&Person {
                email: email.into(),
                name: "x".repeat(4),
            })
            .using(&plan)
            .await
            .unwrap();
        let stored: Encrypted<(EqualityTerm, MatchTerms)> = row.take("email").unwrap();
        *histogram
            .entry(stored.terms.1.positions().len() as u32)
            .or_default() += 1;
    }
    // The pass rate the histogram gives this query, over a large table.
    let bits = query.positions().len() as i32;
    let rows_seen: u64 = histogram.values().sum();
    let p = histogram
        .iter()
        .map(|(&set, &n)| n as f64 * (f64::from(set) / 256.0).powi(bits))
        .sum::<f64>()
        / rows_seen as f64;
    let lambda = p * 1_000_000.0;
    let stats = Stats::measured(1_000_000, histogram);
    let Limit::Rows(rows) = query.target_limit(10, &stats) else {
        panic!("a measured column gives a finite fetch");
    };
    let extra = (rows - 10) as f64;
    assert!(
        extra >= lambda && extra <= lambda + 4.0 * lambda.sqrt() + 3.0,
        "10 wanted, λ = {lambda}: {rows}"
    );
}

/// A value too short to cut a token (two letters under 3-grams, or nothing
/// at all) is a valid thing to store in a match column. ADR-0009: the
/// stored term is the empty filter, which no query matches, and the value
/// itself seals and opens as any other.
#[tokio::test]
async fn a_short_match_value_stores_as_the_empty_filter_and_no_query_finds_it() {
    let cipher = stack_cipher().await;
    let plan = Plan::context("users/name")
        .with::<String, _>((Equality, Match))
        .build()
        .unwrap();
    let query = cipher.query(op::Matches, "alice").on(&plan).await.unwrap();

    for short in ["Al", "", " "] {
        let stored: Encrypted<(EqualityTerm, MatchTerms)> = cipher
            .encrypt(&short.to_owned())
            .using(&plan)
            .await
            .unwrap_or_else(|error| panic!("{short:?} stores: {error}"));
        assert!(
            stored.terms.1.positions().is_empty(),
            "{short:?} is stored as the empty filter"
        );
        assert!(
            !stored.terms.1.matches(&query),
            "{short:?}: the empty filter holds none of a query's positions"
        );
        assert!(!query.verify(short));
        let back: String = cipher.open(stored).using(&plan).await.unwrap();
        assert_eq!(back, short, "{short:?} opens as written");
    }

    // The equality term still finds it: only the match term is empty.
    let stored: Encrypted<(EqualityTerm, MatchTerms)> =
        cipher.encrypt(&"Al".to_owned()).using(&plan).await.unwrap();
    let eq = cipher.query(op::Eq, "Al").on(&plan).await.unwrap();
    assert_eq!(eq, stored.terms.0);
}

/// A query with no tokens would match every row, so it is the one query
/// value the library refuses: when the query is awaited, before a term
/// exists and before any keyset is loaded.
#[tokio::test]
async fn a_match_query_with_no_tokens_is_refused_before_any_term_or_keyset() {
    let (cipher, loads) = loads_counting_cipher().await;
    let plan: Plan<Person, common::CountingSource> = Plan::context("people")
        .fields()
        .encrypt_index::<String>("email", (Equality, Match))
        .encrypt_index::<String>("name", Match::<Exact>::new())
        .build()
        .unwrap();
    let email_plan = plan.field("email").unwrap();

    for text in ["", "  ", "bo"] {
        let refused = cipher
            .query(op::Matches, text)
            .on(&email_plan)
            .keyset("tenant")
            .await;
        assert!(
            matches!(refused, Err(Error::Term(TermError::EmptyTermText))),
            "{text:?}: {refused:?}"
        );
    }
    // Through `via`, under another configuration, and in a batch.
    let refused = cipher
        .query(op::Matches.case_sensitive(), "Al")
        .via(Match::<Exact>::new())
        .on(&plan.field("name").unwrap())
        .await;
    assert!(matches!(
        refused,
        Err(Error::Term(TermError::EmptyTermText))
    ));
    let refused = stack_encrypt::all((
        cipher.query(op::Eq, "bob@example.com").on(&email_plan),
        cipher.query(op::Matches, "bo").on(&email_plan),
    ))
    .await;
    assert!(matches!(
        refused,
        Err(Error::Term(TermError::EmptyTermText))
    ));
    assert_eq!(
        loads.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "refused before the named keyset is loaded"
    );
    assert_eq!(
        TermError::EmptyTermText.to_string(),
        "the query's text produces no match tokens (empty, separator-only, or shorter than the n-gram length)"
    );

    // The same text is a fine equality query, and a fine stored value.
    assert!(cipher.query(op::Eq, "").on(&email_plan).await.is_ok());
    let row = cipher
        .encrypt(&Person {
            email: "bo".into(),
            name: "Al".into(),
        })
        .using(&plan)
        .await;
    assert!(row.is_ok(), "short values store: {row:?}");
}

/// A match query under options the index cannot use is refused with
/// `InvalidOptions`, as storing under them is, and never reaches the
/// tokenizer: an n-gram length of zero would panic there.
#[tokio::test]
async fn a_match_query_under_invalid_options_is_refused_not_tokenised() {
    let cipher = stack_cipher().await;
    let plan = Plan::context("users/name")
        .with::<String, _>(Match::<ZeroGram>::new())
        .build()
        .unwrap();
    let refused = cipher
        .query(op::Matches, "alice")
        .via(Match::<ZeroGram>::new())
        .on(&plan)
        .await;
    assert!(
        matches!(refused, Err(Error::Term(TermError::InvalidOptions(_)))),
        "{refused:?}"
    );
    let stored = cipher.encrypt(&"alice".to_owned()).using(&plan).await;
    assert!(
        matches!(stored, Err(Error::Term(TermError::InvalidOptions(_)))),
        "{stored:?}"
    );
}

/// An ordering query sends the index's own term for the value: this
/// crate's ORE is CLLW, whose ciphertext has no left half to send alone,
/// so what is sent is what is stored, as for an HMAC. The ordering
/// operators default to ORE; OPE is named with `via`.
#[tokio::test]
async fn an_ordering_query_is_the_index_term_of_the_value() {
    let cipher = stack_cipher().await;
    let plan = Plan::context("users/age")
        .with::<u32, _>((Equality, Ore, Ope))
        .build()
        .unwrap();
    let stored: Encrypted<(EqualityTerm, OreTerm<u32>, OpeTerm<u32>)> =
        cipher.encrypt(&34u32).using(&plan).await.unwrap();

    let lt: OreTerm<u32> = cipher.query(op::Lt, &34u32).on(&plan).await.unwrap();
    let lte = cipher.query(op::Lte, &34u32).on(&plan).await.unwrap();
    let gt = cipher.query(op::Gt, &34u32).on(&plan).await.unwrap();
    let gte = cipher.query(op::Gte, &34u32).on(&plan).await.unwrap();
    for (name, term) in [("Lt", &lt), ("Lte", &lte), ("Gt", &gt), ("Gte", &gte)] {
        assert_eq!(term, &stored.terms.1, "{name} sends the ORE term");
    }
    let above = cipher.query(op::Lt, &35u32).on(&plan).await.unwrap();
    let below = cipher.query(op::Lt, &33u32).on(&plan).await.unwrap();
    assert!(
        below < stored.terms.1 && stored.terms.1 < above,
        "ORE terms order as the values"
    );

    let ope: OpeTerm<u32> = cipher
        .query(op::Gte, &34u32)
        .via(Ope)
        .on(&plan)
        .await
        .unwrap();
    assert_eq!(ope, stored.terms.2, "OPE is named with via");
    let ope_above = cipher
        .query(op::Gt, &35u32)
        .via(Ope)
        .on(&plan)
        .await
        .unwrap();
    assert!(
        ope.as_bytes() < ope_above.as_bytes(),
        "OPE terms order as bytes"
    );

    // A typed target answers the orderings through the index it names.
    let typed = Plan::value::<u32>()
        .context("users/balance")
        .encrypt_into::<Encrypted<OpeTerm<u32>>>()
        .build()
        .unwrap();
    let stored = cipher.encrypt(&5u32).using(&typed).await.unwrap();
    let query = cipher.query(op::Lte, &5u32).on(&typed).await.unwrap();
    assert_eq!(query, stored.terms);
}

/// `Between` is one term carrying both bounds, inclusive, derived under
/// the one label; each bound is the term the index sends for that value
/// alone (ADR-0009, decision 7).
#[tokio::test]
async fn a_between_query_is_one_term_carrying_both_bounds() {
    let cipher = stack_cipher().await;
    let plan = Plan::context("users/age")
        .with::<u32, _>(Ore)
        .build()
        .unwrap();

    let range: RangeQuery<OreTerm<u32>> = cipher
        .query(op::Between, &(18u32, 65))
        .on(&plan)
        .await
        .unwrap();
    let lo = cipher.query(op::Gte, &18u32).on(&plan).await.unwrap();
    let hi = cipher.query(op::Lte, &65u32).on(&plan).await.unwrap();
    assert_eq!(range.lo(), &lo);
    assert_eq!(range.hi(), &hi);
    assert_eq!(range.clone().into_bounds(), (lo, hi));

    // A stored value inside the range orders between the bounds.
    let inside: Encrypted<OreTerm<u32>> = cipher.encrypt(&30u32).using(&plan).await.unwrap();
    let outside: Encrypted<OreTerm<u32>> = cipher.encrypt(&70u32).using(&plan).await.unwrap();
    assert!(range.lo() <= &inside.terms && &inside.terms <= range.hi());
    assert!(&outside.terms > range.hi());

    // Inclusive at both ends: one value is `(v, v)`.
    let one = cipher
        .query(op::Between, &(40u32, 40))
        .on(&plan)
        .await
        .unwrap();
    assert_eq!(one.lo(), one.hi());
    assert_ne!(one, range);

    // OPE is named with via, and a typed target answers through its index.
    let both = Plan::context("users/age")
        .with::<u32, _>((Ore, Ope))
        .build()
        .unwrap();
    let ope: RangeQuery<OpeTerm<u32>> = cipher
        .query(op::Between, &(18u32, 65))
        .via(Ope)
        .on(&both)
        .await
        .unwrap();
    assert!(ope.lo().as_bytes() < ope.hi().as_bytes());
    let typed = Plan::value::<u32>()
        .context("users/age")
        .encrypt_into::<Encrypted<OreTerm<u32>>>()
        .build()
        .unwrap();
    let typed_range = cipher
        .query(op::Between, &(1u32, 2))
        .on(&typed)
        .await
        .unwrap();
    assert!(typed_range.lo() < typed_range.hi());
}

/// A range whose low bound is above its high bound holds nothing, so it is
/// refused when the query is awaited, before either bound's term is
/// derived and before any keyset is loaded.
#[tokio::test]
async fn an_inverted_range_is_refused_before_any_term_or_keyset() {
    let (cipher, loads) = loads_counting_cipher().await;
    let plan = Plan::context("users/age")
        .with::<u32, _>(Ore)
        .build()
        .unwrap();
    let refused = cipher
        .query(op::Between, &(65u32, 18))
        .on(&plan)
        .keyset("tenant")
        .await;
    assert!(matches!(
        refused,
        Err(Error::Term(TermError::InvertedRange))
    ));
    let refused = stack_encrypt::all((
        cipher.query(op::Lt, &40u32).on(&plan),
        cipher.query(op::Between, &(2u32, 1)).on(&plan),
    ))
    .await;
    assert!(matches!(
        refused,
        Err(Error::Term(TermError::InvertedRange))
    ));
    assert_eq!(
        loads.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "refused before the named keyset is loaded"
    );
    assert_eq!(
        TermError::InvertedRange.to_string(),
        "the range's low bound is above its high bound"
    );
    assert!(cipher
        .query(op::Between, &(18u32, 18))
        .on(&plan)
        .await
        .is_ok());
}

/// A field of a fields plan answers the orderings over its declared index,
/// under the field's own label, and refuses an index it does not declare.
/// An index-only field needs no sealing, so it can hold the integer types
/// the cipher does not seal on its own.
#[tokio::test]
async fn a_field_answers_the_orderings_through_its_declared_index() {
    #[derive(Clone)]
    struct Member {
        age: u32,
        balance: i64,
    }
    impl Fields for Member {
        fn field_names(&self) -> Vec<&str> {
            vec!["age", "balance"]
        }
        fn schema() -> Option<Vec<FieldSchema>> {
            Some(vec![
                FieldSchema::of::<u32>("age"),
                FieldSchema::of::<i64>("balance"),
            ])
        }
    }
    impl Field<u32> for Member {
        fn field(&self, name: &str) -> Option<&u32> {
            (name == "age").then_some(&self.age)
        }
    }
    impl Field<i64> for Member {
        fn field(&self, name: &str) -> Option<&i64> {
            (name == "balance").then_some(&self.balance)
        }
    }
    let cipher = stack_cipher().await;
    let plan: Plan<Member, FakeDataKeySource> = Plan::context("members")
        .fields()
        .encrypt_index::<u32>("age", Ope)
        .index::<i64>("balance", Ore)
        .build()
        .unwrap();
    let mut row = cipher
        .encrypt(&Member {
            age: 34,
            balance: -250,
        })
        .using(&plan)
        .await
        .unwrap();
    let age: Encrypted<OpeTerm<u32>> = row.take("age").unwrap();
    let balance: OreTerm<i64> = row.take("balance").unwrap();
    let age_plan = plan.field("age").unwrap();
    let balance_plan = plan.field("balance").unwrap();

    let query = cipher
        .query(op::Lte, &34u32)
        .via(Ope)
        .on(&age_plan)
        .await
        .unwrap();
    assert_eq!(query, age.terms);
    let range = cipher
        .query(op::Between, &(30u32, 40))
        .via(Ope)
        .on(&age_plan)
        .await
        .unwrap();
    assert!(
        range.lo().as_bytes() <= age.terms.as_bytes()
            && age.terms.as_bytes() <= range.hi().as_bytes()
    );

    // A signed value, ordered as a signed value.
    let owed = cipher
        .query(op::Lt, &-250i64)
        .on(&balance_plan)
        .await
        .unwrap();
    assert_eq!(owed, balance);
    let zero = cipher
        .query(op::Gte, &0i64)
        .on(&balance_plan)
        .await
        .unwrap();
    assert!(balance < zero, "a negative balance is below zero");
    let overdrawn = cipher
        .query(op::Between, &(-1_000i64, -1))
        .on(&balance_plan)
        .await
        .unwrap();
    assert!(overdrawn.lo() <= &balance && &balance <= overdrawn.hi());

    // The default index for an ordering is ORE, which the age field lacks.
    assert_eq!(
        plan_error(cipher.query(op::Lt, &34u32).on(&age_plan).await),
        PlanError::IndexNotDeclared {
            field: "age".into(),
            index: "ore"
        }
    );
    assert_eq!(
        plan_error(cipher.query(op::Between, &(1u32, 2)).on(&age_plan).await),
        PlanError::IndexNotDeclared {
            field: "age".into(),
            index: "ore"
        }
    );
    // And a value of another type than the field declares.
    assert_eq!(
        plan_error(cipher.query(op::Lt, &34u64).via(Ope).on(&age_plan).await),
        PlanError::FieldType {
            field: "age".into(),
            expected: "u32"
        }
    );
}
