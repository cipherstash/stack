//! Literal-payload smoke tests for the generated `public.eql_v3_text_match` surface:
//! `@@` fuzzy match engages (the `eql_v3.matches` wrapper), `=`/`@>`/`<@` raise
//! (blockers — `@@` is n-gram matching, NOT containment; ), `~~`/`~~*`
//! are absent (no pattern-match), and the domain CHECK requires `bf`. Uses
//! hand-written jsonb payloads carrying `bf` — no encryption/fixtures needed.
//! The fixture-backed match behaviour lives in `text_match.rs`.
use sqlx::PgPool;

/// Build a literal `public.eql_v3_text_match` cast expression carrying bloom array
/// `bf` (e.g. `"[1,2,3]"` or `"[]"`). Lets these tests state set-membership
/// semantics directly on `bf` arrays — deterministic, with no encryption and no
/// bloom false positives to reason about.
fn match_cast(bf: &str) -> String {
    format!("'{{\"v\":\"3\",\"i\":{{}},\"c\":\"x\",\"bf\":{bf}}}'::jsonb::public.eql_v3_text_match")
}

#[sqlx::test]
async fn text_match_at_at_engages(pool: PgPool) -> anyhow::Result<()> {
    // self-match: a filter matches a subset of itself (`@@` reduces to bloom
    // `match_term(a) @> match_term(b)`).
    let hit: bool = sqlx::query_scalar(
        "SELECT ('{\"v\":\"3\",\"i\":{},\"c\":\"x\",\"bf\":[1,2,3]}'::jsonb::public.eql_v3_text_match)
              @@ ('{\"v\":\"3\",\"i\":{},\"c\":\"x\",\"bf\":[2]}'::jsonb::public.eql_v3_text_match)",
    )
    .fetch_one(&pool)
    .await?;
    assert!(hit, "[1,2,3] @@ [2] must hold");
    Ok(())
}

#[sqlx::test]
async fn text_match_eq_is_blocked(pool: PgPool) -> anyhow::Result<()> {
    let err = sqlx::query(
        "SELECT ('{\"v\":\"3\",\"i\":{},\"c\":\"x\",\"bf\":[1]}'::jsonb::public.eql_v3_text_match)
              =  ('{\"v\":\"3\",\"i\":{},\"c\":\"x\",\"bf\":[1]}'::jsonb::public.eql_v3_text_match)",
    )
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(
        format!("{err}").contains("not supported"),
        "= must be blocked on text_match"
    );
    Ok(())
}

#[sqlx::test]
async fn text_match_containment_operators_are_blocked(pool: PgPool) -> anyhow::Result<()> {
    // `@>` / `<@` are NOT the match operator on text_match — the fuzzy match is
    // `@@` (`eql_v3.matches`). The containment operators are generated as blockers
    // and must raise, so a caller who reaches for containment semantics gets a
    // clear error instead of a silently-different result.
    const BF: &str = r#"{"v":"3","i":{},"c":"x","bf":[1,2,3]}"#;
    for op in ["@>", "<@"] {
        let sql = format!(
            "SELECT ($1::jsonb::public.eql_v3_text_match) {op} ($2::jsonb::public.eql_v3_text_match)"
        );
        eql_tests::assert_raises(&pool, &sql, &[Some(BF), Some(BF)], "not supported").await?;
    }
    Ok(())
}

#[sqlx::test]
async fn empty_bloom_needle_uses_like_semantics(pool: PgPool) -> anyhow::Result<()> {
    // A value too short to tokenize (e.g. the empty string) yields an empty bloom
    // filter (`bf: []`). An empty NEEDLE follows `LIKE ''` semantics, NOT
    // empty-set containment: it matches only a value whose own bloom is also
    // empty, never every row. Uses literal payloads so the assertion
    // is deterministic; the real-ciphertext counterparts (a `bf: []` from an
    // actual sub-trigram encryption) live in `text_match::empty_*`.
    const NON_EMPTY: &str =
        "'{\"v\":\"3\",\"i\":{},\"c\":\"x\",\"bf\":[1,2,3]}'::jsonb::public.eql_v3_text_match";
    const EMPTY: &str =
        "'{\"v\":\"3\",\"i\":{},\"c\":\"x\",\"bf\":[]}'::jsonb::public.eql_v3_text_match";

    // non-empty value vs empty needle: `'catty' LIKE ''` → false (was the bug:
    // vacuous containment returned true and matched every row).
    let non_empty_vs_empty: bool =
        sqlx::query_scalar(&format!("SELECT ({NON_EMPTY}) @@ ({EMPTY})"))
            .fetch_one(&pool)
            .await?;
    assert!(
        !non_empty_vs_empty,
        "a populated value must not match an empty needle"
    );

    // empty value vs empty needle: `'' LIKE ''` → true.
    let empty_vs_empty: bool = sqlx::query_scalar(&format!("SELECT ({EMPTY}) @@ ({EMPTY})"))
        .fetch_one(&pool)
        .await?;
    assert!(empty_vs_empty, "an empty value must match an empty needle");

    // empty value vs non-empty needle: `'' LIKE 'cat'` → false.
    let empty_vs_non_empty: bool =
        sqlx::query_scalar(&format!("SELECT ({EMPTY}) @@ ({NON_EMPTY})"))
            .fetch_one(&pool)
            .await?;
    assert!(
        !empty_vs_non_empty,
        "an empty filter must not match a non-empty needle"
    );
    Ok(())
}

#[sqlx::test]
async fn match_null_propagates(pool: PgPool) -> anyhow::Result<()> {
    // A NULL operand yields NULL (three-valued logic) rather than false or an
    // error. `eql_v3.matches` is deliberately NOT declared STRICT (that would
    // block inlining of its empty-needle guard and lose the GIN index); the NULL
    // propagates through the body's containment + guard on its own.
    const BF: &str = r#"{"v":"3","i":{},"c":"x","bf":[1,2,3]}"#;
    let sql =
        "SELECT ($1::jsonb::public.eql_v3_text_match) @@ ($2::jsonb::public.eql_v3_text_match)";
    eql_tests::assert_null(&pool, sql, &[None, Some(BF)]).await?;
    eql_tests::assert_null(&pool, sql, &[Some(BF), None]).await?;
    Ok(())
}

#[sqlx::test]
async fn text_match_matches_requires_all_elements(pool: PgPool) -> anyhow::Result<()> {
    // `@@` reduces to set containment on the bloom terms: the haystack bloom must
    // include *every* element of the needle bloom. This is what makes it unlike
    // SQL `LIKE` — there is no wildcard or anchoring, only "are all of these
    // ngrams present". Asserted on literal `bf` arrays so it is deterministic (no
    // bloom false positives).
    let cases = [
        ("[1,2,3]", "[1,2]", true),  // needle bloom is a proper subset
        ("[1,2,3]", "[3,4]", false), // partial overlap — 4 is absent
        ("[1,2]", "[3]", false),     // disjoint
    ];
    for (hay, needle, expected) in cases {
        let sql = format!("SELECT ({}) @@ ({})", match_cast(hay), match_cast(needle));
        let hit: bool = sqlx::query_scalar(&sql).fetch_one(&pool).await?;
        assert_eq!(
            hit, expected,
            "bf {hay} @@ bf {needle} should be {expected}"
        );
    }
    Ok(())
}

#[sqlx::test]
async fn text_match_like_ilike_absent(pool: PgPool) -> anyhow::Result<()> {
    // The bloom match surface replaces deprecated `LIKE`/`ILIKE`, but it is NOT a
    // pattern-match operator. `~~`/`~~*` are deliberately not declared on
    // public.eql_v3_text_match, so they resolve to PostgreSQL's "operator does not
    // exist" rather than an EQL blocker. Pin that they stay absent on the very
    // domain a `LIKE` user would reach for.
    const BF: &str = r#"{"v":"3","i":{},"c":"x","bf":[1]}"#;
    for op in ["~~", "~~*"] {
        let sql = format!(
            "SELECT $1::jsonb::public.eql_v3_text_match {op} $2::jsonb::public.eql_v3_text_match"
        );
        eql_tests::assert_raises(
            &pool,
            &sql,
            &[Some(BF), Some(BF)],
            "operator does not exist",
        )
        .await?;
    }
    Ok(())
}

#[sqlx::test]
async fn text_match_payload_check_rejects_missing_bf(pool: PgPool) -> anyhow::Result<()> {
    // The generated public.eql_v3_text_match domain CHECK requires the `bf` key
    // (src/v3/scalars/text/text_types.sql). A well-formed envelope lacking `bf`
    // must be rejected at the cast, so a match query can never silently run
    // against a payload that carries no bloom term.
    const NO_BF: &str = r#"{"v":"3","i":{},"c":"x"}"#;
    eql_tests::assert_raises(
        &pool,
        "SELECT $1::jsonb::public.eql_v3_text_match",
        &[Some(NO_BF)],
        "violates check constraint",
    )
    .await?;
    Ok(())
}
