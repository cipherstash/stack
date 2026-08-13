//! Direct behavioural tests for the self-contained `eql_v3` searchable-
//! encrypted-metadata (SEM) index-term functions (`eql_v3_internal.hmac_256`,
//! `eql_v3_internal.ore_block_256` and their comparators).
//!
//! These functions are the self-contained `eql_v3` SEM surface (`src/v3/sem/`).
//! The scalar matrix already exercises the happy path of the *array* comparator
//! end-to-end against real ciphertext fixtures (ordering, equality, min/max,
//! injectivity, index engagement). This file covers the branches the matrix
//! structurally cannot reach:
//!
//! - T2: the `'Ciphertexts are different lengths'` RAISE (all real fixtures are
//!   equal length, so the matrix never hits it).
//! - T3: NULL-term ordering inside `compare_ore_block_256_term` — the
//!   `STRICT` comparison wrappers short-circuit before these branches run.
//! - T4: array-level NULL + empty/cardinality base cases of the recursion.
//! - T5: presence checks (`has_*`) and the missing-`ob` RAISE.
//!
//! These tests build terms directly from hex literals, so they need no fixture
//! data or table setup.

use anyhow::Result;
use eql_tests::assert_raises;
use sqlx::PgPool;

/// A single term built directly from hex — no encryption needed for the
/// structural/edge-case tests.
fn term(hex: &str) -> String {
    format!("ROW(decode('{hex}', 'hex'))::eql_v3_internal.ore_block_256_term")
}

/// T2 — The term comparator must reject ciphertexts of different lengths. This
/// guard is unreachable via the matrix (every real fixture is equal length).
#[sqlx::test]
async fn ore_term_comparator_rejects_different_length_ciphertexts(pool: PgPool) -> Result<()> {
    let sql = format!(
        "SELECT eql_v3_internal.compare_ore_block_256_term({}, {})",
        term("aabbccdd"),   // 4 bytes
        term("aabbccddee"), // 5 bytes
    );
    assert_raises(&pool, &sql, &[], "Ciphertexts are different lengths").await?;
    Ok(())
}

/// T3 — NULL-term ordering inside `compare_ore_block_256_term`. The
/// function is intentionally NOT `STRICT`, so these defensive branches are
/// reachable by a direct call (the `STRICT` comparison wrappers never reach
/// them). Pins: `(NULL, t) = -1`, `(t, NULL) = 1`, `(NULL, NULL) = 0`.
#[sqlx::test]
async fn ore_term_comparator_null_ordering(pool: PgPool) -> Result<()> {
    let t = term("aabb");
    let n = "NULL::eql_v3_internal.ore_block_256_term";

    let cases = [
        (
            format!("SELECT eql_v3_internal.compare_ore_block_256_term({n}, {t})"),
            -1,
        ),
        (
            format!("SELECT eql_v3_internal.compare_ore_block_256_term({t}, {n})"),
            1,
        ),
        (
            format!("SELECT eql_v3_internal.compare_ore_block_256_term({n}, {n})"),
            0,
        ),
    ];

    for (sql, expected) in cases {
        let got: i32 = sqlx::query_scalar(&sql).fetch_one(&pool).await?;
        assert_eq!(got, expected, "null-term ordering: {sql}");
    }
    Ok(())
}

/// T4 — Array-level NULL and empty/cardinality base cases of the recursive
/// `compare_ore_block_256_terms(term[], term[])`. NULL array → NULL;
/// both empty → 0; empty vs non-empty → -1; non-empty vs empty → 1.
#[sqlx::test]
async fn ore_terms_array_null_and_empty_base_cases(pool: PgPool) -> Result<()> {
    let t = format!("ARRAY[{}]", term("aabb"));
    let empty = "ARRAY[]::eql_v3_internal.ore_block_256_term[]";
    let null_arr = "NULL::eql_v3_internal.ore_block_256_term[]";

    // NULL array operand → NULL result (the array overload returns NULL; it is
    // not STRICT). Typed as Option<i32>; the shared `assert_null` helper only
    // types Option<bool>, so query directly here.
    for sql in [
        format!("SELECT eql_v3_internal.compare_ore_block_256_terms({null_arr}, {t})"),
        format!("SELECT eql_v3_internal.compare_ore_block_256_terms({t}, {null_arr})"),
    ] {
        let got: Option<i32> = sqlx::query_scalar(&sql).fetch_one(&pool).await?;
        assert!(got.is_none(), "NULL array operand must yield NULL: {sql}");
    }

    let cases = [
        (
            format!("SELECT eql_v3_internal.compare_ore_block_256_terms({empty}, {empty})"),
            0,
        ),
        (
            format!("SELECT eql_v3_internal.compare_ore_block_256_terms({empty}, {t})"),
            -1,
        ),
        (
            format!("SELECT eql_v3_internal.compare_ore_block_256_terms({t}, {empty})"),
            1,
        ),
    ];
    for (sql, expected) in cases {
        let got: i32 = sqlx::query_scalar(&sql).fetch_one(&pool).await?;
        assert_eq!(got, expected, "array base case: {sql}");
    }
    Ok(())
}

/// T5 — SEM presence checks (`has_ore_block_256`, `has_hmac_256`), the
/// extractor's missing-`ob` and non-array-`ob` RAISEs, and its NULL-jsonb
/// short-circuit.
#[sqlx::test]
async fn sem_presence_checks_and_missing_ob_behaviour(pool: PgPool) -> Result<()> {
    let bool_cases = [
        (
            r#"SELECT eql_v3_internal.has_ore_block_256('{"ob":["aa"]}'::jsonb)"#,
            true,
        ),
        (
            r#"SELECT eql_v3_internal.has_ore_block_256('{}'::jsonb)"#,
            false,
        ),
        // json-null `ob` is typed `'null'`, not `'array'` → absent.
        (
            r#"SELECT eql_v3_internal.has_ore_block_256('{"ob":null}'::jsonb)"#,
            false,
        ),
        // Present-but-non-array `ob` is rejected as absent: a well-formed ORE
        // term is always a JSON array of block terms, so a scalar and an object
        // both → false. This is the boundary that makes `ore_block_256` RAISE on
        // a malformed `ob` instead of degrading it to a NULL index term.
        (
            r#"SELECT eql_v3_internal.has_ore_block_256('{"ob":5}'::jsonb)"#,
            false,
        ),
        (
            r#"SELECT eql_v3_internal.has_ore_block_256('{"ob":{}}'::jsonb)"#,
            false,
        ),
        (
            r#"SELECT eql_v3_internal.has_hmac_256('{"hm":"abc"}'::jsonb)"#,
            true,
        ),
        (r#"SELECT eql_v3_internal.has_hmac_256('{}'::jsonb)"#, false),
    ];
    for (sql, expected) in bool_cases {
        let got: bool = sqlx::query_scalar(sql).fetch_one(&pool).await?;
        assert_eq!(got, expected, "presence check: {sql}");
    }

    // Missing `ob` → RAISE.
    assert_raises(
        &pool,
        r#"SELECT eql_v3_internal.ore_block_256('{"foo":1}'::jsonb)"#,
        &[],
        "Expected an ore index (ob) value",
    )
    .await?;

    // Present-but-non-array `ob` → RAISE at the extractor boundary, NOT a silent
    // NULL index term (`has_ore_block_256` reports it absent).
    assert_raises(
        &pool,
        r#"SELECT eql_v3_internal.ore_block_256('{"ob":5}'::jsonb)"#,
        &[],
        "Expected an ore index (ob) value",
    )
    .await?;

    // NULL jsonb → NULL composite (STRICT short-circuit), NOT a raise.
    let is_null: bool =
        sqlx::query_scalar("SELECT eql_v3_internal.ore_block_256(NULL::jsonb) IS NULL")
            .fetch_one(&pool)
            .await?;
    assert!(
        is_null,
        "NULL jsonb must extract to a NULL composite, not raise"
    );
    Ok(())
}

/// T6 — Characterization of `eql_v3_internal.jsonb_array_to_bytea_array(jsonb)` across its
/// three real-world input shapes. This is the safety net for the plpgsql→sql
/// inlining refactor (the function is reached per-encrypted-value, so it must be
/// inlinable). Behaviour pinned:
///   - JSON null  (`'null'`) → NULL          (the load-bearing null guard)
///   - empty array (`'[]'`)  → NULL          (array_agg over zero rows is NULL)
///   - populated array       → decoded bytea[]
///
/// Note the deliberate divergence the inlinable CASE form introduces vs. the
/// v2 plpgsql equivalent: a non-array JSON *scalar* (e.g. a number) returns NULL
/// rather than raising `cannot extract elements from a scalar`. Both callers only
/// ever pass an array or json-null (`val->'ob'`), so this is unreachable in
/// practice; we pin it here so the divergence is intentional and visible.
#[sqlx::test]
async fn jsonb_array_to_bytea_array_input_shapes(pool: PgPool) -> Result<()> {
    // SQL NULL (distinct from JSON null `'null'`). The function is NOT STRICT,
    // so the body runs: `jsonb_typeof(NULL)` is NULL → the CASE guard
    // `WHEN jsonb_typeof(val) = 'array'` is not-true → ELSE NULL.
    let is_null: bool = sqlx::query_scalar(
        "SELECT eql_v3_internal.jsonb_array_to_bytea_array(NULL::jsonb) IS NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert!(
        is_null,
        "SQL NULL must yield NULL bytea[] (function is not STRICT)"
    );

    // JSON null → NULL.
    let is_null: bool = sqlx::query_scalar(
        "SELECT eql_v3_internal.jsonb_array_to_bytea_array('null'::jsonb) IS NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert!(is_null, "JSON null must yield NULL bytea[]");

    // Empty array → NULL (array_agg over zero rows).
    let is_null: bool = sqlx::query_scalar(
        "SELECT eql_v3_internal.jsonb_array_to_bytea_array('[]'::jsonb) IS NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert!(is_null, "empty JSON array must yield NULL bytea[]");

    // Single-element array → one decoded bytea element.
    let decoded: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT eql_v3_internal.jsonb_array_to_bytea_array('[\"aabb\"]'::jsonb)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        decoded,
        vec![vec![0xaau8, 0xbb]],
        "single-element array must hex-decode to a 1-element bytea[]"
    );

    // Populated array → hex-decoded bytea[] round-trip.
    let decoded: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT eql_v3_internal.jsonb_array_to_bytea_array('[\"aabb\",\"ccdd\"]'::jsonb)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        decoded,
        vec![vec![0xaau8, 0xbb], vec![0xccu8, 0xdd]],
        "populated array must hex-decode to bytea[]"
    );

    // Deliberate delta: a non-array JSON scalar returns NULL (not a raise).
    let is_null: bool =
        sqlx::query_scalar("SELECT eql_v3_internal.jsonb_array_to_bytea_array('5'::jsonb) IS NULL")
            .fetch_one(&pool)
            .await?;
    assert!(
        is_null,
        "non-array JSON scalar must yield NULL (documented delta)"
    );

    // Same delta for a non-array JSON object — `jsonb_typeof` is 'object', so
    // the CASE guard is not-true → ELSE NULL (not a raise).
    let is_null: bool = sqlx::query_scalar(
        "SELECT eql_v3_internal.jsonb_array_to_bytea_array('{}'::jsonb) IS NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert!(
        is_null,
        "non-array JSON object must yield NULL (documented delta)"
    );

    Ok(())
}

/// T7 — Characterization of `eql_v3_internal.jsonb_array_to_ore_block_256(jsonb)`
/// across the same three input shapes. Safety net for the same plpgsql→sql
/// inlining refactor. Behaviour pinned:
///   - JSON null  (`'null'`) → NULL composite
///   - empty array (`'[]'`)  → non-NULL composite with ZERO terms (issue #262).
///     An empty `ob` is what encrypting the empty string `""` produces; it must
///     stay comparable so it sorts first, not collapse to NULL terms and drop
///     out of ordered queries. The inner `array_agg`'s NULL is coalesced to an
///     empty `ore_block_256_term[]`.
///   - populated array       → non-NULL composite with one term per element
///
/// Same documented delta as T6 for a non-array JSON scalar.
#[sqlx::test]
async fn jsonb_array_to_ore_block_input_shapes(pool: PgPool) -> Result<()> {
    // SQL NULL (distinct from JSON null `'null'`). Not STRICT, so the body
    // runs: `jsonb_typeof(NULL)` is NULL → CASE guard not-true → ELSE NULL.
    let is_null: bool = sqlx::query_scalar(
        "SELECT eql_v3_internal.jsonb_array_to_ore_block_256(NULL::jsonb) IS NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert!(
        is_null,
        "SQL NULL must yield NULL composite (function is not STRICT)"
    );

    // JSON null → NULL composite.
    let is_null: bool = sqlx::query_scalar(
        "SELECT eql_v3_internal.jsonb_array_to_ore_block_256('null'::jsonb) IS NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert!(is_null, "JSON null must yield NULL composite");

    // Empty array → non-NULL composite with ZERO terms (issue #262). The empty
    // `ob` from encrypting `""` must remain comparable (so it sorts first via the
    // comparator's cardinality guard) rather than collapsing to NULL terms.
    let is_null: bool = sqlx::query_scalar(
        "SELECT eql_v3_internal.jsonb_array_to_ore_block_256('[]'::jsonb) IS NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert!(!is_null, "empty JSON array must yield a non-NULL composite");
    let term_count: i32 = sqlx::query_scalar(
        "SELECT cardinality((eql_v3_internal.jsonb_array_to_ore_block_256('[]'::jsonb)).terms)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        term_count, 0,
        "empty JSON array must yield a zero-term composite"
    );

    // Single-element array → non-NULL composite with exactly 1 term.
    let term_count: i32 = sqlx::query_scalar(
        "SELECT cardinality((eql_v3_internal.jsonb_array_to_ore_block_256('[\"aabb\"]'::jsonb)).terms)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        term_count, 1,
        "single-element array must yield exactly one term"
    );

    // Populated array → non-NULL composite with one term per element.
    let term_count: i32 = sqlx::query_scalar(
        "SELECT cardinality((eql_v3_internal.jsonb_array_to_ore_block_256('[\"aabb\",\"ccdd\",\"eeff\"]'::jsonb)).terms)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        term_count, 3,
        "populated array must yield one term per element"
    );

    // Deliberate delta: a non-array JSON scalar returns NULL (not a raise).
    let is_null: bool = sqlx::query_scalar(
        "SELECT eql_v3_internal.jsonb_array_to_ore_block_256('5'::jsonb) IS NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert!(
        is_null,
        "non-array JSON scalar must yield NULL (documented delta)"
    );

    // Same delta for a non-array JSON object — `jsonb_typeof` is 'object', so
    // the CASE guard is not-true → ELSE NULL (not a raise).
    let is_null: bool = sqlx::query_scalar(
        "SELECT eql_v3_internal.jsonb_array_to_ore_block_256('{}'::jsonb) IS NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert!(
        is_null,
        "non-array JSON object must yield NULL (documented delta)"
    );

    Ok(())
}

/// T8 — Catalog pin for all three `compare_ore_block_256_term(s)` overloads
/// (term×term, term[]×term[], composite×composite). Two load-bearing catalog
/// properties are pinned at the same layer:
///
///   - `IMMUTABLE` (`provolatile = 'i'`). The
///     comparison is deterministic — pgcrypto `encrypt()` is itself `IMMUTABLE`
///     — and the marker is what lets the planner fold/cache these in
///     ordering/index contexts, so a silent regression to `VOLATILE` (e.g.
///     dropping the keyword on a future edit) must fail CI.
///   - NOT `STRICT` (`proisstrict = false`). The NULL-handling branches inside
///     the comparators are load-bearing (T3 pins their behaviour for the term
///     overload). A stray `STRICT` would let PostgreSQL skip the body on a NULL
///     argument, silently bypassing those branches. T3 guards this behaviourally
///     for the term overload; this pins it at the catalog layer for all three,
///     including the array/composite overloads T3 does not directly assert.
#[sqlx::test]
async fn ore_comparators_are_immutable(pool: PgPool) -> Result<()> {
    let rows: Vec<(String, String, bool)> = sqlx::query_as(
        r#"
        SELECT pg_catalog.pg_get_function_arguments(p.oid) AS args,
               p.provolatile::text                         AS provolatile,
               p.proisstrict                               AS isstrict
        FROM pg_catalog.pg_proc p
        WHERE p.pronamespace = 'eql_v3_internal'::regnamespace
          AND p.proname IN (
            'compare_ore_block_256_term',
            'compare_ore_block_256_terms'
          )
        ORDER BY args
        "#,
    )
    .fetch_all(&pool)
    .await?;

    // Pin the count so an overload silently disappearing (or a fourth appearing)
    // also fails, not just a volatility/strictness flip.
    assert_eq!(
        rows.len(),
        3,
        "expected exactly 3 compare overloads, found: {rows:?}"
    );

    for (args, provolatile, isstrict) in &rows {
        assert_eq!(
            provolatile, "i",
            "compare_ore_block_256_term(s)({args}) must be IMMUTABLE, got provolatile={provolatile}"
        );
        assert!(
            !isstrict,
            "compare_ore_block_256_term(s)({args}) must NOT be STRICT (NULL branches are load-bearing)"
        );
    }
    Ok(())
}

/// T9 — Bloom-filter SEM extractor (`eql_v3_internal.bloom_filter(jsonb)`): reads the
/// `bf` array out of a payload. Inlinable SQL mirroring `hmac_256` — NULL on a
/// missing key, not a raise (the `match` capability is tied to the domain,
/// whose CHECK guarantees `bf`).
#[sqlx::test]
async fn bloom_filter_extractor_reads_bf_array(pool: PgPool) -> Result<()> {
    let got: Vec<i16> = sqlx::query_scalar(
        "SELECT eql_v3_internal.bloom_filter('{\"bf\":[1,2,3]}'::jsonb)::smallint[]",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(got, vec![1i16, 2, 3]);
    Ok(())
}

#[sqlx::test]
async fn bloom_filter_extractor_returns_null_without_bf(pool: PgPool) -> Result<()> {
    // Inlinable SQL extractor (like hmac_256): a payload without `bf` yields
    // NULL, not an exception. The RAISE is redundant because the `text_match`
    // domain CHECK already guarantees `bf` is present on the typed path.
    let got: Option<Vec<i16>> = sqlx::query_scalar(
        "SELECT eql_v3_internal.bloom_filter('{\"hm\":\"x\"}'::jsonb)::smallint[]",
    )
    .fetch_one(&pool)
    .await?;
    assert!(
        got.is_none(),
        "absent bf must return NULL (capability is tied to the domain)"
    );
    Ok(())
}

#[sqlx::test]
async fn bloom_filter_extractor_returns_null_for_non_array_bf(pool: PgPool) -> Result<()> {
    // A payload where `bf` is present but not a json array (`{"bf": null}`) must
    // return NULL, not error inside `jsonb_array_elements`. The `text_match`
    // domain CHECK only requires the `bf` key to be present, not that it is an
    // array, so a non-array `bf` can reach the extractor even on a typed value;
    // gating on `jsonb_typeof(...) = 'array'` treats it like an absent key.
    let got: Option<Vec<i16>> = sqlx::query_scalar(
        "SELECT eql_v3_internal.bloom_filter('{\"bf\":null}'::jsonb)::smallint[]",
    )
    .fetch_one(&pool)
    .await?;
    assert!(got.is_none(), "non-array bf must return NULL, not raise");
    Ok(())
}

#[sqlx::test]
async fn bloom_filter_extractor_empty_array_is_empty_not_null(pool: PgPool) -> Result<()> {
    // An empty `bf` array hits the `jsonb_typeof(...) = 'array'` branch with
    // zero elements and must extract as an EMPTY filter — `Some([])`, not NULL.
    // This is the extractor-level basis for the empty-set containment semantics
    // ("contains nothing, contained by everything") the smoke tests assert only
    // via literal `text_match` casts. Distinct from the absent/non-array NULL
    // branches above.
    let got: Option<Vec<i16>> =
        sqlx::query_scalar("SELECT eql_v3_internal.bloom_filter('{\"bf\":[]}'::jsonb)::smallint[]")
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        got,
        Some(vec![]),
        "empty bf array must extract as empty array, not NULL"
    );
    Ok(())
}

/// T10 — `eql_v3_internal.has_bloom_filter(jsonb)` presence predicate. Mirrors the
/// `has_hmac_256` / `has_ore_block_256` coverage in T5: its two-part guard
/// (`val ? 'bf'` AND `val ->> 'bf' IS NOT NULL`) is exercised across present,
/// absent, and json-null cases. The `{"bf":null}` → false case pins the
/// `IS NOT NULL` half — the predicate is not reached transitively by the
/// extractor or the domain CHECK, so it needs direct coverage.
#[sqlx::test]
async fn has_bloom_filter_detects_bf_presence(pool: PgPool) -> Result<()> {
    let bool_cases = [
        // present + non-null array → true
        (
            r#"SELECT eql_v3_internal.has_bloom_filter('{"bf":[1,2,3]}'::jsonb)"#,
            true,
        ),
        // key absent → false
        (
            r#"SELECT eql_v3_internal.has_bloom_filter('{"hm":"x"}'::jsonb)"#,
            false,
        ),
        // key present but json-null → false (the `->> ... IS NOT NULL` half)
        (
            r#"SELECT eql_v3_internal.has_bloom_filter('{"bf":null}'::jsonb)"#,
            false,
        ),
    ];
    for (sql, expected) in bool_cases {
        let got: bool = sqlx::query_scalar(sql).fetch_one(&pool).await?;
        assert_eq!(got, expected, "presence check: {sql}");
    }
    Ok(())
}

/// T11 — Planner-selectivity metadata for the `eql_v3_internal.ore_block_256`
/// `=` / `<>` operators. `<>` must use the inequality estimators
/// (`neqsel` / `neqjoinsel`) and must NOT declare `HASHES` — an earlier revision
/// copied `=`'s `eqsel` / `eqjoinsel` + `HASHES` onto `<>`, which is meaningless
/// (you cannot hash-join on inequality) and mis-estimates selectivity (#267
/// review / aa13065). `=` is the contrast: it keeps `eqsel` / `eqjoinsel` and
/// `HASHES`. A catalog pin (deterministic, no plan dependence).
#[sqlx::test]
async fn ore_block_comparison_operators_declare_correct_selectivity(pool: PgPool) -> Result<()> {
    let (eq_rest, eq_join, eq_hashes, eq_merges): (String, String, bool, bool) = sqlx::query_as(
        r#"
        SELECT o.oprrest::text, o.oprjoin::text, o.oprcanhash, o.oprcanmerge
        FROM pg_operator o
        WHERE o.oprname = '='
          AND o.oprleft  = 'eql_v3_internal.ore_block_256'::regtype
          AND o.oprright = 'eql_v3_internal.ore_block_256'::regtype
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(eq_rest, "eqsel", "= must use eqsel");
    assert_eq!(eq_join, "eqjoinsel", "= must use eqjoinsel");
    assert!(eq_hashes, "= must declare HASHES");
    assert!(eq_merges, "= must declare MERGES");

    let (neq_rest, neq_join, neq_hashes): (String, String, bool) = sqlx::query_as(
        r#"
        SELECT o.oprrest::text, o.oprjoin::text, o.oprcanhash
        FROM pg_operator o
        WHERE o.oprname = '<>'
          AND o.oprleft  = 'eql_v3_internal.ore_block_256'::regtype
          AND o.oprright = 'eql_v3_internal.ore_block_256'::regtype
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        neq_rest, "neqsel",
        "<> must use neqsel (not eqsel — it estimates the inequality fraction)"
    );
    assert_eq!(
        neq_join, "neqjoinsel",
        "<> must use neqjoinsel (not eqjoinsel)"
    );
    assert!(
        !neq_hashes,
        "<> must NOT declare HASHES — hash joins are meaningless for inequality"
    );
    Ok(())
}
