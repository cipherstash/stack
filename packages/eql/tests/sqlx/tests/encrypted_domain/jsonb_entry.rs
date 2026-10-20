//! Behaviour matrix for SteVec jsonb-entry comparisons, reusing the scalar
//! matrix generators via `jsonb_entry_matrix!`. Covers the positive behaviours
//! (range correctness / ordering / NULL / ORDER BY / COUNT / index engagement, plus
//! entry-specific fixture-shape and CLLW-OPE injectivity tests) that the
//! hand-written `v3_jsonb_tests` suite does not. Document-specific behaviours
//! (containment / path query / array ops / the operator-surface guard) remain
//! in `v3_jsonb_tests` / `v3_jsonb_operator_surface_tests`.
//!
//! The view type (`JsonbEntryInteger`) is deliberately NOT a `eql_domains::CATALOG`
//! scalar, so this suite is hand-written rather than emitted by the
//! `scalar_types!` list — and its test names live under `jsonb_entry::…`,
//! validated by `test:matrix:inventory:jsonb_entry` (NOT the scalar inventory).

use eql_tests::fixtures::v3_doc_integer::field_op_selector;
use eql_tests::jsonb_entry::{entry_column_expr, JsonbEntryInteger};
use eql_tests::scalar_domains::ScalarType;

eql_tests::jsonb_entry_matrix! {
    suite = jsonb_entry_integer,
    scalar = eql_tests::jsonb_entry::JsonbEntryInteger,
    eql_type = "v3_doc_integer",
}

// ----------------------------------------------------------------------------
// Entry-specific structural invariant. Pins that the matrix's access path
// (`column_expr`, the literal lookup of the fixture's `$.field` op selector)
// extracts a real, `op`-carrying entry from every fixture row — a missing entry
// would make every matrix comparison vacuous via NULL extraction rather than
// failing.
// ----------------------------------------------------------------------------
#[sqlx::test(fixtures(path = "../../fixtures", scripts("v3_doc_integer")))]
async fn jsonb_entry_integer_fixture_shape(pool: sqlx::PgPool) -> anyhow::Result<()> {
    let sel = field_op_selector(&pool).await?;
    let col = <JsonbEntryInteger as ScalarType>::column_expr(&pool).await?;
    let n = <JsonbEntryInteger as ScalarType>::fixture_values().len() as i64;

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fixtures.v3_doc_integer")
        .fetch_one(&pool)
        .await?;
    anyhow::ensure!(
        count == n,
        "row count must match fixture_values().len(): want {n}, got {count}",
    );

    // ids sequential from 1 (the split generator inserts in INTEGER_VALUES order).
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM fixtures.v3_doc_integer ORDER BY id")
        .fetch_all(&pool)
        .await?;
    anyhow::ensure!(
        ids == (1..=n).collect::<Vec<i64>>(),
        "ids must be sequential from 1: got {ids:?}",
    );

    // Every row's entry at the selector is non-NULL — guards against a row
    // missing its `$.field` entry silently hollowing out the matrix.
    let null_entries: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM fixtures.v3_doc_integer WHERE ({col}) IS NULL",
    ))
    .fetch_one(&pool)
    .await?;
    anyhow::ensure!(
        null_entries == 0,
        "{null_entries} rows have a NULL entry at the $.field op selector {sel}",
    );

    // Every extracted entry is a valid jsonb_entry payload AND carries `op`
    // (the ordered term the matrix's ord_term paths require —
    // `eql_v3.ord_term` returns SQL NULL for an op-less entry).
    let invalid: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM fixtures.v3_doc_integer \
         WHERE NOT public.eql_v3_is_valid_ste_vec_entry_payload(({col})::jsonb) \
            OR eql_v3.ord_term(({col})::public.eql_v3_json_entry) IS NULL",
    ))
    .fetch_one(&pool)
    .await?;
    anyhow::ensure!(
        invalid == 0,
        "{invalid} rows have an invalid or op-less entry at the $.field op selector {sel}",
    );

    // Distinct op terms == row count (distinct plaintexts → distinct CLLW-OPE
    // leaves), so the correctness/ordering oracle has real discrimination.
    let distinct_op: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(DISTINCT (({col})::jsonb ->> 'op')) \
         FROM fixtures.v3_doc_integer",
    ))
    .fetch_one(&pool)
    .await?;
    anyhow::ensure!(
        distinct_op == n,
        "{n} distinct plaintexts must yield {n} distinct op terms; got {distinct_op}",
    );

    Ok(())
}

// ----------------------------------------------------------------------------
// Selector shape guard. A SteVec selector is a keyed MAC over (workspace keyset,
// STE_VEC_PREFIX, path), so the `$.field` selector differs per CipherStash
// workspace and is never pinned: every test reads it from the loaded fixture
// (`field_op_selector`), and the matrix's `column_expr` embeds it as the literal
// `payload -> '<sel>'::text`. What stays checkable is the SHAPE that makes the
// lookup unambiguous: exactly one op-carrying selector in the fixture. This test
// fails, naming every candidate, when that stops holding, instead of leaving it
// to surface as ~40 confusing failures across the matrix. It also pins that the
// matrix's `column_expr` is the literal lookup of exactly that selector, not a
// subquery or a different selector. That the access path reaches a valid,
// `op`-carrying entry on every row is `jsonb_entry_integer_fixture_shape`, which
// a subquery returning the same entry would pass too. Whether a keyset and path
// still produce the same selector bytes is pinned in
// `packages/eql/tests/encryption`.
// ----------------------------------------------------------------------------
#[sqlx::test(fixtures(path = "../../fixtures", scripts("v3_doc_integer")))]
async fn jsonb_entry_integer_field_selector_is_unique(pool: sqlx::PgPool) -> anyhow::Result<()> {
    let sel = field_op_selector(&pool).await?;
    let col = <JsonbEntryInteger as ScalarType>::column_expr(&pool).await?;
    anyhow::ensure!(
        col == entry_column_expr(&sel),
        "column_expr must be the literal lookup of the fixture's $.field op \
         selector, `{}`; got `{col}`",
        entry_column_expr(&sel),
    );
    Ok(())
}

// ----------------------------------------------------------------------------
// Reading the whole document instead of the entry fails loudly. Every entry
// matrix arm casts its column to `public.eql_v3_json_entry`, whose CHECK
// requires string `s` and `c` and admits only entry keys; a SteVec document has
// neither at its root. So an arm that reads bare `payload` where it should read
// `column_expr` raises a check violation rather than comparing documents. This
// pins that safety net: the matrix relies on it in place of a type-level
// guarantee that every fixture-reading arm resolves `column_expr`.
// ----------------------------------------------------------------------------
#[sqlx::test(fixtures(path = "../../fixtures", scripts("v3_doc_integer")))]
async fn jsonb_entry_integer_document_is_not_an_entry(pool: sqlx::PgPool) -> anyhow::Result<()> {
    let n = <JsonbEntryInteger as ScalarType>::fixture_values().len() as i64;

    // Control: the resolved entry read casts on every row.
    let col = <JsonbEntryInteger as ScalarType>::column_expr(&pool).await?;
    let entries: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(({col})::public.eql_v3_json_entry) FROM fixtures.v3_doc_integer",
    ))
    .fetch_one(&pool)
    .await?;
    anyhow::ensure!(
        entries == n,
        "the entry read must cast on all {n} rows, got {entries}",
    );

    // The mistaken read: the whole document, cast as an arm would cast it.
    let err = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT((payload)::public.eql_v3_json_entry) FROM fixtures.v3_doc_integer",
    )
    .fetch_one(&pool)
    .await
    .expect_err("a whole SteVec document must not cast to public.eql_v3_json_entry");
    let code = err.as_database_error().and_then(|e| e.code());
    anyhow::ensure!(
        code.as_deref() == Some("23514"),
        "expected SQLSTATE 23514 (check_violation) casting the document to an entry, \
         got {code:?}: {err}",
    );

    Ok(())
}

// ----------------------------------------------------------------------------
// CLLW-OPE injectivity. Distinct plaintexts must produce distinct ord_term
// terms. Compares `eql_v3.ord_term(...)` outputs directly; entry equality is a
// fail-loud blocker and is not part of the ordering surface.
// ----------------------------------------------------------------------------
#[sqlx::test(fixtures(path = "../../fixtures", scripts("v3_doc_integer")))]
async fn jsonb_entry_integer_ord_ope_injectivity(pool: sqlx::PgPool) -> anyhow::Result<()> {
    let sel = field_op_selector(&pool).await?;
    let collisions: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) \
         FROM fixtures.v3_doc_integer a \
         JOIN fixtures.v3_doc_integer b ON a.id < b.id \
         WHERE a.plaintext <> b.plaintext \
           AND eql_v3.ord_term((a.payload -> '{sel}'::text)::public.eql_v3_json_entry) \
             = eql_v3.ord_term((b.payload -> '{sel}'::text)::public.eql_v3_json_entry)",
    ))
    .fetch_one(&pool)
    .await?;
    anyhow::ensure!(
        collisions == 0,
        "no two distinct plaintexts may share a CLLW-OPE term ($.field); got {collisions} collisions",
    );
    Ok(())
}

// ----------------------------------------------------------------------------
// Index engagement — hand-written (not via the shared `__scalar_matrix_index`
// driver, which sweeps a bare-jsonb RHS that flattens to native `jsonb < jsonb`
// for entries). Builds the ord_term functional btree and asserts each ORDERING
// op (which inlines to `ord_term(value) <op> ord_term(const)`) engages it, using
// the domain-cast RHS (`'<lit>'::public.eql_v3_json_entry`) so the entry operator
// resolves rather than native jsonb.
//
// VALIDITY ONLY: forces `enable_seqscan = off` on the ~17-row fixture, so a
// green assertion proves the index is USABLE, not that the planner would PREFER
// it at scale (mirrors the scalar index-engagement caveat). Equality is
// excluded because entry `=` is a fail-loud blocker.
// ----------------------------------------------------------------------------
#[sqlx::test(fixtures(path = "../../fixtures", scripts("v3_doc_integer")))]
async fn jsonb_entry_integer_index_engages(pool: sqlx::PgPool) -> anyhow::Result<()> {
    let sel = field_op_selector(&pool).await?;
    let pivot = <JsonbEntryInteger as ScalarType>::fixture_values()[0];
    let payload =
        eql_tests::scalar_domains::fetch_fixture_payload::<JsonbEntryInteger>(&pool, pivot).await?;
    let lit = payload.replace('\'', "''");

    let mut tx = pool.begin().await?;
    sqlx::query("CREATE TEMP TABLE entry_idx (value public.eql_v3_json_entry) ON COMMIT DROP")
        .execute(&mut *tx)
        .await?;
    sqlx::query(&format!(
        "INSERT INTO entry_idx(value) \
         SELECT (payload -> '{sel}'::text)::public.eql_v3_json_entry FROM fixtures.v3_doc_integer",
    ))
    .execute(&mut *tx)
    .await?;
    sqlx::query("CREATE INDEX entry_idx_ope ON entry_idx USING btree (eql_v3.ord_term(value))")
        .execute(&mut *tx)
        .await?;
    sqlx::query("ANALYZE entry_idx").execute(&mut *tx).await?;
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await?;

    for op in ["<", "<=", ">", ">="] {
        let query =
            format!("SELECT * FROM entry_idx WHERE value {op} '{lit}'::public.eql_v3_json_entry",);
        eql_tests::matrix::assert_index_scan_uses(
            &mut *tx,
            &query,
            "entry_idx_ope",
            &format!("entry op {op} (domain-cast RHS) must engage the ord_term functional btree"),
        )
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

// ----------------------------------------------------------------------------
// Aggregate robustness over non-orderable (op-less) entries. `eql_v3.ord_term`
// is NULL for an entry without an `op` term, so a naive `ord_term(value) <
// ord_term(state)` would be NULL whenever the running extremum is op-less —
// pinning a wrong result when the FIRST aggregated row (the STRICT seed) is
// op-less. The min/max sfuncs explicitly skip op-less entries. This feeds a
// forged term-less (op-less) entry in the SEED position alongside real op-carrying
// entries and asserts the extremum is the correct ORDERABLE entry, never the
// op-less seed. The whole-suite matrix never exercises this (every v3_doc_integer
// entry carries op).
// ----------------------------------------------------------------------------
#[sqlx::test(fixtures(path = "../../fixtures", scripts("v3_doc_integer")))]
async fn jsonb_entry_integer_aggregate_ignores_op_less_entries(
    pool: sqlx::PgPool,
) -> anyhow::Result<()> {
    let sel = field_op_selector(&pool).await?;
    // A valid public.eql_v3_json_entry that is NOT orderable: string s, string c,
    // no `op` term (a term-less value/structural entry — the shape a bool/null/
    // object/array leaf or a value entry takes), so `eql_v3.ord_term(entry)` is NULL.
    let op_less = r#"{"s":"forged","c":"x"}"#;

    let mut sorted: Vec<i32> = <JsonbEntryInteger as ScalarType>::fixture_values()
        .iter()
        .map(|e| e.0)
        .collect();
    sorted.sort();
    let low = sorted[0];
    let high = *sorted.last().expect("fixture is non-empty");

    let mut tx = pool.begin().await?;
    sqlx::query("CREATE TEMP TABLE op_mix (value public.eql_v3_json_entry) ON COMMIT DROP")
        .execute(&mut *tx)
        .await?;
    // SEED position: the op-less entry is inserted FIRST, so the STRICT seed is
    // non-orderable — the exact case the sfunc guard must survive.
    sqlx::query("INSERT INTO op_mix(value) VALUES ($1::jsonb::public.eql_v3_json_entry)")
        .bind(op_less)
        .execute(&mut *tx)
        .await?;
    sqlx::query(&format!(
        "INSERT INTO op_mix(value) \
         SELECT (payload -> '{sel}'::text)::public.eql_v3_json_entry \
         FROM fixtures.v3_doc_integer WHERE plaintext IN ({low}, {high})",
    ))
    .execute(&mut *tx)
    .await?;

    // Expected extrema: the orderable entries for the smallest / largest integer,
    // NOT the op-less seed.
    let expect_min: String = sqlx::query_scalar(&format!(
        "SELECT ((payload -> '{sel}'::text)::public.eql_v3_json_entry)::text \
         FROM fixtures.v3_doc_integer WHERE plaintext = {low}",
    ))
    .fetch_one(&mut *tx)
    .await?;
    let expect_max: String = sqlx::query_scalar(&format!(
        "SELECT ((payload -> '{sel}'::text)::public.eql_v3_json_entry)::text \
         FROM fixtures.v3_doc_integer WHERE plaintext = {high}",
    ))
    .fetch_one(&mut *tx)
    .await?;

    let got_min: String = sqlx::query_scalar("SELECT eql_v3.min(value)::text FROM op_mix")
        .fetch_one(&mut *tx)
        .await?;
    let got_max: String = sqlx::query_scalar("SELECT eql_v3.max(value)::text FROM op_mix")
        .fetch_one(&mut *tx)
        .await?;

    anyhow::ensure!(
        got_min == expect_min,
        "eql_v3.min must ignore the op-less seed and return the smallest orderable entry;\n  \
         want {expect_min}\n  got  {got_min}",
    );
    anyhow::ensure!(
        got_max == expect_max,
        "eql_v3.max must ignore the op-less entry and return the largest orderable entry;\n  \
         want {expect_max}\n  got  {got_max}",
    );

    tx.commit().await?;
    Ok(())
}
