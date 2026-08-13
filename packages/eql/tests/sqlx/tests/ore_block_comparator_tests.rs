//! Direct tests for the generalized N-block ORE comparator
//! `eql_v3_internal.compare_ore_block_256_term(s)`.
//!
//! Every test here is **always-on** — it runs in normal (no-creds) CI, because
//! it sources real ORE terms from generated fixtures rather than encrypting at
//! runtime:
//!   * The malformed-length guards build ORE terms by hand from short byte
//!     strings, exercising length validation without real ciphertexts.
//!   * The ordering properties (all-pairs oracle agreement + antisymmetry) read
//!     the generated `eql_v3_numeric` / `eql_v3_timestamp` fixtures, whose
//!     catalog order is the strict ascending oracle.
//!   * The `1 == 1.0` ORE collision reads the generated `v3_numeric_collision`
//!     fixture — the one place the value-equal pair can live, since the catalog
//!     distinctness guard forbids it in `eql_v3_numeric`.
//!
//! Fixtures are generated once (with creds) in the `build-archive` CI job and
//! baked into the test binaries via `include_str!`, so the no-creds shards
//! consume them directly. See `tasks/test/sqlx-archive.sh`.

use anyhow::Result;
use sqlx::PgPool;

/// Fetch two fixture payloads by plaintext literal, wrap each in the ordered
/// extractor, and return the ORE comparison. The single fetch + `ord_term_ore` +
/// `compare_ore_block_256_terms` shape every chain/pair test shares; `lo`/`hi`
/// are the plaintext SQL literals (with cast), e.g. `"(-1)::numeric"`.
///
/// `ord_domain` MUST be an `_ord_ore` domain. `eql_v3.ord_term_ore` and the block-ORE
/// comparator exist only for `Term::Ore`-bearing domains; the bare `_ord` domains
/// are CLLW-OPE-backed (`ord_term` → `eql_v3_internal.ope_cllw`, ordered by
/// native bytea comparison) and have no block terms to compare.
async fn compare_fixture_pair(
    pool: &PgPool,
    table: &str,
    ord_domain: &str,
    lo: &str,
    hi: &str,
) -> Result<i32> {
    let sql = format!(
        "SELECT eql_v3_internal.compare_ore_block_256_terms( \
            eql_v3.ord_term_ore((SELECT payload FROM fixtures.{table} WHERE plaintext = {lo})::public.{ord_domain}), \
            eql_v3.ord_term_ore((SELECT payload FROM fixtures.{table} WHERE plaintext = {hi})::public.{ord_domain}))"
    );
    Ok(sqlx::query_scalar::<_, i32>(&sql).fetch_one(pool).await?)
}

/// A hand-built ORE term of `len` bytes filled with `fill`. Creds-free — the
/// bytes are cryptographically meaningless, so this only drives length/structure
/// validation, never ordering semantics.
fn term_sql(fill: char, len: usize) -> String {
    format!("ROW(repeat('{fill}', {len})::bytea)::eql_v3_internal.ore_block_256_term")
}

/// Assert the ORE comparator agrees with an explicit oracle order over a
/// generated fixture. `ascending[i]` is the SQL literal (with cast) for the
/// value whose oracle rank is `i`; its real ciphertext is fetched from
/// `fixtures.{table}` by `plaintext` and loaded into a connection-local
/// `ore_sample(rank, payload)`.
///
/// Two properties, both over EVERY pair (not just adjacent):
///   * **Oracle agreement** — `rank a < rank b` ⇒ `compare(a, b) = -1`.
///     All-pairs subsumes totality and transitivity; combined with antisymmetry
///     it also pins the `>` direction, so a one-sided bug cannot hide.
///   * **Antisymmetry** — `compare(a, b) = -compare(b, a)` for all distinct
///     pairs.
///
/// Creds-free: every term is a real generated ciphertext. The per-row
/// `rows_affected == 1` check fails loudly if the `ascending` list drifts from
/// the fixture (a removed/renamed value resolves to zero rows).
async fn assert_orders_like_oracle(
    pool: &PgPool,
    table: &str,
    ord_domain: &str,
    ascending: &[String],
) -> Result<()> {
    // TEMP is connection-scoped and a pool may hand out different connections
    // per query — pin everything to one acquired connection.
    let mut conn = pool.acquire().await?;
    sqlx::query("CREATE TEMP TABLE ore_sample (rank int, payload jsonb)")
        .execute(&mut *conn)
        .await?;
    for (rank, literal) in ascending.iter().enumerate() {
        let inserted = sqlx::query(&format!(
            "INSERT INTO ore_sample (rank, payload) \
             SELECT {rank}, payload FROM fixtures.{table} WHERE plaintext = {literal}"
        ))
        .execute(&mut *conn)
        .await?
        .rows_affected();
        anyhow::ensure!(
            inserted == 1,
            "expected exactly 1 fixture row for {literal} (rank {rank}), got {inserted} \
             — the ascending list has drifted from fixtures.{table}"
        );
    }

    // Oracle agreement: lower rank (smaller value) MUST compare -1.
    let order_violations: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM ore_sample a JOIN ore_sample b ON a.rank < b.rank \
         WHERE eql_v3_internal.compare_ore_block_256_terms( \
             eql_v3.ord_term_ore(a.payload::public.{ord_domain}), \
             eql_v3.ord_term_ore(b.payload::public.{ord_domain})) <> -1"
    ))
    .fetch_one(&mut *conn)
    .await?;
    assert_eq!(
        order_violations, 0,
        "ORE comparator disagreed with the oracle order on some pair"
    );

    // Antisymmetry: compare(a, b) = -compare(b, a) for every distinct pair.
    let antisymmetry_violations: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM ore_sample a JOIN ore_sample b ON a.rank <> b.rank \
         WHERE eql_v3_internal.compare_ore_block_256_terms( \
                 eql_v3.ord_term_ore(a.payload::public.{ord_domain}), \
                 eql_v3.ord_term_ore(b.payload::public.{ord_domain})) \
             <> - eql_v3_internal.compare_ore_block_256_terms( \
                 eql_v3.ord_term_ore(b.payload::public.{ord_domain}), \
                 eql_v3.ord_term_ore(a.payload::public.{ord_domain}))"
    ))
    .fetch_one(&mut *conn)
    .await?;
    assert_eq!(
        antisymmetry_violations, 0,
        "ORE comparator violated antisymmetry on some pair"
    );

    Ok(())
}

/// A `bytea` whose length is NOT a valid `49*N + 16` must raise, not silently
/// return 0. Uses a 4-byte term (equal lengths so the equal-length guard does
/// not fire first).
#[sqlx::test]
async fn comparator_rejects_non_conforming_length(pool: PgPool) -> Result<()> {
    let sql = "SELECT eql_v3_internal.compare_ore_block_256_term( \
        ROW('\\x00010203'::bytea)::eql_v3_internal.ore_block_256_term, \
        ROW('\\x04050607'::bytea)::eql_v3_internal.ore_block_256_term)";
    let err = sqlx::query_scalar::<_, i32>(sql)
        .fetch_one(&pool)
        .await
        .expect_err("a 4-byte ORE term must raise, not return a comparison");
    assert!(
        err.to_string()
            .to_lowercase()
            .contains("malformed ore term"),
        "expected malformed-term error, got: {err}"
    );
    Ok(())
}

/// A 16-byte term satisfies `(16 - 16) % 49 == 0` and derives N = 0; the
/// `<= 16` clause must still reject it (otherwise it falls through to the
/// all-blocks-equal path and wrongly returns 0).
#[sqlx::test]
async fn comparator_rejects_sixteen_byte_term(pool: PgPool) -> Result<()> {
    let sql = "SELECT eql_v3_internal.compare_ore_block_256_term( \
        ROW(repeat('a', 16)::bytea)::eql_v3_internal.ore_block_256_term, \
        ROW(repeat('b', 16)::bytea)::eql_v3_internal.ore_block_256_term)";
    let err = sqlx::query_scalar::<_, i32>(sql)
        .fetch_one(&pool)
        .await
        .expect_err("a 16-byte ORE term (N=0) must raise");
    assert!(
        err.to_string()
            .to_lowercase()
            .contains("malformed ore term"),
        "expected malformed-term error, got: {err}"
    );
    Ok(())
}

/// Cross-width footgun: now that N is derived per-term, comparing terms of two
/// different (individually valid) widths must raise via the equal-length guard,
/// not silently compare the shared prefix. Both lengths here are well-formed —
/// 408 = 49*8 + 16 (the integer width, N=8) and 702 = 49*14 + 16 (the numeric
/// width, N=14) — so the only thing that fires is the different-lengths check,
/// ahead of the malformed-length guard. Creds-free (hand-built bytea).
#[sqlx::test]
async fn comparator_rejects_mismatched_block_widths(pool: PgPool) -> Result<()> {
    let sql = "SELECT eql_v3_internal.compare_ore_block_256_term( \
        ROW(repeat('a', 408)::bytea)::eql_v3_internal.ore_block_256_term, \
        ROW(repeat('b', 702)::bytea)::eql_v3_internal.ore_block_256_term)";
    let err = sqlx::query_scalar::<_, i32>(sql)
        .fetch_one(&pool)
        .await
        .expect_err("an 8-block vs 14-block ORE term comparison must raise");
    assert!(
        err.to_string().to_lowercase().contains("different lengths"),
        "expected different-lengths error, got: {err}"
    );
    Ok(())
}

/// An empty ORE term — what encrypting the empty string `""` produces (`ob: []`,
/// verified against cipherstash-client) — sorts BEFORE any non-empty term and
/// equals itself. The extractor must yield an empty-terms composite (cardinality
/// 0), which the comparator's empty-array guard orders first; previously the
/// inner `array_agg` collapsed to NULL terms, so the comparator returned NULL
/// and the row silently dropped out of ordered queries. See issue #262.
///
/// Creds-free: the empty side carries no ciphertext, and the non-empty
/// comparand's bytes are never inspected — the cardinality short-circuit fires
/// ahead of any term-level comparison, so a synthetic one-term composite is
/// sufficient.
#[sqlx::test]
async fn empty_ore_term_sorts_before_non_empty(pool: PgPool) -> Result<()> {
    // Empty `ob` taken through the real extractor path (the buggy site).
    let empty = "eql_v3_internal.ore_block_256('{\"ob\": []}'::jsonb)";
    // A non-empty composite: one synthetic valid-width term; content irrelevant.
    let non_empty = format!(
        "ROW(ARRAY[{}])::eql_v3_internal.ore_block_256",
        term_sql('a', 408)
    );

    let lt: Option<i32> = sqlx::query_scalar(&format!(
        "SELECT eql_v3_internal.compare_ore_block_256_terms({empty}, {non_empty})"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        lt,
        Some(-1),
        "empty ORE term must sort before a non-empty term"
    );

    let gt: Option<i32> = sqlx::query_scalar(&format!(
        "SELECT eql_v3_internal.compare_ore_block_256_terms({non_empty}, {empty})"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        gt,
        Some(1),
        "a non-empty term must sort after an empty ORE term"
    );

    let eq: Option<i32> = sqlx::query_scalar(&format!(
        "SELECT eql_v3_internal.compare_ore_block_256_terms({empty}, {empty})"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(eq, Some(0), "two empty ORE terms must compare equal");

    Ok(())
}

/// Sweep the `49*N + 16` length guard across boundary/off-by lengths the
/// point-example tests above don't reach. Both operands are kept the SAME length
/// so only the malformed-length guard can fire (the different-lengths guard at
/// `bit_length` precedes it). Creds-free.
///
/// Valid lengths are pinned to exact return values (verified against
/// `src/v3/sem/ore_block_256/functions.sql`):
///   * equal operands take the all-blocks-equal path → return **0**
///     (`functions.sql:166-168`; the `encrypt()` branch is unreachable);
///   * differing operands fall through to the `encrypt()` path → return **±1**
///     (`functions.sql:170-190`), which is the branch the length guard protects.
#[sqlx::test]
async fn comparator_length_guard_sweep(pool: PgPool) -> Result<()> {
    // Invalid: not 49*N + 16 (16 and 4 are covered by the dedicated tests above).
    for len in [15usize, 17, 50, 64, 66, 407, 409, 701, 703] {
        let sql = format!(
            "SELECT eql_v3_internal.compare_ore_block_256_term({}, {})",
            term_sql('a', len),
            term_sql('b', len)
        );
        let err = sqlx::query_scalar::<_, i32>(&sql)
            .fetch_one(&pool)
            .await
            .expect_err(&format!("length {len} (not 49*N+16) must raise"));
        assert!(
            err.to_string()
                .to_lowercase()
                .contains("malformed ore term"),
            "len {len}: expected malformed-term error, got: {err}"
        );
    }

    // Valid: 49*N + 16 for N = 1..=14 (spans the integer/timestamp/numeric widths).
    for n in 1..=14usize {
        let len = 49 * n + 16;

        let eq: i32 = sqlx::query_scalar(&format!(
            "SELECT eql_v3_internal.compare_ore_block_256_term({}, {})",
            term_sql('a', len),
            term_sql('a', len)
        ))
        .fetch_one(&pool)
        .await?;
        assert_eq!(eq, 0, "len {len} (N={n}): identical terms must compare 0");

        let ne: i32 = sqlx::query_scalar(&format!(
            "SELECT eql_v3_internal.compare_ore_block_256_term({}, {})",
            term_sql('a', len),
            term_sql('b', len)
        ))
        .fetch_one(&pool)
        .await?;
        assert!(
            ne == -1 || ne == 1,
            "len {len} (N={n}): differing terms must compare ±1 (encrypt path), got {ne}"
        );
    }
    Ok(())
}

/// Width: a numeric ORE term must be 14 blocks => 49*14 + 16 = 702 bytes.
#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_numeric")))]
async fn numeric_term_is_14_blocks(pool: PgPool) -> Result<()> {
    let width: i32 = sqlx::query_scalar(
        "SELECT octet_length((((eql_v3.ord_term_ore( \
            (SELECT payload FROM fixtures.eql_v3_numeric WHERE plaintext = (-1000000)::numeric) \
            ::public.eql_v3_numeric_ord_ore)).terms)[1]).bytes)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(width, 702, "numeric ORE term must be 14 blocks (702 bytes)");
    Ok(())
}

/// 14-block numeric terms must order like `Decimal`'s `Ord` over ALL pairs (not
/// just adjacent), plus antisymmetry. Spans sign, magnitude, and fractional
/// (low-block) scale, so the left blocks — not just the right blocks — decide
/// ordering. This is the regression the missed `9 -> 1+n` left-offset would
/// fail; the all-pairs sweep makes a single lucky pair unable to mask it. The
/// list is the strict ascending oracle (matching `NUMERIC_FIXTURES`' catalog
/// order); `assert_orders_like_oracle` fails loudly if it drifts from the
/// generated fixture.
#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_numeric")))]
async fn numeric_terms_order_like_decimal_ord(pool: PgPool) -> Result<()> {
    let ascending: Vec<String> = [
        "-1000000000000",
        "-1000000",
        "-1.001",
        "-1",
        "-0.5",
        "-0.001",
        "0",
        "0.001",
        "0.5",
        "0.999999999",
        "1",
        "1.001",
        "1000000",
        "1000000000000",
    ]
    .iter()
    .map(|v| format!("({v})::numeric"))
    .collect();
    assert_orders_like_oracle(
        &pool,
        "eql_v3_numeric",
        "eql_v3_numeric_ord_ore",
        &ascending,
    )
    .await
}

/// Width + single-pair sanity for the 12-block (timestamp, N=12 => 604 bytes)
/// term. The full ordering property is `timestamp_terms_order_like_datetime_ord`.
#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_timestamp")))]
async fn timestamp_term_is_12_blocks(pool: PgPool) -> Result<()> {
    let width: i32 = sqlx::query_scalar(
        "SELECT octet_length((((eql_v3.ord_term_ore( \
            (SELECT payload FROM fixtures.eql_v3_timestamp WHERE plaintext = '1970-01-01T00:00:00Z'::timestamptz) \
            ::public.eql_v3_timestamp_ord_ore)).terms)[1]).bytes)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        width, 604,
        "timestamp ORE term must be 12 blocks (604 bytes)"
    );
    Ok(())
}

/// 12-block (timestamp) terms must order like `DateTime<Utc>`'s `Ord` over
/// ALL pairs, plus antisymmetry. N=12 is the only width strictly between the
/// working 8 and the headline 14, so it needs the same left-block-deciding
/// coverage as numeric. The 15 values are the strict ascending oracle (matching
/// `TIMESTAMP_FIXTURES`' catalog order); `assert_orders_like_oracle` fails
/// loudly if the list drifts from the generated fixture.
#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_timestamp")))]
async fn timestamp_terms_order_like_datetime_ord(pool: PgPool) -> Result<()> {
    let ascending: Vec<String> = [
        "1900-01-01T00:00:00Z",
        "1950-07-15T06:30:00Z",
        "1969-12-31T23:59:59Z",
        "1970-01-01T00:00:00Z",
        "1970-01-01T00:00:01Z",
        "1985-04-12T23:20:50Z",
        "1999-12-31T23:59:59Z",
        "2000-01-01T00:00:00Z",
        "2004-02-29T12:00:00Z",
        "2012-06-30T11:59:59Z",
        "2016-03-15T08:15:30Z",
        "2020-10-21T14:45:00Z",
        "2024-02-29T17:30:45Z",
        "2038-01-19T03:14:07Z",
        "2099-12-31T23:59:59Z",
    ]
    .iter()
    .map(|v| format!("'{v}'::timestamptz"))
    .collect();
    assert_orders_like_oracle(
        &pool,
        "eql_v3_timestamp",
        "eql_v3_timestamp_ord_ore",
        &ascending,
    )
    .await
}

/// A real wide-block term must compare equal to itself — the reflexive
/// `eq`-true path (`functions.sql:166`) at N=14 and N=12, creds-free (reuses the
/// generated fixtures). Distinct from the `1 == 1.0` collision (Gap 1), which is
/// equality across *different* ciphertexts.
#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_numeric", "eql_v3_timestamp")))]
async fn wide_block_term_compares_equal_to_itself(pool: PgPool) -> Result<()> {
    let numeric = compare_fixture_pair(
        &pool,
        "eql_v3_numeric",
        "eql_v3_numeric_ord_ore",
        "(1)::numeric",
        "(1)::numeric",
    )
    .await?;
    assert_eq!(numeric, 0, "a 14-block numeric term must equal itself");

    let timestamp = compare_fixture_pair(
        &pool,
        "eql_v3_timestamp",
        "eql_v3_timestamp_ord_ore",
        "'2000-01-01T00:00:00Z'::timestamptz",
        "'2000-01-01T00:00:00Z'::timestamptz",
    )
    .await?;
    assert_eq!(timestamp, 0, "a 12-block timestamp term must equal itself");
    Ok(())
}

/// Compare the collision-fixture rows addressed by `id`. The
/// `v3_numeric_collision` fixture stores `1` (id 1), `1.0` (id 2), `2` (id 3);
/// rows are fetched by `id` because `WHERE plaintext = 1` is ambiguous (numeric
/// equality matches both `1` and `1.0`).
async fn compare_collision_ids(pool: &PgPool, a: i64, b: i64) -> Result<i32> {
    let sql = format!(
        "SELECT eql_v3_internal.compare_ore_block_256_terms( \
            eql_v3.ord_term_ore((SELECT payload FROM fixtures.v3_numeric_collision WHERE id = {a})::public.eql_v3_numeric_ord_ore), \
            eql_v3.ord_term_ore((SELECT payload FROM fixtures.v3_numeric_collision WHERE id = {b})::public.eql_v3_numeric_ord_ore))"
    );
    Ok(sqlx::query_scalar::<_, i32>(&sql).fetch_one(pool).await?)
}

/// Scale-equivalent decimals (`1` and `1.0`) must collide in the ORE
/// ciphertext: they are value-equal numerics, so their ORE terms must compare
/// `0`. Always-on via the generated `v3_numeric_collision` fixture — the only
/// place the value-equal pair can live, since the catalog distinctness guard
/// (`scalar_domains.rs` `numeric_value_guards`) forbids it in `eql_v3_numeric`.
/// This is the positive counterpart to that negative guard.
///
/// Asserted in BOTH directions (a scale-biased comparator could pass a
/// one-directional check); the `1`-vs-`2` guards are load-bearing — they defeat
/// a degenerate everything-returns-0 comparator that would otherwise pass the
/// collision assertions.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_numeric_collision")))]
async fn numeric_scale_equivalents_collide(pool: PgPool) -> Result<()> {
    // ids: 1 => `1`, 2 => `1.0`, 3 => `2`.
    assert_eq!(
        compare_collision_ids(&pool, 1, 2).await?,
        0,
        "1 and 1.0 must collide"
    );
    assert_eq!(
        compare_collision_ids(&pool, 2, 1).await?,
        0,
        "the collision must be order-independent"
    );
    assert_eq!(
        compare_collision_ids(&pool, 1, 3).await?,
        -1,
        "1 must order before 2"
    );
    assert_eq!(
        compare_collision_ids(&pool, 3, 1).await?,
        1,
        "2 must order after 1"
    );
    Ok(())
}
