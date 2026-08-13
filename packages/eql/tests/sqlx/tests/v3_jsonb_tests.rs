//! Parameterized test harness for the `eql_v3` encrypted-JSONB (SteVec) surface
//! (`public.eql_v3_json_search` / `public.eql_v3_json_entry` / `eql_v3.query_json`).
//!
//! Design source of truth:
//! `docs/superpowers/plans/2026-06-09-eql-v3-jsonb-test-harness-design.md`.
//! This file owns dimensions D1–D11 and D13–D14. The signature-aware
//! operator-surface guard (D12) lives in `v3_jsonb_operator_surface_tests.rs`.
//!
//! Parameter axes are `{leaf kind: term-less value selector, op path entry} × {operator / behavior}` — NOT
//! `{scalar type}`, because a SteVec value is a *document* (a collection of
//! leaves addressed by selector), so it does not fit `scalar_matrix!`.
//!
//! CRITICAL correctness rule: `public.eql_v3_json_search` is a DOMAIN over `jsonb`.
//! PostgreSQL resolves `domain OP untyped_literal` to the NATIVE jsonb operator
//! (the domain flattens to its base type for unknown-typed literals). So every
//! `->`/`->>` selector operand and every blocker RHS operand below is
//! explicitly typed (`-> 'sel'::text`, `? 'x'::text`, `@? '$.sv'::jsonpath`,
//! `|| '{}'::jsonb`, …). A BARE literal would resolve to native jsonb and never
//! reach our operator/blocker, giving false results. See the "Typed operands"
//! caveat in `docs/reference/json-support.md`.

use eql_tests::matrix::assert_index_scan_uses;
use sqlx::PgPool;

// ============================================================================
// Fixture constants (fixture `v3_ste_vec.sql` → table `fixtures.v3_ste_vec`,
// 10 rows; loaded per-test via
// `#[sqlx::test(fixtures(scripts("v3_ste_vec")))]` on the tests that read it).
//
// NOTE (axis-1): the fixture is GENERATED — cipherstash-client SteVec document
// encryption through the shared `FixtureSpec` pipeline (`mise run
// fixture:generate:all`), not committed. Under the value-selector wire
// there is NO `hm` term: every sv entry is `{s, c, op?}` and exact value
// equality is VALUE-SELECTOR PRESENCE (a leaf's value is tokenized into its own
// selector `s`, so the presence of that selector in the stored document IS the
// match). Selectors are deterministic functions of the JSON path/value under
// the fixture keyset, re-derived from the generated fixture at RUNTIME
// (`constant_selector` / `row_value_selector`) so they self-heal across keyset /
// `documents()` changes. Regenerate the fixture on a keyset change.
// ============================================================================

/// The `$.hello` op PATH selector — a distinct-per-row `op` leaf, imported from
/// the ONE shared copy (see its doc for provenance and how to re-derive it).
/// Distinctness is load-bearing for the ordering tests and is guarded by
/// `v3_jsonb_fixture_structural_invariants`. Containment deliberately ignores
/// `op`: exact equality uses value-selector presence instead.
use eql_tests::fixtures::v3_ste_vec::SEL_HELLO_OP;

// ============================================================================
// Tier-2 builders — curated literal payloads with KNOWN relationships.
//
// The fixture's real `op` ciphertexts are not in a guaranteed total order, so
// the ORDERED-correctness arms (D2) use a CURATED forged `op` ladder built
// inline here (forge hex differing in the trailing byte). CLLW-OPE ciphertexts
// order as PLAIN LEXICOGRAPHIC byte strings (the hex-decoded bytes compare
// like memcmp; a shorter prefix sorts first), so choosing trailing bytes
// `..00 < ..01 < ..02` at a shared prefix yields a total, known order.
//
// Why not assert ordering over the *real* per-leaf `op` ciphertexts directly:
// the v3_ste_vec fixture's `$.hello` `op` leaves are sampled values with no
// known/stable plaintext-to-order mapping (the client emits OPE ciphertexts
// whose pairwise order is not curated in the fixture), so there is no oracle to
// assert against per leaf. Real-ciphertext ordering *is* covered where an oracle
// exists: the scalar matrix ORDER BY arm (`tests/sqlx/src/matrix.rs`,
// `*_ord_*_order_by`) sorts a column of real fixture ciphertexts and asserts the
// result matches the plaintext-sorted oracle. This forged ladder covers the
// complementary axis — that the per-leaf jsonb `op` comparison wiring itself
// orders correctly — with a known total order the fixture cannot provide.
// ============================================================================

/// A forged `op` hex ladder at a shared prefix, strictly increasing under
/// plain lexicographic byte order (the OPE comparison order).
/// `OP_LADDER[0] < OP_LADDER[1] < OP_LADDER[2] < OP_LADDER[3]`.
const OP_LADDER: [&str; 4] = [
    "00010203040500",
    "00010203040501",
    "00010203040502",
    "00010203040503",
];

/// Build a single sv entry literal (`jsonb_entry`-shaped) carrying selector
/// `sel`, ciphertext `c`, and an `op` ordering term.
fn entry(sel: &str, term_field: &str, term_hex: &str) -> String {
    format!(r#"{{"s":"{sel}","c":"ct","{term_field}":"{term_hex}"}}"#)
}

/// Build a TERM-LESS sv entry literal (`jsonb_entry`-shaped): selector `sel` and
/// a ciphertext, no `op`/`hm`. This is the shape of every VALUE entry and of the
/// bool/null/object/array PATH entries under the value-selector wire —
/// exact value equality is the PRESENCE of this selector, not a per-value term.
fn value_entry(sel: &str) -> String {
    format!(r#"{{"s":"{sel}","c":"ct"}}"#)
}

/// Build a `query_json` containment needle from a set of value SELECTORS (each
/// element is `{"s":"<sel>"}`, no term, no ciphertext). Containment on such a
/// needle is pure selector-subset presence — the exact value match.
fn value_needle(sels: &[&str]) -> String {
    let parts: Vec<String> = sels.iter().map(|s| format!(r#"{{"s":"{s}"}}"#)).collect();
    format!(r#"{{"sv":[{}]}}"#, parts.join(","))
}

/// Build an `op` jsonb_entry literal at the canonical ordered selector.
fn op_entry(op_hex: &str) -> String {
    entry(SEL_HELLO_OP, "op", op_hex)
}

/// Build a document literal (`public.eql_v3_json_search`-shaped) wrapping the given sv element
/// literals (each already a JSON object string).
fn doc(elems: &[String]) -> String {
    format!(
        r#"{{"i":{{"c":"col","t":"encrypted"}},"v":3,"h":"kh","sv":[{}]}}"#,
        elems.join(",")
    )
}

/// Build a `query_json` needle literal from `(selector, term_field, hex)`
/// triples (each element carries `s` + exactly one term, never `c`).
fn needle(elems: &[(&str, &str, &str)]) -> String {
    let parts: Vec<String> = elems
        .iter()
        .map(|(s, field, hex)| format!(r#"{{"s":"{s}","{field}":"{hex}"}}"#))
        .collect();
    format!(r#"{{"sv":[{}]}}"#, parts.join(","))
}

/// Derive a CONSTANT value selector at runtime — a term-less (`{s, c}`) selector
/// present on EVERY fixture row (a structural node / the `$.nested.deep`
/// constant value). A value_needle on it matches all rows, so it is the
/// "matches everything" oracle for containment positives.
///
/// Runtime derivation keeps the fixture-touching tests correct without a stale
/// hard-coded literal — the selector is a deterministic function of the JSON
/// path/value under the fixture keyset.
async fn constant_selector(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(
        "SELECT e->>'s' \
         FROM fixtures.v3_ste_vec f, jsonb_array_elements(f.payload::jsonb->'sv') e \
         WHERE NOT (e ? 'op') \
         GROUP BY e->>'s' \
         HAVING count(DISTINCT f.id) = (SELECT count(*) FROM fixtures.v3_ste_vec) \
         ORDER BY e->>'s' \
         LIMIT 1",
    )
    .fetch_one(pool)
    .await?)
}

/// Derive a value selector UNIQUE to row `id` — a term-less (`{s, c}`) selector
/// carried by exactly ONE fixture row (a per-row `$.hello` / `$.number` VALUE
/// selector). A value_needle on it matches exactly that one row, so it is the
/// exact-value-equality oracle (injective value-selector presence).
async fn row_value_selector(pool: &PgPool, id: i64) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(
        "SELECT e->>'s' \
         FROM fixtures.v3_ste_vec f, jsonb_array_elements(f.payload::jsonb->'sv') e \
         WHERE f.id = $1 AND NOT (e ? 'op') \
           AND (e->>'s') IN ( \
             SELECT e2->>'s' \
             FROM fixtures.v3_ste_vec f2, jsonb_array_elements(f2.payload::jsonb->'sv') e2 \
             WHERE NOT (e2 ? 'op') \
             GROUP BY e2->>'s' \
             HAVING count(DISTINCT f2.id) = 1 \
           ) \
         ORDER BY e->>'s' \
         LIMIT 1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?)
}

// ============================================================================
// D1 — Equality is not an extract operation. Entry-to-entry = / <> are
//      explicit non-STRICT blockers, just like entry-to-query equality.
// ============================================================================

#[sqlx::test]
async fn v3_jsonb_entry_equality_is_blocked(pool: PgPool) -> anyhow::Result<()> {
    let a = op_entry(OP_LADDER[0]);
    let b = op_entry(OP_LADDER[0]);
    for (op, function) in [("=", "eq"), ("<>", "neq")] {
        eql_tests::assert_raises(
            &pool,
            &format!(
                "SELECT '{a}'::public.eql_v3_json_entry {op} \
                 '{b}'::public.eql_v3_json_entry"
            ),
            &[],
            "is not supported",
        )
        .await?;
        eql_tests::assert_raises(
            &pool,
            &format!(
                "SELECT NULL::public.eql_v3_json_entry {op} \
                 '{b}'::public.eql_v3_json_entry"
            ),
            &[],
            "is not supported",
        )
        .await?;
        eql_tests::assert_raises(
            &pool,
            &format!(
                "SELECT eql_v3.{function}('{a}'::public.eql_v3_json_entry, \
                 '{b}'::public.eql_v3_json_entry)"
            ),
            &[],
            "is not supported",
        )
        .await?;
    }
    Ok(())
}

// ============================================================================
// D2 — Ordered correctness on an `op` leaf: < <= > >= follow the CLLW-OPE
//      order (plain bytewise comparison of the decoded ciphertexts), asserted
//      against the curated, KNOWN-ordered forged ladder. Order is total and
//      known, so we assert the exact relation for each operator.
// ============================================================================

macro_rules! v3_jsonb_ord_correctness {
    ( $( ($name:ident, $op:literal, $lo_rel:expr, $eq_rel:expr, $hi_rel:expr) ),+ $(,)? ) => {
        $( paste::paste! {
            #[sqlx::test]
            async fn [<v3_jsonb_op_ $name _correctness>](pool: PgPool) -> anyhow::Result<()> {
                let lo = op_entry(OP_LADDER[1]);
                let mid = op_entry(OP_LADDER[1]); // equal term to `lo`
                let hi = op_entry(OP_LADDER[2]);

                // mid `op` (something strictly greater): the "lo < hi" position.
                let against_greater: bool = sqlx::query_scalar(&format!(
                    "SELECT '{mid}'::public.eql_v3_json_entry {} '{hi}'::public.eql_v3_json_entry", $op
                )).fetch_one(&pool).await?;
                assert_eq!(against_greater, $lo_rel,
                    "op {} against a strictly-greater leaf", $op);

                // mid `op` (equal term).
                let against_equal: bool = sqlx::query_scalar(&format!(
                    "SELECT '{mid}'::public.eql_v3_json_entry {} '{lo}'::public.eql_v3_json_entry", $op
                )).fetch_one(&pool).await?;
                assert_eq!(against_equal, $eq_rel,
                    "op {} against an equal-term leaf", $op);

                // hi `op` (something strictly smaller).
                let against_smaller: bool = sqlx::query_scalar(&format!(
                    "SELECT '{hi}'::public.eql_v3_json_entry {} '{lo}'::public.eql_v3_json_entry", $op
                )).fetch_one(&pool).await?;
                assert_eq!(against_smaller, $hi_rel,
                    "op {} against a strictly-smaller leaf", $op);

                Ok(())
            }
        } )+
    };
}

//                       op    vs-greater  vs-equal  vs-smaller
v3_jsonb_ord_correctness!(
    (lt, "<", true, false, false),
    (lte, "<=", true, true, false),
    (gt, ">", false, false, true),
    (gte, ">=", false, true, true),
);

/// D2 — the forged ladder is a TOTAL order across all four leaves.
#[sqlx::test]
async fn v3_jsonb_op_ladder_is_total_order(pool: PgPool) -> anyhow::Result<()> {
    for w in OP_LADDER.windows(2) {
        let lo = op_entry(w[0]);
        let hi = op_entry(w[1]);
        let ok: bool = sqlx::query_scalar(&format!(
            "SELECT '{lo}'::public.eql_v3_json_entry < '{hi}'::public.eql_v3_json_entry"
        ))
        .fetch_one(&pool)
        .await?;
        assert!(
            ok,
            "ladder must be strictly increasing: {} < {}",
            w[0], w[1]
        );
    }
    // Transitive end-to-end: first < last.
    let first = op_entry(OP_LADDER[0]);
    let last = op_entry(OP_LADDER[OP_LADDER.len() - 1]);
    let end: bool = sqlx::query_scalar(&format!(
        "SELECT '{first}'::public.eql_v3_json_entry < '{last}'::public.eql_v3_json_entry"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(end, "ladder ends must be ordered first < last");
    Ok(())
}

// ============================================================================
// D3 — Entry ordering shape guard: the supported `(entry, entry)` form
//      resolves and behaves. (The mixed-shape ABSENCE — `(entry, jsonb)` /
//      `(jsonb, entry)` — is a structural catalog guard and lives in
//      v3_jsonb_operator_surface_tests.rs, because at runtime such a pair
//      flattens to native `jsonb = jsonb` rather than raising.)
// ============================================================================

#[sqlx::test]
async fn v3_jsonb_entry_entry_shape_resolves(pool: PgPool) -> anyhow::Result<()> {
    let a = entry(SEL_HELLO_OP, "op", OP_LADDER[0]);
    let b = entry(SEL_HELLO_OP, "op", OP_LADDER[1]);
    // Each entry ordering operator resolves on (entry, entry) and returns bool.
    for op in ["<", "<=", ">", ">="] {
        let _v: bool = sqlx::query_scalar(&format!(
            "SELECT '{a}'::public.eql_v3_json_entry {op} '{b}'::public.eql_v3_json_entry"
        ))
        .fetch_one(&pool)
        .await?;
    }
    Ok(())
}

// ============================================================================
// D4 — Containment positives + commutator agreement `a @> b ⇔ b <@ a`.
//      Covers value selectors and compatibility needles that still carry `op`.
//      Exact value equality is value-selector PRESENCE; containment ignores
//      ordering terms.
// ============================================================================

#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn v3_jsonb_containment_constant_value_selector(pool: PgPool) -> anyhow::Result<()> {
    // A CONSTANT value selector (a structural node / the `$.nested.deep`
    // constant value) is present on every fixture row, so the needle matches all
    // of them. Compare against the live row count (W/C: no hard-coded `10`), and
    // require a non-empty table so "matches all" isn't vacuously "matches 0".
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM fixtures.v3_ste_vec")
        .fetch_one(&pool)
        .await?;
    assert!(
        total > 0,
        "fixture sanity: fixtures.v3_ste_vec must be non-empty"
    );

    let sel = constant_selector(&pool).await?;
    let n = value_needle(&[&sel]);
    let hits: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM fixtures.v3_ste_vec WHERE payload @> '{n}'::eql_v3.query_json"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        hits, total,
        "every fixture row carries the constant value selector"
    );

    // Commutator: query_json <@ json must agree row-for-row.
    let hits_rev: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM fixtures.v3_ste_vec WHERE '{n}'::eql_v3.query_json <@ payload"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(hits_rev, hits, "a @> b must agree with b <@ a");

    // Injective end (exact value equality): a value selector UNIQUE to
    // row 1 must match EXACTLY that one row — value-selector presence is the
    // exact match. This is the strict-subset counterpart to the "matches all"
    // constant selector above, so the containment oracle is not a constant-true.
    let uniq = row_value_selector(&pool, 1).await?;
    let uniq_needle = value_needle(&[&uniq]);
    let uniq_rows: Vec<i64> = sqlx::query_scalar(&format!(
        "SELECT id FROM fixtures.v3_ste_vec WHERE payload @> '{uniq_needle}'::eql_v3.query_json ORDER BY id"
    ))
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        uniq_rows,
        vec![1],
        "a per-row-unique value selector must match exactly its one row (injective)"
    );
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn v3_jsonb_containment_ignores_op(pool: PgPool) -> anyhow::Result<()> {
    // Use a compatibility needle that carries row 1's `$.hello` ordering term.
    let op: String = sqlx::query_scalar(&format!(
        "SELECT (payload ->> '{SEL_HELLO_OP}'::text)::jsonb ->> 'op' FROM fixtures.v3_ste_vec WHERE id = 1"
    ))
    .fetch_one(&pool)
    .await?;
    let n = needle(&[(SEL_HELLO_OP, "op", &op)]);

    // Row 1 must be among the matches.
    let row1: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM fixtures.v3_ste_vec WHERE id = 1 AND payload @> '{n}'::eql_v3.query_json"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(row1, 1, "row 1 must contain its own path selector");

    // Commutator agreement over the whole table.
    let fwd: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM fixtures.v3_ste_vec WHERE payload @> '{n}'::eql_v3.query_json"
    ))
    .fetch_one(&pool)
    .await?;
    let rev: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM fixtures.v3_ste_vec WHERE '{n}'::eql_v3.query_json <@ payload"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(fwd, rev, "an op-bearing needle must agree across @> and <@");

    // The path selector is present in every document. The differing `op` bytes
    // must not narrow containment: ordering encodings are deliberately excluded
    // from the selector-set predicate.
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM fixtures.v3_ste_vec")
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        fwd, total,
        "containment must normalize an op-bearing needle to its selector"
    );
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn v3_jsonb_containment_mixed(pool: PgPool) -> anyhow::Result<()> {
    // Mixed needle: a constant value selector plus a row-1-specific value
    // selector carrying an irrelevant op. An OR implementation would match all
    // rows through the constant selector; correct AND/subset containment must
    // return only row 1. The ordering term is ignored.
    let op: String = sqlx::query_scalar(&format!(
        "SELECT (payload ->> '{SEL_HELLO_OP}'::text)::jsonb ->> 'op' FROM fixtures.v3_ste_vec WHERE id = 1"
    ))
    .fetch_one(&pool)
    .await?;
    let constant = constant_selector(&pool).await?;
    let row_specific = row_value_selector(&pool, 1).await?;
    // A value-selector element (`{s}`) + an op element (`{s, op}`).
    let n = format!(r#"{{"sv":[{{"s":"{constant}"}},{{"s":"{row_specific}","op":"{op}"}}]}}"#);

    let hits: Vec<i64> = sqlx::query_scalar(&format!(
        "SELECT id FROM fixtures.v3_ste_vec WHERE payload @> '{n}'::eql_v3.query_json ORDER BY id"
    ))
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        hits,
        vec![1],
        "every selector in a mixed needle is required, independently of op"
    );
    Ok(())
}

/// D4 — self-containment and the document/document containment overload against
/// a curated doc with both leaf kinds (a term-less value entry + an op entry).
#[sqlx::test]
async fn v3_jsonb_containment_self_and_subset(pool: PgPool) -> anyhow::Result<()> {
    // Self-contained: forged selectors are fine (containment keys on selector
    // presence, not on any real ciphertext). VALUE_SEL is term-less; op_entry
    // carries an `op`. They are distinct selectors.
    const VALUE_SEL: &str = "00000000000000000000000000000001";
    let full = doc(&[value_entry(VALUE_SEL), op_entry(OP_LADDER[2])]);
    let subset = doc(&[value_entry(VALUE_SEL)]);

    // Self-containment (json @> json).
    let self_c: bool = sqlx::query_scalar(&format!(
        "SELECT '{full}'::public.eql_v3_json_search @> '{full}'::public.eql_v3_json_search"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(self_c, "a document must contain itself");

    // Superset @> subset, and commutator subset <@ superset.
    let sup: bool = sqlx::query_scalar(&format!(
        "SELECT '{full}'::public.eql_v3_json_search @> '{subset}'::public.eql_v3_json_search"
    ))
    .fetch_one(&pool)
    .await?;
    let sub: bool = sqlx::query_scalar(&format!(
        "SELECT '{subset}'::public.eql_v3_json_search <@ '{full}'::public.eql_v3_json_search"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(
        sup && sub,
        "superset @> subset must agree with subset <@ superset"
    );

    // Subset does NOT contain superset.
    let backwards: bool = sqlx::query_scalar(&format!(
        "SELECT '{subset}'::public.eql_v3_json_search @> '{full}'::public.eql_v3_json_search"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(!backwards, "subset must not contain superset");
    Ok(())
}

#[sqlx::test]
async fn v3_jsonb_single_entry_containment_is_blocked(pool: PgPool) -> anyhow::Result<()> {
    let document = doc(&[op_entry(OP_LADDER[0])]);
    let entry = op_entry(OP_LADDER[0]);
    for sql in [
        format!(
            "SELECT '{document}'::public.eql_v3_json_search \
             @> '{entry}'::public.eql_v3_json_entry"
        ),
        format!(
            "SELECT '{entry}'::public.eql_v3_json_entry \
             <@ '{document}'::public.eql_v3_json_search"
        ),
        format!(
            "SELECT '{document}'::public.eql_v3_json_search \
             @> NULL::public.eql_v3_json_entry"
        ),
        format!(
            "SELECT NULL::public.eql_v3_json_entry \
             <@ '{document}'::public.eql_v3_json_search"
        ),
    ] {
        eql_tests::assert_raises(&pool, &sql, &[], "is not supported").await?;
    }
    Ok(())
}

/// The raw-`jsonb` GIN-inlining convenience helpers (`eql_v3.jsonb_contains` /
/// `eql_v3.jsonb_contained_by`, documented in docs/reference/json-support.md
/// and docs/reference/database-indexes.md as building blocks for hand-rolled
/// GIN index expressions over the raw extracted `jsonb[]` array) are
/// unreachable from the typed `@>`/`<@` operators — those bind to
/// `eql_v3.jsonb_document_contains` instead (see operators.sql) — and previously had
/// only structural (inlinability-allowlist) coverage, never a behavioral
/// assertion. Mirrors `v3_jsonb_containment_self_and_subset` but drives the
/// raw-`jsonb` overload directly, and cross-checks agreement with the typed
/// `@>` operator on the same inputs.
#[sqlx::test]
async fn v3_jsonb_raw_helpers_contains_and_contained_by(pool: PgPool) -> anyhow::Result<()> {
    const VALUE_SEL: &str = "00000000000000000000000000000001";
    let full = doc(&[value_entry(VALUE_SEL), op_entry(OP_LADDER[2])]);
    let subset = doc(&[value_entry(VALUE_SEL)]);

    let sup: bool = sqlx::query_scalar(&format!(
        "SELECT eql_v3.jsonb_contains('{full}'::jsonb, '{subset}'::jsonb)"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(sup, "jsonb_contains: superset must contain subset");

    let sub: bool = sqlx::query_scalar(&format!(
        "SELECT eql_v3.jsonb_contained_by('{subset}'::jsonb, '{full}'::jsonb)"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(
        sub,
        "jsonb_contained_by: subset must be contained by superset"
    );

    let backwards: bool = sqlx::query_scalar(&format!(
        "SELECT eql_v3.jsonb_contains('{subset}'::jsonb, '{full}'::jsonb)"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(
        !backwards,
        "jsonb_contains: subset must not contain superset"
    );

    // The raw helper must agree with the typed `@>` operator (which binds to
    // eql_v3.jsonb_document_contains, not this function) on the same well-formed inputs.
    let typed: bool = sqlx::query_scalar(&format!(
        "SELECT '{full}'::public.eql_v3_json_search @> '{subset}'::public.eql_v3_json_search"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        sup, typed,
        "jsonb_contains must agree with the typed @> operator"
    );

    // Ordering terms are not equality terms. All containment entry points
    // normalize to selector-only matching, so two entries with the same value
    // selector match even when one carries a different `op`.
    let same_selector_different_op = doc(&[entry(VALUE_SEL, "op", OP_LADDER[0])]);
    let raw_ignores_op: bool = sqlx::query_scalar(&format!(
        "SELECT eql_v3.jsonb_contains('{full}'::jsonb, '{same_selector_different_op}'::jsonb)"
    ))
    .fetch_one(&pool)
    .await?;
    let document_ignores_op: bool = sqlx::query_scalar(&format!(
        "SELECT '{full}'::public.eql_v3_json_search @> '{same_selector_different_op}'::public.eql_v3_json_search"
    ))
    .fetch_one(&pool)
    .await?;
    let query_ignores_op: bool = sqlx::query_scalar(&format!(
        "SELECT '{full}'::public.eql_v3_json_search @> '{{\"sv\":[{{\"s\":\"{VALUE_SEL}\",\"op\":\"{}\"}}]}}'::eql_v3.query_json",
        OP_LADDER[0]
    ))
    .fetch_one(&pool)
    .await?;
    assert!(raw_ignores_op && document_ignores_op && query_ignores_op);

    Ok(())
}

/// `eql_v3.ord_term(jsonb_entry)` has no `has_*` companion: absence of an
/// `op` term is signalled by the extractor returning SQL NULL (which a
/// functional btree index stores and comparisons skip). Dedicated
/// positive/negative coverage of both branches — a non-NULL bytea for an
/// op-bearing entry, NULL for a term-less (`{s, c}`) entry.
#[sqlx::test]
async fn v3_jsonb_ord_ope_term_entry_branches(pool: PgPool) -> anyhow::Result<()> {
    let with_op = op_entry(OP_LADDER[0]);
    let term: Option<Vec<u8>> = sqlx::query_scalar(&format!(
        "SELECT eql_v3.ord_term('{with_op}'::public.eql_v3_json_entry)::bytea"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(
        term.is_some(),
        "ord_term must be non-NULL for an op-bearing entry"
    );
    let raw: Option<Vec<u8>> = sqlx::query_scalar(&format!(
        "SELECT eql_v3.ope_term('{with_op}'::public.eql_v3_json_entry)"
    ))
    .fetch_one(&pool)
    .await?;
    let legacy: Option<Vec<u8>> = sqlx::query_scalar(&format!(
        "SELECT eql_v3.eq_term('{with_op}'::public.eql_v3_json_entry)"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(raw, term, "ope_term exposes the same raw bytes as ord_term");
    assert_eq!(
        legacy, raw,
        "the deprecated eq_term(json_entry) alias must remain compatible"
    );

    let term_less = value_entry("00000000000000000000000000000001");
    let no_term: Option<Vec<u8>> = sqlx::query_scalar(&format!(
        "SELECT eql_v3.ord_term('{term_less}'::public.eql_v3_json_entry)::bytea"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(
        no_term.is_none(),
        "ord_term must be NULL for a term-less entry (no op term to extract)"
    );

    Ok(())
}

/// LB1–LB3 structural invariants of the GENERATED fixture, asserted directly
/// (the containment / index oracles only imply them). This is the "generated
/// fixture matches the load-bearing properties" guard, and it doubles as the
/// reproducibility contract: live SteVec encryption is NOT byte-deterministic
/// (ZeroKMS randomises the `c` ciphertext), so the stable contract is these
/// structural invariants, not byte-equality. It is correctly fixture-touching,
/// so it fails on the empty-fixture negative control (count(*) = 10).
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn v3_jsonb_fixture_structural_invariants(pool: PgPool) -> anyhow::Result<()> {
    // LB1: exactly 10 rows, ids 1..=10.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM fixtures.v3_ste_vec")
        .fetch_one(&pool)
        .await?;
    assert_eq!(n, 10, "LB1: exactly 10 rows");
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM fixtures.v3_ste_vec ORDER BY id")
        .fetch_all(&pool)
        .await?;
    assert_eq!(ids, (1..=10).collect::<Vec<_>>(), "LB1: ids 1..=10");

    // LB2: at least one CONSTANT value selector (a term-less `{s, c}` entry — a
    // structural node / the `$.nested.deep` constant value) is present on EVERY
    // row. Under the value-selector wire, exact value equality is
    // value-selector presence, so a constant node's selector recurs across all
    // rows — this is the "matches everything" containment oracle.
    let constant_selectors: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ( \
           SELECT e->>'s' \
           FROM fixtures.v3_ste_vec f, jsonb_array_elements(f.payload::jsonb->'sv') e \
           WHERE NOT (e ? 'op') \
           GROUP BY e->>'s' \
           HAVING count(DISTINCT f.id) = (SELECT count(*) FROM fixtures.v3_ste_vec) \
         ) s",
    )
    .fetch_one(&pool)
    .await?;
    assert!(
        constant_selectors >= 1,
        "LB2: at least one constant value selector present on all rows"
    );
    let sel = constant_selector(&pool).await?;
    let sel_rows: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM fixtures.v3_ste_vec f \
         WHERE EXISTS ( \
           SELECT 1 FROM jsonb_array_elements(f.payload::jsonb->'sv') e \
           WHERE e->>'s' = '{sel}' \
         )"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        sel_rows, 10,
        "LB2: the constant value selector is present in every row"
    );

    // LB3: the $.hello op is present in every row AND distinct across all 10
    // (oracle discrimination — Risk #0).
    let distinct_hello_op: i64 = sqlx::query_scalar(&format!(
        "SELECT count(DISTINCT (payload ->> '{SEL_HELLO_OP}'::text)::jsonb ->> 'op') \
         FROM fixtures.v3_ste_vec"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        distinct_hello_op, 10,
        "LB3: $.hello op distinct across all rows (oracle discrimination)"
    );
    Ok(())
}

// ============================================================================
// D5 — Discriminating containment: ordering bytes do not affect selector-set
//      matching, while a non-existent selector never matches.
// ============================================================================

#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn v3_jsonb_containment_ignores_wrong_op_bytes(pool: PgPool) -> anyhow::Result<()> {
    // A compatibility needle carrying the real ordering term matches every row
    // that carries the shared path selector.
    let op: String = sqlx::query_scalar(&format!(
        "SELECT (payload ->> '{SEL_HELLO_OP}'::text)::jsonb ->> 'op' FROM fixtures.v3_ste_vec WHERE id = 1"
    ))
    .fetch_one(&pool)
    .await?;
    let good = needle(&[(SEL_HELLO_OP, "op", &op)]);
    let good_hits: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM fixtures.v3_ste_vec WHERE payload @> '{good}'::eql_v3.query_json"
    ))
    .fetch_one(&pool)
    .await?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM fixtures.v3_ste_vec")
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        good_hits, total,
        "the real path selector must match every row"
    );

    // Real path selector with different ordering bytes. Containment strips the
    // ordering term and therefore still matches every row carrying the path.
    let n = needle(&[(SEL_HELLO_OP, "op", "deadbeefdeadbeefdeadbeefdeadbeef")]);
    let hits: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM fixtures.v3_ste_vec WHERE payload @> '{n}'::eql_v3.query_json"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(hits, total, "containment must ignore op bytes");
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn v3_jsonb_containment_rejects_wrong_selector(pool: PgPool) -> anyhow::Result<()> {
    // Non-vacuity floor (W3): a REAL (constant) value selector must match, so the
    // `== 0` below means "rejected for wrong selector", not "table empty".
    let sel = constant_selector(&pool).await?;
    let good = value_needle(&[&sel]);
    let good_hits: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM fixtures.v3_ste_vec WHERE payload @> '{good}'::eql_v3.query_json"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(
        good_hits > 0,
        "fixture sanity: a real value selector matches"
    );

    // A selector that exists in no fixture row must match nothing.
    let n = value_needle(&["ffffffffffffffffffffffffffffffff"]);
    let hits: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM fixtures.v3_ste_vec WHERE payload @> '{n}'::eql_v3.query_json"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        hits, 0,
        "a needle at a non-existent selector must not match"
    );
    Ok(())
}

// ============================================================================
// D6 — NULL-per-supported-signature: every supported wrapper is STRICT and
//      propagates NULL on each nullable argument position.
// ============================================================================

macro_rules! v3_jsonb_supported_null {
    ( $( ($name:ident, $sql:expr) ),+ $(,)? ) => {
        $( paste::paste! {
            #[sqlx::test]
            async fn [<v3_jsonb_ $name _supported_null>](pool: PgPool) -> anyhow::Result<()> {
                // Supported operators are STRICT: a NULL operand yields NULL, not
                // an error and not a non-NULL result.
                eql_tests::assert_null(&pool, $sql, &[]).await
            }
        } )+
    };
}

// A well-formed empty document — the non-NULL counterpart used by the blocker
// arms below.
//
// Intentionally crypto-free: this is the minimal structurally-valid envelope
// (empty `i`, version literal, empty `sv`), NOT a stand-in for a generated
// fixture. It carries zero `hm`/`op` index terms, so the real-encrypted-
// data rule (fixtures must come from actual crypto) does not apply — there is
// nothing fabricated to pass off as a real ciphertext. The blocker and
// bare-operand tests that use it exercise PostgreSQL domain/operator resolution
// (a pure type-system property, independent of payload contents), and their
// negative-control assertions DEPEND on `sv` being empty (e.g. bare `-> 'sv'`
// must return native `[]`; typed `-> 'sv'::text` must find no entry -> NULL).
// Swapping in a populated real-fixture document would break those assertions.
// Crypto-exercising arms in this file use the generated `fixtures.v3_ste_vec`
// fixture instead (see `constant_selector` / `row_value_selector`).
const NN_DOC: &str = r#"{"i":{},"v":3,"h":"kh","sv":[]}"#;

v3_jsonb_supported_null!(
    // entry ordering comparisons (< <= > >=)
    (entry_lt_lhs, "SELECT NULL::public.eql_v3_json_entry < '{\"s\":\"r\",\"c\":\"x\",\"op\":\"00\"}'::public.eql_v3_json_entry"),
    (entry_lte_lhs, "SELECT NULL::public.eql_v3_json_entry <= '{\"s\":\"r\",\"c\":\"x\",\"op\":\"00\"}'::public.eql_v3_json_entry"),
    (entry_gt_lhs, "SELECT NULL::public.eql_v3_json_entry > '{\"s\":\"r\",\"c\":\"x\",\"op\":\"00\"}'::public.eql_v3_json_entry"),
    (entry_gte_lhs, "SELECT NULL::public.eql_v3_json_entry >= '{\"s\":\"r\",\"c\":\"x\",\"op\":\"00\"}'::public.eql_v3_json_entry"),
    // document containment: json @> json
    (doc_contains_doc_lhs, "SELECT NULL::public.eql_v3_json_search @> '{\"i\":{},\"v\":3,\"h\":\"kh\",\"sv\":[]}'::public.eql_v3_json_search"),
    (doc_contains_doc_rhs, "SELECT '{\"i\":{},\"v\":3,\"h\":\"kh\",\"sv\":[]}'::public.eql_v3_json_search @> NULL::public.eql_v3_json_search"),
    // json @> query_json
    (doc_contains_query_lhs, "SELECT NULL::public.eql_v3_json_search @> '{\"sv\":[]}'::eql_v3.query_json"),
    (doc_contains_query_rhs, "SELECT '{\"i\":{},\"v\":3,\"h\":\"kh\",\"sv\":[]}'::public.eql_v3_json_search @> NULL::eql_v3.query_json"),
    // <@ reverse
    (query_contained_lhs, "SELECT NULL::eql_v3.query_json <@ '{\"i\":{},\"v\":3,\"h\":\"kh\",\"sv\":[]}'::public.eql_v3_json_search"),
);

// The `-> text` / `-> int` / `->> text` accessors return non-boolean types, so
// they can't go through `assert_null` (which expects `Option<bool>`). Assert
// their STRICT NULL-propagation directly.
#[sqlx::test]
async fn v3_jsonb_arrow_accessors_supported_null(pool: PgPool) -> anyhow::Result<()> {
    let arrow_text: Option<String> =
        sqlx::query_scalar("SELECT (NULL::public.eql_v3_json_search -> 'x'::text)::jsonb::text")
            .fetch_one(&pool)
            .await?;
    assert!(arrow_text.is_none(), "json -> text must propagate NULL");

    let arrow_int: Option<String> =
        sqlx::query_scalar("SELECT (NULL::public.eql_v3_json_search -> 0::integer)::jsonb::text")
            .fetch_one(&pool)
            .await?;
    assert!(arrow_int.is_none(), "json -> int must propagate NULL");

    let arrow_text_text: Option<String> =
        sqlx::query_scalar("SELECT NULL::public.eql_v3_json_search ->> 'x'::text")
            .fetch_one(&pool)
            .await?;
    assert!(
        arrow_text_text.is_none(),
        "json ->> text must propagate NULL"
    );

    let arrow_int_text: Option<String> =
        sqlx::query_scalar("SELECT NULL::public.eql_v3_json_search ->> 0::integer")
            .fetch_one(&pool)
            .await?;
    assert!(arrow_int_text.is_none(), "json ->> int must propagate NULL");
    Ok(())
}

// ============================================================================
// D7 — Blocker-per-unsupported-native-jsonb-signature. Each blocked native op
//      raises "is not supported" using PostgreSQL's real RHS type/value, and
//      the blocker is non-STRICT (NULL domain operand STILL raises).
// ============================================================================

macro_rules! v3_jsonb_blocker_cases {
    ( $( ($name:ident, $op:literal, $rhs:expr, rhs_domain = $rhs_domain:expr) ),+ $(,)? ) => {
        $( paste::paste! {
            #[sqlx::test]
            async fn [<v3_jsonb_ $name _blocker>](pool: PgPool) -> anyhow::Result<()> {
                let lhs = format!("'{}'::public.eql_v3_json_search", NN_DOC);
                let msg = "is not supported";

                // Domain on the left, real-typed RHS — must raise.
                let sql = format!("SELECT {lhs} {} {}", $op, $rhs);
                eql_tests::assert_raises(&pool, &sql, &[], msg).await?;

                // Non-STRICT proof: NULL domain LHS must STILL raise (a STRICT
                // blocker would short-circuit to NULL and bypass the exception).
                let null_lhs = format!("SELECT NULL::public.eql_v3_json_search {} {}", $op, $rhs);
                eql_tests::assert_raises(&pool, &null_lhs, &[], msg).await?;

                // Domain on the RIGHT, only where the surface defines that form.
                let rhs_dom: Option<&str> = $rhs_domain;
                if let Some(_) = rhs_dom {
                    let sql = format!("SELECT {} {} '{}'::public.eql_v3_json_search", $rhs, $op, NN_DOC);
                    eql_tests::assert_raises(&pool, &sql, &[], msg).await?;
                    // Non-STRICT proof for the right-domain form.
                    let null_rhs = format!("SELECT {} {} NULL::public.eql_v3_json_search", $rhs, $op);
                    eql_tests::assert_raises(&pool, &null_rhs, &[], msg).await?;
                }
                Ok(())
            }
        } )+
    };
}

v3_jsonb_blocker_cases!(
    (
        root_eq,
        "=",
        "'{}'::jsonb",
        rhs_domain = Some("'{}'::jsonb")
    ),
    (
        root_neq,
        "<>",
        "'{}'::jsonb",
        rhs_domain = Some("'{}'::jsonb")
    ),
    (
        root_lt,
        "<",
        "'{}'::jsonb",
        rhs_domain = Some("'{}'::jsonb")
    ),
    (
        root_lte,
        "<=",
        "'{}'::jsonb",
        rhs_domain = Some("'{}'::jsonb")
    ),
    (
        root_gt,
        ">",
        "'{}'::jsonb",
        rhs_domain = Some("'{}'::jsonb")
    ),
    (
        root_gte,
        ">=",
        "'{}'::jsonb",
        rhs_domain = Some("'{}'::jsonb")
    ),
    (
        mixed_contains,
        "@>",
        "'{}'::jsonb",
        rhs_domain = Some("'{}'::jsonb")
    ),
    (
        mixed_contained_by,
        "<@",
        "'{}'::jsonb",
        rhs_domain = Some("'{}'::jsonb")
    ),
    (question, "?", "'x'::text", rhs_domain = None),
    (question_pipe, "?|", "ARRAY['x']::text[]", rhs_domain = None),
    (question_amp, "?&", "ARRAY['x']::text[]", rhs_domain = None),
    (at_question, "@?", "'$.sv'::jsonpath", rhs_domain = None),
    (at_at, "@@", "'$.sv'::jsonpath", rhs_domain = None),
    (path_get, "#>", "ARRAY['sv']::text[]", rhs_domain = None),
    (
        path_get_text,
        "#>>",
        "ARRAY['sv']::text[]",
        rhs_domain = None
    ),
    (minus_text, "-", "'sv'::text", rhs_domain = None),
    (minus_int, "-", "0::integer", rhs_domain = None),
    (minus_array, "-", "ARRAY['sv']::text[]", rhs_domain = None),
    (path_del, "#-", "ARRAY['sv']::text[]", rhs_domain = None),
    (
        concat,
        "||",
        "'{}'::jsonb",
        rhs_domain = Some("'{}'::jsonb")
    ),
);

#[sqlx::test]
async fn v3_jsonb_root_doc_doc_comparison_blockers(pool: PgPool) -> anyhow::Result<()> {
    let lhs = format!("'{}'::public.eql_v3_json_search", NN_DOC);
    let rhs = format!("'{}'::public.eql_v3_json_search", NN_DOC);
    for op in ["=", "<>", "<", "<=", ">", ">="] {
        let sql = format!("SELECT {lhs} {op} {rhs}");
        eql_tests::assert_raises(&pool, &sql, &[], "is not supported").await?;
    }
    Ok(())
}

// D7 (negative control) — pins the domain-flattening rule that makes the typed
// RHS in `v3_jsonb_blocker_cases!` LOAD-BEARING (file header, lines 13–20). A
// BARE (unknown-typed) operand flattens `public.eql_v3_json_search` to native `jsonb`, so the
// SAME operator that RAISES with a typed RHS in D7 must SUCCEED here — resolving
// to native and returning a value, never reaching our blocker. Without this, the
// `::text` / `::jsonb` typing in D7 could silently become unnecessary (or, worse,
// a resolution change could route typed operands to native too) and no test
// would notice. See the "Typed operands" caveat in `docs/reference/json-support.md`.
#[sqlx::test]
async fn v3_jsonb_bare_operand_flattens_to_native(pool: PgPool) -> anyhow::Result<()> {
    let doc = format!("'{}'::public.eql_v3_json_search", NN_DOC);

    // `?` is blocked with a typed RHS in D7 (`question`). Bare `'sv'` is unknown
    // -> native `jsonb ? text` -> top-level key present -> TRUE, no raise.
    let bare_question: bool = sqlx::query_scalar(&format!("SELECT {doc} ? 'sv'"))
        .fetch_one(&pool)
        .await?;
    assert!(
        bare_question,
        "bare `?` must resolve to native `jsonb ? text` (top-level key 'sv' is \
         present in NN_DOC -> true); a raise would mean it reached our blocker, \
         breaking the documented domain-flattening contract"
    );

    // Same operator, TYPED RHS -> our blocker raises. Proves the divergence is
    // real (this is the D7 `question` case, re-asserted here to keep the
    // bare/typed contrast in one place).
    eql_tests::assert_raises(
        &pool,
        &format!("SELECT {doc} ? 'sv'::text"),
        &[],
        "is not supported",
    )
    .await?;

    // `||` is blocked with a typed RHS in D7 (`concat`). Bare `'{}'` is unknown
    // -> native `jsonb || jsonb` -> merged object, no raise.
    let bare_concat: String = sqlx::query_scalar(&format!("SELECT ({doc} || '{{}}')::text"))
        .fetch_one(&pool)
        .await?;
    assert!(
        bare_concat.contains("\"sv\""),
        "bare `||` must resolve to native `jsonb || jsonb` and return the merged \
         document, got {bare_concat:?}"
    );
    eql_tests::assert_raises(
        &pool,
        &format!("SELECT {doc} || '{{}}'::jsonb"),
        &[],
        "is not supported",
    )
    .await?;

    Ok(())
}

// D7 (negative control, finding #1) — the `->`/`->>` SUPPORTED operators are the
// DANGEROUS face of domain-flattening. Unlike the blockers above (typed RHS
// RAISES, bare RHS merely succeeds-as-native), `->`/`->>` SILENTLY return a WRONG
// answer for a bare untyped selector: `doc -> 'sel'` flattens `public.eql_v3_json_search` to
// native `jsonb -> text` (a root-key lookup on the envelope), NOT the v3
// selector-lookup operator. This pins BOTH which operator binds (`pg_typeof`) and
// the user-visible divergence, so a future resolution change in either direction
// goes red. The contract is intrinsic to the domain type-kind and CANNOT be
// closed by an extra operator/blocker (an unknown-typed RHS always reduces the
// domain to its base `jsonb`, and the native operator wins the exact-match
// tiebreak); it is mitigated only by the Proxy always sending typed `$n`
// parameters. A direct-SQL caller writing the bare form gets native semantics
// with no error. See the `@warning` in `src/v3/json/operators.sql:20-28` and the
// "Typed operands" caveat in `docs/reference/json-support.md`.
#[sqlx::test]
async fn v3_jsonb_arrow_bare_operand_flattens_to_native(pool: PgPool) -> anyhow::Result<()> {
    let doc = format!("'{}'::public.eql_v3_json_search", NN_DOC);

    // --- `->` : which operator binds? -------------------------------------
    // Bare selector -> NATIVE `jsonb -> text` (result type is `jsonb`).
    let bare_ty: String = sqlx::query_scalar(&format!("SELECT pg_typeof({doc} -> 'sv')::text"))
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        bare_ty, "jsonb",
        "bare `->` must flatten to native `jsonb -> text`; binding the v3 operator \
         (public.eql_v3_json_entry) here would mean the domain-flattening contract changed"
    );
    // Typed selector -> the v3 operator (result type is `public.eql_v3_json_entry`).
    let typed_ty: String =
        sqlx::query_scalar(&format!("SELECT pg_typeof({doc} -> 'sv'::text)::text"))
            .fetch_one(&pool)
            .await?;
    assert!(
        matches!(
            typed_ty.as_str(),
            "public.eql_v3_json_entry" | "eql_v3_json_entry"
        ),
        "typed `-> 'sv'::text` must bind the v3 selector-lookup operator"
    );

    // --- `->` : the user-visible WRONG answer -----------------------------
    // Native root-key lookup finds the top-level `sv` array (non-NULL `[]`); the
    // v3 selector lookup finds no entry with selector 'sv' in the empty sv array
    // (NULL). The bare form silently returns the envelope's raw `sv`, not an
    // encrypted entry — the false-negative finding #1 documents.
    let bare_val: String = sqlx::query_scalar(&format!("SELECT ({doc} -> 'sv')::text"))
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        bare_val, "[]",
        "bare `->` returns the native root-key lookup of `sv` (the raw envelope \
         array), demonstrating the silent wrong answer"
    );
    let typed_val: Option<String> =
        sqlx::query_scalar(&format!("SELECT ({doc} -> 'sv'::text)::text"))
            .fetch_one(&pool)
            .await?;
    assert!(
        typed_val.is_none(),
        "typed `-> 'sv'::text` finds no sv entry in the empty document -> NULL, \
         got {typed_val:?}"
    );

    // --- `->>` : same divergence. Both overloads return `text`, so the split is
    //            value-only: bare native `->>` serializes the root `sv` value
    //            ('[]'); typed v3 `->>` finds no entry (NULL).
    let bare_text: Option<String> = sqlx::query_scalar(&format!("SELECT {doc} ->> 'sv'"))
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        bare_text.as_deref(),
        Some("[]"),
        "bare `->>` must resolve to native `jsonb ->> text` and serialize the root \
         `sv` value"
    );
    let typed_text: Option<String> = sqlx::query_scalar(&format!("SELECT {doc} ->> 'sv'::text"))
        .fetch_one(&pool)
        .await?;
    assert!(
        typed_text.is_none(),
        "typed `->> 'sv'::text` finds no sv entry -> NULL, got {typed_text:?}"
    );

    Ok(())
}

// ============================================================================
// D9 — Payload-CHECK per domain. Malformed payloads are rejected by the domain
//      CHECK (error contains "violates check constraint").
// ============================================================================

macro_rules! v3_jsonb_payload_reject {
    ( $fn:ident, $domain:expr, [ $( $payload:expr ),+ $(,)? ] ) => {
        #[sqlx::test]
        async fn $fn(pool: PgPool) -> anyhow::Result<()> {
            for payload in [ $( $payload ),+ ] {
                let sql = format!("SELECT '{}'::{}", payload, $domain);
                eql_tests::assert_raises(&pool, &sql, &[], "violates check constraint")
                    .await
                    .map_err(|e| anyhow::anyhow!("payload {:?} for {} should reject: {}", payload, $domain, e))?;
            }
            Ok(())
        }
    };
}

v3_jsonb_payload_reject!(
    v3_jsonb_json_payload_check,
    "public.eql_v3_json_search",
    [
        "[]",                                                                               // non-object
        "{\"v\":3,\"h\":\"kh\",\"sv\":[]}",            // missing i
        "{\"i\":{},\"h\":\"kh\",\"sv\":[]}",           // missing v
        "{\"i\":{},\"v\":3,\"sv\":[]}",                // missing h (key header)
        "{\"i\":{},\"v\":2,\"h\":\"kh\",\"sv\":[]}",   // v != 3 (the legacy 2)
        "{\"i\":{},\"v\":3.0,\"h\":\"kh\",\"sv\":[]}", // v renders to text '3.0', not '3'
        "{\"i\":{},\"v\":3,\"h\":\"kh\"}",             // missing sv
        "{\"i\":{},\"v\":3,\"h\":42,\"sv\":[]}",       // h must be a string
        "{\"i\":{},\"v\":3,\"h\":\"kh\",\"sv\":{}}",   // sv not an array
        "{\"i\":{},\"v\":3,\"h\":\"kh\",\"sv\":[{\"s\":null,\"c\":\"y\"}]}", // bad entry s
        "{\"i\":{},\"v\":3,\"h\":\"kh\",\"sv\":[{\"s\":\"x\",\"c\":1}]}", // bad entry c
        "{\"i\":{},\"v\":3,\"h\":\"kh\",\"sv\":[{\"s\":\"x\",\"c\":\"y\",\"hm\":\"00\"}]}", // hm retired
        "{\"i\":{},\"v\":3,\"h\":\"kh\",\"sv\":[{\"s\":\"x\",\"c\":\"y\",\"op\":1}]}", // bad entry op
        "{\"i\":{},\"v\":3,\"h\":\"kh\",\"sv\":[],\"bogus\":true}", // unknown root fields
    ]
);

v3_jsonb_payload_reject!(
    v3_jsonb_ste_vec_entry_payload_check,
    "public.eql_v3_json_entry",
    [
        "[]",                                                    // non-object
        "{\"s\":\"x\"}",                                         // missing c
        "{\"c\":\"y\"}",                                         // missing s
        "{\"s\":\"x\",\"c\":\"y\",\"hm\":\"00\"}",               // hm is retired — rejected
        "{\"s\":\"x\",\"c\":\"y\",\"hm\":\"00\",\"op\":\"01\"}", // hm present (even with op)
        "{\"s\":null,\"c\":\"y\"}",                              // s must be a string
        "{\"s\":\"x\",\"c\":1}",                                 // c must be a string
        "{\"s\":\"x\",\"c\":\"y\",\"op\":1}",                    // op must be a string
        "{\"s\":\"x\",\"c\":\"y\",\"bogus\":true}",              // unknown fields are rejected
    ]
);

v3_jsonb_payload_reject!(
    v3_jsonb_ste_vec_query_payload_check,
    "eql_v3.query_json",
    [
        "[]",                                                   // non-object
        "{\"sv\":{}}",                                          // sv not an array
        "{\"sv\":[{\"s\":\"x\",\"c\":\"y\"}]}",                 // c-bearing element
        "{\"sv\":[{\"op\":\"00\"}]}",                           // no selector (no s)
        "{\"sv\":[{\"s\":\"x\",\"hm\":\"00\"}]}",               // hm is retired — rejected
        "{\"sv\":[{\"s\":\"x\",\"hm\":\"00\",\"op\":\"01\"}]}", // hm present (even with op)
        "{\"sv\":[{\"s\":null}]}",                              // s must be a string
        "{\"sv\":[{\"s\":\"x\",\"op\":1}]}",                    // op must be a string
        "{\"sv\":[{\"s\":\"x\",\"bogus\":true}]}",              // unknown element fields
        "{\"sv\":[],\"bogus\":true}",                           // unknown root fields
    ]
);

/// D9 — the well-formed positives the CHECKs MUST accept (so the rejects above
/// aren't trivially passing because everything is rejected).
#[sqlx::test]
async fn v3_jsonb_payload_check_accepts_valid(pool: PgPool) -> anyhow::Result<()> {
    let ok_doc: bool = sqlx::query_scalar(
        "SELECT '{\"i\":{},\"v\":3,\"h\":\"kh\",\"sv\":[]}'::public.eql_v3_json_search IS NOT NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert!(ok_doc);
    // A term-less `{s, c}` value/path entry and an op-bearing `{s, c, op}` entry
    // are both valid.
    let ok_entry: bool = sqlx::query_scalar(
        "SELECT '{\"s\":\"x\",\"c\":\"y\"}'::public.eql_v3_json_entry IS NOT NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert!(ok_entry);
    let ok_entry_op: bool = sqlx::query_scalar(
        "SELECT '{\"s\":\"x\",\"c\":\"y\",\"op\":\"00\"}'::public.eql_v3_json_entry IS NOT NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert!(ok_entry_op);
    // A selector-only `{s}` needle element and an op-bearing `{s, op}` element
    // are both valid query payloads.
    let ok_query: bool =
        sqlx::query_scalar("SELECT '{\"sv\":[{\"s\":\"x\"}]}'::eql_v3.query_json IS NOT NULL")
            .fetch_one(&pool)
            .await?;
    assert!(ok_query);
    let ok_query_op: bool = sqlx::query_scalar(
        "SELECT '{\"sv\":[{\"s\":\"x\",\"op\":\"00\"}]}'::eql_v3.query_json IS NOT NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert!(ok_query_op);
    Ok(())
}

/// D9 — the cipherstash-client SteVec envelope SHAPE (the extra top-level
/// `k:"sv"` the generator emits, plus the per-entry `a` array marker) must pass
/// the `public.eql_v3_json_search` domain CHECK. The static fixture lacked `k`; the generated
/// fixture carries it, so this guards the generated fixture against a CHECK
/// rejection independently of live encryption (no creds, no fixture load).
#[sqlx::test]
async fn v3_jsonb_generator_envelope_shape_accepted(pool: PgPool) -> anyhow::Result<()> {
    let envelope = r#"{
        "k":"sv","v":3,"i":{"c":"payload","t":"_fixture_v3_ste_vec"},
        "h":"mBbK_key_header",
        "sv":[
            {"s":"87042b77604cf03ab1ec9a05b5f9c2f7","c":"ct","a":false},
            {"s":"3a114ad13d25b030f41175114347de59","c":"ct","op":"00010203","a":false}
        ]
    }"#;
    let ok: bool = sqlx::query_scalar(&format!(
        "SELECT '{envelope}'::public.eql_v3_json_search IS NOT NULL"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(
        ok,
        "cipherstash SteVec envelope (root k:\"sv\" + per-entry a) must pass the public.eql_v3_json_search CHECK"
    );
    Ok(())
}

// ============================================================================
// D10 — Path/array function correctness. Matching selector returns
//       jsonb_entry rows; missing selector returns empty/NULL; non-array
//       raises; jsonb_array_elements returns SETOF jsonb_entry.
// ============================================================================

/// A curated array-flavoured document (`a:true`) the array functions accept.
/// The entries are term-less (`{s, c}`) — these tests exercise path/array
/// STRUCTURE (selector lookup, element count), so the index term is irrelevant.
fn array_doc() -> String {
    r#"{"i":{},"v":3,"h":"kh","a":true,"sv":[{"s":"aa","c":"x"},{"s":"bb","c":"y"}]}"#.to_string()
}

#[sqlx::test]
async fn v3_jsonb_path_query_match_and_miss(pool: PgPool) -> anyhow::Result<()> {
    let d = array_doc();
    // Matching selector returns exactly one entry row, whose selector is 'aa'.
    let hits: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM eql_v3.jsonb_path_query('{d}'::public.eql_v3_json_search::jsonb, 'aa')"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(hits, 1, "one entry matches selector 'aa'");

    let sel: String = sqlx::query_scalar(&format!(
        "SELECT eql_v3.selector(e) FROM eql_v3.jsonb_path_query('{d}'::public.eql_v3_json_search::jsonb, 'aa') AS e"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(sel, "aa", "matched entry carries the queried selector");

    // Missing selector returns an empty set.
    let miss: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM eql_v3.jsonb_path_query('{d}'::public.eql_v3_json_search::jsonb, 'zz')"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(miss, 0, "no entry matches a missing selector");
    Ok(())
}

#[sqlx::test]
async fn v3_jsonb_path_exists_and_first(pool: PgPool) -> anyhow::Result<()> {
    let d = array_doc();
    let exists: bool = sqlx::query_scalar(&format!(
        "SELECT eql_v3.jsonb_path_exists('{d}'::public.eql_v3_json_search::jsonb, 'bb')"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(exists, "selector 'bb' exists");

    let missing: bool = sqlx::query_scalar(&format!(
        "SELECT eql_v3.jsonb_path_exists('{d}'::public.eql_v3_json_search::jsonb, 'zz')"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(!missing, "selector 'zz' does not exist");

    // query_first returns the matching entry (selector 'bb').
    let first_sel: String = sqlx::query_scalar(&format!(
        "SELECT eql_v3.selector(eql_v3.jsonb_path_query_first('{d}'::public.eql_v3_json_search::jsonb, 'bb'))"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(first_sel, "bb");

    // query_first on a miss returns NULL.
    let first_miss: Option<String> = sqlx::query_scalar(&format!(
        "SELECT eql_v3.selector(eql_v3.jsonb_path_query_first('{d}'::public.eql_v3_json_search::jsonb, 'zz'))"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(first_miss.is_none(), "query_first on a miss is NULL");
    Ok(())
}

#[sqlx::test]
async fn v3_jsonb_array_length_and_elements(pool: PgPool) -> anyhow::Result<()> {
    let d = array_doc();
    let len: i32 = sqlx::query_scalar(&format!(
        "SELECT eql_v3.jsonb_array_length('{d}'::public.eql_v3_json_search::jsonb)"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(len, 2, "array doc has two elements");

    let n: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM eql_v3.jsonb_array_elements('{d}'::public.eql_v3_json_search::jsonb)"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(n, 2, "jsonb_array_elements yields one row per element");

    // jsonb_array_elements returns SETOF public.eql_v3_json_entry — the rows are
    // valid entries (the entry extractor accepts them).
    let sels: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT eql_v3.selector(e) FROM eql_v3.jsonb_array_elements('{d}'::public.eql_v3_json_search::jsonb) AS e ORDER BY 1"
    ))
    .fetch_all(&pool)
    .await?;
    assert_eq!(sels, vec!["aa".to_string(), "bb".to_string()]);

    // NOTE: `eql_v3.jsonb_array_elements_text` was REMOVED with the envelope
    // wire format — a bare per-element ciphertext stream is not decryptable
    // (entry `c` is raw AEAD output; the decryption unit is h + s + c), so
    // the entry-returning function above is the only element surface.
    let gone: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS (SELECT 1 FROM pg_proc          WHERE proname = 'jsonb_array_elements_text'            AND pronamespace = 'eql_v3'::regnamespace)",
    )
    .fetch_one(&pool)
    .await?;
    assert!(gone, "eql_v3.jsonb_array_elements_text must not exist");
    Ok(())
}

#[sqlx::test]
async fn v3_jsonb_array_length_non_array_raises(pool: PgPool) -> anyhow::Result<()> {
    // A document WITHOUT the `a:true` array flag is not an array.
    let not_array = r#"{"i":{},"v":3,"h":"kh","sv":[{"s":"aa","c":"x"}]}"#;
    let sql = format!(
        "SELECT eql_v3.jsonb_array_length('{not_array}'::public.eql_v3_json_search::jsonb)"
    );
    eql_tests::assert_raises(&pool, &sql, &[], "non-array").await?;

    let sql2 = format!(
        "SELECT count(*) FROM eql_v3.jsonb_array_elements('{not_array}'::public.eql_v3_json_search::jsonb)"
    );
    eql_tests::assert_raises(&pool, &sql2, &[], "non-array").await?;
    Ok(())
}

// ============================================================================
// D11 — Index engagement (validity, not preference): enable_seqscan=off +
//       node-type-aware assert_index_scan_uses on the 10-row fixture.
// ============================================================================

#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn v3_jsonb_index_to_ste_vec_query_gin_engages(pool: PgPool) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "CREATE INDEX v3_jsonb_gin_idx ON fixtures.v3_ste_vec \
         USING gin ((eql_v3.to_ste_vec_query(payload)::jsonb) jsonb_path_ops)",
    )
    .execute(&mut *tx)
    .await?;

    let sel = constant_selector(&pool).await?;
    let n = value_needle(&[&sel]);
    let query =
        format!("SELECT id FROM fixtures.v3_ste_vec WHERE payload @> '{n}'::eql_v3.query_json");
    assert_index_scan_uses(
        &mut *tx,
        &query,
        "v3_jsonb_gin_idx",
        "to_ste_vec_query GIN must engage for payload @> needle",
    )
    .await?;

    // Row floor (W6): the index must actually RETURN rows, not engage over an
    // empty leaf. Without this, an index-scan-over-nothing would pass green.
    let matched: Vec<i64> = sqlx::query_scalar(&query).fetch_all(&mut *tx).await?;
    assert!(!matched.is_empty(), "the GIN-engaged query must match rows");

    tx.rollback().await?;
    Ok(())
}

#[sqlx::test]
async fn v3_jsonb_document_containment_uses_the_query_gin_index(
    pool: PgPool,
) -> anyhow::Result<()> {
    const VALUE_SEL: &str = "00000000000000000000000000000001";
    let full = doc(&[value_entry(VALUE_SEL), op_entry(OP_LADDER[2])]);
    let subset = doc(&[value_entry(VALUE_SEL)]);

    let mut tx = pool.begin().await?;
    sqlx::query(
        "CREATE TEMP TABLE ste_vec_document_gin (\
           id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, \
           payload public.eql_v3_json_search NOT NULL\
         )",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(&format!(
        "INSERT INTO ste_vec_document_gin (payload) VALUES \
         ('{full}'::public.eql_v3_json_search), \
         ('{subset}'::public.eql_v3_json_search)"
    ))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE INDEX ste_vec_document_gin_idx ON ste_vec_document_gin \
         USING gin ((eql_v3.to_ste_vec_query(payload)::jsonb) jsonb_path_ops)",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await?;

    let query = format!(
        "SELECT id FROM ste_vec_document_gin \
         WHERE payload @> '{subset}'::public.eql_v3_json_search"
    );
    assert_index_scan_uses(
        &mut *tx,
        &query,
        "ste_vec_document_gin_idx",
        "document-to-document containment must use the canonical query GIN index",
    )
    .await?;
    let matched: Vec<i64> = sqlx::query_scalar(&query).fetch_all(&mut *tx).await?;
    assert_eq!(matched.len(), 2, "both selector supersets must match");

    tx.rollback().await?;
    Ok(())
}

// ============================================================================
// D11-scale — jsonb containment GIN is COST-CHOSEN at scale (seqscan ON).
//
// The sibling `v3_jsonb_index_to_ste_vec_query_gin_engages` (above) forces
// `enable_seqscan = off` over the 10-row fixture: it proves the GIN index is
// USABLE, not that the planner PREFERS it. This test replicates ONE real
// fixture document to 5000 rows (the bulk) plus a single DISTINCT pivot
// document and, leaving `enable_seqscan` ON, asserts the planner CHOOSES the
// GIN index for a single-row-selective containment needle. Same pattern as the
// scalar `*_scale_preference_*` arms, and `#[cfg(feature = "scale")]` so it
// rides the bench workflow, not fast PR CI (matches the scalar scale arms).
//
// Real ciphertext only: both documents come from the generated `v3_ste_vec`
// fixture, replicated via generate_series — no new fixture, no static blob.
// Selectivity comes from a value selector unique to the pivot document. This
// exercises the same exact-equality representation clients use in production,
// while ordering terms remain outside the containment predicate.
// ============================================================================

#[cfg(feature = "scale")]
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn v3_jsonb_to_ste_vec_query_gin_is_cost_chosen(pool: PgPool) -> anyhow::Result<()> {
    // Two distinct real fixture rows: the filler (bulk) and the pivot.
    let filler_payload: String = sqlx::query_scalar(
        "SELECT payload::jsonb::text FROM fixtures.v3_ste_vec ORDER BY id ASC LIMIT 1",
    )
    .fetch_one(&pool)
    .await?;
    let pivot_payload: String = sqlx::query_scalar(
        "SELECT payload::jsonb::text FROM fixtures.v3_ste_vec ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await?;

    let pivot_id: i64 =
        sqlx::query_scalar("SELECT id FROM fixtures.v3_ste_vec ORDER BY id DESC LIMIT 1")
            .fetch_one(&pool)
            .await?;
    let pivot_selector = row_value_selector(&pool, pivot_id).await?;

    let mut tx = pool.begin().await?;
    sqlx::query(
        "CREATE TEMP TABLE v3_jsonb_scale (payload public.eql_v3_json_search) ON COMMIT DROP",
    )
    .execute(&mut *tx)
    .await?;
    // The bulk: 5000 copies of the filler document.
    sqlx::query(
        "INSERT INTO v3_jsonb_scale(payload) \
         SELECT $1::jsonb::public.eql_v3_json_search FROM generate_series(1, 5000)",
    )
    .bind(&filler_payload)
    .execute(&mut *tx)
    .await?;
    // The single selective pivot document.
    sqlx::query(
        "INSERT INTO v3_jsonb_scale(payload) VALUES ($1::jsonb::public.eql_v3_json_search)",
    )
    .bind(&pivot_payload)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "CREATE INDEX v3_jsonb_scale_gin_idx ON v3_jsonb_scale \
         USING gin ((eql_v3.to_ste_vec_query(payload)::jsonb) jsonb_path_ops)",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query("ANALYZE v3_jsonb_scale")
        .execute(&mut *tx)
        .await?;
    // enable_seqscan LEFT ON — this is the cost-PREFERENCE proof, not the
    // usability proof (the sibling `*_gin_engages` arm forces seqscan off).

    // Selective needle: a value selector carried only by the pivot row.
    let n = value_needle(&[&pivot_selector]);
    let query =
        format!("SELECT count(*) FROM v3_jsonb_scale WHERE payload @> '{n}'::eql_v3.query_json");
    assert_index_scan_uses(
        &mut *tx,
        &query,
        "v3_jsonb_scale_gin_idx",
        "jsonb containment `@>` must PREFER the to_ste_vec_query GIN index at scale (seqscan ON)",
    )
    .await?;

    // Row floor + selectivity: exactly the single pivot row matches (not zero —
    // which would make the index-scan-over-nothing pass vacuously — and not the
    // bulk, which would mean the needle was not selective).
    let matched: i64 = sqlx::query_scalar(&query).fetch_one(&mut *tx).await?;
    assert_eq!(
        matched, 1,
        "the GIN-engaged containment needle must match exactly the single pivot row"
    );

    tx.rollback().await?;
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn v3_jsonb_index_ord_ope_btree_engages(pool: PgPool) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await?;
    sqlx::query(&format!(
        "CREATE INDEX v3_jsonb_btree_idx ON fixtures.v3_ste_vec \
         (eql_v3.ord_term(payload -> '{SEL_HELLO_OP}'::text))"
    ))
    .execute(&mut *tx)
    .await?;

    let query = format!(
        "SELECT id FROM fixtures.v3_ste_vec ORDER BY eql_v3.ord_term(payload -> '{SEL_HELLO_OP}'::text)"
    );
    assert_index_scan_uses(
        &mut *tx,
        &query,
        "v3_jsonb_btree_idx",
        "ord_term's default bytea btree opclass must engage for ORDER BY on a per-leaf op",
    )
    .await?;

    // Row floor (W6): the ordered scan must actually return rows, not engage
    // over an empty leaf.
    let ordered: Vec<i64> = sqlx::query_scalar(&query).fetch_all(&mut *tx).await?;
    assert!(
        !ordered.is_empty(),
        "the btree-engaged ORDER BY must return rows"
    );

    tx.rollback().await?;
    Ok(())
}

// ============================================================================
// D13 — Operator-integer overload (`-> int`): the array-index form casts
//       through native jsonb and is NOT shadowed by the `-> text` selector op.
// ============================================================================

#[sqlx::test]
async fn v3_jsonb_arrow_integer_index_on_array(pool: PgPool) -> anyhow::Result<()> {
    let d = array_doc();
    // `-> 0` / `-> 1` index the sv array positionally (native jsonb path), not a
    // selector lookup. Selectors come out in array order.
    let i0: String = sqlx::query_scalar(&format!(
        "SELECT eql_v3.selector('{d}'::public.eql_v3_json_search -> 0::integer)"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(i0, "aa", "-> 0 must index the first sv element");

    let i1: String = sqlx::query_scalar(&format!(
        "SELECT eql_v3.selector('{d}'::public.eql_v3_json_search -> 1::integer)"
    ))
    .fetch_one(&pool)
    .await?;
    assert_eq!(i1, "bb", "-> 1 must index the second sv element");

    let t1: String = sqlx::query_scalar(&format!(
        "SELECT '{d}'::public.eql_v3_json_search ->> 1::integer"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(
        t1.contains("\"s\": \"bb\""),
        "->> 1 must serialize the second sv element, got {t1}"
    );

    // Regression: `-> 'sv'::text` is a SELECTOR lookup (our text operator), NOT
    // native key access — there is no element with selector 'sv', so NULL.
    let sv_lookup: Option<String> = sqlx::query_scalar(&format!(
        "SELECT eql_v3.selector('{d}'::public.eql_v3_json_search -> 'sv'::text)"
    ))
    .fetch_one(&pool)
    .await?;
    assert!(
        sv_lookup.is_none(),
        "-> 'sv'::text must be a selector lookup (no match), not native key access"
    );
    Ok(())
}

// ============================================================================
// D14 — Planner metadata: supported entry ordering operators declare
//       COMMUTATOR/NEGATOR. Equality blockers deliberately declare none.
// ============================================================================

#[sqlx::test]
async fn v3_jsonb_entry_operators_declare_commutator_negator(pool: PgPool) -> anyhow::Result<()> {
    // For each entry operator, fetch its declared commutator/negator symbol.
    let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT o.oprname,
               com.oprname AS commutator,
               neg.oprname AS negator
        FROM pg_operator o
        LEFT JOIN pg_operator com ON com.oid = o.oprcom
        LEFT JOIN pg_operator neg ON neg.oid = o.oprnegate
        WHERE o.oprleft = 'public.eql_v3_json_entry'::regtype
          AND o.oprright = 'public.eql_v3_json_entry'::regtype
          AND o.oprname IN ('<', '<=', '>', '>=')
        ORDER BY o.oprname
        "#,
    )
    .fetch_all(&pool)
    .await?;

    // Expected (op, commutator, negator) per operators.sql.
    let expected: &[(&str, &str, &str)] = &[
        ("<", ">", ">="),
        ("<=", ">=", ">"),
        (">", "<", "<="),
        (">=", "<=", "<"),
    ];
    assert_eq!(rows.len(), expected.len(), "four entry ordering operators");

    for (op, com, neg) in expected {
        let found = rows
            .iter()
            .find(|(name, _, _)| name == op)
            .unwrap_or_else(|| panic!("operator {op} missing on jsonb_entry"));
        assert_eq!(
            found.1.as_deref(),
            Some(*com),
            "operator {op} must declare COMMUTATOR {com}"
        );
        assert_eq!(
            found.2.as_deref(),
            Some(*neg),
            "operator {op} must declare NEGATOR {neg}"
        );
    }
    Ok(())
}

#[sqlx::test]
async fn v3_jsonb_entry_equality_blockers_are_non_strict_plpgsql(
    pool: PgPool,
) -> anyhow::Result<()> {
    let rows: Vec<(String, bool, String, bool, bool, bool, bool)> = sqlx::query_as(
        r#"
        SELECT o.oprname,
               p.proisstrict,
               l.lanname,
               o.oprcanhash,
               o.oprcanmerge,
               o.oprcom <> 0,
               o.oprnegate <> 0
        FROM pg_operator o
        JOIN pg_proc p ON p.oid = o.oprcode
        JOIN pg_language l ON l.oid = p.prolang
        WHERE o.oprname IN ('=', '<>')
          AND oprleft = 'public.eql_v3_json_entry'::regtype
          AND oprright = 'public.eql_v3_json_entry'::regtype
        ORDER BY o.oprname
        "#,
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(rows.len(), 2, "both entry equality blockers must exist");
    for (op, strict, language, can_hash, can_merge, has_commutator, has_negator) in rows {
        assert!(!strict, "entry {op} blocker must execute for NULL operands");
        assert_eq!(language, "plpgsql", "entry {op} must be a blocker body");
        assert!(!can_hash && !can_merge);
        assert!(!has_commutator && !has_negator);
    }
    Ok(())
}
