//! Global guard for the encrypted-domain inline-critical SQL surface.
//!
//! `tasks/pin_search_path_v3.sql` runs after every build and pins a fixed
//! `search_path` on every `eql_v3` function — except the
//! inline-critical ones, which must stay unpinned so the planner can
//! inline them and the documented functional indexes (`eql_v3.eq_term(col)`,
//! `eql_v3.ord_term(col)`, `eql_v3.ord_term_ore(col)`, …) engage.
//!
//! The encrypted-domain family is skipped by a structural rule anchored
//! on the *identity predicate*: a `LANGUAGE sql`, `IMMUTABLE` function
//! taking at least one argument typed as a jsonb-backed DOMAIN of the
//! encrypted-domain families — a domain in the `eql_v3` schema (e.g.
//! `public.eql_v3_integer_eq`). The identity
//! predicate is proconfig-independent — it describes what a function
//! intrinsically IS, not whether it has been pinned.
//!
//! This test is the global net for that rule. It uses the identity
//! predicate VERBATIM and appends one offender filter:
//! `proconfig IS NOT NULL` — a function matching the family shape that
//! nonetheless carries a pinned `search_path`. It asserts that offender
//! set is empty. Because the test and the pin-loop skip clause share the
//! identity predicate exactly (the guard only adds the offender filter),
//! they cannot drift apart on identity.
//!
//! A non-empty result means `pin_search_path_v3.sql` pinned an
//! inline-critical encrypted-domain function — index engagement is
//! silently broken for that type. This is not integer-specific: a missed
//! skip for ANY encrypted-domain type — present or future — fails here,
//! so a new type's author does not have to remember to add a per-type
//! inlinability assertion.

use anyhow::Result;
use sqlx::PgPool;

#[sqlx::test]
async fn no_encrypted_domain_inline_critical_function_is_pinned(pool: PgPool) -> Result<()> {
    // The identity predicate is shared verbatim with the structural skip
    // clause in tasks/pin_search_path_v3.sql: LANGUAGE sql, IMMUTABLE, and
    // taking at least one argument typed as an encrypted-domain-family
    // domain over jsonb (an `eql_v3.*` domain). It is
    // proconfig-independent. The ONLY
    // addition here is the offender filter `p.proconfig IS NOT NULL` — a
    // function that matches the identity predicate but DID get pinned.
    // That set must be empty.
    let offenders: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT p.oid::regprocedure::text AS signature,
               array_to_string(p.proconfig, ', ') AS proconfig
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_catalog.pg_language  l ON l.oid = p.prolang
        WHERE n.nspname IN ('eql_v3', 'eql_v3_internal')
          AND l.lanname = 'sql'
          AND p.provolatile = 'i'
          AND p.proconfig IS NOT NULL
          AND EXISTS (
            SELECT 1
            FROM pg_catalog.unnest(p.proargtypes::oid[]) AS arg(typ)
            JOIN pg_catalog.pg_type dt ON dt.oid = arg.typ
            JOIN pg_catalog.pg_namespace dn ON dn.oid = dt.typnamespace
            JOIN pg_catalog.pg_type bt ON bt.oid = dt.typbasetype
            WHERE dt.typtype = 'd'
              AND bt.typname = 'jsonb'
              AND (
                   dn.nspname IN ('eql_v3', 'eql_v3_internal')
              )
          )
        ORDER BY signature
        "#,
    )
    .fetch_all(&pool)
    .await?;

    assert!(
        offenders.is_empty(),
        "pin_search_path_v3.sql pinned {} inline-critical encrypted-domain \
         SQL function(s) — index engagement is silently broken. \
         Offenders (signature → proconfig):\n{}",
        offenders.len(),
        offenders
            .iter()
            .map(|(sig, cfg)| format!("  {sig} → {cfg}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    Ok(())
}

/// Direct guard for the self-contained eql_v3 SEM index-term functions. Unlike
/// the structural guard above (which covers jsonb-domain-arg functions), these
/// take a composite (the ore_block_256 comparators) or raw
/// jsonb (hmac_256, bloom_filter, the ope_cllw extractor, the two
/// per-encrypted-value `jsonb_array_to_*` helpers) arg, so they are NOT caught
/// by the structural pin-skip and need explicit inline_critical allowlisting. If
/// pin_search_path_v3.sql pins any of them, v3 functional-index inlining silently
/// regresses to Seq Scan — this test fails instead.
///
/// `jsonb_array_to_bytea_array(jsonb)` and
/// `jsonb_array_to_ore_block_256(jsonb)` are NOT in this test's inlinable-SQL
/// set: their only caller chain (`ore_block_256(val)`, plpgsql, feeding the
/// btree operator class) can never inline a SQL function, so they are plpgsql
/// by design (issue #353) and guarded by the dedicated
/// `eql_v3_ore_block_256_opclass_helpers_are_plpgsql_and_unpinned` test below.
#[sqlx::test]
async fn eql_v3_sem_inline_critical_functions_are_unpinned(pool: PgPool) -> Result<()> {
    let rows: Vec<(String,)> = sqlx::query_as(
        r#"
        WITH expected(proname, pronargs, arg0, arg1) AS (
          VALUES
            ('ope_cllw', 1, 'jsonb'::regtype, 0::oid),
            ('meta_data', 1, 'jsonb'::regtype, 0::oid),
            ('jsonb_array', 1, 'jsonb'::regtype, 0::oid),
            ('jsonb_contains', 2, 'jsonb'::regtype, 'jsonb'::regtype),
            ('jsonb_contained_by', 2, 'jsonb'::regtype, 'jsonb'::regtype),
            ('jsonb_path_query', 2, 'jsonb'::regtype, 'text'::regtype),
            ('jsonb_path_exists', 2, 'jsonb'::regtype, 'text'::regtype),
            ('jsonb_path_query_first', 2, 'jsonb'::regtype, 'text'::regtype)
        )
        SELECT p.proname || '(' || pg_catalog.pg_get_function_arguments(p.oid) || ')'
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        LEFT JOIN expected e
          ON e.proname = p.proname
         AND e.pronargs = p.pronargs
         AND e.arg0 = p.proargtypes[0]
         AND (e.pronargs = 1 OR e.arg1 = p.proargtypes[1])
        WHERE n.nspname IN ('eql_v3', 'eql_v3_internal')
          AND (
            (p.pronargs = 2 AND p.proname IN (
              'ore_block_256_eq','ore_block_256_neq',
              'ore_block_256_lt','ore_block_256_lte',
              'ore_block_256_gt','ore_block_256_gte'))
            OR (p.pronargs = 1 AND p.proname IN (
              'hmac_256',
              'bloom_filter',
              'ope_cllw')
                AND p.proargtypes[0] = 'jsonb'::regtype)
            OR e.proname IS NOT NULL
          )
          AND (
            -- offender: pinned search_path, or not inlinable SQL/IMMUTABLE
            EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig,'{}'::text[])) c WHERE c LIKE 'search_path=%')
            OR p.provolatile <> 'i'
            OR p.prolang <> (SELECT l.oid FROM pg_catalog.pg_language l WHERE l.lanname = 'sql')
          )
        ORDER BY 1
        "#,
    )
    .fetch_all(&pool)
    .await?;

    assert!(
        rows.is_empty(),
        "eql_v3 SEM inline-critical functions must stay unpinned + inlinable SQL; offenders: {:?}",
        rows.iter().map(|r| &r.0).collect::<Vec<_>>()
    );
    Ok(())
}

/// Companion guard: the unpinned state asserted above is only DURABLE for
/// bare-`jsonb` helpers because each carries an `eql-inline-critical` COMMENT
/// marker that `tasks/pin_search_path_v3.sql` honours (it skips pinning
/// functions whose `pg_description` matches `'eql-inline-critical%'`). These
/// helpers are not caught by the structural jsonb-domain skip, so the marker
/// is the ONLY thing keeping them unpinned — an edit that removes the marker,
/// or a pin_search_path_v3.sql refactor that drops the marker handling, would
/// silently re-pin them and break inlining. This test asserts the marker is
/// present (and the helpers are SQL/IMMUTABLE). The two plpgsql
/// `jsonb_array_to_*` opclass-path helpers are guarded separately below
/// (issue #353).
#[sqlx::test]
async fn eql_v3_sem_inline_critical_helpers_carry_marker(pool: PgPool) -> Result<()> {
    // Each expected helper must appear with a present inline-critical marker
    // and be inlinable SQL/IMMUTABLE. Any helper that is missing, unmarked, or
    // not inlinable SQL/IMMUTABLE is an offender.
    let offenders: Vec<(String, Option<String>, String, String)> = sqlx::query_as(
        r#"
        WITH expected(proname, pronargs, arg0, arg1) AS (
          VALUES
            ('ope_cllw', 1, 'jsonb'::regtype, 0::oid),
            ('meta_data', 1, 'jsonb'::regtype, 0::oid),
            ('jsonb_array', 1, 'jsonb'::regtype, 0::oid),
            ('jsonb_contains', 2, 'jsonb'::regtype, 'jsonb'::regtype),
            ('jsonb_contained_by', 2, 'jsonb'::regtype, 'jsonb'::regtype),
            ('jsonb_path_query', 2, 'jsonb'::regtype, 'text'::regtype),
            ('jsonb_path_exists', 2, 'jsonb'::regtype, 'text'::regtype),
            ('jsonb_path_query_first', 2, 'jsonb'::regtype, 'text'::regtype)
        )
        SELECT e.proname AS proname,
               d.description AS marker,
               l.lanname AS prolang,
               p.provolatile::text AS provolatile
        FROM expected e
        LEFT JOIN pg_catalog.pg_proc p
          ON p.proname = e.proname
         AND p.pronamespace IN ('eql_v3'::regnamespace, 'eql_v3_internal'::regnamespace)
         AND p.pronargs = e.pronargs
         AND p.proargtypes[0] = e.arg0
         AND (e.pronargs = 1 OR p.proargtypes[1] = e.arg1)
        LEFT JOIN pg_catalog.pg_language l ON l.oid = p.prolang
        LEFT JOIN pg_catalog.pg_description d
          ON d.objoid = p.oid AND d.classoid = 'pg_proc'::regclass
        WHERE p.oid IS NULL
           OR d.description IS NULL
           OR d.description NOT LIKE 'eql-inline-critical%'
           OR l.lanname IS DISTINCT FROM 'sql'
           OR p.provolatile IS DISTINCT FROM 'i'
        ORDER BY e.proname
        "#,
    )
    .fetch_all(&pool)
    .await?;

    assert!(
        offenders.is_empty(),
        "eql_v3 SEM bare-jsonb helpers must carry an `eql-inline-critical` COMMENT \
         marker and be inlinable SQL/IMMUTABLE — the marker is what keeps \
         pin_search_path_v3.sql from pinning them. Offenders \
         (proname, marker, prolang, provolatile): {offenders:#?}"
    );
    Ok(())
}

/// One offending opclass helper: `(proname, lanname, provolatile, description, pinned)`.
type OpclassHelperRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<bool>,
);

/// Dedicated guard for the two `ore_block_256` opclass-path helpers
/// (`jsonb_array_to_bytea_array`, `jsonb_array_to_ore_block_256`) — issue #353.
///
/// Their only caller chain is `ore_block_256(val)` (plpgsql) feeding the btree
/// operator class: neither plpgsql callers nor opclass support contexts can
/// EVER inline a SQL function, so as `LANGUAGE sql` these paid the per-call
/// SQL-function executor on every compared value (measured 3.5x the plpgsql
/// per-call cost; +43% end-to-end on ORE ordered index scans — see
/// cipherstash/benches#23). They are therefore plpgsql BY DESIGN, and must
/// stay: (a) plpgsql — a revert to LANGUAGE sql reintroduces the regression;
/// (b) IMMUTABLE; (c) UNPINNED, via the `eql-inline-critical` marker — a
/// `SET search_path` clause on plpgsql forces per-call configuration
/// switching in the same hot path.
#[sqlx::test]
async fn eql_v3_ore_block_256_opclass_helpers_are_plpgsql_and_unpinned(pool: PgPool) -> Result<()> {
    let offenders: Vec<OpclassHelperRow> = sqlx::query_as(
        r#"
        WITH expected(proname) AS (
          VALUES ('jsonb_array_to_bytea_array'), ('jsonb_array_to_ore_block_256')
        )
        SELECT e.proname,
               l.lanname::text,
               p.provolatile::text,
               d.description,
               EXISTS (
                 SELECT 1 FROM unnest(coalesce(p.proconfig, '{}'::text[])) c
                 WHERE c LIKE 'search_path=%'
               ) AS pinned
        FROM expected e
        LEFT JOIN pg_catalog.pg_proc p
          ON p.proname = e.proname
         AND p.pronamespace = 'eql_v3_internal'::regnamespace
         AND p.pronargs = 1
         AND p.proargtypes[0] = 'jsonb'::regtype
        LEFT JOIN pg_catalog.pg_language l ON l.oid = p.prolang
        LEFT JOIN pg_catalog.pg_description d
          ON d.objoid = p.oid AND d.classoid = 'pg_proc'::regclass
        WHERE p.oid IS NULL
           OR l.lanname IS DISTINCT FROM 'plpgsql'
           OR p.provolatile IS DISTINCT FROM 'i'
           OR d.description IS NULL
           OR d.description NOT LIKE 'eql-inline-critical%'
           OR EXISTS (
                 SELECT 1 FROM unnest(coalesce(p.proconfig, '{}'::text[])) c
                 WHERE c LIKE 'search_path=%'
              )
        ORDER BY e.proname
        "#,
    )
    .fetch_all(&pool)
    .await?;

    assert!(
        offenders.is_empty(),
        "ore_block_256 opclass-path helpers must be plpgsql + IMMUTABLE + \
         marker-unpinned (issue #353) — offenders (proname, lang, volatility, \
         marker, pinned): {offenders:#?}"
    );
    Ok(())
}

#[sqlx::test]
async fn every_inline_critical_eligible_domain_has_inline_critical_functions(
    pool: PgPool,
) -> Result<()> {
    // Stronger than a bare `count > 0`: if a future change accidentally
    // narrows the structural predicate (e.g. hard-codes `integer_%`), a
    // `count > 0` assertion would still pass while bigint/bool/date
    // domains silently lose inline-critical coverage. Instead, assert
    // that EVERY inline-critical-eligible domain (any encrypted-domain
    // family domain over jsonb — `eql_v3.*` —
    // that carries a capability suffix — `_eq`, `_ord`, `_ord_ore`)
    // appears as an argument type of at least one inline-critical
    // function.
    //
    // Storage-only variants (the bare `eql_v3.<T>` domain,
    // with no capability suffix) intentionally have NO inline-critical
    // surface and are excluded from the eligibility set.
    let unbound: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT dt.typname
        FROM pg_catalog.pg_type dt
        JOIN pg_catalog.pg_namespace dn ON dn.oid = dt.typnamespace
        JOIN pg_catalog.pg_type bt ON bt.oid = dt.typbasetype
        WHERE dt.typtype = 'd'
          AND bt.typname = 'jsonb'
          AND (
               dn.nspname IN ('eql_v3', 'eql_v3_internal')
          )
          AND (
               dt.typname LIKE '%\_eq'
            OR dt.typname LIKE '%\_ord'
            OR dt.typname LIKE '%\_ord\_ore'
          )
          AND NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc p
            JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            JOIN pg_catalog.pg_language  l ON l.oid = p.prolang
            WHERE n.nspname IN ('eql_v3', 'eql_v3_internal')
              AND l.lanname = 'sql'
              AND p.provolatile = 'i'
              AND dt.oid = ANY(p.proargtypes::oid[])
          )
        ORDER BY dt.typname
        "#,
    )
    .fetch_all(&pool)
    .await?;

    assert!(
        unbound.is_empty(),
        "the following inline-critical-eligible domains have NO \
         inline-critical function bound — index engagement is broken \
         for them: {unbound:?}"
    );
    Ok(())
}

/// Encrypted-domain blockers must be `LANGUAGE plpgsql` and **never**
/// `STRICT`. A LANGUAGE sql blocker is inlinable (the planner can elide
/// it when the result is provably unused); a STRICT blocker returns NULL
/// on a NULL argument, silently bypassing the RAISE. Either footgun
/// re-enables an operator the storage variant exists to block.
///
/// This is a structural guard that does NOT depend on `eql_v3.lints()` —
/// a regression to the lint catalog itself cannot hide a regression to
/// the blocker surface from this test.
#[sqlx::test]
async fn encrypted_domain_blockers_are_plpgsql_and_non_strict(pool: PgPool) -> Result<()> {
    let offenders: Vec<(String, String, bool)> = sqlx::query_as(
        r#"
        SELECT p.oid::regprocedure::text AS signature,
               l.lanname,
               p.proisstrict
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_catalog.pg_language  l ON l.oid = p.prolang
        WHERE n.nspname IN ('eql_v3', 'eql_v3_internal')
          -- Match every blocker helper the codegen emits — `_bool` (comparison
          -- ops), `_jsonb` (`#>`, `||`, `-`), and `_text` (`#>>`, `->>`) — via
          -- the broad `encrypted_domain_unsupported` prefix, kept verbatim in
          -- sync with the `encrypted_domain_blockers` CTE in src/v3/lint/lints.sql
          -- so the structural guard cannot be narrower than the lint it backstops.
          -- The shared `encrypted_domain_unsupported_*(text, text)` helpers carry
          -- the marker too but take text args, so the jsonb-domain-arg EXISTS
          -- below excludes them.
          AND (p.prosrc LIKE '%encrypted_domain_unsupported%'
            OR p.prosrc LIKE '%is not supported for%')
          AND EXISTS (
            SELECT 1
            FROM pg_catalog.unnest(p.proargtypes::oid[]) AS arg(typ)
            JOIN pg_catalog.pg_type dt ON dt.oid = arg.typ
            JOIN pg_catalog.pg_namespace dn ON dn.oid = dt.typnamespace
            JOIN pg_catalog.pg_type bt ON bt.oid = dt.typbasetype
            WHERE dt.typtype = 'd'
              AND bt.typname = 'jsonb'
              AND (
                   dn.nspname IN ('eql_v3', 'eql_v3_internal')
              )
          )
          AND (l.lanname <> 'plpgsql' OR p.proisstrict)
        ORDER BY signature
        "#,
    )
    .fetch_all(&pool)
    .await?;

    assert!(
        offenders.is_empty(),
        "encrypted-domain blockers must be LANGUAGE plpgsql and non-STRICT. \
         Offenders (signature, language, isstrict): {offenders:#?}"
    );
    Ok(())
}

/// No encrypted-domain family domain may be derived from another family
/// domain — operators resolve against the ultimate base type, so a derived
/// domain inherits jsonb's operator surface and not the base domain's
/// blockers. All family domains must be defined directly over jsonb.
#[sqlx::test]
async fn no_encrypted_domain_is_derived_from_another_encrypted_domain(pool: PgPool) -> Result<()> {
    let offenders: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT format('%I.%I', dn.nspname, dt.typname) AS derived,
               format('%I.%I', bn.nspname, bt.typname) AS base
        FROM pg_catalog.pg_type dt
        JOIN pg_catalog.pg_namespace dn ON dn.oid = dt.typnamespace
        JOIN pg_catalog.pg_type bt ON bt.oid = dt.typbasetype
        JOIN pg_catalog.pg_namespace bn ON bn.oid = bt.typnamespace
        WHERE dt.typtype = 'd'
          AND (
               dn.nspname IN ('eql_v3', 'eql_v3_internal')
          )
          AND bt.typtype = 'd'
          AND (
               bn.nspname IN ('eql_v3', 'eql_v3_internal')
          )
        ORDER BY derived
        "#,
    )
    .fetch_all(&pool)
    .await?;

    assert!(
        offenders.is_empty(),
        "encrypted-domain family domains must be defined directly over jsonb, \
         not derived from another family domain. Offenders (derived, base): {offenders:#?}"
    );
    Ok(())
}

/// No operator class may be declared `FOR TYPE` on an encrypted-domain
/// family domain. Opclasses on domains bypass the operator-resolution that
/// storage blockers depend on. The recommended index pattern is a functional
/// index on the extractor (e.g. `eql_v3.eq_term(col)`).
#[sqlx::test]
async fn no_opclass_targets_encrypted_domain(pool: PgPool) -> Result<()> {
    let offenders: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT format('%I.%I', cn.nspname, oc.opcname) AS opclass,
               format('%I.%I', tn.nspname, t.typname)  AS for_type
        FROM pg_catalog.pg_opclass oc
        JOIN pg_catalog.pg_type t ON t.oid = oc.opcintype
        JOIN pg_catalog.pg_namespace tn ON tn.oid = t.typnamespace
        JOIN pg_catalog.pg_namespace cn ON cn.oid = oc.opcnamespace
        WHERE t.typtype = 'd'
          AND (
               tn.nspname IN ('eql_v3', 'eql_v3_internal')
          )
        ORDER BY opclass
        "#,
    )
    .fetch_all(&pool)
    .await?;

    assert!(
        offenders.is_empty(),
        "no operator class may target an encrypted-domain family domain — use a \
         functional index on the extractor instead. Offenders (opclass, for_type): {offenders:#?}"
    );
    Ok(())
}
