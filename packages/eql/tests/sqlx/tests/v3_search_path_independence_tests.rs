//! The `eql_v3` comparison wrappers give the same answer whatever the caller's
//! `search_path` is (CIP-5153).
//!
//! The wrappers (`eql_v3.lt`, `eql_v3.eq`, …) are unpinned `LANGUAGE sql`
//! functions — pinning a `search_path` would stop them inlining, and with it
//! functional-index matching — so PostgreSQL parses their bodies under the
//! CALLER's `search_path`. The `_ord_ore` wrappers compare
//! `eql_v3_internal.ore_block_256` values, a composite type whose comparison
//! operators are created in `public`. With `public` off the path (a
//! `SECURITY DEFINER` helper with `SET search_path = ''`, as Supabase
//! recommends, or a hardened role path) a bare `<` in the body resolved to
//! pg_catalog's built-in RECORD comparison instead: the ciphertext bytes were
//! ordered lexicographically, with no error. The generator now emits every
//! wrapper operator schema-qualified (`OPERATOR(public.<)` for ORE,
//! `OPERATOR(pg_catalog.<)` for the built-in-typed terms).
//!
//! Creds-free: the ORE terms are hand-built from deterministic hex. They are
//! not real ciphertexts, but `eql_v3_internal.compare_ore_block_256_terms` is a
//! deterministic function of the bytes, so it is the oracle; the pairs are
//! chosen from a generator where that oracle and byte order disagree, so a
//! wrapper falling back to byte comparison fails here.
//!
//! The ORE-carrying domains come from the catalog (`eql_domains`), so a new one
//! is covered by construction.

use anyhow::{ensure, Result};
use eql_domains::{scalar_families, Term};
use sqlx::{PgConnection, PgPool};

/// Comparison wrappers and the operator symbol each one backs.
const ORDERING: [(&str, &str); 4] = [("lt", "<"), ("lte", "<="), ("gt", ">"), ("gte", ">=")];
const EQUALITY: [(&str, &str); 2] = [("eq", "="), ("neq", "<>")];

/// An ORE-carrying domain: its storage domain and its query twin, both
/// schema-qualified, plus the wrappers the ORE term serves on it.
struct OreDomain {
    storage: String,
    query: String,
    wrappers: Vec<(&'static str, &'static str)>,
}

/// Every scalar domain whose ordering is served by the ORE term. Equality is
/// included only where ORE serves it too: a domain that also carries `hm`
/// routes `=` through the HMAC term (first supporting term wins).
fn ore_domains() -> Vec<OreDomain> {
    let mut out = Vec::new();
    for family in scalar_families() {
        for d in family.domains {
            if Term::term_for_operator(d.terms, "<") != Some(Term::Ore) {
                continue;
            }
            let mut wrappers = ORDERING.to_vec();
            if Term::term_for_operator(d.terms, "=") == Some(Term::Ore) {
                wrappers.extend(EQUALITY);
            }
            out.push(OreDomain {
                storage: format!("public.{}", family.domain_name(d)),
                query: format!("eql_v3.{}", d.query_name(family.name)),
                wrappers,
            });
        }
    }
    out
}

/// A storage payload carrying one ORE block term of `hex`. Every key any
/// ORE-carrying domain CHECK requires is present (`hm`/`bf` for the
/// multi-term text domains); only `ob` is ever compared.
fn storage_payload(hex: &str) -> String {
    format!(r#"{{"v":3,"i":{{}},"c":"x","hm":"00","bf":[1],"ob":["{hex}"]}}"#)
}

/// The query-twin payload: the same terms, without the ciphertext `c`.
fn query_payload(hex: &str) -> String {
    format!(r#"{{"v":3,"i":{{}},"hm":"00","bf":[1],"ob":["{hex}"]}}"#)
}

/// The ORE comparator's verdict on `(a, b)`, called fully qualified so the
/// answer does not depend on the connection's `search_path`.
async fn ore_compare(conn: &mut PgConnection, domain: &str, a: &str, b: &str) -> Result<i32> {
    let sql = format!(
        "SELECT eql_v3_internal.compare_ore_block_256_terms( \
            eql_v3.ord_term_ore($1::pg_catalog.jsonb::{domain}), \
            eql_v3.ord_term_ore($2::pg_catalog.jsonb::{domain}))"
    );
    Ok(sqlx::query_scalar(&sql)
        .bind(a)
        .bind(b)
        .fetch_one(&mut *conn)
        .await?)
}

/// What a correct wrapper returns for a comparator verdict `cmp`.
fn expected(symbol: &str, cmp: i32) -> bool {
    match symbol {
        "<" => cmp < 0,
        "<=" => cmp <= 0,
        ">" => cmp > 0,
        ">=" => cmp >= 0,
        "=" => cmp == 0,
        "<>" => cmp != 0,
        other => unreachable!("no expectation for {other}"),
    }
}

/// Pairs of single-block ORE terms on which the comparator and plain byte order
/// disagree in BOTH directions, so a byte-comparison fallback is wrong on at
/// least one of them for every ordering operator. The candidates are
/// well-formed single-block terms (49 * 1 + 16 = 65 bytes, 130 hex digits)
/// derived from md5, generated and judged in one round trip; `probe` is any
/// ORE-carrying storage domain (the comparator does not depend on which).
async fn discriminating_pairs(
    conn: &mut PgConnection,
    probe: &str,
) -> Result<Vec<(String, String)>> {
    let sql = format!(
        r#"WITH c AS (
             SELECT i,
                    substr(repeat(md5('a' || i), 5), 1, 130) AS a,
                    substr(repeat(md5('b' || i), 5), 1, 130) AS b
             FROM generate_series(0, 63) AS i
           ), v AS (
             SELECT i, a, b,
                    eql_v3_internal.compare_ore_block_256_terms(
                      eql_v3.ord_term_ore(jsonb_build_object('v', 3, 'i', '{{}}'::jsonb, 'c', 'x',
                        'hm', '00', 'bf', '[1]'::jsonb, 'ob', jsonb_build_array(a))::{probe}),
                      eql_v3.ord_term_ore(jsonb_build_object('v', 3, 'i', '{{}}'::jsonb, 'c', 'x',
                        'hm', '00', 'bf', '[1]'::jsonb, 'ob', jsonb_build_array(b))::{probe})
                    ) AS cmp
             FROM c
           )
           -- lowercase hex: text order under the C collation is byte order
           (SELECT a, b FROM v WHERE cmp = -1 AND a COLLATE "C" > b ORDER BY i LIMIT 1)
           UNION ALL
           (SELECT a, b FROM v WHERE cmp = 1 AND a COLLATE "C" < b ORDER BY i LIMIT 1)"#
    );
    let mut pairs: Vec<(String, String)> = sqlx::query_as(&sql).fetch_all(&mut *conn).await?;
    ensure!(
        pairs.len() == 2,
        "the generated pairs lack an ORE/byte-order disagreement in both directions"
    );
    // An identical pair pins `=` / `<=` / `>=` on equal terms too.
    let same = pairs[0].0.clone();
    pairs.push((same.clone(), same));
    Ok(pairs)
}

/// Every `_ord_ore` wrapper, called by name and through its operator, agrees
/// with the ORE comparator with `search_path = ''` — on the storage domain,
/// the query twin in both directions, and with a bare `jsonb` operand.
#[sqlx::test]
async fn ore_wrappers_use_the_ore_comparator_without_public_on_search_path(
    pool: PgPool,
) -> Result<()> {
    let domains = ore_domains();
    ensure!(!domains.is_empty(), "catalog has no ORE-carrying domain");
    let mut conn = pool.acquire().await?;
    let pairs = discriminating_pairs(&mut conn, &domains[0].storage).await?;

    // Oracle verdicts first, under the default path.
    let mut verdicts = Vec::new();
    for d in &domains {
        for (a, b) in &pairs {
            let cmp = ore_compare(
                &mut conn,
                &d.storage,
                &storage_payload(a),
                &storage_payload(b),
            )
            .await?;
            verdicts.push(cmp);
        }
    }

    sqlx::query("SET search_path = ''")
        .execute(&mut *conn)
        .await?;

    let mut checked = 0;
    let mut verdict = verdicts.into_iter();
    for d in &domains {
        let (s, q) = (&d.storage, &d.query);
        for (a, b) in &pairs {
            let cmp = verdict.next().expect("one verdict per domain and pair");
            let (sa, sb, qb) = (storage_payload(a), storage_payload(b), query_payload(b));
            let qa = query_payload(a);
            for (func, symbol) in &d.wrappers {
                let want = expected(symbol, cmp);
                // (storage, storage), (storage, jsonb), (storage, query) and
                // (query, storage), by wrapper name and by operator.
                let forms = [
                    (format!("eql_v3.{func}($1::pg_catalog.jsonb::{s}, $2::pg_catalog.jsonb::{s})"), &sa, &sb),
                    (format!("eql_v3.{func}($1::pg_catalog.jsonb::{s}, $2::pg_catalog.jsonb)"), &sa, &sb),
                    (format!("eql_v3.{func}($1::pg_catalog.jsonb::{s}, $2::pg_catalog.jsonb::{q})"), &sa, &qb),
                    (format!("eql_v3.{func}($1::pg_catalog.jsonb::{q}, $2::pg_catalog.jsonb::{s})"), &qa, &sb),
                    (format!("$1::pg_catalog.jsonb::{s} OPERATOR(public.{symbol}) $2::pg_catalog.jsonb::{s}"), &sa, &sb),
                    (format!("$1::pg_catalog.jsonb::{s} OPERATOR(public.{symbol}) $2::pg_catalog.jsonb::{q}"), &sa, &qb),
                ];
                for (expr, x, y) in forms {
                    let got: bool = sqlx::query_scalar(&format!("SELECT {expr}"))
                        .bind(x)
                        .bind(y)
                        .fetch_one(&mut *conn)
                        .await?;
                    ensure!(
                        got == want,
                        "{expr} returned {got}, ORE comparator says {want} (cmp = {cmp}) \
                         with search_path = '' — a byte-comparison fallback"
                    );
                    checked += 1;
                }
            }
        }
    }
    ensure!(checked > 0, "no comparisons were checked");
    Ok(())
}

/// The issue's trigger shape: a helper pinned to `SET search_path = ''` (the
/// Supabase-recommended hardening) calling an `_ord_ore` wrapper. A malformed
/// pair must reach the ORE comparator and raise, not be compared as records.
#[sqlx::test]
async fn ore_wrapper_raises_on_malformed_terms_inside_an_empty_search_path_function(
    pool: PgPool,
) -> Result<()> {
    sqlx::query(
        "CREATE FUNCTION public.probe_lt(a jsonb, b jsonb) RETURNS boolean \
         LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$ \
         BEGIN \
           RETURN eql_v3.lt(a::public.eql_v3_integer_ord_ore, b::public.eql_v3_integer_ord_ore); \
         END $$",
    )
    .execute(&pool)
    .await?;

    // Different-length terms: the ORE comparator rejects them; a record
    // comparison would silently answer.
    let err = sqlx::query_scalar::<_, bool>("SELECT public.probe_lt($1::jsonb, $2::jsonb)")
        .bind(storage_payload("aaaa"))
        .bind(storage_payload("bbbbbb"))
        .fetch_one(&pool)
        .await
        .expect_err("a malformed ORE pair must raise, not compare as records");
    ensure!(
        err.to_string()
            .contains("Ciphertexts are different lengths"),
        "unexpected error: {err}"
    );
    Ok(())
}

/// HMAC equality is unaffected by the path today (its operators are
/// pg_catalog's), and must stay so now that the wrapper names them qualified.
#[sqlx::test]
async fn hmac_wrappers_work_without_public_on_search_path(pool: PgPool) -> Result<()> {
    let mut conn = pool.acquire().await?;
    sqlx::query("SET search_path = ''")
        .execute(&mut *conn)
        .await?;
    let eq = |hm: &str| format!(r#"{{"v":3,"i":{{}},"c":"x","hm":"{hm}"}}"#);
    for (a, b, want) in [("aa", "aa", true), ("aa", "bb", false)] {
        let got: bool = sqlx::query_scalar(
            "SELECT eql_v3.eq($1::pg_catalog.jsonb::public.eql_v3_integer_eq, \
                              $2::pg_catalog.jsonb::public.eql_v3_integer_eq)",
        )
        .bind(eq(a))
        .bind(eq(b))
        .fetch_one(&mut *conn)
        .await?;
        ensure!(got == want, "eql_v3.eq({a}, {b}) = {got}, want {want}");
    }
    Ok(())
}
