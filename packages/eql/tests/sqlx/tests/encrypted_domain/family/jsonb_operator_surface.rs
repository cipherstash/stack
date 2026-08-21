//! Structural guard for the blocked native-jsonb operator enumeration.
//!
//! The storage-only domains (`public.eql_v3_integer`, future scalars) promise that
//! *every* native jsonb operator is blocked, so an encrypted column can never
//! fall through to plaintext-jsonb semantics. That promise rests on the
//! enumerated operator surface in `crates/eql-codegen/src/operator_surface.rs`
//! (the `OPERATORS` const), mirrored locally below as `KNOWN_JSONB_OPERATORS`.
//!
//! Those lists are an *enumeration*, not a structural guarantee: a future PG
//! version could add a jsonb operator that nobody adds here, and it would
//! silently route to native jsonb behaviour. This test closes that gap by
//! asking the live catalog which *native* operators touch `jsonb` and failing
//! if any symbol is absent from the known union. The `eql_v3` blockers that
//! take a jsonb operand (e.g. `||`, `#>`) reuse native operator symbols that
//! are already in the known union, so they need no special handling.
//!
//! Source of truth: `crates/eql-codegen/src/operator_surface.rs` (the
//! `OPERATORS` const, pinned at 20 entries by its own unit tests). The set
//! below is a hardcoded mirror and must be kept in sync with that module. If
//! you add an operator there, add it here.

use anyhow::Result;
use sqlx::PgPool;

/// Mirror of the enumerated operator surface in
/// `crates/eql-codegen/src/operator_surface.rs` (`OPERATORS`). Keep in sync
/// with that module.
const KNOWN_JSONB_OPERATORS: &[&str] = &[
    // symmetric (supported wrappers)
    "=", "<>", "<", "<=", ">", ">=", "@>", "<@", //
    // path
    "->", "->>", //
    // blocker-only native jsonb fallbacks
    "?", "?|", "?&", "@?", "@@", "#>", "#>>", "-", "#-", "||",
];

#[sqlx::test]
async fn every_native_jsonb_operator_is_known_to_the_generator(pool: PgPool) -> Result<()> {
    // Distinct operator symbols whose left OR right argument is `jsonb` — the
    // native surface a value typed as a jsonb-backed domain can reach via
    // operator resolution against the ultimate base type.
    let native: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT DISTINCT o.oprname
        FROM pg_catalog.pg_operator o
        WHERE (o.oprleft = 'jsonb'::regtype OR o.oprright = 'jsonb'::regtype)
        ORDER BY 1
        "#,
    )
    .fetch_all(&pool)
    .await?;

    assert!(
        !native.is_empty(),
        "expected pg_operator to expose jsonb operators; query returned none"
    );

    let missing: Vec<&String> = native
        .iter()
        .filter(|sym| !KNOWN_JSONB_OPERATORS.contains(&sym.as_str()))
        .collect();

    assert!(
        missing.is_empty(),
        "PostgreSQL exposes jsonb operator(s) not enumerated in \
         crates/eql-codegen/src/operator_surface.rs (OPERATORS): {missing:#?}. \
         A storage-only encrypted domain would route these to native \
         plaintext-jsonb semantics instead of an EQL blocker. Add each symbol \
         to OPERATORS in operator_surface.rs (and to the mirror in this test) \
         and regenerate the SQL surface."
    );

    Ok(())
}
