//! Real-ciphertext coverage for the storage-only / encryption-only
//! `public.eql_v3_json` domain — the json analogue of boolean's
//! `caps=[storage]` matrix arm.
//!
//! `json` cannot ride the `scalar_matrix!` machinery (its family is non-scalar
//! because of the SteVec domains), so this hand-written suite mirrors the
//! boolean storage matrix's coverage set over a REAL fixture:
//! `fixtures.v3_json_storage` (column `payload public.eql_v3_json`) is GENERATED
//! by encrypting JSON documents with NO index (`mise run fixture:generate:all`),
//! so every payload is a real `{v, i, c}` envelope the domain CHECK validated at
//! INSERT — never a hand-written literal.
//!
//! Coverage, mirroring the boolean storage arm (`tests/sqlx/src/matrix.rs`):
//!   - `storage_fixture_shape`      ~ `matrix_boolean_storage_fixture_shape`
//!   - `storage_comparison_blockers`~ `matrix_boolean_storage_<cmp>_blocker`
//!   - `storage_path_op_blockers`   ~ `matrix_boolean_storage_path_op_blockers`
//!   - `storage_native_jsonb_blockers` ~ `matrix_*_native_jsonb_blockers`
//!   - `storage_native_absent_ops`  ~ `matrix_boolean_storage_native_absent_ops`
//!   - `storage_aggregate_typecheck`~ `matrix_boolean_storage_aggregate_typecheck_{min,max}`
//!   - `storage_row_count`          ~ `matrix_boolean_storage_count`
//!
//! Plus two json-specific tests with no scalar analogue: the `Json` binding
//! parse, and the storage/search domain mutual-exclusion.
//!
//! `storage_aggregate_typecheck` asserts on the SQLSTATE, not the message text —
//! exactly as the boolean driver does — so the "function is not unique"
//! ambiguity (42725) it hits is a stable, meaningful proof that the storage
//! domain owns no aggregate, not a brittle string match. See that test's doc.
//!
//! ## Operator resolution depends on literal typing (load-bearing)
//!
//! The firewall blockers are exact-match operators `(<op>, public.eql_v3_json,
//! <rhs type>)`. PostgreSQL prefers an exact-match operator over walking the
//! domain up to its `jsonb` base type — but ONLY when the RHS type is known.
//! With an *unknown-type* literal (`payload -> 'c'`, no `::text`), the base-type
//! `jsonb -> text` wins and the call falls through to native jsonb. With an
//! explicitly-typed operand (`payload -> 'c'::text`) the domain blocker engages
//! and raises. `storage_path_op_blockers` pins the blocked (explicit) form;
//! `storage_path_operators_unknown_literal_fall_through` pins the fall-through
//! (unknown-literal) form and documents that the two differ only by literal
//! typing. Both are real behaviours of the current generated surface.

use eql_bindings::v3::json::Json;
use sqlx::PgPool;

/// Number of fixture rows — mirrors `ROW_COUNT` in
/// `tests/sqlx/src/fixtures/v3_json_storage.rs` (not importable from a test
/// binary, so pinned here; `storage_row_count` fails loudly if they drift).
const ROW_COUNT: i64 = 3;

/// Assert `sql` raises the EQL "operator ... is not supported" blocker.
async fn assert_blocks(pool: &PgPool, sql: &str) -> anyhow::Result<()> {
    match sqlx::query(sql).fetch_optional(pool).await {
        Ok(_) => anyhow::bail!("expected the firewall blocker, but `{sql}` succeeded"),
        Err(e) => {
            let s = e.to_string();
            anyhow::ensure!(
                s.contains("is not supported"),
                "expected an 'is not supported' blocker for `{sql}`, got: {s}"
            );
            Ok(())
        }
    }
}

/// Assert `sql` fails with PostgreSQL's "operator does not exist" — the operator
/// is neither declared on the domain nor resolvable via the base type.
async fn assert_no_operator(pool: &PgPool, sql: &str) -> anyhow::Result<()> {
    match sqlx::query(sql).fetch_optional(pool).await {
        Ok(_) => anyhow::bail!("expected 'operator does not exist', but `{sql}` succeeded"),
        Err(e) => {
            let s = e.to_string();
            anyhow::ensure!(
                s.contains("does not exist"),
                "expected 'operator does not exist' for `{sql}`, got: {s}"
            );
            Ok(())
        }
    }
}

/// A real storage-only row is a `{v, i, c}` ciphertext envelope with NO SteVec
/// structure (`sv`/`k`) and NO index-term keys (`hm`/`ob`/`bf`/`op`), and the
/// real wire shape parses into the generated strict `Json` binding.
///
/// Mirrors `matrix_boolean_storage_fixture_shape` (structural payload check),
/// plus the json-specific binding-parse that has no scalar analogue.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_json_storage")))]
async fn storage_fixture_shape(pool: PgPool) -> anyhow::Result<()> {
    let payload: serde_json::Value = sqlx::query_scalar(
        "SELECT payload::jsonb FROM fixtures.v3_json_storage ORDER BY id LIMIT 1",
    )
    .fetch_one(&pool)
    .await?;

    let obj = payload.as_object().expect("payload is an object");
    assert_eq!(
        obj.get("v"),
        Some(&serde_json::json!(3)),
        "envelope version"
    );
    assert!(
        obj.contains_key("i"),
        "storage payload carries index metadata"
    );
    assert!(
        obj.contains_key("c"),
        "storage payload carries a ciphertext"
    );
    // Storage-only: no SteVec array / form discriminator, and — crucially — no
    // index-term keys, because nothing is searchable.
    for absent in ["sv", "k", "hm", "ob", "bf", "op"] {
        assert!(
            !obj.contains_key(absent),
            "storage payload must not carry `{absent}` (found in {obj:?})"
        );
    }

    // The real wire shape parses into the generated strict `Json` binding
    // (which rejects unknown keys / a wrong envelope version).
    let _typed: Json = serde_json::from_value(payload)?;
    Ok(())
}

/// Every comparison and containment operator raises the firewall on a REAL
/// fixture row — a storage-only value can never fall through to plaintext-jsonb
/// equality/containment. Sweeps the `(domain, jsonb)` and `(jsonb, domain)`
/// overloads. Mirrors `matrix_boolean_storage_<cmp>_blocker`.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_json_storage")))]
async fn storage_comparison_blockers(pool: PgPool) -> anyhow::Result<()> {
    const FROM: &str = "FROM fixtures.v3_json_storage LIMIT 1";
    for op in ["=", "<>", "<", "<=", ">", ">=", "@>", "<@"] {
        // (domain, jsonb) and (jsonb, domain) — both overloads must engage.
        assert_blocks(&pool, &format!("SELECT payload {op} '{{}}'::jsonb {FROM}")).await?;
        assert_blocks(&pool, &format!("SELECT '{{}}'::jsonb {op} payload {FROM}")).await?;
    }
    Ok(())
}

/// The JSON path/subscript operators `->` / `->>` raise the firewall on a real
/// row when the operand is explicitly typed (`'field'::text`, `0::integer`), and
/// in the reversed `(jsonb, domain)` shape. Mirrors
/// `matrix_boolean_storage_path_op_blockers`.
///
/// NB: an *unknown*-type literal RHS (`payload -> 'field'`) resolves to native
/// jsonb instead — characterised separately in
/// `storage_path_operators_unknown_literal_fall_through`.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_json_storage")))]
async fn storage_path_op_blockers(pool: PgPool) -> anyhow::Result<()> {
    const FROM: &str = "FROM fixtures.v3_json_storage LIMIT 1";
    for op in ["->", "->>"] {
        assert_blocks(&pool, &format!("SELECT payload {op} 'field'::text {FROM}")).await?;
        assert_blocks(&pool, &format!("SELECT payload {op} 0::integer {FROM}")).await?;
        assert_blocks(&pool, &format!("SELECT '{{}}'::jsonb {op} payload {FROM}")).await?;
    }
    Ok(())
}

/// The residual native-jsonb operators the codegen firewall blocks on the
/// storage domain — existence (`? ?| ?&`), path-array (`#> #>>`), jsonpath
/// (`@? @@`), delete (`- #-`), and concat (`||`) — each raise on a real row with
/// explicitly-typed operands. Mirrors the `native_jsonb_blockers` matrix arm
/// (`NATIVE_JSONB_BLOCKER_ARM_SYMBOLS`); `#>` / `||` are the subset the plan
/// called out explicitly.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_json_storage")))]
async fn storage_native_jsonb_blockers(pool: PgPool) -> anyhow::Result<()> {
    const FROM: &str = "FROM fixtures.v3_json_storage LIMIT 1";
    let single = [
        "payload ? 'c'::text",
        "payload ?| ARRAY['c']",
        "payload ?& ARRAY['c']",
        "payload #> ARRAY['i']",
        "payload #>> ARRAY['i', 'c']",
        "payload @? '$.c'::jsonpath",
        "payload @@ '$.c == \"x\"'::jsonpath",
        "payload - 'c'::text",
        "payload - 0",
        "payload - ARRAY['c']",
        "payload #- ARRAY['i']",
    ];
    for expr in single {
        assert_blocks(&pool, &format!("SELECT {expr} {FROM}")).await?;
    }
    // `||` overloads: (domain, jsonb), (jsonb, domain), (domain, domain).
    assert_blocks(&pool, &format!("SELECT payload || '{{}}'::jsonb {FROM}")).await?;
    assert_blocks(&pool, &format!("SELECT '{{}}'::jsonb || payload {FROM}")).await?;
    assert_blocks(
        &pool,
        "SELECT a.payload || b.payload \
         FROM fixtures.v3_json_storage a, fixtures.v3_json_storage b LIMIT 1",
    )
    .await?;
    Ok(())
}

/// `~~` / `~~*` (LIKE / ILIKE) are not declared on the storage domain and have
/// no jsonb base-type form, so resolution fails with "operator does not exist"
/// rather than the EQL blocker. Mirrors `matrix_boolean_storage_native_absent_ops`.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_json_storage")))]
async fn storage_native_absent_ops(pool: PgPool) -> anyhow::Result<()> {
    const FROM: &str = "FROM fixtures.v3_json_storage LIMIT 1";
    for op in ["~~", "~~*"] {
        assert_no_operator(&pool, &format!("SELECT payload {op} payload {FROM}")).await?;
    }
    Ok(())
}

/// KNOWN, DELIBERATE resolution quirk (characterisation — pins current
/// behaviour). With an UNKNOWN-type literal RHS, `->` / `->>` / `?` resolve to
/// the native `jsonb` base-type operator instead of the domain blocker and
/// return a plaintext-SAFE result: `-> 'c'` / `->> 'c'` echo the already-opaque
/// ciphertext string, `?` tests envelope-key presence — none leaks plaintext.
/// The blocked, explicitly-typed forms are covered by `storage_path_op_blockers`;
/// the ONLY difference is whether the RHS literal carries a type annotation.
///
/// This affects every jsonb-backed storage domain (`eql_v3_integer`,
/// `eql_v3_boolean`, …), not just json. The test exists so that if a future
/// PostgreSQL version changes operator resolution, the change surfaces here.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_json_storage")))]
async fn storage_path_operators_unknown_literal_fall_through(pool: PgPool) -> anyhow::Result<()> {
    // `-> 'c'` (unknown literal) returns the ciphertext string as jsonb; an
    // absent key returns SQL NULL. Neither raises.
    let c_val: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT payload -> 'c' FROM fixtures.v3_json_storage ORDER BY id LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        anyhow::anyhow!("`payload -> 'c'` unexpectedly raised (resolution changed?): {e}")
    })?;
    anyhow::ensure!(
        matches!(c_val, Some(serde_json::Value::String(_))),
        "`payload -> 'c'` should echo the ciphertext string, got {c_val:?}"
    );

    let missing: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT payload -> 'missing' FROM fixtures.v3_json_storage ORDER BY id LIMIT 1",
    )
    .fetch_one(&pool)
    .await?;
    anyhow::ensure!(
        missing.is_none(),
        "`payload -> 'missing'` should be NULL, got {missing:?}"
    );

    // `?` (unknown literal) tests envelope-key presence and returns native bool.
    let has_c: bool = sqlx::query_scalar(
        "SELECT payload ? 'c' FROM fixtures.v3_json_storage ORDER BY id LIMIT 1",
    )
    .fetch_one(&pool)
    .await?;
    anyhow::ensure!(
        has_c,
        "`payload ? 'c'` should be true (envelope has a `c` key)"
    );

    let has_absent: bool = sqlx::query_scalar(
        "SELECT payload ? 'absent' FROM fixtures.v3_json_storage ORDER BY id LIMIT 1",
    )
    .fetch_one(&pool)
    .await?;
    anyhow::ensure!(!has_absent, "`payload ? 'absent'` should be false");
    Ok(())
}

/// The real rows loaded through the domain CHECK at INSERT — proves the fixture
/// count and that every generated `{v,i,c}` envelope passed the CHECK. Mirrors
/// `matrix_boolean_storage_count`.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_json_storage")))]
async fn storage_row_count(pool: PgPool) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM fixtures.v3_json_storage")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, ROW_COUNT, "fixture row count drifted from ROW_COUNT");
    Ok(())
}

/// `eql_v3.min` / `max` are NOT available on the storage domain — it carries no
/// ORE term, so no aggregate is defined for it. Mirrors
/// `matrix_boolean_storage_aggregate_typecheck_{min,max}`: the call must FAIL,
/// and asserting on the SQLSTATE (not the message text) makes that stable.
///
/// Two error codes are both acceptable, and mean the same thing — the domain
/// owns no MIN/MAX of its own:
///   - `42883` undefined_function — no overload resolves at all.
///   - `42725` ambiguous_function — the jsonb-backed value coerces equally to
///     the many ordered-domain overloads (`eql_v3.min(eql_v3_integer_ord)`,
///     `eql_v3.min(eql_v3_json_entry)`, …), none specific to the storage domain,
///     so PostgreSQL picks none ("function is not unique"). This is the code
///     `public.eql_v3_json` actually returns.
/// If the call instead resolved, `expect_err` fails loudly — the guarantee is
/// that a storage-only value can never be aggregated, whatever the mechanism.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_json_storage")))]
async fn storage_aggregate_typecheck(pool: PgPool) -> anyhow::Result<()> {
    for agg in ["min", "max"] {
        let sql = format!("SELECT eql_v3.{agg}(payload) FROM fixtures.v3_json_storage");
        let err = sqlx::query_scalar::<_, serde_json::Value>(&sql)
            .fetch_one(&pool)
            .await
            .expect_err(&format!(
                "eql_v3.{agg} must not resolve on the storage-only domain"
            ));
        let code = err.as_database_error().and_then(|e| e.code());
        anyhow::ensure!(
            matches!(code.as_deref(), Some("42883") | Some("42725")),
            "expected SQLSTATE 42883 (undefined_function) or 42725 \
             (ambiguous_function) for eql_v3.{agg}(eql_v3_json), got {code:?}: {err}"
        );
    }
    Ok(())
}

/// A real storage payload (`{v,i,c}`) is accepted by `public.eql_v3_json` but
/// REJECTED by the searchable document domain `public.eql_v3_json_search`
/// (which requires an `sv` array) — the structural distinction between the two
/// json domains, over real crypto.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_json_storage")))]
async fn storage_and_search_domain_checks_are_mutually_exclusive(
    pool: PgPool,
) -> anyhow::Result<()> {
    let storage: serde_json::Value = sqlx::query_scalar(
        "SELECT payload::jsonb FROM fixtures.v3_json_storage ORDER BY id LIMIT 1",
    )
    .fetch_one(&pool)
    .await?;

    // Accepted by the storage domain (round-trips through its CHECK).
    let ok: bool = sqlx::query_scalar("SELECT ($1::jsonb::public.eql_v3_json) IS NOT NULL")
        .bind(&storage)
        .fetch_one(&pool)
        .await?;
    assert!(ok, "storage payload must cast to public.eql_v3_json");

    // Rejected by the searchable document domain — no `sv` array.
    let rejected =
        sqlx::query_scalar::<_, bool>("SELECT ($1::jsonb::public.eql_v3_json_search) IS NOT NULL")
            .bind(&storage)
            .fetch_one(&pool)
            .await;
    assert!(
        rejected.is_err(),
        "a storage {{v,i,c}} payload must NOT cast to the searchable document domain"
    );
    Ok(())
}
