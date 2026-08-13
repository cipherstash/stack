//! Self-checks for the type-generic matrix substrate
//! (`tests/sqlx/src/scalar_domains.rs`). Each test pins one piece of the
//! `ScalarType` / `Variant` / assertion-helper API that the matrix
//! depends on.

use anyhow::Result;
use eql_tests::{sql_string_literal, ScalarDomainSpec, ScalarType, Variant, PLACEHOLDER_PAYLOAD};
use sqlx::PgPool;

#[test]
fn variant_derives_consistent_sql_domain_and_capabilities() {
    // Capabilities are catalog-derived for the scalar's token (`integer`). integer's
    // ordered domains are `[Ore]`-only — ORE is lossless for integers, so `=`
    // routes through `ord_term_ore`, unlike text where `=` routes through `eq_term`.
    let storage = ScalarDomainSpec::new::<i32>(Variant::Storage);
    assert_eq!(storage.sql_domain, "public.eql_v3_integer");
    assert!(!storage.supports_eq());
    assert!(!storage.supports_ord());
    assert_eq!(storage.primary_extractor(), None);
    assert_eq!(
        Variant::Storage.payload_required_keys("integer"),
        vec!["v", "i", "c"]
    );

    let eq = ScalarDomainSpec::new::<i32>(Variant::Eq);
    assert_eq!(eq.sql_domain, "public.eql_v3_integer_eq");
    assert!(eq.supports_eq());
    assert!(!eq.supports_ord());
    assert_eq!(eq.primary_extractor().as_deref(), Some("eql_v3.eq_term"));
    assert_eq!(eq.extractor_for_op("=").as_deref(), Some("eql_v3.eq_term"));
    assert_eq!(
        Variant::Eq.payload_required_keys("integer"),
        vec!["v", "i", "c", "hm"]
    );

    let ord = ScalarDomainSpec::new::<i32>(Variant::Ord);
    assert_eq!(ord.sql_domain, "public.eql_v3_integer_ord");
    assert!(ord.supports_ord());
    assert_eq!(ord.primary_extractor().as_deref(), Some("eql_v3.ord_term"));
    // integer_ord is `[Ope]`-only: equality routes through OPE, which is
    // deterministic and therefore lossless for ints.
    assert_eq!(
        ord.extractor_for_op("=").as_deref(),
        Some("eql_v3.ord_term")
    );
    assert_eq!(
        ord.extractor_for_op("<").as_deref(),
        Some("eql_v3.ord_term")
    );
    assert_eq!(
        Variant::Ord.payload_required_keys("integer"),
        vec!["v", "i", "c", "op"]
    );

    // `_ord_ore` keeps the block-ORE term and its extractor.
    let ord_ore = ScalarDomainSpec::new::<i32>(Variant::OrdOre);
    assert_eq!(ord_ore.sql_domain, "public.eql_v3_integer_ord_ore");
    assert!(ord_ore.supports_ord());
    assert_eq!(
        ord_ore.primary_extractor().as_deref(),
        Some("eql_v3.ord_term_ore")
    );
    assert_eq!(
        ord_ore.extractor_for_op("<").as_deref(),
        Some("eql_v3.ord_term_ore")
    );
    assert_eq!(
        Variant::OrdOre.payload_required_keys("integer"),
        vec!["v", "i", "c", "ob"]
    );
}

#[test]
fn expected_forward_default_is_numeric_ground_truth() {
    // Pinned against the full 17-row fixture (extremes + zero + the
    // original 14). The output is sorted-ascending by `expected_forward`,
    // so a regression in the default impl's filter or sort shows up
    // here.
    assert_eq!(<i32 as ScalarType>::expected_forward("=", 10), vec![10]);
    assert_eq!(
        <i32 as ScalarType>::expected_forward("<", 10),
        vec![i32::MIN, -100, -1, 0, 1, 2, 5]
    );
    assert_eq!(
        <i32 as ScalarType>::expected_forward("<=", 10),
        vec![i32::MIN, -100, -1, 0, 1, 2, 5, 10]
    );
    assert_eq!(
        <i32 as ScalarType>::expected_forward(">", 10),
        vec![17, 25, 42, 50, 100, 250, 1000, 9999, i32::MAX]
    );
    assert_eq!(
        <i32 as ScalarType>::expected_forward(">=", 10),
        vec![10, 17, 25, 42, 50, 100, 250, 1000, 9999, i32::MAX]
    );
    assert_eq!(
        <i32 as ScalarType>::expected_forward("<>", 42),
        vec![
            i32::MIN,
            -100,
            -1,
            0,
            1,
            2,
            5,
            10,
            17,
            25,
            50,
            100,
            250,
            1000,
            9999,
            i32::MAX
        ]
    );
}

#[test]
fn sql_string_literal_escapes_single_quotes() {
    assert_eq!(sql_string_literal("abc'def"), "'abc''def'");
}

#[sqlx::test]
async fn placeholder_payload_casts_to_every_declared_domain(pool: PgPool) -> Result<()> {
    // The whole point of PLACEHOLDER_PAYLOAD: one sentinel that casts
    // successfully to EVERY declared domain of EVERY live scalar type. If a
    // variant CHECK tightens for any type, this fails and PLACEHOLDER_PAYLOAD
    // needs updating. Catalog-driven so a new scalar type is covered the
    // moment its CATALOG row lands — no per-type edit here.
    //
    // (Was i32-only with a TODO to generalize; the TODO is now done.)
    for spec in eql_domains::scalar_families() {
        for domain in spec.domains {
            let sql_domain = format!("public.{}", spec.domain_name(domain));
            let sql = format!("SELECT $1::jsonb::{sql_domain}");
            sqlx::query(&sql)
                .bind(PLACEHOLDER_PAYLOAD)
                .fetch_one(&pool)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("PLACEHOLDER_PAYLOAD must cast to {sql_domain}: {e}")
                })?;
        }
    }
    Ok(())
}

#[sqlx::test]
async fn no_cross_variant_operator_is_declared(pool: PgPool) -> Result<()> {
    // The SCALAR family deliberately does NOT define ANY operator that mixes
    // two different capability variants — e.g. `public.eql_v3_integer_eq = public.eql_v3_integer_ord`
    // would resolve against jsonb (the ultimate base type) and silently
    // bypass the per-variant blockers. The query below has no `oprname`
    // filter, so it catches a cross-variant operator of any kind, not just
    // `=`. If someone accidentally adds such an operator, this test fails.
    //
    // The jsonb DOCUMENT surface is excluded: it intentionally defines
    // cross-type containment operators (`json @> query_json`,
    // `json @> jsonb_entry` and their `<@` commutators) — the documented
    // document-containment API, not scalar capability variants that must
    // resolve to a blocker. So `json` / `jsonb_entry` / `query_json` are
    // out of scope for this scalar-variant guard.
    //
    // The check is structural (`pg_operator`) rather than dynamic
    // ("invoke and see it raise") so a future PG version with stricter
    // operator resolution doesn't mask the regression.
    // Derive the excluded (non-scalar) domain names from the catalog rather than
    // hardcoding `'json', 'jsonb_entry', 'query_json'` — a future rename or a
    // second non-scalar family stays covered automatically (the names come from
    // the same `DomainFamily::domain_name` the SQL surface is generated through).
    let excluded: Vec<String> = eql_domains::CATALOG
        .iter()
        .filter(|f| !f.is_scalar())
        .flat_map(|f| f.domains.iter().map(move |d| f.domain_name(d)))
        .collect();
    assert!(
        !excluded.is_empty(),
        "expected at least one non-scalar (SteVec) family to exclude"
    );
    // Trusted catalog identifiers (not user input) → safe to inline as literals.
    let excluded_sql = excluded
        .iter()
        .map(|n| format!("'{n}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let cross_variant: Vec<String> = sqlx::query_scalar(&format!(
        r#"
        SELECT format('%s(%s, %s)',
                      o.oprname, lt.typname, rt.typname)
        FROM pg_catalog.pg_operator o
        JOIN pg_catalog.pg_type lt ON lt.oid = o.oprleft
        JOIN pg_catalog.pg_namespace ln ON ln.oid = lt.typnamespace
        JOIN pg_catalog.pg_type rt ON rt.oid = o.oprright
        JOIN pg_catalog.pg_namespace rn ON rn.oid = rt.typnamespace
        WHERE ln.nspname = 'eql_v3'
          AND rn.nspname = 'eql_v3'
          AND lt.typname <> rt.typname
          AND lt.typname NOT IN ({excluded_sql})
          AND rt.typname NOT IN ({excluded_sql})
        ORDER BY 1
        "#,
    ))
    .fetch_all(&pool)
    .await?;

    assert!(
        cross_variant.is_empty(),
        "no operator should mix two different eql_v3 domain types, but found: {cross_variant:#?}"
    );
    Ok(())
}
