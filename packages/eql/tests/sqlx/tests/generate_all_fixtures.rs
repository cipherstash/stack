//! Catalog-driven "generate every encrypted fixture" entry point.
//!
//! Replaces the Python-era `fixture:generate <name>` per-type scripts and the
//! `fixture:generate:all` TOML-glob loop (which spawned a separate `cargo test`
//! per type). This runs ALL scalar fixture generators in ONE process, iterating
//! `eql_domains::CATALOG` for the authoritative token set.
//!
//! The encrypted-fixture logic itself is unchanged — each type's
//! `fixtures::eql_v3_<T>::spec().run()` still produces
//! `tests/sqlx/fixtures/eql_v3_<T>.sql` exactly as before.
//!
//! Gated behind `fixture-gen` (needs a live Postgres + CS_* creds). Run via:
//!   mise run fixture:generate:all
#![cfg(feature = "fixture-gen")]

// `generate_for_token(token: &str) -> anyhow::Result<()>` is generated from the
// single harness list in `tests/sqlx/src/scalar_types.rs`: one match arm per
// token (`"integer" => fixtures::eql_v3_integer::spec().run().await`) plus a loud
// catch-all. A catalog token absent from that list hits the catch-all and fails
// the generator loudly, so a new scalar type cannot silently skip generation.
eql_tests::scalar_types!(fixture_dispatch);

#[tokio::test]
#[ignore = "generator — run via `mise run fixture:generate:all`"]
async fn generate_all() -> anyhow::Result<()> {
    let mut generated = 0usize;
    for spec in eql_domains::scalar_families() {
        eprintln!("Generating fixture eql_v3_{}...", spec.name);
        generate_for_token(spec.name).await?;
        generated += 1;
    }
    assert!(generated > 0, "CATALOG is empty — nothing to generate");
    eprintln!("Regenerated {generated} scalar fixture(s).");

    // The v3 jsonb (SteVec document) fixture is not a CATALOG scalar — it is a
    // hand-written `FixtureSpec<serde_json::Value>` that rides the SAME
    // generation pipeline. Generate it in the same process so one
    // `fixture:generate:all` run (and the prep flow) refreshes everything.
    eprintln!("Generating fixture v3_ste_vec (jsonb SteVec document)...");
    eql_tests::fixtures::v3_ste_vec::generate().await?;
    eprintln!("Regenerated v3_ste_vec.");

    // The storage-only / encryption-only json fixture — a
    // hand-written `FixtureSpec<serde_json::Value>` with NO index, so each
    // document encrypts to a plain `{v, i, c}` envelope for the storage-only
    // `public.eql_v3_json` domain. Same pipeline, no SteVec index.
    eprintln!("Generating fixture v3_json_storage (storage-only json)...");
    eql_tests::fixtures::v3_json_storage::generate().await?;
    eprintln!("Regenerated v3_json_storage.");

    // The scalar-shaped SteVec document fixture — one `{"field": <integer>}`
    // document per `eql_domains::INTEGER_VALUES`, with an integer plaintext oracle —
    // drives the jsonb-entry behaviour matrix. Same pipeline, split payload
    // (jsonb-document encryption input, integer oracle column).
    eprintln!("Generating fixture v3_doc_integer (scalar-shaped SteVec document)...");
    eql_tests::fixtures::v3_doc_integer::generate().await?;
    eprintln!("Regenerated v3_doc_integer.");

    // The numeric scale-equivalence collision fixture (`1`, `1.0`, `2`). Not a
    // CATALOG scalar — the distinctness guard forbids `1`/`1.0` coexisting in
    // `eql_v3_numeric` — so it rides the same pipeline as a hand-written
    // `FixtureSpec<Decimal>`. Gives the always-on `1 == 1.0` ORE collision test
    // its generated fixture.
    eprintln!("Generating fixture v3_numeric_collision (1 == 1.0 ORE collision)...");
    eql_tests::fixtures::v3_numeric_collision::generate().await?;
    eprintln!("Regenerated v3_numeric_collision.");

    // The empty-string ordered-text fixture (`""`, `"frank"`, `"zebra"`). Not a
    // CATALOG scalar — `eql-domains::TEXT_FIXTURES` excludes `""` (issue #262) —
    // so it rides the same pipeline as a hand-written `FixtureSpec<String>`.
    // Gives the "empty sorts first" contract (ORDER BY / min / max) a generated
    // real-ciphertext home.
    eprintln!("Generating fixture v3_text_empty (empty-string ordered text)...");
    eql_tests::fixtures::v3_text_empty::generate().await?;
    eprintln!("Regenerated v3_text_empty.");

    // The empty-bloom fuzzy-match fixture (`"pq"`, `"aardvark"`). Not a CATALOG
    // scalar — `eql-domains::TEXT_FIXTURES` carries no sub-trigram string (min 3
    // chars), so no catalog value yields an empty bloom (`bf: []`) — so it rides
    // the same pipeline as a hand-written `FixtureSpec<String>`. Gives the
    // empty-needle guard in `eql_v3.matches` a generated real-ciphertext
    // home.
    eprintln!("Generating fixture v3_text_empty_bloom (empty bloom filter)...");
    eql_tests::fixtures::v3_text_empty_bloom::generate().await?;
    eprintln!("Regenerated v3_text_empty_bloom.");

    // Per-type "doubles" fixtures (each plaintext encrypted twice) for the
    // credential-free cross-ciphertext-equality test. Non-catalog (the catalog
    // fixture is the curated set exactly), generated through the same pipeline.
    for token in eql_tests::fixtures::eql_doubles::DOUBLES_TOKENS {
        eprintln!("Generating fixture eql_v3_{token}_doubles...");
        eql_tests::fixtures::eql_doubles::generate(token).await?;
    }
    eprintln!(
        "Regenerated {} doubles fixture(s).",
        eql_tests::fixtures::eql_doubles::DOUBLES_TOKENS.len()
    );
    Ok(())
}
