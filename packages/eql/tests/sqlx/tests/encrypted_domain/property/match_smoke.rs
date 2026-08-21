//! fixture-suite bloom-filter **match** smoke for the text `_match`
//! domain.
//!
//! Unlike the eq/ord oracles, bloom matching is not a random property: `@@`
//! (`eql_v3.matches`) admits false positives and the plaintext oracle is
//! *substring*, not equality. So this is an example-based smoke over three curated fixtures with
//! known n-gram relationships — `"aardvark"` ⊇ `"aard"`, `"zzzz"` disjoint from
//! both — pinned by the `MatchScalar` trait and the
//! `text_match_pivots_are_in_fixture_values` guard.
//!
//! It reads already-encrypted fixture payloads (no `encrypt_store`, no fresh
//! ZeroKMS), so it lives in the `fixture` suite — un-gated, running wherever the
//! fixtures load, exactly like `fixture_oracle.rs`. It is a `#[sqlx::test]`
//! (its own migrated scratch DB), so the fixtures load into an isolated database.
//! The `Variant` enum models no `_match` member, so the domain
//! (`public.eql_v3_text_match`) is named directly.

use super::fixture_oracle::load_fixtures;
use anyhow::Result;
use eql_tests::property::assert_match_smoke;
use eql_tests::scalar_domains::{fetch_fixture_payload, MatchScalar};
use sqlx::PgPool;

/// `public.eql_v3_text_match` — the bloom-filter (`bf`) domain (`@@` fuzzy match).
const TEXT_MATCH_DOMAIN: &str = "public.eql_v3_text_match";

#[sqlx::test]
async fn text_match_smoke(pool: PgPool) -> Result<()> {
    // Match payloads come from the generated text fixture (encrypted with
    // [Unique, Ore, Match], so each carries a `bf`); load it into this test's
    // isolated DB on demand.
    load_fixtures::<String>(&pool).await?;

    let haystack =
        fetch_fixture_payload::<String>(&pool, <String as MatchScalar>::haystack()).await?;
    let needle = fetch_fixture_payload::<String>(&pool, <String as MatchScalar>::needle()).await?;
    let disjoint =
        fetch_fixture_payload::<String>(&pool, <String as MatchScalar>::disjoint()).await?;

    assert_match_smoke(&pool, TEXT_MATCH_DOMAIN, &haystack, &needle, &disjoint).await
}
