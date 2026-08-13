//! The `v3_json_storage` fixture — the storage-only / encryption-only json
//! analogue of `v3_ste_vec`, generated through the SAME `FixtureSpec`
//! machinery but with NO index (`.storage_only()`). cipherstash-client
//! therefore encrypts each JSON document into a plain `{v, i, c}` envelope (the
//! JSON analogue of a scalar storage payload) rather than a SteVec document.
//!
//! The generated `payload` column is the storage-only `public.eql_v3_json`
//! DOMAIN, so its CHECK runs when the fixture loads. This gives the
//! storage-only json domain — and its native-jsonb operator firewall (generated
//! under `src/v3/scalars/json/`) — a real-ciphertext home, exactly as the `bool`
//! scalar storage fixture does for the scalar storage domains.

use anyhow::Result;
use serde_json::{json, Value};

use super::spec::FixtureSpec;

/// The canonical fixture name → table `fixtures.v3_json_storage`, script
/// `v3_json_storage.sql`, SQLx ref `scripts("v3_json_storage")`.
const NAME: &str = "v3_json_storage";

/// The canonical `payload` column type — the storage-only `public.eql_v3_json`
/// DOMAIN, so the `{v, i, c}` envelope CHECK runs when the fixture loads.
const PAYLOAD_TYPE: &str = "public.eql_v3_json";

/// Number of fixture rows. A small non-trivial set is enough — the storage-only
/// domain is not searchable, so there is no oracle to discriminate; the rows
/// exist to prove real ciphertexts load, decrypt, and reject native jsonb ops.
const ROW_COUNT: i64 = 3;

/// The plaintext documents — the source of truth for the fixture. Distinct
/// per row so a decrypt round-trip has something to compare against.
fn documents() -> Vec<Value> {
    (1..=ROW_COUNT)
        .map(|i| {
            json!({
                "hello": format!("world-{i}"),
                "number": i,
                "nested": { "deep": "constant" },
            })
        })
        .collect()
}

/// Generate `tests/sqlx/fixtures/v3_json_storage.sql` by encrypting the
/// plaintext documents through the shared `FixtureSpec` pipeline with NO index
/// (`.storage_only()`), so each becomes a plain `{v, i, c}` storage-only json
/// payload.
pub async fn generate() -> Result<()> {
    let docs = documents();
    FixtureSpec::new(NAME)
        .storage_only()
        .with_column_type(PAYLOAD_TYPE)
        .with_values(&docs)
        .run()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_builds_a_storage_only_json_fixture() {
        let docs = documents();
        let spec = FixtureSpec::new(NAME)
            .storage_only()
            .with_column_type(PAYLOAD_TYPE)
            .with_values(&docs);
        assert_eq!(spec.fixture_table(), "fixtures.v3_json_storage");
        assert_eq!(spec.column_type().as_str(), "public.eql_v3_json");
        // Storage-only / encryption-only: the fixture declares zero indexes.
        assert!(spec.indexes().is_empty());
        assert!(spec.check_complete().is_ok());
    }
}
