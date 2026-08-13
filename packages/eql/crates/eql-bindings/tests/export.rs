//! JSON Schema export — runs during `cargo test` (alongside ts-rs's own
//! export tests, which write `bindings/`). Output is checked in; freshness
//! is enforced by `mise run types:check`. Schema files are named after the
//! SQL domain — the protocol identity — not the Rust type.
//!
//! Output base defaults to `schema/` (relative to the crate dir, where
//! `cargo test` runs), so a plain `cargo test` regenerates the checked-in
//! tree. `EQL_TYPES_SCHEMA_DIR` overrides it — mirroring ts-rs's
//! `TS_RS_EXPORT_DIR` — so `mise run types:generate` can redirect output to a
//! throwaway temp dir and only swap it into place after a successful build.

use eql_bindings::v3;
#[test]
fn dump_v3_json_schemas() {
    let base = std::env::var("EQL_TYPES_SCHEMA_DIR").unwrap_or_else(|_| "schema".into());
    let dir = format!("{base}/v3");
    // Clear any prior output first so JSON for a domain that was removed from the
    // catalog does not linger as a stale checked-in file. `schema/v3` holds only
    // this test's generated `*.json`, so recreating it from scratch is safe.
    if std::path::Path::new(&dir).exists() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
    std::fs::create_dir_all(&dir).unwrap();
    // Both the stored/SteVec inventory and the query-operand twins: query
    // domains are a wire shape consumers validate, so they get JSON Schema too
    // (parity with the ts-rs export, which picks them up via `#[ts(export)]`).
    for entry in v3::all().into_iter().chain(v3::all_query()) {
        let mut schema = serde_json::to_value(entry.schema()).unwrap();
        // schemars 0.8 emits no $id; inject the canonical one (the URL format
        // lives on DomainType::schema_id, pinned by tests/catalog_parity.rs).
        schema
            .as_object_mut()
            .unwrap()
            .insert("$id".into(), entry.schema_id().into());
        std::fs::write(
            format!("{dir}/{}.json", entry.domain()),
            serde_json::to_string_pretty(&schema).unwrap(),
        )
        .unwrap();
    }
}
