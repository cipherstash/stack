//! Build output validation tests
//!
//! Validates that the built v3 release artifact contains/excludes the expected
//! components. These tests run against the built SQL files, not the database.

use std::fs;
use std::path::Path;

/// Helper to read a release SQL file
fn read_release_sql(filename: &str) -> String {
    let path = format!("../../release/{}", filename);
    fs::read_to_string(&path).unwrap_or_else(|_| panic!("Failed to read {}", path))
}

// =============================================================================
// v3 Variant Tests (the sole self-contained eql_v3 surface)
// =============================================================================

#[test]
fn v3_variant_file_exists() {
    assert!(
        Path::new("../../release/cipherstash-encrypt.sql").exists(),
        "the v3 installer should exist"
    );
}

#[test]
fn v3_uninstaller_exists() {
    assert!(
        Path::new("../../release/cipherstash-encrypt-uninstall.sql").exists(),
        "the v3 uninstaller should exist"
    );
}

#[test]
fn v3_variant_creates_eql_v3_schema() {
    let sql = read_release_sql("cipherstash-encrypt.sql");
    assert!(
        sql.contains("CREATE SCHEMA eql_v3"),
        "v3 variant must create the eql_v3 schema"
    );
}

#[test]
fn v3_variant_has_no_eql_v2_symbol() {
    let sql = read_release_sql("cipherstash-encrypt.sql");
    // Reject both schema-qualified refs (`eql_v2.<fn>`) and bare v2 entity names
    // (`eql_v2_encrypted`, `eql_v2_configuration`, …). Prose mentions like
    // "the eql_v2 original is unchanged" in doc comments are still allowed.
    assert!(
        !sql.contains("eql_v2.") && !sql.contains("eql_v2_"),
        "v3 variant must be self-contained (no eql_v2.<symbol> or eql_v2_<entity> reference)"
    );
}

#[test]
fn v3_variant_omits_v2_coupled_pin_search_path() {
    // The artifact appends tasks/pin_search_path_v3.sql (eql_v3-only), NOT the
    // removed eql_v2-coupled tasks/pin_search_path.sql (which referenced
    // public.eql_v2_encrypted / eql_v2.ste_vec_entry and only pinned eql_v2
    // functions). Match the eql_v2-QUALIFIED markers: a bare `ste_vec_entry`
    // substring would false-positive on the legitimate `public.eql_v3_json_entry`
    // DOMAIN that the v3 jsonb document surface defines.
    let sql = read_release_sql("cipherstash-encrypt.sql");
    assert!(
        !sql.contains("eql_v2.ste_vec_entry") && !sql.contains("eql_v2_encrypted"),
        "v3 variant must not carry the eql_v2-coupled pin_search_path script"
    );
}
