//! Permanent guard: the HAND-WRITTEN `src/v3/mod.rs` `pub mod <family>;` list
//! stays in step with `eql_domains::CATALOG`. `generate_bindings` owns the
//! `<family>.rs` files and `inventory.rs` but deliberately never touches `mod.rs`
//! (it carries the architectural module doc and the non-derivable float-NaN /
//! bool caveats). So adding a family to the catalog writes `<family>.rs` +
//! `inventory.rs` referencing `super::<family>::…`, but if the dev forgets to add
//! `pub mod <family>;` to `mod.rs` the only symptom is a cryptic `E0433`
//! ("failed to resolve: use of undeclared module") during `cargo test` — and only
//! AFTER the in-place regen has already overwritten committed source. This test
//! converts that into a friendly, catalog-pinned assertion with a fix hint.

use eql_domains::CATALOG;

#[test]
fn mod_rs_declares_every_catalog_family() {
    let path = format!("{}/src/v3/mod.rs", env!("CARGO_MANIFEST_DIR"));
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));

    // A `pub mod <family>;` declaration, ignoring leading indentation. The list is
    // flat and unattributed, so an exact-line match is sufficient and avoids
    // false positives from substrings inside doc comments.
    let declared: std::collections::BTreeSet<&str> = src
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix("pub mod ")
                .and_then(|rest| rest.strip_suffix(';'))
        })
        .collect();

    for family in CATALOG {
        assert!(
            declared.contains(family.name),
            "crates/eql-bindings/src/v3/mod.rs is missing `pub mod {0};` for catalog \
             family `{0}`. mod.rs stays hand-written (it carries the architectural \
             module doc + caveats), so generate_bindings cannot add it for you — \
             add the line by hand.",
            family.name
        );
    }
}
