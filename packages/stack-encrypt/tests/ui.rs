//! Compile-fail tests for the derive diagnostics: every `tests/ui/*.rs` must
//! fail to compile with exactly the `.stderr` beside it. Regenerate the
//! expectations after a deliberate message change with `TRYBUILD=overwrite`.

#[test]
fn derive_diagnostics() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
