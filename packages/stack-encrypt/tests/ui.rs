//! Compile-fail tests for the derive diagnostics: every `tests/ui/*.rs` must
//! fail to compile with exactly the `.stderr` beside it. Regenerate the
//! expectations after a deliberate message change with `TRYBUILD=overwrite`.

#[test]
fn derive_diagnostics() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
    // And the shapes that must compile, so a diagnostic never grows to
    // cover a valid call.
    t.pass("tests/ui/pass/*.rs");
}
