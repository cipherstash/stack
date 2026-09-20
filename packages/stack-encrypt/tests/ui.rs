//! Compile-fail tests for the derive diagnostics: every `tests/ui/*.rs` must
//! fail to compile with exactly the `.stderr` beside it. Regenerate the
//! expectations after a deliberate message change with `TRYBUILD=overwrite`.
//!
//! The expectations are recorded with every feature on, as `test:unit` and
//! CI run them (`--all-features`), and this test is only built with the
//! `dynamic` feature (`required-features` in `Cargo.toml`): rustc lists a
//! trait's other implementors in its help, so that feature's `FfiValue`
//! joins one list and pushes another entry off it, and one recording cannot
//! hold under both feature sets.

#[test]
fn derive_diagnostics() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
    // And the shapes that must compile, so a diagnostic never grows to
    // cover a valid call.
    t.pass("tests/ui/pass/*.rs");
}
