//! Compile-fail tests for the derive diagnostics: every `tests/ui/*.rs` must
//! fail to compile with exactly the `.stderr` beside it. Regenerate the
//! expectations after a deliberate message change with `TRYBUILD=overwrite`.
//!
//! The expectations are recorded with every feature on, as `test:unit` and
//! CI run them (`--all-features`). They cannot hold under both feature sets:
//! rustc lists the other implementors of a trait, so the `dynamic` feature's
//! `FfiValue` joins one help list and pushes another entry off it, and its
//! `Opener::Any` variant makes rustc stop trimming `std::any::Any`. So the
//! test is skipped, not failed, when `dynamic` is off — run it with
//! `--all-features`.

#[test]
#[cfg_attr(
    not(feature = "dynamic"),
    ignore = "diagnostics are recorded with --all-features; run with that feature set"
)]
fn derive_diagnostics() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
    // And the shapes that must compile, so a diagnostic never grows to
    // cover a valid call.
    t.pass("tests/ui/pass/*.rs");
}
