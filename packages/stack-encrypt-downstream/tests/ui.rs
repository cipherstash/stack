//! What a user of `stack-encrypt` reads when a derive is refused. The
//! errors name `stack_encrypt` paths, since this crate has no other
//! dependency.
//!
//! rustc lists a trait's other implementors in its help, and a
//! stack-encrypt feature such as `dynamic` adds implementors. The recorded
//! errors are still the same under every feature set. trybuild builds the
//! cases as a separate project, from this crate's dev-dependencies and
//! features. This crate has no features, and
//! `tests/manifest.rs` checks that it has none. So a workspace build with
//! `--all-features`, as CI runs, does not change that project.
//!
//! Re-record with `TRYBUILD=overwrite cargo test -p
//! stack-encrypt-downstream --test ui` after an intended change.

// trybuild launches rustc. Miri cannot run rustc.
#[cfg(not(miri))]
#[test]
fn ui() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
