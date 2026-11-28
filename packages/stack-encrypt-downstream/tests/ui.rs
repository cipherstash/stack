//! What a user of `stack-encrypt` reads when a derive is refused. The
//! errors name `stack_encrypt` paths, since this crate has no other
//! dependency. Re-record with `TRYBUILD=overwrite cargo test -p
//! stack-encrypt-downstream --test ui` after an intended change.

// trybuild launches rustc. Miri cannot run rustc.
#[cfg(not(miri))]
#[test]
fn ui() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
