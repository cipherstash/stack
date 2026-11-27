//! Compile-fail tests for the guards in `#[derive(Encrypt)]` /
//! `#[derive(Decrypt)]`.
//!
//! The derive crate's own unit tests assert that `Shape::parse` returns an
//! error. What they cannot check is the part a developer actually meets: that
//! the derive fails to compile at all, and that the diagnostic points at the
//! offending struct and explains itself. For guards that exist to stop an
//! unsound ciphertext being produced — an enum with no authenticated
//! discriminator, a struct that would seal no tag — that message *is* the
//! feature, so it is pinned here.
//!
//! Regenerate the expected output with `TRYBUILD=overwrite cargo test -p
//! vitaminc-aead --test derive_ui` after an intentional change.

// `trybuild` launches rustc and inspects the filesystem, neither of which can
// run inside Miri's isolated interpreter — mirroring `vitaminc-protected`.
#[cfg(not(miri))]
#[test]
fn derive_ui() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/derive/*.rs");
}
