//! The deterministic key source of the `deterministic-kms` test build:
//! `stack-kms`'s [`DeterministicSource`] (behind its `test-support` feature),
//! the one definition that also sealed stack-encrypt's record fixture
//! (`tests/fixtures/record_lowering.json`). A Go test that loads this build
//! with the fixture's seed opens the records Rust sealed and derives the same
//! term bytes, because both run the same code.
//!
//! It is a test double. The feature that compiles it is off by default, and
//! the build it produces goes under languages/golang/encrypt/testdata, which
//! `go build` and the package's `//go:embed wasm` both ignore, so no Go
//! binary carries it; the tests read it from disk.

pub use stack_kms::DeterministicSource;
