#![cfg_attr(doctest, doc = include_str!("../../../crates/eql-bindings/README.md"))]
// Keep the attribute above on the first line of this file. A doctest is then
// reported at its line in the README: `src/lib.rs - (line 233)` is the code
// block that starts at line 233 of `crates/eql-bindings/README.md`.
//
// This library holds no code of its own. The tests of `eql-bindings`'
// `stack-encrypt` feature are under `tests/`.
//
// It runs the Rust examples in the `eql-bindings` README as doctests. Each
// example is a complete program, and needs a key source and an async
// runtime. This crate has both, and `eql-bindings` keeps them out of its own
// test build. From `packages/eql`:
//
//     cargo test -p eql-encryption-tests --doc
