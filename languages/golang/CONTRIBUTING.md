# Contributing to the Go SDK

This document is for people who change the Go module in this repository.
It covers how to build the engine from a checkout, how to run the tests, and how the Go code connects to the Rust engine.

If you use the SDK in an application, you do not need this document.
A tagged version of the module includes everything it needs.
Start with the [module README](README.md) instead.

## Build the engine in a checkout

A checkout of this repository does not include the compiled engine.
The `.wasm` files are build outputs. They are not committed on development branches.
The release workflow commits them only to the commit that a release tag names.

From the repository root, install the toolchain that `mise.toml` pins (`mise install`).
Then build the guests before you run `go test`:

- `mise run wasm:guest:build` builds the engine that package `encrypt` embeds.
- `mise run wasm:guest:build:eql` builds the engine with the EQL types. Package `encrypt/eql` embeds it, and `stashgen` needs it.
- `mise run wasm:auth-guest:build` builds the credential guest that package `auth` embeds, and checks which functions it imports.
- `mise run wasm:guest:build:deterministic` and `mise run wasm:guest:build:eql:deterministic` build the test builds that package `encrypttest` embeds. The round-trip and fixture tests use them too. Those tests need no network.

Without these builds, `NewClient` returns `encrypt.ErrGuestNotBuilt` or `encrypt.ErrEQLGuestNotBuilt`, `auth.Open` returns `auth.ErrGuestNotBuilt`, and the tests that need them skip.
`encrypttest.NewClient` fails its test instead of skipping.
The `encrypttest` module's tag at the same version includes the test builds.

To run `stashgen` from a checkout, build the guest that includes the EQL types first.
`stashgen` checks each declaration with it:

```sh
mise run wasm:guest:build:eql
```

Without that build, `stashgen` stops with an error that starts `encrypt: guest module with the EQL types not built`.

## Run the tests

`encrypt/encrypttest` and `encrypt/example` are Go modules of their own.
So `go test ./...` from `languages/golang` does not test them.
`mise run go:test` tests all three modules.

`mise run go:test:postgres` runs the shared EQL and JSON conformance tests, then the PostgreSQL tests, against the EQL v4 bundle built from this tree.
The task needs three things:

- a disposable PostgreSQL database, named by `EQL_TEST_DATABASE_URL`
- `psql`
- the Rust test tools (`mise install --env test`), because the conformance tests include Rust tests

## How the Go code reaches the engine

Package `encrypt` is the reference integration for the engine.
The guide in `packages/stack-encrypt/docs/language-integration.md` explains how the binding works, what crosses it, and how to build one for another language.

- Generated code hands the declaration to the engine as data, through package `gensupport`. The engine runs the same plan that the Rust API and the derive macro run.
- An `opaque` struct crosses as one storage blob. The blob is vitaminc's storage profile, version 1, written by `vcffi.MarshalStorage` in `encrypt/gensupport/codec.go`.
- The `OrdOre` types and `TextSearchOre` use block ORE (order-revealing encryption) terms, from ore-rs's 6-bit schemes.
- `encrypt.AuditMetadata` is `AuditMetadata::new().with(key, value)` and `.audit(..)` in the Rust crate. In the ZeroKMS protocol, it is the unverified context of a key request.
- Package `auth` has a method for each thing the napi binding of the `stack-profile` crate exposes, named as in Rust.
- The credential guest creates files with mode 0600. That is wazero's create mode, not the crate's own, because the crate skips setting the mode on wasm32. A test checks the mode.

## Known gaps

After `Decrypt`, part of the last value it opened stays in the guest's stack.
The part is the last 16-byte block that the cipher decrypted.
The cipher that seals each value is AES-256-GCM (Advanced Encryption Standard in Galois/Counter Mode).
The encoded string is one tag byte and then the text.

- A string of 15 bytes or fewer fits in one block, and stays whole.
- For a longer string, only a last block shorter than 16 bytes stays. That is the last (length + 1) mod 16 bytes of the text.
- Nothing stays when the length is 31, 47, 63, or any other length where length + 1 is a multiple of 16.

The next `Encrypt` or `Decrypt` overwrites it.

The cause is a stack buffer in the RustCrypto cipher crates that vitaminc's wasm32 backend decrypts through. Nothing wipes that buffer.
`TestPlaintextDoesNotRemainInGuestMemoryAfterDecrypt` in `encrypt/roundtrip_test.go` records this gap.
The test is skipped until vitaminc wipes that buffer (cipherstash/vitaminc#370).
When that fix is released, remove the skip so the test runs again.

## Design records

The architecture decision records (ADRs) are in two series.
A bare ADR number in a Go code comment can belong to either series, so check both.

The repository-level series is in `docs/adr`.
Its [ADR-0002](../../docs/adr/0002-one-value-model-three-encodings-and-eql-v4-by-producer.md) explains the value model, including integer widths, the text fold, and float order.
Go code comments that cite ADR-0002 mean this record.

The engine's series is in `packages/stack-encrypt/docs/adr`. Two of its records explain how the Go module is divided:

- [ADR-0005](../../packages/stack-encrypt/docs/adr/0005-a-separate-credential-guest-for-the-profile-and-auth.md) explains why package `auth` runs its own guest, apart from the crypto guest, and the options that were rejected.
- [ADR-0007](../../packages/stack-encrypt/docs/adr/0007-bindings-enter-through-a-plan-never-a-second-executor.md) explains why a binding reaches the engine only through a plan. The amendment to ADR-0007 dated 2026-10-06 covers the engine build with the EQL types. Package `encrypt/eql` embeds that build and registers it on import.

For the build and release details, see `mise.toml` and the `languages/golang` entry in [AGENTS.md](../../AGENTS.md).
