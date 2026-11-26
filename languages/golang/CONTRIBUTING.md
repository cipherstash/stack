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

From the repository root, build the guests before you run `go test`:

- `mise run wasm:guest:build` builds the engine that package `encrypt` embeds.
- `mise run wasm:guest:build:eql` builds the engine with the EQL types. Package `encrypt/eql` embeds it, and `stashgen` needs it.
- `mise run wasm:auth-guest:build` builds the credential guest that package `auth` embeds, and checks which functions it imports.
- `mise run wasm:guest:build:deterministic` and `mise run wasm:guest:build:eql:deterministic` build the test builds that package `encrypttest` embeds. The round-trip and fixture tests use them too. Those tests need no network.

Without these builds, `NewClient` returns `encrypt.ErrGuestNotBuilt` or `encrypt.ErrEQLGuestNotBuilt`, `auth.Open` returns `auth.ErrGuestNotBuilt`, and the tests that need them skip.
`encrypttest.NewClient` fails its test instead of skipping.
The `encrypttest` module's tag at the same version includes the test builds.

## Run the tests

`encrypt/encrypttest` and `encrypt/example` are Go modules of their own.
So `go test ./...` from `languages/golang` does not test them.
`mise run go:test` tests all three modules.

## How the Go code reaches the engine

Package `encrypt` is the reference integration for the engine.
The guide in `packages/stack-encrypt/docs/language-integration.md` explains how the binding works, what crosses it, and how to build one for another language.

- Generated code hands the declaration to the engine as data, through package `gensupport`. The engine runs the same plan that the Rust API and the derive macro run.
- The index words in `stash` tags are the Rust API's words for the same behaviour. Go also has two words that the Rust API does not have.
- An `opaque` struct crosses as one storage blob. The blob is vitaminc's storage profile, version 1, written by `vcffi.MarshalStorage` in `encrypt/gensupport/codec.go`.
- The `OrdOre` types and `TextSearchOre` use block ORE (order-revealing encryption) terms, from ore-rs's 6-bit schemes.
- `encrypt.AuditMetadata` is `AuditMetadata::new().with(key, value)` and `.audit(..)` in the Rust crate. In the ZeroKMS protocol, it is the unverified context of a key request.
- Package `auth` has a method for each thing the napi binding of the `stack-profile` crate exposes, named as in Rust.
- The credential guest creates files with mode 0600. That is wazero's create mode, not the crate's own, because the crate skips setting the mode on wasm32. A test checks the mode.

## Design records

The architecture decision records for the engine are in `packages/stack-encrypt/docs/adr`.
These two architecture decision records (ADRs) explain how the Go module is divided:

- [ADR-0005](../../packages/stack-encrypt/docs/adr/0005-a-separate-credential-guest-for-the-profile-and-auth.md) explains why package `auth` runs its own guest, apart from the crypto guest, and the options that were rejected.
- [ADR-0007](../../packages/stack-encrypt/docs/adr/0007-bindings-enter-through-a-plan-never-a-second-executor.md) explains why a binding reaches the engine only through a plan. The amendment to ADR-0007 dated 2026-10-06 covers the engine build with the EQL types. Package `encrypt/eql` embeds that build and registers it on import.

For the build and release details, see `mise.toml` and the `languages/golang` entry in [AGENTS.md](../../AGENTS.md).
