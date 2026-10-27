# CipherStash Stack for Go

This module provides searchable field encryption for Go structs. `stashgen`
turns `stash` tags into typed encryption, decryption and query methods. The
`encrypt` package runs the Rust encryption engine in an embedded WASI guest
with wazero; applications do not need cgo.

Start with the [SDK guide](encrypt/README.md) for installation, credentials,
generation and PostgreSQL storage. The [stashgen reference](cmd/stashgen/README.md)
explains tags, supported field types and generated methods. The
[typed JSON document example](encrypt/example/json/README.md) walks through
an EQL v4 table, queries and partial reads. The [credential guide](auth/README.md)
covers profile, access key and federation strategies. The
[administration guide](control/README.md) covers actors, memberships, keysets,
clients and grants using those same strategies. See the
[Go changelog](CHANGELOG.md) for release and compatibility notes.

## Using a released module

Use Go 1.26.10 or later (or 1.27.3 or later on the 1.27 line). Add the
generator to your application module, declare a struct with `stash`
tags, then generate and commit its `*_stash.go` file:

```sh
go get -tool github.com/cipherstash/stack/languages/golang/cmd/stashgen
go generate ./...
```

Use a tagged Go module version. Release tags include the embedded WASI guests;
a checkout or an untagged commit does not. The [SDK guide](encrypt/README.md#building)
explains how to build them locally. Searchable `encrypt_into` fields require
EQL v4 in PostgreSQL; the EQL v4 SQL bundle is attached to the matching Go
release. Go and TypeScript currently use different EQL versions, so follow
the [EQL column guide](encrypt/README.md#eql-columns) when choosing a schema.

## Working in this repository

From the repository root, install the toolchain pinned by `mise.toml` and
build the guests before running Go tests:

```sh
mise run wasm:guest:build
mise run wasm:guest:build:eql
mise run wasm:guest:build:deterministic
mise run wasm:guest:build:eql:deterministic
mise run wasm:auth-guest:build
mise run go:test
```

The `.wasm` files are build outputs and are not committed on development
branches. `mise run go:test:postgres` also runs the PostgreSQL suite against
the EQL v4 bundle built from this tree; it needs the database named by
`EQL_TEST_DATABASE_URL`. See `mise.toml` and [AGENTS.md](../../AGENTS.md)
for the build and release details.
