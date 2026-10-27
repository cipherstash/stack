# Typed encrypted JSON document example

This program stores a Go `Profile` struct as one encrypted EQL v4 JSON column.
It finds a row by containment, compares an ordered path, decrypts a whole
profile, and opens only the visit times from another query.

## Run

You need Go 1.26.10 or later, PostgreSQL with the EQL v4 SQL bundle installed, a `DATABASE_URL`
pointing to it, and CipherStash credentials. `stash auth login` writes a
developer profile; the `CS_*` environment variables also work. The example
creates a temporary table, so it does not leave data behind.

From the repository root:

```sh
mise run wasm:guest:build:eql wasm:auth-guest:build
export DATABASE_URL='postgres://localhost:5432/your_database'
cd languages/golang
go run ./encrypt/example/json
```

For a fresh database, install the `eql-v4-install.sql` asset attached to the
Go module release before running the program. The guest builds are needed in
a repository checkout because its WASM files are not committed. A tagged Go
module version carries them.

## Change the model

The declaration is in `model.go`. `stashgen` writes `customer_stash.go` from
its `stash` tags. After changing the struct or tags, run this from
`languages/golang` and commit the changed generated file:

```sh
go generate ./encrypt/example/json
```

`Profile` uses `encoding/json` for the document shape. The `ordered=$.age`
tag adds an ordering term for that path. A containment needle made from a
struct includes every field without `omitempty`, including zero values;
`main.go` uses a map to name only the member being queried. The prepared
subtree read returns JSON text, which `encrypt.DecodeJSON[int64]` decodes.

The example's `SELECT` statements cast parameters to EQL's operand types.
The age comparison uses the selector derived from the same ordered path as
its query term. A JSON selector or read token is a capability over a column;
do not log it. Partial reads authenticate returned entries against the
prepared request, but do not prove that the database returned every entry.
