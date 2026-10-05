# Go examples for the plan builder

These files show the Go SDK from [the plan builder design](../2026-10-04-plan-builder.md#the-go-sdk) as complete programs.
The SDK does not exist yet, so this code does not build in this repository.
The module path is `example.com/app`.

## What each file shows

| File | What it shows |
|---|---|
| [`main.go`](main.go) | A client, one cipher for each tenant, and a batch of two types in one request |
| [`users/model.go`](users/model.go) | A struct with `stash` tags, and the `go:generate` line |
| [`users/user_stash.go`](users/user_stash.go) | The file `stashgen` writes: the encrypted type, `Encrypt`, `Decrypt` and `Fields` |
| [`users/sqlstore.go`](users/sqlstore.go) | `database/sql`: batch insert in a transaction, and a search by email |
| [`users/gormstore.go`](users/gormstore.go) | GORM, with the generated type as the model |
| [`users/sqlcstore.go`](users/sqlcstore.go) | sqlc, with its row struct converted to the generated type |
| [`sqlc/`](sqlc/) | The schema, the queries and the overrides that generate [`internal/userdb/`](internal/userdb/) |
| [`accounts/account.go`](accounts/account.go) | An embedded `gorm.Model`, another library's tags, an unexported field and `-redact` |
| [`contacts/contacts.go`](contacts/contacts.go) | [`crm.Contact`](crm/contact.go), a type in another package, in separate columns, with a model |
| [`documents/documents.go`](documents/documents.go) | An `opaque` struct, sealed as one value |
| [`proto/`](proto/) | A protobuf message whose fields carry data categories, which generates [`internal/pb/`](internal/pb/) |
| [`rules/rules.go`](rules/rules.go) | Rules that decide what to encrypt from each field's data categories |
| [`cmd/genencrypt/main.go`](cmd/genencrypt/main.go) | The generate program that runs the rules |
| [`individuals/`](individuals/) | The file the rules give for the protobuf message, and a store that uses it |

The `users` example uses `TextEq`, which is the one EQL type the engine produces today.

## What was checked

| Claim | Status |
|---|---|
| Every Go file type-checks | Run. `go vet ./...` passes against a stub of the SDK. The stub is not in this repository, and it has signatures only. |
| The policy example compiles against real protobuf code | Run. buf v1.50.0 and `protoc-gen-go` wrote `internal/pb/`, and `go vet` passes. |
| A field added to the protobuf message does not stop the build | Run. It builds, as the plan says: CI finds that change. |
| The protobuf source reads the field options, and the rules run | Not run. Neither the source nor the generator exists. |
| A change to a tagged struct, a model or a type in another package stops the build | Run. Each change fails `go build` with "cannot convert". |
| sqlc's row struct converts to the generated type | Run. The conversions in `users/sqlcstore.go` compile against real sqlc output. |
| A struct from another package with an unexported field cannot convert | Run, with `sync.Once`. |
| A generated file from another version does not compile | Run. A file that names an unknown version constant fails `go build`. |
| The files `stashgen` writes | Not run. `stashgen` does not exist, and the five `_stash.go` files are written by hand. |
| The SDK can be built with these signatures | Not run. |
| The record fixture and the EQL fixture | Not run. Neither fixture exists. |
| `stashgen` checks a declaration with the embedded guest | Not run. |
| The code works with a database, GORM or pgx | Not run. Nothing here has connected to a database. |
| The EQL types, and how generated code assembles them | Not run. `eql-codegen` does not write Go yet, and the examples use a stub of `eql.TextEq`. |
| The steps in "Use the SDK" | Not run. Nobody has followed them. |

## Generate the protobuf package

The protobuf package was generated with buf v1.50.0 and `protoc-gen-go`.
Run `buf generate` in `proto/` to generate it again.

## Generate the sqlc package

The sqlc package was generated with sqlc v1.31.1.
Run `sqlc generate` in `sqlc/` to generate it again.

## Use sqlc with EQL columns

Three rules apply when a column has an EQL type:

- **Give sqlc a file that declares the domains.**
  sqlc cannot parse the EQL install bundle, because it rejects function overloads that differ only by `text` and `text[]`.
  The file [`sqlc/eql-domains.sql`](sqlc/eql-domains.sql) declares each domain as `jsonb`, and the database still gets the real bundle from `stash eql install`.
- **Spell a `db_type` override exactly as the schema spells the type.**
  `public.eql_v3_text_eq` and `eql_v3_text_eq` are two different spellings to sqlc.
  An override with the other spelling matches nothing, and the column becomes `interface{}`.
- **Cast a query parameter once, straight to the query domain.**
  sqlc types a parameter by its first cast.
  `$1::eql_v3.query_text_eq` gets the override type, and `$1::jsonb::eql_v3.query_text_eq` gets `json.RawMessage`.
