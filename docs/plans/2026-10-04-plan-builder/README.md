# Go examples for the plan builder

These files show the Go binding from [the plan builder design](../2026-10-04-plan-builder.md#the-go-binding) as complete programs.
The binding does not have this interface yet, so this code does not build in this repository.
The module path is `example.com/app`.

## What each file shows

| File | What it shows |
|---|---|
| [`main.go`](main.go) | A client, one keyset for each tenant, and calls into every package below |
| [`users/model.go`](users/model.go) | A plan in struct tags, and the `go:generate` line that runs `stashgen` |
| [`users/user_stash.go`](users/user_stash.go) | The file that `stashgen` writes: the encrypted type, the plan, and the typed fields |
| [`users/sqlstore.go`](users/sqlstore.go) | `database/sql` with the generated type: insert, batch insert in a transaction, equality search, ORE ordering and JSON containment |
| [`users/gormstore.go`](users/gormstore.go) | GORM, with a hand-written model that a row plan checks at package init |
| [`users/sqlcstore.go`](users/sqlcstore.go) | sqlc, with the sqlc model in a row plan, and an update of one field and its terms |
| [`users/extend.go`](users/extend.go) | A context extension on the write, the query and the read |
| [`sqlc/`](sqlc/) | The schema, the queries and the overrides that generate [`internal/userdb/`](internal/userdb/) |
| [`contacts/contacts.go`](contacts/contacts.go) | A plan built by hand for a type with no tags |
| [`individuals/individuals.go`](individuals/individuals.go) | A plan from the policy package, for a type that cannot carry tags |
| [`blocklist/blocklist.go`](blocklist/blocklist.go) | A value plan for a value with no record around it |
| [`documents/documents.go`](documents/documents.go) | One value sealed as one tree, decrypted with the client |
| [`eql-sqlc/`](eql-sqlc/) | sqlc with EQL v3 domain columns, which generates [`internal/eqldb/`](internal/eqldb/) |

## Generate the encrypted type

`stashgen` does not exist yet, so [`users/user_stash.go`](users/user_stash.go) is written by hand as the file it will write.

## Generate the sqlc packages

The two sqlc packages were generated with sqlc v1.31.1.
Run `sqlc generate` in `sqlc/` and in `eql-sqlc/` to generate them again.

## Use sqlc with EQL domain columns

Three rules apply when a column has an EQL v3 domain type:

- **Give sqlc a file that declares the domains.**
  sqlc cannot parse the EQL install bundle, because it rejects function overloads that differ only by `text` and `text[]`.
  The file [`eql-sqlc/eql-domains.sql`](eql-sqlc/eql-domains.sql) declares each domain as `jsonb`, and the database still gets the real bundle from `stash eql install`.
- **Spell a `db_type` override exactly as the schema spells the type.**
  `public.eql_v3_text_search` and `eql_v3_text_search` are two different spellings to sqlc.
  An override with the other spelling matches nothing, and the column becomes `interface{}`.
- **Cast a query parameter once, straight to the query domain.**
  sqlc types a parameter by its first cast.
  `$1::eql_v3.query_text_search` gets the override type, and `$1::jsonb::eql_v3.query_text_search` gets `json.RawMessage`.
