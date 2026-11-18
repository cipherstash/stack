# `sqlc-gen-stash`

`sqlc-gen-stash` is a sqlc process plugin that writes a Go package, as [sqlc-gen-go](https://github.com/sqlc-dev/sqlc-gen-go) does, and CipherStash encryption code for it. It runs a copy of sqlc-gen-go, which gives each column whose type is an EQL v4 domain its `encrypt/eql` type, and from the Go names that run works out, writes a package of its own with plaintext companions, public conversion helpers and opt-in query methods and, when asked, a value for every column of every table. That package is named after sqlc-gen-go's with `stash` appended (`queriesstash` for `queries`) and sits in a folder of that name inside sqlc-gen-go's.

## What it generates

Every table model and query row with encrypted columns that sqlc can trace gets these declarations in `<package>stash/stash.go`, independently of the query-method flags:

- `Plain<Struct>`: the same struct with each encrypted field in plaintext (`string`, `encrypt.Date`, `json.RawMessage` and so on, a pointer where the column can be NULL). Its `String`, `GoString` and `LogValue` methods hide the plaintext.
- `Decrypt<Struct>(ctx, encrypt.Decrypter, rows)`: opens a batch of rows, with one SDK call for each table the row reads, so a join or a self join works.
- `Encrypt<Struct>(ctx, *encrypt.Cipher, rows)`: seals a batch of plaintext rows, for whole-table models only. Query rows and projections get `Decrypt` only.

Each query's parameters struct that holds an encrypted column also gets a public `Plain<Params>` type and `Encrypt<Params>` helper. The helper takes one value, or a slice for a `:batch*` or `:copyfrom` query. Parameters get no `Decrypt`: they are written, never read back.

Call these helpers to prepare parameters for raw sqlc queries or decrypt rows you have already fetched. Opt-in query methods call the same helpers automatically; enabling either flag does not remove or change the manual API.

Parameter encryption covers INSERT values, UPDATE SET values and a comparison with a stored value (`WHERE email_eql4_eq = $1`), which sqlc doesn't tell apart; EQL v4 compares two stored values by their equality terms, so the last works. A parameter cast to a query domain (`sqlc.arg(name)::eql_v4.query_text_search`) is typed as the query value (`eql.TextSearchQuery`), which the column's value derives (`queriesstash.UserFields.GivenNameEql4Search.Matches(...)`); the plaintext struct holds it as is. A query with one parameter usually has no struct: the generated method accepts its plaintext value directly. Callers using raw sqlc queries can seal individual values with the column's `Encrypt` method.

Encrypting values requires a non-nil cipher. Use `encrypttest.NewClient(t)` for offline encryption tests. A nil value for a nullable field still writes SQL NULL; a missing cipher does not substitute NULL for the encrypted fields.

The table is the encryption context; the identity comes from the `identity` option. A ciphertext opened as a different column fails. sqlc-gen-go keeps the column each query field reads, and a table's model has a field for each of its columns in order, which is how the plugin traces a field back to its column whatever its Go name or SQL alias.

With `emit_table_fields`, the package also has a `<Model>Fields` value for every table, with one value per column, named as sqlc-gen-go names a model's fields. Dynamic SQL builders use them instead of naming tables and columns in strings:

- A plaintext column is a `Column[T]`, where `T` is sqlc-gen-go's Go type for it (`*string` where it can be NULL). It has `Table()`, `Column()`, `QualifiedName()` and `Zero() T`, which lets a generic function infer `T`.
- An encrypted column has the type `<EQLType>Field` of its EQL type, such as `TextSearchField`, shaped like the field entries stashgen generates: `Encrypt` seals one value, and each operator the SDK's engine answers on the column's EQL type is a query method. A `TextSearch` column has `Eq`, `Lt`, `Lte`, `Gt`, `Gte` and `Matches`; a `TextEq` column has `Eq`; a `JsonSearch` column has `Contains`, `ContainedBy`, `EqAt`, `Selector`, `Subtree`, `Children`, `ChildCount` and `Match`; a storage-only column (`Text`, `Date`) has none. Each also has `Table()`, `Column()`, `QualifiedName()`, `EQLType()` and `NullMode()`, and none has `Zero()`, so a function that needs a plaintext column can't be given one.

`Column[T]` and the encrypted field types are ordinary Go in `genstash/fieldtypes`, written beside `stash.go` as `fieldtypes.go`. Each `<EQLType>Field` is an alias of one of them, picked by the operators the engine answers: `Stored`, `Eq`, `Ord`, `Match`, `EqOrd`, `Search` or `Document`, for example `type TextSearchField = Search[string, eql.TextSearch, eql.TextSearchQuery]`. Generation refuses a column whose operators match none of them.

Every table gets one, whatever `omit_unused_structs` says, including a table no query returns and that therefore has no model in sqlc-gen-go's package. A view gets none, so a query builder can only name tables: a column read through a view would carry the view's name, under which nothing is encrypted and no tenant column is guaranteed.

For these values the plugin asks the engine for the operators at generation time, as stashgen does, and reads each table's Go types from the models sqlc-gen-go's steps build before `omit_unused_structs` leaves any out. Without `emit_table_fields` it does neither.

`internal/example` shows the output for a small schema with a table model, a projection, an outer join, a self join, a batch query, a table no query returns and a view.

### Opt-in query methods

`stash` has two independent query-method flags, both false by default:

- `emit_methods_with_param_encryption` replaces encrypted input fields with plaintext inputs (`Plain<Params>` for a struct), encrypts them, then executes the original query. Results keep their original sqlc types unless result decryption is also enabled.
- `emit_methods_with_result_decryption` decrypts returned fields and returns `Plain<Model>` or `Plain<Row>` values. Parameters keep their original sqlc types unless parameter encryption is also enabled. Scalar inputs and outputs use their plaintext types rather than companion structs.

Either flag generates `Queries` and `New(db, lookuper)`. Pass a connection, pool or transaction implementing sqlc's `DBTX`, and a `CipherLookuper`: a `func(context.Context) (*encrypt.Cipher, error)` that returns the cipher for the request, or an error saying why there is none. A converted query wraps that error, so callers can match it with `errors.Is`. A function with that signature, or a method value such as `lookuper.Lookup`, can be passed directly, without an adapter or conversion. The constructor creates the underlying sqlc queries; `go.emit_interface` is not required. The wrapper calls the function for each converted query; it does not resolve keysets, cache a tenant's cipher, inspect rollout flags, start transactions, or retry. Methods with no opted-in conversions are promoted unchanged from the embedded `*Queries`, and `q.Queries` exposes the original methods explicitly. With both flags disabled, the public conversion helpers remain available, but no wrapper is generated.

`q.WithTx(tx)` returns a wrapper bound to that transaction, retaining automatic conversion and cipher lookup. With `go.emit_methods_with_db_argument`, the constructor is `New(lookuper)` and each query takes `db` as sqlc's methods do; there is no `WithTx`. With `go.emit_prepared_queries` for `database/sql`, `Prepare(ctx, db, lookuper)` wraps sqlc's prepared queries, and `Close` closes their statements.

For example, with parameter encryption enabled and result decryption disabled:

```go
// cipherFor returns the request's *encrypt.Cipher.
q := dbstash.New(pool, cipherFor)
user, err := q.InsertUser(ctx, &dbstash.PlainInsertUserParams{
    ID: id,
    CreatedAt: now,
    Status: db.UserStatusActive,
    GivenNameEql4Search: "Alice",
    EmailEql4Eq: &email,
})
// user is the original db.User, including its ciphertext columns.
```

A missing or nil cipher, or an encryption error, prevents SQL execution. SQL errors pass through unchanged. A decryption failure after SQL succeeds is a `*ResultDecryptionError`, with the query name and an unwrapped cause available through `errors.Is`/`errors.As`. A write may already be committed; callers must not blindly retry it. There is no fallback to a legacy plaintext column, so enable result decryption only when the consumer is ready to read the encrypted columns.

For converted `:batch*` methods, an extra error return reports failures before submitting the batch. With result decryption enabled, the batch wrapper decrypts each query's results before its `Query`/`QueryRow` callback and preserves the original `Close` method. Other commands retain sqlc's error/result shape, including affected-row counts.

## Configuration

The plugin replaces sqlc's own `gen: go:` block for the package. Its codegen entry's `out` is the package's folder, `go` holds sqlc-gen-go's options as `gen: go:` would, without `out`, and `stash` holds the plugin's own:

```yaml
plugins:
  - name: go-stash
    process:
      cmd: sqlc-gen-stash

sql:
  - codegen:
      - plugin: go-stash
        # The folder of the package queries. The plugin writes
        # queriesstash/stash.go under it.
        out: internal/db/queries
        options:
          go:
            package: queries
            sql_package: pgx/v5
            # No override for an EQL type: the plugin gives each its
            # encrypt/eql type itself.
            overrides: [...]
          stash:
            # Optional: a <Model>Fields value for every table.
            emit_table_fields: true
            # Optional; both default to false. Parameter encryption alone
            # leaves reads unchanged.
            emit_methods_with_param_encryption: true
            emit_methods_with_result_decryption: false
            # Derives each column's identity the way a regex find and replace
            # does: the matched part of the name is replaced with replacement,
            # where $1 or ${name} is a capture group (Go's ReplaceAllString).
            # family_name_eql4_search has the identity family_name_eql4. Go
            # reads $1_ as a group named "1_", so write ${1}_. Generation
            # refuses an EQL column the pattern doesn't match.
            identity:
              pattern: '^(.+_eql4)(?:_eq|_search)?$'
              replacement: '$1'

# sqlc passes the top-level overrides only to its built-in generator, and
# options.go-stash to the plugin as global options. Its go block reaches the
# plugin's copy of sqlc-gen-go as global options, so give it the same
# overrides.
overrides:
  go:
    overrides: &go_overrides [...]
options:
  go-stash:
    go:
      overrides: *go_overrides
```

The plugin adds a `db_type` override for each EQL type the SDK produces and each of their query domains, nullable or not, giving the column or parameter its `encrypt/eql` type, a pointer where it can be NULL.

The generated code imports sqlc-gen-go's package by the module path in the nearest `go.mod` above `out` and the folder's path inside that module.

Generation fails, rather than generating something wrong, when:

- the options have a key other than `go` and `stash`, `go` has an option sqlc-gen-go doesn't know or `out`, or there is no `go.mod` above the entry's `out`;
- `identity` lacks `pattern` or `replacement`, or the pattern doesn't compile;
- an EQL column has no identity because the pattern doesn't match it, its identity breaks the SDK's rule for a label segment (for example, it contains `/`), or two columns of one table share one;
- a column's EQL type is one the SDK can't produce, an array, or an `eql_v4.query_*` domain;
- an override (package or global) names an EQL type as its `db_type`;
- a parameter is cast to an `eql_v4` type that isn't the query domain of an EQL type this SDK release produces;
- a view has an encrypted column. sqlc describes a view as if it were a table, so the plugin would seal and probe the column under the view's name and nothing stored under the table's would decrypt. sqlc gives plugins no way to tell the two apart, so the plugin finds views by reading the `CREATE VIEW` statements in the schema files, which means sqlc must run from the directory of `sqlc.yaml`;
- `emit_methods_with_param_encryption` needs a multi-field parameter struct that sqlc has flattened into separate arguments. Set `go.query_parameter_limit: 0` to emit parameter structs;
- a conversion helper or `emit_methods_with_param_encryption` encounters an encrypted `sqlc.slice` parameter. Neither supports lists of encrypted values;
- a companion struct mixes traceable encrypted fields with untraceable ones or an encrypted `sqlc.embed`, or an opted-in query conversion includes untraceable encrypted fields or an encrypted `sqlc.embed`. List those columns directly instead;
- with `emit_table_fields`, a plaintext column's Go type is one that `omit_unused_structs` left out of sqlc-gen-go's package, an enum no query uses. Give the column a `go_type` override, write a query that reads it, or turn `omit_unused_structs` off.

A row whose encrypted fields all come through a CTE gets the `eql` types but no companion when result decryption is disabled; enabling it fails generation. Read the columns from their table, for example with `INSERT … RETURNING` instead of selecting from a data-modifying CTE.

## Running it

sqlc runs the plugin as a process, so `sqlc-gen-stash` must be on `PATH` (or named by path in `cmd`) when `sqlc generate` runs. From a checkout of this repository, `go install .` in this directory installs it. `internal/example/generate.go` builds it into the example's folder instead, so the example always uses the plugin in the checkout.

sqlc-gen-go exports none of its steps, so `internal/golang` is a copy of its `internal` package, made by `copy.sh` with the import paths rewritten, plus one file of the plugin's own, `build.go`, whose `Build` runs sqlc-gen-go and returns its files and what its steps worked out on the way. The copy is of the version the `tool` line in this module's `go.mod` pins; nothing runs the tool. `go generate` remakes the copy, so CI fails if the two drift apart. sqlc-gen-go is MIT licensed, and its licence is in `internal/golang/LICENSE`.

## Using it from Go

Another plugin can use the module in code:

- `genstash.Generate(ctx, req)` is the whole plugin: it takes the request sqlc sends, with the options described above, and returns sqlc-gen-go's files and the `<package>stash` package. The `sqlc-gen-stash` command is `codegen.Run(genstash.Generate)`. Its `Options` and `GlobalOptions` types hold those options, to build them in code and marshal them to JSON. Each refusal above is an `*Error`, which says where the problem is (an option, a column, a query or a field) and wraps one of the `Err` sentinels, so a caller tells them apart with `errors.Is` and reads the place with `errors.AsType`. The problems one check finds come together through `errors.Join`.
- `gengo` exposes what sqlc-gen-go works out for a package and keeps internal: `Build(req)` runs sqlc-gen-go and returns a `Package` with its parsed options, its enums and structs (and, before `omit_unused_structs` leaves any out, every enum and every table's model), its queries with their parameter and row structs, the imports its files use, and its files. Every field carries the catalog column it holds, a table model's too. `Package.Declared` lists the structs the package declares with the file each is in, `ModelsFile` names the models file, and `DecodeOptions` and `DecodeGlobalOptions` decode sqlc-gen-go's options, refusing one it doesn't know. The types are sqlc-gen-go's own, through type aliases, so they change when the `go.mod` pin moves.

The tests (`go test ./...` in this directory) check the refusals above, the option combinations, and the generated contract. Query-method tests use `encrypttest.NewClient(t)` for real encryption and decryption without credentials or ZeroKMS, so they need the deterministic test guests (`mise run wasm:guest:build:deterministic` and `wasm:guest:build:eql:deterministic`), and generation needs the EQL guest (`mise run wasm:guest:build:eql`).

This is a Go module of its own, nested in `languages/golang` as `encrypt/example` is, so the SDK does not take on sqlc's dependencies. It requires the SDK and `encrypttest` at the zero pseudo-version, replaced by the directories in this checkout, so it always builds against the tree.
