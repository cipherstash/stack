# Stack Encrypt for Go

Searchable, field-level encryption for Go structs under per-value ZeroKMS
data keys. You declare what to encrypt with struct tags; `stashgen` writes the
encrypted type and the functions that encrypt, decrypt and search it; the
`stack-encrypt` Rust engine runs unmodified inside a WASI module embedded in
this package, through [wazero], with no cgo.

The package reference is on [pkg.go.dev]; the generator's reference is
[`cmd/stashgen/README.md`](../cmd/stashgen/README.md).

[wazero]: https://wazero.io
[pkg.go.dev]: https://pkg.go.dev/github.com/cipherstash/stack/languages/golang/encrypt

## Use the SDK

1. Add the generator to your module. This needs Go 1.26 or later.

   ```sh
   go get -tool github.com/cipherstash/stack/languages/golang/cmd/stashgen
   ```

   This resolves to the latest tagged version, which carries the engine
   builds the module embeds; see [Building](#building).

2. Put a `stash` tag on every exported field of the struct, and a `go:generate`
   comment beside it.

   ```go
   //go:generate go tool stashgen -type User
   type User struct {
   	_     struct{} `stash:"context=users"`
   	ID    int64    `stash:"id,passthrough"`
   	Email string   `stash:"email,encrypt_into=TextEq"`
   	Name  string   `stash:"name,encrypt_into=TextMatch"`
   	Age   int32    `stash:"age,encrypt_into=Integer"`
   }
   ```

   `encrypt_into=` names the EQL type the field is stored as. The Go field
   type must match it; see [EQL columns](#eql-columns).

3. Run the generator. It writes `user_stash.go` beside the struct.

   ```sh
   go generate ./...
   ```

4. Commit the generated file.

5. Call the generated functions where you write and read.

   ```go
   client, err := encrypt.NewClient(ctx)
   if err != nil {
   	return err
   }
   defer client.Close()
   cipher := client.Keyset(encrypt.KeysetName("tenant-42"))

   encrypted, err := users.Encrypt(ctx, cipher, people)
   opened, err := users.Decrypt(ctx, cipher, encrypted)
   term, err := users.Fields.Email.Eq(ctx, cipher, "bob@example.com")
   ```

   `Encrypt` and `Decrypt` send one ZeroKMS request for each 500 sealed
   values in the batch, plus one request the first time a keyset is used.
   A query derives its term locally and sends no request of its own; only
   the first use of a keyset, by a query or anything else, loads it from
   ZeroKMS. See [Queries](#queries).

6. Store the encrypted type. Each `encrypt_into` field is one EQL v4 column:
   `eql.TextEq` implements `driver.Valuer` and `sql.Scanner`, so a database
   library binds and scans it as the JSON a `public.eql_v4_text_eq` column
   holds. Install EQL v4 into PostgreSQL first, with the
   `eql-v4-install.sql` attached to the release. A query casts its parameter
   to the column's query type:

   ```sql
   SELECT id, email, name, age FROM users WHERE email = $1::eql_v4.query_text_eq
   ```

   A field tagged `encrypt` or `index=` stores its ciphertext and each term
   as separate byte columns instead; see [What is stored](#what-is-stored).

7. Run the generator again after each change to the struct or to a tag. A
   change to the fields of the struct stops the build until you do.

8. In CI, run the generator and fail when a generated file changes.

   ```sh
   go generate ./... && git diff --exit-code && test -z "$(git status --porcelain)"
   ```

   `git diff` sees only files git already tracks; the `git status` check
   also fails on a generated file that was never committed.

The rest of this file is the reference. [`example/`](example/) is a program
that stores separate byte columns (`index=`) against real ZeroKMS.

## Connect

A `Client` is one ZeroKMS client: its client key, its default keyset, and the
keysets it has loaded since. Make one per process and share it; it is safe
for concurrent use.

```go
client, err := encrypt.NewClient(ctx)
if err != nil {
    return err // encrypt.ErrNoCredentials: nothing configured
}
defer client.Close()
```

`ctx` is Go's `context.Context`: the deadline and cancellation for the one
ZeroKMS round trip `NewClient` makes. It has nothing to do with an
*encryption* context, which is what a field is sealed under; that is the
`context=` tag.

Every other setting is a functional option with a default:

```go
client, err := encrypt.NewClient(ctx,
    encrypt.WithCredentials(encrypt.OIDCFederation(crn, provider)),
    encrypt.WithTransport(rt),
    encrypt.WithKeysetCacheSize(64),
    encrypt.WithRequireLockedMemory(),
)
```

### Credentials

`AutoCredentials`, the default, reads the environment first
(`CS_CLIENT_ACCESS_KEY` and `CS_WORKSPACE_CRN` for the token, `CS_CLIENT_ID`
and `CS_CLIENT_KEY` for the key), then the developer profile `stash auth login`
writes, through the [`auth`](../auth) package. `NewCredentials` takes a client
id, a client key and an `auth` strategy explicitly; `OIDCFederation` mints the
token from an identity provider's. No credentials take a raw token. The client
key is consumed by `NewClient` and wiped, whatever the outcome.

## The cipher

A `Cipher` is the client bound to one keyset, and to any extension of the
context. Every generated function takes one.

```go
cipher := client.Keyset(encrypt.KeysetName("tenant-42")).Extend("tenant-42")
```

`Extend` appends to the context that the tags declare, for every field, in
every call through the cipher: the write, the query and the read. A row
written through `Extend("tenant-42")` opens and matches only through a cipher
with the same extension. No call takes a keyset or a context, so the three
cannot use different ones.

> **Take care**
>
> The context binds each value to its table, its column and the cipher's
> extension. It does not bind the value to its row, so a value copied to
> another row of the same table decrypts there with no error. To bind each
> row to a context of its own, such as its tenant, give the struct a
> `context_field` instead of a `context=` tag:
>
> ```go
> type Note struct {
> 	Tenant string `stash:"tenant,context_field"`
> 	Text   string `stash:"text,encrypt,index=equality"`
> }
> ```
>
> The field's value is the context every other field is sealed under, a
> label such as `"tenants/acme"`. It is stored as it is, in the clear and
> unauthenticated like a passthrough field, so the row names its own
> context. A row's sealed values open only under the context the row
> stores: a value copied to another tenant's row does not decrypt there.
> `Encrypt` and `Decrypt` take each row's context from the row.
> `cipher.Context("tenants/acme")` names the context every row through the
> cipher is under: `Decrypt` then refuses a row stored under another tenant
> with `ErrContextMismatch`, before any key is retrieved, and `Encrypt`
> refuses a value whose field says otherwise. A query on such a type derives
> its term under the context the cipher names, and fails without one.

`Client.DefaultKeyset()` is the keyset a ZeroKMS administrator set for the
client; `Client.Keyset(encrypt.KeysetName(..))` or `Client.Keyset(id)` any
other, loaded on first use. `Cipher.KeysetID(ctx)` resolves it.

## Reading

`users.Decrypt` takes a `Decrypter`: the `*Cipher`, which refuses a row
another keyset sealed with `ErrForeignKeyset` before any key is retrieved, or
the `*Client`, which opens each row under the keyset that sealed it. The
`*Client` opens only rows that a cipher with no extension sealed; a row
written through `Extend` opens only through a cipher with the same extension.
For a type with a `context_field`, the `*Cipher` from `cipher.Context(..)`
also refuses a row whose stored context is another, with
`ErrContextMismatch`; the `*Client` opens each row under the context it
stores.

## What is stored

A field with `encrypt` and `index=` is a struct with one field for each
output: `Ciphertext` (`encrypt.Ciphertext`, the frozen stack-encrypt leaf),
and `Equality`, `Match`, `Ore` or `Ope` (the term types). A field with
`encrypt` alone has `Ciphertext` only. A passthrough field keeps its Go type.
An `opaque` struct is one `Sealed` field. Every stored type implements
`driver.Valuer` and `sql.Scanner`.

A `match` index stores text with no token (an empty string, separator-only
text, or text shorter than the n-gram length of 3 characters) as the empty
filter: a valid value that no query matches, so an optional or short value can
live under `match`. The empty filter tells anyone who can read the column that
the value is one of those. A match *query* of such text is refused with
`ErrTerm`, because an empty filter as a query would match every row. An EQL
`TextMatch` field is stricter, as "EQL columns" below says.

Terms are byte-equal to the ones the Rust crate derives, so a term from
`users.Fields.Email.Eq` compares against a stored term written from any
language. `EqualityTerm.Equal` compares in constant time; `OreTerm.Compare`
and `OpeTerm.Compare` order as the plaintexts; `MatchTerm.Positions` decodes
the token positions.

A database can compare some terms by itself:

- `Equality`: compare with `=`.
- `Ope`: compare with `<`, `>` and `ORDER BY`. The byte order is the
  plaintext order.
- `Ore`: do not compare in SQL. Plain byte order is almost always right, and
  sometimes wrong, with no error. Compare in Go with `OreTerm.Compare`, or
  use an EQL type (`encrypt_into=`), which the database compares correctly.
- `Match`: a row matches when its stored filter holds every position of the
  query's term. Decode both into positions in SQL and compare with `@>`, as
  [Queries](#queries) shows, or in Go with `MatchTerm.Positions`.

## Queries

Each sealed field's entry in `Fields` has one method for each operator the
engine answers on the field: `Eq`, `Lt`, `Lte`, `Gt`, `Gte`, `Between` and
`Matches`. A field has no method for an operator it does not answer, so such
a query does not compile. The generator asks the engine which operators each
field answers, and which index answers each one; it holds no copy of those
rules.

| The field declares | Methods | Each returns |
|---|---|---|
| `index=equality` | `Eq` | `encrypt.EqualityTerm` |
| `index=ore` or `index=ope`, on an integer | `Lt`, `Lte`, `Gt`, `Gte` | `encrypt.OreTerm`, or `encrypt.OpeTerm` when the field declares no `ore` |
| the same | `Between(ctx, cipher, lo, hi)` | `encrypt.Range[encrypt.OreTerm]` or `encrypt.Range[encrypt.OpeTerm]`, the two bounds' terms |
| `index=match`, on a string | `Matches` | `encrypt.MatchQuery[T]` |
| `encrypt_into=TextEq` | `Eq` | `eql.TextEqQuery` |
| `encrypt_into=TextMatch` | `Matches` | `encrypt.EQLMatchQuery[eql.TextMatchQuery, T]` |

A method takes the field's own Go type, so `Fields.Age.Lt` on a `uint32`
field takes a `uint32`. An order index on text, bytes or a float stores its
term but answers no ordering operator yet, so such a field has no `Lt`; nor
does the `ope` index of a field that declares `ore` too, since `ore` answers
the orderings. stashgen prints a notice for each such index, on stderr and in
the generated file: the terms are stored, and only your own code can compare
them. A match index on an index-only field (`index=match` with no `encrypt`)
is refused, because `Verify` checks a match query's rows by decrypting them.

Every query type implements `driver.Valuer`, so it binds as a parameter in
any library built on `database/sql` or pgx. A `Range` binds as two
parameters, `Low` and `High`.

`Eq`, the orderings and `Between` are exact: the server's answer is the
answer. `Matches` is probabilistic: the server answers with every row whose
stored filter holds the query's bits, which can include rows that do not
hold the query's text. So `MatchQuery` carries two more methods, and an
exact query's type carries neither (on an `encrypt_into=TextMatch` field,
`Matches` returns an `encrypt.EQLMatchQuery`, the `eql.TextMatchQuery`
operand with the same two):

- `TargetLimit(ctx, want, stats)` is how many rows to fetch for `want` of
  them to verify. A field declared with tags states no expected number of
  tokens, so with no measured histogram of the stored filters in
  `encrypt.Stats` the limit is unbounded, and `Limit.FetchOr(page)` fetches
  a page.
- `Verify(ctx, values)` says, for each decrypted value of a page, whether it
  really holds the query's text: one call into the engine for the page, with
  no key.

The example below uses separate byte columns, as [`example/`](example/)
declares its fields (`Email` with `stash:"email,encrypt,index=equality;match"`,
`Age` with `stash:"age,encrypt,index=equality;ore"`), not the `encrypt_into`
`User` of the quick start:

```go
// Positions of a stored filter or a match term, for @>.
const positions = `CREATE FUNCTION match_positions(term bytea) RETURNS int[]
LANGUAGE sql IMMUTABLE STRICT AS $$
  SELECT coalesce(array_agg(get_byte(term, 2 * i) | (get_byte(term, 2 * i + 1) << 8)), '{}')
  FROM generate_series(0, length(term) / 2 - 1) AS i
$$`

q, err := users.Fields.Email.Matches(ctx, cipher, "alice")
limit, err := q.TargetLimit(ctx, 10, encrypt.Stats{Rows: rowCount})

rows, err := db.QueryContext(ctx, `
	SELECT id, email, email_eq, email_match, age, age_eq, age_ore FROM users
	WHERE match_positions(email_match) @> match_positions($1)
	ORDER BY id LIMIT $2`, q, limit.FetchOr(50))
// scan each row into a users.Encrypted, then
people, err := users.Decrypt(ctx, cipher, encrypted)
emails := make([]string, len(people))
for i, p := range people {
	emails[i] = p.Email
}
verified, err := q.Verify(ctx, emails)
hits := people[:0]
for i, p := range people {
	if verified[i] {
		hits = append(hits, p)
	}
}
```

`Verify` cuts the query's text into tokens again in the engine, with the
field's own tokenizer, so a `MatchQuery` keeps that text for as long as the
program holds the query. Go cannot wipe a string: the text stays in memory
until the garbage collector reclaims it, as the string you passed in does.
A `MatchQuery` never prints it; `fmt`, `slog` and `%#v` show the field and
the size of the term only.

## Errors

The generator and the compiler find a mistake in a declaration, so no call
returns an error for one. A call returns an error for a key, for the network,
or for stored data. Check an error two ways.

`errors.Is` tells you the kind, which is what a program branches on:

- `ErrForeignKeyset`: a `*Cipher` got a row another keyset sealed.
- `ErrContextMismatch`: a `*Cipher` with a `Context` got a row whose
  `context_field` names another context, or a value whose field does.
- `ErrForbidden`, `ErrAuthentication`: a ciphertext that does not open under
  its field's context (ZeroKMS refuses the key, or the AEAD fails).
- `ErrEncoding`: a stored value or a call that does not fit the declaration.
- `ErrUnauthorized`, `ErrNotFound`, `ErrTransport`, `ErrKMS`: ZeroKMS.
- `ErrState`: a call on a closed client. `ErrMemoryLock`: see below.

`errors.As` with a `*Diagnostic` gives you the detail behind a failure the
engine reports: a stable `Code` (`stack_encrypt::foreign_keyset`,
`stack_kms::keyset_not_found`, ...), the one-line `Message` that `Error()`
returns after the kind's text, `Help` saying what to do about it, `Fields` (structured values, by
name) and `Causes` (the errors behind it). Accessors read the values a program
is likely to branch on:

```go
var d *encrypt.Diagnostic
if errors.As(err, &d) {
    log.Printf("%s: %s (%s)", d.Code, d.Message, d.Help)
    if expected, ok := d.ExpectedKeyset(); ok {
        found, _ := d.FoundKeyset()
        log.Printf("cipher is bound to %s; the row was sealed under %s",
            encrypt.KeysetID(expected), encrypt.KeysetID(found))
    }
}
```

`Field` and `Reason` name the field and the problem (`field_missing`,
`unknown_key`, ...) on a refused plan, record or value. An error the client
raises itself carries no `Diagnostic`: a closed client, a guest that did not
return, `ErrMemoryLock`, and an argument refused before it reached the engine.

What an error may contain is fixed. It may carry keyset ids and names, field
names, counts, index kinds, ZeroKMS request kinds and HTTP statuses. It never
carries a plaintext value, key material, a token, ciphertext or term bytes, or
the values of an encryption context. No warning or log line holds a plaintext
value either. A generated type hides its sealed fields when a program prints
or logs it; the struct you wrote does not, and `stashgen -redact` writes
`String` and `LogValue` for it.

## Key material

Every key the guest holds lives in the guest's linear memory, which this
package supplies: reserved once, locked in RAM and excluded from core dumps
where the platform allows, and wiped before it is released. The lock is best
effort (`RLIMIT_MEMLOCK` is 64 KiB on many Linux hosts); `Client.MemoryLocked`
reports it, `Client.MemoryLockError` says why not, and
`WithRequireLockedMemory` makes `NewClient` refuse to start unlocked. See the
package documentation for the full account.

## EQL columns

A field tagged `encrypt_into=TextEq` is stored as one EQL value, the JSON
PostgreSQL holds in a `public.eql_v4_text_eq` column, as an `eql.TextEq`
from package `encrypt/eql`. Stack Encrypt writes EQL v4, the `eql_v4` install
of EQL's SQL; the `eql_v3` columns the TypeScript SDK writes hold
cipherstash-client's terms, which these never match. Install EQL v4 into
PostgreSQL first, with the `eql-v4-install.sql` attached to each Go release
(`psql -f eql-v4-install.sql`); `stash eql install` installs EQL v3 only, and
an `eql_v4_*` column needs the v4 domains.

The EQL types the engine produces, and the Go field types each takes:

| EQL type | Go field | Queries |
|---|---|---|
| `TextEq` | `string` | `=`, `<>` |
| `TextMatch` | `string` | `@@` (substring match, 3-grams, case-insensitive) |
| `Text` | `string` | none: stored and read only |
| `Integer` | `int32` | none |
| `IntegerEq` | `int32` | `=`, `<>` |
| `Bigint` | `int64` | none |
| `BigintEq` | `int64` | `=`, `<>` |
| `Boolean` | `bool` | none |
| `Real` | `float32` | none |
| `RealEq` | `float32` | `=`, `<>` |
| `Double` | `float64` | none |
| `DoubleEq` | `float64` | `=`, `<>` |

A `TextMatch` value must be at least three characters long: shorter text has
no 3-grams to index and is refused. The number equality types compare as
PostgreSQL compares the plain types: an integer equals itself whatever its
width, and for floats `-0.0 = 0.0` and `NaN = NaN`; the stored value still
decrypts to exactly what was written. The rest of
the catalog (ordering, dates, decimals, JSON) is listed in
`eql.Types` with the reason it is not produced yet, and `stashgen` refuses it
with that reason. The guest builds the value: the generated code
imports `encrypt/eql`, which embeds the build of the engine that holds the
EQL types and registers it on import, so the program runs that build and
stores what it returns. `Fields.Email.Eq` returns the `eql.TextEqQuery`
the column's `eql_v4.query_text_eq` operand takes; `TextEq` answers `eq`
alone, and a `TextMatch` field's `Matches` returns an
`encrypt.EQLMatchQuery`: the `eql.TextMatchQuery` operand with `Verify` and
`TargetLimit`. `mise run
wasm:guest:build:eql` builds that guest beside the other. A cipher extended
with a tenant part refuses a struct with an `encrypt_into` field: an EQL
value is stored under a table and a column, and the extended label has no
column.

## Building

The package embeds `wasm/stack_encrypt_guest.wasm`, a build artefact of the
Rust crate in [`guest/`](guest/), and package `encrypt/eql` embeds the EQL
build beside it. A tagged version of the module (such as `v0.1.0-alpha.1`, as
`go get` resolves it) carries both builds and the credential guest: the
release workflow commits them to the commit the tag names, so a module that
requires a tagged version needs no Rust toolchain and no build step. A
pseudo-version does not. `go get ...@main`, or any commit rather than a
tag, fetches a tree without the builds; it compiles, and `NewClient` returns
`ErrGuestNotBuilt`.

In a checkout of this repository the builds are not committed: run
`mise run wasm:guest:build` (and `mise run wasm:auth-guest:build` for the
credential guest) before `go test`, and
`mise run wasm:guest:build:deterministic` for the test build the hermetic
round-trip and fixture tests use. Without the builds `NewClient` returns
`ErrGuestNotBuilt` and the tests skip.

## Licence

The Go code in this module is MIT-licensed ([`LICENSE`](../LICENSE)). The
WASI guests it embeds are compiled from Rust crates that are not: the
stack-encrypt guest and its EQL build are compiled from `stack-encrypt`,
`stack-kms`, `stack-auth`, `stack-profile` (a dependency of `stack-auth`) and
`stack-guest-abi`, which are licensed under the
[PolyForm Internal Use License 1.0.0](https://polyformproject.org/licenses/internal-use/1.0.0).
Those terms allow use for your internal business operations only. Each
crate's `LICENSE` in the
[CipherStash Stack repository](https://github.com/cipherstash/stack/tree/main/packages)
has the full text.
