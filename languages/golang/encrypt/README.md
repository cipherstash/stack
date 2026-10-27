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

1. Add the generator to your module. This needs Go 1.26.10 or later (or 1.27.3 or later on 1.27):
   those are the first releases whose `crypto/x509` blocks the compromised eMudhra intermediate CAs
   ([CVE-2026-111943](https://github.com/golang/go/issues/82345)).
   The module's `go` line requires 1.26.10, so under the default `GOTOOLCHAIN=auto` an older local Go downloads and switches to 1.26.10.
   A minimum cannot exclude 1.27.0 to 1.27.2, which are also vulnerable: do not build with those.

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
for concurrent use. The guest runs one call at a time, but never holds the
client across a ZeroKMS round trip: a call that needs ZeroKMS hands its
request to the client, which performs it with the client free for other
callers, and then carries on. A call whose context ends while its request
is in flight returns the context's error and leaves the client open.

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

Every call takes a `ctx` too, and a call whose `ctx` is cancelled or passes
its deadline fails with the context's error. Only that call fails: one
request giving up never closes the shared client for the others.

- A call waiting for the client (it runs one call at a time) leaves the
  queue when its `ctx` ends, and never starts.
- A call waiting on ZeroKMS has that request cancelled. Its error matches
  both `context.Canceled` or `context.DeadlineExceeded` and `ErrTransport`.
- A call waiting on its auth strategy for a token returns too, with the
  context's error. If the strategy is refreshing a device session, the
  refresh finishes in the background, for up to 10 seconds. The service
  rotates the refresh token when it answers, and dropping that answer
  would leave the strategy unable to refresh.

A client closes itself, and every later call returns `ErrState`, only when
the guest's state is unknown: the guest trapped, or a call ran on for 30
seconds after its `ctx` ended, which means a bug. A service that sees
`ErrState` from a client it did not close builds a new one.

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

An access-key strategy takes `auth.NewAccessKey(ownedBytes)`; creating the
strategy consumes and wipes those bytes on success or failure.
`strategy.Token(ctx)` returns a bearer string. Pass the strategy to
`NewCredentials`; the encryption client uses it directly, without requiring
the metadata returned by `strategy.ServiceToken(ctx)`. Token signatures and
permissions are checked by the service, not by the SDK.
The caller owns that strategy and its store, and closes both after the client.

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

A sealed field outside an opaque struct is one value of one of these types,
or a type defined over one (`type Email string`):

| Go field | Seals as | Indexes it can store | Query methods |
|---|---|---|---|
| `string` | text | `equality`, `match`, `ore`, `ope` | `Eq`, `Matches`, `Lt`, `Lte`, `Gt`, `Gte`, `Between` |
| `[]byte` | bytes | `equality`, `ore`, `ope` | `Eq` |
| `bool` | a boolean | none | none |
| `int16`, `int32`, `int64`, `int` | an integer of the field's own width (`int` is 64-bit) | `equality`, `ore`, `ope` | `Eq`, `Lt`, `Lte`, `Gt`, `Gte`, `Between` |
| `uint16`, `uint32`, `uint64`, `uint` | the same, unsigned | `equality`, `ore`, `ope` | the same |
| `int8`, `uint8` (`byte`) | an 8-bit integer | `equality` | `Eq` |
| `encrypt.Int128`, `encrypt.Uint128` | a 128-bit integer | `equality`, `ore`, `ope` | the same |
| `float32`, `float64` | a float of its width | `equality`, `ore`, `ope` | `Eq`, `Lt`, `Lte`, `Gt`, `Gte`, `Between` |
| `encrypt.Decimal` | a decimal: a 96-bit coefficient and a scale up to 28 | `equality` | `Eq` |
| `encrypt.Date` | a calendar date | `equality` | `Eq` |
| `time.Time` | a timestamp, to the nanosecond, in UTC | `equality` | `Eq` |

Each query method needs its index declared. An `ore` or `ope` index on bytes
stores its term, but the engine answers no ordering through it, so such a
field has no `Lt` (see [Queries](#queries)).

`encrypt.Date`, `Int128`, `Uint128` and `Decimal` are vitaminc's `vcvalue`
types; build them with `encrypt.DateOf`, `ParseInt128`, `ParseUint128` and
`ParseDecimal` (which refuses NaN and the infinities). A `time.Time` opens in
UTC: compare it with `Equal`, not `==`. A decimal opens at the scale it was
sealed with, but a zero has no sign: `-0.00` opens as `0.00`. The zero
`encrypt.Date` is not a date, and `Encrypt` or a query refuses it with
`ErrEncoding`, naming the field; so is a decimal or a `time.Time` outside
vitaminc's range. A sealed field cannot be a pointer, so an optional date has
no sealed form yet: keep it in an opaque struct, or use a sentinel date. Each integer type seals at its own
width, and each width is passed to the order scheme as itself, so an `int16`
field's terms are an `int16`'s. An `int8` or `uint8` field has no order
index: with 256 values, an order term would rank every row among 256, which
a few known rows resolve to the values, as a `bool`'s would say which rows
are true. Equality follows vitaminc's normalisation: an
integer equals itself at every width, decimals compare at any scale
(`1.50 = 1.5`), and a timestamp compares to the microsecond, truncated, never rounded. An order index on
a decimal, date or timestamp is refused for now: the engine derives no
order term for those kinds yet.

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
| `index=ore` or `index=ope`, on an integer of 16 bits or wider or a string | `Lt`, `Lte`, `Gt`, `Gte` | `encrypt.OreTerm`, or `encrypt.OpeTerm` when the field declares no `ore` |
| the same | `Between(ctx, cipher, lo, hi)` | `encrypt.Range[encrypt.OreTerm]` or `encrypt.Range[encrypt.OpeTerm]`, the two bounds' terms |
| `index=match`, on a string | `Matches` | `encrypt.MatchQuery[T]` |
| `encrypt_into=TextEq` | `Eq` | `eql.TextEqQuery` |
| `encrypt_into=TextMatch` | `Matches` | `encrypt.EQLMatchQuery[eql.TextMatchQuery, T]` |

A method takes the field's own Go type, so `Fields.Age.Lt` on a `uint32`
field takes a `uint32`.

Text orders by its folded form (ADR-0002): case and accents are folded and
`ß` becomes `ss`, under Unicode 16. So `Café`, `cafe` and `CAFÉ` are one
value and tie, `alice` orders before `Zoe`, and `é` orders with `e`, not
after `z`. `Between` is inclusive at both ends and, as SQL's `BETWEEN`,
does not refuse a range whose low bound is above its high bound: such a
range matches nothing. So `Between("b", "A")` matches nothing, since `A`
folds to `a`, below `b`. Text holding a code point Unicode 16 does not assign has no
fold, and its query or write is refused with `encrypt.ErrTerm`.

Floats order as PostgreSQL's `float8` does (ADR-0002): `-0.0` and `0.0` are
one value, and every NaN is one value, above `+Inf`, so `Between(math.NaN(),
math.Inf(1))` matches nothing. A `float32` orders as the `float64` it
widens to.

An order index on bytes stores its term but answers no ordering
operator, so such a field has no `Lt`; nor does the `ope` index of a field
that declares `ore` too, since `ore` answers the orderings. stashgen prints a notice for each such index, on stderr and in
the generated file: the terms are stored, and only your own code can compare
them. A match index on an index-only field (`index=match` with no `encrypt`)
is refused, because `Verify` checks a match query's rows by decrypting them.

Every query type implements `driver.Valuer`, so it binds as a parameter in
any library built on `database/sql` or pgx. A `Range` binds as two
parameters, `Low` and `High`. On an EQL column a range is one value instead:
package `encrypt/eql` has a range query type per ordered family and order
index (`eql.IntegerRangeOreQuery`, `eql.TextRangeOpeQuery`, ...), the one
operand of `eql_v4.between(column, $1::eql_v4.query_integer_range_ore)`. Keep
the cast to the exact range domain: an uncast `$1`, a `jsonb` parameter, or a
range of another term or family fails with SQLSTATE 42725 ("function ... is
not unique"), unlike the single-bound operators, which resolve an untyped
`$1`. The ordered EQL types are producible, but `stashgen` does not yet
generate a `Between` method or construct these range query values. Their
generated fields expose the four single-bound comparisons.

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
- `ErrState`: a call on a closed client: you closed it, or the guest
  trapped or ran on long after a call's context ended (see Connect).
  `ErrMemoryLock`: see below.
- `context.Canceled`, `context.DeadlineExceeded`: the call's `ctx` ended.
  The client is still open.

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
| `TextMatch` | `string` | `@@` (3-grams and whole two-letter words, case-insensitive; see below) |
| `TextOrd`, `TextOrdOpe`, `TextOrdOre` | `string` | `=`, `<>`, `<`, `<=`, `>`, `>=`, `ORDER BY` |
| `TextSearch`, `TextSearchOre` | `string` | `=`, `<>`, `<`, `<=`, `>`, `>=`, `ORDER BY`, `@@` |
| `Text` | `string` | none: stored and read only |
| `Smallint` | `int16`, or any Go integer type (see below) | none |
| `SmallintEq` | the same | `=`, `<>` |
| `SmallintOrd`, `SmallintOrdOpe`, `SmallintOrdOre` | the same | `=`, `<>`, `<`, `<=`, `>`, `>=`, `ORDER BY` |
| `Integer` | `int32`, or any Go integer type (see below) | none |
| `IntegerEq` | the same | `=`, `<>` |
| `IntegerOrd`, `IntegerOrdOpe`, `IntegerOrdOre` | the same | `=`, `<>`, `<`, `<=`, `>`, `>=`, `ORDER BY` |
| `Bigint` | `int64`, or any Go integer type | none |
| `BigintEq` | the same | `=`, `<>` |
| `BigintOrd`, `BigintOrdOpe`, `BigintOrdOre` | the same | `=`, `<>`, `<`, `<=`, `>`, `>=`, `ORDER BY` |
| `Boolean` | `bool` | none |
| `Real` | `float32` | none |
| `RealEq` | `float32` | `=`, `<>` |
| `RealOrd`, `RealOrdOpe`, `RealOrdOre` | `float32` | `=`, `<>`, `<`, `<=`, `>`, `>=`, `ORDER BY` |
| `Double` | `float64` | none |
| `DoubleEq` | `float64` | `=`, `<>` |
| `DoubleOrd`, `DoubleOrdOpe`, `DoubleOrdOre` | `float64` | `=`, `<>`, `<`, `<=`, `>`, `>=`, `ORDER BY` |
| `Date` | `encrypt.Date` | none |
| `DateEq` | `encrypt.Date` | `=`, `<>` |
| `DateOrd`, `DateOrdOpe`, `DateOrdOre` | `encrypt.Date` | `<`, `<=`, `>`, `>=`, `ORDER BY` |
| `Timestamp` | `time.Time` | none |
| `TimestampEq` | `time.Time` | `=`, `<>` (to the microsecond, truncated) |
| `TimestampOrd`, `TimestampOrdOpe`, `TimestampOrdOre` | `time.Time` | `<`, `<=`, `>`, `>=`, `ORDER BY` |
| `Numeric` | `encrypt.Decimal` | none |
| `NumericEq` | `encrypt.Decimal` | `=`, `<>` (`1.5 = 1.50`) |
| `NumericOrd`, `NumericOrdOpe`, `NumericOrdOre` | `encrypt.Decimal` | `<`, `<=`, `>`, `>=`, `ORDER BY` |
| `JsonSearch` (`eql.JSONSearch`) | struct, map, slice, or `json.RawMessage` | containment, equality at a path, ordering at declared paths, selection, subtree reads; see [Encrypted JSON documents](#encrypted-json-documents) |

Any built-in Go integer field takes an integer EQL type (ADR-0002): the field
is sealed at the type's width, and opens back into the field's type. A type
every value of which fits (an `int16` or a `uint16` field for `Integer`, an
`int8` for `Smallint`)
always seals; a wider one (an `int64` or a `uint32` field for `Integer`) is
range checked value by value, and `Encrypt` refuses a value that does not fit
with `ErrEncoding`, naming the field's kind and not the value.
`encrypt.Int128` and `encrypt.Uint128` are not converted, and floats take
exactly their own width.

A `TextMatch` value is indexed by its 3-grams and by each two-letter word
whole, so a two-letter surname such as "Ng" is stored, and `Matches` with
"ng" finds the rows holding the word "Ng" ("Ng", "Mike Ng"), not "Nguyen".
A query's two-letter words must be whole words of the row, so "Mike Ng" does
not find "Mike Nguyen". The word token reveals one more token per two-letter
word, in the same filter: someone who clusters tokens across rows can tell
"Ng" from "Nguyen", where before only the trigram they share was visible.
Text that cuts no token, such as an empty string or one letter, is refused. A
`TextSearch` value of such text is stored with an empty match filter: `Eq`,
`Lt`, `Lte`, `Gt` and `Gte` find it through its other terms, and no
`Matches` query does. A `TextSearch` query carries only the term its
operator reads, so `Eq` and `Lt` on one-letter text work and `Matches` on it
is refused; EQL v4 raises if a query lacks the term its operator compares. The number
equality types compare as
PostgreSQL compares the plain types: an integer equals itself whatever its
width, and for floats `-0.0 = 0.0` and `NaN = NaN`; the stored value still
decrypts to exactly what was written. The same holds for the date,
timestamp and numeric types: `NumericEq` normalises the scale, so `1.5` and
`1.50` are equal, and `TimestampEq` compares to the microsecond, truncating
(never rounding) the nanoseconds below it, so two instants in one
microsecond are equal; each still opens as it was written, a
decimal with its scale and a `time.Time` with its nanoseconds, in UTC. A
`time.Time` is sealed as its instant, whatever its location. A zero
`encrypt.Date`, a date or instant outside years -262143 to 262142 and a
decimal with more than 28 digits after the point are refused with
`ErrEncoding`. Ordered dates compare by day, timestamps by the truncated
microsecond, and decimals by value (`1.5` ties `1.50`).

The `Ord` and `OrdOpe` types store an OPE term, which EQL compares as bytes,
and order by ADR-0002's order key: integers by value, floats as PostgreSQL's
`float8` sorts them (`-0.0` ties `0.0`, every NaN is one value after
`+Infinity`), text by its fold (case and accents folded, under Unicode 16).
A field gets `Lt`, `Lte`, `Gt` and `Gte`, and a text field `Eq` too; sort
with `ORDER BY eql_v4.ord_term(col)`. `ord_term` returns a `bytea` domain, so
a plain functional btree index, `CREATE INDEX ON t (eql_v4.ord_term(col))`,
serves `<`, `>` and `ORDER BY` with no operator class. That is why these
types work on an install without superuser rights, where the ORE operator
class is skipped. On a number column SQL's `=` compares
the order term; stashgen writes no `Eq` method for one yet, since the engine
answers `Eq` through an equality term only. A text order type also stores
`TextEq`'s equality term, and `=` reads that, so `Café` and `cafe` are
neither `<` nor `>` each other and not `=` either. Text holding a code point
Unicode 16 does not assign has no order term and is refused. There is no
generated `Between` method on these EQL fields yet, although EQL v4 has
range query domains and `eql_v4.between` for them.

The `OrdOre` types and `TextSearchOre` order by the same key, through a block
ORE term (ore-rs's 6-bit schemes) in place of the OPE term. Each term
carries a random nonce, so EQL v4's own comparator orders them, not their
bytes: sort with `ORDER BY eql_v4.ord_term_ore(col)`, and index with
`CREATE INDEX ON t USING btree (eql_v4.ord_term_ore(col))`. That index needs
the ORE operator class, which only a superuser install creates; elsewhere
the installer disables these domains, and the `Ord` types are the ones to
use. Text whose fold is longer than 1023 bytes, or ends in NUL, has no block
ORE term and is refused, stored or queried.

The catalog in `eql.Types` also lists EQL types the engine does not produce,
with the reason for each; `stashgen` refuses those types with that reason.
The guest builds a producible value: the generated code
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

### Encrypted JSON documents

`JsonSearch` stores a whole JSON document in one `public.eql_v4_json_search`
column, from a struct, map or slice field, or a `json.RawMessage`
(`stash:"profile,encrypt_into=JsonSearch(ordered=$.age)"`). See the
[stashgen reference](../cmd/stashgen/README.md#encrypted-json-documents) and
the [runnable typed-document example](example/json/README.md). A struct is
marshalled with `encoding/json` when it is
sealed and read back into its type when it is opened. Its numbers come back
exactly; the stashgen README lists what `encoding/json` does not keep
(invalid UTF-8, a nil map or slice, a time's zone). Unlike the types above,
a type defined over `json.RawMessage` (`type Doc json.RawMessage`) is
refused; an alias of it (`type Doc = json.RawMessage`) is accepted. One
entry per node is encrypted, so the database can test containment, equality
and ordering at a path, return one node with `->`, and walk a subtree,
without decrypting:

```go
q, err := users.Fields.Profile.Contains(ctx, cipher, map[string]any{"plan": "pro"})
rows, err := db.QueryContext(ctx, `SELECT id FROM users WHERE profile @> $1::eql_v4.query_json`, q)

read, err := users.Fields.Profile.Subtree(ctx, cipher, "$.visits[*].at", encrypt.JSONReadOptions{})
// SELECT e FROM users, eql_v4.json_tree_subtree(profile, $1::text[], 64) AS e WHERE id = $2
// with read.Tokens() as $1; collect each row's entries, then:
values, err := read.Open(ctx, entriesPerRow)
at, err := encrypt.DecodeJSON[int64](values[0][0])
```

A needle or a value is a `json.RawMessage` of JSON text, or any Go value
`encoding/json` writes. A document contains a needle when it holds every
member the needle writes, and `encoding/json` writes a zero struct field
that has no `omitempty`: that field narrows the query to documents holding
the zero. Give a needle struct pointer fields with `omitempty`, or use a
map. `Contains` refuses a needle of the field's own struct type for this
reason. Each value a read opens is JSON text, and `encrypt.DecodeJSON` reads
it into a Go type.

A selection or read opens rows only as answers to the request that prepared
it: the engine derives the selector or the read again from the field, the
path and the cipher's keyset, and refuses a row that is not one it asked
for. It does not prove the database returned every row, or rows of the
database row you meant. `encrypt.JSONTokens` binds as a `text[]` literal,
and a selector or token as `text`; cast each parameter, as above, so
PostgreSQL picks EQL's operator and not `jsonb`'s; a zero one is refused
rather than bound. A token is a capability over its node's subtree in every
row of the column, and a path's keys can be your customer's data, so
`JSONToken`, `JSONTokens`, `JSONSelection` and `JSONRead` print and log with
the tokens, the selector and the path redacted. A `JSONValue` holds the
plaintext a read opened, and prints it. Numbers order as `float64`,
so integers past 2^53 can tie at an ordered path; containment and `EqAt`
compare them exactly. At a wildcard path, `->` returns an unspecified
element of each row, so an ordering over every element is written over
`eql_v4.json_tree_path_query(col, $sel)`, its matches (the stashgen README
shows the SQL).

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
