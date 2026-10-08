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

2. Put a `stash` tag on every exported field of the struct, and a `go:generate`
   comment beside it.

   ```go
   //go:generate go tool stashgen -type User
   type User struct {
   	_     struct{} `stash:"context=users"`
   	ID    int64    `stash:"id,passthrough"`
   	Email string   `stash:"email,encrypt,index=equality;match"`
   	Age   uint32   `stash:"age,encrypt,index=equality;ore"`
   }
   ```

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
   term, err := users.Fields.Email.Equality(ctx, cipher, "bob@example.com")
   ```

   `Encrypt` and `Decrypt` send one ZeroKMS request for each 500 sealed
   values in the batch, plus one request the first time a keyset is used.

6. Store the encrypted type. Each sealed field is one or more byte columns:
   `e.Email.Ciphertext`, `e.Email.Equality`, `e.Email.Match`. `Ciphertext`
   and each term type implement `driver.Valuer` and `sql.Scanner`, so a
   database library binds and scans each column as bytes; map each one to
   its own column.

7. Run the generator again after each change to the struct or to a tag. A
   change to the fields of the struct stops the build until you do.

8. In CI, run the generator and fail when a generated file changes.

   ```sh
   go generate ./... && git diff --exit-code && test -z "$(git status --porcelain)"
   ```

   `git diff` sees only files git already tracks; the `git status` check
   also fails on a generated file that was never committed.

The rest of this file is the reference. [`example/`](example/) is the eight
steps as a program.

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

A `match` index needs text with at least one token. The engine derives no
match term for an empty string, separator-only text, or text shorter than the
n-gram length (3 characters), because an empty term would match every row.
`Encrypt` then fails for the whole batch with `ErrTerm`, naming the row, the
field and the index. So an optional or short value does not belong under
`match`: give such a field `equality` alone, or make the value required.

Terms are byte-equal to the ones the Rust crate derives, so a term from
`users.Fields.Email.Equality` compares against a stored term written from any
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
- `Match`: do not compare in SQL. Decode the positions in Go with
  `MatchTerm.Positions`, or use an EQL type.

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
PostgreSQL holds in a `public.eql_v3_text_eq` column, as an `eql.TextEq`
from package `encrypt/eql`. The guest builds the value: the generated code
imports `encrypt/eql`, which embeds the build of the engine that holds the
EQL types and registers it on import, so the program runs that build and
stores what it returns. `Fields.Email.Query` returns the `eql.TextEqQuery`
the column's `eql_v3.query_text_eq` operand takes. `mise run
wasm:guest:build:eql` builds that guest beside the other. A cipher extended
with a tenant part refuses a struct with an `encrypt_into` field: an EQL
value is stored under a table and a column, and the extended label has no
column.

## Building

The package embeds `wasm/stack_encrypt_guest.wasm`, a build artefact of the
Rust crate in [`guest/`](guest/). It is not committed: run
`mise run wasm:guest:build` (and `mise run wasm:auth-guest:build` for the
credential guest) before `go test`, and
`mise run wasm:guest:build:deterministic` for the test build the hermetic
round-trip and fixture tests use. Without the builds `NewClient` returns
`ErrGuestNotBuilt` and the tests skip.
