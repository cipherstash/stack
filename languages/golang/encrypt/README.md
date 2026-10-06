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

1. Add the generator to your module. This needs Go 1.24 or later.

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
   defer client.Close()
   cipher := client.Keyset(encrypt.KeysetName("tenant-42"))

   encrypted, err := users.Encrypt(ctx, cipher, people)  // one ZeroKMS request
   people, err := users.Decrypt(ctx, cipher, encrypted)
   term, err := users.Fields.Email.Equality(ctx, cipher, "bob@example.com")
   ```

6. Store the encrypted type. Each field is one or more byte columns, so
   `database/sql`, pgx, sqlx and GORM take it as it is:
   `e.Email.Ciphertext`, `e.Email.Equality`, `e.Email.Match`.

7. Run the generator again after each change to the struct or to a tag. A
   change to the fields of the struct stops the build until you do.

8. In CI, run the generator and fail when a generated file changes.

   ```sh
   go generate ./... && git diff --exit-code
   ```

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

`Client.DefaultKeyset()` is the keyset a ZeroKMS administrator set for the
client; `Client.Keyset(encrypt.KeysetName(..))` or `Client.Keyset(id)` any
other, loaded on first use. `Cipher.KeysetID(ctx)` resolves it.

## Reading

`users.Decrypt` takes a `Decrypter`: the `*Cipher`, which refuses a row
another keyset sealed with `ErrForeignKeyset` before any key is retrieved, or
the `*Client`, which opens each row under the keyset that sealed it.

## What is stored

A field with `encrypt` and `index=` is a struct with one field for each
output: `Ciphertext` (`encrypt.Ciphertext`, the frozen stack-encrypt leaf),
and `Equality`, `Match`, `Ore` or `Ope` (the term types). A field with
`encrypt` alone has `Ciphertext` only. A passthrough field keeps its Go type.
An `opaque` struct is one `Sealed` field. Every stored type implements
`driver.Valuer` and `sql.Scanner`.

Terms are byte-equal to the ones the Rust crate derives, so a term from
`users.Fields.Email.Equality` compares against a stored term written from any
language. `EqualityTerm.Equal` compares in constant time; `OreTerm.Compare`
and `OpeTerm.Compare` order as the plaintexts; `MatchTerm.Positions` decodes
the token positions.

## Errors

The generator and the compiler find a mistake in a declaration, so no call
returns an error for one. A call returns an error for a key, for the network,
or for stored data; read them with `errors.Is`:

- `ErrForeignKeyset`: a `*Cipher` got a row another keyset sealed.
- `ErrForbidden`, `ErrAuthentication`: a ciphertext that does not open under
  its field's context (ZeroKMS refuses the key, or the AEAD fails).
- `ErrEncoding`: a stored value or a call that does not fit the declaration.
- `ErrUnauthorized`, `ErrNotFound`, `ErrTransport`, `ErrKMS`: ZeroKMS.
- `ErrState`: a call on a closed client. `ErrMemoryLock`: see below.

No error, warning or log line holds a plaintext value. A generated type hides
its sealed fields when a program prints or logs it; the struct you wrote does
not, and `stashgen -redact` writes `String` and `LogValue` for it.

## Key material

Every key the guest holds lives in the guest's linear memory, which this
package supplies: reserved once, locked in RAM and excluded from core dumps
where the platform allows, and wiped before it is released. The lock is best
effort (`RLIMIT_MEMLOCK` is 64 KiB on many Linux hosts); `Client.MemoryLocked`
reports it, `Client.MemoryLockError` says why not, and
`WithRequireLockedMemory` makes `NewClient` refuse to start unlocked. See the
package documentation for the full account.

## Building

The package embeds `wasm/stack_encrypt_guest.wasm`, a build artefact of the
Rust crate in [`guest/`](guest/). It is not committed: run
`mise run wasm:guest:build` (and `mise run wasm:auth-guest:build` for the
credential guest) before `go test`, and
`mise run wasm:guest:build:deterministic` for the test build the hermetic
round-trip and fixture tests use. Without the builds `NewClient` returns
`ErrGuestNotBuilt` and the tests skip.
