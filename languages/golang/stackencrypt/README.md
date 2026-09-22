# stack-encrypt for Go

Client-side encryption of values under per-value ZeroKMS data keys, and the
derivation of searchable index terms from the same values, for Go. The
`stack-encrypt` Rust crate is compiled to a WASI module and embedded in
this package; Go calls it through wazero, a pure-Go WebAssembly runtime,
so there is no cgo and no separate Go port of the cryptography.

The package reference is on [pkg.go.dev]; this README covers connecting,
what happens to key material, and the errors.

[pkg.go.dev]: https://pkg.go.dev/github.com/cipherstash/cipherstash-suite/bindings/go/stackencrypt

## Install

```sh
go get github.com/cipherstash/cipherstash-suite/bindings/go/stackencrypt
```

Go 1.25 or later.

## Connect

A `Client` is one ZeroKMS client: its client key, its default keyset, and
the keysets it has loaded since. Make one per process and share it; it is
safe for concurrent use.

```go
import (
    "context"
    "os"

    "github.com/cipherstash/cipherstash-suite/bindings/go/stackencrypt"
)

func run(ctx context.Context) error {
    client, err := stackencrypt.NewClient(ctx, stackencrypt.Config{
        ClientID:  os.Getenv("CS_CLIENT_ID"),
        ClientKey: stackencrypt.NewClientKey([]byte(os.Getenv("CS_CLIENT_KEY"))),
        Token:     stackencrypt.StaticToken(os.Getenv("CS_CLIENT_ACCESS_KEY")),
    })
    if err != nil {
        return err
    }
    defer client.Close()

    // ...
    return nil
}
```

`ctx` is Go's standard `context.Context`, and it means what it always
means: the deadline and cancellation for the work this call does.
`NewClient` makes one ZeroKMS round trip, to load the client's default
keyset, and `ctx` bounds that request. It has nothing to do with an
*encryption* context, which is the value a field is sealed under; that is
`stackencrypt.Context`. Every method that can reach ZeroKMS takes a
`context.Context` first, for the same reason.

`Token` supplies the bearer token for every request. `StaticToken` is the
simplest source; a `TokenFunc` can fetch or refresh one.

`ClientKey` is an opaque type, not a string: it prints a redaction under
every verb, so a logged `Config` never shows the key. `NewClientKey` takes
ownership of the slice it is given, and `NewClient` consumes the key —
whatever the outcome, even a config it refuses, the key is empty afterwards
and that slice is zero. A key is for one client; build another for another
client. What the SDK cannot reach is what the key was built *from*: the
`os.Getenv` string above is Go's, immutable, and lives until collected.
Read the key from the developer profile through `stackauth` where you can,
and where an environment variable is the source, treat the process
environment as holding the key for the life of the process.

### Key material in memory

The client key enters the instance once, in `NewClient`: it is marshalled
into the config buffer, the `ClientKey` is wiped, the guest copies the key
into its own memory, and the buffer is wiped. From then on the client key,
every loaded index key and every data key in use live in
the wasm instance's memory, and the package owns that memory rather than
leaving it to the runtime's default. It is reserved once and never moves,
so growth never copies a key to somewhere it is not wiped; it is locked in
RAM (`mlock`, `VirtualLock`) so it is never written to swap; on Linux it is
excluded from core dumps (`MADV_DONTDUMP`); and it is wiped before it is
released, on every release path. None of that waits for `Close`. A process
killed by SIGKILL, the OOM killer, a panic on another goroutine or `os.Exit`
runs no deferred call, and the kernel zeroes its pages before anyone else
sees them; the lock and the dump exclusion close the two places a copy
could otherwise outlive the process.

The lock is best effort. `RLIMIT_MEMLOCK` defaults to 64 KiB on many Linux
hosts and the instance is larger, so the lock is often refused, and the
client then runs with memory the kernel may swap out, which is all that is
lost, and nothing on a host without swap. `client.MemoryLocked()` reports
the outcome and `client.MemoryLockError()` names the limit to raise
(`ulimit -l`, a systemd `LimitMEMLOCK=`, a pod `securityContext`) and the
size the instance holds. For a deployment that would rather not start than
run unlocked, set `RequireLockedMemory` and `NewClient` fails with
`ErrMemoryLock`. That policy holds for the life of the client: memory the
instance later grows into must lock too, or the call that needed it fails
with `ErrMemoryLock`, so grant a limit with room to grow. A `Client` prints
its memory state with `%v` and logs it as a `slog` group, so a startup log
shows it.

Production checklist: assert `MemoryLocked()` at startup, or set
`RequireLockedMemory`. Handling `SIGTERM` for a graceful shutdown is
ordinary Go practice and worth doing for your own reasons; the SDK does not
depend on it and installs no signal handler of its own.

`Close` runs the guest's own shutdown, wiping every key in place before the
instance is released, and takes no context because it does no I/O. A
`Client` that becomes unreachable without `Close` is released by a runtime
cleanup, which covers the forgot-to-close case in a running process and
nothing at exit.

## Errors

Errors are sentinel values, matched with `errors.Is`. The wasm guest
reports a status code and nothing else, so the vocabulary is deliberately
small and reveals nothing about plaintext or key material.

| Error | Meaning |
|---|---|
| `ErrAuthentication` | A ciphertext failed to open: tampered, or presented under the wrong context or element derivation. |
| `ErrForbidden` | ZeroKMS refused the request. Also the production form of a wrong-context open, because every data key is bound to its context. |
| `ErrUnauthorized` | ZeroKMS rejected the bearer token: invalid, expired, or for another workspace. |
| `ErrNotFound` | Unknown keyset name or id, or a missing data key. |
| `ErrForeignKeyset` | A keyset-bound `Cipher` was given another keyset's ciphertext. Open it through the `Client`. |
| `ErrEncoding` | Malformed input: a value, ciphertext, plan, context or config refused before any cryptography. |
| `ErrTerm` | A term could not be derived, for example match text that yields no tokens. |
| `ErrTransport` | ZeroKMS could not be reached. |
| `ErrKMS` | Any other ZeroKMS failure. |
| `ErrConflict` | ZeroKMS reported a resource conflict. |
| `ErrState` | The client has been closed: by `Close`, by a call its context interrupted, or by a guest trap. |
| `ErrMemoryLock` | The instance's memory could not be locked in RAM. Returned by `NewClient` under `RequireLockedMemory`, and by a call whose growth could not be locked; otherwise reported by `MemoryLockError`. |
| `ErrInternal` | An unexpected failure inside the guest. |

## How it works under the hood

- **One implementation.** The `stack-encrypt` Rust crate is compiled to a
  WASI module and embedded in the package. There is no separate Go port of
  the cryptography, so ciphertexts and terms are byte-identical to the Rust
  crate's and interchange with every other binding.
- **Key material stays in the guest.** The client key crosses into wasm
  memory once at `NewClient`. Data keys are retrieved from ZeroKMS into
  guest memory and never surface in Go. That memory is the package's own:
  reserved once so it never moves, locked and excluded from core dumps
  where the platform allows, wiped before release. `Close` runs the guest's
  own shutdown as well, so every key is wiped in place before the instance
  is released.
- **Two host imports.** The guest imports exactly one HTTP send, served by
  your `http.RoundTripper`, and one bearer-token fetch, served by your
  `TokenSource`. What crosses the boundary per ZeroKMS call is what would
  cross TLS anyway. The guest sees no environment and no filesystem.
- **Real randomness.** The guest draws IVs and nonces from the process
  CSPRNG. wazero's default random source is deterministic, so the package
  configures every instance with `crypto/rand` explicitly.
- **Concurrency.** A wasm instance is single-threaded, so calls on one
  `Client` are serialised internally. The `Client` is safe to share.
