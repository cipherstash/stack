# stack-encrypt for Go

Client-side encryption of values under per-value ZeroKMS data keys, and the
derivation of searchable index terms from the same values, for Go. The
`stack-encrypt` Rust crate is compiled to a WASI module and embedded in
this package; Go calls it through wazero, a pure-Go WebAssembly runtime,
so there is no cgo and no separate Go port of the cryptography.

The package reference is on [pkg.go.dev]; this README covers connecting,
what happens to key material, and the errors.

[pkg.go.dev]: https://pkg.go.dev/github.com/cipherstash/stack/languages/golang/stackencrypt

## Install

```sh
go get github.com/cipherstash/stack/languages/golang/stackencrypt
```

Go 1.25 or later.

## Connect

A `Client` is one ZeroKMS client: its client key, its default keyset, and
the keysets it has loaded since. Make one per process and share it; it is
safe for concurrent use.

```go
import (
    "context"

    "github.com/cipherstash/stack/languages/golang/stackencrypt"
)

func run(ctx context.Context) error {
    client, err := stackencrypt.NewClient(ctx)
    if err != nil {
        return err // stackencrypt.ErrNoCredentials: nothing configured
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

Everything else is a functional option, and each has a default:

```go
client, err := stackencrypt.NewClient(ctx,
    stackencrypt.WithCredentials(stackencrypt.OIDCFederation(crn, provider)),
    stackencrypt.WithTransport(rt),
    stackencrypt.WithKeysetCacheSize(4096),
    stackencrypt.WithRequireLockedMemory(),
)
```

| Option | Default |
|---|---|
| `WithCredentials(c)` | `AutoCredentials()`: see below. |
| `WithTransport(rt)` | `http.DefaultTransport`. Used for ZeroKMS, and for token requests when the credentials make them. |
| `WithKeysetCacheSize(n)` | 1024 keysets beyond the default one. |
| `WithRequireLockedMemory()` | Off: memory that cannot be locked is reported, not refused. See below. |
| `WithGuest(wasm)` | The embedded guest module. |

If an option is given twice, the later one wins.

### Credentials

With no `WithCredentials`, `NewClient` finds its credentials the way the
Rust client does, with `AutoCredentials`: the environment first, then the
developer profile that `stash auth login` writes. On a developer machine, logging in is enough.
In CI or a deployment, the environment supplies them. The first two rows
are what a deployment with no profile needs; the rest override what would
otherwise be resolved:

| Variable | Role |
|---|---|
| `CS_CLIENT_ACCESS_KEY`, `CS_WORKSPACE_CRN` | An access key, exchanged for a token. Without it, the current workspace's stored session is used, and refreshed as it expires. |
| `CS_CLIENT_ID`, `CS_CLIENT_KEY` | The client key, used when both are set. Without them, the current workspace's `secretkey.json` is used. |
| `CS_ZEROKMS_HOST` (or `CS_VITUR_HOST`) | Pins the ZeroKMS endpoint. Otherwise it comes from the token. Read whatever the credentials. |
| `CS_CTS_HOST` | Overrides the authentication endpoint. |
| `CS_CONFIG_PATH` | The profile directory, instead of `~/.cipherstash`. |

A variable that is set but empty or unusable is an error, not a reason to
look elsewhere. Nothing found is `ErrNoCredentials`, naming what to set;
when the profile would have been consulted, it also says why the profile
could not be opened, so an unreadable or mistyped `CS_CONFIG_PATH` is not
reported as "not logged in".

The ZeroKMS endpoint comes from the token's services claim; there is no
option to pin it. `CS_ZEROKMS_HOST` (or the legacy `CS_VITUR_HOST`)
overrides it whatever the credentials, `NewCredentials` included, as the
Rust client reads them, so a value exported there for another tool is
worth checking.

Resolution happens host-side, in Go. The profile and the token strategies
run in `stackauth`'s credential guest; the crypto guest that holds the
keys is still given no environment and no filesystem. The credential guest
lives as long as the client, and `Close` releases it.

To supply the credentials yourself, pass `NewCredentials` with a client
id, a client key and a `stackauth` strategy for the token:

```go
store, err := stackauth.OpenWithoutProfile(ctx) // or stackauth.Resolve(ctx) for the profile
if err != nil {
    return err
}
defer store.Close()
strategy, err := store.AccessKey(ctx, crn, accessKey) // or DeviceSession, OIDC, Auto
if err != nil {
    return err
}
defer strategy.Close()
client, err := stackencrypt.NewClient(ctx,
    stackencrypt.WithCredentials(stackencrypt.NewCredentials(clientID, clientKey, strategy)),
)
if err != nil {
    return err
}
defer client.Close()
```

The strategy is asked for the bearer token on every request, and mints or
refreshes it as it needs to. The store and the strategy stay yours: the
client never closes them, so keep them open until `client.Close` has
returned, as the deferred calls above do. A nil strategy is refused.

Tokens come only from `stackauth` strategies; there is no way to hand the
client a raw bearer token. A raw token cannot be refreshed when it expires,
and a source outside the strategies would bypass the cross-process lock a
device-session refresh holds with the `stash` CLI.

To authenticate through your own identity provider, pass `OIDCFederation`
with the workspace CRN and a provider of the IdP's tokens. CTS exchanges
the IdP token for a CipherStash one, and the provider is asked again only
when that token needs replacing. `stackauth.OAuth2TokenSource` adapts a
`golang.org/x/oauth2` source. The client key is found as `AutoCredentials`
finds it. `stackauth` strategy options follow the provider:
`OIDCFederation(crn, provider, stackauth.WithAuthBaseURL(cts))` pins the CTS
endpoint for these credentials, where `CS_CTS_HOST` would pin it for the
whole process.

`AutoCredentials`, `NewCredentials` and `OIDCFederation` are the only kinds
of `Credentials`: the interface is sealed.

`ClientKey` is an opaque type, not a string: it prints a redaction under
every verb, so logged credentials never show the key. `NewClientKey` takes
ownership of the slice it is given, and `NewClient` consumes the key —
whatever the outcome, even options it refuses, the key is empty afterwards
and that slice is zero. A key is for one client; build another for another
client. What the SDK cannot reach is what the key was built *from*: a
string read from the environment is Go's, immutable, and lives until
collected. Where an environment variable is the source, treat the process
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
run unlocked, pass `WithRequireLockedMemory()` and `NewClient` fails with
`ErrMemoryLock`. That policy holds for the life of the client: memory the
instance later grows into must lock too, or the call that needed it fails
with `ErrMemoryLock`, so grant a limit with room to grow. A `Client` prints
its memory state with `%v` and logs it as a `slog` group, so a startup log
shows it.

The report and the policy cover the credential guest too, which holds the
token strategy and which the client key may have passed through.
`AutoCredentials` and `OIDCFederation` open it under the client's policy.
With `NewCredentials` it is the `stackauth` store you opened: under
`WithRequireLockedMemory()`, `NewClient` fails with `ErrMemoryLock` if that
store's memory is unlocked, but the store's own policy decides its later
growth. Open it with `stackauth.RequireLockedMemory()` as well to keep it
locked for the life of the client.

Production checklist: assert `MemoryLocked()` at startup, or pass
`WithRequireLockedMemory()`, and with `NewCredentials` open the store with
`stackauth.RequireLockedMemory()`. Handling `SIGTERM` for a graceful shutdown is
ordinary Go practice and worth doing for your own reasons; the SDK does not
depend on it and installs no signal handler of its own.

`Close` runs the guest's own shutdown, wiping every key in place before the
instance is released, and takes no context because it does no I/O. A
`Client` that becomes unreachable without `Close` is released by a runtime
cleanup, which covers the forgot-to-close case in a running process and
nothing at exit.

## Plans from a policy

A record plan says which fields to encrypt, under which context, with which
index terms. `stash` tags or `NewPlan` spell it out by hand. The `plan`
subpackage derives it from what the schema already says about each field
(its facts, such as Fideslang `data_categories`), through a policy written
in Go:

```go
import "github.com/cipherstash/stack/languages/golang/stackencrypt/plan"

type Individual struct {
    ID         int64
    Email      string
    MedicareNo string
}

// Facts come from a Source, such as the protobuf one planned in CIP-4088.
// Any function returning facts is one.
var source = plan.SourceFunc(func(msg any) ([]plan.Fact, error) {
    return []plan.Fact{
        {Field: "id", GoField: "ID"},
        {Field: "email", GoField: "Email", Annotations: []plan.Annotation{
            {Key: "fides.data_categories", Values: []string{"user.contact.email"}}}},
        {Field: "medicare_no", GoField: "MedicareNo", Annotations: []plan.Annotation{
            {Key: "fides.data_categories", Values: []string{"user.government_id"}}}},
    }, nil
})

var category = plan.Key("fides.data_categories")

var Base = plan.FirstOf(
    plan.When(category.Under("user.government_id"), plan.Encrypt(plan.EQL(stackencrypt.Equality))),
    plan.When(category.Under("user.contact.email"), plan.Encrypt(plan.EQL(stackencrypt.Equality, stackencrypt.Match))),
    plan.When(category.Under("user"), plan.Encrypt(plan.EQL())),
)

var Individuals = plan.ForMessage(&Individual{}, plan.Table("individuals"),
    plan.FirstOf(
        plan.When(plan.Field("medicare_no"), plan.Encrypt(plan.EQL(stackencrypt.Equality)),
            plan.Column("medicare_number")),
    ).OrElse(Base),
)

// At startup: panics if a classified field is decided by no rule, or the
// plan names a field the struct does not have.
var individuals = plan.MustPlanFor(source, Individuals)

records, err := cipher.EncryptRecords(ctx, rows, stackencrypt.WithPlan(individuals))
```

A policy fails closed: a field with facts that no rule decides is an error
when the plan is built, naming the field and its facts. There is no default;
write a catch-all, `Plaintext()` included, in the policy. Fields with no
facts are left out and stored as they are. A message the policy encrypts
nothing of has no plan: `PlanFor` reports `ErrNothingEncrypted`, and its
records are stored without one.

An EQL target's context is its column identity, `"<table>/<column>"`. The
table is required per message, never derived from its name. A field is
stored in the column named by its schema name (its `Fact.Field`, such as
`medicare_no`: the spelling the Rust derive and the database column share)
unless a rule names another with `plan.Column`, and that column is also its
identity unless the rule pins one with `plan.Identity`. `plan.Field` matches on that same schema name.

The identity is bound into every stored ciphertext, its data key and its
index terms, so once data is written it must never change. A field never
renamed in the database needs no `Identity`. After
`ALTER TABLE individuals RENAME COLUMN medicare_number TO medicare_num`,
new writes go to the new column under the old identity:

```go
plan.When(plan.Field("medicare_no"), plan.Encrypt(plan.EQL(stackencrypt.Equality)),
    plan.Column("medicare_num"), plan.Identity("medicare_number"))
```

`plan.Custom` targets supply their own context: `plan.Column` names only
their record key, and `plan.Identity` is refused. The plan a
policy builds is a `Plan` like any other: the guest receives the same bytes
as for the equivalent hand-built plan.

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
| `ErrTransport` | ZeroKMS could not be reached, or the token strategy failed. The strategy's own error is wrapped in it, so `errors.Is` finds that too (a refused refresh is `stackauth.ErrInvalidGrant`). |
| `ErrKMS` | Any other ZeroKMS failure. |
| `ErrConflict` | ZeroKMS reported a resource conflict. |
| `ErrState` | The client has been closed: by `Close`, by a call its context interrupted, or by a guest trap. |
| `ErrMemoryLock` | The instance's memory could not be locked in RAM. Returned by `NewClient` under `WithRequireLockedMemory()`, and by a call whose growth could not be locked; otherwise reported by `MemoryLockError`. |
| `ErrNoCredentials` | `NewClient` found no token strategy or no client key, in the environment or the profile. The message names what to set. |
| `ErrCredentialsConsumed` | `NewCredentials` given to a second `NewClient`: the first consumed its key. Build new credentials, with a new key, for another client. |
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
  your `http.RoundTripper`, and one bearer-token fetch, served by the
  credentials' `stackauth` strategy. What crosses the boundary per ZeroKMS call is what would
  cross TLS anyway. The guest sees no environment and no filesystem.
- **Real randomness.** The guest draws IVs and nonces from the process
  CSPRNG. wazero's default random source is deterministic, so the package
  configures every instance with `crypto/rand` explicitly.
- **Concurrency.** A wasm instance is single-threaded, so calls on one
  `Client` are serialised internally. The `Client` is safe to share.
