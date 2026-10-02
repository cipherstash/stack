# stackauth

The Go binding of the developer profile — the directory `stash auth login`
writes — read through the `stack-profile` Rust crate running inside a WASI
guest under [wazero], with `CGO_ENABLED=0`. It is the credential half of
the Go SDK: it hands a [`stackencrypt`](../stackencrypt) client its client
key and its bearer token without either package re-deriving the profile's
layout, and without either importing the other.

The guest also runs the `stack-auth` strategies: access key, device session,
OIDC federation, and automatic selection. Go supplies HTTP and holds the
cross-process refresh lock for device sessions.

[wazero]: https://wazero.io
[ADR-0005]: ../../../packages/stack-encrypt/docs/adr/0005-a-separate-credential-guest-for-the-profile-and-auth.md

## Use

Most applications never call this package directly: a `stackencrypt`
client built with `NewClient(ctx)` and no options resolves its credentials with
`stackencrypt.AutoCredentials`, which reads the environment first and then
the profile, through this package. Use it directly to take the profile
apart yourself:

```go
import (
    "context"

    "github.com/cipherstash/cipherstash-suite/bindings/go/stackauth"
    "github.com/cipherstash/cipherstash-suite/bindings/go/stackencrypt"
)

func run(ctx context.Context) error {
    profile, err := stackauth.Resolve(ctx) // CS_CONFIG_PATH, else ~/.cipherstash
    if err != nil {
        return err
    }
    defer profile.Close()

    workspace, err := profile.CurrentWorkspaceStore(ctx)
    if err != nil {
        return err // stackauth.ErrNoCurrentWorkspace: run `stash auth login`
    }
    clientID, clientKey, err := workspace.SecretKey(ctx)
    if err != nil {
        return err
    }
    source, err := workspace.DeviceSession(ctx) // refreshes under the CLI's lock
    if err != nil {
        return err
    }
    defer source.Close()
    client, err := stackencrypt.NewClient(ctx,
        // The key is consumed and wiped by NewClient.
        stackencrypt.WithCredentials(stackencrypt.NewCredentials(clientID, clientKey, source)),
    )
    if err != nil {
        return err
    }
    defer client.Close()
    // ...
    return nil
}
```

`stackauth.ClientKey` and `stackencrypt.ClientKey` are one type, so the
key goes straight from the profile into the credentials. The profile and
the strategy are the caller's: the client asks the strategy for a token on
every request but never closes it, so both stay open until the client is
closed (the deferred calls above run in that order).

A stackencrypt client takes its token only from a strategy, never a raw
string: a raw token cannot be refreshed when it expires, and would bypass
the cross-process lock a device-session refresh holds with the `stash` CLI
(the IdP revokes a whole refresh-token chain when one is used twice).
`workspace.Token(ctx)` still reads the stored token, for inspection.

With no profile directory at all (CI, a container, a server authenticating
by federation), `stackauth.OpenWithoutProfile(ctx)` runs the guest with
nothing mounted: the access-key and OIDC strategies work, and every profile
read is `ErrNoProfile`.

`profile.AccessKey(ctx, crn, key)`, `profile.OIDC(ctx, crn, provider)`, and
`profile.Auto(ctx)` also return strategies that `stackencrypt.NewCredentials`
takes. `Auto` checks `CS_CLIENT_ACCESS_KEY` and
`CS_WORKSPACE_CRN` first, then the current workspace's stored device session.
The OIDC provider is a one-method `Token(context.Context) (string, error)`
interface. Use `stackauth.OAuth2TokenSource(source)` to adapt a
`golang.org/x/oauth2.TokenSource`. `WithAuthBaseURL(url)` overrides service
discovery for local tests or a custom CTS host.

## What the guest is given

Exactly one directory, mounted read-write at a fixed guest path, and no
environment. It cannot name a path outside it: every path is built by the
Rust crate from the store's directory and a validated filename or
workspace id, and the mount itself is confined — a symlink inside the
profile that leads outside it is refused, for reads and for the one write,
rather than followed with the process's permissions as a plain directory
mount would. Files it creates are mode 0600. It takes no file lock (WASI
preview 1 has none); Go holds the same lock as the CLI across the device
session refresh call, on the path `ProfileStore.LockPath` names. A fresh
token is read without the lock; on refresh the guest re-reads
auth.json after acquisition and saves refreshed tokens before release.

The crypto guest behind `stackencrypt` is not widened by this package
existing: it still has no filesystem and no environment.

## Build

```
mise run wasm:auth-guest:build   # the guest, with its import-surface gate
mise run go:test                 # the whole Go module, both packages
```

The guest module is embedded from `wasm/` and not committed; without it,
`Open` returns `ErrGuestNotBuilt` and the tests skip.
