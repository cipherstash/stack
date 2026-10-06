# auth

The Go binding of the developer profile — the directory `stash auth login`
writes — read through the `stack-profile` Rust crate running inside a WASI
guest under [wazero], with `CGO_ENABLED=0`. It is the credential half of
the Go SDK: it hands an [`encrypt`](../encrypt) client its client
key and its bearer token without either package re-deriving the profile's
layout, and without either importing the other.

The guest also runs the `stack-auth` strategies: access key, device session,
OIDC federation, and automatic selection. Go supplies HTTP and holds the
cross-process refresh lock for device sessions.

[wazero]: https://wazero.io
[ADR-0005]: ../../../packages/stack-encrypt/docs/adr/0005-a-separate-credential-guest-for-the-profile-and-auth.md

## Use

Most applications never call this package directly: an `encrypt`
client built with `NewClient(ctx)` and no options resolves its credentials with
`encrypt.AutoCredentials`, which reads the environment first and then
the profile, through this package. Use it directly to take the profile
apart yourself:

```go
import (
    "context"

    "github.com/cipherstash/stack/languages/golang/auth"
    "github.com/cipherstash/stack/languages/golang/encrypt"
)

func run(ctx context.Context) error {
    profile, err := auth.Resolve(ctx) // CS_CONFIG_PATH, else ~/.cipherstash
    if err != nil {
        return err
    }
    defer profile.Close()

    workspace, err := profile.CurrentWorkspaceStore(ctx)
    if err != nil {
        return err // auth.ErrNoCurrentWorkspace: run `stash auth login`
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
    client, err := encrypt.NewClient(ctx,
        // The key is consumed and wiped by NewClient.
        encrypt.WithCredentials(encrypt.NewCredentials(clientID, clientKey, source)),
    )
    if err != nil {
        return err
    }
    defer client.Close()
    // ...
    return nil
}
```

`auth.ClientKey` and `encrypt.ClientKey` are one type, so the
key goes straight from the profile into the credentials. The profile and
the strategy are the caller's: the client asks the strategy for a token on
every request but never closes it, so both stay open until the client is
closed (the deferred calls above run in that order).

An encrypt client takes its token only from a strategy, never a raw
string: a raw token cannot be refreshed when it expires, and would bypass
the cross-process lock a device-session refresh holds with the `stash` CLI
(the IdP revokes a whole refresh-token chain when one is used twice).
`workspace.Token(ctx)` still reads the stored token, for inspection.

With no profile directory at all (CI, a container, a server authenticating
by federation), `auth.OpenWithoutProfile(ctx)` runs the guest with
nothing mounted: the access-key and OIDC strategies work, and every profile
read is `ErrNoProfile`.

`profile.AccessKey(ctx, crn, key)`, `profile.OIDC(ctx, crn, provider)`, and
`profile.Auto(ctx)` also return strategies that `encrypt.NewCredentials`
takes. `Auto` checks `CS_CLIENT_ACCESS_KEY` and
`CS_WORKSPACE_CRN` first, then the current workspace's stored device session.
The OIDC provider is a one-method `Token(context.Context) (string, error)`
interface, called on every token fetch for the JWT of the user the call is
for; each distinct JWT is exchanged once while its CTS token lasts. Use
`auth.OAuth2TokenSource(source)` to adapt a
`golang.org/x/oauth2.TokenSource`. `WithAuthBaseURL(url)` overrides service
discovery for local tests or a custom CTS host; `WithCacheCapacity(n)` sets
how many users' CTS tokens an OIDC strategy keeps (1024 unless set), sized to
the users it serves within a CTS token's lifetime.

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

The crypto guest behind `encrypt` is not widened by this package
existing: it still has no filesystem and no environment.

## Build

```
mise run wasm:auth-guest:build   # the guest, with its import-surface gate
mise run go:test                 # the whole Go module, both packages
```

The guest module is embedded from `wasm/` and not committed; without it,
`Open` returns `ErrGuestNotBuilt` and the tests skip.
