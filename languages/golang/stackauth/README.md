# stackauth

The Go binding of the developer profile — the directory `stash auth login`
writes — read through the `stack-profile` Rust crate running inside a WASI
guest under [wazero], with `CGO_ENABLED=0`. It is the credential half of
the Go SDK: it hands a [`stackencrypt`](../stackencrypt) client its client
key and its bearer token without either package re-deriving the profile's
layout, and without either importing the other.

This is the **profile half** of [ADR-0005]. Refreshing a token from Go, and
the access-key and OIDC strategies, are the auth half (CIP-4054); until it
lands, an expired stored token means `stash auth login`.

[wazero]: https://wazero.io
[ADR-0005]: ../../../packages/stack-encrypt/docs/adr/0005-a-separate-credential-guest-for-the-profile-and-auth.md

## Use

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
    client, err := stackencrypt.NewClient(ctx, stackencrypt.Config{
        ClientID:  clientID,
        ClientKey: clientKey,               // consumed and wiped by NewClient
        Token:     workspace.TokenSource(), // re-reads auth.json per request
    })
    if err != nil {
        return err
    }
    defer client.Close()
    // ...
    return nil
}
```

`stackauth.ClientKey` and `stackencrypt.ClientKey` are one type, so the
key goes straight from the profile into the config. The token source
refuses a token at its real expiry with `stackauth.ErrTokenExpired`.

## What the guest is given

Exactly one directory, mounted read-write at a fixed guest path, and no
environment. It cannot name a path outside it: every path is built by the
Rust crate from the store's directory and a validated filename or
workspace id. Files it creates are mode 0600. It takes no file lock (WASI
preview 1 has none); the cross-process refresh lock the CLI holds is Go's
to take, on the path `ProfileStore.LockPath` names, once refreshing lands.

The crypto guest behind `stackencrypt` is not widened by this package
existing: it still has no filesystem and no environment.

## Build

```
mise run wasm:auth-guest:build   # the guest, with its import-surface gate
mise run go:stackencrypt:test    # the whole Go module, both packages
```

The guest module is embedded from `wasm/` and not committed; without it,
`Open` returns `ErrGuestNotBuilt` and the tests skip.
