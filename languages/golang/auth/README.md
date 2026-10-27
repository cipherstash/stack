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
`golang.org/x/oauth2.TokenSource`. `WithBaseURL(url)` overrides service
discovery for local tests or a custom CTS host; `WithCacheCapacity(n)` sets
how many users' CTS tokens an OIDC strategy keeps (1024 unless set), sized to
the users it serves within a CTS token's lifetime.

`AccessKey` takes `auth.NewAccessKey(ownedBytes)`, not a string. It consumes
and wipes those bytes even if construction fails. Do not retain or reuse
the slice. The key prints only a redaction.

`strategy.Token(ctx)` returns the bearer string, as before. It does not require
the extra metadata that administrative clients need.

`strategy.ServiceToken(ctx)` returns an opaque `auth.ServiceToken`.
Both methods share acquisition, caching and refresh. Call `Bearer()` explicitly
when constructing an Authorization header from a snapshot.
`WorkspaceID()`, `WorkspaceCRN()`, `Issuer()` and `ZeroKMSURL()` describe
the same bearer. This accessor fails if metadata cannot be decoded or the
ZeroKMS endpoint is absent. The zero value has no bearer. Request a token for
each operation so the strategy can refresh it when needed.

This follows Rust stack-auth's client contract: metadata is decoded, not
signature-verified. CTS and ZeroKMS authenticate and authorize requests.
The SDK does not validate JWT audience, roles or timestamps; refresh uses
the expiry returned by CTS or saved in the profile.
Access-key and OIDC strategies check the decoded workspace against their configured workspace.
The workspace CRN combines that workspace with the configured region; device
sessions use the profile's saved region and decoded workspace instead.

Trust the CTS configuration and credential store. `WithBaseURL` (or
`CS_CTS_HOST`) overrides acquisition and refresh endpoints. Otherwise,
access-key and OIDC strategies discover regional CTS; device refresh uses
the stored token's issuer as the native strategy does. A snapshot is not
proof that an arbitrary token or credential store is authentic. No discovery
or JWKS requests are added to cached-token reads.

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

The guest module is embedded from `wasm/`. A tagged version of the module,
as `go get` resolves it, carries it: the release workflow commits it to the
commit the tag names, so nothing needs building. A pseudo-version
(`go get ...@main`, or any commit rather than a tag) does not, and neither
does a checkout of this repository, where the guest is not committed and the
commands above build it. Without it, `Open` returns `ErrGuestNotBuilt` and
the tests skip.

## Licence

The Go code in this module is MIT-licensed ([`LICENSE`](../LICENSE)). The
credential guest it embeds is compiled from Rust crates that are not:
`stack-auth`, `stack-profile` and `stack-guest-abi` are licensed under the
[PolyForm Internal Use License 1.0.0](https://polyformproject.org/licenses/internal-use/1.0.0).
Those terms allow use for your internal business operations only. Each
crate's `LICENSE` in the
[CipherStash Stack repository](https://github.com/cipherstash/stack/tree/main/packages)
has the full text.
