# stack-encrypt Go example

A runnable tour of the Go binding against real ZeroKMS: seal a value, seal a
record with its index terms, probe those terms with a query, open both again.
It prints what crossed the boundary at each step, including the steps that
are meant to fail.

## Running it

```bash
stash auth login                 # once; the example reads ~/.cipherstash
mise run go:stackencrypt:example # builds both guests, then runs
```

Or, if you would rather drive it yourself:

```bash
mise run wasm:guest:build wasm:auth-guest:build
cd bindings/go && go run ./stackencrypt/example
```

The guest builds are not optional. This package embeds
`wasm/stack_encrypt_guest.wasm` and `stackauth` embeds
`wasm/stack_auth_guest.wasm`; both are gitignored, so a fresh checkout has
no guests and `NewClient` / `Resolve` fail until they are built — and the Go
side will not notice a stale one, so rebuild after any change under either
`guest/src/`.

## What it shows

| | |
|---|---|
| **A value** | An arbitrary map sealed under a caller-chosen AAD. A `vcvalue.Plain` field rides alongside in the clear. Opening under the wrong AAD is refused — at the *key retrieval*, not the AEAD, because every data key is bound to its context. |
| **A record** | A struct's `stash` tags drive a plan: each field sealed under its own context, with the index terms it asked for. Three rows, one batched ZeroKMS request. |
| **A query** | An equality term derived from the value being searched for, matched against the stored terms. The same value under another field's context matches nothing — that is what stops a hit in one column being a hit in another. |
| **Order** | ORE terms sorted, recovering the plaintext order without the plaintext. |

## Credentials

The example calls `NewClient(ctx)` with no options, so it resolves its
credentials with `stackencrypt.AutoCredentials`, which is what any
application gets by default. It looks in the environment first and then in
the developer profile, in the order the Rust client uses:

- **The token.** If `CS_CLIENT_ACCESS_KEY` is set (with `CS_WORKSPACE_CRN`),
  the access key is exchanged for a token. Otherwise the current workspace's
  stored device session is used. Both run in `stackauth`'s credential guest.
- **The client key.** `CS_CLIENT_ID` and `CS_CLIENT_KEY` if both are set,
  otherwise the current workspace's `secretkey.json`.
- **The endpoint.** `CS_ZEROKMS_HOST` if set, otherwise the token's
  `services` claim.

`CS_CONFIG_PATH` overrides the profile directory, and `CS_CTS_HOST`
overrides the authentication endpoint.

Nothing in the example spells out the profile's layout. The `stack-profile`
crate reads it inside the credential guest, so the example cannot drift
from it. The crypto guest still sees no environment and no filesystem:
credentials are resolved host-side.

The device session is **asked on every request and refreshes itself**. A
profile token lasts 45 minutes, so pinning one with `StaticToken` would give
you a program that works for a while and then stops. The refresh takes the
same cross-process lock as the `stash` CLI. The IdP rotates refresh tokens
and detects replay, so two processes sharing `~/.cipherstash` that both
exchanged the same refresh token would get the whole chain revoked; the lock
prevents that.
