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

`profile.go` reads the developer profile through
[`stackauth`](../../stackauth): `Resolve` finds the directory the Rust crate
would, `CurrentWorkspaceStore` scopes to the workspace `stash auth login`
selected, `SecretKey` hands out the client key as the opaque `ClientKey`
a `Config` takes, and `TokenSource` is the token source the client
authenticates with. Nothing in the example spells the profile's layout;
the `stack-profile` crate does, inside the credential guest, so the example
cannot drift from it.

Two details in there that are easy to get wrong:

- **The token is not static.** `TokenSource.Token` is called on *every*
  request, precisely so a token can change under a long-lived client. A
  profile token lasts 45 minutes, so pinning one with `StaticToken` gives you
  a program that works and then stops. `stackauth`'s source re-reads
  `auth.json` each time instead, picking up whatever else refreshes it, and
  refuses a token at its real expiry with `stackauth.ErrTokenExpired`.
- **It never refreshes, yet.** Refreshing is the auth half of `stackauth`
  (see ADR-0005): the IdP rotates refresh tokens and detects replay, so two
  processes sharing `~/.cipherstash` that both exchange the same one get the
  entire chain revoked. Rust handles this with a cross-process lock and a
  re-read after acquiring it, and Go will take the same lock on the path
  `ProfileStore.LockPath` names. Until then an expired token means
  `stash auth login`.

`CS_CLIENT_ID` / `CS_CLIENT_KEY` override the profile's client key.
`CS_CONFIG_PATH` overrides the profile directory. The token always comes from
the profile.
