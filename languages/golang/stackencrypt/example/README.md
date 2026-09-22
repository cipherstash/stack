# stack-encrypt Go example

A runnable tour of the Go binding against real ZeroKMS: seal a value, seal a
record with its index terms, probe those terms with a query, open both again.
It prints what crossed the boundary at each step, including the steps that
are meant to fail.

## Running it

```bash
stash auth login                 # once; the example reads ~/.cipherstash
mise run go:stackencrypt:example # builds the guest, then runs
```

Or, if you would rather drive it yourself:

```bash
mise run wasm:guest:build
cd bindings/go && go run ./stackencrypt/example
```

The guest build is not optional. This package embeds
`wasm/stack_encrypt_guest.wasm`, which is gitignored, so a fresh checkout has
no guest and `NewClient` fails until one is built — and the Go side will not
notice a stale one, so rebuild after any change under `guest/src/`.

## What it shows

| | |
|---|---|
| **A value** | An arbitrary map sealed under a caller-chosen AAD. A `vcvalue.Plain` field rides alongside in the clear. Opening under the wrong AAD is refused — at the *key retrieval*, not the AEAD, because every data key is bound to its context. |
| **A record** | A struct's `stash` tags drive a plan: each field sealed under its own context, with the index terms it asked for. Three rows, one batched ZeroKMS request. |
| **A query** | An equality term derived from the value being searched for, matched against the stored terms. The same value under another field's context matches nothing — that is what stops a hit in one column being a hit in another. |
| **Order** | ORE terms sorted, recovering the plaintext order without the plaintext. |

## Credentials, and a gap worth knowing about

`profile.go` is about half this example, and none of it is library code: it
reads `~/.cipherstash` by hand.

That is not an oversight in the example. The Go binding's `Config` takes a
client id, a client key and a `TokenSource` explicitly, and has no profile or
environment fallback of its own. The Rust crate's fallback is native-only —
`stack-kms` gates the `profile` feature off `wasm32`, and the guest is wasm —
so nothing in that path is reachable from here. **Every Go application will
otherwise write this file for itself**, which is the argument for it moving
into the package.

Two details in there that are easy to get wrong:

- **The token is not static.** `TokenSource.Token` is called on *every*
  request, precisely so a token can change under a long-lived client. A
  profile token lasts 45 minutes, so pinning one with `StaticToken` gives you
  a program that works and then stops. The example re-reads `auth.json` each
  time instead, picking up whatever else refreshes it.
- **It never refreshes, on purpose.** The IdP rotates refresh tokens and
  detects replay: two processes sharing `~/.cipherstash` that both exchange
  the same one get the entire chain revoked, and every later attempt fails
  with `invalid grant` until the user logs in again. Rust handles this with a
  cross-process lock and a re-read after acquiring it (see
  `stack-auth`'s `device_session_refresher`). Hand-rolling it here would put
  a reader's real credentials at risk, so this example reads and never
  writes.

`CS_CLIENT_ID` / `CS_CLIENT_KEY` override the profile's client key.
`CS_CONFIG_PATH` overrides the profile directory. The token always comes from
the profile.
