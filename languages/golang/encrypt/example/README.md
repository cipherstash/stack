# encrypt example

A runnable tour of the Go SDK against real ZeroKMS: declare a struct with
`stash` tags, generate its encrypted type, seal a batch in one request, derive
a query term, open the batch again, and verify a matches query over it.

## Running it

```bash
stash auth login              # once; the example reads ~/.cipherstash
mise run go:encrypt:example   # builds both guests, then runs
```

Or, if you would rather drive it yourself:

```bash
mise run wasm:guest:build wasm:auth-guest:build
cd languages/golang/encrypt/example && go run .
```

The example is a Go module of its own, as an application is. It requires the
SDK and `encrypttest`, and its `go.mod` replaces both with the directories in
this checkout.

The guest builds are not optional. The `encrypt` package embeds
`wasm/stack_encrypt_guest.wasm` and `auth` embeds `wasm/stack_auth_guest.wasm`;
both are gitignored, so a fresh checkout has no guests and `NewClient` fails
until they are built.

## What it shows

- `model.go`: the struct and its `go:generate` line.
- `user_stash.go`: what `stashgen` wrote from the tags. Regenerate it with
  `go generate ./...` in this directory; CI fails when that changes a
  committed file.
- `user_contexts_test.go`: `encrypttest.AssertContexts` pins the context of
  each field, so a change to the declaration that moves one fails the test.
- `main.go`: `Encrypt`, `Fields.Email.Eq`, `Decrypt`, and `Fields.Email.Matches`
  with `Verify` on the decrypted rows.
