# encrypt example

A runnable tour of the Go SDK against real ZeroKMS: declare a struct with
`stash` tags, generate its encrypted type, seal a batch in one request, derive
a query term, and open the batch again.

## Running it

```bash
stash auth login              # once; the example reads ~/.cipherstash
mise run go:encrypt:example   # builds both guests, then runs
```

Or, if you would rather drive it yourself:

```bash
mise run wasm:guest:build wasm:auth-guest:build
cd languages/golang && go run ./encrypt/example
```

The guest builds are not optional. The `encrypt` package embeds
`wasm/stack_encrypt_guest.wasm` and `auth` embeds `wasm/stack_auth_guest.wasm`;
both are gitignored, so a fresh checkout has no guests and `NewClient` fails
until they are built.

## What it shows

- `model.go`: the struct and its `go:generate` line.
- `user_stash.go`: what `stashgen` wrote from the tags. Regenerate it with
  `go generate ./...`; CI fails when that changes a committed file.
- `main.go`: `Encrypt`, `Fields.Email.Equality` and `Decrypt`, the only three
  calls a program makes.
