# Test builds of the engine

These are the deterministic-kms TEST builds of the stack-encrypt guest
(`../../guest`). Their keys derive from a seed, so a client over them needs no
ZeroKMS, no token and no network.

- `stack_encrypt_guest_deterministic.wasm`, from
  `mise run wasm:guest:build:deterministic`.
- `stack_encrypt_guest_eql_deterministic.wasm`, the same build with the EQL
  types, from `mise run wasm:guest:build:eql:deterministic`.

They are not committed on main. The Go release workflow builds them and commits
them on the release tag of the `encrypttest` module, so that module fetched
with `go get` carries them. `encrypttest` is a module of its own, so a program
that does not require it never downloads them.

Package `encrypttest` embeds this directory, and `encrypttest.NewClient` fails
the test when the build it needs is absent. The `encrypt` package's own tests
read the same files from disk, and skip when they are absent.

Only a binary that imports `encrypttest` carries these builds. Import it only
from `_test.go` files.
