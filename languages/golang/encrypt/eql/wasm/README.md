# Guest modules with the EQL types

`stack_encrypt_guest_eql.wasm` is the stack-encrypt guest (`../../guest`)
built with its `eql` feature by `mise run wasm:guest:build:eql`: the build
that links `eql-bindings` and so can run a plan field that names an EQL type
(`TextEq`). It is not committed. Package `eql` embeds this directory and
registers the module on import, so a program whose generated code names an
EQL type runs this build; `NewClient` reports `ErrGuestNotBuilt` when it is
absent, and the package's tests skip.

The same build with the `deterministic-kms` feature too — a TEST build whose
keys derive from a seed, so the tests seal and open a `TextEq` field with no
ZeroKMS — is written by `mise run wasm:guest:build:eql:deterministic` under
`encrypt/testdata/`, not here: nothing test-only is embedded.
