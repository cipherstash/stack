# Guest modules

`stack_encrypt_guest.wasm` is a build artefact of the Rust crate in
`../guest`, copied here by `mise run wasm:guest:build`. It is not committed;
the Go package embeds this directory and reports `ErrGuestNotBuilt` from
`NewClient` when the module is absent, and its tests skip.

The deterministic-kms TEST build of the same crate lives in
`../encrypttest/wasm/` (`mise run wasm:guest:build:deterministic`), not here:
this directory ships in every binary that links `encrypt`, and the test build
ships only in a binary that imports `encrypttest`.
