# Guest module

`stack_encrypt_guest.wasm` is a build artefact of the Rust crate in
`../guest`, copied here by `mise run wasm:guest:build`. It is not committed;
the Go package embeds this directory and reports `ErrGuestNotBuilt` from
`NewClient` when the module is absent, and its tests skip.
