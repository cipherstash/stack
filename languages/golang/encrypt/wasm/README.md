# Guest modules

`stack_encrypt_guest.wasm` is a build artefact of the Rust crate in
`../guest`, copied here by `mise run wasm:guest:build`. It is not committed;
the Go package embeds this directory and reports `ErrGuestNotBuilt` from
`NewClient` when the module is absent, and its tests skip.

`stack_encrypt_guest_deterministic.wasm` is the same crate built with the
`deterministic-kms` feature by `mise run wasm:guest:build:deterministic`: a
TEST build whose keys derive from a seed, so the tests open the Rust record
fixture and run round trips with no ZeroKMS. The package never embeds it as
the guest a program runs; only the tests load it, and they skip when it is
absent.
