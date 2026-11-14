# Move vitaminc's encryption crates and ore.rs into stack-encrypt

Status: draft, 14 November 2026. Decision by Dan Draper: move the code, and
bring `ore.rs` too (option 1 below).

## Summary

`vitaminc-aead`, `vitaminc-ore`, `vitaminc-prf`, and the crates that depend on
them, move out of `cipherstash/vitaminc` and into `stack-encrypt`. The order
scheme crates `clww-ore` and `ore-rs` move with them, from `cipherstash/ore.rs`.
vitaminc keeps its base crates: `protected`, `random`, `context`, and the key
traits.

The move happens in five stages. The first stage pins every stored and wire
format with known-answer tests, so each later stage can prove it changed
nothing that is stored. Code is moved first as it is, then merged with
stack-encrypt's own record layer, and only then deleted from vitaminc.

This plan does not cover any change to the stored formats. A format change
during the move is a defect.

## Why

stack-encrypt is the only consumer that vitaminc's encryption crates exist
for. Splitting the work across two repositories has caused three problems:

- **Two record designs.** vitaminc's `#[derive(Encrypt)]` turns a struct into
  one type-erased tree. The derive copies each passthrough field into bytes.
  stack-encrypt's `EncryptTarget` turns a struct into the user's own record
  type. `EncryptTarget` moves each passthrough field. stack-encrypt uses its own design
  for every record. Only one example uses the vitaminc derive:
  `packages/stack-encrypt/examples/mixed_user.rs`.
- **A release before every change.** stack-encrypt is published, so it builds
  against vitaminc from crates.io. Each fix needs a vitaminc release before
  stack-encrypt can use it. The Go module pins vitaminc's `vcffi` and
  `vcvalue` at an unreleased commit. While that pin is there, the Go release
  script refuses a final version.
- **Unclear ownership.** Work on vitaminc has included features that nothing
  in stack-encrypt uses, such as the derive's by-reference walk.

## What moves, what stays, and what is deleted

### Crates that move into stack-encrypt

I checked this list against vitaminc `main` and `ore.rs` `main`.

| Crate | Repository | Why it moves |
|---|---|---|
| `vitaminc-aead` | vitaminc | The plaintext model, the ciphertext tree, batching, frames |
| `vitaminc-aead-frame` | vitaminc | The transport frame for the bindings |
| `vitaminc-encrypt` | vitaminc | The AES (Advanced Encryption Standard) cipher; it depends on `vitaminc-aead` |
| `vitaminc-normalize` | vitaminc | Text normalization for terms; it depends on `vitaminc-aead` |
| `vitaminc-prf` | vitaminc | The pseudorandom function (PRF) behind equality and match terms |
| `vitaminc-hmac` | vitaminc | It depends on `vitaminc-prf` |
| `vitaminc-ore` | vitaminc | The order scheme traits and order spaces |
| `clww-ore` | ore.rs | The CLLW (Chenette, Lewi, Weis and Wu) order-revealing (ORE) and order-preserving (OPE) schemes; they implement `vitaminc-ore`'s traits |
| `ore-rs` | ore.rs | The block ORE scheme; it implements `vitaminc-ore`'s and `vitaminc-prf`'s traits |

`ore.rs` has to move too. The `ore.rs` schemes implement `vitaminc-ore`'s traits, and
stack-encrypt depends on the schemes. If `vitaminc-ore` moved into
stack-encrypt and the schemes stayed in `ore.rs`, Cargo would refuse the
dependency cycle.

### Go packages that move into `languages/golang`

The stack Go module imports `github.com/cipherstash/vitaminc/bindings/go/vcffi`
and `vcvalue`, in `languages/golang/encrypt` and `languages/golang/auth`. Both
packages move into the Go module. That removes the
temporary pseudo-version pin from `languages/golang/go.mod`.

### Crates that stay in vitaminc

- `vitaminc-protected`, with its derive
- `vitaminc-random`, with its derive
- `vitaminc-context`
- `vitaminc-traits` and `vitaminc-async-traits`
- `vitaminc-kms`
- `vitaminc-password`
- `vitaminc-permutation`
- the `vitaminc` umbrella crate

The umbrella loses its features for the crates that
move.

`stack-auth`, `stack-kms`, and `cts-common` use only these crates.

### Code that is deleted, not moved

| Code | Why |
|---|---|
| `vitaminc-aead-derive` and `#[aead(passthrough)]` | No library code uses it. `EncryptTarget` replaces it. |
| `vitaminc_aead::hlist` | No code in the stack repository uses it. |
| `vitaminc_aead::plaintext::Tee` | No code in the stack repository uses it. Check again before deleting. |
| `vitaminc-aead-napi` | No lockfile in the stack repository includes it. |
| vitaminc's `bindings/go/vcencrypt` and its guest | The stack Go module has its own guest. Check that nothing imports `vcencrypt` before deleting. |

The `mixed_user.rs` example is rewritten with `EncryptTarget`, or deleted.

## Where the code goes

All of it goes into `stack-encrypt` as modules, not as separate crates.

stack-encrypt is published to crates.io. A published crate cannot depend on a
crate that is only a path in this repository. Each separate crate would
have to be published under a new name, and its version kept in step. Modules
avoid that.

Two other crates in this repository use parts of `vitaminc-aead` today, and
they depend on stack-encrypt instead:

- `stack-guest-abi` uses the plaintext model and the transport frame for
  `HostValue`.
- The EQL encryption tests (`packages/eql/tests/encryption`).

`eql-bindings` already reaches these through stack-encrypt.

## The order of work

Each stage is one or more pull requests. Each must pass the known-answer
tests from stage 1 with no change to the pinned bytes.

### Stage 1: pin every stored and wire format

Before any code moves, add known-answer tests for everything that is stored
or that crosses to a host:

- the leaf ciphertext, its additional authenticated data (AAD), and
  `WIRE_VERSION`;
- the AAD of a map entry, a sequence element, and a typed null;
- transport frames and passthrough frames;
- PRF key blocks, and the equality and match terms made from them;
- CLLW ORE, OPE, and block ORE terms, for every order target.

Some of these exist already:

- vitaminc: the storage corpus in `packages/aead-frame/testdata`, with an
  append-only check, and the normalization known answers in
  `packages/normalize/tests/known_answers.rs`;
- ore.rs: `clww-ore/src/known_answers.rs` and
  `ore-rs/src/scheme/chained/compat_vectors_data.rs`.

The work is to find the gaps, fill them, and run the whole set from
stack-encrypt against the crates.io versions it uses today.

### Stage 2: copy the code in, unchanged

Copy the crates into this repository at the versions that stack-encrypt's
`Cargo.lock` resolves today, keeping their names, as members of the root
workspace with `publish = false`. Point stack-encrypt and the other crates at
them by path. Port their tests, fuzz targets, and benchmarks with them.

This stage changes no behaviour, so it is easy to review: the copied source
can be compared with the published crates file by file.

Bring the history with the code if possible, as was done for the EQL subtree
and the stack-* crates.

At the end of this stage stack-encrypt cannot be published, because it
depends on unpublished path crates. Stage 3 must land before the next
stack-encrypt release.

### Stage 3: fold the crates into stack-encrypt

Turn each copied crate into a module of stack-encrypt, then merge it with what
stack-encrypt already has:

- **One record model.** `EncryptTarget` is the only way to encrypt a record.
  `EncryptTarget` moves a passthrough field when the record is owned.
- **The planning sink and the type-erased tree stay** for the dynamic engine.
  The dynamic engine encrypts values from Go and JavaScript.
- **Frames stay** as the format for values that cross to a host.
- Delete the code listed in "Code that is deleted, not moved".

This stage can be several pull requests, one per area. The stage 1 tests pin
the bytes throughout.

### Stage 4: move the Go packages

Move `vcffi` and `vcvalue` into the Go module, update the imports, and delete
the pseudo-version pin from `go.mod`. Remove the matching refusal from
`scripts/go-release-version.mjs`.

### Stage 5: retire the code in vitaminc and ore.rs

- Delete the moved crates from vitaminc, and remove their features from the
  `vitaminc` umbrella crate. Release vitaminc.
- Publish a final release of each moved crate whose README says where the code
  now lives. Do not yank any version: old versions must keep building.
- Archive `ore.rs`, after the question below about `cipherstash-client` is
  settled.

## Checks that must move with the code

vitaminc and ore.rs run checks that the stack repository does not. Each needs
a home in this repository's CI before its code moves:

- Kani proofs, including `kani-storage`;
- sanitizers;
- the storage corpus append-only check;
- `cargo vet` and `cargo deny`;
- the fuzz targets of the moved crates;
- Miri for the moved crates;
- mutation testing. stack-encrypt already has it, with `--in-diff`.

The stack repository already runs Miri, fuzzing, mutation testing, and
`cargo udeps` for its own crates. The work is to add the moved crates to
them, and to add the checks it lacks.

## Open questions

1. **Should the three open vitaminc pull requests be merged in vitaminc first?**
   The three pull requests are reviewed and green:
   - #616 encrypts by reference.
   - #617 keys order schemes from the PRF.
   - #618 adds `Date`, `Decimal`, and `Uuid`.

   Merging them first means stage 2 copies a version that
   stack-encrypt does not use yet, so stage 2 is no longer a pure copy.
   **Recommendation:** copy the released version, then reapply the three
   pull requests in this repository. Drop the derive commit in #616
   (`ee9db984`).
2. **Should ore.rs stay open for `cipherstash-client`?** The legacy client,
   used by protect-ffi and the EQL tests, depends on an older `ore-rs` from
   crates.io. Moving the code does not break the client, because published
   versions stay. But a fix to that line of `ore-rs` would have no
   repository once ore.rs is archived.
3. **Which licence applies to the moved code?** vitaminc uses the MIT
   licence. ore.rs has its own licence file. stack-encrypt has its own
   licence file too. Ask the person responsible for licensing whether the
   moved code keeps its MIT notice, and what licence the moved ore.rs code
   has.
4. **Does anyone outside CipherStash use the vitaminc crates?** The crates
   are on crates.io. Nobody has checked who else depends on them.

## Rules this changes

Two working rules agreed earlier no longer apply once this lands:

- "A fix always belongs in vitaminc." The code that rule was about moves to
  stack-encrypt.
- "The interop types, such as `FfiValue` and frames, live in vitaminc." The
  interop types move with the record layer.

`AGENTS.md` describes vitaminc as a dependency from crates.io, and lists
`clww-ore` and `ore-rs` among the exact pins in the root `Cargo.toml`. Update
both in the stage that changes them.
