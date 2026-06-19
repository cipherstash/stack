# Fuzzing (cargo-fuzz / libFuzzer)

How the repo fuzzes its public, untrusted-input parsers, how to run a
target locally, and how to add a new one. The short-form recipe lives in
[`CLAUDE.md`](../CLAUDE.md); this is the longer explanation.

For background on cargo-fuzz itself — sanitizers, corpus management,
structure-aware fuzzing with `arbitrary`, triaging crashes — use the
[`cargo-fuzz` skill](https://github.com/trailofbits/skills) (Trail of
Bits). We deliberately do **not** maintain our own fuzzing skill; that
skill is the reference, and this doc only covers what's repo-specific.

## What we fuzz and why

We fuzz the parsers that turn **untrusted caller-supplied strings** into
domain types. The invariant under test is always the same: parsing
arbitrary input must **never panic** — malformed input must return an
`Err`, not crash the process.

Current targets:

| mise task            | crate         | target binary         | parses                                        |
|----------------------|---------------|-----------------------|-----------------------------------------------|
| `fuzz:crn`           | `cts-common`  | `crn_parse`           | `Crn` (e.g. `crn:ca-central-1.aws:ZVAT…`)     |
| `fuzz:workspace-id`  | `cts-common`  | `workspace_id_parse`  | `WorkspaceId`                                 |
| `fuzz:region`        | `cts-common`  | `region_parse`        | `Region`                                      |
| `fuzz:access-key`    | `stack-auth`  | `access_key_parse`    | `AccessKey` (`CSAK<key_id>.<key_secret>`)     |
| `fuzz:jwt-decode`    | `stack-auth`  | `jwt_decode`          | JWT claims (`Token::fuzz_decode_claims`)      |

Each target is a few lines — `libfuzzer-sys` hands a `&str` to the
parser via the `arbitrary` crate:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    let _ = s.parse::<cts_common::Crn>();
});
```

When the code under test isn't a public `FromStr` — e.g. the JWT claims
decoder, whose entry points are `pub(crate)` — we don't widen the real
API. Instead the crate exposes a thin **fuzz-only** entry point behind a
`fuzz` Cargo feature (`Token::fuzz_decode_claims`), and the fuzz crate
enables that feature on its dependency (`features = ["fuzz"]` in
`fuzz/Cargo.toml`). Using a Cargo *feature* rather than `#[cfg(fuzzing)]`
keeps `fuzz` a known cfg, so it never trips the `unexpected_cfgs` lint
under CI's `-D warnings`.

## Layout

Each fuzzed crate has a `fuzz/` subdirectory that is a **detached
workspace** — its `Cargo.toml` ends with an empty `[workspace]` table so
the `libfuzzer-sys` dependency and the nightly-only build never touch the
main monorepo workspace, and it is **not** a member of the root
`Cargo.toml`:

```
packages/cts-common/fuzz/
  Cargo.toml                 # detached workspace, cargo-fuzz = true
  fuzz_targets/*.rs          # one file per target binary
  corpus/<target>/*          # committed seed inputs (valid examples)
packages/stack-auth/fuzz/
  …
```

The committed `corpus/<target>/` seeds are valid examples of each format.
They give the fuzzer (and the CI regression replay) a starting point, and
the scheduled campaign grows the corpus from there.

## Running locally

cargo-fuzz needs the **nightly** toolchain and the `cargo-fuzz` binary;
`mise` provides the latter (`cargo:cargo-fuzz` in `mise.toml`). Install
nightly once with `rustup toolchain install nightly`.

Run a target via its `mise` task (60s by default):

```bash
mise run fuzz:crn
```

Override the duration by appending another libFuzzer flag — the last
value of a repeated flag wins:

```bash
mise run fuzz:crn -- -max_total_time=300
```

Replay only the committed seed corpus without fuzzing (what CI's
regression job does):

```bash
mise run fuzz:crn -- -runs=0
```

The tasks pin `--sanitizer none` (these parsers are pure safe Rust, so
ASan buys nothing and roughly doubles throughput) and
`--target $(rustc … host)` (the cargo-fuzz binary can be an x86_64 build
under Rosetta on Apple Silicon, which otherwise misdetects the target and
fails to find `std`).

A crash drops a reproducer into `fuzz/artifacts/<target>/`; re-run that
single input with `cargo +nightly fuzz run <target> <path-to-reproducer>`.

## CI ([`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml))

Two jobs with deliberately different roles:

- **fuzz-regression** (`pull_request`, **blocking**): builds every
  harness — which catches harness/API drift, e.g. a changed `FromStr`
  signature — and replays the committed seed corpus with `-runs=0`. This
  is deterministic (no fuzzing), so it's safe to gate PRs: it fails only
  if a harness stops compiling or a committed corpus input crashes.

- **fuzz-campaign** (`schedule` nightly + `workflow_dispatch`,
  **non-blocking**): the actual time-boxed bug-finding run. A timed fuzz
  run is nondeterministic, so it must not gate PRs. The corpus is
  persisted across runs via `actions/cache` (write-once key + prefix
  `restore-keys`) so coverage compounds, minimized with `cargo fuzz cmin`
  to stay small, and any crash reproducer is uploaded as an artifact.

The `pull_request` trigger is path-filtered to `packages/cts-common/**`,
`packages/stack-auth/**`, and the workflow file, with `!**.md` /
`!**.example` excludes last so docs-only changes are skipped.

## Adding a new target

1. Pick the crate whose parser you're fuzzing and add a target file under
   `packages/<crate>/fuzz/fuzz_targets/<name>.rs` (copy an existing one).
2. Register it as a `[[bin]]` in that crate's `fuzz/Cargo.toml`.
3. Commit at least one valid seed under `fuzz/corpus/<name>/`.
4. Add a `fuzz:<slug>` task in the crate's `tasks.toml` mirroring the
   existing ones (nightly, `--sanitizer none`, host `--target`).
5. Add the target to **both** matrices in `fuzz.yml` — the regression
   `include` (task + slug) and the campaign `include` (task, slug, dir,
   target).

If the entry point is `pub(crate)`, add a `fuzz`-feature-gated shim
rather than widening the public API (see `Token::fuzz_decode_claims`
above), and enable that feature on the dependency in `fuzz/Cargo.toml`.

If the parser can only build for a non-native target, note it as future
work rather than wiring a native target — cargo doesn't gate
`[target.'cfg(…)']` deps on `--cfg fuzzing`, so it needs a wasm-target
build. `fuzz:jwt-decode` covers the native `jsonwebtoken` decode path;
the hand-rolled wasm base64/JSON decoder (whose `base64` dep is
wasm32-only) is not yet fuzzed for this reason.
