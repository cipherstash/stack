# Supply-chain checks for the vitaminc-aead crates

This directory contains the `cargo deny` config and the `cargo vet` store for
three crates and their dependency graph **only**: `vitaminc-aead`,
`recipher-frame`, and `stack-encrypt-derive`. The derive is here because it
writes every derived `Encrypt` and `Decrypt` impl. Nothing here checks the
rest of the root workspace; that is #1842.

CI runs both in `.github/workflows/supply-chain-vitaminc-aead.yml`, on pull
requests that change the three crates, `Cargo.lock`, `Cargo.toml`, or this
directory. `cargo deny` also runs nightly, for advisories published against
versions already in the lockfile.

- `deny.toml`: advisories, yanked versions, licences, sources, and the crates
  allowed a build script. The derive's dev-dependencies include
  `stack-encrypt`, and `stack-encrypt` reaches the rest of the workspace. So
  `cargo deny` checks the derive as the root of its own graph, without its
  dev-dependencies. The tests of the other two crates use the derive, so
  their checks leave it out.
- `config.toml`, `audits.toml`, `imports.lock`: the `cargo vet` store. It
  started as `cipherstash/vitaminc`'s, with its audits and imported
  registries. The policies name every root workspace member, because cargo
  vet checks policies against the whole workspace before it applies the
  filter; naming one does not vet it. The three crates' policies set
  `criteria = "safe-to-deploy"`: they are not roots of the workspace graph
  (stack-encrypt depends on them), and once the filter drops their
  dependents nothing else would require more than `safe-to-run` of their
  runtime dependencies. Two policies narrow what is vetted:
  - `stack-encrypt-derive` sets `dev-criteria = []`. The derive's
    dev-dependencies (`stack-encrypt`, `tokio`) serve only its doctests, and
    they reach the rest of the workspace.
  - `stack-encrypt-jsonpath` sets `dependency-criteria = { miette = [] }`.
    `miette` comes only with the `diagnostics` feature of
    `stack-encrypt-jsonpath`. `stack-encrypt` turns that feature on, and the
    derive does not. `cargo vet` reads the features of the whole workspace at
    once. Without this policy, it would ask for an audit of a crate the
    derive never builds.
- `filter-graph`: the `--filter-graph` expression that drops every other
  root workspace member, so the graph vetted is the three crates,
  `stack-encrypt-jsonpath` (the derive's path grammar), and their
  dependencies.

## Commands

From the repository root:

```sh
# cargo deny, one crate at a time
cargo deny --locked --exclude stack-encrypt-derive \
  --config supply-chain/vitaminc-aead/deny.toml \
  --manifest-path packages/vitaminc-aead/Cargo.toml check
cargo deny --locked --exclude stack-encrypt-derive \
  --config supply-chain/vitaminc-aead/deny.toml \
  --manifest-path packages/recipher-frame/Cargo.toml check
cargo deny --locked --exclude-dev \
  --config supply-chain/vitaminc-aead/deny.toml \
  --manifest-path packages/stack-encrypt-derive/Cargo.toml check

# cargo vet
cargo vet --locked --store-path supply-chain/vitaminc-aead \
  --filter-graph "$(cat supply-chain/vitaminc-aead/filter-graph)"
```

`cargo vet regenerate` and `cargo vet prune` refuse `--filter-graph`. Edit
exemptions by hand, then run the `cargo vet` command above without
`--locked`, which also refreshes `imports.lock`.

## When `cargo vet` fails

A version moved and the store does not cover it.

1. Run the `cargo vet` command above without `--locked`. If it passes and the
   only change is to `imports.lock`, a trusted registry already audits the
   version: commit `imports.lock`.
2. Otherwise nobody has read the delta. Read it with
   `cargo vet --store-path supply-chain/vitaminc-aead diff <crate> <old> <new>`
   and record it with
   `cargo vet --store-path supply-chain/vitaminc-aead certify <crate> <old> <new>`.
   An exemption instead of an audit is a decision for the reviewer of the
   pull request, not a way to make the check pass.
