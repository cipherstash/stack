---
'stash': patch
---

Correct the Dependabot section of the bundled `stash-supply-chain-security`
skill. It described two monitored ecosystems (`npm`, `github-actions`); there
are now three, because the in-tree Rust workspace at `packages/protect-ffi`
brought a `Cargo.lock` that nothing proposed updates for. The skill now names
the `cargo` entry, its non-root `directory`, its monthly cadence, and the
exact-pinned CipherStash crates it ignores.

Two things the section previously got wrong are also fixed. Major bumps do not
"stay un-grouped — one PR each": every entry ignores
`version-update:semver-major`, so Dependabot proposes no major bumps at all and
they are applied by hand. And `ignore` conditions suppress Dependabot *security*
PRs as well as version updates — the skill now says so, and points at
`osv-scanner.yml` (which scans every lockfile in the tree, `Cargo.lock`
included) as the compensating control.
