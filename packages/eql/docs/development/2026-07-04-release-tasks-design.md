# Design: CI-native alpha releases (SQL surface + `eql-bindings` crate)

> **SUPERSEDED (historical record).** The `workflow_dispatch` coordinator with
> `mise run release:*` targets and a `crate-publish`/`crate_tag` job described
> below was never shipped. Releases now run through the single unified
> `.github/workflows/release.yml` (production from `main` via changesets;
> alpha/prerelease from `eql_v3` via a `chore(release): ...` commit). See
> `docs/development/releasing.md` for the current process. This file is
> kept only as a point-in-time design snapshot.

**Date:** 2026-07-04
**Status:** Approved design (CI-native), ready for implementation plan
**Scope:** Release the two EQL artefacts — individually and in version lockstep — from a single `workflow_dispatch` GitHub Actions workflow, with thin `mise run release:*` tasks that only *trigger and watch* CI.

## Problem

EQL ships two artefacts generated from the same `eql-domains::CATALOG`:

1. The **SQL surface** — `release/cipherstash-encrypt.sql` (+ uninstaller), attached to a GitHub Release tagged `eql-<semver>`, built by `.github/workflows/release-eql.yml`.
2. The **`eql-bindings` crate** — published to crates.io by release-plz (`.github/workflows/release-plz.yml`), tagged `eql-bindings-v<semver>`.

We want to cut alpha (prerelease) versions of **the SQL surface alone**, **the crate alone**, and **both in version lockstep**, with a consistent interface. Because both come from the same catalog, their versions must not diverge.

### Decision: CI-native, not laptop-orchestrated

Orchestration runs **in GitHub Actions** (`workflow_dispatch`); `mise run release:*` only calls `gh workflow run … && gh run watch`. The rejected laptop-orchestrator needed a stack of safeguards (remote-tag derivation, clean-worktree checks, a branch-head SHA guard, "build with the exact string CI uses") — **all of which exist only because a laptop is an unreliable conductor.** CI removes the root cause:

| Laptop hazard | Safeguard it needed | CI-native outcome |
|---|---|---|
| Local tags go stale | derive `N` from remote tags | checkout fetches remote tags fresh |
| Dirty/leftover worktree | clean-worktree check | runner checkout is always clean |
| Concurrent push races the release | `ls-remote` SHA guard | dispatch pins an immutable tag; concurrency group serialises |
| Local build ≠ CI build | build with the `eql-`-stripped identity | the build **is** the CI build |

### Hard constraint: alphas are cut from the `eql_v3` branch

The v3 code is not yet on `main`. Alphas are cut from **`eql_v3`**; once v3 merges, `main` becomes the channel. The workflow **runs on the dispatched ref**, so the branch is just the `--ref` of the dispatch. (Main-channel branch protection is a future constraint; see [Future](#future-the-main-channel).)

## Verified mechanism facts (load-bearing)

Verified against release-plz source, crates.io server source, GitHub Actions docs, and this repo's workflows:

1. **`release-plz release` is branch-agnostic** and publishes on `(version not on crates.io) && (git tag absent)` — no default-branch gate. It tags the **checked-out HEAD** via the GitHub API and cuts a GitHub Release, auto-marked pre-release for a `-alpha.N` version (default `git_release_type = auto`). **No release-plz config change is required.**
2. **The crate publish must happen in CI** — crates.io auth is OIDC Trusted Publishing (no `CARGO_REGISTRY_TOKEN`).
3. **release-plz publishes the committed `Cargo.toml` version verbatim**; pinning is `release-plz set-version eql-bindings@<version>`. No config sets an absolute version. From a prerelease base its default next bump is `-alpha.(N+1)`.
4. **`release-eql.yml` builds with the `eql-`-stripped identity** (`--version "${TAG#eql-}"`) so `eql_v3.version()` reports bare semver; its `verify-changelog` job is gated to `prerelease == false`, so alphas stay under `[Unreleased]`.
5. **GITHUB_TOKEN event suppression + its exceptions.** Events created with the automatic `GITHUB_TOKEN` do **not** trigger new workflow runs — **except `workflow_dispatch` and `repository_dispatch`, which always run.** Therefore:
   - Creating a Release or pushing a commit with `GITHUB_TOKEN` will **not** fire `release-eql.yml`'s `on: release` or any `on: push` — so a coordinator must **build SQL in its own run**, not rely on event fan-out.
   - A coordinator **can `workflow_dispatch` `release-plz.yml` with `GITHUB_TOKEN`** (no PAT/App token needed).
6. **crates.io Trusted Publishing matches on `workflow_ref` = the entry-point workflow filename, not `job_workflow_ref`** (verified in `crates_io_trustpub` source; opposite of PyPI; undocumented — flagged). So the crate must publish from **`release-plz.yml` as its own dispatched entry point** to keep the existing TP config (`workflow: release-plz.yml`) matching. Publishing via a reusable `workflow_call` from `release-alpha.yml` would make the identity `release-alpha.yml` and **fail** the token exchange unless TP is reconfigured.
7. **`gh workflow run --ref <tag>` dispatches against a tag** (immutable commit), reading the workflow file from that tag's tree.

## Architecture

A **coordinator workflow** does everything server-side; **thin mise triggers** only fire and watch it.

### The coordinator — `.github/workflows/release-alpha.yml`

`on: workflow_dispatch`, runs on the dispatched ref. `concurrency: { group: release-alpha, cancel-in-progress: false }` (serialises coordinator runs; the crate publish is separately serialised by `release-plz.yml`'s existing `release-plz` group). `run-name` includes the resolved identity + target so the exact run is findable. Inputs:

| Input | Meaning | Default |
|-------|---------|---------|
| `target` | `all` \| `eql` \| `bindings` | `all` |
| `version` | base SemVer | `3.0.0` |
| `channel` | `alpha` \| `beta` \| `rc` | `alpha` |
| `pre` | exact identity (e.g. `3.0.0-alpha.2`), bypassing `N` derivation | (derived) |
| `dry_run` | resolve + verify + print plan; mutate nothing | `false` |

**Identity** `<version>-<channel>.<N>`, with `N = 1 + max(N across BOTH tag namespaces — SQL `eql-<v>-<ch>.N` and crate `eql-bindings-v<v>-<ch>.N`)`, computed from the freshly-fetched tags (`fetch-depth: 0`). Deriving across both namespaces for every target prevents divergence. It yields SQL tag `eql-<identity>`, crate version/tag `<identity>` / `eql-bindings-v<identity>`.

### `target=all` (lockstep — the normal path)

1. **Resolve** identity; fail if `eql-<identity>` or `eql-bindings-v<identity>` already exists.
2. **Verify** drift gates `types:check` + `codegen:parity` (crate `src/v3` matches the shipped SQL). Abort before any mutation on failure.
3. **Pin** — `release-plz set-version eql-bindings@<identity>`, commit (GPG-signed) staging only the crate files, `git push` the branch. This is commit **S**. (Push via `GITHUB_TOKEN` fires nothing — intended.)
4. **SQL release, in this run** — build via a reusable `workflow_call` (below), create the `eql-<identity>` prerelease **targeting S**, attach the two `.sql` artefacts. If the build fails, the run fails here — before anything irreversible.
5. **Docs, in this run** — build + attach the `eql-docs-*` bundle to the same release via a second reusable `workflow_call` (below), after step 4 has created the release. Also runs before anything irreversible.
6. **Crate publish** — `gh workflow run release-plz.yml --ref eql-<identity>` (dispatch against the immutable SQL tag = commit **S**; `GITHUB_TOKEN` works — `workflow_dispatch` exception). `release-plz.yml` runs **as its own entry point** (TP matches), checks out **S**, publishes the crate, tags `eql-bindings-v<identity>` on **S**. Its `release-pr` job is skipped because the ref is a tag, not `refs/heads/main` (gate below).
7. **Summary** — link the coordinator run and the dispatched `release-plz.yml` run.

**Same commit `S`, for free:** the crate is pinned+committed at S, the SQL release targets S, and the crate publish is dispatched against the *tag* that points at S — so both tags land on S with no SHA guard and no race. **Ordering is safe:** the SQL build+release **and** the docs attach happen in-run and must both succeed before step 6 dispatches the (irreversible) crate publish; the release payload (SQL + docs) is reversible, the crate is not. A docs failure aborts before the crate ships.

*Decoupling caveat:* the crate publish is a **separate run** (fire-and-forget). The coordinator confirms SQL success before dispatching, but cannot report the publish result in its own summary — the operator watches two runs. Acceptable: the failure direction (crate publish fails after SQL shipped) leaves SQL-without-crate, which is the safe direction.

### `target=eql` (SQL only — allowed, no crate)

Resolve → verify → build SQL in-run → create `eql-<identity>` prerelease on the current branch HEAD → attach the `eql-docs-*` bundle in-run. No `set-version`, no commit, no crate. SQL (with docs) without a crate counterpart is permitted.

### `target=bindings` (crate only — requires a matching SQL release)

Per the lockstep decision, a crate version never ships without a corresponding SQL release of the **same version** (same identity, not necessarily same commit — pinning the crate version is itself a commit, so same-*commit* is only guaranteed by `target=all`).

1. **Resolve** — `identity` must correspond to an **existing `eql-<identity>` tag** (default: the latest `eql-<v>-<ch>.N` lacking a crate counterpart; or an explicit `--pre`). **Fail if no matching SQL release exists** — this is the invariant.
2. **Same-source guard** — require the dispatched branch **HEAD to equal the `eql-<identity>` tag's commit**. This makes the follow-up crate *same-source*, not merely same-version: the published bindings provably match the code the SQL release shipped. If the branch has advanced past the SQL commit, **abort** and direct the operator to `target=all` for a fresh coherent identity. (This tightens the "same version, possibly different commit" latitude into "same source, +1 metadata commit"; it stays feasible because the pin below only touches `Cargo.toml`/`CHANGELOG`, never `src/v3`.)
3. **Verify** drift gates on HEAD (`src/v3` matches the catalog).
4. **Pin + publish** — `set-version`, commit (metadata only) on top of the SQL commit, push the branch (advances by one), then dispatch `release-plz.yml --ref <branch>` (HEAD == pin commit, whose `src/v3` == the SQL release's). The crate ships at `<identity>`, same-source with the existing SQL release.

### The reusable build workflows — `_build-sql.yml` and `_build-docs.yml`

Extract `release-eql.yml`'s two build jobs into `workflow_call` reusable workflows: **`_build-sql.yml`** (from `build-and-publish` — builds + attaches the two `.sql` artefacts, and for the coordinator *creates* the prerelease at commit S) and **`_build-docs.yml`** (from `publish-docs` — doxygen + `docs:generate`/`docs:package`, attaches the `eql-docs-*` bundle to the release). Both are called **inline** by the coordinator (so no reliance on the suppressed `release:published` event) **and** by `release-eql.yml` for final (human-created) releases (whose `release:published` event *does* fire). One code path per artefact, no double build. The docs reusable attaches to the release the SQL reusable created, so in the coordinator the docs job `needs` the SQL job; the crate publish `needs` **both** (a complete SQL+docs payload before the irreversible publish).

### The thin mise triggers

`tasks/release/{all,eql,bindings}.sh` — each preflights `gh`, dispatches the coordinator with the matching `target`, forwards `--version`/`--channel`/`--pre`/`--dry-run`, then watches by the unique `run-name`:

```bash
gh workflow run release-alpha.yml --ref "$ref" \
  -f target=all -f version="$version" -f channel="$channel" ${pre:+-f pre="$pre"} ${dry:+-f dry_run=true}
# find THIS run by the identity in run-name, not `-L1` (which races a concurrent dispatch)
```

`--ref` defaults to the current branch. Nothing release-relevant runs locally.

## Companion changes (in scope)

1. **New `.github/workflows/_build-sql.yml`** and **`.github/workflows/_build-docs.yml`** (reusable), with `release-eql.yml`'s `build-and-publish` and `publish-docs` jobs refactored to call them. Alpha releases keep their `eql-docs-*` bundle (built in-run, since the `GITHUB_TOKEN`-created release can't fire the old event-driven `publish-docs`).
2. **New `.github/workflows/release-alpha.yml`** (the coordinator).
3. **Gate `release-plz.yml`'s `release-pr` job** with `if: github.ref == 'refs/heads/main'` — so a dispatch against a tag (or feature branch) publishes without opening a stray PR. (No change to `release-plz.yml`'s `concurrency` group; the coordinator uses its own.)
4. **Three thin `tasks/release/*.sh`** + mise task wiring; retire `preview.sh` / `release:preview`.

## Future: the `main` channel

When alphas move to `main`: (a) a workflow pushing the set-version commit to a **protected `main`** is blocked — allow the release identity to push, or route the crate bump through release-plz's PR flow for `main`; (b) that push also interacts with `release-plz.yml`'s `push: main` trigger (release-plz is idempotent, but reconcile then). Out of scope now.

## Non-goals

- **No final-release automation** — the coordinator cuts **prereleases** only.
- **No change to crates.io Trusted Publishing / OIDC / GPG** — preserved *because* the crate still publishes from `release-plz.yml` as its own entry point (fact 6). This constrains the design: the crate publish must **not** move into a reusable `workflow_call`.
- **No solution for the protected-`main` push** (future constraint above).
- **No `jsonb` domain surface work.**

## Verification

- **`dry_run`** each target: resolved identity, ref, and plan appear in the summary; nothing mutated.
- **Cross-namespace `N`:** with `eql-…-alpha.5` present and no crate alpha tag, `target=bindings` refuses (no matching SQL) and `target=all` resolves `alpha.6`.
- **`target=bindings` invariant:** dispatching for an identity with no `eql-<identity>` tag fails fast; with one present, the crate ships at that version.
- **`target=all`:** both tags land on the **same** commit `S`; SQL build **and docs attach** succeed in-run before the crate dispatch; the release carries the two `.sql` + the `eql-docs-*` bundle; TP token exchange succeeds (publish ran as `release-plz.yml`); **no stray `release-pr`**.
- **`target=eql`:** prerelease with both `.sql` artefacts **and the `eql-docs-*` bundle**; no crate.
- **Docs-on-alpha:** confirm a coordinator-cut alpha carries the `eql-docs-*` bundle (built in-run via `_build-docs.yml`), and that a docs-build failure aborts the run before the crate publish.
- **GITHUB_TOKEN paths:** confirm the coordinator's `workflow_dispatch` of `release-plz.yml` actually starts a run (exception holds), and that it does **not** rely on any suppressed `release:published`/`push` fan-out.
- **Watch correctness:** two overlapping dispatches — each mise task watches its own run via the identity in `run-name`, not `-L1`.

## Alternatives considered

- **Laptop bash orchestrator** (rejected) — needs the safeguard stack CI eliminates.
- **Crate publish via reusable `workflow_call`** (rejected) — cleaner single synchronous run, but crates.io TP matches `workflow_ref` = `release-alpha.yml`, so it would **require adding `release-alpha.yml` to the TP config**. Deferred to keep TP untouched; revisit if a single-run publish is later wanted.
- **GitHub App token to fan out a real `release:published`** (rejected) — unnecessary given the `workflow_dispatch` exception and the reusable inline build.

## Locked decisions

- CI-native coordinator; thin mise triggers; identity across both namespaces; prereleases only; branch = dispatched ref.
- **Lockstep scope:** `target=all` guarantees same commit + identity; `target=eql` is free (SQL without crate allowed); `target=bindings` requires a matching `eql-<identity>` release to already exist **and the branch HEAD to still be at that SQL commit** — so the follow-up crate is *same-source* (no orphan crate version, and the published bindings provably match the shipped SQL). If the branch advanced, `bindings` refuses and points to `target=all`.
- **Input hardening:** `--version` / `--pre` are strictly regex-validated (`X.Y.Z`, `X.Y.Z-(alpha|beta|rc).N`) in both wrappers and the coordinator before flowing into tags/versions/`jq`/`run-name`; the pin path requires a `refs/heads/*` ref (wrappers reject detached HEAD); a client-generated hidden `dispatch_id` input is echoed into `run-name` so the wrapper watches its **own** run unambiguously; the pin step is no-op-tolerant (idempotent retries after a partial `target=all`). A persistent CI job lints the release workflows/tasks (actionlint + shellcheck).
- SQL **and docs** built **in-run** via reusable `workflow_call`s (`_build-sql.yml` + `_build-docs.yml`, not event fan-out) — alphas keep their `eql-docs-*` bundle; crate published by **dispatching `release-plz.yml`** against the SQL tag (TP unchanged); crate publish gated on both build jobs; `release-pr` gated to `main`.
