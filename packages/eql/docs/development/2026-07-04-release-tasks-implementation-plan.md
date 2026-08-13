# CI-native alpha releases (SQL surface + `eql-bindings` crate) — Implementation Plan

> **SUPERSEDED (historical record).** The `workflow_dispatch` coordinator with
> `mise run release:*` targets and a `crate-publish`/`crate_tag` job described
> below was never shipped. Releases now run through the single unified
> `.github/workflows/release.yml`. See `docs/development/releasing.md`
> for the current process. This file is kept only as a point-in-time snapshot.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cut alpha (prerelease) versions of the EQL SQL surface alone, the `eql-bindings` crate alone, or both in version lockstep, from a single `workflow_dispatch` GitHub Actions coordinator, driven by thin `mise run release:*` tasks that only trigger and watch CI. Alpha releases carry the same assets as finals: the two `.sql` files **and** the packaged docs bundle.

**Architecture:** A coordinator workflow (`release-alpha.yml`) does all orchestration server-side: it resolves the release identity across both tag namespaces, verifies drift gates, pins + commits the crate version, builds and attaches the SQL release **in-run** via a reusable `_build-sql.yml`, builds and attaches the docs bundle **in-run** via a reusable `_build-docs.yml`, then dispatches the crate publish by triggering `release-plz.yml` against the immutable SQL tag (so crates.io Trusted Publishing still matches `workflow_ref = release-plz.yml`). Thin mise tasks only `gh workflow run` the coordinator and watch the resulting run.

**Tech Stack:** GitHub Actions (`workflow_call` reusable workflows, `workflow_dispatch`), `gh` CLI, `mise` file-based tasks (auto-discovered from `tasks/`), `release-plz` CLI, doxygen, GPG-signed commits, crates.io OIDC Trusted Publishing.

## Global Constraints

These are the spec's **verified, load-bearing facts**. Every task's requirements implicitly include them; violating any is a plan failure.

- **SQL and docs must build in-run.** A coordinator running under the automatic `GITHUB_TOKEN` **cannot** rely on any `on: release`/`on: push` fan-out — `GITHUB_TOKEN`-created Releases and pushes do **not** trigger new workflow runs. The SQL build+attach *and* the docs build+attach therefore happen inside the coordinator's own run via reusable `workflow_call`s, never by firing `release-eql.yml`.
- **The crate must publish from `release-plz.yml` as its own dispatched entry point.** crates.io Trusted Publishing matches on `workflow_ref` = the entry-point workflow filename (verified opposite to PyPI). Publishing via a reusable `workflow_call` from `release-alpha.yml` would make the identity `release-alpha.yml` and fail the OIDC token exchange. **Do not move the crate publish into a reusable workflow.** The coordinator triggers the publish with `gh workflow run release-plz.yml --ref <ref>` (the `workflow_dispatch` exception means `GITHUB_TOKEN` *can* do this).
- **`target=all` same-commit `S` is achieved by dispatching the crate publish against the immutable SQL tag.** The crate version is pinned+committed at `S`, the SQL release targets `S`, docs are built at `S`, and the crate publish is dispatched against the *tag* `eql-<identity>` that points at `S` — so both tags land on `S` with no SHA guard and no race.
- **`target=bindings` is same-source, +1 metadata commit.** The crate is published from the **same code** as the referenced `eql-<identity>` SQL release. The coordinator requires branch HEAD to currently equal the SQL tag's commit, adds a metadata-only pin commit **on top of it**, and publishes from there — so the crate never ships later code than the SQL release it corresponds to.
- **Ordering is SQL → docs → crate.** SQL and docs are reversible (a GitHub prerelease can be deleted); a crates.io publish is irreversible. The crate publish must be dispatched only **after** a *complete* release (SQL **and** docs) has been built and attached in-run.
- **Identity `<version>-<channel>.<N>` with `N = 1 + max(N across BOTH tag namespaces)`** — SQL `eql-<v>-<ch>.N` and crate `eql-bindings-v<v>-<ch>.N` — computed from freshly-fetched tags (`fetch-depth: 0`). Deriving across both namespaces for every target prevents version divergence.
- **`release-eql.yml` builds with the `eql-`-stripped identity** (`mise run build --version "${TAG#eql-}"`) so `eql_v3.version()` reports bare semver. Empty tag → bare `mise run build` DEV default (`build.sh` uses `RELEASE_VERSION=${usage_version:-DEV}`, so **empty *or* unset → `DEV`**; PR runs of `release-eql.yml` rely on this). This behaviour is preserved by the reusable.
- **Blockers/prereleases only.** The coordinator cuts prereleases only. No final-release automation, no `verify-changelog` promotion, no `CHANGELOG.md` edits — alpha entries stay under `[Unreleased]`.
- **`release-plz` config is unchanged.** No TP / OIDC / GPG changes. `release-plz set-version eql-bindings@<identity>` is the only pin mechanism (no absolute-version config field exists).
- **Branch = dispatched ref.** Alphas are cut from `eql_v3` today; the workflow runs on the `--ref` of the dispatch. For `all`/`bindings` the ref **must be a branch** (the pin pushes to it). `main`-channel branch protection is out of scope (future).
- **mise tasks are auto-discovered** from the `tasks/` directory (verified: `release:preview` has no `[tasks]` entry in `mise.toml`). A new executable `tasks/release/<name>.sh` with `#MISE`/`#USAGE` headers auto-registers as `release:<name>`; deleting `tasks/release/preview.sh` removes `release:preview`.

---

## File Structure

| File | Responsibility | Action |
|------|----------------|--------|
| `.github/workflows/_build-sql.yml` | Reusable (`workflow_call`) SQL build + upload-artifact + attach/create-release + Multitudes notify. | Create (Task 1) |
| `.github/workflows/_build-docs.yml` | Reusable (`workflow_call`) docs generate + package + upload-artifact + attach `eql-docs-*` to an existing release. | Create (Task 2) |
| `.github/workflows/release-eql.yml` | Finals path: `verify-changelog`, delegate SQL build to `_build-sql.yml`, delegate docs to `_build-docs.yml`. | Modify (Task 3) |
| `.github/workflows/release-plz.yml` | Crate publish entry point (unchanged) + `release-pr` job gated to `main`. | Modify (Task 4) |
| `.github/scripts/derive-identity.sh` + `.github/scripts/derive-identity.test.sh` | Unit-testable identity-derivation function (git seams overridable) + a dependency-free bash test. | Create (Task 5) |
| `.github/workflows/release-alpha.yml` | The coordinator: resolve → pin → build-sql → build-docs → crate-publish → summary. | Create (Task 6) |
| `tasks/release/all.sh`, `tasks/release/eql.sh`, `tasks/release/bindings.sh` | Thin mise triggers: dispatch coordinator + watch by unique `dispatch_id`. | Create (Task 7) |
| `tasks/release/preview.sh` | Retired. | Delete (Task 7) |
| `.github/workflows/lint-release.yml` | Persistent PR gate: `actionlint` on the release workflows + `shellcheck` on `tasks/release/*.sh` + the identity-derivation unit test. | Create (Task 8) |
| `docs/development/releasing-an-alpha.md`, `CLAUDE.md` | Runbook + reference updated to the task/dispatch flow. | Modify (Task 9) |

---

### Task 1: Reusable SQL build — `.github/workflows/_build-sql.yml`

**Files:**
- Create: `.github/workflows/_build-sql.yml`

**Interfaces:**
- Produces (the reusable's `workflow_call` inputs — later tasks call with exactly these):
  - `ref` (string, default `''`) — git ref/SHA to check out; empty → default `github.sha`.
  - `tag` (string, default `''`) — full release tag, e.g. `eql-3.0.0-alpha.2`. Drives the build version via `${TAG#eql-}`; empty → bare `mise run build` DEV default.
  - `attach` (boolean, default `false`) — attach the two `.sql` artefacts to a release.
  - `target_commitish` (string, default `''`) — when non-empty, **create** a prerelease at this commit; when empty, **attach to an existing** release named by `tag`.
  - `prerelease` (boolean, default `false`) — only consulted on the create path.
- Consumes: `secrets: inherit` from the caller (for `MULTITUDES_ACCESS_TOKEN`, referenced only on the `github.event_name == 'release'` path).

- [ ] **Step 1: Write the full reusable workflow file**

```yaml
name: "Build SQL (reusable)"

# Reusable SQL build+attach, extracted from release-eql.yml's build-and-publish
# job. Called INLINE by:
#   - release-alpha.yml (the coordinator) — SQL must build in-run because a
#     GITHUB_TOKEN-created Release does not fire release-eql.yml's `on: release`.
#   - release-eql.yml — for final (human-created) releases, whose `on: release`
#     DOES fire (human token). One SQL-build code path, no double build.

on:
  workflow_call:
    inputs:
      ref:
        description: "Git ref/SHA to build from. Empty -> default checkout (github.sha)."
        required: false
        type: string
        default: ""
      tag:
        description: "Full release tag (e.g. eql-3.0.0-alpha.2). Empty -> DEV build, no attach."
        required: false
        type: string
        default: ""
      attach:
        description: "Attach the built .sql artefacts to a GitHub Release."
        required: false
        type: boolean
        default: false
      target_commitish:
        description: "Non-empty -> CREATE a prerelease at this commit; empty -> attach to the existing release named by `tag`."
        required: false
        type: string
        default: ""
      prerelease:
        description: "Mark the created release as a prerelease (create path only)."
        required: false
        type: boolean
        default: false

env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"
  MISE_VERBOSE: "1"

defaults:
  run:
    shell: bash {0}

permissions:
  contents: write

jobs:
  build:
    runs-on: blacksmith-16vcpu-ubuntu-2204
    name: Build EQL
    timeout-minutes: 5

    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ inputs.ref }}

      - uses: jdx/mise-action@v3
        with:
          version: 2026.4.0
          install: true
          cache: true

      - name: Build EQL release
        # Strip the `eql-` tag prefix so eql_v3.version() reports bare semver
        # (e.g. "3.0.0-alpha.2"). Empty TAG -> ${TAG#eql-} is "" -> build.sh's
        # ${usage_version:-DEV} yields DEV (empty OR unset both map to DEV).
        env:
          TAG: ${{ inputs.tag }}
        run: |
          mise run build --version "${TAG#eql-}"

      - name: Upload EQL artifacts
        uses: actions/upload-artifact@v4
        with:
          name: eql-release
          path: |
            release/cipherstash-encrypt.sql
            release/cipherstash-encrypt-uninstall.sql

      # Finals path: the release already exists (human-created); just upload the
      # two artefacts. No prerelease flag is set, so the existing release's
      # prerelease state is preserved byte-for-byte with the old behaviour.
      - name: Attach artefacts to existing release
        if: ${{ inputs.attach && inputs.target_commitish == '' }}
        uses: softprops/action-gh-release@v2
        with:
          tag_name: ${{ inputs.tag }}
          files: |
            release/cipherstash-encrypt.sql
            release/cipherstash-encrypt-uninstall.sql

      # Coordinator path: no release exists yet — create the prerelease at the
      # exact commit `target_commitish` and attach the two artefacts.
      - name: Create prerelease at commit
        if: ${{ inputs.attach && inputs.target_commitish != '' }}
        uses: softprops/action-gh-release@v2
        with:
          tag_name: ${{ inputs.tag }}
          target_commitish: ${{ inputs.target_commitish }}
          prerelease: ${{ inputs.prerelease }}
          name: ${{ inputs.tag }}
          body: "Preview (prerelease) of the standalone eql_v3 surface. See [Unreleased] in CHANGELOG.md."
          files: |
            release/cipherstash-encrypt.sql
            release/cipherstash-encrypt-uninstall.sql

      # Preserved from the original build-and-publish job. Only fires for real
      # (human) release events; for the coordinator (workflow_dispatch) and PR
      # runs the guard is false, so the secret is never referenced there.
      - name: Notify Multitudes
        if: ${{ github.event_name == 'release' }}
        run: |
          curl --request POST \
            --fail-with-body \
            --url "https://api.developer.multitudes.co/deployments" \
            --header "Content-Type: application/json" \
            --header "Authorization: ${{ secrets.MULTITUDES_ACCESS_TOKEN }}" \
            --data '{"commitSha": "${{ github.sha }}", "environmentName":"production"}'
```

- [ ] **Step 2: Validate the workflow syntax**

Run: `actionlint .github/workflows/_build-sql.yml`
(If `actionlint` is not installed: `go install github.com/rhysd/actionlint/cmd/actionlint@latest`, or `brew install actionlint`, or download the release binary.)
Expected: no output (exit 0).

- [ ] **Step 3: Sanity-check the YAML parses**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/_build-sql.yml'))" && echo OK`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/_build-sql.yml
git commit -m "ci(release): add reusable _build-sql.yml (workflow_call SQL build+attach)"
```

---

### Task 2: Reusable docs build — `.github/workflows/_build-docs.yml`

**Files:**
- Create: `.github/workflows/_build-docs.yml`

**Context (from the real `release-eql.yml` `publish-docs` job, lines ~105–156):** it checks out, runs mise-action, installs doxygen (`sudo apt-get update && sudo apt-get install -y doxygen`), runs `mise run docs:generate` then `mise run docs:generate:markdown -- <tag>` (with `set -euo pipefail` so a generate failure fails fast), `mise run docs:package <tag>`, uploads `eql-docs-*.{zip,tar.gz}`, then attaches those files to the release. **The Multitudes-notify step lives in `build-and-publish`, NOT `publish-docs`** — so this reusable has no Multitudes step. The original attach step was gated `if: startsWith(github.ref, 'refs/tags/')`; that gate is **dropped** here because the coordinator's `github.ref` is a branch (not a tag), so gating on it would suppress the alpha docs attach. Attachment is instead gated on the passed `tag` being non-empty.

**Interfaces:**
- Produces (the reusable's `workflow_call` inputs — Tasks 3 and 6 call with exactly these):
  - `ref` (string, default `''`) — git ref/SHA to build docs from; empty → default `github.sha`.
  - `tag` (string, default `''`) — full release tag. Passed to `docs:generate:markdown`/`docs:package` and names the release to attach to. Empty → build docs, do **not** attach (PR/dispatch parity with the original).

- [ ] **Step 1: Write the full reusable workflow file**

```yaml
name: "Build docs (reusable)"

# Reusable docs build+attach, extracted from release-eql.yml's publish-docs job.
# Called INLINE by:
#   - release-alpha.yml (the coordinator) — docs must build in-run for the same
#     reason as SQL: a GITHUB_TOKEN-created Release does not fire release-eql.yml.
#   - release-eql.yml — for final (human-created) releases.
# The release the docs attach to already exists: _build-sql.yml creates it for
# alphas; a human creates it for finals. So this reusable only ATTACHES.

on:
  workflow_call:
    inputs:
      ref:
        description: "Git ref/SHA to build docs from. Empty -> default checkout (github.sha)."
        required: false
        type: string
        default: ""
      tag:
        description: "Full release tag (e.g. eql-3.0.0-alpha.2). Passed to docs:generate:markdown / docs:package and names the release to attach to. Empty -> build only, no attach."
        required: false
        type: string
        default: ""

env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"
  MISE_VERBOSE: "1"

defaults:
  run:
    shell: bash {0}

permissions:
  contents: write

jobs:
  publish-docs:
    runs-on: blacksmith-16vcpu-ubuntu-2204
    name: Build and Publish Documentation
    timeout-minutes: 10

    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ inputs.ref }}

      - uses: jdx/mise-action@v3
        with:
          version: 2026.4.0
          install: true
          cache: true

      - name: Install Doxygen
        run: |
          sudo apt-get update
          sudo apt-get install -y doxygen

      - name: Generate documentation
        # Fail fast: the workflow default shell is `bash {0}` (no -e), so without
        # this a failure in docs:generate would be masked by the trailing
        # docs:generate:markdown command and only surface later in docs:package.
        env:
          TAG: ${{ inputs.tag }}
        run: |
          set -euo pipefail
          mise run docs:generate
          mise run docs:generate:markdown -- "${TAG}"

      - name: Package documentation
        env:
          TAG: ${{ inputs.tag }}
        run: |
          mise run docs:package "${TAG}"

      - name: Upload documentation artifacts
        uses: actions/upload-artifact@v4
        with:
          name: eql-docs
          path: |
            release/eql-docs-*.zip
            release/eql-docs-*.tar.gz

      # Attach only when a real release tag was passed. Empty tag (PR / bare
      # dispatch of release-eql.yml) builds docs without attaching, matching the
      # original `if: startsWith(github.ref,'refs/tags/')` behaviour without
      # relying on github.ref (which is a branch under the coordinator).
      - name: Publish documentation to release
        if: ${{ inputs.tag != '' }}
        uses: softprops/action-gh-release@v2
        with:
          tag_name: ${{ inputs.tag }}
          files: |
            release/eql-docs-*.zip
            release/eql-docs-*.tar.gz
```

- [ ] **Step 2: Validate the workflow syntax**

Run: `actionlint .github/workflows/_build-docs.yml`
Expected: no output (exit 0).

- [ ] **Step 3: Sanity-check the YAML parses**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/_build-docs.yml'))" && echo OK`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/_build-docs.yml
git commit -m "ci(release): add reusable _build-docs.yml (workflow_call docs build+attach)"
```

---

### Task 3: Refactor `release-eql.yml` to call the reusables

**Files:**
- Modify: `.github/workflows/release-eql.yml` (`build-and-publish` → `uses: _build-sql.yml`; `publish-docs` → `uses: _build-docs.yml`; leave `verify-changelog` unchanged)

**Interfaces:**
- Consumes: `_build-sql.yml` inputs (Task 1) and `_build-docs.yml` inputs (Task 2).

- [ ] **Step 1: Replace the `build-and-publish` job body**

```yaml
  build-and-publish:
    name: Build EQL
    if: ${{ github.event_name != 'release' || (contains(github.event.release.tag_name, 'eql') && !startsWith(github.event.release.tag_name, 'eql-bindings')) }}
    permissions:
      contents: write
    secrets: inherit
    uses: ./.github/workflows/_build-sql.yml
    with:
      ref: ""
      tag: ${{ github.event_name == 'release' && github.event.release.tag_name || '' }}
      attach: ${{ github.event_name == 'release' && startsWith(github.ref, 'refs/tags/') }}
      target_commitish: ""
      prerelease: false
```

- [ ] **Step 2: Replace the `publish-docs` job body**

```yaml
  publish-docs:
    name: Build and Publish Documentation
    if: ${{ github.event_name != 'release' || (contains(github.event.release.tag_name, 'eql') && !startsWith(github.event.release.tag_name, 'eql-bindings')) }}
    permissions:
      contents: write
    uses: ./.github/workflows/_build-docs.yml
    with:
      ref: ""
      tag: ${{ github.event_name == 'release' && github.event.release.tag_name || '' }}
```

Keep `verify-changelog` and the top-level `on`, `env`, `defaults`, `permissions` unchanged.

- [ ] **Step 3: Confirm no behaviour change for finals (read-through)**

- `release: published` (eql, non-bindings) → `build-and-publish` attaches the two `.sql` to the existing release (Multitudes fires); `publish-docs` builds docs at the release commit and attaches `eql-docs-*`. Identical to before.
- `pull_request` → both run with `tag = ''` → build only, no attach. Identical.

- [ ] **Step 4: Validate**

Run: `actionlint .github/workflows/release-eql.yml && python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release-eql.yml'))" && echo OK`
Expected: `OK`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release-eql.yml
git commit -m "ci(release): route release-eql.yml SQL + docs builds through reusables"
```

---

### Task 4: Gate `release-plz.yml`'s `release-pr` job to `main`

**Files:**
- Modify: `.github/workflows/release-plz.yml` (add one `if:` to the `release-pr` job)

**Interfaces:**
- Produces: a `release-plz.yml` whose `release` job still publishes on any ref, but whose `release-pr` runs **only** on `refs/heads/main`. A dispatch against a tag skips `release-pr` → no stray release PR.

- [ ] **Step 1: Add the `if:` guard to `release-pr`**

```yaml
  release-pr:
    name: "Release PR"
    # Only open/refresh the release PR on push-to-main. A workflow_dispatch
    # against a tag (the coordinator's crate-publish path) or a feature branch
    # must publish WITHOUT opening a stray recursive release PR.
    if: github.ref == 'refs/heads/main'
    runs-on: blacksmith-16vcpu-ubuntu-2204
    needs: release
    steps:
      # ... unchanged ...
```

Leave `release:`, `concurrency`, `permissions`, `on` unchanged.

- [ ] **Step 2: Verify the gate logic (read-through)**

- Push to `main` → runs. Coordinator `--ref eql-3.0.0-alpha.2` (tag) → `release-pr` **skipped**, `release` runs. Manual dispatch on `main` → runs.

- [ ] **Step 3: Validate**

Run: `actionlint .github/workflows/release-plz.yml && python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release-plz.yml'))" && echo OK`
Expected: `OK`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release-plz.yml
git commit -m "ci(release): gate release-plz release-pr job to refs/heads/main"
```

---

### Task 5: Identity-derivation helper + unit test — `.github/scripts/`

**Files:**
- Create: `.github/scripts/derive-identity.sh`
- Create: `.github/scripts/derive-identity.test.sh`

**Interfaces:**
- Produces: a `derive_identity <target> <version> <channel> <pre>` bash function that prints the resolved `<version>-<channel>.<N>` identity to stdout, computing `N = 1 + max(SQL N, crate N)` for `all`/`eql` and the latest SQL alpha lacking a crate counterpart for `bindings`. Two git seams — `list_tags <glob>` and `tag_exists <tag>` — are overridable so the test can run against a synthetic tag set with **no git repo and no dependencies**. The coordinator (Task 6) sources this file and calls `derive_identity`; the repo-state guards (existence, branch-HEAD==tag-commit, branch ref) stay in the coordinator.

- [ ] **Step 1: Write `.github/scripts/derive-identity.sh`**

```bash
#!/usr/bin/env bash
# Identity derivation for release-alpha.yml, factored out so it is unit-testable
# with a synthetic tag set (see derive-identity.test.sh). The two git seams
# (list_tags / tag_exists) are overridable by the test harness.
set -euo pipefail

# Seam: print tag names matching a shell glob. Override in tests.
list_tags() { git tag --list "$1"; }

# Seam: succeed iff a tag exists. Override in tests.
tag_exists() { git rev-parse -q --verify "refs/tags/$1" >/dev/null; }

# highest_n <prefix> -> highest integer N among tags "<prefix>N", or empty.
highest_n() {
  local prefix="$1" esc
  esc="${prefix//./\\.}"
  list_tags "${prefix}*" \
    | sed -n "s/^${esc}\([0-9]\{1,\}\)$/\1/p" \
    | sort -n | tail -1
}

# derive_identity <target> <version> <channel> <pre>
# Prints the resolved identity (e.g. 3.0.0-alpha.6). Does NOT run repo-state
# guards (existence / branch-HEAD) — those stay in the resolve job.
derive_identity() {
  local target="$1" version="$2" channel="$3" pre="$4"
  local sql_prefix="eql-${version}-${channel}."
  local crate_prefix="eql-bindings-v${version}-${channel}."

  if [[ -n "$pre" ]]; then
    printf '%s\n' "$pre"; return 0
  fi

  case "$target" in
    all|eql)
      local sql_n crate_n n
      sql_n=$(highest_n "$sql_prefix");     sql_n=${sql_n:-0}
      crate_n=$(highest_n "$crate_prefix"); crate_n=${crate_n:-0}
      if (( sql_n >= crate_n )); then n=$(( sql_n + 1 )); else n=$(( crate_n + 1 )); fi
      printf '%s\n' "${version}-${channel}.${n}"
      ;;
    bindings)
      local esc found n
      esc="${sql_prefix//./\\.}"
      found=""
      for n in $(list_tags "${sql_prefix}*" | sed -n "s/^${esc}\([0-9]\{1,\}\)$/\1/p" | sort -rn); do
        if ! tag_exists "${crate_prefix}${n}"; then found="$n"; break; fi
      done
      if [[ -z "$found" ]]; then
        echo "error: no ${sql_prefix}N SQL release is awaiting a crate publish" >&2
        return 1
      fi
      printf '%s\n' "${version}-${channel}.${found}"
      ;;
    *)
      echo "error: unknown target '$target'" >&2; return 1
      ;;
  esac
}

# Run derive_identity with CLI args when executed directly (not sourced).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  derive_identity "$@"
fi
```

- [ ] **Step 2: Write `.github/scripts/derive-identity.test.sh`**

```bash
#!/usr/bin/env bash
# Dependency-free unit test for derive_identity: overrides the git seams with a
# synthetic tag set. No git repo, no bats. Exit 0 = all pass.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${here}/derive-identity.sh"

FAKE_TAGS=()
list_tags() {
  local glob="$1" t
  (( ${#FAKE_TAGS[@]} )) || return 0
  for t in "${FAKE_TAGS[@]}"; do
    # shellcheck disable=SC2254
    case "$t" in $glob) printf '%s\n' "$t" ;; esac
  done
}
tag_exists() {
  local want="$1" t
  (( ${#FAKE_TAGS[@]} )) || return 1
  for t in "${FAKE_TAGS[@]}"; do [[ "$t" == "$want" ]] && return 0; done
  return 1
}

fail=0
check() { # <desc> <got> <expected>
  if [[ "$2" == "$3" ]]; then echo "ok: $1"; else echo "FAIL: $1 — got '$2' want '$3'"; fail=1; fi
}

FAKE_TAGS=()
check "all: empty -> .1" "$(derive_identity all 3.0.0 alpha '')" "3.0.0-alpha.1"

FAKE_TAGS=(eql-3.0.0-alpha.5)
check "all: sql .5 -> .6" "$(derive_identity all 3.0.0 alpha '')" "3.0.0-alpha.6"

FAKE_TAGS=(eql-3.0.0-alpha.2 eql-bindings-v3.0.0-alpha.4)
check "all: crate .4 wins (cross-namespace) -> .5" "$(derive_identity all 3.0.0 alpha '')" "3.0.0-alpha.5"

FAKE_TAGS=(eql-3.0.0-alpha.5 eql-bindings-v3.0.0-alpha.4)
check "bindings: latest sql lacking crate -> .5" "$(derive_identity bindings 3.0.0 alpha '')" "3.0.0-alpha.5"

FAKE_TAGS=(eql-3.0.0-alpha.5 eql-bindings-v3.0.0-alpha.5)
if derive_identity bindings 3.0.0 alpha '' >/dev/null 2>&1; then
  echo "FAIL: bindings should error when none awaiting"; fail=1
else
  echo "ok: bindings errors when none awaiting a crate"
fi

check "pre passthrough" "$(derive_identity all 3.0.0 alpha 3.0.0-alpha.9)" "3.0.0-alpha.9"

# channel isolation: a beta tag must not bump the alpha counter.
FAKE_TAGS=(eql-3.0.0-beta.7)
check "all: beta.7 does not affect alpha -> .1" "$(derive_identity all 3.0.0 alpha '')" "3.0.0-alpha.1"

exit "$fail"
```

- [ ] **Step 3: Run the unit test**

Run: `bash .github/scripts/derive-identity.test.sh`
Expected: every line prefixed `ok:`, exit 0. (This is the same test the CI gate in Task 8 runs.)

- [ ] **Step 4: ShellCheck the scripts**

Run: `shellcheck .github/scripts/derive-identity.sh .github/scripts/derive-identity.test.sh`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
chmod +x .github/scripts/derive-identity.sh .github/scripts/derive-identity.test.sh
git add .github/scripts/derive-identity.sh .github/scripts/derive-identity.test.sh
git commit -m "ci(release): add unit-testable identity-derivation helper + test"
```

---

### Task 6: The coordinator — `.github/workflows/release-alpha.yml`

**Files:**
- Create: `.github/workflows/release-alpha.yml`

**Interfaces:**
- Consumes: `_build-sql.yml` (Task 1) and `_build-docs.yml` (Task 2) via `workflow_call`; `.github/scripts/derive-identity.sh` (Task 5) sourced in `resolve`; `release-plz.yml` (Task 4) via `gh workflow run`.
- Produces (relied on by Task 7's mise tasks): `workflow_dispatch` inputs `target` / `version` / `channel` / `pre` / `dry_run` / `dispatch_id`; a `run-name` that embeds `<target>`, the resolved-or-partial identity, and the unique `[<dispatch_id>]` so the mise task can find the exact run; `concurrency: { group: release-alpha }`.

**Job graph:**

```
resolve ──> pin ──> build-sql ──> build-docs ──> crate-publish ──> summary
   │         │          │             │              │
   └─────────┴──────────┴─────────────┴──────────────┘  (each gated by target + dry_run)
```

- `resolve` — always. Validate `channel`/`version`/`pre`; guard a pushable **branch** ref for `all`/`bindings`; derive identity (via the Task 5 helper); target-specific existence guards; for `bindings` also guard **branch HEAD == the SQL tag's commit** (same-source); run drift gates `types:check` + `codegen:parity`. On `dry_run`, print the plan and stop.
- `pin` — `all`/`bindings` only, non-dry: `release-plz set-version`; **no-op tolerant** (skip commit/push when set-version changed nothing); GPG-signed commit staging crate files; push → commit `S`.
- `build-sql` — `all`/`eql` only, non-dry: reusable call. For `all`, checks out `S` and creates the prerelease at `S`; for `eql`, at branch `github.sha`.
- `build-docs` — `all`/`eql` only, non-dry, **after** `build-sql`: reusable call at the same commit, attaching `eql-docs-*` to the SQL release.
- `crate-publish` — `all`/`bindings` only, non-dry, **after** `build-sql` **and** `build-docs`: `gh workflow run release-plz.yml --ref <tag|branch>`.
- `summary` — always.

Current implementation note: `release-alpha.yml` now keeps the target-specific
resolution and pinning logic in script entrypoints. Future changes should start
from `.github/scripts/release-alpha-resolve.sh` for the `resolve` job contract
and `.github/scripts/release-alpha-pin-bindings.sh` for the `pin` job contract,
with their adjacent shell tests as the source of truth. The inline shell blocks
below are retained as historical context from the original implementation plan,
not as the active workflow shape.

- [ ] **Step 1: Historical coordinator header, inputs, permissions, concurrency, run-name**

```yaml
name: "Release alpha (coordinator)"

# CI-native prerelease coordinator for the two EQL artefacts (SQL surface +
# eql-bindings crate). Alphas ship the same assets as finals: two .sql files
# AND the packaged docs bundle. Runs on the DISPATCHED REF (a BRANCH for
# all/bindings, since the crate pin is pushed to it). See
# docs/development/2026-07-04-release-tasks-design.md for the full rationale.

on:
  workflow_dispatch:
    inputs:
      target:
        description: "all | eql | bindings"
        required: true
        type: choice
        options: [all, eql, bindings]
        default: all
      version:
        description: "Base SemVer, e.g. 3.0.0"
        required: false
        type: string
        default: "3.0.0"
      channel:
        description: "alpha | beta | rc"
        required: false
        type: choice
        options: [alpha, beta, rc]
        default: alpha
      pre:
        description: "Exact identity (e.g. 3.0.0-alpha.2), bypassing N derivation"
        required: false
        type: string
        default: ""
      dry_run:
        description: "Resolve + verify + print plan; mutate nothing"
        required: false
        type: boolean
        default: false
      dispatch_id:
        description: "Client-generated correlation id (the mise wrapper sets this to find its exact run). Leave blank for manual dispatch."
        required: false
        type: string
        default: ""

# The mise task finds THIS run by the UNIQUE dispatch_id echoed here (never -L1,
# never a createdAt guess). Identity is exact when `pre` is given; otherwise N is
# derived server-side and run-name carries version-channel for readability.
run-name: >-
  release-alpha ${{ inputs.target }} ${{ inputs.pre != '' && inputs.pre || format('{0}-{1}', inputs.version, inputs.channel) }}${{ inputs.dry_run && ' [dry-run]' || '' }} [${{ inputs.dispatch_id }}]

permissions:
  contents: write   # pin push + prerelease creation + docs/sql attach
  actions: write    # gh workflow run release-plz.yml (dispatch)

concurrency:
  group: release-alpha
  cancel-in-progress: false

env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"
  MISE_VERBOSE: "1"

defaults:
  run:
    shell: bash {0}
```

- [ ] **Step 2: Historical `resolve` job sketch**

Current flow: the `resolve` job checks out with full tag history, fetches tags,
then runs `.github/scripts/release-alpha-resolve.sh` with `TARGET`, `VERSION`,
`CHANNEL`, `PRE`, `REF_TYPE`, and `REF_NAME`. That script validates the inputs,
derives or accepts the identity, applies target-specific tag/source guards, and
emits `identity`, `sql_tag`, and `crate_tag` through `GITHUB_OUTPUT`.

```yaml
jobs:
  resolve:
    name: Resolve identity + verify
    runs-on: blacksmith-16vcpu-ubuntu-2204
    timeout-minutes: 15
    outputs:
      identity: ${{ steps.derive.outputs.identity }}
      sql_tag: ${{ steps.derive.outputs.sql_tag }}
      crate_tag: ${{ steps.derive.outputs.crate_tag }}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Fetch all tags
        run: git fetch --tags --force

      - name: Validate inputs
        env:
          CHANNEL: ${{ inputs.channel }}
          TARGET: ${{ inputs.target }}
          VERSION: ${{ inputs.version }}
          PRE: ${{ inputs.pre }}
        run: |
          set -euo pipefail
          case "$CHANNEL" in alpha|beta|rc) ;; *) echo "::error::invalid channel '$CHANNEL'"; exit 1 ;; esac
          case "$TARGET" in all|eql|bindings) ;; *) echo "::error::invalid target '$TARGET'"; exit 1 ;; esac
          [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "::error::invalid version '$VERSION' (expected X.Y.Z)"; exit 1; }
          if [[ -n "$PRE" ]]; then
            [[ "$PRE" =~ ^[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta|rc)\.[0-9]+$ ]] || { echo "::error::invalid pre '$PRE' (expected X.Y.Z-(alpha|beta|rc).N)"; exit 1; }
          fi

      - name: Guard pushable branch (all/bindings)
        if: ${{ inputs.target == 'all' || inputs.target == 'bindings' }}
        env:
          TARGET: ${{ inputs.target }}
          REF_TYPE: ${{ github.ref_type }}
          REF_NAME: ${{ github.ref_name }}
        run: |
          set -euo pipefail
          if [[ "$REF_TYPE" != "branch" ]]; then
            echo "::error::target=${TARGET} pins+pushes the crate version and requires a BRANCH ref; got ${REF_TYPE} '${REF_NAME}'. Dispatch with --ref <branch>."
            exit 1
          fi

      - name: Derive identity + guards
        id: derive
        env:
          TARGET: ${{ inputs.target }}
          VERSION: ${{ inputs.version }}
          CHANNEL: ${{ inputs.channel }}
          PRE: ${{ inputs.pre }}
        run: |
          set -euo pipefail

          # Pure derivation is unit-tested in .github/scripts/derive-identity.test.sh.
          source .github/scripts/derive-identity.sh
          identity="$(derive_identity "$TARGET" "$VERSION" "$CHANNEL" "$PRE")"

          sql_tag="eql-${identity}"
          crate_tag="eql-bindings-v${identity}"

          case "$TARGET" in
            all)
              if git rev-parse -q --verify "refs/tags/${sql_tag}"   >/dev/null; then echo "::error::${sql_tag} already exists";   exit 1; fi
              if git rev-parse -q --verify "refs/tags/${crate_tag}" >/dev/null; then echo "::error::${crate_tag} already exists"; exit 1; fi
              ;;
            eql)
              if git rev-parse -q --verify "refs/tags/${sql_tag}" >/dev/null; then echo "::error::${sql_tag} already exists"; exit 1; fi
              ;;
            bindings)
              # Lockstep invariant: a crate version never ships without a
              # matching SQL release of the SAME version.
              if ! git rev-parse -q --verify "refs/tags/${sql_tag}" >/dev/null; then
                echo "::error::${sql_tag} SQL release must exist before publishing the crate (lockstep invariant)"; exit 1
              fi
              if git rev-parse -q --verify "refs/tags/${crate_tag}" >/dev/null; then echo "::error::${crate_tag} already exists"; exit 1; fi
              # Same-source invariant: the crate must publish from the SAME code as
              # the SQL release. The pin adds a metadata-only commit ON TOP of the
              # SQL tag's commit, so branch HEAD must currently equal that commit.
              head_sha="$(git rev-parse HEAD)"
              tag_sha="$(git rev-parse "refs/tags/${sql_tag}^{commit}")"
              if [[ "$head_sha" != "$tag_sha" ]]; then
                echo "::error::branch HEAD (${head_sha}) has advanced past ${sql_tag} (${tag_sha}); use target=all for a fresh identity"; exit 1
              fi
              ;;
          esac

          echo "identity=${identity}"   >> "$GITHUB_OUTPUT"
          echo "sql_tag=${sql_tag}"     >> "$GITHUB_OUTPUT"
          echo "crate_tag=${crate_tag}" >> "$GITHUB_OUTPUT"

      - uses: jdx/mise-action@v3
        with:
          version: 2026.4.0
          install: true
          cache: true

      - name: Verify drift gates (types:check + codegen:parity)
        # DB-free: regenerate the committed bindings / SQL surface and git diff.
        run: |
          set -euo pipefail
          mise run types:check
          mise run codegen:parity

      - name: Print plan
        env:
          TARGET: ${{ inputs.target }}
          DRY: ${{ inputs.dry_run }}
        run: |
          set -euo pipefail
          {
            echo "## Release plan"
            echo ""
            echo "| field | value |"
            echo "|---|---|"
            echo "| target | ${TARGET} |"
            echo "| identity | ${{ steps.derive.outputs.identity }} |"
            echo "| sql_tag | ${{ steps.derive.outputs.sql_tag }} |"
            echo "| crate_tag | ${{ steps.derive.outputs.crate_tag }} |"
            echo "| ref | ${{ github.ref_name }} @ ${{ github.sha }} |"
            echo "| dry_run | ${DRY} |"
          } >> "$GITHUB_STEP_SUMMARY"
```

Notes on `set -e` safety: every guard uses `if <cmd>; then …; fi` (not `<cmd> && { fail; }`), so a `git rev-parse` returning non-zero does not abort the script.

- [ ] **Step 3: Historical `pin` job sketch**

Current flow: the `pin` job checks out the dispatch SHA, imports the signing key,
installs `release-plz`, then runs
`.github/scripts/release-alpha-pin-bindings.sh` with `IDENTITY` and `BRANCH`.
That script performs the no-op-tolerant `release-plz set-version`, creates the
signed metadata commit only when files changed, pushes it to the selected branch,
and emits `commit_sha`.

```yaml
  pin:
    name: Pin crate version (commit S)
    runs-on: blacksmith-16vcpu-ubuntu-2204
    needs: resolve
    if: ${{ !inputs.dry_run && (inputs.target == 'all' || inputs.target == 'bindings') }}
    timeout-minutes: 15
    outputs:
      commit_sha: ${{ steps.commit.outputs.commit_sha }}
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.ref_name }}   # the dispatched branch; push target
          fetch-depth: 0

      - name: Import GPG key
        uses: crazy-max/ghaction-import-gpg@v7
        with:
          gpg_private_key: ${{ secrets.GPG_PRIVATE_KEY }}
          git_user_signingkey: true
          git_commit_gpgsign: true

      - uses: jdx/mise-action@v3
        with:
          version: 2026.4.0
          install: true
          cache: true

      - name: Install release-plz CLI
        run: cargo binstall --no-confirm release-plz

      - name: Pin + commit + push (commit S)
        id: commit
        env:
          IDENTITY: ${{ needs.resolve.outputs.identity }}
          BRANCH: ${{ github.ref_name }}
        run: |
          set -euo pipefail
          release-plz set-version "eql-bindings@${IDENTITY}"

          # Idempotent recovery: on a rerun where the crate is already pinned to
          # IDENTITY (e.g. SQL+docs shipped but the crate publish failed before
          # tagging), set-version is a no-op. Skip commit/push and reuse HEAD as S
          # rather than failing on "nothing to commit".
          if git diff --quiet && git diff --cached --quiet; then
            echo "set-version produced no changes (already pinned to ${IDENTITY}); skipping commit/push"
          else
            git add crates/eql-bindings/Cargo.toml crates/eql-bindings/CHANGELOG.md Cargo.lock
            git commit -S -m "chore(release): pin eql-bindings to ${IDENTITY}"
            git push origin "HEAD:${BRANCH}"
          fi
          echo "commit_sha=$(git rev-parse HEAD)" >> "$GITHUB_OUTPUT"
```

- [ ] **Step 4: Write the `build-sql` reusable-call job**

```yaml
  build-sql:
    name: Build + release SQL (in-run)
    needs: [resolve, pin]
    if: >-
      ${{ !cancelled() && !inputs.dry_run
          && (inputs.target == 'all' || inputs.target == 'eql')
          && needs.resolve.result == 'success'
          && (needs.pin.result == 'success' || needs.pin.result == 'skipped') }}
    permissions:
      contents: write
    secrets: inherit
    uses: ./.github/workflows/_build-sql.yml
    with:
      ref:              ${{ inputs.target == 'all' && needs.pin.outputs.commit_sha || '' }}
      tag:              ${{ needs.resolve.outputs.sql_tag }}
      attach:           true
      target_commitish: ${{ inputs.target == 'all' && needs.pin.outputs.commit_sha || github.sha }}
      prerelease:       true
```

- [ ] **Step 5: Write the `build-docs` reusable-call job**

```yaml
  build-docs:
    name: Build + attach docs (in-run)
    needs: [resolve, pin, build-sql]
    if: >-
      ${{ !cancelled() && !inputs.dry_run
          && (inputs.target == 'all' || inputs.target == 'eql')
          && needs.build-sql.result == 'success' }}
    permissions:
      contents: write
    uses: ./.github/workflows/_build-docs.yml
    with:
      ref: ${{ inputs.target == 'all' && needs.pin.outputs.commit_sha || github.sha }}
      tag: ${{ needs.resolve.outputs.sql_tag }}
```

- [ ] **Step 6: Write the `crate-publish` job**

```yaml
  crate-publish:
    name: Dispatch crate publish (release-plz.yml)
    runs-on: blacksmith-16vcpu-ubuntu-2204
    needs: [resolve, pin, build-sql, build-docs]
    # A COMPLETE release (SQL + docs) must exist first — for `all`, build-sql AND
    # build-docs must have succeeded — before the irreversible crate publish. For
    # `bindings`, build-sql/build-docs are skipped (the SQL release + its docs
    # already exist; the crate publishes same-source from the pin commit).
    if: >-
      ${{ !cancelled() && !inputs.dry_run
          && (inputs.target == 'all' || inputs.target == 'bindings')
          && needs.pin.result == 'success'
          && (needs.build-sql.result == 'success' || needs.build-sql.result == 'skipped')
          && (needs.build-docs.result == 'success' || needs.build-docs.result == 'skipped') }}
    timeout-minutes: 10
    steps:
      - name: Dispatch release-plz.yml against the pinned commit
        # crates.io Trusted Publishing matches workflow_ref = release-plz.yml, so
        # the crate MUST publish from release-plz.yml as its own entry point.
        # `workflow_dispatch` is the GITHUB_TOKEN suppression exception. For `all`
        # we dispatch against the immutable SQL tag (== commit S); for `bindings`
        # against the branch, whose head is the +1 metadata pin commit on top of
        # the SQL release commit (same source).
        env:
          GH_TOKEN: ${{ github.token }}
          SQL_TAG: ${{ needs.resolve.outputs.sql_tag }}
          BRANCH: ${{ github.ref_name }}
          TARGET: ${{ inputs.target }}
        run: |
          set -euo pipefail
          if [[ "$TARGET" == "all" ]]; then
            ref="$SQL_TAG"
          else
            ref="$BRANCH"
          fi
          echo "Dispatching release-plz.yml --ref ${ref}"
          gh workflow run release-plz.yml --ref "$ref"
          {
            echo "## Crate publish dispatched"
            echo ""
            echo "Dispatched \`release-plz.yml\` against \`${ref}\`."
            echo "Watch it separately: it runs as its own entry point (TP matches)."
          } >> "$GITHUB_STEP_SUMMARY"
```

- [ ] **Step 7: Write the `summary` job**

```yaml
  summary:
    name: Summary
    runs-on: blacksmith-16vcpu-ubuntu-2204
    needs: [resolve, pin, build-sql, build-docs, crate-publish]
    if: always()
    steps:
      - name: Emit run summary
        env:
          TARGET: ${{ inputs.target }}
          DRY: ${{ inputs.dry_run }}
        run: |
          set -euo pipefail
          {
            echo "## release-alpha result"
            echo ""
            echo "- target: \`${TARGET}\` (dry_run=${DRY})"
            echo "- identity: \`${{ needs.resolve.outputs.identity }}\`"
            echo "- sql_tag: \`${{ needs.resolve.outputs.sql_tag }}\`"
            echo "- crate_tag: \`${{ needs.resolve.outputs.crate_tag }}\`"
            echo "- resolve: ${{ needs.resolve.result }} | pin: ${{ needs.pin.result }} | build-sql: ${{ needs.build-sql.result }} | build-docs: ${{ needs.build-docs.result }} | crate-publish: ${{ needs.crate-publish.result }}"
            echo ""
            echo "Coordinator run: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
            echo "The crate publish (if dispatched) runs as a SEPARATE release-plz.yml run — watch it in the Actions tab."
          } >> "$GITHUB_STEP_SUMMARY"
```

- [ ] **Step 8: Validate the coordinator**

Run: `actionlint .github/workflows/release-alpha.yml && python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release-alpha.yml'))" && echo OK`
Expected: `OK`.

- [ ] **Step 9: Commit**

```bash
git add .github/workflows/release-alpha.yml
git commit -m "ci(release): add release-alpha.yml coordinator (branch/same-source guards, no-op-tolerant pin, dispatch_id)"
```

---

### Task 7: Thin mise triggers + retire `preview.sh`

**Files:**
- Create: `tasks/release/all.sh`, `tasks/release/eql.sh`, `tasks/release/bindings.sh`
- Delete: `tasks/release/preview.sh`

**Interfaces:**
- Consumes: `release-alpha.yml` inputs (Task 6): `target`, `version`, `channel`, `pre`, `dry_run`, `dispatch_id`; and the `run-name` which embeds `[<dispatch_id>]`.
- Each task validates inputs, builds the dispatch as a **Bash args array** (ShellCheck-clean), generates a unique `dispatch_id`, dispatches, then watches the run whose `displayTitle` **contains that `dispatch_id`** (unambiguous — no `-L1`, no createdAt tiebreak).

Design note — the three scripts are intentionally near-identical (only `target=` and a couple of messages differ), so the logic is inlined in each. mise auto-discovers **every** file under `tasks/`, so a sourced helper would register as a phantom task; inlining ~40 thin lines avoids that.

- [ ] **Step 1: Write `tasks/release/all.sh`**

```bash
#!/usr/bin/env bash
#MISE description="Cut an alpha of BOTH artefacts in lockstep: dispatch release-alpha.yml (target=all) and watch the run"
#USAGE flag "--version <version>" help="Base SemVer, e.g. 3.0.0" default="3.0.0"
#USAGE flag "--channel <channel>" help="Preview channel: alpha | beta | rc" default="alpha"
#USAGE flag "--pre <pre>" help="Exact identity (e.g. 3.0.0-alpha.2), bypassing N derivation" default=""
#USAGE flag "--ref <ref>" help="Git branch to dispatch against (the crate pin is pushed here)" default=""
#USAGE flag "--dry-run" help="Resolve + verify + print plan; mutate nothing"

set -euo pipefail

# Thin trigger: nothing release-relevant runs locally. It dispatches the
# CI-native coordinator (.github/workflows/release-alpha.yml) with target=all and
# watches THAT run. Same-commit lockstep + all safety live in CI.

target="all"
version="${usage_version:-3.0.0}"
channel="${usage_channel:-alpha}"
pre="${usage_pre:-}"
ref="${usage_ref:-}"
dry_run="${usage_dry_run:-false}"

err() { echo "error: $*" >&2; exit 1; }

# --- Validate (mirrors the coordinator's resolve guards) ---------------------
case "$channel" in alpha|beta|rc) ;; *) err "invalid --channel '$channel' (expected: alpha | beta | rc)" ;; esac
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || err "invalid --version '$version' (expected X.Y.Z)"
if [[ -n "$pre" ]]; then
  [[ "$pre" =~ ^[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta|rc)\.[0-9]+$ ]] || err "invalid --pre '$pre' (expected X.Y.Z-(alpha|beta|rc).N)"
fi

command -v gh >/dev/null 2>&1 || err "gh CLI not found (https://cli.github.com)"
gh auth status >/dev/null 2>&1 || err "gh is not authenticated; run 'gh auth login'"

# target=all pins+pushes the crate version, so it needs a real BRANCH.
if [[ -z "$ref" ]]; then
  ref="$(git rev-parse --abbrev-ref HEAD)"
  [[ "$ref" != "HEAD" ]] || err "detached HEAD; pass --ref <branch> (target=all pushes the crate pin to a branch)"
fi

# Unique correlation id echoed into the coordinator's run-name so we watch the
# EXACT run we started.
dispatch_id="$(uuidgen 2>/dev/null || echo "$$-$RANDOM-$(date +%s)")"

args=(--ref "$ref" -f target="$target" -f version="$version" -f channel="$channel" -f dispatch_id="$dispatch_id")
[[ -n "$pre" ]] && args+=(-f pre="$pre")
[[ "$dry_run" == "true" ]] && args+=(-f dry_run=true)

echo "==> Dispatching release-alpha.yml (target=${target}, dispatch_id=${dispatch_id}) on ref ${ref}"
gh workflow run release-alpha.yml "${args[@]}"

echo "==> Locating the dispatched run by dispatch_id (unambiguous)"
run_id=""
for _ in $(seq 1 30); do
  run_id=$(gh run list --workflow release-alpha.yml --event workflow_dispatch \
    --json databaseId,displayTitle \
    --jq "[.[] | select(.displayTitle | contains(\"${dispatch_id}\"))] | first | .databaseId")
  [[ -n "$run_id" && "$run_id" != "null" ]] && break
  sleep 2
done
[[ -n "$run_id" && "$run_id" != "null" ]] || err "could not find the dispatched run (dispatch_id=${dispatch_id})"

echo "==> Watching run ${run_id}"
gh run watch "$run_id" --exit-status
echo "==> Coordinator finished. For target=all, the crate publish runs as a SEPARATE release-plz.yml run — watch it in the Actions tab."
```

- [ ] **Step 2: Write `tasks/release/eql.sh`**

Identical to `all.sh` except `#MISE description`, `target`, the ref guard (eql needs no push, so **any** ref is allowed — only the unusable `HEAD` default is rejected), and the trailing note. Full file:

```bash
#!/usr/bin/env bash
#MISE description="Cut an alpha of the SQL surface + docs only: dispatch release-alpha.yml (target=eql) and watch the run"
#USAGE flag "--version <version>" help="Base SemVer, e.g. 3.0.0" default="3.0.0"
#USAGE flag "--channel <channel>" help="Preview channel: alpha | beta | rc" default="alpha"
#USAGE flag "--pre <pre>" help="Exact identity (e.g. 3.0.0-alpha.2), bypassing N derivation" default=""
#USAGE flag "--ref <ref>" help="Git ref (branch or tag) to dispatch against" default=""
#USAGE flag "--dry-run" help="Resolve + verify + print plan; mutate nothing"

set -euo pipefail

target="eql"
version="${usage_version:-3.0.0}"
channel="${usage_channel:-alpha}"
pre="${usage_pre:-}"
ref="${usage_ref:-}"
dry_run="${usage_dry_run:-false}"

err() { echo "error: $*" >&2; exit 1; }

case "$channel" in alpha|beta|rc) ;; *) err "invalid --channel '$channel' (expected: alpha | beta | rc)" ;; esac
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || err "invalid --version '$version' (expected X.Y.Z)"
if [[ -n "$pre" ]]; then
  [[ "$pre" =~ ^[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta|rc)\.[0-9]+$ ]] || err "invalid --pre '$pre' (expected X.Y.Z-(alpha|beta|rc).N)"
fi

command -v gh >/dev/null 2>&1 || err "gh CLI not found (https://cli.github.com)"
gh auth status >/dev/null 2>&1 || err "gh is not authenticated; run 'gh auth login'"

# target=eql does not push, so any ref works; only reject the unusable "HEAD"
# default from a detached checkout.
if [[ -z "$ref" ]]; then
  ref="$(git rev-parse --abbrev-ref HEAD)"
  [[ "$ref" != "HEAD" ]] || err "detached HEAD; pass --ref <branch or tag>"
fi

dispatch_id="$(uuidgen 2>/dev/null || echo "$$-$RANDOM-$(date +%s)")"

args=(--ref "$ref" -f target="$target" -f version="$version" -f channel="$channel" -f dispatch_id="$dispatch_id")
[[ -n "$pre" ]] && args+=(-f pre="$pre")
[[ "$dry_run" == "true" ]] && args+=(-f dry_run=true)

echo "==> Dispatching release-alpha.yml (target=${target}, dispatch_id=${dispatch_id}) on ref ${ref}"
gh workflow run release-alpha.yml "${args[@]}"

echo "==> Locating the dispatched run by dispatch_id (unambiguous)"
run_id=""
for _ in $(seq 1 30); do
  run_id=$(gh run list --workflow release-alpha.yml --event workflow_dispatch \
    --json databaseId,displayTitle \
    --jq "[.[] | select(.displayTitle | contains(\"${dispatch_id}\"))] | first | .databaseId")
  [[ -n "$run_id" && "$run_id" != "null" ]] && break
  sleep 2
done
[[ -n "$run_id" && "$run_id" != "null" ]] || err "could not find the dispatched run (dispatch_id=${dispatch_id})"

echo "==> Watching run ${run_id}"
gh run watch "$run_id" --exit-status
echo "==> Done. SQL prerelease + docs cut; no crate published (target=eql)."
```

- [ ] **Step 3: Write `tasks/release/bindings.sh`**

Identical to `all.sh` except `#MISE description`, `target="bindings"`, the branch-required note, and the trailing note. Full file:

```bash
#!/usr/bin/env bash
#MISE description="Publish the eql-bindings crate for an EXISTING SQL alpha (same-source, +1 metadata commit): dispatch release-alpha.yml (target=bindings) and watch"
#USAGE flag "--version <version>" help="Base SemVer, e.g. 3.0.0" default="3.0.0"
#USAGE flag "--channel <channel>" help="Preview channel: alpha | beta | rc" default="alpha"
#USAGE flag "--pre <pre>" help="Exact identity (e.g. 3.0.0-alpha.2), bypassing N derivation" default=""
#USAGE flag "--ref <ref>" help="Git branch to dispatch against (must currently be AT the eql-<identity> commit)" default=""
#USAGE flag "--dry-run" help="Resolve + verify + print plan; mutate nothing"

set -euo pipefail

# target=bindings publishes the crate SAME-SOURCE from an existing eql-<identity>
# SQL release: the branch must currently be AT that release's commit (the
# coordinator guards branch-HEAD == SQL-tag-commit), and the pin adds a
# metadata-only commit on top. Requires a BRANCH (the pin is pushed).

target="bindings"
version="${usage_version:-3.0.0}"
channel="${usage_channel:-alpha}"
pre="${usage_pre:-}"
ref="${usage_ref:-}"
dry_run="${usage_dry_run:-false}"

err() { echo "error: $*" >&2; exit 1; }

case "$channel" in alpha|beta|rc) ;; *) err "invalid --channel '$channel' (expected: alpha | beta | rc)" ;; esac
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || err "invalid --version '$version' (expected X.Y.Z)"
if [[ -n "$pre" ]]; then
  [[ "$pre" =~ ^[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta|rc)\.[0-9]+$ ]] || err "invalid --pre '$pre' (expected X.Y.Z-(alpha|beta|rc).N)"
fi

command -v gh >/dev/null 2>&1 || err "gh CLI not found (https://cli.github.com)"
gh auth status >/dev/null 2>&1 || err "gh is not authenticated; run 'gh auth login'"

if [[ -z "$ref" ]]; then
  ref="$(git rev-parse --abbrev-ref HEAD)"
  [[ "$ref" != "HEAD" ]] || err "detached HEAD; pass --ref <branch> (target=bindings pushes the crate pin to a branch)"
fi

dispatch_id="$(uuidgen 2>/dev/null || echo "$$-$RANDOM-$(date +%s)")"

args=(--ref "$ref" -f target="$target" -f version="$version" -f channel="$channel" -f dispatch_id="$dispatch_id")
[[ -n "$pre" ]] && args+=(-f pre="$pre")
[[ "$dry_run" == "true" ]] && args+=(-f dry_run=true)

echo "==> Dispatching release-alpha.yml (target=${target}, dispatch_id=${dispatch_id}) on ref ${ref}"
gh workflow run release-alpha.yml "${args[@]}"

echo "==> Locating the dispatched run by dispatch_id (unambiguous)"
run_id=""
for _ in $(seq 1 30); do
  run_id=$(gh run list --workflow release-alpha.yml --event workflow_dispatch \
    --json databaseId,displayTitle \
    --jq "[.[] | select(.displayTitle | contains(\"${dispatch_id}\"))] | first | .databaseId")
  [[ -n "$run_id" && "$run_id" != "null" ]] && break
  sleep 2
done
[[ -n "$run_id" && "$run_id" != "null" ]] || err "could not find the dispatched run (dispatch_id=${dispatch_id})"

echo "==> Watching run ${run_id}"
gh run watch "$run_id" --exit-status
echo "==> Coordinator finished. The crate publish runs as a SEPARATE release-plz.yml run — watch it in the Actions tab."
```

- [ ] **Step 4: Make the scripts executable and delete `preview.sh`**

```bash
chmod +x tasks/release/all.sh tasks/release/eql.sh tasks/release/bindings.sh
git rm tasks/release/preview.sh
```

- [ ] **Step 5: Verify mise task registration**

Run: `mise tasks ls | grep -E '^release:'`
Expected: `release:all`, `release:bindings`, `release:eql` present; `release:preview` **absent**.

- [ ] **Step 6: ShellCheck the wrappers**

Run: `shellcheck tasks/release/all.sh tasks/release/eql.sh tasks/release/bindings.sh`
Expected: **no errors** (the args-array construction and quoted expansions clear SC2046/SC2086).

- [ ] **Step 7: Commit**

```bash
git add tasks/release/all.sh tasks/release/eql.sh tasks/release/bindings.sh
git commit -m "ci(release): add thin release:{all,eql,bindings} mise triggers (dispatch_id watch); retire release:preview"
```

---

### Task 8: Persistent CI gate — `.github/workflows/lint-release.yml`

**Files:**
- Create: `.github/workflows/lint-release.yml`

**Interfaces:**
- Produces: a PR-triggered job that runs `actionlint` on the release workflows, `shellcheck` on `tasks/release/*.sh` and the `.github/scripts` helpers, and the identity-derivation unit test — turning the previously manual/observational checks into a durable gate.

- [ ] **Step 1: Write the gate workflow**

```yaml
name: "Lint release tooling"

# Durable gate for the CI-native release machinery. Runs on any PR that touches
# the release workflows, wrappers, or helper scripts (and manually), so a broken
# workflow expression, a ShellCheck regression, or a broken identity derivation
# is caught in review — not on a real alpha.

on:
  pull_request:
    paths:
      - .github/workflows/_build-sql.yml
      - .github/workflows/_build-docs.yml
      - .github/workflows/release-eql.yml
      - .github/workflows/release-plz.yml
      - .github/workflows/release-alpha.yml
      - .github/workflows/lint-release.yml
      - .github/scripts/derive-identity.sh
      - .github/scripts/derive-identity.test.sh
      - tasks/release/*.sh
  workflow_dispatch: {}

permissions:
  contents: read

defaults:
  run:
    shell: bash

jobs:
  lint:
    name: actionlint + shellcheck + unit test
    runs-on: blacksmith-16vcpu-ubuntu-2204
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - name: Install actionlint
        run: |
          set -euo pipefail
          bash <(curl -sSfL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash)
          echo "$PWD" >> "$GITHUB_PATH"

      - name: actionlint (release workflows)
        run: |
          set -euo pipefail
          actionlint \
            .github/workflows/_build-sql.yml \
            .github/workflows/_build-docs.yml \
            .github/workflows/release-eql.yml \
            .github/workflows/release-plz.yml \
            .github/workflows/release-alpha.yml \
            .github/workflows/lint-release.yml

      - name: shellcheck (wrappers + helpers)
        # shellcheck is preinstalled on ubuntu runners.
        run: |
          set -euo pipefail
          shellcheck \
            tasks/release/all.sh \
            tasks/release/eql.sh \
            tasks/release/bindings.sh \
            .github/scripts/derive-identity.sh \
            .github/scripts/derive-identity.test.sh

      - name: identity-derivation unit test
        run: bash .github/scripts/derive-identity.test.sh
```

- [ ] **Step 2: Validate the gate workflow itself**

Run: `actionlint .github/workflows/lint-release.yml && python3 -c "import yaml; yaml.safe_load(open('.github/workflows/lint-release.yml'))" && echo OK`
Expected: `OK`.

- [ ] **Step 3: Dry-run the gate's commands locally**

Run:
```bash
shellcheck tasks/release/*.sh .github/scripts/derive-identity.sh .github/scripts/derive-identity.test.sh
bash .github/scripts/derive-identity.test.sh
```
Expected: shellcheck clean; the unit test prints all `ok:` and exits 0.

- [ ] **Step 4: Document the docs-failure fault-injection check (scratch-branch only)**

This proves the SQL→docs→crate ordering guarantee — it cannot run on a real publish, so record it as a **scratch-branch-only** manual procedure (add it under a "Verification" note in `docs/development/releasing-an-alpha.md` in Task 9, and reference it here):

1. On a throwaway branch, temporarily edit `_build-docs.yml`'s "Generate documentation" step to `run: exit 1` (force a docs failure). Commit to the scratch branch only.
2. `mise run release:eql --ref <scratch-branch>` (or `release:all`).
3. Observe: `build-docs` is **red**, and `crate-publish` (for `all`) is **skipped** — never started — because its `if` requires `needs.build-docs.result == 'success'`. Delete any prerelease/tag the run created and discard the scratch branch.
4. **Never** run this on a branch you will dispatch a real publish from.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/lint-release.yml
git commit -m "ci(release): add lint-release gate (actionlint + shellcheck + identity unit test)"
```

---

### Task 9: Documentation updates

**Files:**
- Modify: `docs/development/releasing-an-alpha.md`
- Modify: `CLAUDE.md`
- Grep-and-fix any remaining stray `release:preview` references

- [ ] **Step 1: Rewrite `docs/development/releasing-an-alpha.md`**

Replace the "Scripted path", "Steps (manual equivalent)", and "Releasing `eql-bindings` in lockstep" sections with the CI-native flow. Include:

- **What ships (unchanged for alphas):** the two `.sql` files **and** the docs bundle (`eql-docs-*`), both built in-run — same assets as a final release.
- **The three tasks:**
  - `mise run release:all` → `target=all`: pins the crate to `<identity>`, commits+pushes (commit `S`), builds+attaches SQL + docs at `S`, then dispatches `release-plz.yml` against the `eql-<identity>` tag to publish the crate at `S`. Both tags on `S`. **Requires `--ref <branch>`** (the pin is pushed).
  - `mise run release:eql` → `target=eql`: SQL prerelease + docs only (no crate). Any ref works (no push).
  - `mise run release:bindings` → `target=bindings`: publishes the crate for an **existing** `eql-<identity>` SQL release, **same-source** — the branch must currently be **at that release's commit** (the coordinator guards branch-HEAD == SQL-tag-commit) and the pin adds a metadata-only commit on top. Fails fast if no matching SQL release exists, or if the branch has advanced past it (use `release:all` for a fresh identity). **Requires `--ref <branch>`**.
- **Flags:** `--version` (default `3.0.0`, validated `X.Y.Z`), `--channel` (`alpha`|`beta`|`rc`), `--pre` (exact identity, validated `X.Y.Z-(alpha|beta|rc).N`), `--ref`, `--dry-run`.
- **Always `--dry-run` first.** Examples:
  ```bash
  mise run release:all --dry-run
  mise run release:all                    # -> eql-3.0.0-alpha.N (+ docs) + eql-bindings-v3.0.0-alpha.N on one commit
  mise run release:eql --channel beta     # -> eql-3.0.0-beta.N (SQL + docs)
  mise run release:bindings --pre 3.0.0-alpha.2   # publish the crate for an existing eql-3.0.0-alpha.2 (same source)
  ```
- **Identity derivation** is server-side across both namespaces (`N = 1 + max(SQL N, crate N)`).
- **Two runs to watch** for `all`/`bindings`: the mise task watches the coordinator run (found via the unique `dispatch_id`); the crate publish is a **separate** `release-plz.yml` run.
- **Ordering guarantee:** SQL → docs → crate. A docs-build failure aborts before the crate publish.
- **TP prerequisite:** crates.io Trusted Publishing is configured for `Workflow: release-plz.yml`; the coordinator dispatches that workflow so the identity matches. Do not move the crate publish into the coordinator.
- Add a **Verification** subsection pointing to the durable gate (`lint-release.yml`: actionlint + shellcheck + `derive-identity.test.sh`) and the **scratch-branch-only** docs-failure fault-injection procedure from Task 8 Step 4.
- Remove all `mise run release:preview`, `--tag`, `--target <sha>`, manual `gh release create`, and hand-coordinated-lockstep content. Keep "Smoke-test the alpha" and "Promoting to a final release later", updating tag examples to `eql-3.0.0-alpha.N`.

- [ ] **Step 2: Update `CLAUDE.md`**

Replace the **Prerelease** bullet (around line 243):

```
- **Prerelease (alpha / beta / rc):** run `mise run release:all` (both artefacts in lockstep, same commit), `mise run release:eql` (SQL surface + docs only), or `mise run release:bindings` (crate for an existing SQL alpha, same-source). Each is a thin trigger that dispatches the CI-native coordinator `.github/workflows/release-alpha.yml` (`workflow_dispatch`) and watches the run via a unique `dispatch_id` — nothing release-relevant runs locally. The coordinator derives the `<version>-<channel>.<N>` identity server-side across both tag namespaces, verifies the drift gates, and (for `all`) pins+commits the crate, builds+attaches the SQL prerelease and the docs bundle in-run, then dispatches the crate publish so both land on one commit; `all`/`bindings` require `--ref <branch>` (the pin is pushed). Always `--dry-run` first. It does **not** touch `CHANGELOG.md` (previews stay under `[Unreleased]`). Full runbook: **`docs/development/releasing-an-alpha.md`**.
```

Also update the lockstep paragraph below it (lockstep is now automated by `mise run release:all` / the coordinator, same-commit) and the line-291-area pointer to name the three new tasks.

- [ ] **Step 3: Grep for stray references**

Run:
```bash
grep -rn "release:preview\|tasks/release/preview" --include="*.md" --include="*.toml" --include="*.sh" . | grep -v node_modules
```
Expected: **no matches**. Fix any that remain.

- [ ] **Step 4: Commit**

```bash
git add docs/development/releasing-an-alpha.md CLAUDE.md
git commit -m "docs(release): document CI-native release:{all,eql,bindings} flow; drop release:preview"
```

---

### Task 10: End-to-end validation (staged rollout)

**Files:** none (execution + observation only). A crates.io publish is irreversible, so a **real alpha is the only true end-to-end test**. Validate in increasing order of irreversibility. **Precondition:** the branch must be **pushed** (`gh workflow run` reads the workflow file from the dispatched ref).

- [ ] **Step 1: Static validation (mirrors the durable gate)**

Run:
```bash
actionlint .github/workflows/_build-sql.yml .github/workflows/_build-docs.yml .github/workflows/release-eql.yml .github/workflows/release-plz.yml .github/workflows/release-alpha.yml .github/workflows/lint-release.yml
shellcheck tasks/release/*.sh .github/scripts/derive-identity.sh .github/scripts/derive-identity.test.sh
bash .github/scripts/derive-identity.test.sh
```
Expected: all clean; unit test all `ok:`.

- [ ] **Step 2: `dry_run` each target (mutates nothing)**

```bash
mise run release:eql --dry-run
mise run release:all --dry-run
mise run release:bindings --dry-run   # fast failure if no SQL alpha awaits a crate, or branch advanced past it
```
Expected: each resolves an identity, prints the plan, creates nothing. Confirm via the run's "Release plan" summary. The wrapper finds its own run via `dispatch_id`.

- [ ] **Step 3: Cross-namespace `N` + guard checks (read the resolved plan / errors)**

- With `eql-3.0.0-alpha.5` present, no crate alpha: `release:all --dry-run` → identity `3.0.0-alpha.6`.
- `release:bindings --pre 3.0.0-alpha.5 --dry-run` → resolves only if the branch is **at** the `eql-3.0.0-alpha.5` commit; otherwise fails with "branch has advanced past …".
- `release:all` dispatched against a **tag** ref → `resolve` fails the pushable-branch guard.
- Invalid inputs: `release:all --version 3.0 --dry-run` and `release:all --pre 3.0.0alpha1 --dry-run` fail fast in the wrapper (and would also fail in `resolve`).

- [ ] **Step 4: Throwaway `target=eql` smoke release (SQL + docs)**

```bash
mise run release:eql
```
Expected: prerelease `eql-3.0.0-alpha.N` on branch HEAD with both `.sql` files **and** `eql-docs-*`; **no crate**, **no `release-pr`**. Verify with `gh release view` and `gh run list --workflow release-plz.yml -L 3`. Delete the throwaway: `gh release delete eql-3.0.0-alpha.N --cleanup-tag --yes`.

- [ ] **Step 5: Docs-failure aborts the crate (scratch-branch, optional)**

Run the fault-injection procedure documented in Task 8 Step 4: force `_build-docs.yml` to fail on a scratch branch and confirm `crate-publish` is **skipped**. Never on a real-publish branch.

- [ ] **Step 6: Recovery idempotence (optional)**

After a `target=all` where the crate publish failed but SQL+docs shipped, re-running `mise run release:all --pre <same-identity>` must **not** fail on the pin: `set-version` is a no-op → `pin` skips the commit/push and reuses HEAD as `S`; the run re-dispatches the crate publish. (release-plz itself is idempotent and won't republish an existing version.)

- [ ] **Step 7: Real `target=all` end-to-end**

```bash
mise run release:all
```
Verify: both tags on the **same commit `S`** (`git rev-list -n1 eql-3.0.0-alpha.N` == `git rev-list -n1 eql-bindings-v3.0.0-alpha.N`); SQL + docs built+attached in-run before the crate dispatch; the crate publish ran as a **separate `release-plz.yml` run** with `release` green, `release-pr` **skipped**, **TP token exchange succeeded**; the release lists two `.sql` + `eql-docs-*`; `eql-bindings@3.0.0-alpha.N` live on crates.io.

- [ ] **Step 8: Watch-correctness under overlap (optional)**

Dispatch two runs close together (even with identical inputs) and confirm each mise invocation watches **its own** run via its unique `dispatch_id` in the run-name.

---

## Self-Review

**Spec coverage** (companion changes + docs decision + review findings + verification):
1. `_build-sql.yml` → Task 1. ✅
2. `_build-docs.yml` (docs on alphas) → Task 2. ✅
3. `release-eql.yml` refactor (both reusables, finals parity) → Task 3. ✅
4. `release-plz.yml` `release-pr` gated to `main` → Task 4. ✅
5. Unit-testable identity derivation + test (review finding 7) → Task 5. ✅
6. Coordinator with: cross-namespace identity, all/eql/bindings flows, in-run docs, SQL→docs→crate ordering; **branch-HEAD==SQL-commit same-source guard for bindings** (finding 1); **no-op-tolerant pin** (finding 2); **pushable-branch guard** (finding 3a); **version/pre validation** (finding 4); **`dispatch_id`** in inputs + run-name (finding 6) → Task 6. ✅
7. Thin wrappers: **args-array/ShellCheck-clean** (finding 5), **detached-HEAD rejection** (finding 3b), **version/pre validation** (finding 4), **`dispatch_id` generation + unambiguous watch** (finding 6); retire `preview.sh` → Task 7. ✅
8. **Persistent actionlint + shellcheck + unit-test CI gate** + documented docs-failure fault-injection (finding 7) → Task 8. ✅
9. Docs updates → Task 9. ✅
10. Verification (dry_run, cross-namespace N, guard failures, invalid-input rejection, target=eql with docs, docs-failure aborts crate, recovery idempotence, same-commit + TP + no stray release-pr, dispatch_id watch) → Task 10. ✅

**Type/name consistency:** reusable inputs are defined once (Tasks 1, 2) and reused in Tasks 3, 6. `derive_identity` (Task 5) is called by the coordinator (Task 6) and the CI gate (Task 8). Coordinator inputs (`target`/`version`/`channel`/`pre`/`dry_run`/`dispatch_id`) match the wrappers (Task 7) and the `run-name` `[<dispatch_id>]` that the watcher greps. `pin.outputs.commit_sha` (`S`) feeds `build-sql`/`build-docs` `ref`/`target_commitish`; `crate-publish` gates on both build jobs.

**Rejected finding (per the review):** "empty tag → DEV default" is **kept as-is** — `build.sh` uses `${usage_version:-DEV}` (colon-dash), so empty *or* unset → `DEV`, and `release-eql.yml`'s PR runs rely on it. Only a one-line clarifying comment was added in `_build-sql.yml` and the Global Constraints.

---

## Risks and open questions

1. **Docs bundle preserved in-run (resolved).** `build-docs` (Task 6) attaches `eql-docs-*` after `build-sql`; `crate-publish` gates on `build-docs` success. **Cost:** each alpha run adds a doxygen install + `docs:generate`/`generate:markdown`/`package` (10-min job, no DB).

2. **Watch ambiguity (resolved via `dispatch_id`).** The wrapper generates a unique `dispatch_id` (`uuidgen`, or a PID/RANDOM/epoch fallback), passes it as an input, the coordinator echoes it into `run-name`, and the wrapper finds its run by `displayTitle | contains(dispatch_id)` — no `-L1`, no createdAt tiebreak. Even identical concurrent dispatches are disambiguated. The `lint-release.yml` gate keeps the wrappers ShellCheck-clean so this logic can't silently rot.

3. **`release-plz set-version` availability.** Installed via `cargo binstall --no-confirm release-plz` (cargo-binstall is a mise tool). If no prebuilt exists for the runner it falls back to a slow source build. **Alternative if flaky:** pin `"cargo:release-plz"` in `mise.toml [tools]`.

4. **Pin pushes to the branch with `GITHUB_TOKEN`.** Works on the unprotected `eql_v3` branch; the pushable-branch guard (Task 6) fails fast on a tag/detached ref. Protected `main` is future/out-of-scope.

5. **Cannot fully rehearse the crates.io publish.** Everything reversible (dry-run, throwaway `eql`, recovery idempotence, docs-failure fault-injection) is covered; the OIDC/TP exchange and the irreversible publish are exercised only by a real `all`/`bindings`. First real `all` should use a low, disposable `N`.

6. **`softprops/action-gh-release` prerelease semantics on the finals path.** The finals SQL attach step sets no `prerelease` input (preserving the existing release's flag); the docs reusable only attaches. Verified against the current file. A future action default change would need an explicit passthrough — watch-item, not a current change.
