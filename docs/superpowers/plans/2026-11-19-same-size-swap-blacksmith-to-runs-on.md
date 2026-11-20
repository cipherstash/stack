# Same-size swap from Blacksmith to RunsOn: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move every Blacksmith job in `cipherstash/stack` to a RunsOn machine with the same vCPU count, architecture, and Ubuntu version.

**Architecture:** Pull request #1419 already moves some jobs to RunsOn at 8 vCPUs. It also adds Docker Hub logins and a test that requires them. This plan merges `main` into that branch, gives every job its Blacksmith size, and moves the remaining jobs. Each rule gets a test in `scripts/__tests__/`. A later change that breaks a rule then fails a test.

**Tech Stack:** GitHub Actions YAML, RunsOn v3.6.2 labels, Node.js ESM scripts, Vitest, js-yaml, and actionlint 1.7.7.

**Spec:** `docs/adr/0004-same-size-swap-from-blacksmith-to-runs-on.md`.

## Global Constraints

- The 16 vCPU label, verbatim: `runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=16/image=ubuntu22-full-x64/volume=80gb/extras=s3-cache`
- The 4 vCPU label, verbatim: `runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=4/image=ubuntu24-full-x64/volume=80gb/extras=s3-cache`
- `blacksmith-16vcpu-ubuntu-2204` becomes the 16 vCPU label. `blacksmith-4vcpu-ubuntu-2404` becomes the 4 vCPU label.
- A job that fails for lack of memory changes `family=c8a+m8a` to `family=m8a`. Nothing else in its label changes. No job starts on `m8a`.
- Every job that names a Blacksmith label moves. On `main` at `0a0fb63ec`, that is 55 job definitions in 27 workflows. Of these, 31 have 16 vCPUs. The other 24 have 4 vCPUs.
- The three Linux platforms of the FFI release matrix move too. `scripts/ffi-release-matrix.mjs` gives them their label, with the run ID passed in.
- Jobs on GitHub-hosted runners stay where they are.
- Job IDs, job names, triggers, trigger paths, and existing steps stay the same. Branch rules require some job names, so a renamed job would leave a required check waiting.
- The swap adds three things only: Docker Hub logins, a wait for the apt lock, and two secrets for one reusable workflow.
- The login reads `DOCKER_HUB_USERNAME` and `DOCKER_HUB_PASSWORD`. It does nothing when either secret is empty, as on a pull request from a fork.
- #1427 sets the time limits. It merges before #1419.
- Commits are SSH-signed. They carry no `Co-Authored-By` or `Claude-Session` lines. Pull request text contains no Claude attribution.
- Pull requests stay drafts. Push only after the user has asked for this plan to be carried out. Never force-push.
- GitHub text contains no Linear issue IDs. It never names or describes the private repository that the stack-* crates came from.
- Comments, commit messages, and pull request text use short, literal sentences, one idea each.
- Do not change repository settings or secrets. The user does that.

## Steps only the user does

These are not tasks for the executor, and no task waits for them. Until the secrets exist, the login steps do nothing, and pulls stay anonymous.

- Create the free Docker Hub account. Create a personal access token for it with read-only access to public repositories.
- Add `DOCKER_HUB_USERNAME` and `DOCKER_HUB_PASSWORD` to `cipherstash/stack` as Actions secrets. Add both as Dependabot secrets too, because Dependabot runs read only those.
- Merge #1427. Mark #1419 ready and merge it when you choose.

## Review Focus

1. **A reusable workflow whose caller passes no secrets.** In a called workflow, `secrets.*` is empty unless the caller passes it. The login would skip. The job would then pull anonymously without an error. Task 3 adds a test that every such caller passes both secrets.
2. **A RunsOn runner chosen by a matrix.** The FFI `binaries` job takes its runner from `matrix.cfg.os`. The login test from #1419 checks only jobs with a literal `runs-on=` label. So it would miss the musl build. That build pulls Alpine from Docker Hub. Task 2 lists each matrix runner job, and Task 3 checks the RunsOn ones.
3. **apt on a fresh machine.** A new RunsOn machine can still be running apt from boot. `apt-get` then fails at once on the held lock. Task 4 adds a test that every apt command in a RunsOn job waits for the lock.
4. **A label of the wrong size.** #1419 used `cpu=8`. A label left at `cpu=8` would give a job the wrong machine. A label with no run ID would be shared by every run. Task 2's tests accept only the labels in Global Constraints, and refuse an FFI label with no run ID.
5. **A 16 vCPU job that needs more than 32 GB.** No repository test can show this. The pull request's own CI run is the test. Task 5 watches it and applies the `m8a` rule to any job killed for lack of memory.

---

## Outside this plan

- AWS has not yet raised the `RunInstances` request rate. When Service Quotas shows 4 for `L-A2D70E6C`, a second CloudFormation change set moves `AppSize` to `medium`.
- AWS has not yet approved the vCPU quotas of 5,000. Until it does, jobs above 512 vCPUs wait for a machine.
- The repository already requires approval before a workflow from any outside contributor runs. The API showed `all_external_contributors` on 19 November 2026.

---

### Task 1: Bring #1427 up to date with `main`

#1427 sets `timeout-minutes` on every job, and its test fails when a job has none. Jobs added to `main` since 28 October may have no limit.

**Files:**
- Modify: each `.github/workflows/*.yml` file the test lists
- Test: `scripts/__tests__/workflow-job-timeouts.test.mjs`, already on the branch

**Interfaces:**
- Consumes: nothing
- Produces: branch `ci/job-timeouts`. It merges into `main` with its test passing.

- [ ] **Step 1: Merge `main` into the branch**

Create a worktree for `ci/job-timeouts` with the superpowers:using-git-worktrees skill. In it, run:

```bash
git fetch origin
git merge --no-edit origin/main
pnpm install --frozen-lockfile
```

Expected: the merge completes. On a conflict, keep `main`'s lines and add the branch's `timeout-minutes` line to the job.

- [ ] **Step 2: Run the test**

Run: `pnpm exec vitest run --config scripts/vitest.config.mjs scripts/__tests__/workflow-job-timeouts.test.mjs`

Expected: PASS, or FAIL with a list of `<file>#<job>` references that have no limit.

- [ ] **Step 3: Give each listed job a limit**

Use the rule from commit `c1985b4a8`. The limit is about twice the job's longest successful run in the last 30 days. Round it up to a multiple of 5 minutes, with a floor of 10. Read run times with `gh run list --workflow <file> --status success --limit 50 --json databaseId` and `gh run view <id> --json jobs`.

- [ ] **Step 4: Run the test again**

Run: the command in Step 2. Expected: PASS.

- [ ] **Step 5: Commit and push**

If Step 2 passed, push nothing, because the pull request already merges cleanly. Otherwise:

```bash
git add .github/workflows
git commit -S -m "ci(timeouts): set timeout-minutes on the jobs added since 28 October"
git push
```

Then tell the user that #1427 is ready for them to merge.

### Task 2: Swap every runner label

**Files:**
- Create: `scripts/__tests__/lib/runs-on.mjs`
- Create: `scripts/__tests__/workflow-runs-on.test.mjs`
- Modify: `scripts/ffi-release-matrix.mjs`, in `runnerFor`, `releaseMatrix`, and their doc comment
- Modify: `scripts/__tests__/ffi-release-matrix.test.mjs`
- Modify: every `.github/workflows/*.yml` file that names `blacksmith-` or `cpu=8` in a `runs-on:` line
- Modify: `.github/actionlint.yaml`
- Modify: comments at lines 9 and 22 of `.github/workflows/lint-release.yml`

**Interfaces:**
- Consumes: `imageOf()` in `scripts/__tests__/workflow-mise-cache-image.test.mjs`. On #1419's branch, it already reads `image=ubuntuNN` from a RunsOn label.
- Produces, in `scripts/__tests__/lib/runs-on.mjs`:
  - `runsOnLabel(cpu: 4 | 16, { family = 'c8a+m8a', runId = '${{ github.run_id }}' } = {}): string`. A `cpu` of 16 gives `image=ubuntu22-full-x64`. A `cpu` of 4 gives `image=ubuntu24-full-x64`. Any other `cpu` throws.
  - `RUNS_ON_LABELS: ReadonlySet<string>`, holding `runsOnLabel(16)` and `runsOnLabel(4)`, plus both with `family: 'm8a'`.
  - `MATRIX_RUNNERS: Record<string, { runsOn: boolean, reason: string }>`, keyed by `'<workflow path>#<job id>'`. The workflow path is what `workflowFiles()` in `lib/workflows.mjs` returns.
  - `isRunsOnJob(job: object, ref?: string): boolean`. It is true when `job['runs-on']` is a string that starts with `runs-on=`. It is also true when `MATRIX_RUNNERS[ref]?.runsOn` is true.
- Produces, in `scripts/ffi-release-matrix.mjs`: `runnerFor(platform: string, runId = process.env.GITHUB_RUN_ID): string` and `releaseMatrix(triples, runId = process.env.GITHUB_RUN_ID)`.

- [ ] **Step 1: Merge `main` into #1419's branch**

The branch `ci/heavy-jobs-runs-on` already has a worktree, at `.claude/worktrees/agent-a7c8ac844ed823b0f`. Check that `git status` is clean there. Then run:

```bash
git fetch origin
git merge --no-edit origin/main
pnpm install --frozen-lockfile
pnpm run test:scripts
```

Expected: PASS. Resolve each conflict by keeping `main`'s lines, plus the branch's `runs-on:`, Docker Hub login, and apt lock changes. A test failure at this step comes from the merge, so fix it before going on.

- [ ] **Step 2: Write `scripts/__tests__/lib/runs-on.mjs`**

Implement the interface above. `MATRIX_RUNNERS` contains exactly these entries:

```js
export const MATRIX_RUNNERS = {
  '.github/workflows/_build-ffi-artifacts.yml#binaries': {
    runsOn: true,
    reason: 'scripts/ffi-release-matrix.mjs gives every Linux platform a RunsOn label.',
  },
  '.github/workflows/_build-auth-artifacts.yml#binaries': {
    runsOn: false,
    reason: 'Its matrix names GitHub-hosted runners only.',
  },
  '.github/workflows/tests-golang.yml#go-binding-cross': {
    runsOn: false,
    reason: 'Its matrix is macos-latest and windows-latest.',
  },
}
```

- [ ] **Step 3: Write the failing tests in `scripts/__tests__/workflow-runs-on.test.mjs`**

Read every job with `workflowFiles()` and `readWorkflow()`, as `{ ref: '<file>#<id>', job }`. Two local helpers return references. `refsWhere(predicate)` returns the `ref` of each job that matches. `expressionRunnerRefs()` returns the `ref` of each job whose runner comes from an expression.

```js
describe('RunsOn runner labels', () => {
  it('builds the labels ADR 0004 names', () => {
    expect(runsOnLabel(16)).toBe('runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=16/image=ubuntu22-full-x64/volume=80gb/extras=s3-cache')
    expect(runsOnLabel(4)).toBe('runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=4/image=ubuntu24-full-x64/volume=80gb/extras=s3-cache')
    expect(runsOnLabel(4, { family: 'm8a' })).toBe('runs-on=${{ github.run_id }}/family=m8a/cpu=4/image=ubuntu24-full-x64/volume=80gb/extras=s3-cache')
    expect(() => runsOnLabel(8)).toThrow()
  })

  it('finds the jobs it checks', () => {
    expect(jobs.filter(({ job, ref }) => isRunsOnJob(job, ref)).length).toBeGreaterThan(50)
  })

  it('names no Blacksmith label', () => {
    // JSON.stringify covers a runs-on that is a list or an object.
    expect(refsWhere(({ job }) => /blacksmith-/.test(JSON.stringify(job['runs-on'] ?? '')))).toEqual([])
  })

  it('uses only the labels ADR 0004 names', () => {
    expect(refsWhere(({ job }) => {
      const label = job['runs-on']
      return typeof label === 'string' && label.startsWith('runs-on=') && !RUNS_ON_LABELS.has(label)
    })).toEqual([])
  })

  it('lists every job whose runner comes from an expression', () => {
    // An expression runner: runs-on is not a string, or contains `${{` and
    // does not start with `runs-on=`. Both directions, so a stale entry fails.
    expect(expressionRunnerRefs().sort()).toEqual(Object.keys(MATRIX_RUNNERS).sort())
    expect(Object.values(MATRIX_RUNNERS).every(({ reason }) => reason.trim())).toBe(true)
  })
})
```

Each string that contains `${{` needs the `biome-ignore lint/suspicious/noTemplateCurlyInString` comment that `workflow-mise-cache-image.test.mjs` uses.

- [ ] **Step 4: Update `scripts/__tests__/ffi-release-matrix.test.mjs`**

Import `runsOnLabel` from `./lib/runs-on.mjs`. Set `const RUN_ID = '1234'`, `const MATRIX = releaseMatrix(TRIPLES, RUN_ID)`, and `const RUNS_ON_4 = runsOnLabel(4, { runId: RUN_ID })`. Then:

- The `linux-x64-gnu`, `linux-arm64-gnu`, and `linux-x64-musl` entries expect `os: RUNS_ON_4`. Their `script` and `log` stay as they are.
- The fallback test expects `runnerFor('linux-arm64-musl', RUN_ID)` to be `RUNS_ON_4`. Its comment says that a platform the table does not name builds on RunsOn.
- Keep the test that refuses an empty run ID: `expect(() => runnerFor('linux-x64-gnu', '')).toThrow(/GITHUB_RUN_ID/)`.
- Add `expect(runnerFor('darwin-x64', '')).toBe('macos-latest')`, because only a RunsOn label needs the run ID.

- [ ] **Step 5: Run both tests to see them fail**

Run: `pnpm exec vitest run --config scripts/vitest.config.mjs scripts/__tests__/workflow-runs-on.test.mjs scripts/__tests__/ffi-release-matrix.test.mjs`

Expected: FAIL. "names no Blacksmith label" lists the jobs still on Blacksmith. "uses only the labels ADR 0004 names" lists the `cpu=8` jobs. The FFI test shows `cpu=8` labels, and a Blacksmith label for musl.

- [ ] **Step 6: Replace the labels in the workflows**

```bash
sed -i \
  -e 's|runs-on: blacksmith-16vcpu-ubuntu-2204|runs-on: runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=16/image=ubuntu22-full-x64/volume=80gb/extras=s3-cache|' \
  -e 's|runs-on: blacksmith-4vcpu-ubuntu-2404|runs-on: runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=4/image=ubuntu24-full-x64/volume=80gb/extras=s3-cache|' \
  -e 's|/cpu=8/image=ubuntu22-full-x64/|/cpu=16/image=ubuntu22-full-x64/|' \
  -e 's|/cpu=8/image=ubuntu24-full-x64/|/cpu=4/image=ubuntu24-full-x64/|' \
  .github/workflows/*.yml
```

The last two lines undo #1419's sizes. On `main`, every 16 vCPU label is Ubuntu 22.04, and every 4 vCPU label is Ubuntu 24.04. So the image of a `cpu=8` job shows its Blacksmith size.

The publish jobs get `extras=s3-cache` too. It has no effect in a job with no cache step. `scripts/lint-no-workflow-caching.mjs` keeps the publish jobs free of cache steps.

- [ ] **Step 7: Change `runnerFor` in `scripts/ffi-release-matrix.mjs`**

A `win32` platform gives `windows-latest`, and a `darwin` platform gives `macos-latest`. Neither needs the run ID. Every other platform gives the 4 vCPU label, with the run ID in place of the expression. An empty run ID throws an error that names `GITHUB_RUN_ID`.

Rewrite the doc comment to say three things. Darwin and Windows need GitHub-hosted images for their SDKs. Every Linux platform builds on a RunsOn machine with 4 vCPUs, its size on Blacksmith. A matrix value cannot read `${{ github.run_id }}`, so the run ID is passed in. Remove #1419's sentences about build times and about musl staying on Blacksmith.

- [ ] **Step 8: Empty the self-hosted label list in `.github/actionlint.yaml`**

Replace the file's content with:

```yaml
# actionlint checks every `runs-on:` label against the GitHub-hosted labels it
# knows, and against the self-hosted labels listed here.
#
# The list is empty. Every self-hosted job runs on RunsOn, and each RunsOn
# label starts with `runs-on=${{ github.run_id }}`. actionlint does not check
# a label that contains an expression. So a Blacksmith label is now unknown,
# and actionlint reports it.
self-hosted-runner:
  labels: []
```

In `.github/workflows/lint-release.yml`, change "for the Blacksmith runner label" at line 9 to "for its self-hosted runner labels". Change "the config it resolves the Blacksmith label from" at line 22 to "the config it reads runner labels from".

- [ ] **Step 9: Run the tests to see them pass**

Run: `pnpm run test:scripts`

Expected: PASS, with one exception. `workflow-docker-hub-login.test.mjs` now checks every moved job, and lists those that pull an image with no login. Task 3 adds those logins. `workflow-mise-cache-image.test.mjs` passes, because each job keeps its Ubuntu version.

- [ ] **Step 10: Run actionlint on the release workflows**

Run the `actionlint` command from the "actionlint (release workflows)" step of `lint-release.yml`. Start it with `mise x go -- go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7` in place of `actionlint`.

Expected: no output, and exit code 0. The release workflows now carry RunsOn labels, so this also shows that actionlint skips a label with an expression.

- [ ] **Step 11: Check the counts and what is left**

```bash
git grep -h 'runs-on: blacksmith-16vcpu-ubuntu-2204' origin/main -- .github/workflows | wc -l
git grep -h 'cpu=16/image=ubuntu22-full-x64' -- .github/workflows | wc -l
git grep -h 'runs-on: blacksmith-4vcpu-ubuntu-2404' origin/main -- .github/workflows | wc -l
git grep -h 'cpu=4/image=ubuntu24-full-x64' -- .github/workflows | wc -l
git grep -n -E 'cpu=8|blacksmith-' -- .github scripts/ffi-release-matrix.mjs
```

Expected: the first two numbers match, and so do the next two. At `0a0fb63ec` they were 31 and 24. The last command lists only comments. They say why some jobs use GitHub-hosted runners, and one names an arm64 label in `_build-auth-artifacts.yml`.

- [ ] **Step 12: Commit**

```bash
git add .github scripts
git commit -S -m "ci(runners): move every Blacksmith job to a RunsOn machine of the same size"
```

### Task 3: Log in to Docker Hub on every RunsOn job that pulls an image

**Files:**
- Modify: `scripts/__tests__/workflow-docker-hub-login.test.mjs`
- Modify: each workflow the test lists
- Modify: `.github/workflows/_build-ffi-artifacts.yml`, `.github/workflows/release.yml`, and `.github/workflows/ffi-preflight.yml`

**Interfaces:**
- Consumes: `isRunsOnJob(job, ref)` from `scripts/__tests__/lib/runs-on.mjs`, made in Task 2.
- Produces, in `workflow-docker-hub-login.test.mjs`:
  - `jobFindings(where: string, job: object, ref?: string): string[]`. Its RunsOn check becomes `isRunsOnJob(job, ref)`.
  - `callerFinding(job: object): string | null`. It returns null when `job.secrets` is `'inherit'`. It also returns null when `job.secrets` maps `DOCKER_HUB_USERNAME` to `${{ secrets.DOCKER_HUB_USERNAME }}` and `DOCKER_HUB_PASSWORD` to `${{ secrets.DOCKER_HUB_PASSWORD }}`. Otherwise it returns a message that names each missing secret.

- [ ] **Step 1: Write the failing tests**

In `workflow-docker-hub-login.test.mjs`:

- Replace the local `isRunsOn` with `isRunsOnJob`. `runsOnJobs()` builds `ref` as `${file}#${name}` and passes it to `jobFindings`.
- Rewrite the last paragraph of the header comment. A job counts as RunsOn when its label starts with `runs-on=`. It also counts when `MATRIX_RUNNERS` in `lib/runs-on.mjs` says its matrix gives it RunsOn machines.
- Raise the count in "finds the jobs it checks" from 20 to 50.
- Add `it('passes the Docker Hub secrets to every called workflow whose RunsOn jobs log in')`. Take each job whose `uses` starts with `./.github/workflows/`, and read the workflow it calls. When one of that workflow's RunsOn jobs has a step with `loginFinding(step) === null`, `callerFinding(job)` must be null. Collect each failure as `<file>#<job>: <finding>`, and expect `[]`.
- Add these unit cases:

```js
expect(callerFinding({ uses: './.github/workflows/x.yml' })).toMatch(/DOCKER_HUB_USERNAME/)
expect(callerFinding({ uses: './.github/workflows/x.yml', secrets: 'inherit' })).toBeNull()
expect(callerFinding({ uses: './.github/workflows/x.yml', secrets: { DOCKER_HUB_USERNAME: USERNAME, DOCKER_HUB_PASSWORD: PASSWORD } })).toBeNull()
expect(callerFinding({ uses: './.github/workflows/x.yml', secrets: { DOCKER_HUB_USERNAME: USERNAME } })).toMatch(/DOCKER_HUB_PASSWORD/)
expect(jobFindings('w j', { 'runs-on': '${{ matrix.cfg.os }}', steps: [up] }, '.github/workflows/_build-ffi-artifacts.yml#binaries'))
  .toEqual([expect.stringMatching(/no Docker Hub login comes before it/)])
```

- [ ] **Step 2: Run the test to see it fail**

Run: `pnpm exec vitest run --config scripts/vitest.config.mjs scripts/__tests__/workflow-docker-hub-login.test.mjs`

Expected: FAIL. "logs in before every pull" lists each job that pulls an image with no login before it. The list includes `_build-ffi-artifacts.yml binaries`.

- [ ] **Step 3: Add a login before each pull the test lists**

Copy the "Log in to Docker Hub" step, with its comment, from a `test-eql.yml` job that has one. Put it right before the step that the finding names. A service or job container from Docker Hub instead gets the `credentials:` expression and comment from the `encryption-postgres` service in `test-eql.yml`.

- [ ] **Step 4: Give the musl FFI build its login and its secrets**

In `.github/workflows/_build-ffi-artifacts.yml`:

- Under `on.workflow_call`, declare both secrets with `required: false`.
- Add the login step right before "Build the binding in Alpine (linux-x64-musl)", with `if: ${{ matrix.cfg.platform == 'linux-x64-musl' }}`. The macOS and Windows legs have no Docker. Without the condition, `docker login` would fail there once the secrets exist.

In `release.yml`, in the job that calls `_build-ffi-artifacts.yml`, pass both secrets. Do the same in the `artifacts` job of `ffi-preflight.yml`:

```yaml
    secrets:
      DOCKER_HUB_USERNAME: ${{ secrets.DOCKER_HUB_USERNAME }}
      DOCKER_HUB_PASSWORD: ${{ secrets.DOCKER_HUB_PASSWORD }}
```

Pass these two by name, not with `secrets: inherit`. The called workflow then receives no other secret of the release workflow.

- [ ] **Step 5: Run the tests to see them pass**

Run: `pnpm run test:scripts`. Expected: PASS.

- [ ] **Step 6: Run actionlint on the release workflows**

Run: the command in Task 2, Step 10. Expected: no output, and exit code 0. actionlint fails when a caller passes a secret that the called workflow does not declare.

- [ ] **Step 7: Commit**

```bash
git add .github scripts
git commit -S -m "ci(runners): log in to Docker Hub before every RunsOn job pulls an image"
```

### Task 4: Wait for the apt lock on every RunsOn job

#1419 added `-o DPkg::Lock::Timeout=300` to the two `apt-get` steps that run on RunsOn. Nothing yet stops a new step without it.

**Files:**
- Modify: `scripts/__tests__/workflow-runs-on.test.mjs`
- Modify: each workflow or local action the test lists. None is expected.

**Interfaces:**
- Consumes: `isRunsOnJob(job, ref)`, made in Task 2.
- Produces: `aptFinding(run: string): string | null`, exported from `workflow-runs-on.test.mjs`. It ignores comment lines. It looks for a line that runs `apt` or `apt-get` with `update`, `install`, `upgrade`, `dist-upgrade`, `remove`, `purge`, or `autoremove`. When such a line has no `DPkg::Lock::Timeout=`, it returns a message that names the line. Otherwise it returns null.

- [ ] **Step 1: Write the failing tests**

```js
it('recognises an apt command that does not wait for the lock', () => {
  expect(aptFinding('sudo apt-get update')).toMatch(/DPkg::Lock::Timeout/)
  expect(aptFinding('sudo apt install -y jq')).toMatch(/DPkg::Lock::Timeout/)
  expect(aptFinding('sudo apt-get -o DPkg::Lock::Timeout=300 install -y doxygen')).toBeNull()
  expect(aptFinding('# sudo apt-get update')).toBeNull()
  expect(aptFinding('apt-cache policy doxygen')).toBeNull()
})

it('waits for the apt lock in every RunsOn job', () => {
  // Every step of every RunsOn job. A `uses: ./…` step is followed into the
  // composite action's runs.steps, as stepPulls does in
  // workflow-docker-hub-login.test.mjs.
  expect(aptFindingsInRunsOnJobs()).toEqual([])
})
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `pnpm exec vitest run --config scripts/vitest.config.mjs scripts/__tests__/workflow-runs-on.test.mjs`

Expected: FAIL with "aptFinding is not defined".

- [ ] **Step 3: Implement `aptFinding` and `aptFindingsInRunsOnJobs`**

`aptFindingsInRunsOnJobs()` returns one `<file>#<job> step <n>: <finding>` string for each step that `aptFinding` reports.

- [ ] **Step 4: Run the tests to see them pass**

Run: the command in Step 2. Expected: PASS. If the second test lists a step, add `-o DPkg::Lock::Timeout=300` after each `apt-get` in that step.

- [ ] **Step 5: Commit**

```bash
git add scripts .github
git commit -S -m "test(ci): require every RunsOn job to wait for the apt lock"
```

### Task 5: Check the branch, and update #1419

**Files:** no new files.

- [ ] **Step 1: Run the checks that CI runs on these files**

```bash
pnpm run test:scripts
pnpm run lint:workflow-cache
pnpm run code:check
```

Expected: all three pass. `code:check` fails on errors only, and may print warnings.

- [ ] **Step 2: Check that no job name changed**

```bash
git diff origin/main -U0 -- .github/workflows | grep -E '^[-+][[:space:]]+(- )?name:'
```

Expected: only added lines that read `+      - name: Log in to Docker Hub`. A removed or changed job `name:` would leave a required check waiting.

- [ ] **Step 3: Push**

Run: `git push origin ci/heavy-jobs-runs-on`

Expected: a normal push. If git refuses because the remote branch moved, stop and tell the user.

- [ ] **Step 4: Update the title and body of #1419**

Use the meta-pr-creation skill. The title is `ci(runners): move every Blacksmith job to a RunsOn machine of the same size`. The body says what changes, why, and how to check it. It points to ADR 0004 for the cost reasons. Keep the pull request a draft, and set both with `gh pr edit 1419 --title <title> --body-file <file>`.

- [ ] **Step 5: Run the FFI build on RunsOn**

The release workflows do not run on a pull request. `ffi-preflight.yml` runs the FFI build without publishing anything:

```bash
gh workflow run ffi-preflight.yml --ref ci/heavy-jobs-runs-on -f ref=ci/heavy-jobs-runs-on
```

Expected: the two gnu legs and the wrapper job pass. The musl leg fails as it does on `main`, for the reason in #1380.

- [ ] **Step 6: Watch the pull request's CI run**

Run: `gh pr checks 1419 --watch`. Read each failed job's log with `gh run view <run-id> --log-failed`.

- **Killed for lack of memory:** the log shows exit code 137, "Killed", or "signal: 9, SIGKILL". Change that job's `family=c8a+m8a` to `family=m8a`. Run `pnpm run test:scripts`, then commit with the message `ci(runners): give <job name> 4 GB per vCPU on m8a`, and push.
- **`toomanyrequests` from Docker Hub:** report the job to the user. The secrets may not exist yet. Or the jobs may have used all 200 pulls that the free account allows in 6 hours.
- **Any other failure:** compare it with the same job's latest run on `main`. Report it to the user with an excerpt from each log.

### Task 6: Record the decision and this plan in #1416

This task is done. Commit `6d0933ccd` on #1416 made these changes.

**Files:**
- Modify: `docs/adr/0004-same-size-swap-from-blacksmith-to-runs-on.md`, to `status: accepted`
- Add: `docs/superpowers/plans/2026-11-19-same-size-swap-blacksmith-to-runs-on.md`
- Add: the uncommitted changes to `.github/CONTEXT.md`, ADR 0002, and ADR 0003

Work in the worktree of branch `docs/ci-cost-decisions`. Leave out the CSV and PDF files at the repository root. They are local data, not documentation.

- [x] **Step 1: Set the ADR's status**

Change line 2 of ADR 0004 to `status: accepted`.

- [x] **Step 2: Commit**

```bash
git add .github/CONTEXT.md docs/adr/0002-light-ci-jobs-on-github-hosted-runners-heavy-jobs-on-runs-on.md docs/adr/0003-expensive-ci-checks-run-in-merge-queues-on-main-and-next.md docs/adr/0004-same-size-swap-from-blacksmith-to-runs-on.md docs/superpowers/plans/2026-11-19-same-size-swap-blacksmith-to-runs-on.md
git commit -S -m "docs(ci): record the same-size swap from Blacksmith to RunsOn"
```

- [x] **Step 3: Push and update #1416**

Run `git push`. Then add one paragraph to the body of #1416. It says that ADR 0004 supersedes ADR 0002 and pauses ADR 0003. Keep the pull request a draft.
