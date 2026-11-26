# Same-size swap from Blacksmith to RunsOn: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move every Blacksmith job in `cipherstash/stack` to a RunsOn machine with the same vCPU count, architecture, and Ubuntu version.

**Status:** Every task is done.
Every step box is ticked.
The line under each task heading says how that task was done.

**Architecture:** Pull request #1419 already moves some jobs to RunsOn at 8 vCPUs.
Pull request #1419 also adds Docker Hub logins, and a test that requires them.
This plan merges `main` into that branch, gives every job the size it had on Blacksmith, and moves the remaining jobs.
The plan adds a test in `scripts/__tests__/` for each rule.
A later change that breaks a rule then fails that rule's test.

**Tech Stack:** GitHub Actions YAML, RunsOn v3.6.2 labels, Node.js ESM scripts, Vitest, js-yaml, and actionlint 1.7.7.

**Spec:** architecture decision record (ADR) 0004, in `docs/adr/0004-same-size-swap-from-blacksmith-to-runs-on.md`.

## Global Constraints

- The 16 vCPU label, verbatim: `runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=16/image=ubuntu22-full-x64/volume=80gb/extras=s3-cache`
- The 4 vCPU label, verbatim: `runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=4/image=ubuntu24-full-x64/volume=80gb/extras=s3-cache`
- `blacksmith-16vcpu-ubuntu-2204` becomes the 16 vCPU label.
  `blacksmith-4vcpu-ubuntu-2404` becomes the 4 vCPU label.
- If a job fails for lack of memory, its label changes from `family=c8a+m8a` to `family=m8a`.
  Nothing else in the label changes.
  No job starts on `m8a`.
- Every job that names a Blacksmith label moves.
  On `main` at `0a0fb63ec`, that is 55 job definitions in 27 workflows.
  Of these, 31 have 16 vCPUs.
  The other 24 have 4 vCPUs.
- The three Linux platforms of the FFI release matrix move too.
  `scripts/ffi-release-matrix.mjs` gives them their label, with the run ID passed in.
- Jobs on GitHub-hosted runners stay where they are.
- Job IDs, job names, triggers, trigger paths, and existing steps stay the same.
- The swap adds only three things: Docker Hub logins, a wait for the apt lock, and two secrets for one reusable workflow.
- The login reads `DOCKER_HUB_USERNAME` and `DOCKER_HUB_PASSWORD`.
  The login does nothing when either secret is empty.
  The secrets are empty on a pull request from a fork.
- Pull request #1427 sets a time limit on every job.
  Pull request #1427 merges before #1419.
- Commits are SSH-signed.
  Commits contain no `Co-Authored-By` or `Claude-Session` lines.
  Pull request text contains no Claude attribution.
- Pull requests stay drafts.
  Push only after the user has asked for this plan to be carried out.
  Never force-push.
- Text on GitHub contains no Linear issue IDs.
  Text on GitHub never names or describes the private repository that the stack-* crates came from.
- Comments, commit messages, and pull request text use short, literal sentences, one idea each.
- Do not change repository settings or secrets.
  The user does that.

## Steps only the user does

The person or agent who carries out the tasks does not do these steps.
No task waits for them.
Until the secrets exist, the login steps do nothing.
Image pulls stay anonymous until then.

- Create the free Docker Hub account.
  Create a personal access token for the account, with read-only access to public repositories.
- Add `DOCKER_HUB_USERNAME` and `DOCKER_HUB_PASSWORD` to `cipherstash/stack` as Actions secrets.
  Add both as Dependabot secrets too, because a run that Dependabot starts reads only Dependabot secrets.
- Merge #1427.
  When you choose, mark #1419 ready and merge it.

## Review Focus

1. **A reusable workflow whose caller passes no secrets.** In a called workflow, `secrets.*` is empty unless the caller passes it.
   The login would then do nothing.
   The job would pull images anonymously, with no error.
   Task 3 adds a test that every such caller passes both secrets.
2. **A RunsOn runner chosen by a matrix.** The FFI `binaries` job takes its runner from `matrix.cfg.os`.
   The login test from #1419 checks only jobs with a literal `runs-on=` label.
   So the login test would miss the musl build.
   The musl build pulls an Alpine image from Docker Hub.
   Task 2 lists each job whose runner comes from a matrix.
   Task 3 checks the ones that use RunsOn.
3. **apt on a new machine.** A new RunsOn machine can still be running an apt process that started at boot.
   `apt-get` in the job then fails at once, because the lock is already held.
   Task 4 adds a test that every apt command in a RunsOn job sets `DPkg::Lock::Timeout`.
   `DPkg::Lock::Timeout` does not make `apt-get update` wait.
   So #1419 also retries each `apt-get update`, as Task 4 explains.
4. **A label of the wrong size.** Pull request #1419 used `cpu=8`.
   A label left at `cpu=8` would give a job the wrong machine.
   If a label had no run ID, every run would share it.
   Task 2's tests accept only the labels in Global Constraints.
   The tests also refuse an FFI label with no run ID.
5. **A 16 vCPU job that needs more than 32 GB.** No test in the repository can show that a job needs this much memory.
   The CI run of #1419 is the test.
   Task 5 watches that run.
   Task 5 then applies the `m8a` rule from Global Constraints to any job killed for lack of memory.

---

## Outside this plan

- AWS has not yet raised the `RunInstances` request rate.
  When Service Quotas shows 4 for `L-A2D70E6C`, a second CloudFormation change set moves `AppSize` to `medium`.
- AWS has not yet approved the vCPU quotas of 5,000.
  Until AWS approves them, jobs beyond the first 512 vCPUs wait for a machine.
- The repository already requires approval before a workflow from any outside contributor runs.
  The GitHub API showed `all_external_contributors` on 19 November 2026.

---

### Task 1: Bring #1427 up to date with `main`

This task is done another way.
Pull request #1427 was rebased onto `main`, instead of merging `main` into it.
Pull request #1427 merged into `main` as 11db0ef99 on 20 November 2026.

Pull request #1427 sets `timeout-minutes` on every job.
The test from #1427 fails when a job has no `timeout-minutes`.
Jobs added to `main` since 28 October may have no limit.

**Files:**
- Modify: each `.github/workflows/*.yml` file the test lists
- Test: `scripts/__tests__/workflow-job-timeouts.test.mjs`, already on the branch

**Interfaces:**
- Consumes: nothing
- Produces: branch `ci/job-timeouts`.
  The branch merges into `main` with its test passing.

- [x] **Step 1: Merge `main` into the branch**

Create a worktree for `ci/job-timeouts` with the superpowers:using-git-worktrees skill.
In the worktree, run:

```bash
git fetch origin
git merge --no-edit origin/main
pnpm install --frozen-lockfile
```

Expected: the merge completes.
If the merge has a conflict, keep `main`'s lines, and add the branch's `timeout-minutes` line to the job.

- [x] **Step 2: Run the test**

Run: `pnpm exec vitest run --config scripts/vitest.config.mjs scripts/__tests__/workflow-job-timeouts.test.mjs`

Expected: PASS, or FAIL with a list of the jobs that have no limit, as `<file>#<job>` references.

- [x] **Step 3: Give each listed job a limit**

Use the rule from #1427's commit `ci(timeouts): set timeout-minutes on every job`.
The limit is about twice the job's longest successful run in the last 30 days.
Round the limit up to a multiple of 5 minutes.
The limit is never less than 10 minutes.
Read run times with `gh run list --workflow <file> --status success --limit 50 --json databaseId` and `gh run view <id> --json jobs`.

- [x] **Step 4: Run the test again**

Run: the command in Step 2.
Expected: PASS.

- [x] **Step 5: Commit and push**

If Step 1 had no conflict and Step 2 passed, push nothing, because the pull request already merges cleanly.
If Step 1 had a conflict and Step 2 passed, run `git push` to publish the merge commit.
Otherwise:

```bash
git add .github/workflows
git commit -S -m "ci(timeouts): set timeout-minutes on the jobs added since 28 October"
git push
```

Then tell the user that #1427 is ready for them to merge.

### Task 2: Swap every runner label

This task is done.
The commit `ci(runners): move every Blacksmith job to a RunsOn machine of the same size` in #1419 made these changes.
Pull request #1419 was rebased onto the branch of pull request #1416, instead of merging `main` into it.

**Files:**
- Create: `scripts/__tests__/lib/runs-on.mjs`
- Create: `scripts/__tests__/workflow-runs-on.test.mjs`
- Modify: `scripts/ffi-release-matrix.mjs`, in `runnerFor`, `releaseMatrix`, and their doc comment
- Modify: `scripts/__tests__/ffi-release-matrix.test.mjs`
- Modify: every `.github/workflows/*.yml` file that names `blacksmith-` or `cpu=8` in a `runs-on:` line
- Modify: `.github/actionlint.yaml`
- Modify: comments at lines 9 and 22 of `.github/workflows/lint-release.yml`

**Interfaces:**
- Consumes: `imageOf()` in `scripts/__tests__/workflow-mise-cache-image.test.mjs`.
  On #1419's branch, `imageOf()` already reads `image=ubuntuNN` from a RunsOn label.
- Produces, in `scripts/__tests__/lib/runs-on.mjs`:
  - `runsOnLabel(cpu: 4 | 16, { family = 'c8a+m8a', runId = '${{ github.run_id }}' } = {}): string`.
    A `cpu` of 16 gives `image=ubuntu22-full-x64`.
    A `cpu` of 4 gives `image=ubuntu24-full-x64`.
    Any other `cpu` throws an error.
  - `RUNS_ON_LABELS: ReadonlySet<string>`.
    The set contains `runsOnLabel(16)` and `runsOnLabel(4)`, plus both with `family: 'm8a'`.
  - `MATRIX_RUNNERS: Record<string, { runsOn: boolean, reason: string }>`, keyed by `'<workflow path>#<job id>'`.
    The workflow path is what `workflowFiles()` in `lib/workflows.mjs` returns.
  - `isRunsOnJob(job: object, ref?: string): boolean`.
    The result is true when `job['runs-on']` is a string that starts with `runs-on=`.
    The result is also true when `MATRIX_RUNNERS[ref]?.runsOn` is true.
- Produces, in `scripts/ffi-release-matrix.mjs`: `runnerFor(platform: string, runId = process.env.GITHUB_RUN_ID): string` and `releaseMatrix(triples, runId = process.env.GITHUB_RUN_ID)`.

- [x] **Step 1: Merge `main` into #1419's branch**

The branch `ci/heavy-jobs-runs-on` already has a worktree, at `.claude/worktrees/agent-a7c8ac844ed823b0f`.
Check that `git status` is clean there.
Then run:

```bash
git fetch origin
git merge --no-edit origin/main
pnpm install --frozen-lockfile
pnpm run test:scripts
```

Expected: PASS.
Resolve each conflict by keeping `main`'s lines, plus the branch's `runs-on:`, Docker Hub login, and apt lock changes.
A test that fails at this step fails because of the merge.
Fix the failure before you go on.

- [x] **Step 2: Write `scripts/__tests__/lib/runs-on.mjs`**

Implement the interface above.
`MATRIX_RUNNERS` contains exactly these entries:

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

- [x] **Step 3: Write the failing tests in `scripts/__tests__/workflow-runs-on.test.mjs`**

Read every job with `workflowFiles()` and `readWorkflow()`, as `{ ref: '<file>#<id>', job }`.
Two local helpers return references.
`refsWhere(predicate)` returns the `ref` of each job that matches.
`expressionRunnerRefs()` returns the `ref` of each job whose runner comes from an expression.

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

- [x] **Step 4: Update `scripts/__tests__/ffi-release-matrix.test.mjs`**

Import `runsOnLabel` from `./lib/runs-on.mjs`.
Set `const RUN_ID = '1234'`, `const MATRIX = releaseMatrix(TRIPLES, RUN_ID)`, and `const RUNS_ON_4 = runsOnLabel(4, { runId: RUN_ID })`.
Then make these changes:

- The `linux-x64-gnu`, `linux-arm64-gnu`, and `linux-x64-musl` entries expect `os: RUNS_ON_4`.
  The `script` and `log` of those entries stay as they are.
- The fallback test expects `runnerFor('linux-arm64-musl', RUN_ID)` to be `RUNS_ON_4`.
  The comment in that test says that a platform the table does not name is built on RunsOn.
- Keep the test that refuses an empty run ID: `expect(() => runnerFor('linux-x64-gnu', '')).toThrow(/GITHUB_RUN_ID/)`.
- Add `expect(runnerFor('darwin-x64', '')).toBe('macos-latest')`, because only a RunsOn label needs the run ID.

- [x] **Step 5: Run both tests to see them fail**

Run: `pnpm exec vitest run --config scripts/vitest.config.mjs scripts/__tests__/workflow-runs-on.test.mjs scripts/__tests__/ffi-release-matrix.test.mjs`

Expected: FAIL.
The test "names no Blacksmith label" lists the jobs still on Blacksmith.
The test "uses only the labels ADR 0004 names" lists the `cpu=8` jobs.
The FFI test shows `cpu=8` labels, and a Blacksmith label for musl.

- [x] **Step 6: Replace the labels in the workflows**

```bash
sed -i \
  -e 's|runs-on: blacksmith-16vcpu-ubuntu-2204|runs-on: runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=16/image=ubuntu22-full-x64/volume=80gb/extras=s3-cache|' \
  -e 's|runs-on: blacksmith-4vcpu-ubuntu-2404|runs-on: runs-on=${{ github.run_id }}/family=c8a+m8a/cpu=4/image=ubuntu24-full-x64/volume=80gb/extras=s3-cache|' \
  -e 's|/cpu=8/image=ubuntu22-full-x64/|/cpu=16/image=ubuntu22-full-x64/|' \
  -e 's|/cpu=8/image=ubuntu24-full-x64/|/cpu=4/image=ubuntu24-full-x64/|' \
  .github/workflows/*.yml
```

The last two `-e` expressions undo #1419's sizes.
On `main`, every 16 vCPU label is Ubuntu 22.04.
Every 4 vCPU label on `main` is Ubuntu 24.04.
So the image of a `cpu=8` job shows its Blacksmith size.

The labels of the publish jobs contain `extras=s3-cache` too.
`extras=s3-cache` has no effect in a job with no cache step.
`scripts/lint-no-workflow-caching.mjs` makes sure the publish jobs have no cache steps.

- [x] **Step 7: Change `runnerFor` in `scripts/ffi-release-matrix.mjs`**

For a `win32` platform, `runnerFor` returns `windows-latest`.
For a `darwin` platform, `runnerFor` returns `macos-latest`.
Neither label needs the run ID.
For every other platform, `runnerFor` returns the 4 vCPU label, with the run ID in place of `${{ github.run_id }}`.
If that run ID is empty, `runnerFor` throws an error that names `GITHUB_RUN_ID`.

Rewrite the doc comment to say three things:

- Darwin and Windows need GitHub-hosted images for their SDKs.
- Every Linux platform is built on a RunsOn machine with 4 vCPUs, the size it had on Blacksmith.
- A matrix value cannot read `${{ github.run_id }}`, so the run ID is passed in.

Remove #1419's sentences about build times, and about musl staying on Blacksmith.

- [x] **Step 8: Empty the self-hosted label list in `.github/actionlint.yaml`**

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

In `.github/workflows/lint-release.yml`, change "for the Blacksmith runner label" at line 9 to "for its self-hosted runner labels".
Change "the config it resolves the Blacksmith label from" at line 22 to "the config it reads runner labels from".

- [x] **Step 9: Run the tests to see them pass**

Run: `pnpm run test:scripts`

Expected: PASS, with one exception.
`workflow-docker-hub-login.test.mjs` now checks every moved job.
The login test lists each moved job that pulls an image with no login.
Task 3 adds those logins.
`workflow-mise-cache-image.test.mjs` passes, because each job keeps its Ubuntu version.

- [x] **Step 10: Run actionlint on the release workflows**

Run the `actionlint` command from the "actionlint (release workflows)" step of `lint-release.yml`.
Start the command with `mise x go -- go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7` in place of `actionlint`.

Expected: no output, and exit code 0.
The release workflows now contain RunsOn labels.
So this result also shows that actionlint skips a label that contains an expression.

- [x] **Step 11: Check the counts and what is left**

```bash
git grep -h 'runs-on: blacksmith-16vcpu-ubuntu-2204' origin/main -- .github/workflows | wc -l
git grep -h 'cpu=16/image=ubuntu22-full-x64' -- .github/workflows | wc -l
git grep -h 'runs-on: blacksmith-4vcpu-ubuntu-2404' origin/main -- .github/workflows | wc -l
git grep -h 'cpu=4/image=ubuntu24-full-x64' -- .github/workflows | wc -l
git grep -n -E 'cpu=8|blacksmith-' -- .github scripts/ffi-release-matrix.mjs
```

Expected:

- The first two numbers are equal.
  At `0a0fb63ec`, this pair was 31.
- The next two numbers are equal.
  At `0a0fb63ec`, this pair was 24.
- The last command lists only comments.
  The comments say why some jobs use GitHub-hosted runners.
  One comment names an arm64 label in `_build-auth-artifacts.yml`.

- [x] **Step 12: Commit**

```bash
git add .github scripts
git commit -S -m "ci(runners): move every Blacksmith job to a RunsOn machine of the same size"
```

### Task 3: Log in to Docker Hub on every RunsOn job that pulls an image

This task is done.
Two commits in #1419 made these changes: `ci(runners): log in to Docker Hub before every RunsOn job pulls an image` and `ci(runners): log in before the README walkthrough pulls its database`.

**Files:**
- Modify: `scripts/__tests__/workflow-docker-hub-login.test.mjs`
- Modify: each workflow the test lists
- Modify: `.github/workflows/_build-ffi-artifacts.yml`, `.github/workflows/release.yml`, and `.github/workflows/ffi-preflight.yml`

**Interfaces:**
- Consumes: `isRunsOnJob(job, ref)` from `scripts/__tests__/lib/runs-on.mjs`, made in Task 2.
- Produces, in `workflow-docker-hub-login.test.mjs`:
  - `jobFindings(where: string, job: object, ref?: string): string[]`.
    The RunsOn check in `jobFindings` becomes `isRunsOnJob(job, ref)`.
  - `callerFinding(job: object): string | null`.
    `callerFinding` returns null when `job.secrets` is `'inherit'`.
    `callerFinding` also returns null when `job.secrets` maps `DOCKER_HUB_USERNAME` to `${{ secrets.DOCKER_HUB_USERNAME }}` and `DOCKER_HUB_PASSWORD` to `${{ secrets.DOCKER_HUB_PASSWORD }}`.
    Otherwise, `callerFinding` returns a message that names each missing secret.

- [x] **Step 1: Write the failing tests**

In `workflow-docker-hub-login.test.mjs`:

- Replace the local `isRunsOn` with `isRunsOnJob`.
  `runsOnJobs()` builds `ref` as `${file}#${name}`, and passes `ref` to `jobFindings`.
- Rewrite the last paragraph of the header comment to say the following.
  A job counts as RunsOn when its label starts with `runs-on=`.
  A job also counts as RunsOn when `MATRIX_RUNNERS` in `lib/runs-on.mjs` says its matrix gives it RunsOn machines.
- Raise the count in the test "finds the jobs it checks" from 20 to 50.
- Add `it('passes the Docker Hub secrets to every called workflow whose RunsOn jobs log in')`.
  For each job whose `uses` starts with `./.github/workflows/`, read the workflow that the job calls.
  When one of that workflow's RunsOn jobs has a step with `loginFinding(step) === null`, `callerFinding(job)` must be null.
  Collect each failure as `<file>#<job>: <finding>`, and expect `[]`.
- Add these unit cases:

```js
expect(callerFinding({ uses: './.github/workflows/x.yml' })).toMatch(/DOCKER_HUB_USERNAME/)
expect(callerFinding({ uses: './.github/workflows/x.yml', secrets: 'inherit' })).toBeNull()
expect(callerFinding({ uses: './.github/workflows/x.yml', secrets: { DOCKER_HUB_USERNAME: USERNAME, DOCKER_HUB_PASSWORD: PASSWORD } })).toBeNull()
expect(callerFinding({ uses: './.github/workflows/x.yml', secrets: { DOCKER_HUB_USERNAME: USERNAME } })).toMatch(/DOCKER_HUB_PASSWORD/)
expect(jobFindings('w j', { 'runs-on': '${{ matrix.cfg.os }}', steps: [up] }, '.github/workflows/_build-ffi-artifacts.yml#binaries'))
  .toEqual([expect.stringMatching(/no Docker Hub login comes before it/)])
```

- [x] **Step 2: Run the test to see it fail**

Run: `pnpm exec vitest run --config scripts/vitest.config.mjs scripts/__tests__/workflow-docker-hub-login.test.mjs`

Expected: FAIL.
The test "logs in before every pull" lists each job that pulls an image with no login before it.
The list includes `_build-ffi-artifacts.yml binaries`.

- [x] **Step 3: Add a login before each pull the test lists**

Copy the "Log in to Docker Hub" step, with its comment, from a `test-eql.yml` job that has one.
Put the copy directly before the step that the finding names.
For a service container or a job container from Docker Hub, use the `credentials:` expression and its comment instead.
Copy both from the `encryption-postgres` service in `test-eql.yml`.

- [x] **Step 4: Give the musl FFI build its login and its secrets**

In `.github/workflows/_build-ffi-artifacts.yml`:

- Under `on.workflow_call`, declare both secrets with `required: false`.
- Add the login step directly before "Build the binding in Alpine (linux-x64-musl)", with `if: ${{ matrix.cfg.platform == 'linux-x64-musl' }}`.
  The macOS and Windows legs of the matrix have no Docker.
  Without the condition, `docker login` would fail on those legs once the secrets exist.

In `release.yml`, in the job that calls `_build-ffi-artifacts.yml`, pass both secrets.
Do the same in the `artifacts` job of `ffi-preflight.yml`:

```yaml
    secrets:
      DOCKER_HUB_USERNAME: ${{ secrets.DOCKER_HUB_USERNAME }}
      DOCKER_HUB_PASSWORD: ${{ secrets.DOCKER_HUB_PASSWORD }}
```

Pass these two secrets by name, not with `secrets: inherit`.
The called workflow then receives no other secret of the release workflow.

- [x] **Step 5: Run the tests to see them pass**

Run: `pnpm run test:scripts`.
Expected: PASS.

- [x] **Step 6: Run actionlint on the release workflows**

Run: the command in Task 2, Step 10.
Expected: no output, and exit code 0.
actionlint fails when a caller passes a secret that the called workflow does not declare.

- [x] **Step 7: Commit**

```bash
git add .github scripts
git commit -S -m "ci(runners): log in to Docker Hub before every RunsOn job pulls an image"
```

### Task 4: Wait for the apt lock on every RunsOn job

This task is done.
Two commits in #1419 made these changes: `test(ci): require every RunsOn job to wait for the apt lock` and `ci(runners): retry apt-get update until boot-time apt lets go`.

Pull request #1419 added `-o DPkg::Lock::Timeout=300` to the two `apt-get` steps that run on RunsOn.
Nothing yet stops a new step that leaves the option out.

`DPkg::Lock::Timeout` makes apt wait only for the dpkg lock.
`apt-get update` takes the package-list lock instead.
`apt-get update` does not wait for the package-list lock, with or without the option.
So `apt-get update` can still fail at once on a new machine.

The commit `ci(runners): retry apt-get update until boot-time apt lets go` in #1419 handles this case.
Each `apt-get update` runs in a loop of up to 20 tries, 15 seconds apart.
The `apt-get update` line in the loop ends with `&& break`.
`aptFinding` also returns a finding for an `apt-get update` line that has no `&& break`.

**Files:**
- Modify: `scripts/__tests__/workflow-runs-on.test.mjs`
- Modify: each workflow or local action the test lists.
  None is expected.

**Interfaces:**
- Consumes: `isRunsOnJob(job, ref)`, made in Task 2.
- Produces: `aptFinding(run: string): string | null`, exported from `workflow-runs-on.test.mjs`.
  `aptFinding` ignores comment lines.
  The function looks for a line that runs `apt` or `apt-get` with `update`, `install`, `upgrade`, `dist-upgrade`, `remove`, `purge`, or `autoremove`.
  When such a line has no `DPkg::Lock::Timeout=`, the function returns a message that names the line.
  Otherwise, the function returns null.

- [x] **Step 1: Write the failing tests**

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

- [x] **Step 2: Run the tests to see them fail**

Run: `pnpm exec vitest run --config scripts/vitest.config.mjs scripts/__tests__/workflow-runs-on.test.mjs`

Expected: FAIL with "aptFinding is not defined".

- [x] **Step 3: Implement `aptFinding` and `aptFindingsInRunsOnJobs`**

`aptFindingsInRunsOnJobs()` returns one `<file>#<job> step <n>: <finding>` string for each step that `aptFinding` reports.

- [x] **Step 4: Run the tests to see them pass**

Run: the command in Step 2.
Expected: PASS.
If the second test lists a step, add `-o DPkg::Lock::Timeout=300` after each `apt-get` in that step.

- [x] **Step 5: Commit**

```bash
git add scripts .github
git commit -S -m "test(ci): require every RunsOn job to wait for the apt lock"
```

### Task 5: Check the branch, and update #1419

This task is done.
The FFI run in Step 5 is GitHub Actions run 45574782571, from 25 November 2026.

**Files:** no new files.

- [x] **Step 1: Run the checks that CI runs on these files**

```bash
pnpm run test:scripts
pnpm run lint:workflow-cache
pnpm run code:check
```

Expected: all three pass.
`code:check` fails only on errors.
The check may still print warnings.

- [x] **Step 2: Check that no job name changed**

```bash
git diff origin/main...HEAD -U0 -- .github/workflows | grep -E '^[-+][[:space:]]+(- )?name:'
```

With three dots, `git diff` compares with the commit where the branch left `main`.
Without them, the diff also shows `main`'s newer changes, as if the branch had made them.

Expected: only added lines that read `+      - name: Log in to Docker Hub`.
A removed or changed job `name:` means the diff changes more than ADR 0004 allows.

- [x] **Step 3: Push**

Run: `git push origin ci/heavy-jobs-runs-on`

Expected: a normal push.
If git refuses because the remote branch moved, stop and tell the user.

- [x] **Step 4: Update the title and body of #1419**

Use the meta-pr-creation skill.
The title is `ci(runners): move every Blacksmith job to a RunsOn machine of the same size`.
The body says what changes, why, and how to check it.
The body points to ADR 0004 for the cost reasons.

Set the title and body with `gh pr edit 1419 --title <title> --body-file <file>`.
Keep the pull request a draft.

- [x] **Step 5: Run the FFI build on RunsOn**

The release workflows do not run on a pull request.
`ffi-preflight.yml` runs the FFI build without publishing anything:

```bash
gh workflow run ffi-preflight.yml --ref ci/heavy-jobs-runs-on -f ref=ci/heavy-jobs-runs-on
```

Expected: the two gnu legs pass.
The musl leg fails as it does on `main`, for the reason in #1380.
The wrapper job is skipped, because it needs the musl leg.

- [x] **Step 6: Watch the pull request's CI run**

Run: `gh pr checks 1419 --watch`.
Read each failed job's log with `gh run view <run-id> --log-failed`.

- **Killed for lack of memory:** the log shows exit code 137, "Killed", or "signal: 9, SIGKILL".
  Change that job's `family=c8a+m8a` to `family=m8a`.
  Run `pnpm run test:scripts`.
  Then commit with the message `ci(runners): give <job name> 4 GB per vCPU on m8a`, and push.
- **`toomanyrequests` from Docker Hub:** report the job to the user.
  The secrets may not exist yet.
  Or the jobs may have used all 200 pulls that the free account allows in 6 hours.
  ADR 0004 names the source of that figure.
- **Any other failure:** compare it with the same job's latest run on `main`.
  Report the failure to the user, with an excerpt from each log.

### Task 6: Record the decision and this plan in #1416

This task is done.
The commit `docs(ci): record the same-size swap from Blacksmith to RunsOn` in #1416 made these changes.

**Files:**
- Modify: `docs/adr/0004-same-size-swap-from-blacksmith-to-runs-on.md`, to `status: accepted`
- Add: `docs/superpowers/plans/2026-11-19-same-size-swap-blacksmith-to-runs-on.md`
- Add: the uncommitted changes to `.github/CONTEXT.md`, ADR 0002, and ADR 0003

Work in the worktree of branch `docs/ci-cost-decisions`.
Leave out the CSV and PDF files at the repository root.
Those files are local data, not documentation.

- [x] **Step 1: Set the ADR's status**

Change line 2 of ADR 0004 to `status: accepted`.

- [x] **Step 2: Commit**

```bash
git add .github/CONTEXT.md docs/adr/0002-light-ci-jobs-on-github-hosted-runners-heavy-jobs-on-runs-on.md docs/adr/0003-expensive-ci-checks-run-in-merge-queues-on-main-and-next.md docs/adr/0004-same-size-swap-from-blacksmith-to-runs-on.md docs/superpowers/plans/2026-11-19-same-size-swap-blacksmith-to-runs-on.md
git commit -S -m "docs(ci): record the same-size swap from Blacksmith to RunsOn"
```

- [x] **Step 3: Push and update #1416**

Run `git push`.
Then add one paragraph to the body of #1416.
The paragraph says that ADR 0004 supersedes ADR 0002, and pauses ADR 0003.
Keep the pull request a draft.
