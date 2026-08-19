import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, WORKFLOW_DIR, workflowFiles } from './lib/workflows.mjs'

/**
 * Guards that the EQL suite is RUN, not merely present.
 *
 * This is the second time the repo has hit this. Upstream
 * (`cipherstash/encrypt-query-language`) ran the SQLx matrix on every pull
 * request from `.github/workflows/test-eql.yml`; the subtree import copied that
 * file to `packages/eql/.github/workflows/test-eql.yml`, where GitHub never
 * looks — it reads workflows from the repository root alone. For the length of
 * the import, every sharded SQLx assertion, the e2e property suite, the codegen
 * parity gates and the doc/known-failure checks executed nowhere, and a suite
 * that never starts reads exactly like a suite that passes.
 *
 * `packages/protect-ffi/src/integrationSuiteCi.test.ts` is the same file for
 * the same failure one absorption earlier, and its comment predicted this one:
 * "the next subtree import brings its own `.github/`, and it will arrive
 * looking exactly as authoritative as this one did."
 *
 * Two properties, and the second is the one that would go quiet without a
 * sound. That a root workflow invokes the suite is loud when wrong — nothing
 * runs, no status appears. That its RELEVANCE FILTER still selects EQL's files
 * after the tree moved a level down is not: an unprefixed `src/**` matches
 * `packages/stack/src/**` and misses `packages/eql/src/**` entirely, so the
 * heavy jobs would skip on exactly the changes they exist to check, report
 * `skipped`, and let `ci-required` go green having compiled nothing.
 */

/** The EQL suite's own workflow, at the only path GitHub reads. */
const EQL_WORKFLOW = `${WORKFLOW_DIR}/test-eql.yml`

/**
 * The nightly/push-only bench workflow, named because it is the SOLE caller of
 * a cargo check (`test:bench`) and therefore the subject of the mutation test
 * at the bottom of this file.
 */
const BENCH_WORKFLOW = `${WORKFLOW_DIR}/bench-eql.yml`

/** A `.github` deposited inside the package by the subtree import. */
const DEAD_GITHUB_DIR = 'packages/eql/.github'

/** Where the imported tree lives, as a `paths:` filter has to spell it. */
const EQL_PREFIX = 'packages/eql/'

/**
 * The mise tasks that ARE the suite. Each is the entry point for a distinct
 * body of coverage, and each was running upstream:
 *
 *   test:sqlx:archive    compiles the nextest archive (and, via prep, mints the
 *                        per-type fixtures through ZeroKMS at compile time)
 *   test:sqlx:partition  the sharded run of that archive against live Postgres
 *   test:sqlx:e2e        the proptest oracle, encrypting fresh values at run time
 *
 * Named individually rather than as "something matching test:sqlx" because they
 * fail independently: dropping the partition step leaves a workflow that builds
 * an archive and never runs it, which still mentions `test:sqlx` throughout.
 */
const SUITE_TASKS = [
  'test:sqlx:archive',
  'test:sqlx:partition',
  'test:sqlx:e2e',
]

/**
 * The part of a workflow that actually does something: `jobs:` and everything
 * under it, with comment lines stripped.
 *
 * Lifted from `integrationSuiteCi.test.ts`, and for the reason recorded there —
 * a claim satisfied by prose rather than by a step. Every assertion below is a
 * substring search, and this file's own header names all three suite tasks. Cut
 * at `jobs:` and the `on:`/`paths:` block goes too, which is what makes "a
 * `paths:` filter naming the suite is a trigger, not a run" true rather than
 * merely intended.
 */
function executablePart(body) {
  const jobsAt = body.search(/^jobs:/m)
  // No `jobs:` key means nothing runs, so nothing can match. Returning the
  // whole body here would hand every assertion the header comments instead.
  return jobsAt === -1 ? '' : body.slice(jobsAt).replace(/^[ \t]*#.*$/gm, '')
}

/** Every workflow GitHub actually executes, read from the repository root. */
const rootWorkflows = workflowFiles().map((relPath) => ({
  relPath,
  body: executablePart(readFileSync(join(REPO_ROOT, relPath), 'utf8')),
}))

describe('a root workflow runs the EQL SQLx suite', () => {
  it('finds workflows at the repository root at all', () => {
    // Guards the guard. An empty scan satisfies every "some workflow contains
    // X" assertion below by vacuum, which is the failure mode this whole file
    // exists to rule out.
    expect(rootWorkflows.length).toBeGreaterThan(0)
  })

  for (const task of SUITE_TASKS) {
    it(`invokes \`mise run ${task}\` from a root workflow`, () => {
      const running = rootWorkflows
        .filter(({ body }) => body.includes(task))
        .map(({ relPath }) => relPath)

      expect(
        running,
        `No workflow in ${WORKFLOW_DIR} runs \`${task}\`, so that coverage executes nowhere. A copy under ${DEAD_GITHUB_DIR} does not count — GitHub reads workflows from the repository root alone. Comments and \`paths:\` entries do not count either: this searches the \`jobs:\` block with comment lines stripped.`,
      ).not.toEqual([])
    })
  }

  it('runs the suite on pull requests, not only on demand', () => {
    const wf = readWorkflow(EQL_WORKFLOW)
    const on = wf?.on ?? wf?.[true] ?? {}
    expect(
      Object.keys(on),
      `${EQL_WORKFLOW} must run on \`pull_request\`. A suite reachable only by \`workflow_dispatch\` is a suite nobody runs — it gates nothing, and its absence from a PR's checks looks identical to a pass.`,
    ).toContain('pull_request')
  })
})

describe('the relevance filter still selects the imported tree', () => {
  const wf = readWorkflow(EQL_WORKFLOW)

  /**
   * Every path the `dorny/paths-filter` step lists, across every filter it
   * declares. `filters:` is a YAML document embedded in a YAML string, so it is
   * parsed rather than pattern-matched — a regex over the raw block would also
   * match the surrounding commentary.
   */
  const filterPaths = Object.values(wf?.jobs ?? {})
    .flatMap((job) => job?.steps ?? [])
    .filter((step) => (step?.uses ?? '').startsWith('dorny/paths-filter@'))
    .flatMap((step) => {
      const filters = yaml.load(step?.with?.filters ?? '')
      return Object.values(filters ?? {}).flat()
    })

  it('finds the paths-filter step', () => {
    // Without this the check below iterates an empty list and passes having
    // read nothing — including in the case that matters most, a step whose
    // action was renamed or whose `filters:` stopped parsing.
    expect(
      filterPaths,
      `No \`dorny/paths-filter\` step with a parseable \`filters:\` block was found in ${EQL_WORKFLOW}, so the prefix check below examines nothing. Either the step moved (follow it) or \`filters:\` is no longer a YAML string.`,
    ).not.toEqual([])
  })

  /**
   * The composite actions this workflow reaches through `uses: ./…`.
   *
   * They are the second legitimate class of non-subtree path, alongside the
   * workflow's own file: `require-cs-secrets` lives at the repository root, and
   * a change to it changes what every credentialed EQL job does — so it belongs
   * in the relevance filter. Derived from the `uses:` edges rather than
   * allowlisted by name, so adding an action to the workflow and to the filter
   * needs no edit here, while an unrelated root path still fails.
   */
  const localActionPrefixes = Object.values(wf?.jobs ?? {})
    .flatMap((job) => job?.steps ?? [])
    .map((step) => step?.uses ?? '')
    .filter((uses) => uses.startsWith('./'))
    .map((uses) => `${uses.slice('./'.length)}/`)

  it('prefixes every source path with the subtree root', () => {
    // Two legitimate exceptions, both outside the subtree by nature: the
    // workflow's own path, and a composite action it `uses:`.
    const offenders = filterPaths.filter(
      (path) =>
        path !== EQL_WORKFLOW &&
        !path.startsWith(EQL_PREFIX) &&
        !localActionPrefixes.some((prefix) => path.startsWith(prefix)),
    )

    expect(
      offenders,
      `These \`paths:\` entries in ${EQL_WORKFLOW} are not under \`${EQL_PREFIX}\`, are not the workflow itself, and are not a composite action it \`uses:\`. dorny/paths-filter matches repo-root-relative paths, so after the subtree import an unprefixed glob matches the WRONG tree — \`src/**\` selects \`packages/stack/src/**\` and never \`packages/eql/src/**\`. The heavy jobs then skip on real EQL changes, report \`skipped\`, and \`ci-required\` treats skipped as pass.\n${offenders.map((p) => `  ${p}`).join('\n')}`,
    ).toEqual([])
  })

  it('points the Rust cache at the nested Cargo workspace', () => {
    // Silent when wrong, which is why it is asserted rather than left to
    // review: `workspaces: .` resolves to the monorepo root, where there is no
    // Cargo.lock for this workspace, so every job restores and saves nothing
    // while reporting success. The shared `sqlx-tests` key would then buy the
    // matrix exactly zero, and the only symptom is a slower run.
    const wrong = Object.entries(wf?.jobs ?? {}).flatMap(([jobName, job]) =>
      (job?.steps ?? [])
        .filter((step) => (step?.uses ?? '').startsWith('Swatinem/rust-cache@'))
        .filter((step) => step?.with?.workspaces !== 'packages/eql')
        .map((step) => `${jobName}: workspaces: ${step?.with?.workspaces}`),
    )
    expect(wrong).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// Every cargo check EQL owns is reached by a root workflow
// ---------------------------------------------------------------------------

/**
 * The other half of the split this repo insists on for `packages/protect-ffi`.
 *
 * There, `lintWiring.test.ts` holds two properties from the manifest side: no
 * cargo on the default `test` path, and every cargo check reachable from
 * `test:cargo`. EQL has no npm-script layer over its cargo work at all — its
 * checks are mise tasks, invoked directly by workflows — so the first property
 * is free (`@cipherstash/eql`'s `test` is `vitest run`, and the repo-wide
 * PATH-trap check covers the rest) and the second has nowhere to attach except
 * CI itself.
 *
 * So this asserts the property one level up: a mise task that compiles or runs
 * Rust must be reached by some workflow GitHub actually executes. Twenty-six
 * tasks qualify, and they arrived from a repository where a different set of
 * workflows ran them — which is exactly the state in which one goes quiet
 * without anyone noticing.
 *
 * ## Why the scan is as long as it is
 *
 * The first version of it parsed one shape (`[tasks."name"]`) out of three
 * hard-coded files and closed reachability over `depends` alone. That missed
 * three whole classes of task, and the floors it guarded itself with — "at
 * least 30 tasks", "at least 18 cargo tasks" — were satisfiable by
 * `packages/eql/mise.toml` on its own, so the two configs contributing NOTHING
 * were invisible. Mutation-tested: with that scan in place, deleting
 * `bench-eql.yml` (the sole caller of `test:bench`) left all 14 assertions
 * green. Everything below exists because of one of those three classes.
 */

/** The imported package, and mise's entry point inside it. */
const EQL_PACKAGE = 'packages/eql'
const MISE_TOML = `${EQL_PACKAGE}/mise.toml`

const readRepo = (relPath) => readFileSync(join(REPO_ROOT, relPath), 'utf8')

/** The `["a", 'b']` inside a TOML array, without a TOML parser. */
const parseStringArray = (inner) =>
  [...inner.matchAll(/"([^"]+)"|'([^']+)'/g)].map((m) => m[1] ?? m[2])

/**
 * `[task_config].includes`, read rather than hard-coded.
 *
 * The list used to be a `MISE_CONFIGS` const here, which is a copy of a
 * declaration that lives in mise.toml — and the failure mode of a stale copy is
 * the one this file is about: a fourth config lands, this scan never opens it,
 * and every task in it becomes unguarded silently. Reading the real list means
 * a new entry is covered the day it is added; `TASK_SOURCES` below then insists
 * each entry actually yielded a task, so an entry that resolves to nothing
 * fails rather than contributing nothing.
 */
function parseIncludes(miseText) {
  const section = /^\[task_config\][^\n]*\n([\s\S]*?)(?=^\[|$)/m.exec(miseText)
  const array = /^includes\s*=\s*\[([^\]]*)\]/m.exec(section?.[1] ?? '')
  return array ? parseStringArray(array[1]) : []
}

/**
 * mise's task blocks, without a TOML parser.
 *
 * Adding one is an audit decision in this repo, and the shape needed here is
 * small: a table header, an optional `depends = [...]`, and the body text.
 *
 * The two dialects are NOT interchangeable, and merging them would be wrong in
 * both directions. In `mise.toml` a task is `[tasks."name"]` and a bare
 * `[settings]` / `[tools]` / `[env]` table is configuration. In a file named by
 * `includes` the whole document is tasks, so EVERY top-level table is a task
 * name and `[tasks."name"]` is not a task at all — mise rejects the file with
 * "unknown field `name`, expected one of `description`, `alias`, …". That is
 * why `tasks/postgres.toml` writes `["postgres:up"]` and `tasks/fixtures.toml`
 * writes `["fixture:generate:all"]`, and why the old single regex parsed 0 of
 * their 6 tasks.
 */
function parseTomlTasks(text, { bareTables }) {
  const header = bareTables
    ? /^\[(?:"([^"]+)"|([\w:.-]+))\]/
    : /^\[tasks\.(?:"([^"]+)"|([\w:.-]+))\]/
  return text
    .split(/^(?=\[)/m) // split on top-level table headers; keep header + body
    .map((block) => ({ match: header.exec(block), block }))
    .filter(({ match }) => match)
    .map(({ match, block }) => ({ name: match[1] ?? match[2], block }))
}

/**
 * A task's `depends`, from either dialect.
 *
 * TOML tasks spell it `depends = ["build"]`. FILE tasks spell it as a header
 * comment, `#MISE depends=["build"]` — `tasks/docs/validate/source.sh` and
 * three siblings carry one, and it is a real edge: without it those tasks are
 * unreachable-from and `build` loses a caller.
 */
function parseDepends(text) {
  const m = /^[ \t]*(?:#MISE[ \t]+)?depends\s*=\s*\[([^\]]*)\]/m.exec(text)
  return m ? parseStringArray(m[1]) : []
}

/**
 * Comment lines, in both TOML and shell. Prose is not a step — see `invokes`
 * and `scriptBodies`, which both read a body only after this has run.
 *
 * Memoised on the exact input string. The mutation test below re-runs the whole
 * reachability walk once per workflow, so this is called tens of thousands of
 * times over the same ~100 bodies; without the cache that test spends most of a
 * second re-stripping text and starts flaking against vitest's 5s timeout.
 */
const strippedBodies = new Map()
function stripCommentLines(text) {
  let stripped = strippedBodies.get(text)
  if (stripped === undefined) {
    stripped = text.replace(/^[ \t]*#.*$/gm, '')
    strippedBodies.set(text, stripped)
  }
  return stripped
}

/**
 * The scripts a task delegates to, inlined.
 *
 * Most of EQL's heavier tasks are one line — `run = "bash tasks/test/foo.sh"` —
 * and every cargo invocation lives in the script. Reading only the block would
 * therefore see cargo in nine tasks and miss `test:sqlx:archive`,
 * `test:sqlx:partition`, `codegen:parity` and the rest, which is the whole
 * class of task most worth checking. One hop is enough: no script here invokes
 * another via a second `tasks/` path.
 *
 * Comment lines are stripped first, and that is not cosmetic. `tasks/build.sh`
 * lists eight sibling scripts in a `#MISE sources=[…]` header (cache-
 * invalidation inputs, not delegations) and `prepare-bindings-assets.sh`
 * mentions `tasks/build.sh` in prose. Inlining those makes a task look like it
 * shells to cargo when it does not — `release:prepare-bindings-assets` was
 * reported as an unreached cargo check on the strength of one comment.
 *
 * A path that does not resolve contributes nothing rather than throwing — a
 * task naming a script that does not exist is a different defect, and mise
 * fails loudly on it.
 */
function scriptBodies(text) {
  return [...stripCommentLines(text).matchAll(/\btasks\/[\w./-]+\.sh\b/g)]
    .map((m) => join(REPO_ROOT, EQL_PACKAGE, m[0]))
    .map((abs) => (existsSync(abs) ? readFileSync(abs, 'utf8') : ''))
    .join('\n')
}

/**
 * Every executable regular file under a directory, recursively and in a stable
 * order.
 *
 * The executable bit IS the inclusion rule — mise makes a file under an
 * `includes` directory a task if and only if it can be executed, and this
 * repository leans on that distinction deliberately. `tasks/build/ordering.sh`
 * and `tasks/test/stub-fixtures.sh` are `source`d by other scripts rather than
 * run, `tasks/test/{doc-anchors,sqlx-archive,sqlx-partition}.sh` are invoked as
 * `bash tasks/...` from a TOML task, and `symbol_order_allowlist.txt`,
 * `*.sql` and the two included `*.toml` are data. All nine are mode 644 and all
 * nine are correctly excluded by this one rule — no extension allowlist, which
 * would have to guess about `tasks/githooks/pre-commit` (no extension, a task)
 * and `tasks/docs/generate/xml-to-json.py` (a `.py`, also a task).
 *
 * The mode is what git records (100755 vs 100644), so a CI checkout reproduces
 * this exactly; it is not a property of one developer's umask.
 */
function executableFilesUnder(absDir) {
  return readdirSync(absDir, { withFileTypes: true })
    .sort((a, b) => (a.name < b.name ? -1 : 1))
    .flatMap((entry) => {
      const abs = join(absDir, entry.name)
      if (entry.isDirectory()) return executableFilesUnder(abs)
      if (!entry.isFile()) return []
      // The POSIX mode is a bitfield; `& 0o111` is "executable by anyone".
      return (statSync(abs).mode & 0o111) !== 0 ? [abs] : []
    })
}

/**
 * The task name mise derives from a file's path under an `includes` directory:
 * directory separators become `:`, and the last extension is dropped —
 * `tasks/test/bench.sh` is `test:bench`, `tasks/githooks/pre-commit` is
 * `githooks:pre-commit`, `tasks/release/prepare-bindings-assets.test.sh` is
 * `release:prepare-bindings-assets.test` (only the LAST extension goes).
 *
 * The exception is a collision. `tasks/test/known-failures.sh` would be
 * `test:known-failures`, which `mise.toml` already defines; mise keeps the
 * extension and calls the file task `test:known-failures.sh` instead. Modelling
 * that matters here — collapse the two and the file task overwrites the TOML
 * one, taking its `depends` and its body with it, and `test:known-failures`
 * (which test-eql.yml really does run) stops resolving to the task CI runs.
 *
 * All three rules were checked against `mise tasks ls --hidden --json` on this
 * tree: 73 tasks, and this derivation reproduces all 73 names exactly.
 */
function fileTaskName(relPath, isTaken) {
  const segments = relPath.split(sep).join('/').split('/')
  const base = segments.pop()
  const stem = [...segments, base.replace(/\.[^.]+$/, '')].join(':')
  return isTaken(stem) ? [...segments, base].join(':') : stem
}

/**
 * The whole task graph, plus which config each task came from.
 *
 * `TASK_SOURCES` is not bookkeeping — it is the guard that would have caught
 * the original defect. Two of the three configs contributed zero tasks and no
 * assertion noticed, because the only floors were on the TOTAL.
 */
function taskGraph() {
  const tasks = new Map()
  const bySource = new Map()

  const add = (source, name, body, depends) => {
    tasks.set(name, { source, body: body + scriptBodies(body), depends })
    bySource.get(source).push(name)
  }

  // mise.toml first, and the order is load-bearing: the file-task collision
  // rule above asks whether a name is already taken.
  const miseText = readRepo(MISE_TOML)
  bySource.set(MISE_TOML, [])
  for (const { name, block } of parseTomlTasks(miseText, {
    bareTables: false,
  })) {
    add(MISE_TOML, name, block, parseDepends(block))
  }

  for (const include of parseIncludes(miseText)) {
    const rel = `${EQL_PACKAGE}/${include}`
    const abs = join(REPO_ROOT, rel)
    // A missing include is not silently skipped: the empty source it leaves
    // behind fails the per-config assertion below, which is the point.
    const isDir = existsSync(abs) && statSync(abs).isDirectory()
    const source = isDir ? `${rel}/**` : rel
    bySource.set(source, bySource.get(source) ?? [])
    if (!existsSync(abs)) continue

    if (isDir) {
      for (const fileAbs of executableFilesUnder(abs)) {
        const body = readFileSync(fileAbs, 'utf8')
        const name = fileTaskName(relative(abs, fileAbs), (n) => tasks.has(n))
        add(source, name, body, parseDepends(body))
      }
    } else {
      const text = readRepo(rel)
      for (const { name, block } of parseTomlTasks(text, {
        bareTables: true,
      })) {
        add(source, name, block, parseDepends(block))
      }
    }
  }

  return { tasks, bySource }
}

const { tasks: TASKS, bySource: TASK_SOURCES } = taskGraph()
const INCLUDES = parseIncludes(readRepo(MISE_TOML))

/**
 * Tasks whose body shells out to cargo.
 *
 * Deliberately matched against the RAW body, comments included. Over-matching
 * costs one exemption with a reason; under-matching drops a real cargo check
 * out of the set this file exists to police, and nothing downstream would say
 * so.
 */
const CARGO_TASKS = [...TASKS]
  .filter(([, task]) => /(^|[^\w-])cargo(\s|$)/m.test(task.body))
  .map(([name]) => name)
  .sort()

/**
 * The positions a real command can start at: the beginning of a line, after a
 * shell separator, or after a YAML `run:` key. See `invokes`.
 */
const COMMAND_START = String.raw`(?:^|&&|\|\||[;|(){}]|(?<![\w:.-])run:)[ \t]*`

/**
 * Whether a body invokes a task BY NAME — as a command, not as prose.
 *
 * Three things are load-bearing here, and each was learned from a wrong answer
 * this scan gave:
 *
 *   * The trailing `(?![\w:.-])` guard is what makes `test:sqlx` distinct from
 *     `test:sqlx:archive`. A plain substring search marks the former reached by
 *     any mention of the latter, and `test:sqlx` is precisely one of the tasks
 *     that is NOT in CI (the archive/partition split replaced it). Getting that
 *     wrong turns the exemption list below into a list of tasks that appear to
 *     run.
 *
 *   * Comment lines are stripped, and `COMMAND_START` requires the invocation
 *     to begin a command. Task bodies here are heavily commented and full of
 *     `echo "… run 'mise run build' first"` diagnostics: of the 56 times the
 *     string `mise run` appears across mise.toml and `tasks/**`, only 20 are a
 *     command. Counting the other 36 creates FALSE reachability, which is the
 *     one direction that matters — `test:sqlx`'s exemption went stale off a
 *     single comment in `tasks/fixtures.toml` reading "regenerated on every
 *     `mise run test:sqlx`".
 *
 *   * The gap between `mise run` and the name may not contain a quote
 *     (`[^\n'"]*?`), only flags like `--output prefix`. Without it a real
 *     invocation at the start of a line lends its command position to every
 *     task named later on the SAME line, including inside a trailing quoted
 *     `echo` — the shape `macro-expand-eql.yml` uses one line further down.
 *
 * The residual imprecision is one-directional by construction: a missed edge
 * shows up as an orphan that has to be justified, which is loud.
 */
const invocationPatterns = new Map()
function invokes(body, taskName) {
  let pattern = invocationPatterns.get(taskName)
  if (pattern === undefined) {
    const escaped = taskName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    pattern = new RegExp(
      `${COMMAND_START}mise\\s+run\\s+[^\\n'"]*?(?<![\\w:.-])${escaped}(?![\\w:.-])`,
      'm',
    )
    invocationPatterns.set(taskName, pattern)
  }
  return pattern.test(stripCommentLines(body))
}

/**
 * Every task→task edge, computed once.
 *
 * `depends` alone is not the graph. mise tasks routinely invoke other tasks
 * from their `run =` body — `test:sqlx:prep` ends with `mise run
 * fixture:generate:all`, `test:bench` opens with `mise run test:sqlx:prep`,
 * `docs:validate:source` is three `mise run` lines and nothing else. Follow
 * only `depends` and `fixture:generate:all` (which encrypts every SQLx fixture
 * through ZeroKMS) reads as a task no workflow reaches.
 *
 * Computed here rather than inside `reachableFrom` because it does not depend
 * on which workflows are in play, and the mutation test below runs that walk
 * once per workflow.
 */
for (const [name, task] of TASKS) {
  task.calls = new Set([
    ...task.depends,
    ...[...TASKS.keys()].filter(
      (other) => other !== name && invokes(task.body, other),
    ),
  ])
}

/**
 * Task names the given workflows run, closed over both edge kinds.
 *
 * The workflow list is a PARAMETER, not a read of the directory, so the
 * mutation test at the bottom can delete a workflow without deleting a file.
 */
function reachableFrom(tasks, workflows) {
  const seen = new Set()
  const queue = [...tasks.keys()].filter((name) =>
    workflows.some(({ body }) => invokes(body, name)),
  )
  while (queue.length > 0) {
    const name = queue.pop()
    if (seen.has(name)) continue
    seen.add(name)
    queue.push(...(tasks.get(name)?.calls ?? []))
  }
  return seen
}

/**
 * Cargo tasks no workflow runs, each with the reason. Every entry is one of:
 *
 *   (a) a developer convenience — a watcher, an unsharded local run;
 *   (b) the WRITE half of a regenerate-and-diff pair whose READ half is in CI;
 *   (c) a second mise NAME for work CI already does under another name;
 *   (d) blocked on a workflow that has not been ported yet, tracked in
 *       UNPORTED_DEPOSIT at the bottom of this file.
 *
 * Never "we decided not to check this". An entry that stops describing an
 * unreached cargo task fails the staleness check below, in both directions — so
 * (d) in particular expires by itself the day its workflow is ported.
 */
const CI_EXEMPT_CARGO_TASKS = new Map([
  [
    'test:sqlx',
    'The unsharded run of the SQLx suite, for local use. CI runs it as `test:sqlx:archive` compiled once plus `test:sqlx:partition` per shard.',
  ],
  ['test:sqlx:watch', 'A file watcher. There is nothing for CI to watch.'],
  [
    'test:matrix:snapshots:regen',
    'Writes the matrix snapshots. CI runs the read half — `test:matrix:inventory` and friends, then `git diff --exit-code` — in test-eql.yml `matrix-coverage`.',
  ],
  [
    'test:surface:snapshot:regen',
    'Writes the public-surface snapshot. Its read half runs inside `test:crates`.',
  ],
  [
    'test:codegen',
    "The generator's own unit tests, which `test:crates` already runs as part of the workspace. CI runs the stronger check: `codegen:parity` regenerates and diffs against the golden output.",
  ],
  [
    'codegen-parity',
    'A second mise NAME for `tasks/codegen-parity.sh`: the script is executable and sits under an `includes` directory, so mise exposes it as a file task in addition to the `[tasks."codegen:parity"]` block that runs `bash tasks/codegen-parity.sh`. CI runs that block, in test-eql.yml `codegen`. Same script, same check, one name.',
  ],
  [
    'schemas-parity',
    'The same duplicate-name case as `codegen-parity`, for `tasks/schemas-parity.sh`. CI runs it as `test:schemas:parity`, in test-eql.yml `codegen`.',
  ],
  [
    'test:lint',
    '`cargo fmt --check` scoped to tests/sqlx. `test:crates` runs `cargo fmt --check` at the EQL workspace ROOT, and tests/sqlx is a workspace member, so the CI run covers exactly these files and four crates more — verified against `cargo fmt --check -v`, which lists packages/eql/tests/sqlx/** among its targets. test-eql.yml says the same thing at the `rust-crates` job, which is where the standalone lint step used to be.',
  ],
  [
    'docs:generate:json',
    'Generates docs/api/json/eql-manifest.json for the release docs bundle. Its only caller is `packages/eql/.github/workflows/_build-docs.yml` — one of the four unported RELEASE workflows in UNPORTED_DEPOSIT — so this is category (d): it becomes reachable the day that file is ported, and this entry then goes stale and must be deleted. It is also not portable as-is, since it falls back to `mise run docs:generate`, which needs a doxygen binary no job installs. Its cargo step (`cargo run -p eql-codegen dump-catalog`) is separately exercised in CI by `test:matrix:catalog-coverage`.',
  ],
])

/** Cargo tasks a given reachability set leaves unaccounted for. */
const orphanCargoTasks = (reachable) =>
  CARGO_TASKS.filter(
    (name) => !reachable.has(name) && !CI_EXEMPT_CARGO_TASKS.has(name),
  )

describe('the scan sees every task mise sees', () => {
  it('reads the include list out of mise.toml', () => {
    // If this parse fails, every included config below disappears at once and
    // the per-source check has nothing left to find empty.
    expect(
      INCLUDES,
      `Could not read \`[task_config].includes\` from ${MISE_TOML}. Everything mise loads beyond mise.toml itself is named there, so an unparsed list means this whole scan reads one file and reports success.`,
    ).toContain('tasks')
  })

  it('draws at least one task from every config, and from the file walk', () => {
    // THE property whose absence made the original defect invisible.
    // `tasks/postgres.toml` and `tasks/fixtures.toml` contributed zero tasks
    // for the life of the old scan — it looked only for `[tasks."x"]`, and
    // those files use the bare-table form — while `TASKS.size >= 30` passed on
    // mise.toml's 32 blocks alone. A floor on the total cannot see a config
    // that goes quiet; a floor per config is the only shape that can.
    const empty = [...TASK_SOURCES]
      .filter(([, names]) => names.length === 0)
      .map(([source]) => source)

    expect(
      empty,
      `These task configs contributed no tasks at all. Either the file moved, or its table syntax is a shape the parser does not know. A config contributing zero is indistinguishable from a config full of tasks that all pass:\n${empty
        .map((s) => `  ${s}`)
        .join('\n')}`,
    ).toEqual([])

    // One source per `includes` entry, plus mise.toml itself. Catches an entry
    // that resolved to nothing at all rather than to an empty file.
    expect(TASK_SOURCES.size).toBe(INCLUDES.length + 1)
  })

  it('names a task from each source, so a source cannot be full of nonsense', () => {
    // Non-emptiness would be satisfied by a parser that read table headers as
    // gibberish. These four pin one real name per source.
    const from = (source) => TASK_SOURCES.get(source) ?? []
    expect(from(MISE_TOML)).toContain('test:sqlx:archive')
    expect(from(`${EQL_PACKAGE}/tasks/postgres.toml`)).toContain('postgres:up')
    expect(from(`${EQL_PACKAGE}/tasks/fixtures.toml`)).toContain(
      'fixture:generate:all',
    )
    expect(from(`${EQL_PACKAGE}/tasks/**`)).toContain('test:bench')
  })

  it('derives file-task names the way mise does', () => {
    const names = [...TASKS.keys()]
    // Extension dropped, directories joined with `:`.
    expect(names).toContain('test:bench')
    // No extension at all, and not under `tasks/test`.
    expect(names).toContain('githooks:pre-commit')
    // Only the LAST extension goes.
    expect(names).toContain('release:prepare-bindings-assets.test')
    // The collision case: `tasks/test/known-failures.sh` keeps its extension
    // because `[tasks."test:known-failures"]` in mise.toml claimed the stem.
    // Collapse these two and the file task silently replaces the TOML one, and
    // `test:known-failures` — which test-eql.yml runs — resolves to a task with
    // different content.
    expect(names).toContain('test:known-failures.sh')
    expect(TASKS.get('test:known-failures')?.source).toBe(MISE_TOML)
  })

  it('leaves non-executable files out of the task set', () => {
    // The inclusion rule is the executable bit, nothing else. These four are
    // mode 644 and are NOT tasks: two are `source`d by other scripts, one is
    // invoked as `bash tasks/...` from a TOML task, one is data. A rule based
    // on the `.sh` extension would wrongly promote all three scripts, and an
    // allowlist of extensions would wrongly demote `githooks:pre-commit`.
    const names = [...TASKS.keys()]
    expect(names).not.toContain('build:ordering') // sourced by tasks/build.sh
    expect(names).not.toContain('test:stub-fixtures') // sourced by 5 tasks
    expect(names).not.toContain('test:sqlx-archive') // `bash tasks/...`
    expect(names).not.toContain('test:symbol_order_allowlist') // a .txt
  })

  it('reads `depends` from both dialects', () => {
    // TOML form.
    expect(TASKS.get('test:sqlx')?.depends).toEqual(['test:sqlx:prep'])
    // `#MISE depends=[...]` header-comment form, which only file tasks use. Without
    // it `docs:validate:source` — which test-eql.yml runs on every PR — stops
    // being a caller of `build`.
    expect(TASKS.get('docs:validate:source')?.depends).toEqual(['build'])
  })

  it('parses the whole graph, not a fragment of it', () => {
    // 73 today, matching `mise tasks ls --hidden --json` name for name. A
    // coarse net under the per-source checks above: it catches a shrinkage
    // that leaves every source non-empty.
    expect(TASKS.size).toBeGreaterThanOrEqual(70)
  })
})

describe('every cargo check EQL owns is reached by a root workflow', () => {
  const reachable = reachableFrom(TASKS, rootWorkflows)

  it('finds the tasks that invoke cargo, including through a script', () => {
    // 26 today. The floor sits above the 19 a mise.toml-only scan finds, so
    // losing the file walk or an included config fails here rather than
    // silently shrinking the set by the seven tasks it took to notice they
    // were missing.
    expect(CARGO_TASKS.length).toBeGreaterThanOrEqual(24)

    // One named case per parsing class, because the count alone cannot say
    // WHICH class went missing:
    // a TOML task whose cargo lives in a delegated script,
    expect(CARGO_TASKS).toContain('test:sqlx:archive')
    // a FILE task (tasks/test/bench.sh — the class that made deleting
    // bench-eql.yml invisible),
    expect(CARGO_TASKS).toContain('test:bench')
    // and a bare-table task in an included config.
    expect(CARGO_TASKS).toContain('fixture:generate:all')
  })

  it('distinguishes a task name from a longer task that starts with it', () => {
    // The property the trailing guard in `invokes` exists for. Without it,
    // `test:sqlx` reads as reached by test-eql.yml's archive and partition
    // steps, and drops out of the exemption list silently.
    const body = 'run: mise run test:sqlx:archive\nrun: mise run test:schema\n'
    expect(invokes(body, 'test:sqlx:archive')).toBe(true)
    expect(invokes(body, 'test:sqlx')).toBe(false)
    expect(invokes(body, 'test:schema')).toBe(true)
  })

  it('counts a command and not a mention of one', () => {
    // Every form below is real text from this tree. The three that must NOT
    // count are the ones that made `test:sqlx` look reached.
    expect(invokes('  mise run test:sqlx:prep\n', 'test:sqlx:prep')).toBe(true)
    expect(invokes('mise run clean && mise run build\n', 'build')).toBe(true)
    expect(invokes('        run: mise run test:crates\n', 'test:crates')).toBe(
      true,
    )
    expect(
      invokes(
        'mise run --output prefix test:bench --postgres 17\n',
        'test:bench',
      ),
    ).toBe(true)

    // A comment (tasks/fixtures.toml, on the fixture regeneration cadence).
    expect(
      invokes('# regenerated on every `mise run test:sqlx`\n', 'test:sqlx'),
    ).toBe(false)
    // Comment stripping is a SECOND line of defence, not a redundant one, and
    // this case is what separates the two: the sentence puts `mise run` right
    // after a `;`, which is a position COMMAND_START accepts. mise.toml is full
    // of prose in this shape ("only WRITES the snapshots; `mise run
    // test:matrix:inventory` is the gate"), and today every instance happens to
    // carry a backtick that COMMAND_START rejects — an accident, not a rule.
    expect(
      invokes(
        '# writes them; mise run test:matrix:inventory is the gate\n',
        'test:matrix:inventory',
      ),
    ).toBe(false)
    // A diagnostic (tasks/codegen-parity.sh).
    expect(
      invokes(
        `echo "surface is stale — run 'mise run build' and commit"\n`,
        'build',
      ),
    ).toBe(false)
    // A real invocation and a quoted mention on ONE line (macro-expand-eql.yml
    // shape). The first must count and the second must not.
    const mixed = `mise run test:schema || { echo "run 'mise run test:sqlx' first"; }\n`
    expect(invokes(mixed, 'test:schema')).toBe(true)
    expect(invokes(mixed, 'test:sqlx')).toBe(false)
  })

  it('follows `mise run` inside a task body, not only `depends`', () => {
    // `test:sqlx:prep` ends with `mise run fixture:generate:all`, and nothing
    // declares that as a dependency. Under a depends-only closure the task that
    // mints every SQLx fixture through ZeroKMS reads as unreached — an orphan
    // that no workflow could ever clear, since no workflow names it.
    expect(TASKS.get('test:sqlx:prep')?.depends).not.toContain(
      'fixture:generate:all',
    )
    expect([...reachable]).toContain('fixture:generate:all')
  })

  it('runs every cargo task, or names it as exempt with a reason', () => {
    const orphans = orphanCargoTasks(reachable)
    expect(
      orphans,
      `These mise tasks invoke cargo and no workflow in ${WORKFLOW_DIR} reaches them, directly, through \`depends\`, or through a \`mise run\` in a task body. A check nothing invokes reads exactly like a check that passes. Either add it to a workflow, or add it to CI_EXEMPT_CARGO_TASKS with the reason it does not belong in CI:\n${orphans
        .map((name) => `  ${name}`)
        .join('\n')}`,
    ).toEqual([])
  })

  it('keeps no exemption for a task that is run, or has gone', () => {
    // Both directions. An exemption for a task CI now runs is noise that hides
    // the next one; an exemption for a task that no longer exists is a claim
    // about nothing. This is also what retires the `docs:generate:json` entry
    // automatically once `_build-docs.yml` is ported to the repository root.
    const stale = [...CI_EXEMPT_CARGO_TASKS.keys()].filter(
      (name) => !TASKS.has(name) || reachable.has(name),
    )
    expect(
      stale,
      'These CI_EXEMPT_CARGO_TASKS entries no longer describe an unreached cargo task — the task was deleted, renamed, or is now run by a workflow. Remove them.',
    ).toEqual([])
  })
})

/**
 * Workflows that are the SOLE caller of some cargo check.
 *
 * Deleting one of these silently removes coverage, which is the failure this
 * whole file is about — so the list is written down, and the tests below drive
 * the scan against a workflow set with each one removed to prove the guard
 * actually fails.
 */
const SOLE_CALLER_WORKFLOWS = [
  `${WORKFLOW_DIR}/bench-eql.yml`, // test:bench
  `${WORKFLOW_DIR}/macro-expand-eql.yml`, // test:matrix:expand
  `${WORKFLOW_DIR}/test-eql.yml`, // most of the suite
]

describe('the guard fails when a workflow stops calling a cargo check', () => {
  /**
   * The mutation is injected, not performed. Deleting `bench-eql.yml` from the
   * working tree and re-running is what proved the ORIGINAL scan blind — all 14
   * assertions stayed green, because `test:bench` is a FILE task and file tasks
   * were not parsed at all. Encoding that as a permanent test means passing a
   * shorter workflow list to `reachableFrom`, which is the reason that function
   * takes one rather than reading the directory. `lint-no-eql-registry-pins.mjs`
   * splits `lint()` from `report()` for the same reason.
   */
  const without = (relPath) =>
    rootWorkflows.filter((wf) => wf.relPath !== relPath)

  it('reports test:bench as an orphan when bench-eql.yml goes', () => {
    const workflows = without(BENCH_WORKFLOW)
    // The mutation has to actually remove something, or this proves nothing.
    expect(workflows.length).toBe(rootWorkflows.length - 1)

    const orphans = orphanCargoTasks(reachableFrom(TASKS, workflows))
    expect(
      orphans,
      `Removing ${BENCH_WORKFLOW} left every cargo check accounted for, which means this file would not notice its deletion. \`test:bench\` (packages/eql/tasks/test/bench.sh, the cargo \`bench\`-feature SQLx suite) has no other caller, so it must be reported. If the bench suite genuinely moved to another workflow, update SOLE_CALLER_WORKFLOWS.`,
    ).toContain('test:bench')
  })

  it('names every workflow whose deletion would orphan a cargo check', () => {
    const soleCallers = rootWorkflows
      .map(({ relPath }) => relPath)
      .filter(
        (relPath) =>
          orphanCargoTasks(reachableFrom(TASKS, without(relPath))).length > 0,
      )

    expect(
      soleCallers,
      `The set of workflows carrying EQL's only copy of some cargo check has changed.\n` +
        'GREW: a check that had a second caller now has one — expected if a job moved, but it means that file is now load-bearing.\n' +
        "SHRANK: a workflow stopped being anyone's only caller. Either its checks moved elsewhere (fine, update this list) or it stopped running them (not fine).\n" +
        'A workflow dropping out because its checks now run NOWHERE cannot happen quietly — the orphan check above fails first.',
    ).toEqual(SOLE_CALLER_WORKFLOWS)
  })

  it('is not vacuous: some workflow is load-bearing', () => {
    // If every cargo check had two callers this whole describe block would pass
    // by finding nothing, and so would a scan that parsed no tasks at all.
    expect(SOLE_CALLER_WORKFLOWS.length).toBeGreaterThan(0)
    expect(CARGO_TASKS.length).toBeGreaterThan(
      CI_EXEMPT_CARGO_TASKS.size, // more cargo tasks run than are excused
    )
  })
})

/**
 * What is still allowed to sit in the deposited `.github`, and why.
 *
 * The end state is no directory at all — the rule `lintWiring.test.ts` applies
 * to protect-ffi's deposit, and for the same reason: a workflow file under a
 * package reads as live CI and is not. It cannot be deleted in one step here,
 * because four of EQL's ten workflows are the RELEASE machinery. Porting those
 * to the repository root is what makes them fire, and it is gated on repointing
 * npm and crates.io trusted publishing — an irreversible cutover that has not
 * happened. Deleting them first would mean porting from git history at the one
 * moment nobody wants to be reconstructing a publish pipeline.
 *
 * So this is a SHRINKING allowlist, not an exemption list. Each entry names a
 * file that has not been ported yet; porting one means deleting it here in the
 * same commit. The equality below fails in both directions — a file that comes
 * back fails, and so does an entry left behind after its file is gone, which is
 * what turns the last removal into "delete the directory" rather than a check
 * that quietly stops meaning anything.
 */
const UNPORTED_DEPOSIT = [
  // Phase 5 — the release cutover. Each publishes something, and each is inert
  // until trusted publishing is repointed at cipherstash/stack.
  '.github/release.yml', // release-notes categorisation config, not a workflow
  '.github/workflows/README.md', // documents the four below
  '.github/workflows/_build-docs.yml', // the sole caller of `docs:generate:json`
  '.github/workflows/_build-sql.yml',
  '.github/workflows/lint-release.yml', // actionlints the four below
  '.github/workflows/rebuild-docs.yml',
  '.github/workflows/release-plz.yml',
  '.github/workflows/release-postgres-eql-image.yml',
  '.github/workflows/release.yml',
  // Not CI. Ported with the repository settings, not with a workflow.
  '.github/ISSUE_TEMPLATE/docs-feedback.yml',
  '.github/actionlint.yaml',
].sort()

describe('the imported workflow directory is on its way out', () => {
  it('holds only the files still waiting to be ported', () => {
    const deposit = existsSync(join(REPO_ROOT, DEAD_GITHUB_DIR))
      ? execFileSync('git', ['ls-files', '-z', '--', DEAD_GITHUB_DIR], {
          cwd: REPO_ROOT,
          encoding: 'utf8',
        })
          .split('\0')
          .filter(Boolean)
          .map((path) => path.slice('packages/eql/'.length))
          .sort()
      : []

    expect(
      deposit,
      `${DEAD_GITHUB_DIR} no longer matches the list of files still waiting to be ported.\n` +
        'If you PORTED one, delete it from the deposit and from UNPORTED_DEPOSIT in the same commit — ' +
        'leaving it here means two copies of a workflow, one of which GitHub ignores.\n' +
        'If you ADDED one, it is inert: GitHub reads workflows from the repository root alone.\n' +
        'When this list empties, delete the directory and replace this check with ' +
        '`expect(existsSync(...)).toBe(false)`.',
    ).toEqual(UNPORTED_DEPOSIT)
  })
})
