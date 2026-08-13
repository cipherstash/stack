import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
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

  it('prefixes every source path with the subtree root', () => {
    // The workflow's own path is the one legitimate exception: it lives at the
    // repository root, not inside the subtree.
    const offenders = filterPaths.filter(
      (path) => path !== EQL_WORKFLOW && !path.startsWith(EQL_PREFIX),
    )

    expect(
      offenders,
      `These \`paths:\` entries in ${EQL_WORKFLOW} are not under \`${EQL_PREFIX}\`. dorny/paths-filter matches repo-root-relative paths, so after the subtree import an unprefixed glob matches the WRONG tree — \`src/**\` selects \`packages/stack/src/**\` and never \`packages/eql/src/**\`. The heavy jobs then skip on real EQL changes, report \`skipped\`, and \`ci-required\` treats skipped as pass.\n${offenders.map((p) => `  ${p}`).join('\n')}`,
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
 * Rust must be reached by some workflow GitHub actually executes. Fifteen tasks
 * qualify, and they arrived from a repository where a different set of
 * workflows ran them — which is exactly the state in which one goes quiet
 * without anyone noticing.
 */

const MISE_CONFIGS = [
  'packages/eql/mise.toml',
  'packages/eql/tasks/fixtures.toml',
  'packages/eql/tasks/postgres.toml',
]

/**
 * The scripts a task block delegates to, inlined.
 *
 * Most of EQL's heavier tasks are one line — `run = "bash tasks/test/foo.sh"` —
 * and every cargo invocation lives in the script. Reading only the block would
 * therefore see cargo in nine tasks and miss `test:sqlx:archive`,
 * `test:sqlx:partition`, `codegen:parity` and the rest, which is the whole
 * class of task most worth checking. One hop is enough: no script here invokes
 * another via a second `tasks/` path.
 *
 * A path that does not resolve contributes nothing rather than throwing — a
 * task naming a script that does not exist is a different defect, and mise
 * fails loudly on it.
 */
function scriptBodies(block) {
  const paths = [...block.matchAll(/\btasks\/[\w./-]+\.sh\b/g)].map((m) => m[0])
  return paths
    .map((rel) => {
      const abs = join(REPO_ROOT, 'packages/eql', rel)
      return existsSync(abs) ? readFileSync(abs, 'utf8') : ''
    })
    .join('\n')
}

/**
 * mise's task blocks, without a TOML parser.
 *
 * Adding one is an audit decision in this repo, and the shape needed here is
 * small: a `[tasks."<name>"]` header, an optional `depends = [...]`, and the
 * body text. `taskGraph` is guarded below on both the task count and a named
 * sample, so a format change empties nothing silently — it fails.
 */
function taskGraph() {
  const tasks = new Map()
  for (const rel of MISE_CONFIGS) {
    const text = readFileSync(join(REPO_ROOT, rel), 'utf8')
    // Split on top-level table headers; keep the header with its body.
    const blocks = text.split(/^(?=\[)/m)
    for (const block of blocks) {
      const header = /^\[tasks\.(?:"([^"]+)"|([\w:.-]+))\]/.exec(block)
      if (!header) continue
      const name = header[1] ?? header[2]
      const depends = /^depends\s*=\s*\[([^\]]*)\]/m.exec(block)
      tasks.set(name, {
        file: rel,
        body: block + scriptBodies(block),
        depends: depends
          ? [...depends[1].matchAll(/"([^"]+)"|'([^']+)'/g)].map(
              (m) => m[1] ?? m[2],
            )
          : [],
      })
    }
  }
  return tasks
}

const TASKS = taskGraph()

/** Tasks whose body shells out to cargo. */
const CARGO_TASKS = [...TASKS]
  .filter(([, task]) => /(^|[^\w-])cargo(\s|$)/m.test(task.body))
  .map(([name]) => name)
  .sort()

/**
 * Whether a workflow's executable part invokes a task BY NAME.
 *
 * The trailing guard is what makes `test:sqlx` distinct from
 * `test:sqlx:archive`: a plain substring search would mark the former reached
 * by any mention of the latter, and `test:sqlx` is precisely one of the tasks
 * that is NOT in CI (the archive/partition split replaced it). Getting that
 * wrong turns the exemption list below into a list of tasks that appear to run.
 */
function invokes(body, taskName) {
  const escaped = taskName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp(
    `mise\\s+run\\s+[^\\n]*?(?<![\\w:.-])${escaped}(?![\\w:.-])`,
  ).test(body)
}

/** Task names any root workflow runs, closed over `depends`. */
function reachableFromCi() {
  const seen = new Set()
  const queue = [...TASKS.keys()].filter((name) =>
    rootWorkflows.some(({ body }) => invokes(body, name)),
  )
  while (queue.length > 0) {
    const name = queue.pop()
    if (seen.has(name)) continue
    seen.add(name)
    queue.push(...(TASKS.get(name)?.depends ?? []))
  }
  return seen
}

/**
 * Cargo tasks no workflow runs, each with the reason. Every entry is either a
 * developer convenience or the WRITE half of a regenerate-and-diff pair whose
 * READ half is in CI — never "we decided not to check this".
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
])

describe('every cargo check EQL owns is reached by a root workflow', () => {
  const reachable = reachableFromCi()

  it('parses the mise task graph', () => {
    // The guard on the scan. A `[tasks."x"]` spelling change, or a config file
    // moving, would empty `TASKS` — and every check below would then pass
    // having examined nothing.
    expect(TASKS.size).toBeGreaterThanOrEqual(30)
    expect([...TASKS.keys()]).toContain('test:sqlx:archive')
    expect(TASKS.get('test:sqlx')?.depends).toEqual(['test:sqlx:prep'])
  })

  it('finds the tasks that invoke cargo, including through a script', () => {
    // 19 today. The floor is set above the 15 that block-only parsing finds, so
    // losing `scriptBodies` fails here rather than silently shrinking the set
    // by the four tasks most worth checking.
    expect(CARGO_TASKS.length).toBeGreaterThanOrEqual(18)

    // The named case: `run = "bash tasks/test/sqlx-archive.sh"`. Nothing in the
    // task block mentions cargo; `cargo nextest archive` is in the script.
    expect(CARGO_TASKS).toContain('test:sqlx:archive')
  })

  it('distinguishes a task name from a longer task that starts with it', () => {
    // The property `invokes` exists for. Without the trailing guard,
    // `test:sqlx` reads as reached by test-eql.yml's archive and partition
    // steps, and drops out of the exemption list silently.
    const body = 'run: mise run test:sqlx:archive\nrun: mise run test:schema\n'
    expect(invokes(body, 'test:sqlx:archive')).toBe(true)
    expect(invokes(body, 'test:sqlx')).toBe(false)
    expect(invokes(body, 'test:schema')).toBe(true)
  })

  it('runs every cargo task, or names it as exempt with a reason', () => {
    const orphans = CARGO_TASKS.filter(
      (name) => !reachable.has(name) && !CI_EXEMPT_CARGO_TASKS.has(name),
    )
    expect(
      orphans,
      `These mise tasks invoke cargo and no workflow in ${WORKFLOW_DIR} reaches them, directly or through \`depends\`. A check nothing invokes reads exactly like a check that passes. Either add it to a workflow, or add it to CI_EXEMPT_CARGO_TASKS with the reason it does not belong in CI:\n${orphans
        .map((name) => `  ${name}`)
        .join('\n')}`,
    ).toEqual([])
  })

  it('keeps no exemption for a task that is run, or has gone', () => {
    // Both directions. An exemption for a task CI now runs is noise that hides
    // the next one; an exemption for a task that no longer exists is a claim
    // about nothing.
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
  '.github/workflows/_build-docs.yml',
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
