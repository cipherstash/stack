import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, WORKFLOW_DIR, workflowFiles } from './lib/workflows.mjs'

/**
 * Guards that the stack-* crates, their node bindings and the Go module are
 * RUN by CI, not merely present.
 *
 * The set arrived from cipherstash-suite with its workflows exported to
 * `.github/imported-workflows/`, where GitHub never looks, and deleted in the
 * import's cleanup commit. Until the CI port landed, every check the set
 * carried ran nowhere — the failure `eql-suite-ci.test.mjs` records for the
 * EQL import, and `integrationSuiteCi.test.ts` for protect-ffi's before it.
 * This file is the same guard for this set, in two halves:
 *
 *   1. Every mise task the set defines — the five crate `tasks.toml` files the
 *      root `mise.toml` includes, and the root tasks — is reached from a root
 *      workflow, or named as exempt with a reason. The scan is a smaller copy
 *      of `eql-suite-ci.test.mjs`'s: the same `invokes` rule for "a command,
 *      not a mention", plus `depends` globs (`doc:*`) and `${{ matrix.* }}`
 *      expansion, which the root tasks and `fuzz.yml` need and EQL does not.
 *
 *   2. The failures specific to this set that would be silent: the trybuild
 *      `ui` binary stops running, `NEXTEST_PROFILE` names a profile nobody
 *      defined, the Go jobs test a guest nobody checked, and
 *      `@cipherstash/profile` loses its private flag while it is unpublished.
 */

const readRepo = (relPath) => readFileSync(join(REPO_ROOT, relPath), 'utf8')

const ROOT_MISE = 'mise.toml'
const IMPORTED_WORKFLOW_DIR = '.github/imported-workflows'

// ---------------------------------------------------------------------------
// The task graph
// ---------------------------------------------------------------------------

/** The `["a", 'b']` inside a TOML array, without a TOML parser. */
const parseStringArray = (inner) =>
  [...inner.matchAll(/"([^"]+)"|'([^']+)'/g)].map((m) => m[1] ?? m[2])

/** `[task_config].includes` from the root mise.toml. */
function parseIncludes(miseText) {
  const section = /^\[task_config\][^\n]*\n([\s\S]*?)(?=^\[|$(?![\s\S]))/m.exec(
    miseText,
  )
  const array = /^includes\s*=\s*\[([^\]]*)\]/m.exec(section?.[1] ?? '')
  return array ? parseStringArray(array[1]) : []
}

/**
 * mise task blocks. In mise.toml a task is `[tasks."name"]`; in an included
 * file every top-level table is a task, `["name"]` (see
 * `eql-suite-ci.test.mjs` for why the dialects must not be merged).
 */
function parseTomlTasks(text, { bareTables }) {
  const header = bareTables
    ? /^\[(?:"([^"]+)"|([\w:.-]+))\]/
    : /^\[tasks\.(?:"([^"]+)"|([\w:.-]+))\]/
  return text
    .split(/^(?=\[)/m)
    .map((block) => ({ match: header.exec(block), block }))
    .filter(({ match }) => match)
    .map(({ match, block }) => ({ name: match[1] ?? match[2], block }))
}

const parseDepends = (block) => {
  const m = /^[ \t]*depends\s*=\s*\[([^\]]*)\]/m.exec(block)
  return m ? parseStringArray(m[1]) : []
}

const stripCommentLines = (text) => text.replace(/^[ \t]*#.*$/gm, '')

function taskGraph() {
  const tasks = new Map()
  const bySource = new Map()
  const add = (source, name, block) => {
    tasks.set(name, { source, body: block, depends: parseDepends(block) })
    bySource.get(source).push(name)
  }
  const miseText = readRepo(ROOT_MISE)
  bySource.set(ROOT_MISE, [])
  for (const { name, block } of parseTomlTasks(miseText, {
    bareTables: false,
  })) {
    add(ROOT_MISE, name, block)
  }
  for (const include of parseIncludes(miseText)) {
    bySource.set(include, [])
    if (!existsSync(join(REPO_ROOT, include))) continue
    for (const { name, block } of parseTomlTasks(readRepo(include), {
      bareTables: true,
    })) {
      add(include, name, block)
    }
  }
  return { tasks, bySource }
}

const { tasks: TASKS, bySource: TASK_SOURCES } = taskGraph()
const INCLUDES = parseIncludes(readRepo(ROOT_MISE))

/** mise's `depends` glob: `doc:*` is every task whose name starts `doc:`. */
function expandDepends(pattern) {
  if (!pattern.includes('*')) return [pattern]
  const re = new RegExp(
    `^${pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`,
  )
  return [...TASKS.keys()].filter((name) => re.test(name))
}

/** Where a command can start; see `eql-suite-ci.test.mjs` `invokes`. */
const COMMAND_START = String.raw`(?:^|&&|\|\||[;|(){}])[ \t]*`

function invokes(body, taskName) {
  const escaped = taskName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp(
    `${COMMAND_START}mise\\s+run\\s+[^\\n'"]*?(?<![\\w:.-])${escaped}(?![\\w:.-])`,
    'm',
  ).test(stripCommentLines(body))
}

for (const [name, task] of TASKS) {
  task.calls = new Set([
    ...task.depends.flatMap(expandDepends),
    ...[...TASKS.keys()].filter(
      (other) => other !== name && invokes(task.body, other),
    ),
  ])
}

// ---------------------------------------------------------------------------
// The workflows
// ---------------------------------------------------------------------------

/**
 * A step's `run:` once per value of each `${{ matrix.<key> }}` it names.
 *
 * `fuzz.yml` runs `mise run ${{ matrix.task }}` over six targets. Read as
 * text, that line invokes no task at all, and all six `fuzz:*` tasks would
 * need an exemption that claims CI does not run them — the false report the
 * EQL scan's comments warn about. Values come from `matrix.include[*]` and
 * from plain list axes.
 */
function expandMatrix(run, job) {
  const matrix = job?.strategy?.matrix ?? {}
  const values = (key) => [
    ...(Array.isArray(matrix.include)
      ? matrix.include.map((row) => row?.[key])
      : []),
    ...(Array.isArray(matrix[key]) ? matrix[key] : []),
  ]
  let bodies = [run]
  for (const [, key] of run.matchAll(/\$\{\{\s*matrix\.([\w-]+)\s*\}\}/g)) {
    const pattern = new RegExp(`\\$\\{\\{\\s*matrix\\.${key}\\s*\\}\\}`, 'g')
    const vals = values(key).filter((v) => v !== undefined)
    bodies = bodies.flatMap((body) =>
      vals.map((v) => body.replace(pattern, String(v))),
    )
  }
  return bodies
}

const jobSteps = (job) => (Array.isArray(job?.steps) ? job.steps : [])

/** Every root workflow, with the `run:` bodies of all its jobs' steps. */
const ROOT_WORKFLOWS = workflowFiles().map((relPath) => {
  const wf = readWorkflow(relPath)
  const body = Object.values(wf?.jobs ?? {})
    .flatMap((job) =>
      jobSteps(job)
        .filter((step) => typeof step?.run === 'string')
        .flatMap((step) => expandMatrix(step.run, job)),
    )
    .join('\n')
  return { relPath, wf, body }
})

function reachableFrom(workflows) {
  const seen = new Set()
  const queue = [...TASKS.keys()].filter((name) =>
    workflows.some(({ body }) => invokes(body, name)),
  )
  while (queue.length > 0) {
    const name = queue.pop()
    if (seen.has(name)) continue
    seen.add(name)
    queue.push(...(TASKS.get(name)?.calls ?? []))
  }
  return seen
}

/**
 * Tasks no workflow runs by name, each with the reason. Never "we decided not
 * to check this": each entry says where CI does the same work, or why there
 * is nothing for CI to do.
 */
const CI_EXEMPT_TASKS = new Map([
  ...[
    'stack-auth',
    'stack-encrypt',
    'stack-guest-abi',
    'stack-kms',
    'stack-profile',
  ].map((crate) => [
    `test:doc:${crate}`,
    'A second name for work CI does: tests-crates.yml runs the root `test:doc`, which runs every doctest in the workspace (`cargo test --doc --workspace --all-features`), this crate included.',
  ]),
  [
    'mutants:stack-auth',
    'The full-crate sweep, for local use (~15 min). CI runs `cargo mutants -p stack-auth -p stack-encrypt --in-diff` in mutants.yml, reading the same .cargo/mutants.toml, and sweeps both crates on workflow_dispatch.',
  ],
  [
    'mutants:stack-encrypt',
    'The full-crate sweep, for local use (~60 min). CI runs it `--in-diff` in mutants.yml; see mutants:stack-auth.',
  ],
  [
    'mutants',
    'The fan-out over the two sweeps above, for local use. Both would write mutants.out in the same directory, so CI runs cargo-mutants once over both crates instead.',
  ],
  [
    'go:stackencrypt:example',
    'A walkthrough against real ZeroKMS for a developer who has run `stash auth login`. CI exercises the same client through the Go live tests in tests-golang.yml `live`.',
  ],
  [
    'go:stackencrypt:example:explicit',
    'The same walkthrough, with credentials passed as flags after `--`. Nothing for CI to pass; the live tests cover explicit credentials (`liveClient`).',
  ],
])

describe('the scan sees every task mise sees', () => {
  it('reads the five crate task files from the root mise.toml', () => {
    expect(INCLUDES.sort()).toEqual(
      [
        'packages/stack-auth/tasks.toml',
        'packages/stack-encrypt/tasks.toml',
        'packages/stack-guest-abi/tasks.toml',
        'packages/stack-kms/tasks.toml',
        'packages/stack-profile/tasks.toml',
      ].sort(),
    )
  })

  it('draws at least one task from every config', () => {
    const empty = [...TASK_SOURCES]
      .filter(([, names]) => names.length === 0)
      .map(([source]) => source)
    expect(
      empty,
      'These configs yielded no task: either the file is missing, or the parser no longer reads its dialect. Either way every task in it is unguarded.',
    ).toEqual([])
  })

  it('agrees with mise about the task names', () => {
    // The parser is a regex over TOML, so it is checked against mise itself
    // where mise is installed. On a machine without mise this is skipped, not
    // failed: the per-config floor above still holds.
    let listed
    try {
      listed = JSON.parse(
        execFileSync('mise', ['tasks', 'ls', '--json', '--hidden'], {
          cwd: REPO_ROOT,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore'],
        }),
      )
    } catch {
      return
    }
    const fromMise = listed
      .filter(({ source }) =>
        [ROOT_MISE, ...INCLUDES].some((rel) =>
          String(source).endsWith(`/${rel}`),
        ),
      )
      .map(({ name }) => name)
      .sort()
    expect([...TASKS.keys()].sort()).toEqual(fromMise)
  })

  it('expands a `depends` glob to the tasks it names', () => {
    expect([...TASKS.get('doc').calls].sort()).toEqual(
      [
        'doc:stack-auth',
        'doc:stack-encrypt',
        'doc:stack-guest-abi',
        'doc:stack-kms',
        'doc:stack-profile',
      ].sort(),
    )
  })

  it('expands a matrix axis in a run line', () => {
    const job = {
      strategy: { matrix: { include: [{ task: 'a:b' }, { task: 'c:d' }] } },
    }
    // biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression, which is what is being expanded.
    expect(expandMatrix('mise run ${{ matrix.task }} -- -runs=0', job)).toEqual(
      ['mise run a:b -- -runs=0', 'mise run c:d -- -runs=0'],
    )
  })

  it('counts a command and not a mention', () => {
    expect(invokes('mise run doc', 'doc')).toBe(true)
    expect(invokes('mise run doc:stack-auth', 'doc')).toBe(false)
    expect(invokes('# mise run doc', 'doc')).toBe(false)
    expect(invokes('echo "run \'mise run doc\' first"', 'doc')).toBe(false)
  })
})

describe('every task the set defines is reached by a root workflow', () => {
  const reachable = reachableFrom(ROOT_WORKFLOWS)
  const orphans = (reach) =>
    [...TASKS.keys()].filter(
      (name) => !reach.has(name) && !CI_EXEMPT_TASKS.has(name),
    )

  it('runs every task, or names it as exempt with a reason', () => {
    expect(
      orphans(reachable),
      'These mise tasks are run by no root workflow and are not in CI_EXEMPT_TASKS. A check nothing invokes reads exactly like a check that passes. Run it from a workflow, or exempt it with the reason CI does not need to.',
    ).toEqual([])
  })

  it('keeps no exemption for a task that is run, or has gone', () => {
    const stale = [...CI_EXEMPT_TASKS.keys()].filter(
      (name) => !TASKS.has(name) || reachable.has(name),
    )
    expect(
      stale,
      'These CI_EXEMPT_TASKS entries name a task that CI now runs, or one that no longer exists. Delete them.',
    ).toEqual([])
  })

  /**
   * Each workflow whose deletion would leave some task unreached. Injected,
   * not performed: the scan runs against the workflow list with one removed.
   * If a workflow leaves this list, its tasks either moved (update it) or
   * stopped running (the orphan check above fails first).
   */
  const SOLE_CALLER_WORKFLOWS = [
    `${WORKFLOW_DIR}/crap-crates.yml`, // crap:*
    `${WORKFLOW_DIR}/fuzz.yml`, // fuzz:*
    `${WORKFLOW_DIR}/miri.yml`, // miri:stack-guest-abi
    `${WORKFLOW_DIR}/tests-crates.yml`, // doc, test:doc, test:integration:*
    `${WORKFLOW_DIR}/tests-golang.yml`, // wasm:*, go:test, go:lint
  ]

  it('names every workflow whose deletion would orphan a task', () => {
    const soleCallers = ROOT_WORKFLOWS.map(({ relPath }) => relPath).filter(
      (relPath) =>
        orphans(
          reachableFrom(ROOT_WORKFLOWS.filter((wf) => wf.relPath !== relPath)),
        ).length > 0,
    )
    expect(soleCallers).toEqual(SOLE_CALLER_WORKFLOWS)
  })
})

describe('the imported workflow directory is gone', () => {
  it('does not exist', () => {
    expect(
      existsSync(join(REPO_ROOT, IMPORTED_WORKFLOW_DIR)),
      `${IMPORTED_WORKFLOW_DIR} is back. GitHub reads workflows from .github/workflows alone, so anything in there runs on no event.`,
    ).toBe(false)
  })

  it('has no tracked files', () => {
    const tracked = execFileSync(
      'git',
      ['ls-files', '-z', '--', IMPORTED_WORKFLOW_DIR],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    )
      .split('\0')
      .filter(Boolean)
    expect(tracked).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// The silent failures specific to this set
// ---------------------------------------------------------------------------

const triggers = (wf) => wf?.on ?? wf?.[true] ?? {}

/** Every step of every root workflow, with its job and effective env. */
const STEPS = ROOT_WORKFLOWS.flatMap(({ relPath, wf }) =>
  Object.entries(wf?.jobs ?? {}).flatMap(([jobName, job]) =>
    jobSteps(job).map((step, index) => ({
      relPath,
      wf,
      jobName,
      job,
      step,
      index,
      env: { ...(wf?.env ?? {}), ...(job?.env ?? {}), ...(step?.env ?? {}) },
    })),
  ),
)

describe('the trybuild `ui` binary runs somewhere', () => {
  // stack-encrypt's `tests/ui` compile-fail suite is one nextest binary,
  // `ui`, gated on the `dynamic` feature. crap:stack-encrypt and
  // .cargo/mutants.toml both filter out `binary(ui)`, so a single nextest run
  // is its only runner. If that run drops the feature, adds the same filter,
  // or narrows to other packages, the suite stops running and nothing fails.
  const runsUi = ({ step }) => {
    const run = String(step?.run ?? '')
    return run
      .split('\n')
      .some(
        (line) =>
          /\bcargo\s+nextest\s+run\b/.test(line) &&
          !/\bllvm-cov\b/.test(line) &&
          (/--workspace\b/.test(line) || /-p\s+stack-encrypt\b/.test(line)) &&
          (/--all-features\b/.test(line) ||
            /(?:--features|-F)[\s=]\S*\bdynamic\b/.test(line)) &&
          !/binary\(ui\)/.test(line),
      )
  }

  it('is declared as a test binary named `ui` behind `dynamic`', () => {
    const manifest = readRepo('packages/stack-encrypt/Cargo.toml')
    expect(manifest).toMatch(
      /\[\[test\]\]\s*\nname = "ui"\s*\nrequired-features = \["dynamic"\]/,
    )
    expect(existsSync(join(REPO_ROOT, 'packages/stack-encrypt/tests/ui'))).toBe(
      true,
    )
  })

  it('is run by a nextest step on pull requests', () => {
    const runners = STEPS.filter(runsUi).filter(
      ({ wf }) => triggers(wf).pull_request !== undefined,
    )
    expect(
      runners.map(({ relPath, jobName }) => `${relPath} / ${jobName}`),
      'No pull-request workflow runs `cargo nextest run` over stack-encrypt with the `dynamic` feature and without a `binary(ui)` filter, so the trybuild UI snapshots are checked nowhere.',
    ).not.toEqual([])
  })

  it('is filtered out where the plan says, and so needs the run above', () => {
    expect(readRepo('packages/stack-encrypt/tasks.toml')).toMatch(
      /not binary\(ui\)/,
    )
    expect(readRepo('.cargo/mutants.toml')).toMatch(/not binary\(ui\)/)
  })
})

describe('NEXTEST_PROFILE names a profile that exists', () => {
  const PROFILES = [
    ...readRepo('.config/nextest.toml').matchAll(/^\[profile\.([\w-]+)\]/gm),
  ].map((m) => m[1])

  it('defines the ci profile', () => {
    expect(PROFILES).toContain('ci')
  })

  it('sets NEXTEST_PROFILE=ci on the step that runs the ui binary', () => {
    const uiSteps = STEPS.filter(({ step }) =>
      /\bcargo\s+nextest\s+run\b.*--workspace/.test(String(step?.run ?? '')),
    )
    expect(uiSteps.length).toBeGreaterThan(0)
    for (const { relPath, jobName, env } of uiSteps) {
      expect(env.NEXTEST_PROFILE, `${relPath} / ${jobName}`).toBe('ci')
    }
  })

  it('names only defined profiles, wherever it is set', () => {
    const unknown = STEPS.filter(
      ({ env }) =>
        env.NEXTEST_PROFILE !== undefined &&
        !PROFILES.includes(env.NEXTEST_PROFILE),
    ).map(
      ({ relPath, jobName, env }) =>
        `${relPath} / ${jobName}: ${env.NEXTEST_PROFILE}`,
    )
    expect(unknown).toEqual([])
  })
})

describe('the Go jobs test the guest the Linux job built and checked', () => {
  const GO_WORKFLOW = `${WORKFLOW_DIR}/tests-golang.yml`
  const wf = readWorkflow(GO_WORKFLOW)
  const jobs = Object.entries(wf?.jobs ?? {})
  const runOf = (step) => String(step?.run ?? '')
  const isRecord = (step) =>
    /openssl dgst -sha256/.test(runOf(step)) &&
    />\s*"\$guest\.sha256"/.test(runOf(step))
  const isVerify = (step) =>
    /openssl dgst -sha256/.test(runOf(step)) &&
    /cat\s+"\$guest\.sha256"/.test(runOf(step)) &&
    /exit 1/.test(runOf(step))
  const isUpload = (step) =>
    String(step?.uses ?? '').startsWith('actions/upload-artifact@') &&
    step?.with?.name === 'wasm-guests'
  const isDownload = (step) =>
    String(step?.uses ?? '').startsWith('actions/download-artifact@') &&
    step?.with?.name === 'wasm-guests'
  const isGoTest = (step) =>
    /\bgo\s+test\b|go-binding-test\.sh|mise run go:test\b/.test(runOf(step))

  const producers = jobs.filter(([, job]) => jobSteps(job).some(isRecord))

  it('has exactly one job that records the checksums', () => {
    expect(producers.map(([name]) => name)).toEqual(['wasi-check'])
  })

  it('builds both guests, then records, then uploads, then tests', () => {
    const [, job] = producers[0]
    const steps = jobSteps(job)
    const at = (pred) => steps.findIndex(pred)
    const build = (task) => at((step) => invokes(runOf(step), task))
    const record = at(isRecord)
    expect(build('wasm:guest:build')).toBeGreaterThan(-1)
    expect(build('wasm:auth-guest:build')).toBeGreaterThan(-1)
    expect(build('wasm:guest:build')).toBeLessThan(record)
    expect(build('wasm:auth-guest:build')).toBeLessThan(record)
    expect(record).toBeLessThan(at(isUpload))
    expect(record).toBeLessThan(at(isGoTest))
  })

  it('makes every job that downloads the guests wait for, and verify, them', () => {
    const consumers = jobs.filter(([, job]) => jobSteps(job).some(isDownload))
    expect(consumers.length).toBeGreaterThan(0)
    for (const [name, job] of consumers) {
      const needs = [job?.needs ?? []].flat()
      expect(needs, `${name} needs`).toContain('wasi-check')
      const steps = jobSteps(job)
      const verify = steps.findIndex(isVerify)
      const firstGo = steps.findIndex(isGoTest)
      expect(verify, `${name}: no sha256 verification step`).toBeGreaterThan(
        steps.findIndex(isDownload),
      )
      expect(firstGo, `${name}: no Go test step`).toBeGreaterThan(-1)
      expect(verify, `${name}: Go runs before the sha256 check`).toBeLessThan(
        firstGo,
      )
    }
  })
})

describe('napi builds leave the hand-written typings alone', () => {
  // `napi build` writes its generated typings to `index.d.ts` unless `--dts`
  // names another file. Both bindings' `index.d.ts` are hand-written (auth's
  // wraps every call in a `Result`; profile's adds the error codes), so a
  // build without `--dts` overwrites them and dirties the tree of every job
  // that builds the binding. Each writes `native.d.ts` instead, which is
  // committed and diffed by the drift guard in tests-crates.yml.
  const BINDINGS = [
    'languages/typescript/packages/auth',
    'languages/typescript/packages/profile',
  ]
  const napiBuilds = BINDINGS.flatMap((dir) =>
    Object.entries(JSON.parse(readRepo(`${dir}/package.json`)).scripts ?? {})
      .filter(([, script]) => /\bnapi\s+build\b/.test(script))
      .map(([name, script]) => ({ id: `${dir} ${name}`, dir, script })),
  )

  it('finds a napi build in each binding', () => {
    for (const dir of BINDINGS) {
      expect(
        napiBuilds.some((b) => b.dir === dir),
        dir,
      ).toBe(true)
    }
  })

  it('sends every napi build to native.d.ts', () => {
    const offenders = napiBuilds
      .filter(({ script }) => !/--dts\s+native\.d\.ts\b/.test(script))
      .map(({ id, script }) => `${id}: ${script}`)
    expect(
      offenders,
      'These napi builds write their typings to the hand-written index.d.ts. Pass `--dts native.d.ts`.',
    ).toEqual([])
  })

  it('commits the native.d.ts each build writes, so the drift guard can diff it', () => {
    const missing = BINDINGS.filter(
      (dir) => !existsSync(join(REPO_ROOT, dir, 'native.d.ts')),
    )
    expect(missing).toEqual([])
  })

  it('has the drift guard rebuild each binding and fail on any change to it', () => {
    const guard = STEPS.filter(
      ({ relPath, step }) =>
        relPath === `${WORKFLOW_DIR}/tests-crates.yml` &&
        /git (?:diff --exit-code|status --porcelain)/.test(
          String(step?.run ?? ''),
        ),
    )
    expect(guard.length).toBeGreaterThan(0)
    // Commands, not mentions: the step's error message names both too.
    const lines = guard
      .flatMap(({ step }) => step.run.split('\n'))
      .map((line) => line.trim())
    const check = lines.find((line) => /git status --porcelain/.test(line))
    for (const dir of BINDINGS) {
      const name = JSON.parse(readRepo(`${dir}/package.json`)).name
      expect(
        lines.includes(`pnpm --filter ${name} run build:debug`),
        `${name} is not rebuilt`,
      ).toBe(true)
      expect(check, `${dir} is not checked`).toContain(dir)
    }
  })
})

describe('the root workspace is tested with nextest, not cargo test', () => {
  // `cargo test` runs a binary's tests as threads of one process, so tests
  // that set environment variables race (stack-kms `builder::tests::
  // invalid_config::*` fail that way). nextest runs each test in its own
  // process. Doctests are the exception: nextest cannot run them.
  const runsAtRoot = ({ job, step }) =>
    step?.['working-directory'] === undefined &&
    job?.defaults?.run?.['working-directory'] === undefined
  const testsWholeWorkspace = (line) =>
    /\bcargo\s+test\b/.test(line) &&
    !/--doc\b/.test(line) &&
    (/--workspace\b/.test(line) ||
      !/(?:\s-p\s|--package\b|--manifest-path\b)/.test(line))

  it('has no root step that runs cargo test over the workspace', () => {
    const offenders = STEPS.filter(runsAtRoot).flatMap(
      ({ relPath, jobName, step }) =>
        String(step?.run ?? '')
          .split('\n')
          .filter(testsWholeWorkspace)
          .map((line) => `${relPath} / ${jobName}: ${line.trim()}`),
    )
    expect(
      offenders,
      'Use `cargo nextest run` (and `cargo test --doc` for doctests).',
    ).toEqual([])
  })

  it('flags the shapes it is meant to', () => {
    expect(testsWholeWorkspace('cargo test --workspace')).toBe(true)
    expect(testsWholeWorkspace('cargo test --locked')).toBe(true)
    expect(testsWholeWorkspace('cargo test --doc --workspace')).toBe(false)
    expect(testsWholeWorkspace('cargo test -p stack-kms')).toBe(false)
    expect(testsWholeWorkspace('cargo nextest run --workspace')).toBe(false)
  })
})

describe('@cipherstash/profile stays private while it is unpublished', () => {
  // Without the flag the release gate classifies it as `js`, and changesets
  // would publish 0.35.0 with no binaries. Its six platform packages are the
  // same, one level down.
  const PROFILE = 'languages/typescript/packages/profile'
  const manifests = [
    `${PROFILE}/package.json`,
    ...readdirSync(join(REPO_ROOT, PROFILE, 'platforms'))
      .map((dir) => `${PROFILE}/platforms/${dir}/package.json`)
      .filter((rel) => existsSync(join(REPO_ROOT, rel))),
  ]

  it('finds the wrapper and its six platform packages', () => {
    expect(manifests).toHaveLength(7)
  })

  it('marks each one private', () => {
    const published = manifests.filter(
      (rel) => JSON.parse(readRepo(rel)).private !== true,
    )
    expect(published).toEqual([])
  })
})
