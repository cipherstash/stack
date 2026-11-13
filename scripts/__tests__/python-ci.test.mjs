import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join, posix } from 'node:path'
import { describe, expect, it } from 'vitest'
import { pathPackageNames } from './lib/cargo-lock.mjs'
import { filterCovers } from './lib/paths-filter.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import {
  readWorkflow,
  runWorkingDirectory,
  triggers,
} from './lib/workflows.mjs'

/**
 * `tests-python.yml` is held to the Python workspace it tests, with every
 * expectation derived from the tree rather than copied into this file.
 *
 * The workspace at `languages/python` is the fourth Cargo workspace. It is
 * the first whose checks a path filter can skip without anything else
 * noticing. `tests-crates.yml` compiles the stack-* crates but never links
 * them into pyo3. `tests.yml`'s `changes` filter excludes those crates on
 * purpose. So a stack-encrypt change that breaks the Python engine crate is
 * caught here or nowhere. "Here" depends on the `pull_request` filter naming
 * every tree the workspace compiles. That list is the workspace's path
 * dependencies.
 * `Cargo.lock` records those as packages with no `source`. A new path
 * dependency appears in the lockfile, and this file fails until the filter
 * follows.
 *
 * The other facts are read the same way. The two Python versions come from
 * `pyproject.toml`'s floor and `mise.toml`'s own version. The six wheel
 * targets come from the protect-ffi platform packages. The issue names "the
 * six platforms the FFI already ships for". A seventh platform or a moved
 * floor changes the source and this file says so.
 */

const WORKFLOW = '.github/workflows/tests-python.yml'
const PYTHON_ROOT = 'languages/python'

const read = (rel) => readFileSync(join(REPO_ROOT, rel), 'utf8')

/**
 * The directories outside `languages/python` whose crates the workspace
 * compiles. Every `[[package]]` in its Cargo.lock without a `source` line is
 * a path dependency. The stack-* ones live at `packages/<name>`. The EQL
 * crates live at `packages/eql/crates/<name>`.
 */
function pathDependencyTrees() {
  const trees = new Set()
  for (const name of pathPackageNames(read(`${PYTHON_ROOT}/Cargo.lock`))) {
    if (name.startsWith('stackencrypt-')) continue
    const dir = [`packages/${name}`, `packages/eql/crates/${name}`].find((d) =>
      existsSync(join(REPO_ROOT, d, 'Cargo.toml')),
    )
    if (!dir) {
      throw new Error(
        `${PYTHON_ROOT}/Cargo.lock lists ${name} as a path dependency, and neither packages/${name} nor packages/eql/crates/${name} holds its Cargo.toml; teach this test where it lives`,
      )
    }
    trees.add(dir)
  }
  return [...trees].sort()
}

/**
 * A `paths:` glob of the form `dir/**` selects a file under `dir`. Only that
 * form. A narrower glob (`dir/src/**`) would leave part of the tree
 * unwatched. GitHub's full glob grammar is not needed to read this one filter.
 */
const coversTree = (pattern, file) =>
  pattern.endsWith('/**') && file.startsWith(pattern.slice(0, -2))

/**
 * The files the workspace's crates compile through a `#[path = "..."]`
 * module. Cargo.lock does not record them, so they are read from every `.rs`
 * file under `crates/`. A path is resolved from the directory of the file
 * that names it, which is Rust's rule outside an inline `mod { }` block.
 */
function pathModuleFiles() {
  const files = []
  const walk = (dir) => {
    for (const entry of readdirSync(join(REPO_ROOT, dir), {
      withFileTypes: true,
    })) {
      const rel = `${dir}/${entry.name}`
      if (entry.isDirectory()) walk(rel)
      else if (entry.name.endsWith('.rs')) {
        const attribute = /#\[\s*path\s*=\s*"([^"]+)"\s*\]/g
        for (const match of read(rel).matchAll(attribute)) {
          files.push(posix.normalize(`${dir}/${match[1]}`))
        }
      }
    }
  }
  walk(`${PYTHON_ROOT}/crates`)
  return files.sort()
}

describe('tests-python.yml', () => {
  it('runs on pull requests touching every tree the Python workspace compiles', () => {
    const on = triggers(readWorkflow(WORKFLOW))
    const paths = on.pull_request?.paths ?? []
    const wanted = [
      PYTHON_ROOT,
      ...pathDependencyTrees(),
      // The issue names the EQL codegen. eql-codegen generates the marker
      // names the SDK ships from the eql-domains catalog (#1385). A change to
      // either must rerun the suite that reads the generated names.
      'packages/eql/crates/eql-codegen',
      'packages/eql/crates/eql-domains',
    ]
    const missing = wanted.filter(
      (dir) => !filterCovers(paths, `${dir}/x`, coversTree),
    )
    expect(
      missing,
      `pull_request.paths does not select these trees, which the Python workspace compiles or generates from:\n${missing.join('\n')}`,
    ).toEqual([])
  })

  it('finds the stack crates as path dependencies, so the filter check is not empty', () => {
    // A lockfile parser that finds nothing would leave the check above with
    // no tree to look for, and it would pass.
    expect(pathDependencyTrees()).toEqual(
      expect.arrayContaining(['packages/stack-encrypt', 'packages/stack-kms']),
    )
  })

  it('runs on pull requests touching a file the core crate compiles by #[path]', () => {
    const paths = triggers(readWorkflow(WORKFLOW)).pull_request?.paths ?? []
    const files = pathModuleFiles()
    expect(files).toContain('languages/golang/encrypt/guest/src/targets.rs')
    const exact = (pattern, file) => pattern === file
    const missing = files.filter(
      (file) =>
        !filterCovers(paths, file, (p, f) => exact(p, f) || coversTree(p, f)),
    )
    expect(
      missing,
      `pull_request.paths does not select these files, which crates/core compiles by #[path]:\n${missing.join('\n')}`,
    ).toEqual([])
  })

  it('runs the pure-Python suite on the oldest supported Python and the one mise.toml names', () => {
    // The floor is `requires-python` in pyproject.toml; the local version is the
    // interpreter `mise run test` links locally. A wheel tagged abi3-py39 is a
    // claim about the floor, and only a run on the floor tests it.
    const floor = /^requires-python = ">=(\d+\.\d+)"/m.exec(
      read(`${PYTHON_ROOT}/pyproject.toml`),
    )?.[1]
    const local = /^python = "(\d+\.\d+)"/m.exec(
      read(`${PYTHON_ROOT}/mise.toml`),
    )?.[1]
    expect(floor, 'pyproject.toml requires-python floor').toBeTruthy()
    expect(local, 'languages/python/mise.toml python version').toBeTruthy()

    const wf = readWorkflow(WORKFLOW)
    const matrices = Object.entries(wf.jobs)
      .map(([id, job]) => [id, job.strategy?.matrix?.python])
      .filter(([, versions]) => Array.isArray(versions))
    expect(matrices.length, 'one job carries a `python:` matrix').toBe(1)
    const [[id, versions]] = matrices
    // Strings, not floats: YAML reads a bare `3.10` as the number 3.1.
    expect(
      versions.map(String).sort(),
      `jobs.${id}.strategy.matrix.python must be exactly the floor and the local version`,
    ).toEqual([floor, local].sort())
    for (const v of versions) {
      expect(typeof v, `matrix.python entry ${v} must be a quoted string`).toBe(
        'string',
      )
    }
  })

  it('builds one wheel per platform the FFI ships for, by the same Rust triples', () => {
    // Each platform package carries `neon.rust`, the triple its binary is
    // built for. The issue names "the six platforms the FFI already ships
    // for". So the wheel matrix is held to that list, not to a copy of it. A
    // seventh platform package, or a moved triple, fails here. The count six
    // is written here and nowhere else: the workflow derives its own count
    // from the platform list in `wheels-summary`.
    const platformsDir = 'languages/typescript/packages/protect-ffi/platforms'
    const ffi = readdirSync(join(REPO_ROOT, platformsDir))
      .map((name) => {
        const pkg = JSON.parse(read(`${platformsDir}/${name}/package.json`))
        return { platform: name, target: pkg.neon?.rust }
      })
      .filter((p) => p.target)
      .sort((a, b) => a.platform.localeCompare(b.platform))
    expect(ffi.length, 'protect-ffi platform packages').toBe(6)

    const wf = readWorkflow(WORKFLOW)
    const wheelJobs = Object.entries(wf.jobs).filter(
      ([, job]) =>
        Array.isArray(job.strategy?.matrix?.include) &&
        job.strategy.matrix.include.some((leg) => leg.target),
    )
    expect(wheelJobs.length, 'one job carries a matrix of `target` legs').toBe(
      1,
    )
    const [[id, job]] = wheelJobs
    const legs = job.strategy.matrix.include
      .map(({ platform, target }) => ({ platform, target }))
      .sort((a, b) => a.platform.localeCompare(b.platform))
    expect(
      legs,
      `jobs.${id}.strategy.matrix.include (platform, target)`,
    ).toEqual(ffi)
  })

  it('restores a Rust cache in every job that compiles Rust', () => {
    // The acceptance criterion, and the repo-wide rule eql-suite-ci.test.mjs
    // holds the EQL workflows to. A job compiles Rust when a step runs cargo
    // directly or through maturin-action. A mise task of the Python workspace
    // counts too: every one of them builds.
    const wf = readWorkflow(WORKFLOW)
    const compiles = (step) =>
      /\bcargo\b|\bmise run\b/.test(step.run ?? '') ||
      /^PyO3\/maturin-action@/.test(step.uses ?? '')
    // The scan must find the jobs that compile, or the check below passes
    // over none: a wheel step in another form would drop out of it.
    const compiling = Object.entries(wf.jobs)
      .filter(([, job]) => job.steps.some(compiles))
      .map(([id]) => id)
    expect(compiling.sort()).toEqual(['live', 'python', 'wheels'])
    const missing = Object.entries(wf.jobs)
      .filter(([, job]) => job.steps.some(compiles))
      .filter(
        ([, job]) =>
          !job.steps.some((step) =>
            /^Swatinem\/rust-cache@/.test(step.uses ?? ''),
          ),
      )
      .map(([id]) => id)
    expect(
      missing,
      'jobs that compile Rust with no Swatinem/rust-cache step',
    ).toEqual([])
  })

  it('builds the deterministic test extension with the features of the normal build', () => {
    // `--features` replaces pyproject.toml's list. A feature added there and
    // not here would leave tests_deterministic/ testing another extension.
    const pyproject = read(`${PYTHON_ROOT}/pyproject.toml`)
    const declared = pyproject.match(/^features = \[([^\]]*)\]/m)
    expect(
      declared,
      'pyproject.toml has a [tool.maturin] features list',
    ).not.toBeNull()
    const normal = [...declared[1].matchAll(/"([^"]+)"/g)].map((m) => m[1])
    // The test:deterministic task's own body: test:cargo names --features
    // too, so the first match in the file depends on the order of tasks.
    const body = read(`${PYTHON_ROOT}/mise.toml`).match(
      /^\[tasks\."test:deterministic"\]\n([\s\S]*?)(?=^\[|(?![\s\S]))/m,
    )
    expect(body, 'mise.toml has a test:deterministic task').not.toBeNull()
    const task = body[1].match(/--features ([^\s"]+)/)
    expect(task, 'test:deterministic passes --features').not.toBeNull()
    expect(task[1].split(',').sort()).toEqual(
      [...normal, 'deterministic-kms'].sort(),
    )
  })

  it('builds the wheels with the maturin version uv.lock locks', () => {
    // The live job and mise run build use uv.lock's maturin; the wheels job
    // pins its own. Dependabot updates the lock alone, so the two can part.
    const lock = read(`${PYTHON_ROOT}/uv.lock`)
    const locked = lock.match(/^name = "maturin"\nversion = "([^"]+)"/m)
    expect(locked, 'uv.lock locks maturin').not.toBeNull()
    const pins = [...read(WORKFLOW).matchAll(/maturin-version: v?(\S+)/g)].map(
      (m) => m[1],
    )
    expect(pins.length, 'maturin-version pins in the workflow').toBeGreaterThan(
      0,
    )
    expect(new Set(pins), "every maturin-version equals uv.lock's").toEqual(
      new Set([locked[1]]),
    )
  })

  it('runs the parity test that refuses a hand edit to _eql.py', () => {
    // The one check that fails when someone edits the generated
    // `_eql.py` by hand: test-eql.yml does not start on a change under
    // languages/python.
    const wf = readWorkflow(WORKFLOW)
    const runs = Object.values(wf.jobs)
      .flatMap((job) => job.steps)
      .map((step) => step.run ?? '')
      .filter((run) =>
        [
          'cargo test',
          '--locked',
          '-p eql-codegen',
          '--test py_eql_parity',
        ].every((part) => run.includes(part)),
      )
    expect(
      runs,
      "steps that run eql-codegen's py_eql_parity test",
    ).toHaveLength(1)
  })

  it('builds from uv.lock, with no tool resolved outside it', () => {
    // `uv sync --locked` refuses a lock that does not match pyproject.toml;
    // without it, uv would update the lock and the build would pass. Each
    // `uv pip install` must take nothing from the index: `--no-deps` for
    // the package's dependencies, `--no-build-isolation` for maturin.
    expect(existsSync(join(REPO_ROOT, PYTHON_ROOT, 'uv.lock'))).toBe(true)
    const miseToml = read(`${PYTHON_ROOT}/mise.toml`)
    const build = miseToml.match(
      /^\[tasks\.build\]\n([\s\S]*?)(?=^\[|(?![\s\S]))/m,
    )
    expect(build, 'mise.toml has a [tasks.build]').not.toBeNull()
    const lines = build[1]
      .split('\n')
      .filter((line) => !line.trim().startsWith('#'))
    const syncs = lines.filter((line) => /\buv sync\b/.test(line))
    expect(syncs, 'uv sync lines in the build task').toHaveLength(1)
    expect(syncs[0]).toContain('--locked')
    expect(syncs[0]).toContain('--group build')
    const installs = lines.filter((line) => /\buv pip install\b/.test(line))
    expect(
      installs.length,
      'uv pip install lines in the build task',
    ).toBeGreaterThan(0)
    for (const line of installs) {
      expect(line).toContain('--no-deps')
      expect(line).toContain('--no-build-isolation')
    }
  })

  it('runs every task of the Python workspace, and the two cargo lints, from that folder', () => {
    // "A check nothing invokes reads exactly like a check that passes"
    // (crates-ci.test.mjs). That file scans the root mise.toml and the crate
    // task files. It does not read languages/python/mise.toml, where the
    // Python tasks live. So this is their caller check. Every task defined
    // there is run by a step whose working directory is the workspace, except
    // one another task depends on. fmt and clippy are plain cargo commands,
    // not tasks, so they are named here.
    const miseToml = read(`${PYTHON_ROOT}/mise.toml`)
    const tasks = [
      ...miseToml.matchAll(/^\[tasks\.(?:"([^"]+)"|([\w:-]+))\]/gm),
    ].map((m) => m[1] ?? m[2])
    const dependedOn = new Set(
      [...miseToml.matchAll(/^depends = \[([^\]]*)\]/gm)].flatMap((m) =>
        [...m[1].matchAll(/"([^"]+)"/g)].map((d) => d[1]),
      ),
    )
    expect(tasks, 'tasks read from languages/python/mise.toml').toContain(
      'test',
    )

    const wf = readWorkflow(WORKFLOW)
    const runs = Object.values(wf.jobs).flatMap((job) =>
      job.steps
        .filter((step) => runWorkingDirectory(wf, job, step) === PYTHON_ROOT)
        .map((step) => step.run ?? ''),
    )
    const invoked = (command) =>
      runs.some((run) =>
        new RegExp(`(^|[\\s;&|])${command}(\\s|$)`, 'm').test(run),
      )

    // A local shortcut CI runs in parts. `test:live` builds, then runs
    // `test:live:run`. The live job runs the builds and `test:live:run` as
    // separate steps, so that no build runs with the CS_* credentials set.
    const localOnly = { 'test:live': 'mise run test:live:run' }
    for (const [task, runs] of Object.entries(localOnly)) {
      const body = miseToml.match(
        new RegExp(
          `^\\[tasks\\."${task}"\\]\\n([\\s\\S]*?)(?=^\\[|(?![\\s\\S]))`,
          'm',
        ),
      )
      expect(body, `${task} is still a task`).not.toBeNull()
      expect(body[1], `${task} still runs ${runs}`).toContain(runs)
    }

    const wanted = [
      ...tasks
        .filter((t) => !dependedOn.has(t) && !(t in localOnly))
        .map((t) => `mise run ${t}`),
      'cargo fmt --all --check',
      'cargo clippy',
    ]
    const missing = wanted.filter((command) => !invoked(command))
    expect(
      missing,
      `no step with working-directory ${PYTHON_ROOT} runs these:\n${missing.join('\n')}`,
    ).toEqual([])
  })

  it('lists in the summary job the same platforms the wheel matrix builds', () => {
    // `wheels-summary` cannot see the matrix, so it carries the list a second
    // time. This holds the copy to the original.
    const wf = readWorkflow(WORKFLOW)
    const matrix = wf.jobs.wheels.strategy.matrix.include.map(
      (leg) => leg.platform,
    )
    const summary = wf.jobs['wheels-summary'].steps
      .map((s) => s.run ?? '')
      .join('\n')
    const listed = /^\s*platforms="([^"]+)"/m.exec(summary)?.[1]?.split(/\s+/)
    expect(listed, 'a `platforms="…"` line in wheels-summary').toBeTruthy()
    expect([...listed].sort()).toEqual([...matrix].sort())
  })

  it('hands the engine commit to every container build, under the name build.rs reads', () => {
    // maturin-action runs the Linux legs in a manylinux container, as root,
    // on a bind mount the runner user owns. There the core crate's build
    // script cannot read the commit from git. The first run of this workflow
    // failed on all three container legs with its "no engine commit" panic.
    // The script reads one override variable instead. The name comes from
    // build.rs, so a rename there fails here. maturin-action forwards only
    // the variables on its own prefix allowlist, so the step must name this
    // one in `docker-options` as well as set it.
    const override = /^const ENV_OVERRIDE: &str = "([A-Z0-9_]+)";/m.exec(
      read(`${PYTHON_ROOT}/crates/core/build.rs`),
    )?.[1]
    expect(override, 'ENV_OVERRIDE in crates/core/build.rs').toBeTruthy()

    const wf = readWorkflow(WORKFLOW)
    const steps = Object.values(wf.jobs).flatMap((job) =>
      job.steps.filter((step) =>
        /^PyO3\/maturin-action@/.test(step.uses ?? ''),
      ),
    )
    expect(steps.length, 'maturin-action steps').toBeGreaterThan(0)
    for (const step of steps) {
      expect(
        step.env?.[override],
        `the maturin-action step must set ${override}`,
      ).toBeTruthy()
      expect(
        String(step.with?.['docker-options'] ?? '').split(/\s+/),
        `docker-options must forward ${override} into the container`,
      ).toEqual(expect.arrayContaining(['-e', override]))
    }
  })

  it('gives a CipherStash credential to the live job only, which skips on a fork', () => {
    // A credentialed job is one ffi-binding-step-order.test.mjs holds to the
    // secrets pre-flight. Only `live` needs one (#1389). A fork's pull
    // request has no secrets, so the job skips there rather than fails.
    const { jobs } = readWorkflow(WORKFLOW)
    const credentialed = Object.entries(jobs)
      .filter(([, job]) => /(vars|secrets)\.CS_/.test(JSON.stringify(job)))
      .map(([id]) => id)
    expect(credentialed).toEqual(['live'])
    expect(jobs.live.if).toMatch(/head\.repo\.full_name == github\.repository/)
  })
})
