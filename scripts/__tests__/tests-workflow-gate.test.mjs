import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, posix } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * `tests.yml` runs its live jobs (two native bindings, Postgres, CipherStash
 * credentials) only when a pull request changes a file they can read. The
 * `changes` job decides that with two dorny/paths-filter lists:
 *
 *   `rest`   — `**` minus excluded trees, `predicate-quantifier: every`, so a
 *              file selects it only when it is outside every exclusion;
 *   `direct` — paths inside those trees that the live jobs do read.
 *
 * As one GitHub-style ordered list that is `[...rest, ...direct]`: later
 * entries win, so a `direct` entry re-includes what a `rest` negation
 * excluded. This file holds the two lists to the jobs they gate.
 *
 * Getting an exclusion wrong is the failure that matters. A path the live jobs
 * read, excluded here, is a change that merges with every suite that would
 * have caught it skipped, and a skipped job reads as green.
 */

const WORKFLOW = '.github/workflows/tests.yml'
const wf = readWorkflow(WORKFLOW)
const changes = wf.jobs.changes
const step = (id) => changes.steps.find((candidate) => candidate.id === id)
const filterOf = (id) => yaml.load(step(id)?.with?.filters ?? '')?.js ?? []
const REST = filterOf('rest')
const DIRECT = filterOf('direct')
const EFFECTIVE = [...REST, ...DIRECT]

/** GitHub / picomatch-style glob, `dot: true`: `*` stops at `/`, `**` does not. */
function globRegExp(glob) {
  let source = ''
  for (const token of glob.split(/(\*\*\/|\*\*|\*|\?)/)) {
    if (token === '**/') source += '(?:.*/)?'
    else if (token === '**') source += '.*'
    else if (token === '*') source += '[^/]*'
    else if (token === '?') source += '[^/]'
    else source += token.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  }
  return new RegExp(`^${source}$`)
}

const COMPILED = EFFECTIVE.map((entry) => ({
  negated: entry.startsWith('!'),
  re: globRegExp(entry.replace(/^!/, '')),
}))

/** Whether a change to `file` alone leaves the live jobs skipped. */
function skips(file) {
  let selected = false
  for (const { negated, re } of COMPILED) {
    if (re.test(file)) selected = !negated
  }
  return !selected
}

/** A path, or anything beneath it if it names a directory. */
const skipsPath = (path) =>
  skips(path) || skips(`${path.replace(/\/$/, '')}/__probe__`)

const GATED = Object.entries(wf.jobs).filter(
  ([, job]) => job.if === "needs.changes.outputs.js == 'true'",
)
const UNGATED = ['lint', 'changes', 'repo-checks', 'tests-required']

describe('tests.yml — the gate itself', () => {
  it('splits the question into the two lists the comments describe', () => {
    expect(step('rest')?.with?.['predicate-quantifier']).toBe('every')
    expect(REST[0]).toBe('**')
    expect(
      REST.slice(1).filter((entry) => !entry.startsWith('!')),
      'Under `predicate-quantifier: every` a positive entry after `**` intersects rather than re-includes. A path the live jobs read belongs in `direct`.',
    ).toEqual([])
    expect(step('direct')?.with?.['predicate-quantifier']).toBeUndefined()
    expect(DIRECT.filter((entry) => entry.startsWith('!'))).toEqual([])
    expect(DIRECT.length).toBeGreaterThan(0)
    for (const id of ['rest', 'direct']) {
      expect(step(id).if).toBe("github.event_name == 'pull_request'")
    }
  })

  it('gates every job but the ones that read the whole tree', () => {
    const jobs = Object.keys(wf.jobs)
    expect(
      jobs.filter((id) => !UNGATED.includes(id)).sort(),
      'Every job outside UNGATED must carry the gate. A new live job without it runs on every pull request again; a new job WITH no live dependency belongs in `repo-checks`.',
    ).toEqual(GATED.map(([id]) => id).sort())
    for (const [id, job] of GATED) {
      expect([job.needs].flat(), `${id} must need \`changes\``).toContain(
        'changes',
      )
    }
    expect(GATED.map(([id]) => id)).toContain('run-tests')
  })

  it('has `tests-required` summarise every other job', () => {
    const summary = wf.jobs['tests-required']
    expect(summary.if).toBe('always()')
    expect([...summary.needs].sort()).toEqual(
      Object.keys(wf.jobs)
        .filter((id) => id !== 'tests-required')
        .sort(),
    )
  })

  describe('the decision script', () => {
    const run = (env) => {
      const dir = mkdtempSync(join(tmpdir(), 'tests-gate-'))
      const output = join(dir, 'out')
      try {
        execFileSync('bash', ['-c', ': > "$GITHUB_OUTPUT"'], {
          env: { PATH: process.env.PATH, GITHUB_OUTPUT: output },
        })
        execFileSync('bash', ['-c', String(step('r').run)], {
          env: { PATH: process.env.PATH, GITHUB_OUTPUT: output, ...env },
        })
        return readFileSync(output, 'utf8').trim()
      } finally {
        rmSync(dir, { recursive: true, force: true })
      }
    }
    const pr = { EVENT_NAME: 'pull_request' }
    it('runs everything on any event but a pull request', () => {
      expect(run({ EVENT_NAME: 'push', REST: '', DIRECT: '' })).toBe('js=true')
    })
    it('runs when either list matched', () => {
      expect(run({ ...pr, REST: 'true', DIRECT: 'false' })).toBe('js=true')
      expect(run({ ...pr, REST: 'false', DIRECT: 'true' })).toBe('js=true')
    })
    it('skips only when neither did', () => {
      expect(run({ ...pr, REST: 'false', DIRECT: 'false' })).toBe('js=false')
    })
  })
})

/**
 * What the live jobs run, as the trees their code lives in. `pnpm test` walks
 * every package under `languages/typescript/packages/` and `packages/eql/`'s
 * npm package; the e2e and WASM jobs run `e2e/`.
 */
const LIVE_ROOTS = ['languages/typescript', 'e2e', 'packages/eql/packages/eql']

/**
 * Files under LIVE_ROOTS that read an excluded path, and why that is not a
 * hole. Each must name a reason; the stale check fails an entry that no longer
 * matches anything.
 */
const READS_EXCLUDED = new Map([
  [
    'e2e/tests/supply-chain.e2e.test.ts',
    'Reads `.github/workflows/`. Run in `repo-checks`, which is not gated.',
  ],
  [
    'languages/typescript/packages/protect-ffi/src/lintWiring.test.ts',
    'Reads `.github/workflows/`. protect-ffi’s suite also runs in `repo-checks`.',
  ],
  [
    'languages/typescript/packages/protect-ffi/src/integrationSuiteCi.test.ts',
    'Reads `.github/workflows/`. protect-ffi’s suite also runs in `repo-checks`.',
  ],
  [
    'packages/eql/packages/eql/scripts/sync-generated.mjs',
    'Reads `crates/eql-bindings/bindings` and `schema`. Run by `check:generated` and the release, never by `pnpm test`.',
  ],
])

/**
 * The directories a relative literal in `file` may be resolved from: its own,
 * and each one above it up to its package root (the nearest `package.json`).
 * Code joins from either; the protect-ffi suites join
 * `../../../../.github/workflows` onto the package root. Not above it, where
 * `./dist/…` in a package manifest would resolve to nonsense.
 */
function basesOf(file) {
  const bases = []
  for (let dir = posix.dirname(file); ; dir = posix.dirname(dir)) {
    bases.push(dir)
    if (dir === '.' || PACKAGE_ROOTS.has(dir)) break
  }
  return bases
}

const PACKAGE_ROOTS = new Set(
  execFileSync(
    'git',
    [
      'ls-files',
      '--',
      ...LIVE_ROOTS.map((root) => `${root}/**/package.json`),
      ...LIVE_ROOTS.map((root) => `${root}/package.json`),
    ],
    {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    },
  )
    .split('\n')
    .filter(Boolean)
    .map((manifest) => posix.dirname(manifest)),
)

/** Source files the live jobs may execute, as opposed to prose and manifests. */
const CODE = /\.(?:[cm]?[jt]sx?|json|ya?ml)$/

/**
 * Every file under LIVE_ROOTS that names a path the gate skips, with the line.
 *
 * Text, not execution, so it sees a path written out rather than built at run
 * time. A literal counts when it is relative (`../…`) and resolves to an
 * excluded path from the file's directory or any directory above it (code
 * often joins from its package root, not its own directory), or when it is
 * repo-relative on a line that mentions a repo root.
 */
function readsOfExcludedPaths() {
  const files = execFileSync('git', ['ls-files', '-z', '--', ...LIVE_ROOTS], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  })
    .split('\0')
    .filter((file) => CODE.test(file))
  const literal = /(['"`])((?:\.\.?\/)*[A-Za-z0-9_.@-][^'"`\s$]*)\1/g
  const found = []
  for (const file of files) {
    const text = readFileSync(join(REPO_ROOT, file), 'utf8')
    const lines = text.split('\n')
    lines.forEach((line, idx) => {
      if (line.length > 1000) return
      const rooted = /\b(?:repo|workspace|monorepo)_?root\b/i.test(line)
      for (const [, , value] of line.matchAll(literal)) {
        const targets = []
        if (/^\.\.?\//.test(value)) {
          for (const base of basesOf(file)) {
            targets.push(posix.normalize(posix.join(base, value)))
          }
        } else if (rooted) {
          targets.push(value)
        }
        const hit = targets.find(
          (target) =>
            !target.startsWith('..') && target !== '.' && skipsPath(target),
        )
        if (hit) found.push({ file, line: idx + 1, value, hit })
      }
    })
  }
  return found
}

describe('tests.yml — what the gate skips, no live job reads', () => {
  const reads = readsOfExcludedPaths()

  it('finds no live code reading an excluded path', () => {
    const unexplained = reads
      .filter(({ file }) => !READS_EXCLUDED.has(file))
      .map(({ file, line, value, hit }) => `${file}:${line} ${value} (${hit})`)
    expect(
      unexplained,
      'These files run in a gated job and name a path the gate excludes, so a pull request changing only that path skips the job that reads it. Either take the path out of the `rest` exclusions (or add it to `direct`), or, if the read happens somewhere ungated, record where in READS_EXCLUDED.',
    ).toEqual([])
  })

  it('keeps no stale READS_EXCLUDED entries', () => {
    const live = new Set(reads.map(({ file }) => file))
    expect(
      [...READS_EXCLUDED.keys()].filter((file) => !live.has(file)),
      'These entries excuse nothing the scan finds any more. Delete them.',
    ).toEqual([])
  })

  it('the scan sees a read when there is one', () => {
    // The protect-ffi suites join `../../../../.github/workflows` onto their
    // package root, not their own directory. A scan resolving only from the
    // file would miss both, and every check above would pass having seen
    // nothing.
    expect(reads.map(({ file }) => file)).toEqual(
      expect.arrayContaining([
        'languages/typescript/packages/protect-ffi/src/lintWiring.test.ts',
        'e2e/tests/supply-chain.e2e.test.ts',
      ]),
    )
  })

  it('the readers it excuses as ungated do run in repo-checks', () => {
    const runs = wf.jobs['repo-checks'].steps
      .map((candidate) => String(candidate.run ?? ''))
      .join('\n')
    expect(runs).toMatch(
      /turbo run test --filter @cipherstash\/protect-ffi(\s|$)/,
    )
    expect(runs).toContain('tests/supply-chain.e2e.test.ts')
    expect(runs).toContain('pnpm run test:scripts')
  })
})

describe('tests.yml — the bindings the live jobs build stay selected', () => {
  /**
   * The Rust crates behind `@cipherstash/auth` and `@cipherstash/profile`,
   * which every live job compiles, found by following `path =` dependencies
   * from the binding crates. Optional ones are followed too: over-reading
   * here only makes the check stricter.
   */
  function pathDependencyClosure(manifests) {
    // `name = { workspace = true }` inherits the root's `[workspace.dependencies]`
    // entry, which is where the stack-* path dependencies are written.
    const inherited = new Map()
    let inTable = false
    for (const raw of readFileSync(join(REPO_ROOT, 'Cargo.toml'), 'utf8').split(
      '\n',
    )) {
      const header = /^\s*\[([^\]]+)\]/.exec(raw)
      if (header) inTable = header[1] === 'workspace.dependencies'
      const entry =
        inTable &&
        /^([A-Za-z0-9_-]+)\s*=\s*\{.*\bpath\s*=\s*"([^"]+)"/.exec(raw)
      if (entry) inherited.set(entry[1], entry[2])
    }
    const seen = new Set()
    const queue = [...manifests]
    while (queue.length > 0) {
      const manifest = queue.shift()
      const dir = posix.dirname(manifest)
      if (seen.has(dir)) continue
      seen.add(dir)
      const text = readFileSync(join(REPO_ROOT, manifest), 'utf8')
      for (const [, path] of text.matchAll(/\bpath\s*=\s*"([^"]+)"/g)) {
        const target = posix.normalize(posix.join(dir, path))
        if (target.endsWith('.rs')) continue
        queue.push(`${target}/Cargo.toml`)
      }
      for (const [, name] of text.matchAll(
        /^([A-Za-z0-9_-]+)\s*=\s*\{[^}\n]*\bworkspace\s*=\s*true/gm,
      )) {
        const path = inherited.get(name)
        if (path) queue.push(`${posix.normalize(path)}/Cargo.toml`)
      }
    }
    return [...seen]
  }

  const crates = pathDependencyClosure([
    'languages/typescript/packages/auth/Cargo.toml',
    'languages/typescript/packages/profile/Cargo.toml',
  ])

  it('finds the crates the auth and profile bindings compile', () => {
    expect(crates).toEqual(
      expect.arrayContaining(['packages/stack-auth', 'packages/stack-profile']),
    )
  })

  it('excludes none of them', () => {
    expect(
      crates.filter((dir) => skips(`${dir}/src/lib.rs`)),
      'The live jobs compile these crates into the auth and profile bindings, and the gate would skip a change to them.',
    ).toEqual([])
  })

  it('keeps the root Cargo manifests and toolchain pins', () => {
    for (const file of [
      'Cargo.toml',
      'Cargo.lock',
      '.cargo/config.toml',
      'mise.toml',
      'pnpm-lock.yaml',
      'pnpm-workspace.yaml',
      'package.json',
      'turbo.json',
      '.github/workflows/tests.yml',
      '.github/actions/build-ffi-binding/action.yml',
    ]) {
      expect(skips(file), `${file} must start the live jobs`).toBe(false)
    }
  })
})
