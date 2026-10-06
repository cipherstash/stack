import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { isShipped } from '../check-auth-npm-changeset.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * `require-auth-npm-changeset.yml` and the script it runs, ported from
 * cipherstash-suite with the stack-* crates.
 *
 * The workflow decides WHEN the check applies (a pull request that changes
 * what `@cipherstash/auth` ships) and the script decides WHETHER the
 * changesets it is handed carry a release for it. Both halves fail open: a
 * path the workflow does not diff is a change that never needs a changeset,
 * a path `--shipped` wrongly drops is a change released with no version, and
 * a script that accepts anything is a check that passes.
 */

const SCRIPT = 'scripts/check-auth-npm-changeset.mjs'
const WORKFLOW = '.github/workflows/require-auth-npm-changeset.yml'

const dir = mkdtempSync(join(tmpdir(), 'check-auth-npm-changeset-'))
afterAll(() => rmSync(dir, { recursive: true, force: true }))

let count = 0
const changeset = (body, name = `c${++count}.md`) => {
  const file = join(dir, name)
  writeFileSync(file, body)
  return file
}

const run = (...files) =>
  spawnSync(process.execPath, [SCRIPT, ...files], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  })

describe('check-auth-npm-changeset.mjs', () => {
  it('fails with no changeset', () => {
    const result = run()
    expect(result.status).toBe(1)
    expect(result.stderr).toContain('require an @cipherstash/auth changeset')
  })

  it.each(['patch', 'minor', 'major'])(
    'passes a %s release of @cipherstash/auth',
    (type) => {
      const result = run(
        changeset(`---\n"@cipherstash/auth": ${type}\n---\n\nA change.\n`),
      )
      expect(result.stderr).toBe('')
      expect(result.status).toBe(0)
    },
  )

  it('fails a changeset that releases only other packages', () => {
    const result = run(
      changeset('---\n"@cipherstash/stack": patch\n---\n\nA change.\n'),
    )
    expect(result.status).toBe(1)
    expect(result.stderr).toContain('with a patch, minor, or major bump')
  })

  it('fails a `none` release of @cipherstash/auth', () => {
    const result = run(
      changeset('---\n"@cipherstash/auth": none\n---\n\nA change.\n'),
    )
    expect(result.status).toBe(1)
  })

  it('fails a changeset with an empty summary', () => {
    const result = run(changeset('---\n"@cipherstash/auth": patch\n---\n\n'))
    expect(result.status).toBe(1)
    expect(result.stderr).toContain('summary must not be empty')
  })

  it('ignores .changeset/README.md, which the workflow pathspec matches', () => {
    const readme = changeset('# Changesets\n', 'README.md')
    expect(run(readme).status).toBe(1)
    expect(
      run(
        readme,
        changeset('---\n"@cipherstash/auth": patch\n---\n\nA change.\n'),
      ).status,
    ).toBe(0)
  })

  it('tells a contributor to run the pnpm changeset command', () => {
    expect(run().stderr).toContain("'pnpm changeset'")
  })
})

const AUTH = 'languages/typescript/packages/auth'
const WASM = 'languages/typescript/packages/stack-auth-wasm'

/** A manifest on each side of a pull request; `undefined` is absent. */
const sides = (base, head) => ({
  readBase: () => (base === undefined ? undefined : JSON.stringify(base)),
  readHead: () => (head === undefined ? undefined : JSON.stringify(head)),
})
const unread = sides({}, {})

const manifest = {
  name: '@cipherstash/auth',
  version: '1.0.0',
  files: ['index.js'],
  peerDependencies: { next: '>=14' },
  devDependencies: { vitest: '^3' },
}

describe('isShipped', () => {
  it.each([
    `${AUTH}/__tests__/consumer-typecheck.test.ts`,
    `${AUTH}/examples/device-code.ts`,
    `${AUTH}/vitest.config.ts`,
    `${AUTH}/tsconfig.json`,
  ])('drops %s, which no tarball contains', (path) => {
    expect(isShipped(path, unread)).toBe(false)
  })

  it.each([
    `${AUTH}/index.js`,
    `${AUTH}/wasm-inline.mjs`,
    `${AUTH}/src/lib.rs`,
    `${AUTH}/Cargo.toml`,
    `${AUTH}/build.rs`,
    `${AUTH}/scripts/inline-wasm.mjs`,
    `${AUTH}/a-file-nobody-has-classified.mjs`,
    `${AUTH}/__tests__-lookalike.mjs`,
    `${WASM}/src/lib.rs`,
    'packages/stack-auth/src/lib.rs',
    'packages/stack-auth/Cargo.toml',
  ])('keeps %s', (path) => {
    expect(isShipped(path, unread)).toBe(true)
  })

  it.each([
    `${AUTH}/package.json`,
    `${AUTH}/platforms/linux-x64-gnu/package.json`,
    `${WASM}/package.json`,
  ])('drops %s when only devDependencies moved', (path) => {
    const head = { ...manifest, devDependencies: { vitest: '^4.1.11' } }
    expect(isShipped(path, sides(manifest, head))).toBe(false)
    const added = { ...manifest }
    delete added.devDependencies
    expect(isShipped(path, sides(added, manifest))).toBe(false)
  })

  it.each([
    ['version', { version: '1.0.1' }],
    ['files', { files: ['index.js', 'next.mjs'] }],
    ['peerDependencies', { peerDependencies: { next: '>=15' } }],
    ['dependencies', { dependencies: { jose: '^6' } }],
    ['exports', { exports: { '.': './index.js' } }],
  ])('keeps the manifest when %s moved', (_, change) => {
    const head = {
      ...manifest,
      ...change,
      devDependencies: { vitest: '^4' },
    }
    expect(isShipped(`${AUTH}/package.json`, sides(manifest, head))).toBe(true)
  })

  it('keeps a manifest added, deleted or unparseable', () => {
    const path = `${AUTH}/platforms/new/package.json`
    expect(isShipped(path, sides(undefined, manifest))).toBe(true)
    expect(isShipped(path, sides(manifest, undefined))).toBe(true)
    expect(isShipped(path, { readBase: () => '{', readHead: () => '{}' })).toBe(
      true,
    )
  })

  it('treats any other package.json as a plain shipped path', () => {
    // Only the binding manifests get the devDependencies rule.
    const head = { ...manifest, devDependencies: { vitest: '^4' } }
    expect(
      isShipped(
        `${AUTH}/examples-lookalike/package.json`,
        sides(manifest, head),
      ),
    ).toBe(true)
  })
})

describe('check-auth-npm-changeset.mjs --shipped', () => {
  const shipped = (base, paths) =>
    spawnSync(process.execPath, [SCRIPT, '--shipped', base], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      input: paths.join('\n'),
    })

  it('reads the base side from git and the head side from the tree', () => {
    // HEAD's manifest equals the working tree's unless this checkout has
    // edited it, so the comparison is a no-op and the manifest is dropped;
    // the test file always ships nothing and index.js always ships.
    const result = shipped('HEAD', [
      `${AUTH}/__tests__/consumer-typecheck.test.ts`,
      `${AUTH}/index.js`,
    ])
    expect(result.stderr).toBe('')
    expect(result.status).toBe(0)
    expect(result.stdout.trim()).toBe(`${AUTH}/index.js`)
  })

  it('prints nothing when nothing ships', () => {
    const result = shipped('HEAD', [`${AUTH}/vitest.config.ts`])
    expect(result.status).toBe(0)
    expect(result.stdout).toBe('')
  })

  it('keeps a manifest the base commit does not have', () => {
    // The root commit predates the auth package.
    const root = spawnSync('git', ['rev-list', '--max-parents=0', 'HEAD'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    }).stdout.split('\n')[0]
    const result = shipped(root, [`${AUTH}/package.json`])
    expect(result.status).toBe(0)
    expect(result.stdout.trim()).toBe(`${AUTH}/package.json`)
  })

  it('fails without a base commit', () => {
    expect(shipped('', []).status).toBe(1)
  })
})

describe('require-auth-npm-changeset.yml', () => {
  const workflow = readWorkflow(WORKFLOW)
  const [job] = Object.values(workflow?.jobs ?? {})
  const check = job?.steps?.find((step) => step.run?.includes(`node ${SCRIPT}`))

  /** The pathspec of the job's first `git diff`: what counts as shipped. */
  const shipped = (
    /git diff --name-only[^\n]*-- \\\n([\s\S]*?)\n\s*\)"/.exec(
      check?.run ?? '',
    )?.[1] ?? ''
  )
    .split(/\\?\n/)
    .map((line) => line.trim().replace(/\s*\\$/, ''))
    .filter(Boolean)

  const filters = workflow?.on?.pull_request?.paths ?? []

  it('diffs the crate and both binding folders', () => {
    expect(shipped).toEqual([
      'packages/stack-auth/Cargo.toml',
      'packages/stack-auth/src',
      'languages/typescript/packages/auth',
      'languages/typescript/packages/stack-auth-wasm',
    ])
  })

  it('runs on a pull request touching any path it diffs', () => {
    // A path diffed but not filtered never boots the job.
    for (const path of shipped) {
      expect(
        filters.some((filter) => filter === path || filter === `${path}/**`),
        `${path} is diffed by the job but missing from its paths filter`,
      ).toBe(true)
    }
  })

  it('diffs every path that boots it, except its own inputs', () => {
    // A path filtered but not diffed boots the job to report no change.
    const own = [SCRIPT, WORKFLOW]
    for (const filter of filters.filter((f) => !own.includes(f))) {
      expect(
        shipped.includes(filter.replace(/\/\*\*$/, '')),
        `${filter} boots the job but the job does not diff it`,
      ).toBe(true)
    }
  })

  it('names folders that exist', () => {
    for (const path of shipped) {
      expect(
        spawnSync('git', ['ls-files', '--error-unmatch', path], {
          cwd: REPO_ROOT,
        }).status,
        path,
      ).toBe(0)
    }
  })

  it('lists a moved file by its source path too', () => {
    // With rename detection, moving a shipped file under __tests__/ reports
    // only the unshipped destination and skips the changeset.
    expect(check?.run).toMatch(/git diff --name-only --no-renames /)
  })

  it('filters the diffed paths through --shipped before deciding', () => {
    // Without it every test or devDependency edit demands a release.
    expect(check?.run).toMatch(
      new RegExp(`node ${SCRIPT} --shipped "\\$BASE_SHA" <<< "\\$CHANGED"`),
    )
    expect(check?.run).toMatch(/if \[\[ -z "\$SHIPPED_CHANGES" \]\]/)
  })

  it('installs a root that declares the parser the script imports', () => {
    // pnpm does not expose `@changesets/cli`'s own dependencies to the root,
    // so without this declaration the script dies on its first import.
    const { devDependencies } = JSON.parse(
      readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'),
    )
    expect(devDependencies['@changesets/parse']).toBeDefined()
    expect(
      job?.steps?.some((step) =>
        /pnpm install --frozen-lockfile\b.*--filter @cipherstash\/stack-monorepo/.test(
          step.run ?? '',
        ),
      ),
    ).toBe(true)
  })
})
