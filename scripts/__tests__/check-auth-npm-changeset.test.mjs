import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
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
 * and a script that accepts anything is a check that passes.
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
