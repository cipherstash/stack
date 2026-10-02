import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * `_build-auth-artifacts.yml` builds the seven `@cipherstash/auth` tarballs
 * that `release.yml`'s `publish-auth` uploads. Three things about it are easy
 * to undo in an edit that still looks right, and each one ships a broken
 * package rather than failing a build:
 *
 * 1. `napi build --platform` with no `--js false` writes napi's own loader over
 *    the committed `index.js`, one of the wrapper's frozen published files.
 *    The workflow runs `git diff --exit-code` on the package after the build,
 *    so the build must leave the tracked tree as it found it.
 * 2. The wrapper's six platform peers are `workspace:*`. `pnpm pack` rewrites
 *    them to the exact version; `npm pack` publishes `workspace:*`, which no
 *    registry resolves.
 * 3. The matrix is a third list of the six platforms, beside the `platforms/`
 *    folders and the napi triples in the wrapper's `package.json`.
 */

const WORKFLOW = '.github/workflows/_build-auth-artifacts.yml'
const AUTH_DIR = 'languages/typescript/packages/auth'
const AUTH = join(REPO_ROOT, AUTH_DIR)

const workflow = readWorkflow(WORKFLOW)
const binaries = workflow?.jobs?.binaries
const wrapper = workflow?.jobs?.wrapper
const runs = (job) => (job?.steps ?? []).map((step) => String(step?.run ?? ''))

const PLATFORMS = readdirSync(join(AUTH, 'platforms'), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort()

describe('_build-auth-artifacts.yml', () => {
  it('builds every platform package, and only those', () => {
    const matrix = binaries?.strategy?.matrix?.include ?? []
    expect(PLATFORMS).toHaveLength(6)
    expect(matrix.map((leg) => leg.platform).sort()).toEqual(PLATFORMS)

    const { napi } = JSON.parse(
      readFileSync(join(AUTH, 'package.json'), 'utf8'),
    )
    expect(matrix.map((leg) => leg.target).sort()).toEqual(
      [...napi.triples.additional].sort(),
    )
  })

  it('builds each binding without writing over the committed loader', () => {
    const build = runs(binaries).filter((run) => /\bnapi build\b/.test(run))
    expect(build).toHaveLength(1)
    for (const flag of [
      '--platform',
      '--release',
      '--target',
      '--strip',
      '--dts native.d.ts',
      '--js false',
    ]) {
      expect(build[0]).toContain(flag)
    }
  })

  it('fails the leg when the build changed a tracked file', () => {
    const all = runs(binaries)
    const build = all.findIndex((run) => /\bnapi build\b/.test(run))
    const check = all.findIndex((run) =>
      new RegExp(`git diff --exit-code\\b.*${AUTH_DIR}`).test(run),
    )
    expect(check).toBeGreaterThan(build)
  })

  it('packs the wrapper with pnpm, which rewrites its workspace peers', () => {
    const packs = runs(wrapper).filter((run) => /\bpack\b/.test(run))
    expect(packs.some((run) => /\bpnpm\b.*\bpack\b/.test(run))).toBe(true)
    expect(packs.some((run) => /\bnpm pack\b/.test(run))).toBe(false)
  })
})
