import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  allowedMajors,
  goReleaseVersionErrors,
  modulePathOf,
} from '../go-release-version.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * `release-golang.yml` pushes an immutable tag before `go` resolves it, so a
 * version Go refuses must be refused here instead, before the build.
 */

const MODULE = 'github.com/cipherstash/stack/languages/golang'
const MAIN = 'refs/heads/main'
const BRANCH = 'refs/heads/ci/golang-release'

const errorsFor = (version, ref = MAIN, modulePath = MODULE) =>
  goReleaseVersionErrors(version, { modulePath, ref })

describe('goReleaseVersionErrors', () => {
  it.each([
    '0.1.0',
    '1.0.0',
    '0.10.20',
    '0.1.0-alpha.1',
    '0.1.0-rc.0',
    '1.2.3-x-y.7.z9',
    // Near misses: a 14-digit identifier that is not a pseudo-version's
    // timestamp position, and a date-stamped pre-release.
    '0.1.0-alpha.20261012131135',
    '0.1.0-rc.20261012',
  ])('accepts %s from main', (version) => {
    expect(errorsFor(version)).toEqual([])
  })

  it.each([
    ['v0.1.0', 'leading v'],
    ['01.2.3', 'leading zeros'],
    ['0.01.0', 'leading zeros'],
    ['0.1', 'MAJOR.MINOR.PATCH'],
    ['0.1.0.0', 'MAJOR.MINOR.PATCH'],
    ['0.1.0-', 'empty pre-release identifier'],
    ['0.1.0-alpha..1', 'empty pre-release identifier'],
    ['0.1.0-alpha.01', 'leading zero'],
    ['0.1.0-al_pha', 'may contain only'],
    ['0.1.0+build.1', '+build metadata'],
    ['2.0.0', 'major version 0 or 1'],
    ['2.0.0-alpha.1', 'major version 0 or 1'],
    // The three pseudo-version forms: no earlier tag, after a pre-release,
    // and after a release (the patch bumped, `-0.` before the timestamp).
    ['0.0.0-20261012131135-deadbeefdead', 'pseudo-version'],
    ['0.1.0-alpha.1.0.20261012131135-deadbeefdead', 'pseudo-version'],
    ['0.1.1-0.20261012131135-deadbeefdead', 'pseudo-version'],
  ])('refuses %s (%s)', (version, reason) => {
    const errors = errorsFor(version)
    expect(errors.length).toBeGreaterThan(0)
    expect(errors.join('\n')).toContain(reason)
  })

  it('lets a pre-release come from a branch', () => {
    expect(errorsFor('0.1.0-alpha.1', BRANCH)).toEqual([])
  })

  it('keeps a final version on main', () => {
    expect(errorsFor('0.1.0', BRANCH).join('\n')).toContain(
      'released from main only',
    )
  })

  it('follows a /vN module path to its own major', () => {
    expect(errorsFor('2.1.0', MAIN, `${MODULE}/v2`)).toEqual([])
    expect(errorsFor('1.0.0', MAIN, `${MODULE}/v2`).join('\n')).toContain(
      'major version 2',
    )
  })
})

describe('allowedMajors', () => {
  it('reads the /vN suffix and nothing else', () => {
    expect(allowedMajors(MODULE)).toEqual([0, 1])
    expect(allowedMajors(`${MODULE}/v3`)).toEqual([3])
    // `/v1` is not a major-version suffix Go recognises.
    expect(allowedMajors(`${MODULE}/v1`)).toEqual([0, 1])
  })
})

describe('the module being released', () => {
  it('is the one at languages/golang', () => {
    const goMod = readFileSync(
      join(REPO_ROOT, 'languages/golang/go.mod'),
      'utf8',
    )
    expect(modulePathOf(goMod)).toBe(MODULE)
  })
})

describe('the script as the workflow runs it', () => {
  const run = (...args) => {
    try {
      return {
        status: 0,
        out: execFileSync(
          process.execPath,
          [join(REPO_ROOT, 'scripts/go-release-version.mjs'), ...args],
          { encoding: 'utf8' },
        ),
      }
    } catch (error) {
      return { status: error.status, out: String(error.stdout) }
    }
  }

  it('exits 0 for a version it accepts', () => {
    expect(run('0.1.0-alpha.1', BRANCH).status).toBe(0)
  })

  it('exits 1 with a workflow error annotation for one it refuses', () => {
    const { status, out } = run('2.0.0', MAIN)
    expect(status).toBe(1)
    expect(out).toContain('::error::')
  })

  it('is what release-golang.yml checks the version with, before any build', () => {
    // The check is only worth something if it runs before the guests are
    // built and long before the tag is pushed.
    const steps = readWorkflow('.github/workflows/release-golang.yml').jobs
      .build.steps
    const check = steps.findIndex((step) =>
      String(step.run ?? '').includes('scripts/go-release-version.mjs'),
    )
    const firstBuild = steps.findIndex((step) =>
      String(step.run ?? '').includes('mise run'),
    )
    expect(check).toBeGreaterThanOrEqual(0)
    expect(check).toBeLessThan(firstBuild)
  })
})
